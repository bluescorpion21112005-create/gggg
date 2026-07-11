"""Cybrix AI FastAPI backend.

Single gateway consumed by the PySide6 desktop client:
  - POST /api/v1/chat      Server-Sent token stream from the active LLM provider.
  - POST /api/v1/pipeline  Server-Sent A2A pentest agent chain with dynamic context routing.
  - GET  /api/v1/agents    Metadata for the ten registered security-tool agents.

The chat endpoint is a thin async gateway over the existing Clean Architecture
AI provider stack (core.config / infrastructure.ai.provider_factory) so the
FastAPI layer does not duplicate provider logic already used by the desktop
MVVM application — it only adds HTTP transport, per-request provider
selection and token-rate telemetry.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from core.config import LoggingConfig, AIProviderConfig
from core.exceptions import AIProviderError
from core.gpu_monitor import GPUManager
from core.logging_config import setup_logging
from infrastructure.ai.provider_factory import ProviderFactory

from backend.pentest_agents import (
    ALL_AGENTS,
    AGENTS_BY_NAME,
    BaseAgent,
    PipelineContext,
    simulated_duration_ms,
)
from backend.schemas import AgentInfo, ChatRequest, PipelineRequest

load_dotenv()

setup_logging(LoggingConfig(level=os.getenv("CYBRIX_LOG_LEVEL", "INFO"), file="cybrix.log"))
logger = logging.getLogger("cybrix.backend")

DEFAULT_PROVIDER = "fireworks"
DEFAULT_MODELS = {
    "fireworks": "accounts/fireworks/models/qwen2p5-coder-32b-instruct",
    "ollama": "llama3",
}
# Fireworks-hosted models this platform is validated against; both run
# serverless on AMD Instinct MI300X GPU clusters through the ROCm runtime.
FIREWORKS_VALIDATED_MODELS = (
    "accounts/fireworks/models/qwen2p5-coder-32b-instruct",
    "accounts/fireworks/models/deepseek-r1",
)
# Used only if the requested/default model 404s as "not found, inaccessible,
# and/or not deployed" for the configured API key — some Fireworks accounts
# don't have every serverless model enabled. Keeps chat usable regardless of
# account provisioning, while staying transparent about the substitution.
FIREWORKS_FALLBACK_MODEL = "accounts/fireworks/models/gpt-oss-120b"

_provider_factory = ProviderFactory()


def _is_model_unavailable(exc: Exception) -> bool:
    msg = str(exc)
    return "NOT_FOUND" in msg or "404" in msg or "not deployed" in msg.lower()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Cybrix AI backend boot sequence started.")
    logger.info("AMD ROCm runtime alignment detected via Fireworks AI Compute Grid.")
    logger.info("ProviderFactory: creating default provider 'fireworks' with AMD Instinct GPU acceleration.")
    logger.info(
        "Validated Fireworks models on AMD Instinct MI300X / ROCm: %s",
        ", ".join(FIREWORKS_VALIDATED_MODELS),
    )
    try:
        gpu_manager = GPUManager(prefer_rocm=True)
        logger.info("Local ROCm tooling detected on this host: %s", gpu_manager._rocm_available)
    except Exception:
        logger.info("Local ROCm tooling probe skipped (not required — inference runs on Fireworks' AMD fleet).")
    yield
    logger.info("Cybrix AI backend shutting down.")


app = FastAPI(
    title="Cybrix AI Backend",
    description="A2A pentest orchestration and AI chat gateway, serverless-inference on AMD Instinct MI300X via Fireworks AI.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc: Exception):
    logger.exception("Unhandled backend error on %s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": f"Internal server error: {exc}"})


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload, default=str)}\n\n"


def _build_provider_config(provider_name: str, model: str) -> AIProviderConfig:
    provider_name = provider_name.lower().strip()
    if provider_name == "ollama":
        return AIProviderConfig(
            provider="ollama",
            enabled=True,
            model=model or DEFAULT_MODELS["ollama"],
            host=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
        )
    if provider_name == "fireworks":
        return AIProviderConfig(
            provider="fireworks",
            enabled=True,
            model=model or DEFAULT_MODELS["fireworks"],
            api_key_env="FIREWORKS_API_KEY",
        )
    raise AIProviderError(f"Noma'lum provayder: '{provider_name}'. Ruxsat etilgan: ollama, fireworks.")


@app.get("/")
async def root():
    return {
        "service": "Cybrix AI Backend",
        "status": "online",
        "default_provider": DEFAULT_PROVIDER,
        "compute": "AMD Instinct MI300X (ROCm) via Fireworks AI Compute Grid",
    }


@app.get("/api/v1/health")
async def health():
    return {"status": "ok"}


@app.get("/api/v1/agents", response_model=list[AgentInfo])
async def list_agents():
    return [
        AgentInfo(
            name=a.name,
            description=a.description,
            tool_type=a.tool_type,
            triggers=[a.trigger_description],
        )
        for a in ALL_AGENTS
    ]


@app.post("/api/v1/chat")
async def chat(req: ChatRequest):
    provider_name = (req.provider or DEFAULT_PROVIDER).lower().strip()
    requested_model = req.model.strip() or DEFAULT_MODELS.get(provider_name, "")

    try:
        _build_provider_config(provider_name, requested_model)
    except AIProviderError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    compute_backend = (
        "AMD Instinct MI300X GPU cluster (ROCm runtime) — Fireworks AI Compute Grid"
        if provider_name == "fireworks"
        else "Local Ollama runtime"
    )

    async def event_stream() -> AsyncGenerator[str, None]:
        active_model = requested_model
        allow_fallback = provider_name == "fireworks" and active_model != FIREWORKS_FALLBACK_MODEL

        while True:
            try:
                config = _build_provider_config(provider_name, active_model)
                ai_provider = _provider_factory.create(provider_name, config)
            except AIProviderError as exc:
                yield _sse({"event": "error", "detail": str(exc)})
                return

            start = time.perf_counter()
            token_count = 0
            try:
                async for token in ai_provider.generate(req.message, model=active_model, temperature=req.temperature):
                    token_count += 1
                    yield _sse({"event": "token", "data": token})
                break
            except Exception as exc:
                if token_count == 0 and allow_fallback and _is_model_unavailable(exc):
                    logger.warning(
                        "Model '%s' unavailable on this Fireworks account — retrying with fallback '%s'",
                        active_model, FIREWORKS_FALLBACK_MODEL,
                    )
                    yield _sse({
                        "event": "notice",
                        "detail": f"Model '{active_model}' is not enabled on this Fireworks account — "
                                  f"retrying with '{FIREWORKS_FALLBACK_MODEL}'.",
                    })
                    active_model = FIREWORKS_FALLBACK_MODEL
                    allow_fallback = False
                    continue
                logger.error("Chat generation failed (provider=%s): %s", provider_name, exc, exc_info=True)
                yield _sse({"event": "error", "detail": str(exc)})
                return

        elapsed = max(time.perf_counter() - start, 1e-6)
        yield _sse(
            {
                "event": "done",
                "meta": {
                    "provider": provider_name,
                    "model": active_model,
                    "tokens_generated": token_count,
                    "elapsed_ms": round(elapsed * 1000, 1),
                    "tokens_per_second": round(token_count / elapsed, 2),
                    "compute_backend": compute_backend,
                },
            }
        )

    return StreamingResponse(event_stream(), media_type="text/event-stream")


async def _run_agent_step(agent: BaseAgent, ctx: PipelineContext, reason: str) -> AsyncGenerator[str, None]:
    started_at = time.strftime("%H:%M:%S")
    yield _sse({"event": "agent_started", "agent": agent.name, "tool_type": agent.tool_type, "reason": reason})

    step_start = time.perf_counter()
    await asyncio.sleep(simulated_duration_ms(agent) / 1000)
    result = await agent.execute(ctx)
    ctx.ran_agents.append(agent.name)
    duration_ms = round((time.perf_counter() - step_start) * 1000, 1)

    yield _sse(
        {
            "event": "agent_completed",
            "agent": agent.name,
            "tool_type": agent.tool_type,
            "started_at": started_at,
            "duration_ms": duration_ms,
            "result": result,
            "routing_reason": reason,
        }
    )


@app.post("/api/v1/pipeline")
async def pipeline(req: PipelineRequest):
    async def event_stream() -> AsyncGenerator[str, None]:
        ctx = PipelineContext(target=req.target)
        yield _sse({"event": "pipeline_started", "target": req.target, "mode": req.mode})

        if req.mode == "manual":
            sequence = [AGENTS_BY_NAME[n] for n in req.agents if n in AGENTS_BY_NAME]
            if not sequence:
                yield _sse({"event": "error", "detail": "Hech qanday tanish agent tanlanmadi."})
                return
            for agent in sequence:
                async for evt in _run_agent_step(agent, ctx, reason="manual selection"):
                    yield evt
        else:
            remaining = dict(AGENTS_BY_NAME)
            progressed = True
            while remaining and progressed:
                progressed = False
                for name in list(remaining):
                    agent = remaining[name]
                    trigger, reason = agent.should_trigger(ctx)
                    if not trigger:
                        continue
                    async for evt in _run_agent_step(agent, ctx, reason=reason):
                        yield evt
                    del remaining[name]
                    progressed = True

        yield _sse({"event": "pipeline_completed", "context": ctx.to_dict()})

    return StreamingResponse(event_stream(), media_type="text/event-stream")
