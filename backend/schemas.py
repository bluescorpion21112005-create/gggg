"""Pydantic request/response contracts for the Cybrix AI backend."""
from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, description="User prompt")
    provider: str = Field(default="fireworks", description="ollama | fireworks")
    model: str = Field(default="", description="Model id; empty = provider default")
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)


class ChatCompleteMeta(BaseModel):
    provider: str
    model: str
    tokens_generated: int
    elapsed_ms: float
    tokens_per_second: float
    compute_backend: str


class AgentInfo(BaseModel):
    name: str
    description: str
    tool_type: str
    triggers: list[str] = Field(default_factory=list, description="A2A context conditions that auto-invoke this agent")


class PipelineRequest(BaseModel):
    target: str = Field(..., min_length=1, description="IP address, domain, or URL under test")
    mode: Literal["chain", "manual"] = Field(default="chain")
    agents: list[str] = Field(default_factory=list, description="Agent names to run when mode='manual'")


class AgentStepResult(BaseModel):
    agent: str
    tool_type: str
    started_at: str
    duration_ms: float
    result: dict[str, Any]
    triggered_by: Optional[str] = None
    routing_reason: Optional[str] = None
