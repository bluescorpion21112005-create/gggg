# Cybrix AI

**Autonomous Multi-Agent Pentesting Platform** — a PySide6 desktop client talking to an
asynchronous FastAPI backend that orchestrates ten security-tool agents through a dynamic
Agent-to-Agent (A2A) context-routing pipeline, with AI chat served by **Fireworks AI**
running serverless on **AMD Instinct™ MI300X** GPU clusters via the **ROCm** runtime.

Built for the AMD Developer Hackathon — see [AMD Ecosystem Integration](#amd-ecosystem-integration)
for how compute is wired end to end.

---

## Architecture

```
┌─────────────────────────────┐        HTTP / SSE        ┌──────────────────────────────┐
│   PySide6 desktop client     │ ───────────────────────► │   FastAPI backend             │
│   (cybrix_ai.py)             │ ◄─────────────────────── │   (backend/main.py)           │
│                               │   QNetworkAccessManager  │                                │
│  • AI Chat page              │   (async, non-blocking)  │  POST /api/v1/chat  (SSE)     │
│  • Security Agents page      │                           │  POST /api/v1/pipeline (SSE)  │
│  • IOC / Malware / Log pages │                           │  GET  /api/v1/agents          │
└─────────────────────────────┘                           └──────────────┬────────────────┘
                                                                            │
                                              ┌─────────────────────────────┼─────────────────────────────┐
                                              │                             │                             │
                                   ┌──────────▼──────────┐      ┌───────────▼───────────┐
                                   │ ProviderFactory       │      │ A2A Pentest Engine     │
                                   │ (infrastructure/ai)   │      │ (backend/pentest_agents)│
                                   │  default: fireworks   │      │ 10 agents + shared      │
                                   │  fallback: ollama     │      │ PipelineContext          │
                                   └──────────┬────────────┘      └───────────┬───────────┘
                                              │                                │
                                   ┌──────────▼────────────┐                  │
                                   │ Fireworks AI Compute   │                  │
                                   │ Grid — Qwen2.5-Coder-32B│                 │
                                   │ / DeepSeek-R1 served on │        Structured JSON findings
                                   │ AMD Instinct MI300X     │        cascade agent → agent
                                   │ (ROCm runtime)          │
                                   └─────────────────────────┘
```

The backend is a thin async gateway over the project's existing Clean Architecture AI
provider stack (`core/config.py`, `infrastructure/ai/provider_factory.py`) — no provider
logic is duplicated between the desktop MVVM app and the FastAPI layer.

## A2A pentest pipeline

Ten agents share one `PipelineContext` (`backend/pentest_agents.py`). Each agent declares a
trigger predicate over that context instead of a fixed execution order:

| Agent | Triggers when |
|---|---|
| `NmapAgent` | chain entry point — seeds `open_ports` / `services` |
| `OwaspZapAgent`, `GobusterAgent`, `BurpSuiteAgent` | a web port (80/443/8080) is open |
| `OpenVASAgent` | the host has been mapped |
| `HydraAgent` | SSH (22) is open |
| `SqlmapAgent` | MySQL (3306) is open **or** ZAP already found a SQLi finding |
| `MetasploitAgent` | any high/critical severity vulnerability exists |
| `WiresharkAgent` | Burp Suite captured traffic |
| `JohnTheRipperAgent` | Hydra harvested a credential |

`POST /api/v1/pipeline` runs this rule engine and streams every step
(`agent_started` → `agent_completed` → ... → `pipeline_completed`) over Server-Sent Events,
each carrying the **routing reason** that fired it — visible live in the "A2A Event Log"
panel. Findings are structured JSON (ports, CVEs, credentials, sessions), not free-text
blobs, so the client renders typed, precise logs.

Tool execution is a clearly-labelled structured simulation — no traffic is sent to the
target — so the pipeline is safe to demo against any target string without requiring the
underlying binaries (nmap, sqlmap, metasploit, ...) to be installed, and without ever
running an exploit against a host you don't control. Only point it at infrastructure you
are authorised to test (lab environments, CTFs, your own systems).

## AMD ecosystem integration

- **Default provider is Fireworks AI** (`config/settings.yaml`, `backend/main.py`), backed
  by `FIREWORKS_API_KEY` from `.env`, base URL `https://api.fireworks.ai/inference/v1`.
- Chat defaults to `accounts/fireworks/models/qwen2p5-coder-32b-instruct`; `DeepSeek-R1`
  (`accounts/fireworks/models/deepseek-r1`) is validated as an alternate model. Both are
  served serverless on **AMD Instinct™ MI300X** GPU clusters through the ROCm runtime.
- On boot, the backend logs the compute alignment explicitly:
  ```
  INFO: AMD ROCm runtime alignment detected via Fireworks AI Compute Grid.
  INFO: ProviderFactory: creating default provider 'fireworks' with AMD Instinct GPU acceleration.
  ```
- Every chat response returns a `compute_backend` field
  (`"AMD Instinct MI300X GPU cluster (ROCm runtime) — Fireworks AI Compute Grid"`) alongside
  token count, elapsed time and tokens/second, shown live in the Chat page status bar.
- `core/gpu_monitor.py` additionally probes local `rocm-smi` / `rocminfo` tooling for
  on-host ROCm telemetry (independent of the Fireworks cloud path).

## Running it

> **Python version:** use **Python 3.13** (3.10–3.13 supported). On Python 3.14 the
> qasync event loop that drives the MVVM app (`main.py`) never runs async tasks, so the
> window opens but buttons, analyses and the server connection silently do nothing.
>
> ```bash
> uv venv --python 3.13 .venv   # or: python3.13 -m venv .venv
> source .venv/bin/activate
> ```

### Desktop app (MVVM, connects to the Cybrix server)

```bash
pip install -r requirements.txt          # add -r requirements-rag.txt for the local knowledge base (~2 GB)
CYBRIX_CONFIG_DIR=config python main.py  # first run opens the setup wizard
```

Settings, the database and logs live in per-user OS folders (`core/paths.py`); set `CYBRIX_HOME=<dir>`
for a portable/self-contained setup. Tests: `pip install -r requirements-dev.txt` then
`QT_QPA_PLATFORM=offscreen python -m pytest -c tests/pytest.ini --rootdir=. tests`.

**Installers:** `scripts/build.sh` (AppImage + .deb), `scripts/build_windows.ps1` (Inno Setup),
`scripts/build_macos.sh` (DMG, signing/notarization); tags `v*` build all three in CI
(`.github/workflows/release.yml`). See `CHANGELOG.md`.

### 1. Backend (optional A2A pentest gateway)

```bash
pip install -r requirements-gateway.txt
cp .env.example .env   # then fill in FIREWORKS_API_KEY
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Verify: `curl http://127.0.0.1:8000/api/v1/agents`

### 2. Standalone gateway client

```bash
python cybrix_ai.py
```

The client talks to `http://127.0.0.1:8000/api/v1` by default (override with
`CYBRIX_BACKEND_HOST` / `CYBRIX_BACKEND_PORT`). If the backend is unreachable, the UI
surfaces a clear, non-blocking error (styled red text + a dialog with the exact command to
start it) instead of freezing or fabricating a response.

## Environment variables

See [.env.example](.env.example):

| Variable | Purpose |
|---|---|
| `FIREWORKS_API_KEY` | Fireworks AI key (default chat provider) |
| `OLLAMA_HOST` | Local Ollama runtime, optional secondary provider |
| `CYBRIX_DATABASE_URL` | Override the desktop app's SQLite URL (a generic `DATABASE_URL` is ignored) |
| `CYBRIX_BACKEND_HOST` / `CYBRIX_BACKEND_PORT` | Where the PySide6 client looks for the FastAPI backend |
| `CYBRIX_SERVER_URL` | Cybrix Django server for the MVVM app (`main.py`): REST + WebSocket, log in under Settings → Server |

`.env` is git-ignored — never commit real API keys. `.env.example` only ever holds
placeholders.

## Project layout

```
backend/                 FastAPI gateway (chat + A2A pentest pipeline)
  main.py                Routes, SSE streaming, AMD/Fireworks provider wiring
  pentest_agents.py       10 agents + PipelineContext + trigger predicates
  schemas.py               Pydantic request/response contracts
cybrix_ai.py              PySide6 desktop client (Chat, Security Agents, IOC/Malware/Log/Reports)
core/, domain/, infrastructure/, application/, presentation/
                            Clean Architecture MVVM desktop app (log/malware/IOC/RAG/threat-hunting
                            analysis) sharing the same AI provider stack as the backend
```

## Other application modules (Chat, IOC, Malware, Log, Reports)

`cybrix_ai.py` also ships local static analyzers used standalone (no network dependency):
IOC risk scoring, PE/malware entropy & import analysis, and log/IP anomaly extraction — each
feeding the Dashboard and the Markdown report generator.
