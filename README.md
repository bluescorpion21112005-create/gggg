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

## Pentest Lab (desktop, real tools)

The **Pentest Lab** tab (`presentation/views/pentest_view.py`) runs the same A2A idea against
your own lab with the **real** scanners installed on the machine, so you can find as many
weaknesses in your own site/app as possible. The engine, agents and safety live in
`application/pentest/` and are driven by `application/services/pentest_service.py`.

- **Many agents, one shared context, auto-routing.** Nmap seeds open ports/services; the web
  agents fire on web ports; the TLS agent on 443; WPScan only when WhatWeb fingerprints
  WordPress; SQLMap only when the URL carries a query parameter; an OWASP Top 10 agent maps
  every finding to the 2021 categories and runs last. Roster: **nmap** (ports/services),
  **nmap `--script vuln`**, **whatweb**, **HTTP security headers** (built-in), **nikto**,
  **sslscan**, **nuclei**, **gobuster**, **wpscan**, **sqlmap**, **dnsrecon**, and the
  **OWASP Top 10** aggregator.
- **Real, but gated.** A tool runs only through an argv list (never a shell), with a per-tool
  timeout, and only after you tick *"I am authorised to test this target"*. When a binary is
  missing the agent returns a clearly-labelled **simulated** result instead, so the lab still
  works end-to-end without the toolchain.
- **Local targets only by default.** `application/pentest/safety.py` accepts only
  private/loopback/`.local` targets; public targets are refused unless you set
  `pentest.allow_remote_targets: true` in `config/settings.yaml` (for systems you own or may
  test). Scope is checked before any tool starts.
- **Final AI conclusion.** After the chain, the configured LLM writes a Markdown conclusion
  for the user — an executive summary, the top risks grouped by OWASP category with one-line
  fixes, and next steps — streamed token by token. The agents themselves never call the LLM.

For authorised local lab / CTF / own-systems use only — defensive and educational, not for
attacking third-party systems.

### Roster (24 agents) + headless automation

The roster now covers recon, web, TLS, SMB and exploit-mapping: **nmap**, **masscan** (manual),
nmap `--script vuln`, **subfinder**, **amass**, **theHarvester**, **dnsrecon**, **whatweb**,
**httpx**, **wafw00f**, HTTP security headers, **nikto**, **nuclei**, **gobuster**, **feroxbuster**,
**sslscan**, **testssl.sh**, **SMB enum** (enum4linux), **wpscan**, **sqlmap**, **dalfox** (XSS),
**searchsploit** (Exploit-DB), **hydra** (manual) and the OWASP Top 10 aggregator. The auto-chain
routes by context; `masscan`/`hydra` are manual-only (privileged / intrusive) and never fire
automatically. Missing tools fall back to a labelled simulation. Check/install them with
`scripts/install-pentest-tools.sh`.

Run it headless (no GUI) from the terminal — the whole pentest package is Qt-free:

```bash
python -m application.pentest.cli 127.0.0.1                 # full auto chain + Markdown/JSON report
scripts/pentest-scan.sh http://localhost:8080 --agents nmap,nikto,nuclei
scripts/pentest-scan.sh 127.0.0.1 --no-conclusion          # no LLM key needed
scripts/pentest-batch.sh targets.txt                       # one report per target
python -m application.pentest.cli --list-agents            # see the roster
```

Reports (`report.md` + `report.json`) group findings by severity and OWASP category and include the
AI conclusion. Private/loopback targets only unless `--allow-remote` (for systems you may test).
Code: `application/pentest/{agents,engine,cli,report}.py`.

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

### Local AMD GPU (ROCm) — PyTorch and Ollama on your own Radeon

Besides the cloud path, the app uses a local AMD GPU directly (Linux, amdgpu driver):

- **Detection without `rocminfo`.** `core/accelerator.py` reads the kernel's KFD topology
  (`/sys/class/kfd`) and picks the strongest GPU, i.e. the discrete card on an APU laptop.
- **Automatic ROCm settings.** Before PyTorch starts, the app sets two variables, but only if you
  have not set them yourself:
  - `HSA_OVERRIDE_GFX_VERSION=10.3.0` for Radeon RX 6000 cards (gfx103x, not on ROCm's list);
  - `HIP_VISIBLE_DEVICES`, which hides an integrated GPU.
- **Live metrics.** `core/gpu_monitor.py` shows real GPU load, VRAM and temperature on the
  dashboard and in telemetry. It reads `rocm-smi` 7.x JSON and falls back to amdgpu sysfs.
- **PyTorch on the GPU** (`requirements-rocm.txt`, `torch 2.9.1+rocm6.4`; the wheel bundles HIP):
  - RAG embeddings (sentence-transformers) run on the GPU;
  - log analysis gains an *ML anomalies* section: a PyTorch autoencoder learns what a file's lines
    normally look like and lists the strangest ones
    (`infrastructure/analyzers/log_anomaly_torch.py`);
  - Settings → **GPU / ROCm** shows the device, gfx, VRAM and PyTorch/HIP versions, and has a
    benchmark and an auto / AMD GPU / CPU switch.
- **Ollama on the GPU.** With `scripts/ollama-rocm.conf` installed, the dashboard shows how much
  of each loaded model sits in VRAM.

```bash
scripts/install_rocm.sh            # PyTorch ROCm into .venv, then prints the GPU and a TFLOPS benchmark
# Ollama (local LLM) on the GPU — system-wide with sudo:
curl -fsSL https://ollama.com/install.sh | sh
sudo mkdir -p /etc/systemd/system/ollama.service.d
sudo cp scripts/ollama-rocm.conf /etc/systemd/system/ollama.service.d/rocm.conf
sudo systemctl daemon-reload && sudo systemctl restart ollama
# …or without sudo, for your user only:
mkdir -p ~/.local/opt/ollama
for f in ollama-linux-amd64 ollama-linux-amd64-rocm; do
  curl -fL "https://ollama.com/download/$f.tar.zst" | zstd -d |
    tar -x -C ~/.local/opt/ollama --exclude='lib/ollama/cuda_*'; done   # NVIDIA libs not needed on AMD
mkdir -p ~/.config/systemd/user && cp scripts/ollama-rocm.user.service ~/.config/systemd/user/ollama.service
systemctl --user daemon-reload && systemctl --user enable --now ollama
ollama run llama3.2:3b "hello" && ollama ps   # PROCESSOR column → "100% GPU"
```

Without the ROCm extras nothing breaks: everything runs on the CPU and the ML section is skipped.
`settings.yaml → gpu:` has `device` (auto | rocm | cpu), `hsa_override` and `visible_devices`.

## REA — reverse engineering (github.com/morluto/rea)

[REA](https://github.com/morluto/rea) ("Reverse Engineer Anything", MIT) is integrated as a static
analysis backend and as an MCP server for coding agents.

- **Source:** git submodule `third_party/rea`, pinned to a reviewed commit. Clone with
  `git clone --recurse-submodules`, or run `git submodule update --init` in an existing checkout.
- **Runtime:** the official npm package, pinned, needs no sudo and requires Node.js 22.19+ or 24.11+:
  ```bash
  npm install --prefix ~/.local/opt/rea rea-agents@6.7.0
  ```
  The app looks for `rea` in `CYBRIX_REA_PATH`, then `PATH`, then `~/.local/opt/rea`.
- **Malware analysis:** `infrastructure/analyzers/rea_analyzer.py` runs the read-only inspections that fit
  the file:
  - objdump headers and sections, plus Go/Rust build metadata, for ELF/PE/Mach-O;
  - .NET metadata;
  - the JavaScript/Electron module graph;
  - the artifact graph for anything else.

  The evidence goes into the AI prompt and the report. Non-PE files (ELF, Mach-O, apps) are analysed
  from REA's evidence instead of failing. The file is never executed.
- **Server command `rea_analysis`:** the same inspection, run on request from the web app. It works
  only inside your allowed folders and only after you approve it on this computer.
- **Ghidra (deep native analysis):**
  - When Ghidra 12.1.x and a full JDK 21+ are available, native binaries up to 50 MB also get
    `rea analyze --provider ghidra` (functions, segments, strings). Through MCP or the CLI you can
    also decompile functions to C pseudocode.
  - The app finds them via `GHIDRA_INSTALL_DIR` / `JAVA_HOME`, otherwise in `~/.local/opt`.
  - Sudo-less install, verified against the official SHA-256 sums:
    - Temurin JDK 21 tarball → `~/.local/opt/jdk-21…`;
    - `ghidra_12.1.4_PUBLIC_*.zip` (GitHub release) → `~/.local/opt/ghidra_12.1.4_PUBLIC`.

    Then check with `rea doctor --provider ghidra --json`.
- **For agents (MCP):** `rea mcp` serves REA's tools. The ccybrix workspace registers it in `.mcp.json`;
  use deep native analysis (Ghidra/IDA/Hopper) only where you have them installed and licensed.

Use REA only on software you own or are authorised to examine (see `third_party/rea/DISCLAIMER.md`).

## Look & feel

The desktop app ships a **futuristic cyberpunk dark theme** — near-black panels with neon
cyan/magenta/violet accents, gradient buttons and progress bars, and a neon sidebar. Headings and
the navigation use **Orbitron**, body text uses **Share Tech Mono** (both bundled under
`presentation/theme/fonts/`, OFL, registered by `ThemeManager.load_fonts()`); when the fonts are
missing the QSS falls back to a system monospace. A clean light theme is also available
(Settings → appearance). Styling is all in `presentation/theme/*.qss`.

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
`scripts/build_windows_wine.sh` (Windows installer built on Linux: PyInstaller under Wine + NSIS, `--setup` the first time),
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

## License

MIT — see [`LICENSE`](LICENSE). Third-party components keep their own licenses: REA (`third_party/rea`) is MIT
(© morluto); PySide6/Qt is LGPLv3, so the installers ship the Qt libraries as separate shared libraries;
the bundled fonts Orbitron and Share Tech Mono are under the SIL Open Font License
(`presentation/theme/fonts/OFL.txt`).
