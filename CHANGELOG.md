# Changelog — Cybrix desktop (gggg)

Format: [Keep a Changelog](https://keepachangelog.com/), versions follow [SemVer](https://semver.org/).

## [Unreleased] — closed beta readiness

### Added
- **Pentest Lab expanded to 24 agents + headless automation**: added masscan, subfinder, amass,
  theHarvester, httpx, wafw00f, feroxbuster, dalfox (XSS), testssl.sh, SMB enum (enum4linux),
  searchsploit (Exploit-DB) and hydra; masscan/hydra are manual-only. New headless CLI
  `python -m application.pentest.cli` (Qt-free) writes Markdown + JSON reports, plus
  `scripts/pentest-scan.sh`, `scripts/pentest-batch.sh` and `scripts/install-pentest-tools.sh`.
  The GUI Pentest Lab picks up the new agents automatically.
- **Futuristic cyberpunk dark theme**: near-black panels with neon cyan/magenta/violet accents,
  gradient primary buttons and progress bars, a neon sidebar, and bundled display fonts (Orbitron
  for headings/nav, Share Tech Mono for body — OFL, loaded by `ThemeManager.load_fonts()`). The
  light theme stays clean; selector parity is preserved.
- **Pentest Lab (desktop, real tools)**: a new tab that runs an A2A chain of security-tool agents
  (nmap, nmap `--script vuln`, whatweb, HTTP security headers, nikto, sslscan, nuclei, gobuster,
  wpscan, sqlmap, dnsrecon) against a scope-checked local target, maps findings to the OWASP Top 10
  (2021), and has the LLM write a final conclusion for the user. Agents share one context and trigger
  each other; tools run through argv lists (never a shell) with per-tool timeouts, only after the user
  confirms authorisation, and fall back to a labelled simulation when a binary is absent. Private/
  loopback targets only by default (`pentest.allow_remote_targets` to opt in). Code in
  `application/pentest/` + `application/services/pentest_service.py`, UI in `presentation/…/pentest_*`.
- **Windows installer built on Linux**: `scripts/build_windows_wine.sh` (Windows Python 3.13 from NuGet under 64-bit Wine → PyInstaller → NSIS `scripts/cybrix.nsi`, per-user install, en/ru/uz) → `dist/Cybrix-Setup-<version>.exe`, published on the server's `/download/` page.
- **Installers**: one-folder PyInstaller build → Linux AppImage + .deb (`scripts/build.sh`), Windows Inno
  Setup (`scripts/build_windows.ps1`, Authenticode when a certificate is set), macOS .app/DMG with signing
  and notarization (`scripts/build_macos.sh`); release workflow on tags.
- **Auto-update**: Ed25519-signed manifests verified against the key pinned in `settings.yaml`, sha256/size
  checked download, install with consent; stable/beta channels.
- **First-run wizard**: server address (https, connection test), privacy choices (all off by default),
  server-command policy.
- **Crash reporting**: local crash log always; Sentry only with consent; "Export diagnostics" ZIP.
- **Settings**: editable server address, language (en/ru/uz), Ollama host, update channel, crash reports,
  feedback to the team.
- **i18n**: Russian and Uzbek translations for the whole UI (170 strings; a test fails on any new untranslated
  widget text), complete light theme.
- **Per-user OS directories** for settings, database, logs and caches (`core/paths.py`, `CYBRIX_HOME`).
- Dashboard severity chart from real analyses.
- **REA reverse engineering** (github.com/morluto/rea, MIT):
  - source pinned as the submodule `third_party/rea`;
  - the `rea-agents@6.7.0` CLI drives static inspections: objdump, Go/Rust metadata, .NET, JS/Electron, artifact graph;
  - malware analysis adds REA evidence to the prompt and report, and handles non-PE files (ELF, Mach-O, apps) instead of failing;
  - new approved server command `rea_analysis`, limited to allowed folders;
  - **Ghidra 12.1.4** deep analysis (`rea analyze --provider ghidra`): automatic when Ghidra and JDK 21+ are found
    (env vars or `~/.local/opt`); `deep` can be forced on or off per command.
- **AMD ROCm + PyTorch**:
  - `core/accelerator.py` detects AMD GPUs from KFD sysfs (no `rocminfo`), picks the discrete card and sets
    `HSA_OVERRIDE_GFX_VERSION` (RX 6000 → 10.3.0) and `HIP_VISIBLE_DEVICES` before PyTorch starts;
  - the GPU monitor reads `rocm-smi` 7.x (bytes) or amdgpu sysfs;
  - `requirements-rocm.txt` (torch 2.9.1+rocm6.4) and `scripts/install_rocm.sh` install the GPU build;
  - RAG embeddings run on the GPU;
  - log analysis gets a PyTorch autoencoder "unusual lines" section;
  - Settings → GPU / ROCm: device info, benchmark, auto/GPU/CPU choice;
  - the dashboard shows the GPU's gfx target and how much of each Ollama model sits in VRAM (`scripts/ollama-rocm.conf`);
  - telemetry sends `gpu_gfx`.
- **Two-factor sign-in**: when the account has 2FA, the Server page asks for the authenticator (or backup)
  code; a team that requires 2FA gets a clear message to enable it in the web app first.
- **Signed detection rules**: YARA/Sigma bundles are fetched from the server, verified against the pinned
  `rules.public_key`, never rolled back, and re-verified at start. New approved `yara_scan` command (file or
  folder inside `command_allowed_dirs`); `log_analysis` also reports Sigma matches. Built-in Sigma evaluator
  (selections, modifiers, and/or/not, `1 of`/`all of`); rules it cannot evaluate are skipped, not half-run.
  Server page shows the installed rules version.
- **Malware hash check** (opt-in, off by default; Settings → Server, Server page, first-run wizard): the
  SHA-256 and file name of running programs are sent as `process.hashes` — hashed once per path/size/mtime,
  only new or changed files, files over 200 MB skipped, never the path or contents. Matches appear in the
  suspicious-activity list and open their alert.
- Suspicious-connection hits link to their server-side alert (double-click opens it in the browser).
- CI: ruff + pytest on Linux, Windows and macOS.

### Changed
- RAG (chromadb, sentence-transformers/torch) is an optional extra (`requirements-rag.txt`) and loads lazily;
  the FastAPI gateway moved to `requirements-gateway.txt`. Installer size: ~140 MB instead of several GB.
- No torch import at startup.

### Fixed
- ROCm detection relied on `rocminfo` (often not installed), so AMD GPUs showed as "CPU only"; VRAM was always 0
  with ROCm-SMI 7.x (keys changed to bytes). Removed the unused duplicate `infrastructure/gpu/gpu_manager.py`.
- A generic `DATABASE_URL` in the environment (e.g. the Django server's PostgreSQL URL) silently replaced the
  desktop database; the app now only honours `CYBRIX_DATABASE_URL` and logs a warning about the other.
- `VectorStore` had lost all its methods (RAG was broken).
- Theme, Ollama host and server URL settings were never saved.
- Stale test fixtures (`_init_db`, missing `provider/singleton` imports); both long-failing tests pass.
