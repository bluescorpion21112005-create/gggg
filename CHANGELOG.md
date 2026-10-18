# Changelog — Cybrix desktop (gggg)

Format: [Keep a Changelog](https://keepachangelog.com/), versions follow [SemVer](https://semver.org/).

## [Unreleased] — closed beta readiness

### Added
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
- A generic `DATABASE_URL` in the environment (e.g. the Django server's PostgreSQL URL) silently replaced the
  desktop database; the app now only honours `CYBRIX_DATABASE_URL` and logs a warning about the other.
- `VectorStore` had lost all its methods (RAG was broken).
- Theme, Ollama host and server URL settings were never saved.
- Stale test fixtures (`_init_db`, missing `provider/singleton` imports); both long-failing tests pass.
