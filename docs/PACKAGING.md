# Packaging Cybrix AI

## Prerequisites
- Python 3.12+
- PyInstaller (`pip install pyinstaller`)
- All project dependencies installed (`pip install -r requirements.txt`)

## Build Instructions
1. Ensure you are in the project root.
2. Run `./scripts/build.sh`
3. The output will be in `dist/`:
   - `cybrix-ai/` folder containing the executable and required files.
   - A compressed archive `cybrix-ai-linux-x86_64.tar.gz` for distribution.

## Running from the Bundle
- Extract the archive to any directory.
- Run `./cybrix-ai` (Linux) or `cybrix-ai.exe` (Windows).
- For local AI, ensure Ollama is installed and running (https://ollama.com).
- Configuration can be overridden by placing `settings.yaml` next to the executable, or via environment variables.

## Installing as a Desktop Application (Linux)
- Copy the `cybrix-ai` folder to `/opt/cybrix-ai`.
- Copy `scripts/cybrix.desktop` to `~/.local/share/applications/` or `/usr/share/applications/`.
- Place an icon file in the app folder.

## Note on GPU (ROCm)
- Ollama must be installed separately with ROCm support.
- Cybrix AI will detect the GPU status and display it on the dashboard.