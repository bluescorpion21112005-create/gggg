#!/usr/bin/env bash
# Windows build on Linux: PyInstaller under Wine (64-bit Windows Python) → NSIS installer
#   dist/Cybrix-Setup-<version>.exe  (+ dist/SHA256SUMS-windows)
#
#   scripts/build_windows_wine.sh            # build
#   scripts/build_windows_wine.sh --setup    # first time: create the Wine prefix + Windows Python + deps
#
# Needs wine (64-bit is enough), makensis and mingw-w64 (Debian/Kali: apt install wine nsis mingw-w64).
# The Windows Python comes from the official NuGet "python" package (no 32-bit installer bootstrapper needed).
# Output goes to dist/windows/ so the Linux build in dist/cybrix-ai is left alone.
# Publish on the server: python manage.py publish_desktop_installer dist/Cybrix-Setup-<version>.exe
set -euo pipefail
cd "$(dirname "$0")/.."

PY_VERSION="${CYBRIX_WIN_PYTHON:-3.13.16}"
BUILD_HOME="${CYBRIX_WINBUILD_HOME:-$HOME/.local/share/cybrix-winbuild}"
export WINEPREFIX="${WINEPREFIX:-$BUILD_HOME/prefix}" WINEDEBUG="${WINEDEBUG:--all}"
export WINEDLLOVERRIDES="${WINEDLLOVERRIDES:-mscoree,mshtml=}"     # no Mono/Gecko prompts
WINPY='C:\Python313\python.exe'
PYDIR="$WINEPREFIX/drive_c/Python313"

for tool in wine makensis curl unzip x86_64-w64-mingw32-gcc; do
  command -v "$tool" >/dev/null || { echo "[build] missing: $tool" >&2; exit 1; }
done

setup() {
  mkdir -p "$BUILD_HOME"
  [ -d "$WINEPREFIX/drive_c" ] || wineboot --init
  if [ ! -x "$PYDIR/python.exe" ]; then
    local pkg="$BUILD_HOME/python.$PY_VERSION.nupkg" unpack
    curl -fL --retry 5 -o "$pkg" "https://api.nuget.org/v3-flatcontainer/python/$PY_VERSION/python.$PY_VERSION.nupkg"
    unpack="$(mktemp -d "$BUILD_HOME/nupkg.XXXXXX")"
    unzip -q "$pkg" 'tools/*' -d "$unpack"
    mkdir -p "$PYDIR" && cp -a "$unpack/tools/." "$PYDIR/"
  fi
  wine "$WINPY" -m pip install --disable-pip-version-check --no-warn-script-location --prefer-binary \
    -r requirements.txt "pyinstaller>=6.10"
}

[ "${1:-}" = "--setup" ] && setup
[ -f "$PYDIR/python.exe" ] || { echo "[build] run: $0 --setup" >&2; exit 1; }

# Qt 6.12 links the ICU that ships with Windows 10+; Wine has none, so give the prefix a stub (see the .c file)
STUB="$WINEPREFIX/drive_c/windows/system32/icuuc.dll"
[ "$STUB" -nt scripts/winbuild/icuuc_stub.c ] || x86_64-w64-mingw32-gcc -shared -O2 -s -o "$STUB" scripts/winbuild/icuuc_stub.c

VERSION="$(python3 -c "import yaml;print(yaml.safe_load(open('config/settings.yaml'))['app']['version'])")"
echo "[build] Cybrix $VERSION (Windows x64)"
wine "$WINPY" -m PyInstaller --noconfirm --clean --distpath dist/windows --workpath build/windows cybrix_ai.spec
APP=dist/windows/cybrix-ai
[ -f "$APP/cybrix-ai.exe" ] || { echo "[build] PyInstaller produced no $APP/cybrix-ai.exe" >&2; exit 1; }
if find "$APP" -iname 'icuuc.dll' | grep -q .; then
  echo "[build] the build-time ICU stub got bundled; refusing to package it" >&2; exit 1
fi

makensis -V2 -DAppVersion="$VERSION" -DAppDir="../$APP" scripts/cybrix.nsi
INSTALLER="dist/Cybrix-Setup-$VERSION.exe"
(cd dist && sha256sum "$(basename "$INSTALLER")" > SHA256SUMS-windows)
echo "[build] $INSTALLER ($(du -h "$INSTALLER" | cut -f1)), unsigned: sign it (osslsigncode/signtool) before a public release"
