#!/usr/bin/env bash
# Linux release build: PyInstaller one-folder → AppImage + .deb (+ SHA256SUMS).
#   scripts/build.sh                    → dist/Cybrix-<ver>-x86_64.AppImage, dist/cybrix_<ver>_amd64.deb
#   GPG_KEY=<id> scripts/build.sh       → also detached signatures (*.asc) for both
# Then sign the update manifest on the release machine (cybrix_ai: manage.py sign_release --output).
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-.venv/bin/python}"
VERSION="$("$PY" -c 'import yaml;print(yaml.safe_load(open("config/settings.yaml"))["app"]["version"])')"
ARCH="$(uname -m)"; DEB_ARCH=$([ "$ARCH" = aarch64 ] && echo arm64 || echo amd64)
say() { printf '\033[36m[build]\033[0m %s\n' "$*"; }

say "Cybrix $VERSION ($ARCH)"
rm -rf build/cybrix-ai dist/cybrix-ai dist/AppDir dist/deb
"$PY" -m PyInstaller --noconfirm --clean cybrix_ai.spec
du -sh dist/cybrix-ai | sed 's/^/[build] bundle size: /'

# ── AppImage ────────────────────────────────────────────────────────────────
APPDIR=dist/AppDir
mkdir -p "$APPDIR/usr/lib" "$APPDIR/usr/share/icons/hicolor/256x256/apps"
cp -a dist/cybrix-ai "$APPDIR/usr/lib/cybrix-ai"
cp presentation/assets/cybrix.png "$APPDIR/cybrix.png"
cp presentation/assets/cybrix.png "$APPDIR/usr/share/icons/hicolor/256x256/apps/cybrix.png"
sed -e 's#^Exec=.*#Exec=cybrix-ai#' -e 's#^Icon=.*#Icon=cybrix#' scripts/cybrix.desktop > "$APPDIR/cybrix.desktop"
cat > "$APPDIR/AppRun" <<'RUN'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/lib/cybrix-ai/cybrix-ai" "$@"
RUN
chmod +x "$APPDIR/AppRun"
TOOL="${APPIMAGETOOL:-$(command -v appimagetool || true)}"
if [ -z "$TOOL" ]; then
  TOOL=build/tools/appimagetool-$ARCH.AppImage
  if [ ! -x "$TOOL" ]; then
    say "downloading appimagetool"
    mkdir -p build/tools
    curl -fsSL -o "$TOOL" "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-$ARCH.AppImage"
    chmod +x "$TOOL"
  fi
fi
APPIMAGE="dist/Cybrix-$VERSION-$ARCH.AppImage"
ARCH="$ARCH" APPIMAGE_EXTRACT_AND_RUN=1 "$TOOL" --no-appstream "$APPDIR" "$APPIMAGE" >/dev/null
say "AppImage: $APPIMAGE"

# ── .deb (installs to /opt/cybrix-ai, desktop entry + icon) ────────────────
DEB=dist/deb
mkdir -p "$DEB/DEBIAN" "$DEB/opt" "$DEB/usr/share/applications" "$DEB/usr/share/icons/hicolor/256x256/apps" "$DEB/usr/bin"
cp -a dist/cybrix-ai "$DEB/opt/cybrix-ai"
cp scripts/cybrix.desktop "$DEB/usr/share/applications/cybrix.desktop"
sed -i 's#^Icon=.*#Icon=cybrix#' "$DEB/usr/share/applications/cybrix.desktop"
cp presentation/assets/cybrix.png "$DEB/usr/share/icons/hicolor/256x256/apps/cybrix.png"
ln -sf /opt/cybrix-ai/cybrix-ai "$DEB/usr/bin/cybrix-ai"
cat > "$DEB/DEBIAN/control" <<CTRL
Package: cybrix
Version: $VERSION
Section: net
Priority: optional
Architecture: $DEB_ARCH
Maintainer: Cybrix <support@cybrix.local>
Depends: libegl1, libxkbcommon-x11-0, libxcb-cursor0, libdbus-1-3, libfontconfig1
Description: Cybrix AI desktop security agent
 Log/IOC/malware analysis with AI, connected to your Cybrix server.
CTRL
DEBFILE="dist/cybrix_${VERSION}_${DEB_ARCH}.deb"
dpkg-deb --root-owner-group --build "$DEB" "$DEBFILE" >/dev/null
say "deb: $DEBFILE"

( cd dist && sha256sum "$(basename "$APPIMAGE")" "$(basename "$DEBFILE")" > SHA256SUMS )
if [ -n "${GPG_KEY:-}" ]; then
  for f in "$APPIMAGE" "$DEBFILE"; do gpg --batch --yes --local-user "$GPG_KEY" --armor --detach-sign "$f"; done
  say "GPG signatures written"
fi
cat dist/SHA256SUMS
