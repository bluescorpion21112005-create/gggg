#!/usr/bin/env bash
# macOS release build: PyInstaller .app → codesign (hardened runtime) → DMG → notarize + staple.
#   scripts/build_macos.sh
#   CODESIGN_IDENTITY="Developer ID Application: …" NOTARY_PROFILE=cybrix scripts/build_macos.sh
#   (store the notary profile once: xcrun notarytool store-credentials cybrix --apple-id … --team-id …)
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-.venv/bin/python}"
VERSION="$("$PY" -c 'import yaml;print(yaml.safe_load(open("config/settings.yaml"))["app"]["version"])')"
"$PY" -m PyInstaller --noconfirm --clean cybrix_ai.spec
APP=dist/Cybrix.app
if [ -n "${CODESIGN_IDENTITY:-}" ]; then
  codesign --force --deep --options runtime --timestamp --entitlements scripts/macos.entitlements \
    --sign "$CODESIGN_IDENTITY" "$APP"
  codesign --verify --strict --verbose=2 "$APP"
else
  echo "[build] unsigned .app (set CODESIGN_IDENTITY for a Developer ID signature)"
fi
DMG="dist/Cybrix-$VERSION-$(uname -m).dmg"
rm -f "$DMG"
hdiutil create -volname "Cybrix $VERSION" -srcfolder "$APP" -ov -format UDZO "$DMG"
if [ -n "${CODESIGN_IDENTITY:-}" ] && [ -n "${NOTARY_PROFILE:-}" ]; then
  codesign --sign "$CODESIGN_IDENTITY" --timestamp "$DMG"
  xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$DMG"
fi
shasum -a 256 "$DMG" > dist/SHA256SUMS-macos
echo "[build] $DMG"
