#!/bin/bash
# Build script for Cybrix AI distribution

echo "Cleaning previous build..."
rm -rf build dist

echo "Running PyInstaller..."
pyinstaller --clean cybrix_ai.spec

# Copy additional runtime files that PyInstaller might miss (e.g., sentence-transformers models)
echo "Copying sentence-transformers models..."
# If you downloaded models locally, copy them to dist/cybrix-ai/_internal/ or the appropriate location.
# For this build, we rely on sentence-transformers' default cache.

echo "Creating AppImage (optional)..."
# This is a placeholder: use linuxdeploy or appimage-builder.
# For now, we'll just create a simple tar.gz
cd dist
tar -czf cybrix-ai-linux-x86_64.tar.gz cybrix-ai/
echo "Distribution archive created: dist/cybrix-ai-linux-x86_64.tar.gz"
cd ..

echo "Build complete."