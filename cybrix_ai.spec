# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for the Cybrix desktop app — one-folder build (fast start, required for AppImage,
# .deb, Inno Setup and the macOS .app). Build with scripts/build.sh (Linux), scripts/build_windows.ps1,
# scripts/build_macos.sh; CI: .github/workflows/release.yml.
#
# Not shipped: the optional RAG stack (chromadb / sentence-transformers / torch — requirements-rag.txt)
# and the FastAPI pentest gateway (backend/, cybrix_ai.py — requirements-gateway.txt).
import sys
from pathlib import Path

import yaml

BASE_DIR = Path(SPECPATH)
VERSION = yaml.safe_load((BASE_DIR / "config" / "settings.yaml").read_text())["app"]["version"]
ICON = BASE_DIR / "presentation" / "assets" / ("cybrix.ico" if sys.platform == "win32" else "cybrix-512.png")

a = Analysis(
    ["main.py"],
    pathex=[str(BASE_DIR)],
    binaries=[],
    datas=[
        ("config/settings.yaml", "config"),                 # seeds the user's settings on first run
        ("plugins", "plugins"),
        ("presentation/theme/*.qss", "presentation/theme"),
        ("presentation/assets", "presentation/assets"),
        ("presentation/i18n/*.qm", "presentation/i18n"),
    ],
    hiddenimports=[
        "PySide6.QtCharts",
        "qasync", "injector", "keyring.backends", "platformdirs",
        "sentry_sdk.integrations.logging", "sentry_sdk.integrations.threading",
        "cryptography.hazmat.primitives.asymmetric.ed25519",
        # parsers/analyzers/reporters are wired in core/di.py; listed so a refactor to dynamic
        # loading cannot silently drop them from the bundle
        "infrastructure.parsers.evtx_parser", "infrastructure.parsers.syslog_parser",
        "infrastructure.parsers.apache_parser", "infrastructure.parsers.nginx_parser",
        "infrastructure.parsers.firewall_parser", "infrastructure.parsers.json_parser",
        "infrastructure.parsers.csv_parser",
        "infrastructure.analyzers.malware.pe_analyzer", "infrastructure.analyzers.ioc.ioc_validator",
        "infrastructure.reporting.pdf_generator", "infrastructure.reporting.markdown_generator",
        "infrastructure.reporting.html_generator",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter", "tests", "tests_live",
        "torch", "torchvision", "chromadb", "sentence_transformers", "transformers", "onnxruntime",
        "fastapi", "uvicorn", "starlette", "backend", "cybrix_ai",
        "PySide6.Qt3DCore", "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtMultimedia",
        "PySide6.QtQuick", "PySide6.QtQml", "PySide6.QtPdf", "PySide6.QtDesigner",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="cybrix-ai",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                       # UPX-packed binaries trigger antivirus false positives
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,          # macOS signing happens in scripts/build_macos.sh
    entitlements_file=None,
    icon=str(ICON),
)

coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="cybrix-ai")

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="Cybrix.app",
        icon=str(ICON),
        bundle_identifier="io.cybrix.desktop",
        version=VERSION,
        info_plist={
            "CFBundleShortVersionString": VERSION,
            "NSHighResolutionCapable": True,
            "LSMinimumSystemVersion": "11.0",
        },
    )
