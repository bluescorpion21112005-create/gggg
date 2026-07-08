# -*- mode: python ; coding: utf-8 -*-
import sys
from pathlib import Path

block_cipher = None

# Determine base path
BASE_DIR = Path(__file__).parent

a = Analysis(
    ['main.py'],
    pathex=[str(BASE_DIR)],
    binaries=[],
    datas=[
        ('config', 'config'),          # config folder
        ('plugins', 'plugins'),        # plugins folder
        ('presentation/theme', 'presentation/theme'),   # QSS files
        ('presentation/assets', 'presentation/assets'), # icons
    ],
    hiddenimports=[
        'PySide6.QtCore', 'PySide6.QtGui', 'PySide6.QtWidgets',
        'PySide6.QtCharts',
        'openai', 'ollama', 'chromadb', 'sentence_transformers',
        'pefile', 'pypdf', 'docx', 'markdown', 'lxml', 'reportlab',
        'validators', 'keyring', 'yaml', 'aiosqlite', 'psutil',
        'injector', 'qasync', 'magic',
        # Include all parsers and analyzers
        'infrastructure.parsers.evtx_parser',
        'infrastructure.parsers.syslog_parser',
        'infrastructure.parsers.apache_parser',
        'infrastructure.parsers.nginx_parser',
        'infrastructure.parsers.firewall_parser',
        'infrastructure.parsers.json_parser',
        'infrastructure.parsers.csv_parser',
        'infrastructure.analyzers.malware.pe_analyzer',
        'infrastructure.analyzers.ioc.ioc_validator',
        'infrastructure.rag.document_loader',
        'infrastructure.rag.chunker',
        'infrastructure.rag.embedder',
        'infrastructure.rag.vector_store',
        'infrastructure.reporting.pdf_generator',
        'infrastructure.reporting.markdown_generator',
        'infrastructure.reporting.html_generator',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='cybrix-ai',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,   # Hide console on Windows; on Linux keep for logs
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)