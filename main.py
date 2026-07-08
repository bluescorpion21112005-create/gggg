"""Application entry point."""
import sys
import os
from pathlib import Path

# For PyInstaller bundles, resources are in _MEIPASS
if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    BUNDLE_DIR = Path(sys._MEIPASS)
else:
    BUNDLE_DIR = Path(__file__).resolve().parent

# Adjust config path to be relative to bundle
os.environ['CYBRIX_CONFIG_DIR'] = str(BUNDLE_DIR / 'config')

from core.bootstrap import main

if __name__ == "__main__":
    main()