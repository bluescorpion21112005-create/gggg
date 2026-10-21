"""Application entry point."""
# Settings, data and logs live in per-user OS directories (core/paths.py); the bundled
# config/settings.yaml only seeds the user's copy on first run. Set CYBRIX_CONFIG_DIR to use another
# settings directory (development: CYBRIX_CONFIG_DIR=config) or CYBRIX_HOME for a portable install.
from core.bootstrap import main

if __name__ == "__main__":
    main()