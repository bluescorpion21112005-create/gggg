"""Structured logging configuration with rotating file handler and full traceback support."""
import logging
import logging.config
import logging.handlers
from pathlib import Path
from typing import Optional

from core.config import LoggingConfig

# Maximum log file size: 5 MB; keep 3 backups
_MAX_BYTES = 5 * 1024 * 1024
_BACKUP_COUNT = 3


def setup_logging(config: LoggingConfig, log_file: Optional[Path] = None) -> None:
    """Configure root logger with console + optional rotating file output.

    Every exception includes a full traceback via the 'detailed' formatter.
    """
    handlers: dict = {
        "console": {
            "class": "logging.StreamHandler",
            "level": config.level,
            "formatter": "detailed",
            "stream": "ext://sys.stdout",
        }
    }

    file_path = log_file or (Path(config.file) if config.file else None)
    if file_path:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        handlers["file"] = {
            "class": "logging.handlers.RotatingFileHandler",
            "level": config.level,
            "formatter": "detailed",
            "filename": str(file_path),
            "maxBytes": _MAX_BYTES,
            "backupCount": _BACKUP_COUNT,
            "encoding": "utf-8",
        }

    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "detailed": {
                "format": "%(asctime)s [%(levelname)-8s] %(name)s:%(lineno)d — %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            }
        },
        "handlers": handlers,
        "loggers": {
            "": {
                "handlers": list(handlers.keys()),
                "level": config.level,
                "propagate": False,
            },
            "cybrix": {
                "handlers": list(handlers.keys()),
                "level": config.level,
                "propagate": False,
            },
            # Silence noisy third-party loggers
            "chromadb": {"level": "WARNING", "propagate": True},
            "sentence_transformers": {"level": "WARNING", "propagate": True},
            "httpx": {"level": "WARNING", "propagate": True},
            "openai": {"level": "WARNING", "propagate": True},
        },
    }
    logging.config.dictConfig(logging_config)
