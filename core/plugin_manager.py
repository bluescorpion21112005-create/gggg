"""Plugin manager: discovers and loads external analyzers/agents."""
from __future__ import annotations

import importlib
import importlib.util
import logging
import sys
from pathlib import Path
from typing import List, Type

from domain.plugin_base import PluginBase
from core.exceptions import PluginLoadError

logger = logging.getLogger(__name__)


class PluginManager:
    """Scans a directory for Python modules containing subclasses of PluginBase."""

    def __init__(self, plugins_dir: str = "plugins"):
        self._plugins_dir = Path(plugins_dir)
        self._loaded_plugins: List[Type[PluginBase]] = []

    def discover_plugins(self) -> List[Type[PluginBase]]:
        """Find and load all valid plugin classes."""
        if not self._plugins_dir.exists():
            logger.warning(f"Plugins directory '{self._plugins_dir}' not found. Skipping plugin discovery.")
            return []

        loaded = []
        for file_path in self._plugins_dir.glob("*.py"):
            if file_path.name.startswith("_"):
                continue
            module_name = file_path.stem
            try:
                # Load module dynamically
                spec = importlib.util.spec_from_file_location(module_name, file_path)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[module_name] = module
                    spec.loader.exec_module(module)
                    # Find all PluginBase subclasses
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if isinstance(attr, type) and issubclass(attr, PluginBase) and attr is not PluginBase:
                            loaded.append(attr)
                            logger.info(f"Loaded plugin: {attr.__name__} from {file_path}")
            except Exception as e:
                logger.error(f"Failed to load plugin from {file_path}: {e}")
                raise PluginLoadError(f"Error loading {file_path}") from e

        self._loaded_plugins = loaded
        return loaded

    def get_plugins(self) -> List[Type[PluginBase]]:
        return self._loaded_plugins