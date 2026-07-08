"""Test configuration loader."""
import yaml
import tempfile
import os
from core.config import ConfigLoader, AppConfig

def test_config_from_yaml():
    yaml_data = {
        "app": {"name": "Test", "version": "0.2"},
        "default_model": "llama3",
        "ai_providers": {
            "ollama": {"enabled": True, "model": "llama3"}
        },
        "ui": {"theme": "light"}
    }
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml.dump(yaml_data, f)
        f.flush()
        config = ConfigLoader.load(f.name)
    assert config.name == "Test"
    assert config.ui.theme == "light"
    assert config.ai_providers["ollama"].enabled == True