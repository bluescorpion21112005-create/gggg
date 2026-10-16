"""Shared fixtures for all tests."""
import pytest
import tempfile
import os

# Tests must never touch the real per-user directories (settings, DB, logs): see core/paths.py.
os.environ.setdefault("CYBRIX_HOME", tempfile.mkdtemp(prefix="cybrix-tests-home-"))
from typing import AsyncGenerator
from unittest.mock import AsyncMock
from domain.interfaces.ai_provider import AIProvider
from core.config import AppConfig, AIProviderConfig, UIConfig, LoggingConfig, GPUConfig
from infrastructure.db.sqlite_repository import SQLiteRepository
from injector import Injector, provider, singleton
from core.di import CybrixModule


@pytest.fixture
def test_config() -> AppConfig:
    return AppConfig(
        name="Cybrix Test",
        version="0.1.0",
        default_model="test-model",
        ai_providers={
            "ollama": AIProviderConfig(
                provider="ollama",
                enabled=True,
                model="test-model",
                host="http://localhost:11434"
            )
        },
        ui=UIConfig(theme="dark"),
        logging=LoggingConfig(level="DEBUG", file=None),
        gpu=GPUConfig(prefer_rocm=False, fallback_to_cpu=True),
        database_url="sqlite:///test_cybrix.db",
        plugins_dir="plugins"
    )


@pytest.fixture
def mock_ai_provider():
    """AIProvider mock that yields preset tokens."""
    provider = AsyncMock(spec=AIProvider)
    async def generate(prompt: str, model: str = "test-model", **kwargs) -> AsyncGenerator[str, None]:
        # Simple echo for testing
        for token in ["Mock ", "response ", "streamed."]:
            yield token
    provider.generate = generate
    provider.list_models = AsyncMock(return_value=["test-model"])
    return provider


@pytest.fixture
async def test_repo(tmp_path):
    """Provide an SQLite repository using a temporary database."""
    db_path = tmp_path / "test_cybrix.db"
    return SQLiteRepository(str(db_path))  # creates the schema in __init__


@pytest.fixture
def injector_test(test_config, mock_ai_provider):
    """Create injector with test config and mocked AI provider."""
    # Override the module to use mock AI provider
    class TestModule(CybrixModule):
        @provider
        @singleton
        def provide_ai_provider(self, config: AppConfig) -> AIProvider:
            return mock_ai_provider

    return Injector([TestModule(test_config)])


@pytest.fixture(scope="session")
def qapp():
    """Create a QApplication for UI tests."""
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app
    app.quit()