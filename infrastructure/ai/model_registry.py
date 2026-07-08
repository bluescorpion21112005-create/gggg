"""Registry aggregating models from all configured providers."""
from domain.interfaces.ai_provider import AIProvider
from typing import Dict

class ModelRegistry:
    def __init__(self, providers: Dict[str, AIProvider]):
        self._providers = providers

    async def list_all_models(self) -> Dict[str, list[str]]:
        result = {}
        for name, provider in self._providers.items():
            try:
                models = await provider.list_models()
                result[name] = models
            except Exception as e:
                # Log and skip provider if listing fails
                result[name] = [f"error: {e}"]
        return result