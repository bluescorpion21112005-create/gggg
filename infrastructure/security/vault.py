"""Secure storage for API keys using OS keyring and environment fallback."""
import keyring
import os

SERVICE_NAME = "CybrixAI"

class Vault:
    @staticmethod
    def store_api_key(provider: str, key: str) -> None:
        keyring.set_password(SERVICE_NAME, provider, key)

    @staticmethod
    def get_api_key(provider: str, env_var: str = None) -> str | None:
        # 1. Try OS keyring
        key = keyring.get_password(SERVICE_NAME, provider)
        if key:
            return key
        # 2. Try environment variable if specified
        if env_var:
            key = os.getenv(env_var)
            if key:
                return key
        return None

    @staticmethod
    def delete_api_key(provider: str) -> None:
        try:
            keyring.delete_password(SERVICE_NAME, provider)
        except keyring.errors.PasswordDeleteError:
            pass