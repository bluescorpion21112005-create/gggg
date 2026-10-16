"""Device token persistence in the OS keyring (via Vault)."""
from __future__ import annotations

import logging
from typing import Optional

from infrastructure.security.vault import Vault

logger = logging.getLogger(__name__)

TOKEN_KEY = "cybrix_backend_token"
DEVICE_KEY = "cybrix_backend_device_id"
EXPIRES_KEY = "cybrix_backend_token_expires_at"


class TokenStore:
    """Holds the device token in memory and mirrors it to the keyring."""

    def __init__(self, vault: type[Vault] = Vault):
        self._vault = vault
        self._token: Optional[str] = None
        self._device_id: Optional[str] = None
        self._expires_at: Optional[str] = None
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        try:
            self._token = self._vault.get_api_key(TOKEN_KEY)
            self._device_id = self._vault.get_api_key(DEVICE_KEY)
            self._expires_at = self._vault.get_api_key(EXPIRES_KEY)
        except Exception as exc:  # keyring backend unavailable
            logger.warning("TokenStore: keyring unavailable: %s", exc)

    @property
    def token(self) -> Optional[str]:
        self._load()
        return self._token

    @property
    def device_id(self) -> Optional[str]:
        self._load()
        return self._device_id

    @property
    def expires_at(self) -> Optional[str]:
        """ISO-8601 expiry of the current token, if the server told us."""
        self._load()
        return self._expires_at

    def save(self, token: str, device_id: str, expires_at: Optional[str] = None) -> None:
        self._token, self._device_id, self._expires_at, self._loaded = token, device_id, expires_at, True
        try:
            self._vault.store_api_key(TOKEN_KEY, token)
            self._vault.store_api_key(DEVICE_KEY, device_id)
            if expires_at:
                self._vault.store_api_key(EXPIRES_KEY, expires_at)
            else:
                self._vault.delete_api_key(EXPIRES_KEY)
        except Exception as exc:
            logger.warning("TokenStore: could not persist token (kept in memory only): %s", exc)

    def clear(self) -> None:
        self._token = self._device_id = self._expires_at = None
        self._loaded = True
        try:
            self._vault.delete_api_key(TOKEN_KEY)
            self._vault.delete_api_key(DEVICE_KEY)
            self._vault.delete_api_key(EXPIRES_KEY)
        except Exception as exc:
            logger.warning("TokenStore: could not clear keyring: %s", exc)
