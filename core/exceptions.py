"""Custom exception hierarchy for Cybrix AI."""


class CybrixError(Exception):
    """Base exception for all Cybrix-specific errors."""
    pass


class ConfigurationError(CybrixError):
    """Raised when configuration is invalid or missing."""
    pass


class AIProviderError(CybrixError):
    """Errors from AI model providers."""
    pass


class PluginLoadError(CybrixError):
    """Failure to load a plugin."""
    pass


class RepositoryError(CybrixError):
    """Database or storage errors."""
    pass


class AnalysisError(CybrixError):
    """Error during an analysis task."""
    pass


class SecurityVaultError(CybrixError):
    """Error accessing the secure vault."""
    pass


class BackendError(CybrixError):
    """Error talking to the Cybrix server (REST or WebSocket)."""

    def __init__(self, message: str, status_code: int | None = None, errors: list | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.errors = errors or []


class AuthenticationError(BackendError):
    """Credentials or device token rejected by the server."""
    pass


class BackendUnavailableError(BackendError):
    """Server unreachable (network error, timeout, 5xx)."""
    pass


class InsecureTransportError(BackendError):
    """Refused to send credentials over an unencrypted connection to a remote host."""
    pass


class RagUnavailableError(CybrixError):
    """Optional RAG dependencies (chromadb / sentence-transformers) are not installed."""
