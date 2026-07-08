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