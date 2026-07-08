"""Plugin discovery base. All external analyzers should inherit from BaseAnalyzer."""
from domain.interfaces.analyzer import BaseAnalyzer

# Future: plugin manager will use this class to auto-discover analyzers.
PluginBase = BaseAnalyzer  # alias for clarity in the plugin system