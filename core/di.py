"""Dependency Injection container configuration using injector."""
from __future__ import annotations

import logging
from typing import List

from injector import Module, provider, singleton

from core.config import AppConfig
from core.exceptions import ConfigurationError
from core.plugin_manager import PluginManager
from core.session import SessionManager
from core.gpu_monitor import GPUManager
from core.event_bus import EventBus, event_bus
from domain.interfaces.ai_provider import AIProvider
from domain.interfaces.repository import Repository
from domain.interfaces.log_parser import LogParser
from infrastructure.ai.provider_factory import ProviderFactory
from infrastructure.ai.model_registry import ModelRegistry
from infrastructure.db.sqlite_repository import SQLiteRepository
from infrastructure.parsers.evtx_parser import EVTXParser
from infrastructure.parsers.syslog_parser import SyslogParser
from infrastructure.parsers.apache_parser import ApacheParser
from infrastructure.parsers.nginx_parser import NginxParser
from infrastructure.parsers.json_parser import JSONParser
from infrastructure.parsers.csv_parser import CSVParser
from infrastructure.parsers.firewall_parser import FirewallParser
from application.orchestrator import Orchestrator
from application.agents.chat_agent import ChatAgent
from application.agents.log_agent import LogAgent
from application.agents.malware_agent import MalwareAgent
from application.agents.ioc_agent import IOCAgent
from application.agents.threat_hunting_agent import ThreatHuntingAgent
from application.agents.rag_agent import RAGAgent
from application.agents.report_agent import ReportAgent
from application.use_cases.log_analysis_use_case import LogAnalysisUseCase
from application.use_cases.ioc_analysis_use_case import IOCAnalysisUseCase
from application.use_cases.malware_analysis_use_case import MalwareAnalysisUseCase
from application.use_cases.threat_hunting_use_case import ThreatHuntingUseCase
from application.use_cases.rag_use_case import RAGUseCase
from application.use_cases.report_use_case import ReportUseCase
from infrastructure.rag.embedder import Embedder
from infrastructure.rag.vector_store import VectorStore
from infrastructure.reporting.pdf_generator import PdfReportGenerator
from infrastructure.reporting.markdown_generator import MarkdownReportGenerator
from infrastructure.reporting.html_generator import HtmlReportGenerator

# ViewModel imports
from presentation.viewmodels.dashboard_viewmodel import DashboardViewModel
from presentation.viewmodels.chat_viewmodel import ChatViewModel
from presentation.viewmodels.settings_viewmodel import SettingsViewModel
from presentation.viewmodels.log_analysis_viewmodel import LogAnalysisViewModel
from presentation.viewmodels.malware_analysis_viewmodel import MalwareAnalysisViewModel
from presentation.viewmodels.ioc_viewmodel import IOCViewModel
from presentation.viewmodels.rag_viewmodel import RAGViewModel
from presentation.viewmodels.report_viewmodel import ReportViewModel

logger = logging.getLogger(__name__)


class CybrixModule(Module):
    """DI module that configures all bindings."""

    def __init__(self, config: AppConfig):
        self._config = config

    def configure(self, binder) -> None:
        # ── Core ────────────────────────────────────────────────────────────
        binder.bind(AppConfig, to=self._config, scope=singleton)
        binder.bind(EventBus, to=event_bus, scope=singleton)

        # NOTE: GPUManager, PluginManager, Repository, AIProvider, ModelRegistry,
        # and Orchestrator are wired via @provider methods below — no binder.bind()
        # for those to avoid double-binding conflicts.

        # ── Session Manager ──────────────────────────────────────────────────
        binder.bind(SessionManager, to=SessionManager, scope=singleton)

        # ── RAG components ───────────────────────────────────────────────────
        binder.bind(Embedder, to=Embedder, scope=singleton)
        binder.bind(VectorStore, to=VectorStore, scope=singleton)

        # ── Report generators ────────────────────────────────────────────────
        binder.bind(PdfReportGenerator, to=PdfReportGenerator, scope=singleton)
        binder.bind(MarkdownReportGenerator, to=MarkdownReportGenerator, scope=singleton)
        binder.bind(HtmlReportGenerator, to=HtmlReportGenerator, scope=singleton)

        # ── Use Cases (explicit bindings prevent silent resolution failures) ──
        binder.bind(IOCAnalysisUseCase, to=IOCAnalysisUseCase, scope=singleton)
        binder.bind(MalwareAnalysisUseCase, to=MalwareAnalysisUseCase, scope=singleton)
        binder.bind(ThreatHuntingUseCase, to=ThreatHuntingUseCase, scope=singleton)
        binder.bind(RAGUseCase, to=RAGUseCase, scope=singleton)
        binder.bind(ReportUseCase, to=ReportUseCase, scope=singleton)

        # ── Agents ────────────────────────────────────────────────────────────
        binder.bind(ChatAgent, to=ChatAgent, scope=singleton)
        binder.bind(MalwareAgent, to=MalwareAgent, scope=singleton)
        binder.bind(IOCAgent, to=IOCAgent, scope=singleton)
        binder.bind(ThreatHuntingAgent, to=ThreatHuntingAgent, scope=singleton)
        binder.bind(RAGAgent, to=RAGAgent, scope=singleton)
        binder.bind(ReportAgent, to=ReportAgent, scope=singleton)

        # ── ViewModels ────────────────────────────────────────────────────────
        binder.bind(DashboardViewModel, to=DashboardViewModel, scope=singleton)
        binder.bind(ChatViewModel, to=ChatViewModel, scope=singleton)
        binder.bind(SettingsViewModel, to=SettingsViewModel, scope=singleton)
        binder.bind(LogAnalysisViewModel, to=LogAnalysisViewModel, scope=singleton)
        binder.bind(MalwareAnalysisViewModel, to=MalwareAnalysisViewModel, scope=singleton)
        binder.bind(IOCViewModel, to=IOCViewModel, scope=singleton)
        binder.bind(RAGViewModel, to=RAGViewModel, scope=singleton)
        binder.bind(ReportViewModel, to=ReportViewModel, scope=singleton)

    # ── Provider methods (complex construction logic) ─────────────────────────

    @provider
    @singleton
    def provide_gpu_manager(self, config: AppConfig) -> GPUManager:
        """Create GPUManager with config-driven ROCm preference."""
        return GPUManager(prefer_rocm=config.gpu.prefer_rocm)

    @provider
    @singleton
    def provide_plugin_manager(self, config: AppConfig) -> PluginManager:
        """Create PluginManager with config-driven plugins directory."""
        return PluginManager(plugins_dir=config.plugins_dir)

    @provider
    @singleton
    def provide_repository(self, config: AppConfig) -> Repository:
        """Create SQLiteRepository with WAL mode for concurrent access."""
        return SQLiteRepository(db_path=config.database_url)

    @provider
    @singleton
    def provide_ai_provider(self, config: AppConfig) -> AIProvider:
        """Select and build the active AI provider via ProviderFactory.

        The factory supports all configured providers:
        ollama, openai, huggingface, openrouter, lm_studio, vllm, fireworks.
        Provider selection is entirely config-driven — no code changes needed
        to switch providers.
        """
        factory = ProviderFactory()
        for prov_name, prov_conf in config.ai_providers.items():
            if prov_conf.enabled:
                logger.info("Activating AI provider: %s (model: %s)", prov_name, prov_conf.model)
                try:
                    return factory.create(prov_name, prov_conf)
                except Exception as exc:
                    logger.error(
                        "Failed to initialise provider '%s': %s. Trying next.", prov_name, exc
                    )
                    continue
        raise ConfigurationError(
            "No AI provider could be initialised. "
            "Check settings.yaml and ensure at least one provider is enabled and reachable."
        )

    @provider
    @singleton
    def provide_model_registry(self, ai_provider: AIProvider, config: AppConfig) -> ModelRegistry:
        """Create ModelRegistry keyed by provider name from config — no isinstance checks."""
        providers: dict[str, AIProvider] = {}
        for prov_name, prov_conf in config.ai_providers.items():
            if prov_conf.enabled:
                # The active provider is registered under its config name.
                providers[prov_name] = ai_provider
        return ModelRegistry(providers)

    @provider
    @singleton
    def provide_orchestrator(
        self, ai_provider: AIProvider, repository: Repository, config: AppConfig
    ) -> Orchestrator:
        """Create Orchestrator wired to active provider, repository, and configured default model."""
        return Orchestrator(ai_provider, repository=repository, default_model=config.default_model)

    @provider
    @singleton
    def provide_log_agent(self, ai_provider: AIProvider, repository: Repository) -> LogAgent:
        """Build LogAgent with the full set of log parsers and repository for persistence."""
        parsers = [
            EVTXParser(),
            SyslogParser(),
            ApacheParser(),
            NginxParser(),
            JSONParser(),
            CSVParser(),
            FirewallParser(),
        ]
        use_case = LogAnalysisUseCase(parsers, ai_provider)
        return LogAgent(use_case, repository)
