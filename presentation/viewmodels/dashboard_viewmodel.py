"""ViewModel for the Dashboard view."""
import asyncio
import logging
from typing import Optional

from injector import inject
from PySide6.QtCore import QTimer, Signal

from core.event_bus import event_bus
from core.gpu_monitor import GPUManager, GPUMetrics
from application.orchestrator import Orchestrator
from domain.interfaces.repository import Repository
from domain.entities import AnalysisResult
from .base_viewmodel import BaseViewModel

logger = logging.getLogger(__name__)


class DashboardViewModel(BaseViewModel):
    """Provides data for dashboard widgets.

    All potentially blocking operations (GPU polling, DB queries, provider health)
    are dispatched as asyncio tasks so the Qt event loop is never blocked.
    """

    gpu_metrics_updated = Signal(GPUMetrics)
    recent_analyses_updated = Signal(list)
    gpu_ollama_status = Signal(dict)

    @inject
    def __init__(
        self,
        gpu_manager: GPUManager,
        repository: Repository,
        orchestrator: Orchestrator,
    ) -> None:
        super().__init__()
        self._gpu_manager = gpu_manager
        self._repository = repository
        self._orchestrator = orchestrator
        self._gpu_status_task: Optional[asyncio.Task] = None
        self._recent_analyses_task: Optional[asyncio.Task] = None

        # GPU/CPU monitoring: fires every 2 seconds
        self._monitor_timer = QTimer()
        self._monitor_timer.timeout.connect(self._schedule_metrics_update)
        self._monitor_timer.start(2000)

        # Recent analyses refresh: fires every 5 seconds
        self._analysis_timer = QTimer()
        self._analysis_timer.timeout.connect(self._schedule_analyses_update)
        self._analysis_timer.start(5000)

        # React to new analysis events
        event_bus.subscribe("analysis_completed", self._on_analysis_completed)

        # Kick off initial load after the event loop is running
        QTimer.singleShot(100, self._schedule_metrics_update)
        QTimer.singleShot(200, self._schedule_analyses_update)

    # ── Scheduling helpers ────────────────────────────────────────────────────

    def _schedule_task(
        self,
        coro_fn,
        task_attr: str,
    ) -> None:
        """Schedule an async coroutine as a task if none is already running."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            logger.debug("Event loop not running yet; skipping %s", coro_fn.__name__)
            return
        existing: Optional[asyncio.Task] = getattr(self, task_attr)
        if existing and not existing.done():
            return  # already in flight
        task = loop.create_task(coro_fn())
        task.add_done_callback(lambda t: self._handle_task_exception(t))
        setattr(self, task_attr, task)

    def _handle_task_exception(self, task: asyncio.Task) -> None:
        """Log unhandled exceptions from background tasks."""
        if not task.cancelled() and task.exception() is not None:
            logger.error(
                "Background task %s raised an exception: %s",
                task.get_name(),
                task.exception(),
                exc_info=task.exception(),
            )

    def _schedule_metrics_update(self) -> None:
        self._schedule_task(self._fetch_metrics, "_gpu_status_task")

    def _schedule_analyses_update(self) -> None:
        self._schedule_task(self._fetch_recent_analyses, "_recent_analyses_task")

    # ── Async workers ─────────────────────────────────────────────────────────

    async def _fetch_metrics(self) -> None:
        """Fetch GPU/CPU metrics off the main thread, then update provider health."""
        try:
            metrics = await self._gpu_manager.get_metrics_async()
            self.gpu_metrics_updated.emit(metrics)
        except Exception as exc:
            logger.error("Failed to get GPU metrics: %s", exc, exc_info=True)
            self.error_occurred.emit(f"Failed to get GPU metrics: {exc}")

        # Provider health check (non-blocking network call)
        try:
            status = await self._orchestrator.provider_health()
            if "error" not in status:
                self.gpu_ollama_status.emit(status)
            else:
                logger.debug("Provider health returned error: %s", status["error"])
        except Exception as exc:
            logger.debug("Provider health check failed: %s", exc)

    async def _fetch_recent_analyses(self) -> None:
        """Fetch recent analyses from repository and emit signal."""
        try:
            analyses = await self._repository.list_analyses(limit=10)
            self.recent_analyses_updated.emit(analyses)
        except Exception as exc:
            logger.error("Failed to fetch recent analyses: %s", exc, exc_info=True)
            self.error_occurred.emit(f"Failed to fetch analyses: {exc}")

    # ── Event bus handlers ────────────────────────────────────────────────────

    def _on_analysis_completed(self, result: AnalysisResult) -> None:
        """Immediately refresh list when a new analysis is completed."""
        self._schedule_analyses_update()

    # ── Actions ───────────────────────────────────────────────────────────────

    def run_quick_action(self, action: str) -> None:
        """Dispatch a quick action (e.g., 'New Malware Scan') to the orchestrator."""
        self.status_message.emit(f"Quick action '{action}' triggered.")
