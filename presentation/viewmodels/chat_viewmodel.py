"""ViewModel for the AI Chat interface."""
import logging
from typing import List
from uuid import UUID

from PySide6.QtCore import Signal, Property, Slot
from qasync import asyncSlot
from injector import inject

from application.orchestrator import Orchestrator
from core.session import SessionManager
from .base_viewmodel import BaseViewModel

logger = logging.getLogger(__name__)


class ChatViewModel(BaseViewModel):
    """Manages chat conversations, message sending, and streaming responses."""

    messages_changed = Signal(list)
    active_session_changed = Signal(str)
    sessions_list_changed = Signal(list)

    @inject
    def __init__(self, orchestrator: Orchestrator, session_manager: SessionManager):
        super().__init__()
        self._orchestrator = orchestrator
        self._session_manager = session_manager

        # Ensure there is always an active session
        active = self._session_manager.get_active_session()
        if not active:
            active = self._session_manager.create_session("New Chat")
        self._active_session = active

        self._emit_messages()
        self._emit_sessions()

    @Property(str, notify=active_session_changed)
    def active_session_title(self) -> str:
        return self._active_session.title

    @Property(list, notify=messages_changed)
    def messages(self) -> List[dict]:
        return self._active_session.messages

    @asyncSlot(str)
    async def send_message(self, message: str):
        """Send a user message and stream the AI response."""
        if not message.strip():
            return

        session = self._active_session
        session.add_message("user", message)
        self._emit_messages()
        self.is_busy = True
        logger.info(
            "ChatViewModel.send_message: session=%s, msg_len=%d", session.id, len(message)
        )

        # Add placeholder for the assistant response so the UI shows it immediately
        session.add_message("assistant", "")
        self._emit_messages()

        response = ""
        try:
            async for token in self._orchestrator.dispatch_stream(
                "chat",
                {"message": message, "context": session.get_context()},
                model=self._orchestrator.default_model,
            ):
                response += token
                session.messages[-1]["content"] = response
                self._emit_messages()
            logger.info(
                "ChatViewModel.send_message: response complete (%d chars)", len(response)
            )
        except Exception as exc:
            logger.error(
                "ChatViewModel.send_message failed: %s", exc, exc_info=True
            )
            self.error_occurred.emit(f"Chat error: {exc}")
            session.messages[-1]["content"] = f"[Error: {exc}]"
            self._emit_messages()
        finally:
            self.is_busy = False

    @Slot()
    def new_chat(self):
        session = self._session_manager.create_session("New Chat")
        self._active_session = session
        self._emit_messages()
        self._emit_sessions()
        self.active_session_changed.emit(session.title)
        logger.info("ChatViewModel: new session created (%s)", session.id)

    @Slot(str)
    def switch_session(self, session_id_str: str):
        try:
            sid = UUID(session_id_str)
            self._session_manager.switch_session(sid)
            self._active_session = self._session_manager.get_active_session()
            self._emit_messages()
            self.active_session_changed.emit(self._active_session.title)
        except Exception as exc:
            logger.error("ChatViewModel.switch_session failed: %s", exc)
            self.error_occurred.emit(f"Could not switch session: {exc}")

    @Slot(str)
    def delete_session(self, session_id_str: str):
        try:
            sid = UUID(session_id_str)
            self._session_manager.delete_session(sid)
            active = self._session_manager.get_active_session()
            if active is None:
                active = self._session_manager.create_session("New Chat")
            self._active_session = active
            self._emit_messages()
            self._emit_sessions()
        except Exception as exc:
            logger.error("ChatViewModel.delete_session failed: %s", exc)
            self.error_occurred.emit(f"Could not delete session: {exc}")

    # ── Private ───────────────────────────────────────────────────────────────

    def _emit_messages(self):
        self.messages_changed.emit(list(self._active_session.messages))

    def _emit_sessions(self):
        sessions = self._session_manager.list_sessions()
        summaries = [
            {"id": str(s.id), "title": s.title, "updated": s.updated_at.isoformat()}
            for s in sessions
        ]
        self.sessions_list_changed.emit(summaries)
