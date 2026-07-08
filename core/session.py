"""Session and conversation memory management."""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID, uuid4

from domain.interfaces.repository import Repository
from core.event_bus import event_bus

from injector import inject
logger = logging.getLogger(__name__)


class ChatSession:
    """Holds conversation messages and metadata."""
    def __init__(self, session_id: UUID = None, title: str = "New Chat"):
        self.id = session_id or uuid4()
        self.title = title
        self.messages: List[dict] = []  # list of {"role": str, "content": str, "timestamp": datetime}
        self.created_at = datetime.utcnow()
        self.updated_at = self.created_at

    def add_message(self, role: str, content: str) -> None:
        self.messages.append({
            "role": role,
            "content": content,
            "timestamp": datetime.utcnow(),
        })
        self.updated_at = datetime.utcnow()

    def get_context(self, max_tokens: int = 4000) -> str:
        """Build a prompt context from the conversation history."""
        # Simple concatenation; will be enhanced with token counting.
        context = ""
        for msg in self.messages:
            context += f"{msg['role'].capitalize()}: {msg['content']}\n"
        return context[-max_tokens:]  # rough truncation


class SessionManager:
    """Manages multiple chat sessions, with persistence."""
    @inject
    def __init__(self, repository: Repository):
        self._repo = repository
        self._sessions: Dict[UUID, ChatSession] = {}
        self._active_session_id: Optional[UUID] = None

    def create_session(self, title: str = "New Chat") -> ChatSession:
        session = ChatSession(title=title)
        self._sessions[session.id] = session
        self._active_session_id = session.id
        event_bus.emit("session_created", session)
        logger.info(f"Created session {session.id}")
        return session

    def get_active_session(self) -> Optional[ChatSession]:
        return self._sessions.get(self._active_session_id) if self._active_session_id else None

    def switch_session(self, session_id: UUID) -> None:
        if session_id in self._sessions:
            self._active_session_id = session_id
            event_bus.emit("session_switched", self._sessions[session_id])
        else:
            logger.error(f"Session {session_id} not found")

    def list_sessions(self) -> List[ChatSession]:
        return list(self._sessions.values())

    def delete_session(self, session_id: UUID) -> None:
        if session_id in self._sessions:
            del self._sessions[session_id]
            if self._active_session_id == session_id:
                self._active_session_id = None
            event_bus.emit("session_deleted", session_id)
            logger.info(f"Deleted session {session_id}")