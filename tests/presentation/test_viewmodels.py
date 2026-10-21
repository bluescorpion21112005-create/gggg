"""ViewModel tests using pytest-qt."""
import pytest
from PySide6.QtCore import QTimer
from presentation.viewmodels.chat_viewmodel import ChatViewModel
from application.orchestrator import Orchestrator
from core.session import SessionManager

@pytest.fixture
def session_manager():
    # Need a real repository mock? SessionManager takes Repository, we can use mock
    from unittest.mock import MagicMock
    repo = MagicMock()
    return SessionManager(repo)

@pytest.mark.asyncio
async def test_chat_viewmodel_send_message(qapp, mock_ai_provider, session_manager, test_repo):
    orch = Orchestrator(mock_ai_provider, repository=test_repo)
    from application.agents.chat_agent import ChatAgent
    orch.register_agent("chat", ChatAgent(mock_ai_provider))
    vm = ChatViewModel(orch, session_manager)
    # Connect signal spy
    messages = []
    vm.messages_changed.connect(lambda msgs: messages.extend(msgs))
    await vm.send_message("Hello")
    # Wait for async completion (qasync processes signals)
    QTimer.singleShot(100, lambda: None)  # not perfect, we'll need a real async test
    # For demonstration, we just check that messages list grew
    assert len(vm.messages) >= 2  # user + assistant
    assert any("Mock" in msg['content'] for msg in vm.messages)