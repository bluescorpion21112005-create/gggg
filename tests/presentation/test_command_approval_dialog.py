from PySide6.QtCore import Qt

from domain.interfaces.backend import ApprovalDecision
from presentation.widgets.command_approval_dialog import CommandApprovalDialog, QtCommandApprover
from presentation.widgets.notification_widget import ToastManager

COMMAND = {"command_id": "c1", "type": "log_analysis", "payload": {"file_path": "/var/log/auth.log"},
           "server": "https://cybrix.example"}


def test_buttons_emit_decisions(qapp, qtbot):
    for button, expected in (("_once_btn", "allow_once"), ("_always_btn", "allow_always"), ("_deny_btn", "deny")):
        dialog = CommandApprovalDialog(COMMAND, timeout=30)
        qtbot.addWidget(dialog)
        with qtbot.waitSignal(dialog.decided) as sig:
            qtbot.mouseClick(getattr(dialog, button), Qt.LeftButton)
        assert sig.args == [expected]


def test_deny_is_default_and_countdown_auto_denies(qapp, qtbot):
    dialog = CommandApprovalDialog(COMMAND, timeout=1)
    qtbot.addWidget(dialog)
    assert dialog._deny_btn.isDefault()
    with qtbot.waitSignal(dialog.decided, timeout=3000) as sig:
        dialog.show()
    assert sig.args == ["deny"]


def test_closing_window_denies(qapp, qtbot):
    dialog = CommandApprovalDialog(COMMAND, timeout=30)
    qtbot.addWidget(dialog)
    dialog.show()
    with qtbot.waitSignal(dialog.decided) as sig:
        dialog.close()
    assert sig.args == ["deny"]


async def test_qt_approver_resolves_from_dialog(qapp, qtbot):
    import asyncio
    from PySide6.QtWidgets import QApplication

    approver = QtCommandApprover()
    task = asyncio.ensure_future(approver.request_approval(COMMAND, timeout=30))
    await asyncio.sleep(0.05)
    dialog = next(w for w in QApplication.topLevelWidgets()
                  if isinstance(w, CommandApprovalDialog) and w.isVisible())
    dialog._once_btn.click()
    assert await asyncio.wait_for(task, 2) is ApprovalDecision.ALLOW_ONCE


def test_toasts_stack_and_cap(qapp, qtbot):
    from PySide6.QtWidgets import QWidget

    host = QWidget()
    host.resize(900, 600)
    qtbot.addWidget(host)
    toasts = ToastManager(host)
    shown = [toasts.show(f"t{i}", "body <b>not html</b>", "success") for i in range(6)]
    assert len(toasts._toasts) == ToastManager.MAX_VISIBLE
    ys = [t.y() for t in toasts._toasts]
    assert ys == sorted(ys)
    from PySide6.QtWidgets import QLabel
    body = [l for l in shown[-1].findChildren(QLabel) if l.objectName() == "toastBody"][0]
    assert body.textFormat() == Qt.PlainText  # server text is never rendered as HTML
