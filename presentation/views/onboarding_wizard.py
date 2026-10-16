"""First-run wizard: server address, privacy choices, server-command policy.

Shown once, before the main window, so the chosen server is used from the first connection.
Nothing is shared until the user ticks it here or later in Settings (telemetry, network
connections and crash reports all start unticked).
"""
from __future__ import annotations

from PySide6.QtCore import QT_TRANSLATE_NOOP, Qt
from PySide6.QtWidgets import (QButtonGroup, QCheckBox, QHBoxLayout, QLabel, QLineEdit, QPushButton,
                               QRadioButton, QVBoxLayout, QWizard, QWizardPage)

from core.config import AppConfig
from infrastructure.remote.agent_settings import AgentSettings, validate_server_url


def check_server(url: str, verify_tls: bool = True, timeout: float = 5.0) -> tuple[bool, str, str]:
    """(ok, message, detail) — GET <url>/health/ with a short timeout (runs before the event loop).

    message is a translatable source string; detail is appended untranslated (error class, status).
    """
    import httpx

    try:
        url = validate_server_url(url)
    except ValueError as exc:
        return False, str(exc), ""
    try:
        resp = httpx.get(url + "/health/", timeout=timeout, verify=verify_tls, follow_redirects=False)
    except httpx.HTTPError as exc:
        return False, QT_TRANSLATE_NOOP("ServerPage", "Cannot reach the server."), type(exc).__name__
    if resp.status_code == 200 and resp.headers.get("content-type", "").startswith("application/json"):
        return True, QT_TRANSLATE_NOOP("ServerPage", "Server reachable."), ""
    return False, QT_TRANSLATE_NOOP("ServerPage", "Unexpected answer from the server."), f"HTTP {resp.status_code}"


class ServerPage(QWizardPage):
    def __init__(self, config: AppConfig):
        super().__init__()
        self._config = config
        self.setTitle(self.tr("Connect to your Cybrix server"))
        self.setSubTitle(self.tr("The address your administrator gave you. You can change it later in Settings."))
        layout = QVBoxLayout(self)
        self.url = QLineEdit(config.backend.base_url)
        self.url.setPlaceholderText("https://cybrix.example.com")
        test = QPushButton(self.tr("Test connection"))
        test.clicked.connect(self._test)
        row = QHBoxLayout()
        row.addWidget(self.url)
        row.addWidget(test)
        layout.addLayout(row)
        self.result = QLabel()
        self.result.setWordWrap(True)
        self.result.setTextFormat(Qt.PlainText)
        layout.addWidget(self.result)
        self.registerField("server_url*", self.url)

    def _test(self):
        ok, message, detail = check_server(self.url.text(), self._config.backend.verify_tls)
        self.result.setText(("✓ " if ok else "✗ ") + self.tr(message) + (f" ({detail})" if detail else ""))

    def validatePage(self) -> bool:
        try:
            self.url.setText(validate_server_url(self.url.text()))
        except ValueError as exc:
            self.result.setText("✗ " + self.tr(str(exc)))
            return False
        return True


class PrivacyPage(QWizardPage):
    def __init__(self, config: AppConfig):
        super().__init__()
        self.setTitle(self.tr("What may this computer share?"))
        self.setSubTitle(self.tr("Everything is off until you turn it on. Change it any time in Settings → Server."))
        layout = QVBoxLayout(self)
        self.telemetry = QCheckBox(self.tr("Health metrics: CPU, memory, disk and network usage"))
        self.netflows = QCheckBox(self.tr("Network connections (remote address, port, program) for threat detection"))
        self.crash = QCheckBox(self.tr("Anonymous crash reports"))
        self.crash.setEnabled(bool(config.sentry_dsn))
        for box in (self.telemetry, self.netflows, self.crash):
            layout.addWidget(box)
        note = QLabel(self.tr("File contents, documents and passwords are never sent."))
        note.setWordWrap(True)
        layout.addWidget(note)


class CommandsPage(QWizardPage):
    OPTIONS = (("ask", QT_TRANSLATE_NOOP("CommandsPage", "Ask me before running anything the server requests (recommended)")),
               ("allow_listed", QT_TRANSLATE_NOOP("CommandsPage", "Only run request types I have allowed permanently")),
               ("deny_all", QT_TRANSLATE_NOOP("CommandsPage", "Never run server requests")))

    def __init__(self):
        super().__init__()
        self.setTitle(self.tr("Requests from the server"))
        self.setSubTitle(self.tr("Your administrator can ask this app to analyse logs, IOCs or files."))
        layout = QVBoxLayout(self)
        self.group = QButtonGroup(self)
        for i, (key, label) in enumerate(self.OPTIONS):
            button = QRadioButton(self.tr(label))
            button.setProperty("policy", key)
            button.setChecked(i == 0)
            self.group.addButton(button)
            layout.addWidget(button)

    @property
    def policy(self) -> str:
        return self.group.checkedButton().property("policy")


class OnboardingWizard(QWizard):
    def __init__(self, config: AppConfig, settings: AgentSettings):
        super().__init__()
        self._settings = settings
        self.setWindowTitle(self.tr("Welcome to Cybrix"))
        self.server = ServerPage(config)
        self.privacy = PrivacyPage(config)
        self.commands = CommandsPage()
        for page in (self.server, self.privacy, self.commands):
            self.addPage(page)
        done = QWizardPage()
        done.setTitle(self.tr("All set"))
        QVBoxLayout(done).addWidget(QLabel(self.tr("Sign in on the Server page to connect this computer.")))
        self.addPage(done)

    def accept(self):
        self.save()
        super().accept()

    def save(self) -> None:
        s = self._settings
        s.set_pref("server_url", self.server.url.text())
        s.share_telemetry = self.privacy.telemetry.isChecked()
        s.share_network_flows = self.privacy.netflows.isChecked()
        s.set_pref("crash_reports", self.privacy.crash.isChecked())
        s.command_policy = self.commands.policy
        s.set_pref("onboarding_done", True)
