"""Packaging/lifecycle: per-user paths, UI preferences, crash diagnostics, first-run wizard, dashboard stats."""
import json
import zipfile
from pathlib import Path

import pytest

from core import crash, paths
from core.config import AppConfig, AIProviderConfig, BackendConfig, ConfigLoader
from infrastructure.remote.agent_settings import AgentSettings, apply_user_overrides, validate_server_url


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBRIX_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("CYBRIX_CONFIG_DIR", raising=False)
    monkeypatch.delenv("CYBRIX_SERVER_URL", raising=False)
    monkeypatch.delenv("CYBRIX_THEME", raising=False)
    monkeypatch.delenv("CYBRIX_DATABASE_URL", raising=False)
    monkeypatch.chdir(tmp_path)
    return tmp_path / "home"


def make_config(tmp_path, **backend):
    return AppConfig(backend=BackendConfig(data_dir=str(tmp_path / "agent"), **backend),
                     ai_providers={"ollama": AIProviderConfig(provider="ollama", enabled=True, model="llama3",
                                                              host="http://localhost:11434")})


# ── paths & config resolution ────────────────────────────────────────────────

def test_settings_are_seeded_into_the_user_config_dir(home):
    target = paths.user_settings_path()
    assert target == home / "config" / "settings.yaml"
    assert target.read_text() == (paths.bundle_dir() / "config" / "settings.yaml").read_text()


def test_relative_paths_resolve_to_user_dirs_not_cwd(home):
    config = ConfigLoader.load()
    assert config.database_url == f"sqlite:///{home / 'data' / 'cybrix.db'}"
    assert Path(config.logging.file) == home / "logs" / "cybrix.log"
    assert Path(config.plugins_dir) == paths.bundle_dir() / "plugins"


def test_generic_database_url_is_ignored(home, tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("DATABASE_URL", "postgres://cybrix:pw@127.0.0.1:5433/cybrix")   # e.g. the server's
    assert ConfigLoader.load().database_url == f"sqlite:///{home / 'data' / 'cybrix.db'}"
    assert "Ignoring DATABASE_URL" in caplog.text
    monkeypatch.setenv("CYBRIX_DATABASE_URL", f"sqlite:///{tmp_path}/mine.db")
    assert ConfigLoader.load().database_url == f"sqlite:///{tmp_path}/mine.db"


def test_legacy_db_in_working_directory_is_migrated_once(home, tmp_path):
    (tmp_path / "cybrix.db").write_bytes(b"old-db")
    ConfigLoader.load()
    assert (home / "data" / "cybrix.db").read_bytes() == b"old-db"
    assert (tmp_path / "cybrix.db").exists()          # the original is kept


def test_absolute_paths_are_kept(home, tmp_path):
    cfg = tmp_path / "s.yaml"
    cfg.write_text(f"database_url: sqlite:///{tmp_path}/abs.db\nlogging:\n  file: {tmp_path}/x.log\n")
    config = ConfigLoader.load(cfg)
    assert config.database_url == f"sqlite:///{tmp_path}/abs.db"
    assert config.logging.file == f"{tmp_path}/x.log"


# ── preferences ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("url,ok", [
    ("https://cybrix.example.com", True), ("https://cybrix.example.com/", True),
    ("http://localhost:8000", True), ("http://127.0.0.1:8088", True),
    ("http://cybrix.example.com", False), ("ftp://x", False), ("https://u:p@x.com", False),
    ("https://x.com/api", False), ("cybrix.example.com", False), ("", False),
])
def test_server_url_validation(url, ok):
    if ok:
        assert validate_server_url(url) == url.rstrip("/")
    else:
        with pytest.raises(ValueError):
            validate_server_url(url)


def test_saved_preferences_override_config_at_start(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBRIX_SERVER_URL", raising=False)
    monkeypatch.delenv("CYBRIX_THEME", raising=False)
    config = make_config(tmp_path)
    settings = AgentSettings(config)
    settings.set_pref("server_url", "https://cybrix.example.com/")
    settings.set_pref("theme", "light")
    settings.set_pref("language", "uz")
    settings.set_pref("ollama_host", "http://gpu-box:11434/")
    out = apply_user_overrides(config)
    assert out.backend.base_url == "https://cybrix.example.com"
    assert (out.ui.theme, out.ui.language) == ("light", "uz")
    assert out.ai_providers["ollama"].host == "http://gpu-box:11434"


def test_env_server_url_wins_over_saved(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    AgentSettings(config).set_pref("server_url", "https://saved.example.com")
    monkeypatch.setenv("CYBRIX_SERVER_URL", "http://127.0.0.1:8088")
    assert apply_user_overrides(config).backend.base_url == config.backend.base_url


def test_invalid_preferences_are_rejected(tmp_path):
    settings = AgentSettings(make_config(tmp_path))
    for key, value in (("theme", "neon"), ("language", "klingon"), ("update_channel", "nightly"),
                       ("server_url", "http://remote.example.com")):
        with pytest.raises(ValueError):
            settings.set_pref(key, value)
    with pytest.raises(KeyError):
        settings.set_pref("token", "x")              # arbitrary keys cannot be smuggled in


def test_privacy_defaults_are_off(tmp_path):
    settings = AgentSettings(make_config(tmp_path))
    assert settings.crash_reports is False and settings.share_network_flows is False
    assert settings.share_process_hashes is False
    assert settings.onboarding_done is False


# ── crash diagnostics ────────────────────────────────────────────────────────

def test_export_diagnostics_contains_logs_but_no_home_path(home, tmp_path):
    log = paths.log_dir() / "cybrix.log"
    log.write_text(f"error reading {Path.home()}/secret-project/file.txt\n")
    out = crash.export_diagnostics(tmp_path / "diag.zip", "0.1.0", tmp_path / "agent")
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        assert "system.json" in names and "logs/cybrix.log" in names
        assert str(Path.home()) not in zf.read("logs/cybrix.log").decode()
        assert json.loads(zf.read("system.json"))["app_version"] == "0.1.0"


def test_sentry_event_scrub_drops_user_vars_and_home():
    event = {"user": {"email": "a@b.c"}, "server_name": "alice-laptop",
             "exception": {"values": [{"value": f"open {Path.home()}/x failed",
                                       "stacktrace": {"frames": [{"abs_path": f"{Path.home()}/app.py",
                                                                  "vars": {"token": "t"}}]}}]}}
    out = crash._scrub_event(event, None)
    assert "user" not in out and "server_name" not in out
    frame = out["exception"]["values"][0]["stacktrace"]["frames"][0]
    assert "vars" not in frame and str(Path.home()) not in frame["abs_path"]
    assert str(Path.home()) not in out["exception"]["values"][0]["value"]


def test_crash_hook_writes_crash_log(home):
    try:
        raise RuntimeError("boom for the crash log")
    except RuntimeError as exc:
        crash._excepthook(RuntimeError, exc, exc.__traceback__)
    assert "boom for the crash log" in crash.crash_log_path().read_text()


def test_sentry_needs_consent_and_dsn(home):
    assert crash.install("0.1.0", sentry_dsn="https://k@sentry.example/1", consent=False) is False
    assert crash.install("0.1.0", sentry_dsn="", consent=True) is False


# ── first-run wizard & dashboard ─────────────────────────────────────────────

def test_onboarding_wizard_saves_choices(qtbot, tmp_path):
    from presentation.views.onboarding_wizard import OnboardingWizard

    config = make_config(tmp_path)
    settings = AgentSettings(config)
    wizard = OnboardingWizard(config, settings)
    qtbot.addWidget(wizard)
    wizard.server.url.setText("https://cybrix.example.com")
    wizard.privacy.netflows.setChecked(True)
    wizard.privacy.hashes.setChecked(True)
    wizard.commands.group.buttons()[2].setChecked(True)      # deny_all
    wizard.save()
    reloaded = AgentSettings(config)
    assert reloaded.get_pref("server_url") == "https://cybrix.example.com"
    assert reloaded.share_network_flows is True and reloaded.share_telemetry is False
    assert reloaded.share_process_hashes is True
    assert reloaded.command_policy == "deny_all" and reloaded.onboarding_done


def test_server_check_refuses_insecure_remote_without_network():
    from presentation.views.onboarding_wizard import check_server

    ok, message, _ = check_server("http://cybrix.example.com")
    assert not ok and "https" in message


def test_severity_counts():
    from domain.entities import AnalysisResult, Severity
    from presentation.viewmodels.dashboard_viewmodel import severity_counts

    rows = [AnalysisResult(severity=Severity.HIGH), AnalysisResult(severity=Severity.HIGH),
            AnalysisResult(severity=Severity.LOW)]
    assert severity_counts(rows) == {"critical": 0, "high": 2, "medium": 0, "low": 1, "info": 0}


def test_translations_compiled_for_every_language():
    from PySide6.QtCore import QTranslator

    for lang in ("uz", "ru"):
        qm = paths.bundle_dir() / "presentation" / "i18n" / f"cybrix_{lang}.qm"
        translator = QTranslator()
        assert translator.load(str(qm)), qm
        assert translator.translate("SettingsWindow", "Settings") not in ("", "Settings")


def test_light_theme_is_complete():
    theme = paths.bundle_dir() / "presentation" / "theme"
    dark, light = (theme / "dark_theme.qss").read_text(), (theme / "light_theme.qss").read_text()

    def selectors(css):
        return {line.split("{")[0].strip() for line in css.splitlines() if "{" in line}

    assert selectors(dark) <= selectors(light)


def test_ts_files_have_no_unfinished_translations():
    import xml.etree.ElementTree as ET

    for lang in ("uz", "ru"):
        tree = ET.parse(paths.bundle_dir() / "presentation" / "i18n" / f"cybrix_{lang}.ts")
        unfinished = [m.find("source").text for m in tree.getroot().iter("message")
                      if m.find("translation").get("type") == "unfinished"
                      or not (m.find("translation").text or "").strip()]
        assert unfinished == [], (lang, unfinished[:5])


def test_widget_text_literals_go_through_tr():
    """A new QLabel("…")/setText("…") etc. without tr() would stay English in uz/ru."""
    import re

    pattern = re.compile(r'(QLabel|QPushButton|QGroupBox|QCheckBox|QRadioButton)\("[A-Za-z]'
                         r'|\.(setText|setWindowTitle|setToolTip|setTitle|addTab)\("[A-Za-z]|addRow\("[A-Za-z]')
    offenders = []
    for path in (paths.bundle_dir() / "presentation").rglob("*.py"):
        for no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if pattern.search(line):
                offenders.append(f"{path.name}:{no}: {line.strip()}")
    assert offenders == [], offenders
