"""Theme manager: loads and applies QSS stylesheets."""
from pathlib import Path
from PySide6.QtWidgets import QApplication

class ThemeManager:
    THEMES = {
        "dark": "dark_theme.qss",
        "light": "light_theme.qss",
    }

    @classmethod
    def apply_theme(cls, app: QApplication, theme: str = "dark"):
        theme_file = Path(__file__).parent / cls.THEMES.get(theme, "dark_theme.qss")
        if theme_file.exists():
            with open(theme_file, "r") as f:
                qss = f.read()
            app.setStyleSheet(qss)