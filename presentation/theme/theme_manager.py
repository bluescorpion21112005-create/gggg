"""Theme manager: loads the bundled display fonts and applies QSS stylesheets."""
from pathlib import Path

from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import QApplication

_FONTS_LOADED = False
# Bundled OFL fonts (presentation/theme/fonts): Orbitron for headings/nav, Share Tech Mono for body.
# The QSS falls back to installed monospace faces when these are missing, so loading is best-effort.
BUNDLED_FONTS = ("Orbitron.ttf", "ShareTechMono.ttf")


class ThemeManager:
    THEMES = {
        "dark": "dark_theme.qss",
        "light": "light_theme.qss",
    }

    @classmethod
    def load_fonts(cls) -> None:
        """Register the bundled fonts with Qt once. Safe to call without any fonts present."""
        global _FONTS_LOADED
        if _FONTS_LOADED:
            return
        fonts_dir = Path(__file__).parent / "fonts"
        for name in BUNDLED_FONTS:
            path = fonts_dir / name
            if path.exists():
                QFontDatabase.addApplicationFont(str(path))
        _FONTS_LOADED = True

    @classmethod
    def apply_theme(cls, app: QApplication, theme: str = "dark"):
        cls.load_fonts()
        theme_file = Path(__file__).parent / cls.THEMES.get(theme, "dark_theme.qss")
        if theme_file.exists():
            with open(theme_file, "r") as f:
                qss = f.read()
            app.setStyleSheet(qss)
