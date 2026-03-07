"""
PyVault GUI Theme

Modern dark theme with accent colors.
Inspired by modern file managers and IDEs.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ColorPalette:
    """Color palette for the theme."""
    # Background colors
    bg_primary: str = "#0d1117"      # Main background
    bg_secondary: str = "#161b22"    # Card/panel background
    bg_tertiary: str = "#21262d"     # Hover states
    bg_elevated: str = "#1c2128"     # Elevated surfaces
    
    # Border colors
    border_default: str = "#30363d"
    border_muted: str = "#21262d"
    border_accent: str = "#388bfd"
    
    # Text colors
    text_primary: str = "#e6edf3"
    text_secondary: str = "#8b949e"
    text_muted: str = "#6e7681"
    text_link: str = "#58a6ff"
    
    # Accent colors
    accent_primary: str = "#388bfd"    # Blue
    accent_success: str = "#3fb950"    # Green
    accent_warning: str = "#d29922"    # Yellow
    accent_danger: str = "#f85149"     # Red
    accent_purple: str = "#a371f7"     # Purple
    
    # Selection colors
    selection_bg: str = "#1f3a5f"
    selection_border: str = "#388bfd"
    
    # Scrollbar
    scrollbar_bg: str = "#161b22"
    scrollbar_thumb: str = "#30363d"
    scrollbar_thumb_hover: str = "#484f58"


@dataclass
class Spacing:
    """Spacing constants."""
    xs: int = 4
    sm: int = 8
    md: int = 12
    lg: int = 16
    xl: int = 24
    xxl: int = 32


@dataclass
class Typography:
    """Typography settings."""
    font_family: str = "Segoe UI, SF Pro Display, -apple-system, sans-serif"
    font_mono: str = "Cascadia Code, Consolas, monospace"
    
    size_xs: int = 11
    size_sm: int = 12
    size_md: int = 13
    size_lg: int = 14
    size_xl: int = 16
    size_xxl: int = 20
    size_title: int = 24


@dataclass
class BorderRadius:
    """Border radius constants."""
    sm: int = 4
    md: int = 6
    lg: int = 8
    xl: int = 12
    round: int = 9999


class Theme:
    """Theme configuration container."""
    colors = ColorPalette()
    spacing = Spacing()
    typography = Typography()
    radius = BorderRadius()
    
    # Thumbnail sizes (base values at scale 1.0)
    THUMBNAIL_SIZE = 160
    CARD_WIDTH = 180
    CARD_HEIGHT = 200
    
    # Zoom settings
    MIN_CARD_SCALE = 0.5
    MAX_CARD_SCALE = 1.5
    DEFAULT_CARD_SCALE = 1.0
    ZOOM_STEP = 0.1


def get_stylesheet() -> str:
    """Generate the complete QSS stylesheet."""
    c = Theme.colors
    s = Theme.spacing
    t = Theme.typography
    r = Theme.radius
    
    return f"""
    /* ===== Global ===== */
    QWidget {{
        font-family: {t.font_family};
        font-size: {t.size_md}px;
        color: {c.text_primary};
        background-color: {c.bg_primary};
    }}
    
    QMainWindow {{
        background-color: {c.bg_primary};
    }}
    
    /* ===== Scrollbars ===== */
    QScrollArea {{
        border: none;
        background-color: transparent;
    }}
    
    QScrollBar:vertical {{
        background-color: {c.scrollbar_bg};
        width: 10px;
        margin: 0;
        border-radius: 5px;
    }}
    
    QScrollBar::handle:vertical {{
        background-color: {c.scrollbar_thumb};
        min-height: 30px;
        border-radius: 5px;
        margin: 2px;
    }}
    
    QScrollBar::handle:vertical:hover {{
        background-color: {c.scrollbar_thumb_hover};
    }}
    
    QScrollBar::add-line:vertical,
    QScrollBar::sub-line:vertical {{
        height: 0;
    }}
    
    QScrollBar:horizontal {{
        background-color: {c.scrollbar_bg};
        height: 10px;
        margin: 0;
        border-radius: 5px;
    }}
    
    QScrollBar::handle:horizontal {{
        background-color: {c.scrollbar_thumb};
        min-width: 30px;
        border-radius: 5px;
        margin: 2px;
    }}
    
    QScrollBar::handle:horizontal:hover {{
        background-color: {c.scrollbar_thumb_hover};
    }}
    
    QScrollBar::add-line:horizontal,
    QScrollBar::sub-line:horizontal {{
        width: 0;
    }}
    
    /* ===== Labels ===== */
    QLabel {{
        background-color: transparent;
        color: {c.text_primary};
    }}
    
    QLabel[class="secondary"] {{
        color: {c.text_secondary};
    }}
    
    QLabel[class="muted"] {{
        color: {c.text_muted};
    }}
    
    QLabel[class="title"] {{
        font-size: {t.size_title}px;
        font-weight: 600;
    }}
    
    /* ===== Buttons ===== */
    QPushButton {{
        background-color: {c.bg_tertiary};
        color: {c.text_primary};
        border: 1px solid {c.border_default};
        border-radius: {r.md}px;
        padding: {s.sm}px {s.lg}px;
        font-weight: 500;
        min-height: 32px;
    }}
    
    QPushButton:hover {{
        background-color: {c.bg_elevated};
        border-color: {c.border_accent};
    }}
    
    QPushButton:pressed {{
        background-color: {c.bg_secondary};
    }}
    
    QPushButton:disabled {{
        background-color: {c.bg_secondary};
        color: {c.text_muted};
        border-color: {c.border_muted};
    }}
    
    QPushButton[class="primary"] {{
        background-color: {c.accent_primary};
        border-color: {c.accent_primary};
        color: white;
    }}
    
    QPushButton[class="primary"]:hover {{
        background-color: #4c9aff;
        border-color: #4c9aff;
    }}
    
    QPushButton[class="danger"] {{
        background-color: {c.accent_danger};
        border-color: {c.accent_danger};
        color: white;
    }}
    
    QPushButton[class="danger"]:hover {{
        background-color: #ff6b63;
        border-color: #ff6b63;
    }}
    
    QPushButton[class="ghost"] {{
        background-color: transparent;
        border: none;
    }}
    
    QPushButton[class="ghost"]:hover {{
        background-color: {c.bg_tertiary};
    }}
    
    /* ===== Line Edits ===== */
    QLineEdit {{
        background-color: {c.bg_secondary};
        color: {c.text_primary};
        border: 1px solid {c.border_default};
        border-radius: {r.md}px;
        padding: {s.sm}px {s.md}px;
        selection-background-color: {c.selection_bg};
        min-height: 20px;
    }}
    
    QLineEdit:focus {{
        border-color: {c.accent_primary};
        background-color: {c.bg_elevated};
    }}
    
    QLineEdit:disabled {{
        background-color: {c.bg_primary};
        color: {c.text_muted};
    }}
    
    QLineEdit[class="search"] {{
        padding-left: 32px;
        border-radius: {r.lg}px;
    }}
    
    /* ===== ComboBox ===== */
    QComboBox {{
        background-color: {c.bg_secondary};
        color: {c.text_primary};
        border: 1px solid {c.border_default};
        border-radius: {r.md}px;
        padding: {s.sm}px {s.md}px;
        min-height: 20px;
        min-width: 120px;
    }}
    
    QComboBox:hover {{
        border-color: {c.border_accent};
    }}
    
    QComboBox:focus {{
        border-color: {c.accent_primary};
    }}
    
    QComboBox::drop-down {{
        border: none;
        width: 24px;
    }}
    
    QComboBox::down-arrow {{
        image: none;
        border-left: 4px solid transparent;
        border-right: 4px solid transparent;
        border-top: 6px solid {c.text_secondary};
        margin-right: 8px;
    }}
    
    QComboBox QAbstractItemView {{
        background-color: {c.bg_secondary};
        color: {c.text_primary};
        border: 1px solid {c.border_default};
        border-radius: {r.md}px;
        selection-background-color: {c.selection_bg};
        outline: none;
    }}
    
    QComboBox QAbstractItemView::item {{
        padding: {s.sm}px {s.md}px;
        min-height: 28px;
    }}
    
    QComboBox QAbstractItemView::item:hover {{
        background-color: {c.bg_tertiary};
    }}
    
    /* ===== Frames ===== */
    QFrame[class="card"] {{
        background-color: {c.bg_secondary};
        border: 1px solid {c.border_muted};
        border-radius: {r.lg}px;
    }}
    
    QFrame[class="card"]:hover {{
        border-color: {c.border_default};
        background-color: {c.bg_elevated};
    }}
    
    QFrame[class="card"][selected="true"] {{
        border-color: {c.accent_primary};
        background-color: {c.selection_bg};
    }}
    
    QFrame[class="toolbar"] {{
        background-color: {c.bg_secondary};
        border-bottom: 1px solid {c.border_muted};
        padding: {s.sm}px {s.md}px;
    }}
    
    QFrame[class="statusbar"] {{
        background-color: {c.bg_secondary};
        border-top: 1px solid {c.border_muted};
        padding: {s.xs}px {s.md}px;
    }}
    
    QFrame[class="separator"] {{
        background-color: {c.border_muted};
        max-height: 1px;
        min-height: 1px;
    }}
    
    /* ===== Dialogs ===== */
    QDialog {{
        background-color: {c.bg_primary};
    }}
    
    /* ===== Menu ===== */
    QMenu {{
        background-color: {c.bg_secondary};
        border: 1px solid {c.border_default};
        border-radius: {r.md}px;
        padding: {s.xs}px;
    }}
    
    QMenu::item {{
        padding: {s.sm}px {s.lg}px;
        border-radius: {r.sm}px;
    }}
    
    QMenu::item:selected {{
        background-color: {c.bg_tertiary};
    }}
    
    QMenu::separator {{
        height: 1px;
        background-color: {c.border_muted};
        margin: {s.xs}px {s.sm}px;
    }}
    
    /* ===== ToolTip ===== */
    QToolTip {{
        background-color: {c.bg_elevated};
        color: {c.text_primary};
        border: 1px solid {c.border_default};
        border-radius: {r.sm}px;
        padding: {s.xs}px {s.sm}px;
    }}
    
    /* ===== Progress Bar ===== */
    QProgressBar {{
        background-color: {c.bg_tertiary};
        border: none;
        border-radius: {r.sm}px;
        height: 6px;
        text-align: center;
    }}
    
    QProgressBar::chunk {{
        background-color: {c.accent_primary};
        border-radius: {r.sm}px;
    }}
    
    /* ===== CheckBox ===== */
    QCheckBox {{
        spacing: {s.sm}px;
        color: {c.text_primary};
    }}
    
    QCheckBox::indicator {{
        width: 18px;
        height: 18px;
        border-radius: {r.sm}px;
        border: 1px solid {c.border_default};
        background-color: {c.bg_secondary};
    }}
    
    QCheckBox::indicator:hover {{
        border-color: {c.accent_primary};
    }}
    
    QCheckBox::indicator:checked {{
        background-color: {c.accent_primary};
        border-color: {c.accent_primary};
    }}
    
    /* ===== Message Box ===== */
    QMessageBox {{
        background-color: {c.bg_primary};
    }}
    
    QMessageBox QLabel {{
        color: {c.text_primary};
    }}
    """


def get_file_card_style(selected: bool = False, hover: bool = False) -> str:
    """Get dynamic style for file cards."""
    c = Theme.colors
    r = Theme.radius
    
    if selected:
        bg = c.selection_bg
        border = c.accent_primary
    elif hover:
        bg = c.bg_elevated
        border = c.border_default
    else:
        bg = c.bg_secondary
        border = c.border_muted
    
    return f"""
        background-color: {bg};
        border: 1px solid {border};
        border-radius: {r.lg}px;
    """

