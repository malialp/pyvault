"""
Toolbar Widget

Main toolbar with actions and status information.
"""

from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QPushButton, 
    QLabel, QFrame, QSizePolicy
)
from PyQt6.QtCore import Qt, pyqtSignal

from ..styles.theme import Theme


class Toolbar(QFrame):
    """
    Main toolbar with action buttons and selection info.
    
    Signals:
        action_clicked: Emitted when main action button is clicked
        select_all_clicked: Emitted when select all is clicked
        refresh_clicked: Emitted when refresh is clicked
    """
    
    action_clicked = pyqtSignal()
    select_all_clicked = pyqtSignal()
    refresh_clicked = pyqtSignal()
    
    def __init__(self, mode: str = "encrypted", parent=None):
        """
        Initialize toolbar.
        
        Args:
            mode: "encrypted" or "unencrypted"
        """
        super().__init__(parent)
        self._mode = mode
        self._selected_count = 0
        self._total_count = 0
        self._setup_ui()
        self._connect_signals()
    
    def _setup_ui(self):
        """Initialize the user interface."""
        self.setProperty("class", "toolbar")
        self.setStyleSheet(f"""
            Toolbar {{
                background-color: {Theme.colors.bg_secondary};
                border-bottom: 1px solid {Theme.colors.border_muted};
            }}
        """)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(
            Theme.spacing.lg, Theme.spacing.md,
            Theme.spacing.lg, Theme.spacing.md
        )
        layout.setSpacing(Theme.spacing.md)
        
        # Left side - Action buttons
        left_layout = QHBoxLayout()
        left_layout.setSpacing(Theme.spacing.sm)
        
        # Main action button (Decrypt or Encrypt)
        if self._mode == "encrypted":
            action_text = "Decrypt Selected"
            action_color = Theme.colors.accent_primary
            action_hover = "#4c9aff"
        else:
            action_text = "Encrypt Selected"
            action_color = Theme.colors.accent_success
            action_hover = "#4cc764"
        
        self._action_btn = QPushButton(action_text)
        self._action_btn.setEnabled(False)
        self._action_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {action_color};
                color: white;
                border: none;
                border-radius: {Theme.radius.md}px;
                padding: 8px 16px;
                font-weight: 500;
                font-size: {Theme.typography.size_sm}px;
            }}
            QPushButton:hover {{
                background-color: {action_hover};
            }}
            QPushButton:disabled {{
                background-color: {Theme.colors.bg_tertiary};
                color: {Theme.colors.text_muted};
            }}
        """)
        left_layout.addWidget(self._action_btn)
        
        # Select all button
        self._select_all_btn = QPushButton("Select All")
        self._select_all_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {Theme.colors.bg_tertiary};
                color: {Theme.colors.text_primary};
                border: 1px solid {Theme.colors.border_default};
                border-radius: {Theme.radius.md}px;
                padding: 8px 16px;
                font-weight: 500;
                font-size: {Theme.typography.size_sm}px;
            }}
            QPushButton:hover {{
                background-color: {Theme.colors.bg_elevated};
                border-color: {Theme.colors.border_accent};
            }}
        """)
        left_layout.addWidget(self._select_all_btn)
        
        # Refresh button
        self._refresh_btn = QPushButton("↻ Refresh")
        self._refresh_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {Theme.colors.text_secondary};
                border: none;
                border-radius: {Theme.radius.md}px;
                padding: 8px 12px;
                font-size: {Theme.typography.size_sm}px;
            }}
            QPushButton:hover {{
                background-color: {Theme.colors.bg_tertiary};
                color: {Theme.colors.text_primary};
            }}
        """)
        left_layout.addWidget(self._refresh_btn)
        
        layout.addLayout(left_layout)
        
        # Spacer
        layout.addStretch()
        
        # Right side - Status info
        right_layout = QHBoxLayout()
        right_layout.setSpacing(Theme.spacing.lg)
        
        # Selection info
        self._selection_label = QLabel("0 selected")
        self._selection_label.setStyleSheet(f"""
            color: {Theme.colors.text_secondary};
            font-size: {Theme.typography.size_sm}px;
            background: transparent;
        """)
        right_layout.addWidget(self._selection_label)
        
        # Separator
        separator = QFrame()
        separator.setFixedWidth(1)
        separator.setStyleSheet(f"background-color: {Theme.colors.border_muted};")
        right_layout.addWidget(separator)
        
        # Total files
        self._total_label = QLabel("0 files")
        self._total_label.setStyleSheet(f"""
            color: {Theme.colors.text_muted};
            font-size: {Theme.typography.size_sm}px;
            background: transparent;
        """)
        right_layout.addWidget(self._total_label)
        
        layout.addLayout(right_layout)
    
    def _connect_signals(self):
        """Connect widget signals."""
        self._action_btn.clicked.connect(self.action_clicked)
        self._select_all_btn.clicked.connect(self.select_all_clicked)
        self._refresh_btn.clicked.connect(self.refresh_clicked)
    
    def set_selection_count(self, count: int):
        """Update selection count display."""
        self._selected_count = count
        self._selection_label.setText(f"{count} selected")
        self._action_btn.setEnabled(count > 0)
        
        # Update button text
        if self._mode == "encrypted":
            if count > 1:
                self._action_btn.setText(f"Decrypt {count} Files")
            else:
                self._action_btn.setText("Decrypt Selected")
        else:
            if count > 1:
                self._action_btn.setText(f"Encrypt {count} Files")
            else:
                self._action_btn.setText("Encrypt Selected")
    
    def set_total_count(self, total: int, visible: int = None):
        """Update total files count display."""
        self._total_count = total
        
        if visible is not None and visible != total:
            self._total_label.setText(f"{visible} of {total} files")
        else:
            self._total_label.setText(f"{total} files")
    
    def enable_actions(self, enabled: bool):
        """Enable or disable action buttons."""
        self._select_all_btn.setEnabled(enabled)
        self._refresh_btn.setEnabled(enabled)
