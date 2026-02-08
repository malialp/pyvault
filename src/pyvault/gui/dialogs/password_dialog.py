"""
Password Dialog

Modal dialog for entering vault password on startup.
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
    QLineEdit, QPushButton, QFrame, QSpacerItem,
    QSizePolicy
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QKeyEvent

from ..styles.theme import Theme


class PasswordDialog(QDialog):
    """
    Password entry dialog for vault unlock.
    
    Signals:
        password_entered: Emitted when valid password is submitted
    """
    
    password_entered = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        self._connect_signals()
    
    def _setup_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("PyVault - Unlock")
        self.setFixedSize(400, 280)
        self.setModal(True)
        self.setWindowFlags(
            Qt.WindowType.Dialog | 
            Qt.WindowType.FramelessWindowHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        
        # Main container with rounded corners
        container = QFrame(self)
        container.setObjectName("dialogContainer")
        container.setStyleSheet(f"""
            QFrame#dialogContainer {{
                background-color: {Theme.colors.bg_primary};
                border: 1px solid {Theme.colors.border_default};
                border-radius: {Theme.radius.xl}px;
            }}
        """)
        
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(32, 32, 32, 32)
        container_layout.setSpacing(16)
        
        # Icon/Logo area
        logo_label = QLabel("🔐")
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo_label.setStyleSheet(f"font-size: 48px; background: transparent;")
        container_layout.addWidget(logo_label)
        
        # Title
        title_label = QLabel("Unlock Vault")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet(f"""
            font-size: {Theme.typography.size_xl}px;
            font-weight: 600;
            color: {Theme.colors.text_primary};
            background: transparent;
        """)
        container_layout.addWidget(title_label)
        
        # Subtitle
        subtitle_label = QLabel("Enter your password to unlock the vault")
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle_label.setStyleSheet(f"""
            font-size: {Theme.typography.size_sm}px;
            color: {Theme.colors.text_secondary};
            background: transparent;
        """)
        container_layout.addWidget(subtitle_label)
        
        container_layout.addSpacing(8)
        
        # Password input
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {Theme.colors.bg_secondary};
                color: {Theme.colors.text_primary};
                border: 1px solid {Theme.colors.border_default};
                border-radius: {Theme.radius.md}px;
                padding: 12px 16px;
                font-size: {Theme.typography.size_md}px;
            }}
            QLineEdit:focus {{
                border-color: {Theme.colors.accent_primary};
            }}
        """)
        container_layout.addWidget(self.password_input)
        
        # Error label (hidden by default)
        self.error_label = QLabel("")
        self.error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.error_label.setStyleSheet(f"""
            color: {Theme.colors.accent_danger};
            font-size: {Theme.typography.size_sm}px;
            background: transparent;
        """)
        self.error_label.hide()
        container_layout.addWidget(self.error_label)
        
        container_layout.addSpacing(8)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(12)
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {Theme.colors.bg_tertiary};
                color: {Theme.colors.text_primary};
                border: 1px solid {Theme.colors.border_default};
                border-radius: {Theme.radius.md}px;
                padding: 10px 24px;
                font-weight: 500;
            }}
            QPushButton:hover {{
                background-color: {Theme.colors.bg_elevated};
                border-color: {Theme.colors.border_accent};
            }}
        """)
        button_layout.addWidget(self.cancel_btn)
        
        self.unlock_btn = QPushButton("Unlock")
        self.unlock_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {Theme.colors.accent_primary};
                color: white;
                border: none;
                border-radius: {Theme.radius.md}px;
                padding: 10px 24px;
                font-weight: 500;
            }}
            QPushButton:hover {{
                background-color: #4c9aff;
            }}
            QPushButton:disabled {{
                background-color: {Theme.colors.bg_tertiary};
                color: {Theme.colors.text_muted};
            }}
        """)
        self.unlock_btn.setDefault(True)
        button_layout.addWidget(self.unlock_btn)
        
        container_layout.addLayout(button_layout)
        
        # Main dialog layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(container)
        
        # Focus password input
        self.password_input.setFocus()
    
    def _connect_signals(self):
        """Connect widget signals."""
        self.cancel_btn.clicked.connect(self.reject)
        self.unlock_btn.clicked.connect(self._on_unlock)
        self.password_input.returnPressed.connect(self._on_unlock)
        self.password_input.textChanged.connect(self._on_text_changed)
    
    def _on_unlock(self):
        """Handle unlock button click."""
        password = self.password_input.text()
        
        if not password:
            self.show_error("Please enter a password")
            return
        
        self.password_entered.emit(password)
    
    def _on_text_changed(self):
        """Clear error when user types."""
        if self.error_label.isVisible():
            self.error_label.hide()
    
    def show_error(self, message: str):
        """Display error message."""
        self.error_label.setText(message)
        self.error_label.show()
        self.password_input.setFocus()
        self.password_input.selectAll()
    
    def get_password(self) -> str:
        """Get the entered password."""
        return self.password_input.text()
    
    def keyPressEvent(self, event: QKeyEvent):
        """Handle key press events."""
        if event.key() == Qt.Key.Key_Escape:
            self.reject()
        else:
            super().keyPressEvent(event)

