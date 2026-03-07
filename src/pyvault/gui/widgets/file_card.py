"""
File Card Widget

Displays a single encrypted file with thumbnail and filename.
Supports selection and hover states.
"""

from PyQt6.QtWidgets import (
    QFrame, QVBoxLayout, QLabel, QSizePolicy
)
from PyQt6.QtCore import Qt, pyqtSignal, QSize
from PyQt6.QtGui import QPixmap, QImage, QMouseEvent, QPainter, QColor, QFont

from ..styles.theme import Theme
from typing import Optional
import os


class ThumbnailLabel(QLabel):
    """
    Custom label for displaying thumbnails with placeholder support.
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._pixmap: Optional[QPixmap] = None
        self._extension: str = ""
        self._has_thumbnail: bool = False
        
        self.setFixedSize(Theme.THUMBNAIL_SIZE, Theme.THUMBNAIL_SIZE)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(f"""
            background-color: {Theme.colors.bg_tertiary};
            border-radius: {Theme.radius.md}px;
        """)
    
    def set_thumbnail(self, data: bytes):
        """Set thumbnail from raw bytes."""
        image = QImage()
        if image.loadFromData(data):
            self._pixmap = QPixmap.fromImage(image)
            self._has_thumbnail = True
            self._update_display()
    
    def set_extension(self, ext: str):
        """Set file extension for placeholder display."""
        self._extension = ext.upper().lstrip('.')
        if not self._has_thumbnail:
            self._update_display()
    
    def reset(self):
        """Reset thumbnail to placeholder state."""
        self._pixmap = None
        self._has_thumbnail = False
        self._extension = ""
        self.clear()
        self.update()
    
    def _update_display(self):
        """Update the displayed content."""
        if self._has_thumbnail and self._pixmap:
            # Scale pixmap to fit while maintaining aspect ratio
            scaled = self._pixmap.scaled(
                self.size(),
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            )
            self.setPixmap(scaled)
        else:
            self.clear()
            self.update()
    
    def paintEvent(self, event):
        """Custom paint for placeholder when no thumbnail."""
        super().paintEvent(event)
        
        if not self._has_thumbnail:
            painter = QPainter(self)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            
            # Draw extension text
            if self._extension:
                font = QFont(Theme.typography.font_family)
                font.setPixelSize(24)
                font.setBold(True)
                painter.setFont(font)
                painter.setPen(QColor(Theme.colors.text_muted))
                painter.drawText(
                    self.rect(),
                    Qt.AlignmentFlag.AlignCenter,
                    self._extension[:4]
                )
            else:
                # Draw file icon placeholder
                font = QFont()
                font.setPixelSize(36)
                painter.setFont(font)
                painter.setPen(QColor(Theme.colors.text_muted))
                painter.drawText(
                    self.rect(),
                    Qt.AlignmentFlag.AlignCenter,
                    "📄"
                )
            
            painter.end()


class FileCard(QFrame):
    """
    Card widget for displaying a file (encrypted or unencrypted).
    
    Displays:
    - Thumbnail (if available) or extension placeholder
    - Filename (truncated if too long)
    - Selection state
    
    Signals:
        clicked: Emitted when card is clicked (with Ctrl/Shift modifiers)
        double_clicked: Emitted when card is double-clicked
        context_menu_requested: Emitted for right-click menu
    """
    
    clicked = pyqtSignal(object, bool, bool)  # card, ctrl, shift
    double_clicked = pyqtSignal(object)
    context_menu_requested = pyqtSignal(object, object)  # card, position
    
    def __init__(
        self,
        enc_filename: str,
        original_filename: str,
        thumbnail_data: Optional[bytes] = None,
        has_thumbnail: bool = False,
        is_image: bool = False,
        is_encrypted: bool = True,
        parent=None
    ):
        super().__init__(parent)
        
        self.enc_filename = enc_filename
        self.original_filename = original_filename
        self.has_thumbnail = has_thumbnail
        self.is_image = is_image
        self.is_encrypted = is_encrypted
        self._selected = False
        self._hover = False
        self._thumbnail_data = thumbnail_data
        
        self._setup_ui(thumbnail_data)
        self._update_style()
    
    def _setup_ui(self, thumbnail_data: Optional[bytes]):
        """Initialize the user interface."""
        self.setFixedSize(Theme.CARD_WIDTH, Theme.CARD_HEIGHT)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setProperty("class", "card")
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Thumbnail
        self.thumbnail_label = ThumbnailLabel()
        if thumbnail_data:
            self.thumbnail_label.set_thumbnail(thumbnail_data)
        
        # Set extension from original filename
        ext = os.path.splitext(self.original_filename)[1]
        self.thumbnail_label.set_extension(ext)
        
        layout.addWidget(self.thumbnail_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        # Filename label
        self.filename_label = QLabel(self._truncate_filename(self.original_filename))
        self.filename_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.filename_label.setWordWrap(True)
        self.filename_label.setMaximumHeight(36)
        self.filename_label.setStyleSheet(f"""
            font-size: {Theme.typography.size_sm}px;
            color: {Theme.colors.text_primary};
            background: transparent;
        """)
        self.filename_label.setToolTip(self.original_filename)
        layout.addWidget(self.filename_label)
    
    def _truncate_filename(self, filename: str, max_chars: int = 18) -> str:
        """Truncate filename for display."""
        if len(filename) <= max_chars:
            return filename
        
        name, ext = os.path.splitext(filename)
        available = max_chars - len(ext) - 3  # 3 for "..."
        
        if available > 0:
            return f"{name[:available]}...{ext}"
        else:
            return f"{filename[:max_chars-3]}..."
    
    def _update_style(self):
        """Update card style based on state."""
        c = Theme.colors
        r = Theme.radius
        
        if self._selected:
            bg = c.selection_bg
            border = c.accent_primary
        elif self._hover:
            bg = c.bg_elevated
            border = c.border_default
        else:
            bg = c.bg_secondary
            border = c.border_muted
        
        self.setStyleSheet(f"""
            FileCard {{
                background-color: {bg};
                border: 2px solid {border};
                border-radius: {r.lg}px;
            }}
        """)
    
    @property
    def selected(self) -> bool:
        """Check if card is selected."""
        return self._selected
    
    @selected.setter
    def selected(self, value: bool):
        """Set selection state."""
        if self._selected != value:
            self._selected = value
            self._update_style()
    
    def enterEvent(self, event):
        """Handle mouse enter."""
        self._hover = True
        self._update_style()
        super().enterEvent(event)
    
    def leaveEvent(self, event):
        """Handle mouse leave."""
        self._hover = False
        self._update_style()
        super().leaveEvent(event)
    
    def mousePressEvent(self, event: QMouseEvent):
        """Handle mouse press."""
        if event.button() == Qt.MouseButton.LeftButton:
            ctrl = event.modifiers() & Qt.KeyboardModifier.ControlModifier
            shift = event.modifiers() & Qt.KeyboardModifier.ShiftModifier
            self.clicked.emit(self, bool(ctrl), bool(shift))
        elif event.button() == Qt.MouseButton.RightButton:
            self.context_menu_requested.emit(self, event.globalPosition().toPoint())
        
        super().mousePressEvent(event)
    
    def mouseDoubleClickEvent(self, event: QMouseEvent):
        """Handle double click."""
        if event.button() == Qt.MouseButton.LeftButton:
            self.double_clicked.emit(self)
        super().mouseDoubleClickEvent(event)
    
    def get_extension(self) -> str:
        """Get the file extension."""
        return os.path.splitext(self.original_filename)[1].lower()
    
    def set_thumbnail(self, data: bytes):
        """Set thumbnail from raw bytes."""
        self._thumbnail_data = data
        self.thumbnail_label.set_thumbnail(data)
        self.has_thumbnail = True

    def get_thumbnail_data(self) -> Optional[bytes]:
        """Get the raw thumbnail data."""
        return self._thumbnail_data
    
    def update_data(
        self,
        enc_filename: str,
        original_filename: str,
        thumbnail_data: Optional[bytes] = None,
        has_thumbnail: bool = False,
        is_image: bool = False,
        is_encrypted: bool = True
    ):
        """
        Update card data for reuse in virtualized list.
        
        This allows the card widget to be reused with different file data
        instead of creating a new widget each time.
        """
        self.enc_filename = enc_filename
        self.original_filename = original_filename
        self.has_thumbnail = has_thumbnail
        self.is_image = is_image
        self.is_encrypted = is_encrypted
        self._thumbnail_data = thumbnail_data
        
        # Reset and update thumbnail
        self.thumbnail_label.reset()
        if thumbnail_data:
            self.thumbnail_label.set_thumbnail(thumbnail_data)
        
        # Update extension
        ext = os.path.splitext(original_filename)[1]
        self.thumbnail_label.set_extension(ext)
        
        # Update filename label
        self.filename_label.setText(self._truncate_filename(original_filename))
        self.filename_label.setToolTip(original_filename)
        
        # Reset selection state
        self._selected = False
        self._hover = False
        self._update_style()
