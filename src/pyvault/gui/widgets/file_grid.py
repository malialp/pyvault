"""
File Grid Widget

Displays files in a responsive grid layout.
Supports selection, filtering, and context menus.
"""

from PyQt6.QtWidgets import (
    QWidget, QScrollArea, QVBoxLayout, QHBoxLayout,
    QLabel, QFrame, QMenu, QSizePolicy
)
from PyQt6.QtCore import Qt, pyqtSignal, QSize, QPoint, QTimer
from PyQt6.QtGui import QAction

from .file_card import FileCard
from ..styles.theme import Theme
from typing import List, Optional, Set, Callable
from dataclasses import dataclass


@dataclass
class FileInfo:
    """Information about a file."""
    enc_filename: str  # For encrypted files, this is the .enc filename; for unencrypted, the actual filename
    original_filename: str  # The display name
    thumbnail_data: Optional[bytes] = None
    has_thumbnail: bool = False
    is_image: bool = False
    extension: str = ""
    is_encrypted: bool = True


class FlowLayout(QWidget):
    """
    Flow layout that wraps items to next line when needed.
    Similar to CSS flexbox with wrap.
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._items: List[FileCard] = []
        self._spacing = Theme.spacing.md
        self._item_width = Theme.CARD_WIDTH
        self._item_height = Theme.CARD_HEIGHT
        self._layout_pending = False
    
    def add_widget(self, widget: FileCard):
        """Add a widget to the flow."""
        widget.setParent(self)
        self._items.append(widget)
        self._schedule_layout()
    
    def clear(self):
        """Remove all widgets safely."""
        # Hide and schedule deletion
        for item in self._items:
            item.hide()
            item.setParent(None)
        self._items.clear()
        self._schedule_layout()
    
    def remove_widget(self, widget: FileCard):
        """Remove a specific widget."""
        if widget in self._items:
            widget.hide()
            widget.setParent(None)
            self._items.remove(widget)
            self._schedule_layout()
    
    def count(self) -> int:
        """Get number of items."""
        return len(self._items)
    
    def items(self) -> List[FileCard]:
        """Get all items."""
        return self._items.copy()
    
    def _schedule_layout(self):
        """Schedule a layout update to avoid multiple rapid updates."""
        if not self._layout_pending:
            self._layout_pending = True
            QTimer.singleShot(0, self._do_layout)
    
    def _do_layout(self):
        """Actually perform the layout."""
        self._layout_pending = False
        self._update_layout()
    
    def _update_layout(self):
        """Recalculate positions of all items."""
        if not self._items:
            self.setMinimumHeight(0)
            return
        
        width = max(self.width(), 200)
        
        # Calculate columns
        cols = max(1, (width + self._spacing) // (self._item_width + self._spacing))
        
        # Position items
        x, y = 0, 0
        col = 0
        
        for item in self._items:
            if item.parent() == self:  # Safety check
                item.move(x, y)
                item.show()
                
                col += 1
                
                if col >= cols:
                    col = 0
                    x = 0
                    y += self._item_height + self._spacing
                else:
                    x += self._item_width + self._spacing
        
        # Set minimum height to fit all items
        if self._items:
            rows = (len(self._items) + cols - 1) // cols
            total_height = rows * (self._item_height + self._spacing)
            self.setMinimumHeight(total_height)
    
    def resizeEvent(self, event):
        """Handle resize to reflow items."""
        super().resizeEvent(event)
        self._schedule_layout()


class FileGrid(QScrollArea):
    """
    Scrollable grid view for files.
    
    Features:
    - Responsive grid layout
    - Single and multi-selection
    - Keyboard navigation
    - Context menu support
    
    Signals:
        selection_changed: Emitted when selection changes
        file_double_clicked: Emitted when file is double-clicked
        decrypt_requested: Emitted when decrypt is requested for selection
        encrypt_requested: Emitted when encrypt is requested for selection
    """
    
    selection_changed = pyqtSignal(list)  # List of selected FileCard
    file_double_clicked = pyqtSignal(object)  # FileCard
    decrypt_requested = pyqtSignal(list)  # List of FileCard
    encrypt_requested = pyqtSignal(list)  # List of FileCard
    
    def __init__(self, mode: str = "encrypted", parent=None):
        """
        Initialize file grid.
        
        Args:
            mode: "encrypted" or "unencrypted"
        """
        super().__init__(parent)
        
        self._mode = mode
        self._cards: List[FileCard] = []
        self._visible_cards: List[FileCard] = []
        self._selected: Set[FileCard] = set()
        self._last_clicked: Optional[FileCard] = None
        self._filter_extension: str = ""
        self._filter_text: str = ""
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Initialize the user interface."""
        self.setWidgetResizable(True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        # Container widget
        self._container = QWidget()
        self._container.setStyleSheet(f"background-color: {Theme.colors.bg_primary};")
        self.setWidget(self._container)
        
        # Main layout
        main_layout = QVBoxLayout(self._container)
        main_layout.setContentsMargins(Theme.spacing.lg, Theme.spacing.lg, 
                                       Theme.spacing.lg, Theme.spacing.lg)
        main_layout.setSpacing(0)
        
        # Flow layout for cards
        self._flow = FlowLayout()
        main_layout.addWidget(self._flow)
        main_layout.addStretch()
        
        # Empty state label
        if self._mode == "encrypted":
            empty_text = "No encrypted files"
        else:
            empty_text = "No files to encrypt"
        
        self._empty_label = QLabel(empty_text)
        self._empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_label.setStyleSheet(f"""
            color: {Theme.colors.text_muted};
            font-size: {Theme.typography.size_lg}px;
            padding: 60px;
        """)
        self._empty_label.hide()
        main_layout.addWidget(self._empty_label)
    
    def set_files(self, files: List[FileInfo]):
        """
        Set the files to display.
        
        Args:
            files: List of FileInfo objects
        """
        # Clear existing
        self._selected.clear()
        self._last_clicked = None
        self._flow.clear()
        self._cards.clear()
        self._visible_cards.clear()
        
        # Create cards
        for file_info in files:
            card = FileCard(
                enc_filename=file_info.enc_filename,
                original_filename=file_info.original_filename,
                thumbnail_data=file_info.thumbnail_data,
                has_thumbnail=file_info.has_thumbnail,
                is_image=file_info.is_image,
                is_encrypted=file_info.is_encrypted
            )
            
            # Connect signals
            card.clicked.connect(self._on_card_clicked)
            card.double_clicked.connect(self._on_card_double_clicked)
            card.context_menu_requested.connect(self._on_context_menu)
            
            self._cards.append(card)
        
        # Apply current filter and update display
        self._apply_filter()
    
    def _apply_filter(self):
        """Apply current filter and update visible cards."""
        self._flow.clear()
        self._visible_cards.clear()
        
        for card in self._cards:
            # Check extension filter
            if self._filter_extension:
                if card.get_extension() != self._filter_extension:
                    continue
            
            # Check text filter
            if self._filter_text:
                if self._filter_text.lower() not in card.original_filename.lower():
                    continue
            
            self._flow.add_widget(card)
            self._visible_cards.append(card)
        
        # Show/hide empty state
        self._empty_label.setVisible(len(self._visible_cards) == 0)
        
        # Clear selection for hidden cards
        self._selected = {c for c in self._selected if c in self._visible_cards}
        self.selection_changed.emit(list(self._selected))
    
    def set_filter_extension(self, extension: str):
        """Filter by file extension."""
        self._filter_extension = extension.lower() if extension else ""
        self._apply_filter()
    
    def set_filter_text(self, text: str):
        """Filter by filename text."""
        self._filter_text = text
        self._apply_filter()
    
    def get_selected(self) -> List[FileCard]:
        """Get list of selected cards."""
        return list(self._selected)
    
    def select_all(self):
        """Select all visible cards."""
        for card in self._visible_cards:
            card.selected = True
            self._selected.add(card)
        self.selection_changed.emit(list(self._selected))
    
    def clear_selection(self):
        """Clear all selections."""
        for card in self._selected:
            card.selected = False
        self._selected.clear()
        self.selection_changed.emit([])
    
    def _on_card_clicked(self, card: FileCard, ctrl: bool, shift: bool):
        """Handle card click with modifiers."""
        if shift and self._last_clicked and self._last_clicked in self._visible_cards:
            # Range selection
            self._select_range(self._last_clicked, card)
        elif ctrl:
            # Toggle selection
            if card in self._selected:
                card.selected = False
                self._selected.remove(card)
            else:
                card.selected = True
                self._selected.add(card)
        else:
            # Single selection
            self.clear_selection()
            card.selected = True
            self._selected.add(card)
        
        self._last_clicked = card
        self.selection_changed.emit(list(self._selected))
    
    def _select_range(self, start: FileCard, end: FileCard):
        """Select range of cards between start and end."""
        try:
            start_idx = self._visible_cards.index(start)
            end_idx = self._visible_cards.index(end)
        except ValueError:
            return
        
        if start_idx > end_idx:
            start_idx, end_idx = end_idx, start_idx
        
        # Clear current selection
        self.clear_selection()
        
        # Select range
        for i in range(start_idx, end_idx + 1):
            card = self._visible_cards[i]
            card.selected = True
            self._selected.add(card)
    
    def _on_card_double_clicked(self, card: FileCard):
        """Handle card double click."""
        self.file_double_clicked.emit(card)
    
    def _on_context_menu(self, card: FileCard, position: QPoint):
        """Show context menu for card."""
        # Ensure card is selected
        if card not in self._selected:
            self.clear_selection()
            card.selected = True
            self._selected.add(card)
            self.selection_changed.emit(list(self._selected))
        
        menu = QMenu(self)
        
        if self._mode == "encrypted":
            # Decrypt action
            decrypt_action = QAction("Decrypt Selected", self)
            decrypt_action.triggered.connect(
                lambda: self.decrypt_requested.emit(list(self._selected))
            )
            menu.addAction(decrypt_action)
        else:
            # Encrypt action
            encrypt_action = QAction("Encrypt Selected", self)
            encrypt_action.triggered.connect(
                lambda: self.encrypt_requested.emit(list(self._selected))
            )
            menu.addAction(encrypt_action)
        
        # Select all action
        menu.addSeparator()
        select_all_action = QAction("Select All", self)
        select_all_action.triggered.connect(self.select_all)
        menu.addAction(select_all_action)
        
        menu.exec(position)
    
    def get_extensions(self) -> List[str]:
        """Get list of unique extensions from all files."""
        extensions = set()
        for card in self._cards:
            ext = card.get_extension()
            if ext:
                extensions.add(ext)
        return sorted(extensions)
    
    def get_file_count(self) -> int:
        """Get total number of files."""
        return len(self._cards)
    
    def get_visible_count(self) -> int:
        """Get number of visible (filtered) files."""
        return len(self._visible_cards)
    
    def clear_files(self):
        """Clear all files from the grid."""
        self._selected.clear()
        self._last_clicked = None
        self._flow.clear()
        self._cards.clear()
        self._visible_cards.clear()
        self._empty_label.setVisible(True)
    
    def update_card_thumbnail(self, enc_filename: str, thumbnail_data: bytes):
        """Update thumbnail for a specific card."""
        for card in self._cards:
            if card.enc_filename == enc_filename:
                card.set_thumbnail(thumbnail_data)
                break