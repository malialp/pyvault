"""
File Grid Widget

Displays files in a responsive grid layout with virtualization.
Only visible items are rendered for optimal performance with large file counts.
"""

from PyQt6.QtWidgets import (
    QWidget, QScrollArea, QVBoxLayout, QHBoxLayout,
    QLabel, QFrame, QMenu, QSizePolicy
)
from PyQt6.QtCore import Qt, pyqtSignal, QSize, QPoint, QTimer, QRect
from PyQt6.QtGui import QAction

from .file_card import FileCard
from ..styles.theme import Theme
from typing import List, Optional, Set, Dict, Tuple
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


class VirtualizedFlowLayout(QWidget):
    """
    Virtualized flow layout that only renders visible items.
    
    Instead of creating widgets for all items, it:
    1. Keeps a pool of reusable FileCard widgets
    2. Only renders items in the visible viewport
    3. Recycles widgets as user scrolls
    """
    
    # Signal emitted when visible range changes (for thumbnail loading)
    visible_range_changed = pyqtSignal(int, int)  # start_idx, end_idx
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self._spacing = Theme.spacing.md
        self._base_item_width = Theme.CARD_WIDTH
        self._base_item_height = Theme.CARD_HEIGHT
        self._scale = Theme.DEFAULT_CARD_SCALE
        self._item_width = int(self._base_item_width * self._scale)
        self._item_height = int(self._base_item_height * self._scale)
        
        # Data - list of FileInfo (not widgets)
        self._items: List[FileInfo] = []
        
        # Widget pool - reusable FileCard widgets
        self._card_pool: List[FileCard] = []
        self._active_cards: Dict[int, FileCard] = {}  # index -> card mapping
        
        # Viewport info
        self._viewport_top = 0
        self._viewport_height = 600
        self._cols = 1
        self._left_margin = 0  # For centering
        
        # Selection state (by index, not by widget)
        self._selected_indices: Set[int] = set()
        self._last_clicked_index: Optional[int] = None
        
        # Layout state
        self._layout_pending = False
        self._total_height = 0
        
        # Resize debounce timer
        self._resize_timer: Optional[QTimer] = None
        
        # Callbacks for card events
        self._on_card_clicked_callback = None
        self._on_card_double_clicked_callback = None
        self._on_context_menu_callback = None
    
    def set_callbacks(self, clicked, double_clicked, context_menu):
        """Set callbacks for card events."""
        self._on_card_clicked_callback = clicked
        self._on_card_double_clicked_callback = double_clicked
        self._on_context_menu_callback = context_menu
    
    def set_scale(self, scale: float):
        """Set the scale factor for items."""
        scale = max(Theme.MIN_CARD_SCALE, min(Theme.MAX_CARD_SCALE, scale))
        if scale != self._scale:
            self._scale = scale
            self._item_width = int(self._base_item_width * scale)
            self._item_height = int(self._base_item_height * scale)
            
            # Update active card sizes
            for card in self._active_cards.values():
                card.setFixedSize(self._item_width, self._item_height)
                card.update_scale(scale)
            
            # Also update pooled cards
            for card in self._card_pool:
                card.setFixedSize(self._item_width, self._item_height)
                card.update_scale(scale)
            
            self._schedule_layout()
    
    def get_scale(self) -> float:
        """Get current scale factor."""
        return self._scale
    
    def set_items(self, items: List[FileInfo]):
        """Set the items to display."""
        # Clear active cards
        for card in self._active_cards.values():
            card.hide()
            self._card_pool.append(card)
        self._active_cards.clear()
        
        # Set new items
        self._items = items
        self._selected_indices.clear()
        self._last_clicked_index = None
        
        self._schedule_layout()
    
    def get_items(self) -> List[FileInfo]:
        """Get all items."""
        return self._items.copy()
    
    def add_items(self, items: List[FileInfo]):
        """Add items to the list."""
        self._items.extend(items)
        self._schedule_layout()
    
    def remove_items(self, enc_filenames: Set[str]) -> List[FileInfo]:
        """Remove items by enc_filename and return removed items."""
        removed = []
        new_items = []
        old_to_new_index = {}
        new_idx = 0
        
        for old_idx, item in enumerate(self._items):
            if item.enc_filename in enc_filenames:
                removed.append(item)
                # Remove from selection
                self._selected_indices.discard(old_idx)
            else:
                new_items.append(item)
                old_to_new_index[old_idx] = new_idx
                new_idx += 1
        
        # Update selected indices to new positions
        new_selected = set()
        for old_idx in self._selected_indices:
            if old_idx in old_to_new_index:
                new_selected.add(old_to_new_index[old_idx])
        self._selected_indices = new_selected
        
        # Update last clicked
        if self._last_clicked_index is not None:
            if self._last_clicked_index in old_to_new_index:
                self._last_clicked_index = old_to_new_index[self._last_clicked_index]
            else:
                self._last_clicked_index = None
        
        self._items = new_items
        
        # Clear active cards and re-render
        for card in self._active_cards.values():
            card.hide()
            self._card_pool.append(card)
        self._active_cards.clear()
        
        self._schedule_layout()
        return removed
    
    def update_item_thumbnail(self, enc_filename: str, thumbnail_data: bytes):
        """Update thumbnail for a specific item."""
        for idx, item in enumerate(self._items):
            if item.enc_filename == enc_filename:
                item.thumbnail_data = thumbnail_data
                # If this item is currently visible, update its card
                if idx in self._active_cards:
                    self._active_cards[idx].set_thumbnail(thumbnail_data)
                break
    
    def count(self) -> int:
        """Get number of items."""
        return len(self._items)
    
    def clear(self):
        """Clear all items."""
        for card in self._active_cards.values():
            card.hide()
            self._card_pool.append(card)
        self._active_cards.clear()
        self._items.clear()
        self._selected_indices.clear()
        self._last_clicked_index = None
        self._schedule_layout()
    
    def set_viewport(self, top: int, height: int):
        """Update viewport position and size."""
        if self._viewport_top != top or self._viewport_height != height:
            self._viewport_top = top
            self._viewport_height = height
            self._update_visible_cards()
    
    def _schedule_layout(self):
        """Schedule a layout update."""
        if not self._layout_pending:
            self._layout_pending = True
            QTimer.singleShot(0, self._do_layout)
    
    def _do_layout(self):
        """Perform layout calculation."""
        self._layout_pending = False
        self._calculate_layout()
        self._update_visible_cards()
    
    def _calculate_layout(self):
        """Calculate total height based on items."""
        if not self._items:
            self._total_height = 0
            self._left_margin = 0
            self.setMinimumHeight(0)
            return
        
        width = max(self.width(), 200)
        self._cols = max(1, (width + self._spacing) // (self._item_width + self._spacing))
        
        # Calculate left margin for centering
        used_width = self._cols * (self._item_width + self._spacing) - self._spacing
        self._left_margin = max(0, (width - used_width) // 2)
        
        rows = (len(self._items) + self._cols - 1) // self._cols
        self._total_height = rows * (self._item_height + self._spacing)
        self.setMinimumHeight(self._total_height)
    
    def _get_visible_range(self) -> Tuple[int, int]:
        """Calculate which items are visible in the viewport."""
        if not self._items or self._cols == 0:
            return (0, 0)
        
        row_height = self._item_height + self._spacing
        
        # Calculate visible rows with some buffer (render 2 extra rows above/below)
        buffer_rows = 2
        first_visible_row = max(0, (self._viewport_top // row_height) - buffer_rows)
        last_visible_row = ((self._viewport_top + self._viewport_height) // row_height) + buffer_rows
        
        start_idx = first_visible_row * self._cols
        end_idx = min(len(self._items), (last_visible_row + 1) * self._cols)
        
        return (start_idx, end_idx)
    
    def _update_visible_cards(self):
        """Update which cards are rendered based on viewport."""
        if not self._items:
            # Hide all active cards
            for card in self._active_cards.values():
                card.hide()
                self._card_pool.append(card)
            self._active_cards.clear()
            return
        
        start_idx, end_idx = self._get_visible_range()
        visible_indices = set(range(start_idx, end_idx))
        
        # Find cards to remove (no longer visible)
        to_remove = []
        for idx in self._active_cards:
            if idx not in visible_indices:
                to_remove.append(idx)
        
        # Return removed cards to pool
        for idx in to_remove:
            card = self._active_cards.pop(idx)
            card.hide()
            self._card_pool.append(card)
        
        # Add cards for newly visible items
        for idx in range(start_idx, end_idx):
            if idx not in self._active_cards:
                card = self._get_card()
                self._setup_card(card, idx)
                self._active_cards[idx] = card
        
        # Position all active cards
        self._position_cards()
        
        # Emit signal for thumbnail loading
        self.visible_range_changed.emit(start_idx, end_idx)
    
    def _get_card(self) -> FileCard:
        """Get a card from pool or create new one."""
        if self._card_pool:
            card = self._card_pool.pop()
        else:
            card = FileCard(
                enc_filename="",
                original_filename="",
                is_encrypted=True
            )
            card.setParent(self)
            # Connect signals once when creating
            card.clicked.connect(self._on_card_clicked)
            card.double_clicked.connect(self._on_card_double_clicked)
            card.context_menu_requested.connect(self._on_context_menu)
        
        # Apply current scale
        card.setFixedSize(self._item_width, self._item_height)
        card.update_scale(self._scale)
        
        return card
    
    def _setup_card(self, card: FileCard, idx: int):
        """Configure a card for a specific item."""
        item = self._items[idx]
        card.update_data(
            enc_filename=item.enc_filename,
            original_filename=item.original_filename,
            thumbnail_data=item.thumbnail_data,
            has_thumbnail=item.has_thumbnail,
            is_image=item.is_image,
            is_encrypted=item.is_encrypted
        )
        card.selected = idx in self._selected_indices
        card.setProperty("item_index", idx)
    
    def _position_cards(self):
        """Position all active cards (centered)."""
        for idx, card in self._active_cards.items():
            row = idx // self._cols
            col = idx % self._cols
            x = self._left_margin + col * (self._item_width + self._spacing)
            y = row * (self._item_height + self._spacing)
            card.move(x, y)
            card.show()
    
    def _on_card_clicked(self, card: FileCard, ctrl: bool, shift: bool):
        """Handle card click."""
        idx = card.property("item_index")
        if idx is None:
            return
        
        if self._on_card_clicked_callback:
            self._on_card_clicked_callback(idx, ctrl, shift)
    
    def _on_card_double_clicked(self, card: FileCard):
        """Handle card double click."""
        idx = card.property("item_index")
        if idx is None:
            return
        
        if self._on_card_double_clicked_callback:
            self._on_card_double_clicked_callback(idx)
    
    def _on_context_menu(self, card: FileCard, position: QPoint):
        """Handle context menu."""
        idx = card.property("item_index")
        if idx is None:
            return
        
        if self._on_context_menu_callback:
            self._on_context_menu_callback(idx, position)
    
    # Selection management
    def select_index(self, idx: int):
        """Select an item by index."""
        if 0 <= idx < len(self._items):
            self._selected_indices.add(idx)
            if idx in self._active_cards:
                self._active_cards[idx].selected = True
    
    def deselect_index(self, idx: int):
        """Deselect an item by index."""
        self._selected_indices.discard(idx)
        if idx in self._active_cards:
            self._active_cards[idx].selected = False
    
    def clear_selection(self):
        """Clear all selections."""
        for idx in self._selected_indices:
            if idx in self._active_cards:
                self._active_cards[idx].selected = False
        self._selected_indices.clear()
    
    def select_all(self):
        """Select all items."""
        self._selected_indices = set(range(len(self._items)))
        for idx, card in self._active_cards.items():
            card.selected = True
    
    def get_selected_indices(self) -> Set[int]:
        """Get selected item indices."""
        return self._selected_indices.copy()
    
    def set_last_clicked(self, idx: Optional[int]):
        """Set last clicked index."""
        self._last_clicked_index = idx
    
    def get_last_clicked(self) -> Optional[int]:
        """Get last clicked index."""
        return self._last_clicked_index
    
    def resizeEvent(self, event):
        """Handle resize with debounce."""
        super().resizeEvent(event)
        
        # Debounce resize - wait 50ms after last resize before layout
        if self._resize_timer is not None:
            self._resize_timer.stop()
        
        self._resize_timer = QTimer()
        self._resize_timer.setSingleShot(True)
        self._resize_timer.timeout.connect(self._schedule_layout)
        self._resize_timer.start(50)


class FileGrid(QScrollArea):
    """
    Scrollable grid view for files with virtualization.
    
    Features:
    - Virtualized rendering (only visible items rendered)
    - Responsive grid layout
    - Single and multi-selection
    - Context menu support
    - Zoom with Ctrl+wheel
    """
    
    selection_changed = pyqtSignal(list)  # List of selected indices
    file_double_clicked = pyqtSignal(object)  # FileInfo
    decrypt_requested = pyqtSignal(list)  # List of FileInfo
    encrypt_requested = pyqtSignal(list)  # List of FileInfo
    visible_range_changed = pyqtSignal(int, int)  # For lazy thumbnail loading
    scale_changed = pyqtSignal(float)  # For zoom slider sync
    
    def __init__(self, mode: str = "encrypted", parent=None):
        super().__init__(parent)
        
        self._mode = mode
        self._filter_extension: str = ""
        self._filter_text: str = ""
        
        # All files (unfiltered)
        self._all_files: List[FileInfo] = []
        
        self._setup_ui()
        self._connect_signals()
    
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
        
        # Virtualized flow layout
        self._flow = VirtualizedFlowLayout()
        self._flow.set_callbacks(
            clicked=self._on_item_clicked,
            double_clicked=self._on_item_double_clicked,
            context_menu=self._on_context_menu
        )
        main_layout.addWidget(self._flow)
        main_layout.addStretch()
        
        # Empty state label
        empty_text = "No encrypted files" if self._mode == "encrypted" else "No files to encrypt"
        self._empty_label = QLabel(empty_text)
        self._empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_label.setStyleSheet(f"""
            color: {Theme.colors.text_muted};
            font-size: {Theme.typography.size_lg}px;
            padding: 60px;
        """)
        self._empty_label.hide()
        main_layout.addWidget(self._empty_label)
    
    def _connect_signals(self):
        """Connect internal signals."""
        self.verticalScrollBar().valueChanged.connect(self._on_scroll)
        self._flow.visible_range_changed.connect(self._on_visible_range_changed)
    
    def _on_scroll(self, value: int):
        """Handle scroll events."""
        viewport_height = self.viewport().height()
        self._flow.set_viewport(value, viewport_height)
    
    def _on_visible_range_changed(self, start: int, end: int):
        """Forward visible range signal."""
        self.visible_range_changed.emit(start, end)
    
    def set_files(self, files: List[FileInfo]):
        """Set the files to display."""
        self._all_files = files
        self._apply_filter()
    
    def _apply_filter(self):
        """Apply current filter and update display."""
        filtered = []
        
        for file_info in self._all_files:
            # Check extension filter
            if self._filter_extension:
                ext = file_info.extension.lower() if file_info.extension else ""
                if ext != self._filter_extension:
                    continue
            
            # Check text filter
            if self._filter_text:
                if self._filter_text.lower() not in file_info.original_filename.lower():
                    continue
            
            filtered.append(file_info)
        
        self._flow.set_items(filtered)
        self._empty_label.setVisible(len(filtered) == 0)
        
        # Emit selection change
        self.selection_changed.emit(list(self._flow.get_selected_indices()))
        
        # Trigger initial viewport update
        QTimer.singleShot(0, self._update_viewport)
    
    def _update_viewport(self):
        """Update viewport after layout changes."""
        viewport_height = self.viewport().height()
        scroll_pos = self.verticalScrollBar().value()
        self._flow.set_viewport(scroll_pos, viewport_height)
    
    def set_filter_extension(self, extension: str):
        """Filter by file extension."""
        self._filter_extension = extension.lower() if extension else ""
        self._apply_filter()
    
    def set_filter_text(self, text: str):
        """Filter by filename text."""
        self._filter_text = text
        self._apply_filter()
    
    def _on_item_clicked(self, idx: int, ctrl: bool, shift: bool):
        """Handle item click."""
        items = self._flow.get_items()
        last_clicked = self._flow.get_last_clicked()
        
        if shift and last_clicked is not None and 0 <= last_clicked < len(items):
            # Range selection
            start_idx = min(last_clicked, idx)
            end_idx = max(last_clicked, idx)
            self._flow.clear_selection()
            for i in range(start_idx, end_idx + 1):
                self._flow.select_index(i)
        elif ctrl:
            # Toggle selection
            if idx in self._flow.get_selected_indices():
                self._flow.deselect_index(idx)
            else:
                self._flow.select_index(idx)
        else:
            # Single selection
            self._flow.clear_selection()
            self._flow.select_index(idx)
        
        self._flow.set_last_clicked(idx)
        self.selection_changed.emit(list(self._flow.get_selected_indices()))
    
    def _on_item_double_clicked(self, idx: int):
        """Handle item double click."""
        items = self._flow.get_items()
        if 0 <= idx < len(items):
            self.file_double_clicked.emit(items[idx])
    
    def _on_context_menu(self, idx: int, position: QPoint):
        """Show context menu."""
        items = self._flow.get_items()
        
        # Ensure clicked item is selected
        if idx not in self._flow.get_selected_indices():
            self._flow.clear_selection()
            self._flow.select_index(idx)
            self.selection_changed.emit(list(self._flow.get_selected_indices()))
        
        menu = QMenu(self)
        
        if self._mode == "encrypted":
            decrypt_action = QAction("Decrypt Selected", self)
            decrypt_action.triggered.connect(lambda: self._emit_decrypt_request())
            menu.addAction(decrypt_action)
        else:
            encrypt_action = QAction("Encrypt Selected", self)
            encrypt_action.triggered.connect(lambda: self._emit_encrypt_request())
            menu.addAction(encrypt_action)
        
        menu.addSeparator()
        select_all_action = QAction("Select All", self)
        select_all_action.triggered.connect(self.select_all)
        menu.addAction(select_all_action)
        
        menu.exec(position)
    
    def _emit_decrypt_request(self):
        """Emit decrypt request with selected items."""
        selected = self.get_selected()
        if selected:
            self.decrypt_requested.emit(selected)
    
    def _emit_encrypt_request(self):
        """Emit encrypt request with selected items."""
        selected = self.get_selected()
        if selected:
            self.encrypt_requested.emit(selected)
    
    def get_selected(self) -> List[FileInfo]:
        """Get list of selected files."""
        items = self._flow.get_items()
        indices = self._flow.get_selected_indices()
        return [items[i] for i in sorted(indices) if 0 <= i < len(items)]
    
    def select_all(self):
        """Select all visible items."""
        self._flow.select_all()
        self.selection_changed.emit(list(self._flow.get_selected_indices()))
    
    def clear_selection(self):
        """Clear all selections."""
        self._flow.clear_selection()
        self.selection_changed.emit([])
    
    def get_extensions(self) -> List[str]:
        """Get list of unique extensions from all files."""
        extensions = set()
        for f in self._all_files:
            if f.extension:
                extensions.add(f.extension.lower())
        return sorted(extensions)
    
    def get_file_count(self) -> int:
        """Get total number of files."""
        return len(self._all_files)
    
    def get_visible_count(self) -> int:
        """Get number of visible (filtered) files."""
        return self._flow.count()
    
    def clear_files(self):
        """Clear all files from the grid."""
        self._all_files.clear()
        self._flow.clear()
        self._empty_label.setVisible(True)
    
    def update_card_thumbnail(self, enc_filename: str, thumbnail_data: bytes):
        """Update thumbnail for a specific file."""
        # Update in all_files
        for f in self._all_files:
            if f.enc_filename == enc_filename:
                f.thumbnail_data = thumbnail_data
                break
        # Update in flow (filtered items)
        self._flow.update_item_thumbnail(enc_filename, thumbnail_data)
    
    def remove_files(self, enc_filenames: List[str]) -> List[FileInfo]:
        """Remove files by enc_filename."""
        filenames_set = set(enc_filenames)
        
        # Remove from all_files
        removed = []
        new_all = []
        for f in self._all_files:
            if f.enc_filename in filenames_set:
                removed.append(f)
            else:
                new_all.append(f)
        self._all_files = new_all
        
        # Remove from flow
        self._flow.remove_items(filenames_set)
        
        # Update empty state
        self._empty_label.setVisible(self._flow.count() == 0)
        
        # Emit selection change
        self.selection_changed.emit(list(self._flow.get_selected_indices()))
        
        return removed
    
    def add_files(self, files: List[FileInfo]):
        """Add files to the grid."""
        self._all_files.extend(files)
        
        # Filter new files
        filtered_new = []
        for file_info in files:
            passes = True
            if self._filter_extension:
                ext = file_info.extension.lower() if file_info.extension else ""
                if ext != self._filter_extension:
                    passes = False
            if self._filter_text:
                if self._filter_text.lower() not in file_info.original_filename.lower():
                    passes = False
            if passes:
                filtered_new.append(file_info)
        
        if filtered_new:
            self._flow.add_items(filtered_new)
        
        self._empty_label.setVisible(self._flow.count() == 0)
    
    def resizeEvent(self, event):
        """Handle resize."""
        super().resizeEvent(event)
        QTimer.singleShot(0, self._update_viewport)
    
    def set_scale(self, scale: float):
        """Set the scale factor for items."""
        self._flow.set_scale(scale)
    
    def get_scale(self) -> float:
        """Get current scale factor."""
        return self._flow.get_scale()
    
    def wheelEvent(self, event):
        """Handle wheel event - Ctrl+wheel for zoom."""
        from PyQt6.QtCore import Qt
        from PyQt6.QtGui import QWheelEvent
        
        if event.modifiers() == Qt.KeyboardModifier.ControlModifier:
            # Zoom with Ctrl+wheel
            delta = event.angleDelta().y()
            current_scale = self._flow.get_scale()
            
            if delta > 0:
                new_scale = current_scale + Theme.ZOOM_STEP
            else:
                new_scale = current_scale - Theme.ZOOM_STEP
            
            new_scale = max(Theme.MIN_CARD_SCALE, min(Theme.MAX_CARD_SCALE, new_scale))
            
            if new_scale != current_scale:
                self._flow.set_scale(new_scale)
                self.scale_changed.emit(new_scale)
            
            event.accept()
        else:
            # Normal scroll
            super().wheelEvent(event)
