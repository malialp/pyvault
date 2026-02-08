"""
Search Bar Widget

Search and filter controls for the file grid.
"""

from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QLineEdit, QComboBox, QLabel
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QIcon

from ..styles.theme import Theme
from typing import List


class SearchBar(QWidget):
    """
    Search and filter bar for file grid.
    
    Features:
    - Text search with debounce
    - Extension filter dropdown
    
    Signals:
        search_changed: Emitted when search text changes (debounced)
        filter_changed: Emitted when extension filter changes
    """
    
    search_changed = pyqtSignal(str)
    filter_changed = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self._debounce_timer = QTimer()
        self._debounce_timer.setSingleShot(True)
        self._debounce_timer.setInterval(300)
        self._debounce_timer.timeout.connect(self._emit_search)
        
        self._setup_ui()
        self._connect_signals()
    
    def _setup_ui(self):
        """Initialize the user interface."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(Theme.spacing.md)
        
        # Search input
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Search files...")
        self._search_input.setClearButtonEnabled(True)
        self._search_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {Theme.colors.bg_secondary};
                color: {Theme.colors.text_primary};
                border: 1px solid {Theme.colors.border_default};
                border-radius: {Theme.radius.lg}px;
                padding: 8px 16px;
                padding-left: 36px;
                font-size: {Theme.typography.size_md}px;
                min-width: 250px;
            }}
            QLineEdit:focus {{
                border-color: {Theme.colors.accent_primary};
                background-color: {Theme.colors.bg_elevated};
            }}
        """)
        layout.addWidget(self._search_input)
        
        # Search icon overlay (using unicode)
        search_icon = QLabel("🔍")
        search_icon.setStyleSheet(f"""
            background: transparent;
            color: {Theme.colors.text_muted};
            font-size: 14px;
        """)
        search_icon.setParent(self._search_input)
        search_icon.move(12, 7)
        
        # Spacer
        layout.addStretch()
        
        # Filter label
        filter_label = QLabel("Filter:")
        filter_label.setStyleSheet(f"""
            color: {Theme.colors.text_secondary};
            font-size: {Theme.typography.size_sm}px;
            background: transparent;
        """)
        layout.addWidget(filter_label)
        
        # Extension filter dropdown
        self._filter_combo = QComboBox()
        self._filter_combo.setStyleSheet(f"""
            QComboBox {{
                background-color: {Theme.colors.bg_secondary};
                color: {Theme.colors.text_primary};
                border: 1px solid {Theme.colors.border_default};
                border-radius: {Theme.radius.md}px;
                padding: 6px 12px;
                min-width: 120px;
                font-size: {Theme.typography.size_sm}px;
            }}
            QComboBox:hover {{
                border-color: {Theme.colors.border_accent};
            }}
            QComboBox::drop-down {{
                border: none;
                width: 20px;
            }}
            QComboBox::down-arrow {{
                image: none;
                border-left: 4px solid transparent;
                border-right: 4px solid transparent;
                border-top: 5px solid {Theme.colors.text_secondary};
                margin-right: 6px;
            }}
            QComboBox QAbstractItemView {{
                background-color: {Theme.colors.bg_secondary};
                color: {Theme.colors.text_primary};
                border: 1px solid {Theme.colors.border_default};
                border-radius: {Theme.radius.md}px;
                selection-background-color: {Theme.colors.selection_bg};
                outline: none;
                padding: 4px;
            }}
            QComboBox QAbstractItemView::item {{
                padding: 6px 10px;
                border-radius: {Theme.radius.sm}px;
            }}
            QComboBox QAbstractItemView::item:hover {{
                background-color: {Theme.colors.bg_tertiary};
            }}
        """)
        self._filter_combo.addItem("All Files", "")
        layout.addWidget(self._filter_combo)
    
    def _connect_signals(self):
        """Connect widget signals."""
        self._search_input.textChanged.connect(self._on_search_changed)
        self._filter_combo.currentIndexChanged.connect(self._on_filter_changed)
    
    def _on_search_changed(self, text: str):
        """Handle search text change with debounce."""
        self._debounce_timer.start()
    
    def _emit_search(self):
        """Emit search changed signal after debounce."""
        self.search_changed.emit(self._search_input.text())
    
    def _on_filter_changed(self, index: int):
        """Handle filter selection change."""
        extension = self._filter_combo.currentData()
        self.filter_changed.emit(extension or "")
    
    def set_extensions(self, extensions: List[str]):
        """
        Update available extensions in filter dropdown.
        
        Args:
            extensions: List of extensions (e.g., ['.jpg', '.png'])
        """
        current = self._filter_combo.currentData()
        
        self._filter_combo.clear()
        self._filter_combo.addItem("All Files", "")
        
        for ext in extensions:
            display_name = ext.upper().lstrip('.')
            self._filter_combo.addItem(f"{display_name} Files", ext)
        
        # Restore previous selection if possible
        if current:
            index = self._filter_combo.findData(current)
            if index >= 0:
                self._filter_combo.setCurrentIndex(index)
    
    def clear(self):
        """Clear search and filter."""
        self._search_input.clear()
        self._filter_combo.setCurrentIndex(0)
    
    def get_search_text(self) -> str:
        """Get current search text."""
        return self._search_input.text()
    
    def get_filter_extension(self) -> str:
        """Get current filter extension."""
        return self._filter_combo.currentData() or ""

