"""
Main Window

The main application window for PyVault GUI.
"""

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QFrame, QMessageBox, QProgressDialog,
    QApplication, QTabWidget, QProgressBar, QSlider
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QCloseEvent

from .widgets.file_grid import FileGrid, FileInfo
from .widgets.search_bar import SearchBar
from .widgets.toolbar import Toolbar
from .styles.theme import Theme, get_stylesheet
from .workers import FileListWorker, ThumbnailWorker, OperationWorker, FileItem

from typing import List, Optional, Dict
import os


class FileTab(QWidget):
    """
    A tab containing a file grid with toolbar and search.
    """
    
    def __init__(self, mode: str = "encrypted", parent=None):
        super().__init__(parent)
        self._mode = mode
        self._setup_ui()
        self._connect_signals()
    
    def _setup_ui(self):
        """Initialize UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Toolbar
        self._toolbar = Toolbar(mode=self._mode)
        layout.addWidget(self._toolbar)
        
        # Loading bar
        self._loading_bar = QProgressBar()
        self._loading_bar.setTextVisible(True)
        self._loading_bar.setFormat("Loading... %p%")
        self._loading_bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: {Theme.colors.bg_secondary};
                border: none;
                height: 3px;
                text-align: center;
            }}
            QProgressBar::chunk {{
                background-color: {Theme.colors.accent_primary};
            }}
        """)
        self._loading_bar.hide()
        layout.addWidget(self._loading_bar)
        
        # Search bar
        search_container = QFrame()
        search_container.setStyleSheet(f"""
            background-color: {Theme.colors.bg_primary};
            border-bottom: 1px solid {Theme.colors.border_muted};
        """)
        search_layout = QHBoxLayout(search_container)
        search_layout.setContentsMargins(
            Theme.spacing.lg, Theme.spacing.md,
            Theme.spacing.lg, Theme.spacing.md
        )
        
        self._search_bar = SearchBar()
        search_layout.addWidget(self._search_bar)
        layout.addWidget(search_container)
        
        # File grid
        self._file_grid = FileGrid(mode=self._mode)
        layout.addWidget(self._file_grid, 1)
    
    def _connect_signals(self):
        """Connect signals."""
        self._search_bar.search_changed.connect(self._file_grid.set_filter_text)
        self._search_bar.filter_changed.connect(self._file_grid.set_filter_extension)
        self._toolbar.select_all_clicked.connect(self._file_grid.select_all)
        self._file_grid.selection_changed.connect(self._on_selection_changed)
    
    def get_toolbar(self) -> Toolbar:
        return self._toolbar
    
    def get_file_grid(self) -> FileGrid:
        return self._file_grid
    
    def set_loading(self, loading: bool, progress: int = 0, total: int = 100):
        """Show/hide loading."""
        if loading:
            self._loading_bar.setMaximum(total)
            self._loading_bar.setValue(progress)
            self._loading_bar.show()
        else:
            self._loading_bar.hide()
    
    def set_files(self, items: List[FileItem]):
        """Set files from worker results."""
        files = [
            FileInfo(
                enc_filename=item.enc_filename,
                original_filename=item.original_filename,
                thumbnail_data=None,  # Thumbnails loaded separately
                has_thumbnail=item.has_thumbnail,
                is_image=item.is_image,
                extension=item.extension,
                is_encrypted=item.is_encrypted
            )
            for item in items
        ]
        self._file_grid.set_files(files)
        self._search_bar.set_extensions(self._file_grid.get_extensions())
        self._update_counts()
    
    def clear_files(self):
        """Clear files."""
        self._file_grid.clear_files()
    
    def update_thumbnail(self, enc_filename: str, thumbnail_data: bytes):
        """Update a thumbnail."""
        self._file_grid.update_card_thumbnail(enc_filename, thumbnail_data)
    
    def remove_files(self, enc_filenames: list):
        """Remove files from the grid by their enc_filename."""
        self._file_grid.remove_files(enc_filenames)
        self._search_bar.set_extensions(self._file_grid.get_extensions())
        self._update_counts()
    
    def add_files(self, items: list):
        """Add files to the grid."""
        from .workers import FileItem
        files = [
            FileInfo(
                enc_filename=item.enc_filename,
                original_filename=item.original_filename,
                thumbnail_data=None,
                has_thumbnail=item.has_thumbnail,
                is_image=item.is_image,
                extension=item.extension,
                is_encrypted=item.is_encrypted
            )
            for item in items
        ]
        self._file_grid.add_files(files)
        self._search_bar.set_extensions(self._file_grid.get_extensions())
        self._update_counts()
    
    def _on_selection_changed(self, selected: list):
        """Handle selection change."""
        self._toolbar.set_selection_count(len(selected))
    
    def _update_counts(self):
        """Update counts."""
        self._toolbar.set_total_count(
            self._file_grid.get_file_count(),
            self._file_grid.get_visible_count()
        )
    
    def get_file_count(self) -> int:
        return self._file_grid.get_file_count()


class MainWindow(QMainWindow):
    """
    Main application window.
    
    Uses background workers for file loading and thumbnail extraction.
    """
    
    def __init__(self, password: str, parent=None):
        super().__init__(parent)
        
        self._password = password
        self._fernet = None
        self._salt_hash = None
        self._config = None
        
        # Workers
        self._list_worker: Optional[FileListWorker] = None
        self._enc_thumbnail_worker: Optional[ThumbnailWorker] = None
        self._unenc_thumbnail_worker: Optional[ThumbnailWorker] = None
        self._operation_worker: Optional[OperationWorker] = None
        
        # File lists for thumbnail loading
        self._encrypted_files: List[str] = []
        self._unencrypted_files: List[str] = []
        
        # Track which thumbnails have been loaded (for lazy loading)
        self._loaded_enc_thumbnails: set = set()
        self._loaded_unenc_thumbnails: set = set()
        
        # Pending thumbnail requests (debounce)
        self._pending_enc_thumbnails: List[str] = []
        self._pending_unenc_thumbnails: List[str] = []
        self._thumbnail_load_timer: Optional[QTimer] = None
        
        self._setup_crypto()
        self._setup_ui()
        self._connect_signals()
        
        # Start loading
        QTimer.singleShot(100, self._load_files)
    
    def _setup_crypto(self):
        """Initialize crypto."""
        from ..vault import get_fernet, get_config
        from ..crypto import hash_salt
        
        self._config = get_config()
        self._fernet = get_fernet(self._password)
        
        salt = bytes.fromhex(self._config["salt"])
        self._salt_hash = hash_salt(salt)
    
    def _setup_ui(self):
        """Initialize UI."""
        self.setWindowTitle("PyVault")
        self.setMinimumSize(900, 600)
        self.resize(1100, 700)
        self.setStyleSheet(get_stylesheet())
        
        central = QWidget()
        self.setCentralWidget(central)
        
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Header
        header = self._create_header()
        main_layout.addWidget(header)
        
        # Tabs
        self._tab_widget = QTabWidget()
        self._tab_widget.setStyleSheet(f"""
            QTabWidget::pane {{
                border: none;
                background-color: {Theme.colors.bg_primary};
            }}
            QTabBar::tab {{
                background-color: {Theme.colors.bg_secondary};
                color: {Theme.colors.text_secondary};
                border: none;
                border-bottom: 2px solid transparent;
                padding: 12px 24px;
                font-size: {Theme.typography.size_md}px;
                font-weight: 500;
            }}
            QTabBar::tab:selected {{
                color: {Theme.colors.text_primary};
                border-bottom: 2px solid {Theme.colors.accent_primary};
                background-color: {Theme.colors.bg_primary};
            }}
            QTabBar::tab:hover:!selected {{
                color: {Theme.colors.text_primary};
                background-color: {Theme.colors.bg_tertiary};
            }}
        """)
        
        self._encrypted_tab = FileTab(mode="encrypted")
        self._tab_widget.addTab(self._encrypted_tab, "Encrypted")
        
        self._unencrypted_tab = FileTab(mode="unencrypted")
        self._tab_widget.addTab(self._unencrypted_tab, "Unencrypted")
        
        main_layout.addWidget(self._tab_widget, 1)
        
        # Status bar
        self._status_bar = self._create_status_bar()
        main_layout.addWidget(self._status_bar)
    
    def _create_header(self) -> QFrame:
        """Create header."""
        header = QFrame()
        header.setStyleSheet(f"""
            background-color: {Theme.colors.bg_secondary};
            border-bottom: 1px solid {Theme.colors.border_muted};
        """)
        
        layout = QHBoxLayout(header)
        layout.setContentsMargins(
            Theme.spacing.lg, Theme.spacing.md,
            Theme.spacing.lg, Theme.spacing.md
        )
        
        title_layout = QHBoxLayout()
        title_layout.setSpacing(Theme.spacing.sm)
        
        logo = QLabel("[P]")
        logo.setStyleSheet(f"""
            font-size: 20px;
            font-weight: bold;
            color: {Theme.colors.accent_primary};
            background: transparent;
        """)
        title_layout.addWidget(logo)
        
        title = QLabel("PyVault")
        title.setStyleSheet(f"""
            font-size: {Theme.typography.size_xl}px;
            font-weight: 600;
            color: {Theme.colors.text_primary};
            background: transparent;
        """)
        title_layout.addWidget(title)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        vault_path = os.path.basename(os.getcwd())
        path_label = QLabel(f"[{vault_path}]")
        path_label.setStyleSheet(f"""
            color: {Theme.colors.text_secondary};
            font-size: {Theme.typography.size_sm}px;
            background: transparent;
        """)
        path_label.setToolTip(os.getcwd())
        layout.addWidget(path_label)
        
        return header
    
    def _create_status_bar(self) -> QFrame:
        """Create status bar."""
        status_bar = QFrame()
        status_bar.setStyleSheet(f"""
            background-color: {Theme.colors.bg_secondary};
            border-top: 1px solid {Theme.colors.border_muted};
        """)
        
        layout = QHBoxLayout(status_bar)
        layout.setContentsMargins(
            Theme.spacing.lg, Theme.spacing.sm,
            Theme.spacing.lg, Theme.spacing.sm
        )
        
        self._status_label = QLabel("Ready")
        self._status_label.setStyleSheet(f"""
            color: {Theme.colors.text_muted};
            font-size: {Theme.typography.size_xs}px;
            background: transparent;
        """)
        layout.addWidget(self._status_label)
        
        layout.addStretch()
        
        # Zoom slider
        zoom_label = QLabel("🔍")
        zoom_label.setStyleSheet(f"""
            color: {Theme.colors.text_muted};
            font-size: {Theme.typography.size_sm}px;
            background: transparent;
        """)
        layout.addWidget(zoom_label)
        
        self._zoom_slider = QSlider(Qt.Orientation.Horizontal)
        self._zoom_slider.setMinimum(int(Theme.MIN_CARD_SCALE * 100))
        self._zoom_slider.setMaximum(int(Theme.MAX_CARD_SCALE * 100))
        self._zoom_slider.setValue(int(Theme.DEFAULT_CARD_SCALE * 100))
        self._zoom_slider.setFixedWidth(100)
        self._zoom_slider.setStyleSheet(f"""
            QSlider::groove:horizontal {{
                height: 4px;
                background: {Theme.colors.bg_tertiary};
                border-radius: 2px;
            }}
            QSlider::handle:horizontal {{
                background: {Theme.colors.accent_primary};
                width: 12px;
                height: 12px;
                margin: -4px 0;
                border-radius: 6px;
            }}
            QSlider::handle:horizontal:hover {{
                background: {Theme.colors.accent_purple};
            }}
        """)
        layout.addWidget(self._zoom_slider)
        
        self._zoom_value_label = QLabel("100%")
        self._zoom_value_label.setFixedWidth(40)
        self._zoom_value_label.setStyleSheet(f"""
            color: {Theme.colors.text_muted};
            font-size: {Theme.typography.size_xs}px;
            background: transparent;
        """)
        layout.addWidget(self._zoom_value_label)
        
        # Spacer
        spacer = QLabel(" ")
        spacer.setFixedWidth(Theme.spacing.lg)
        layout.addWidget(spacer)
        
        from ..settings import APP_VERSION
        version_label = QLabel(f"v{APP_VERSION}")
        version_label.setStyleSheet(f"""
            color: {Theme.colors.text_muted};
            font-size: {Theme.typography.size_xs}px;
            background: transparent;
        """)
        layout.addWidget(version_label)
        
        return status_bar
    
    def _connect_signals(self):
        """Connect signals."""
        # Toolbar
        self._encrypted_tab.get_toolbar().action_clicked.connect(
            lambda: self._on_action("decrypt")
        )
        self._encrypted_tab.get_toolbar().refresh_clicked.connect(self._load_files)
        
        self._unencrypted_tab.get_toolbar().action_clicked.connect(
            lambda: self._on_action("encrypt")
        )
        self._unencrypted_tab.get_toolbar().refresh_clicked.connect(self._load_files)
        
        # File grid
        self._encrypted_tab.get_file_grid().file_double_clicked.connect(
            lambda card: self._process_files([card], "decrypt")
        )
        self._encrypted_tab.get_file_grid().decrypt_requested.connect(
            lambda cards: self._process_files(cards, "decrypt")
        )
        
        self._unencrypted_tab.get_file_grid().file_double_clicked.connect(
            lambda card: self._process_files([card], "encrypt")
        )
        self._unencrypted_tab.get_file_grid().encrypt_requested.connect(
            lambda cards: self._process_files(cards, "encrypt")
        )
        
        # Lazy thumbnail loading - load thumbnails as user scrolls
        self._encrypted_tab.get_file_grid().visible_range_changed.connect(
            lambda start, end: self._on_visible_range_changed(start, end, is_encrypted=True)
        )
        self._unencrypted_tab.get_file_grid().visible_range_changed.connect(
            lambda start, end: self._on_visible_range_changed(start, end, is_encrypted=False)
        )
        
        # Zoom slider
        self._zoom_slider.valueChanged.connect(self._on_zoom_slider_changed)
        
        # Sync zoom from grid (Ctrl+wheel)
        self._encrypted_tab.get_file_grid().scale_changed.connect(self._on_grid_scale_changed)
        self._unencrypted_tab.get_file_grid().scale_changed.connect(self._on_grid_scale_changed)
    
    def _on_zoom_slider_changed(self, value: int):
        """Handle zoom slider value change."""
        scale = value / 100.0
        self._encrypted_tab.get_file_grid().set_scale(scale)
        self._unencrypted_tab.get_file_grid().set_scale(scale)
        self._zoom_value_label.setText(f"{value}%")
    
    def _on_grid_scale_changed(self, scale: float):
        """Handle scale change from grid (Ctrl+wheel)."""
        value = int(scale * 100)
        self._zoom_slider.blockSignals(True)
        self._zoom_slider.setValue(value)
        self._zoom_slider.blockSignals(False)
        self._zoom_value_label.setText(f"{value}%")
        
        # Sync to other grid
        self._encrypted_tab.get_file_grid().set_scale(scale)
        self._unencrypted_tab.get_file_grid().set_scale(scale)
    
    def _load_files(self):
        """Load file lists."""
        # Cancel existing workers
        self._cancel_workers()
        
        # Clear loaded thumbnails tracking
        self._loaded_enc_thumbnails.clear()
        self._loaded_unenc_thumbnails.clear()
        self._pending_enc_thumbnails.clear()
        self._pending_unenc_thumbnails.clear()
        
        # Clear
        self._encrypted_tab.clear_files()
        self._unencrypted_tab.clear_files()
        
        # Get file lists
        from ..vault import get_files
        vault_files = get_files()
        
        self._encrypted_files = list(vault_files['encrypted_files'])
        self._unencrypted_files = list(vault_files['unencrypted_files'])
        
        # Update tabs
        self._tab_widget.setTabText(0, f"Encrypted ({len(self._encrypted_files)})")
        self._tab_widget.setTabText(1, f"Unencrypted ({len(self._unencrypted_files)})")
        
        self._set_status(f"Loading {len(self._encrypted_files)} encrypted files...")
        
        # Show loading
        self._encrypted_tab.set_loading(True, 0, max(1, len(self._encrypted_files)))
        
        # Start encrypted loader
        if self._encrypted_files:
            self._load_encrypted_list()
        else:
            self._encrypted_tab.set_loading(False)
            self._load_unencrypted_list()
    
    def _load_encrypted_list(self):
        """Load encrypted file names."""
        worker = FileListWorker()
        worker.setup(
            files=self._encrypted_files,
            fernet=self._fernet,
            salt_hash=self._salt_hash,
            mode="encrypted"
        )
        
        worker.progress.connect(self._on_enc_progress)
        worker.finished_loading.connect(self._on_enc_finished)
        
        # Clean up reference when finished
        def on_finished():
            self._list_worker = None
            worker.deleteLater()
        worker.finished.connect(on_finished)
        
        self._list_worker = worker
        worker.start()
    
    def _on_enc_progress(self, current: int, total: int):
        """Handle encrypted loading progress."""
        self._encrypted_tab.set_loading(True, current, total)
        self._set_status(f"Loading encrypted files... {current}/{total}")
    
    def _on_enc_finished(self, results: List[FileItem]):
        """Handle encrypted loading complete."""
        self._encrypted_tab.set_files(results)
        self._encrypted_tab.set_loading(False)
        
        self._set_status(f"Loaded {len(results)} encrypted files")
        
        # Clear loaded thumbnails tracking (fresh load)
        self._loaded_enc_thumbnails.clear()
        
        # Thumbnails will be loaded lazily via visible_range_changed signal
        # No need to load all thumbnails upfront
        
        # Now load unencrypted
        self._load_unencrypted_list()
    
    def _load_unencrypted_list(self):
        """Load unencrypted file names."""
        if not self._unencrypted_files:
            self._on_unenc_finished([])
            return
        
        self._unencrypted_tab.set_loading(True, 0, len(self._unencrypted_files))
        
        worker = FileListWorker()
        worker.setup(
            files=self._unencrypted_files,
            fernet=None,
            salt_hash=b"",
            mode="unencrypted"
        )
        
        worker.progress.connect(self._on_unenc_progress)
        worker.finished_loading.connect(self._on_unenc_finished)
        
        # Clean up reference when finished
        def on_finished():
            self._list_worker = None
            worker.deleteLater()
        worker.finished.connect(on_finished)
        
        self._list_worker = worker
        worker.start()
    
    def _on_unenc_progress(self, current: int, total: int):
        """Handle unencrypted loading progress."""
        self._unencrypted_tab.set_loading(True, current, total)
    
    def _on_unenc_finished(self, results: List[FileItem]):
        """Handle unencrypted loading complete."""
        self._unencrypted_tab.set_files(results)
        self._unencrypted_tab.set_loading(False)
        
        enc_count = self._encrypted_tab.get_file_count()
        unenc_count = len(results)
        
        self._tab_widget.setTabText(0, f"Encrypted ({enc_count})")
        self._tab_widget.setTabText(1, f"Unencrypted ({unenc_count})")
        
        # Clear loaded thumbnails tracking (fresh load)
        self._loaded_unenc_thumbnails.clear()
        
        # Thumbnails will be loaded lazily via visible_range_changed signal
        # No need to load all thumbnails upfront
        
        self._set_status(f"Ready - {enc_count + unenc_count} files")
    
    def _load_thumbnails(self, filenames: List[str], is_encrypted: bool):
        """Load thumbnails for the given files."""
        if not filenames:
            return
        
        # Use separate workers for encrypted and unencrypted to prevent
        # one from cancelling the other (fixes thumbnail disappearing issue)
        if is_encrypted:
            # Cancel old encrypted thumbnail worker if running
            if self._enc_thumbnail_worker is not None:
                if self._enc_thumbnail_worker.isRunning():
                    self._enc_thumbnail_worker.cancel()
                    self._enc_thumbnail_worker.wait(500)
                # Note: deleteLater is called via finished signal
                self._enc_thumbnail_worker = None
        else:
            # Cancel old unencrypted thumbnail worker if running
            if self._unenc_thumbnail_worker is not None:
                if self._unenc_thumbnail_worker.isRunning():
                    self._unenc_thumbnail_worker.cancel()
                    self._unenc_thumbnail_worker.wait(500)
                # Note: deleteLater is called via finished signal
                self._unenc_thumbnail_worker = None
        
        # Filter to files that need thumbnails
        # For encrypted: check if has_thumbnail flag
        # For unencrypted: only images (videos are too slow)
        files_to_load = []
        
        if is_encrypted:
            # Load all that have thumbnails
            files_to_load = filenames
        else:
            # Only images for unencrypted
            from ..thumbnail import get_media_type, MediaType
            for f in filenames:
                if get_media_type(f) == MediaType.IMAGE:
                    files_to_load.append(f)
        
        if not files_to_load:
            return
        
        worker = ThumbnailWorker()
        worker.setup(
            files=files_to_load,
            password=self._password,
            is_encrypted=is_encrypted,
            fernet=self._fernet,
            salt_hash=self._salt_hash
        )
        
        worker.thumbnail_loaded.connect(
            lambda f, d: self._on_thumbnail_loaded(f, d, is_encrypted)
        )
        
        # Clean up worker reference and delete when finished
        def on_worker_finished():
            if is_encrypted:
                self._enc_thumbnail_worker = None
            else:
                self._unenc_thumbnail_worker = None
            worker.deleteLater()
        
        worker.finished.connect(on_worker_finished)
        
        # Store reference to appropriate worker
        if is_encrypted:
            self._enc_thumbnail_worker = worker
        else:
            self._unenc_thumbnail_worker = worker
        
        worker.start()
    
    def _on_thumbnail_loaded(self, enc_filename: str, data: bytes, is_encrypted: bool):
        """Handle thumbnail loaded."""
        # Mark as loaded
        if is_encrypted:
            self._loaded_enc_thumbnails.add(enc_filename)
            self._encrypted_tab.update_thumbnail(enc_filename, data)
        else:
            self._loaded_unenc_thumbnails.add(enc_filename)
            self._unencrypted_tab.update_thumbnail(enc_filename, data)
    
    def _on_visible_range_changed(self, start: int, end: int, is_encrypted: bool):
        """
        Handle visible range change for lazy thumbnail loading.
        
        This is called when user scrolls and new items become visible.
        We load thumbnails only for visible items that haven't been loaded yet.
        """
        if is_encrypted:
            grid = self._encrypted_tab.get_file_grid()
            loaded_set = self._loaded_enc_thumbnails
        else:
            grid = self._unencrypted_tab.get_file_grid()
            loaded_set = self._loaded_unenc_thumbnails
        
        # Get visible items from the flow layout
        flow = grid._flow
        items = flow.get_items()
        
        # Find items that need thumbnails and haven't been loaded
        files_to_load = []
        for idx in range(start, min(end, len(items))):
            item = items[idx]
            if item.has_thumbnail and item.enc_filename not in loaded_set:
                # Check if thumbnail data is already in the item
                if item.thumbnail_data is None:
                    files_to_load.append(item.enc_filename)
                    # Mark as pending to avoid duplicate requests
                    loaded_set.add(item.enc_filename)
        
        if files_to_load:
            # Use debounce to avoid loading during fast scroll
            self._queue_thumbnail_load(files_to_load, is_encrypted)
    
    def _queue_thumbnail_load(self, filenames: List[str], is_encrypted: bool):
        """Queue thumbnail load with debounce."""
        if is_encrypted:
            self._pending_enc_thumbnails.extend(filenames)
        else:
            self._pending_unenc_thumbnails.extend(filenames)
        
        # Cancel existing timer
        if self._thumbnail_load_timer:
            self._thumbnail_load_timer.stop()
        
        # Start new timer (50ms debounce)
        self._thumbnail_load_timer = QTimer()
        self._thumbnail_load_timer.setSingleShot(True)
        self._thumbnail_load_timer.timeout.connect(self._process_pending_thumbnails)
        self._thumbnail_load_timer.start(50)
    
    def _process_pending_thumbnails(self):
        """Process pending thumbnail requests."""
        # Load encrypted thumbnails
        if self._pending_enc_thumbnails:
            files = self._pending_enc_thumbnails.copy()
            self._pending_enc_thumbnails.clear()
            self._load_thumbnails(files, is_encrypted=True)
        
        # Load unencrypted thumbnails
        if self._pending_unenc_thumbnails:
            files = self._pending_unenc_thumbnails.copy()
            self._pending_unenc_thumbnails.clear()
            self._load_thumbnails(files, is_encrypted=False)
    
    def _on_action(self, operation: str):
        """Handle toolbar action."""
        if operation == "decrypt":
            selected = self._encrypted_tab.get_file_grid().get_selected()
        else:
            selected = self._unencrypted_tab.get_file_grid().get_selected()
        
        if selected:
            self._process_files(selected, operation)
    
    def _process_files(self, cards: list, operation: str):
        """Process files."""
        if not cards:
            return
        
        count = len(cards)
        action_name = "Decrypt" if operation == "decrypt" else "Encrypt"
        
        reply = QMessageBox.question(
            self,
            f"Confirm {action_name}",
            f"{action_name} {count} file{'s' if count > 1 else ''}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        files = [card.enc_filename for card in cards]
        
        progress = QProgressDialog(
            f"{action_name}ing files...",
            "Cancel",
            0, len(files),
            self
        )
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setMinimumDuration(0)
        progress.setWindowTitle(action_name)
        progress.setStyleSheet(get_stylesheet())
        
        worker = OperationWorker(
            files, self._fernet, self._salt_hash, operation
        )
        
        def on_progress(current, total, filename):
            progress.setValue(current)
            progress.setLabelText(f"{action_name}ing: {os.path.basename(filename)}")
        
        def on_finished(successful, failed):
            progress.close()
            
            # Clean up reference
            self._operation_worker = None
            worker.deleteLater()
            
            past_tense = "decrypted" if operation == "decrypt" else "encrypted"
            
            if failed:
                QMessageBox.warning(
                    self,
                    f"{action_name} Complete",
                    f"Successfully {past_tense} {len(successful)} files.\n"
                    f"Failed: {len(failed)} files.",
                    QMessageBox.StandardButton.Ok
                )
            elif successful:
                QMessageBox.information(
                    self,
                    f"{action_name} Complete",
                    f"Successfully {past_tense} {len(successful)} files.",
                    QMessageBox.StandardButton.Ok
                )
            
            # Optimize: Instead of reloading everything, just move the affected files
            if successful:
                self._update_after_operation(cards, successful, operation)
        
        worker.progress.connect(on_progress)
        worker.finished.connect(on_finished)
        progress.canceled.connect(worker.cancel)
        
        self._operation_worker = worker
        worker.start()
    
    def _update_after_operation(self, cards: list, successful: list, operation: str):
        """
        Update UI after encrypt/decrypt operation without full reload.
        
        This is much more efficient than _load_files() because:
        - We don't re-read the entire directory
        - We don't reload thumbnails for unchanged files
        - We only process the affected files
        """
        from ..thumbnail import get_media_type, MediaType
        
        successful_set = set(successful)
        
        # Build a map from enc_filename to card for quick lookup
        card_map = {card.enc_filename: card for card in cards}
        
        if operation == "decrypt":
            # Remove from encrypted tab, add to unencrypted tab
            files_to_remove = [f for f in successful if f in card_map]
            self._encrypted_tab.remove_files(files_to_remove)
            
            # Remove from loaded thumbnails tracking
            for f in files_to_remove:
                self._loaded_enc_thumbnails.discard(f)
            
            # Create FileItems for the newly decrypted files
            new_items = []
            thumbnail_files = []
            
            for enc_filename in files_to_remove:
                card = card_map[enc_filename]
                # After decrypt, the file is now named original_filename
                new_filename = card.original_filename
                
                # Check if it's an image/video for thumbnail
                media_type = get_media_type(new_filename)
                is_image = (media_type == MediaType.IMAGE)
                is_video = (media_type == MediaType.VIDEO)
                has_thumb = is_image or is_video
                
                new_items.append(FileItem(
                    enc_filename=new_filename,  # Now the actual filename
                    original_filename=new_filename,
                    extension=os.path.splitext(new_filename)[1].lower(),
                    has_thumbnail=has_thumb,
                    is_image=is_image,
                    is_encrypted=False
                ))
                
                # Only load thumbnails for images (videos are slow)
                if is_image:
                    thumbnail_files.append(new_filename)
            
            if new_items:
                self._unencrypted_tab.add_files(new_items)
            
            # Load thumbnails for newly added files only
            if thumbnail_files:
                self._load_thumbnails(thumbnail_files, is_encrypted=False)
            
        else:
            # Encrypt: For now, fall back to full reload since finding the new
            # .enc filename requires decrypting each filename to match.
            # This is acceptable since encrypt operations are less common
            # and typically involve fewer files than the initial load.
            self._load_files()
            return
        
        # Update tab counts
        enc_count = self._encrypted_tab.get_file_count()
        unenc_count = self._unencrypted_tab.get_file_count()
        self._tab_widget.setTabText(0, f"Encrypted ({enc_count})")
        self._tab_widget.setTabText(1, f"Unencrypted ({unenc_count})")
        self._set_status(f"Ready - {enc_count + unenc_count} files")
    
    def _cancel_workers(self):
        """Cancel all running workers and clean up."""
        if self._list_worker is not None:
            if self._list_worker.isRunning():
                self._list_worker.cancel()
                self._list_worker.wait(500)
            self._list_worker.deleteLater()
            self._list_worker = None
        
        if self._enc_thumbnail_worker is not None:
            if self._enc_thumbnail_worker.isRunning():
                self._enc_thumbnail_worker.cancel()
                self._enc_thumbnail_worker.wait(500)
            self._enc_thumbnail_worker.deleteLater()
            self._enc_thumbnail_worker = None
        
        if self._unenc_thumbnail_worker is not None:
            if self._unenc_thumbnail_worker.isRunning():
                self._unenc_thumbnail_worker.cancel()
                self._unenc_thumbnail_worker.wait(500)
            self._unenc_thumbnail_worker.deleteLater()
            self._unenc_thumbnail_worker = None
    
    def _set_status(self, message: str):
        """Set status message."""
        self._status_label.setText(message)
    
    def closeEvent(self, event: QCloseEvent):
        """Handle close."""
        self._cancel_workers()
        
        if self._operation_worker is not None:
            if self._operation_worker.isRunning():
                self._operation_worker.cancel()
                self._operation_worker.wait(1000)
            self._operation_worker.deleteLater()
            self._operation_worker = None
        
        event.accept()
