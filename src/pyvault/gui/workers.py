"""
Background Workers

Lightweight workers for async file operations.
Optimized for large file counts (500+).
"""

from PyQt6.QtCore import QThread, pyqtSignal
from typing import List, Optional, Set
from dataclasses import dataclass, field
import os


@dataclass
class FileItem:
    """Lightweight file info - no thumbnail data initially."""
    enc_filename: str
    original_filename: str
    extension: str = ""
    has_thumbnail: bool = False
    is_image: bool = False
    is_encrypted: bool = True
    error: Optional[str] = None


class FileListWorker(QThread):
    """
    Fast worker that only loads file names.
    No thumbnail extraction - that's done separately on-demand.
    
    This should complete in < 5 seconds for 500+ files.
    """
    
    file_loaded = pyqtSignal(object)  # FileItem
    progress = pyqtSignal(int, int)  # current, total
    finished_loading = pyqtSignal(list)  # List[FileItem]
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._files: List[str] = []
        self._fernet = None
        self._salt_hash: bytes = b""
        self._mode = "encrypted"
        self._cancelled = False
    
    def setup(
        self,
        files: List[str],
        fernet,
        salt_hash: bytes,
        mode: str = "encrypted"
    ):
        """Configure the worker."""
        self._files = files
        self._fernet = fernet
        self._salt_hash = salt_hash
        self._mode = mode
        self._cancelled = False
    
    def cancel(self):
        """Cancel the operation."""
        self._cancelled = True
    
    def run(self):
        """Load file names only (no thumbnails)."""
        if self._mode == "encrypted":
            self._load_encrypted()
        else:
            self._load_unencrypted()
    
    def _load_encrypted(self):
        """Load encrypted file names."""
        from ..vault import get_file_info
        from ..container import ContainerReader
        from ..settings import FILENAME_DECRYPT_CHUNK_SIZE
        
        results: List[FileItem] = []
        total = len(self._files)
        
        for i, enc_filename in enumerate(self._files):
            if self._cancelled:
                break
            
            item = FileItem(
                enc_filename=enc_filename,
                original_filename=enc_filename,
                is_encrypted=True
            )
            
            try:
                # Get basic info (fast - just reads header)
                info = get_file_info(enc_filename)
                if info:
                    item.has_thumbnail = info.get('has_thumbnail', False)
                    item.is_image = info.get('is_image', False)
                
                # Decrypt filename (fast)
                try:
                    with open(enc_filename, 'rb') as f:
                        reader = ContainerReader(f)
                        is_new = reader.detect_format()
                        
                        if is_new:
                            reader.read_header()
                            file_salt = reader.read_salt()
                            if file_salt == self._salt_hash:
                                encrypted_name = reader.read_encrypted_filename(FILENAME_DECRYPT_CHUNK_SIZE)
                                item.original_filename = self._fernet.decrypt(encrypted_name).decode('utf-8').rstrip('0')
                        else:
                            file_salt = f.read(32)
                            if file_salt == self._salt_hash:
                                encrypted_name = f.read(FILENAME_DECRYPT_CHUNK_SIZE)
                                item.original_filename = self._fernet.decrypt(encrypted_name).decode('utf-8').rstrip('0')
                except Exception:
                    pass
                
                item.extension = os.path.splitext(item.original_filename)[1].lower()
                
            except Exception as e:
                item.error = str(e)
            
            results.append(item)
            
            # Emit progress every 20 files
            if (i + 1) % 20 == 0:
                self.progress.emit(i + 1, total)
        
        self.progress.emit(total, total)
        self.finished_loading.emit(results)
    
    def _load_unencrypted(self):
        """Load unencrypted file names."""
        from ..thumbnail import get_media_type, MediaType
        
        results: List[FileItem] = []
        total = len(self._files)
        
        for i, filename in enumerate(self._files):
            if self._cancelled:
                break
            
            media_type = get_media_type(filename)
            is_image = (media_type == MediaType.IMAGE)
            is_video = (media_type == MediaType.VIDEO)
            
            item = FileItem(
                enc_filename=filename,
                original_filename=filename,
                extension=os.path.splitext(filename)[1].lower(),
                has_thumbnail=(is_image or is_video),
                is_image=is_image,
                is_encrypted=False
            )
            
            results.append(item)
            
            if (i + 1) % 50 == 0:
                self.progress.emit(i + 1, total)
        
        self.progress.emit(total, total)
        self.finished_loading.emit(results)


class ThumbnailWorker(QThread):
    """
    Worker that loads thumbnails for a specific set of files.
    Used for loading visible page thumbnails only.
    
    Limited to process files one at a time to avoid overwhelming the system.
    
    OPTIMIZATION: Accepts pre-created fernet and salt_hash to avoid
    expensive key derivation (480,000 PBKDF2 iterations) per file.
    """
    
    thumbnail_loaded = pyqtSignal(str, bytes)  # enc_filename, data
    finished_loading = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._files: List[str] = []
        self._password: str = ""
        self._fernet = None
        self._salt_hash: bytes = b""
        self._is_encrypted: bool = True
        self._cancelled = False
    
    def setup(
        self,
        files: List[str],
        password: str = "",
        is_encrypted: bool = True,
        fernet=None,
        salt_hash: bytes = b""
    ):
        """
        Configure the worker.
        
        Args:
            files: List of file paths to load thumbnails for
            password: Password (used only if fernet not provided)
            is_encrypted: Whether files are encrypted
            fernet: Pre-created Fernet instance (recommended for performance)
            salt_hash: Pre-computed salt hash (required if fernet provided)
        """
        self._files = files
        self._password = password
        self._fernet = fernet
        self._salt_hash = salt_hash
        self._is_encrypted = is_encrypted
        self._cancelled = False
    
    def cancel(self):
        """Cancel the operation."""
        self._cancelled = True
    
    def run(self):
        """Load thumbnails for the given files."""
        if self._is_encrypted:
            self._load_encrypted_thumbnails()
        else:
            self._load_unencrypted_thumbnails()
        
        self.finished_loading.emit()
    
    def _load_encrypted_thumbnails(self):
        """Load thumbnails from encrypted files."""
        from ..vault import get_thumbnail_fast, get_thumbnail, get_file_info, get_fernet, get_config
        from ..crypto import hash_salt
        
        # Use pre-created fernet if available, otherwise create once
        fernet = self._fernet
        salt_hash = self._salt_hash
        
        if fernet is None and self._password:
            # Fallback: create fernet once (not per file!)
            fernet = get_fernet(self._password)
            config = get_config()
            salt = bytes.fromhex(config["salt"])
            salt_hash = hash_salt(salt)
        
        for enc_filename in self._files:
            if self._cancelled:
                break
            
            try:
                info = get_file_info(enc_filename)
                if not info or not info.get('has_thumbnail', False):
                    continue
                
                # Use fast version with pre-created fernet
                if fernet is not None:
                    thumbnail_data = get_thumbnail_fast(enc_filename, fernet, salt_hash)
                else:
                    # Ultimate fallback (shouldn't happen)
                    thumbnail_data = get_thumbnail(enc_filename, self._password)
                
                if thumbnail_data:
                    self.thumbnail_loaded.emit(enc_filename, thumbnail_data)
                    
            except Exception:
                continue
    
    def _load_unencrypted_thumbnails(self):
        """Extract thumbnails from unencrypted files."""
        from ..thumbnail import ThumbnailService, get_media_type, MediaType
        
        thumbnail_service = ThumbnailService(enabled=True)
        
        for filename in self._files:
            if self._cancelled:
                break
            
            try:
                media_type = get_media_type(filename)
                
                # Skip unknown types
                if media_type == MediaType.UNKNOWN:
                    continue
                
                # Images are fast, videos are slow
                # Only load image thumbnails automatically
                # Video thumbnails would require ffmpeg which is slow
                if media_type == MediaType.IMAGE:
                    result = thumbnail_service.extract(filename)
                    if result and result.data:
                        self.thumbnail_loaded.emit(filename, result.data)
                        
            except Exception:
                continue


class OperationWorker(QThread):
    """
    Background worker for encrypt/decrypt operations.
    """
    
    progress = pyqtSignal(int, int, str)
    finished = pyqtSignal(list, list)  # successful, failed
    
    def __init__(self, files: List[str], fernet, salt_hash: bytes, operation: str = "decrypt"):
        super().__init__()
        self._files = files
        self._fernet = fernet
        self._salt_hash = salt_hash
        self._operation = operation
        self._cancelled = False
    
    def cancel(self):
        """Cancel the operation."""
        self._cancelled = True
    
    def run(self):
        """Run operation in background."""
        from ..vault import decrypt_file, encrypt_file
        
        successful = []
        failed = []
        total = len(self._files)
        
        for i, filename in enumerate(self._files):
            if self._cancelled:
                break
            
            self.progress.emit(i + 1, total, filename)
            
            try:
                if self._operation == "decrypt":
                    status = decrypt_file(filename, self._fernet, self._salt_hash)
                else:
                    status = encrypt_file(filename, self._fernet, self._salt_hash)
                
                if status is None:
                    successful.append(filename)
                else:
                    failed.append(filename)
            except Exception:
                failed.append(filename)
        
        self.finished.emit(successful, failed)
