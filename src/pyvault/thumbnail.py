"""
PyVault Thumbnail Service Module

This module handles thumbnail extraction for images and videos.
Thumbnails are used for preview purposes in GUI applications.

Supported formats:
- Images: jpg, jpeg, png, gif, webp, bmp
- Videos: mp4, mov, mkv, avi, webm

Configuration:
- Max resolution: 160x160
- Aspect ratio: preserved
- Output format: JPEG
- JPEG quality: 65 (optimized for preview)
"""

import io
import os
import subprocess
import tempfile
from typing import Optional
from dataclasses import dataclass
from enum import Enum

# Optional imports - gracefully handle missing dependencies
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


# Constants
THUMBNAIL_MAX_SIZE = (160, 160)
THUMBNAIL_JPEG_QUALITY = 65
THUMBNAIL_FORMAT = "JPEG"

# Supported file extensions
IMAGE_EXTENSIONS = frozenset({'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp'})
VIDEO_EXTENSIONS = frozenset({'.mp4', '.mov', '.mkv', '.avi', '.webm'})
SUPPORTED_EXTENSIONS = IMAGE_EXTENSIONS | VIDEO_EXTENSIONS


class MediaType(Enum):
    """Type of media file."""
    IMAGE = "image"
    VIDEO = "video"
    UNKNOWN = "unknown"


class ThumbnailError(Exception):
    """Base exception for thumbnail operations."""
    pass


class UnsupportedFormatError(ThumbnailError):
    """Raised when file format is not supported for thumbnail extraction."""
    pass


class ExtractionError(ThumbnailError):
    """Raised when thumbnail extraction fails."""
    pass


class DependencyError(ThumbnailError):
    """Raised when required dependency is not available."""
    pass


@dataclass
class ThumbnailResult:
    """Result of thumbnail extraction."""
    data: bytes
    width: int
    height: int
    media_type: MediaType
    original_width: Optional[int] = None
    original_height: Optional[int] = None


def get_media_type(filename: str) -> MediaType:
    """
    Determine media type from filename extension.
    
    Args:
        filename: Original filename with extension
        
    Returns:
        MediaType enum value
    """
    ext = os.path.splitext(filename)[1].lower()
    
    if ext in IMAGE_EXTENSIONS:
        return MediaType.IMAGE
    elif ext in VIDEO_EXTENSIONS:
        return MediaType.VIDEO
    else:
        return MediaType.UNKNOWN


def is_thumbnail_supported(filename: str) -> bool:
    """
    Check if thumbnail extraction is supported for a file.
    
    Args:
        filename: Original filename with extension
        
    Returns:
        True if thumbnail can be extracted
    """
    ext = os.path.splitext(filename)[1].lower()
    return ext in SUPPORTED_EXTENSIONS


def _calculate_thumbnail_size(
    original_width: int, 
    original_height: int, 
    max_size: tuple[int, int] = THUMBNAIL_MAX_SIZE
) -> tuple[int, int]:
    """
    Calculate thumbnail dimensions preserving aspect ratio.
    
    Args:
        original_width: Original image width
        original_height: Original image height
        max_size: Maximum thumbnail dimensions (width, height)
        
    Returns:
        Tuple of (width, height) for thumbnail
    """
    max_width, max_height = max_size
    
    # If image is smaller than max size, keep original dimensions
    if original_width <= max_width and original_height <= max_height:
        return original_width, original_height
    
    # Calculate scaling factor
    width_ratio = max_width / original_width
    height_ratio = max_height / original_height
    ratio = min(width_ratio, height_ratio)
    
    new_width = int(original_width * ratio)
    new_height = int(original_height * ratio)
    
    return new_width, new_height


def _extract_image_thumbnail(file_path: str) -> ThumbnailResult:
    """
    Extract thumbnail from an image file using Pillow.
    
    Args:
        file_path: Path to the image file
        
    Returns:
        ThumbnailResult with JPEG thumbnail data
        
    Raises:
        DependencyError: If Pillow is not installed
        ExtractionError: If extraction fails
    """
    if not PIL_AVAILABLE:
        raise DependencyError(
            "Pillow is required for image thumbnail extraction. "
            "Install with: pip install Pillow"
        )
    
    try:
        with Image.open(file_path) as img:
            original_width, original_height = img.size
            
            # Convert to RGB if necessary (for JPEG output)
            if img.mode in ('RGBA', 'P', 'LA'):
                # Create white background for transparent images
                background = Image.new('RGB', img.size, (255, 255, 255))
                if img.mode == 'P':
                    img = img.convert('RGBA')
                background.paste(img, mask=img.split()[-1] if img.mode == 'RGBA' else None)
                img = background
            elif img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Calculate new size preserving aspect ratio
            new_size = _calculate_thumbnail_size(original_width, original_height)
            
            # Use high-quality resampling
            img.thumbnail(new_size, Image.Resampling.LANCZOS)
            
            # Save to bytes
            output = io.BytesIO()
            img.save(output, format=THUMBNAIL_FORMAT, quality=THUMBNAIL_JPEG_QUALITY, optimize=True)
            thumbnail_data = output.getvalue()
            
            return ThumbnailResult(
                data=thumbnail_data,
                width=img.width,
                height=img.height,
                media_type=MediaType.IMAGE,
                original_width=original_width,
                original_height=original_height
            )
            
    except Exception as e:
        raise ExtractionError(f"Failed to extract image thumbnail: {e}")


def _extract_video_thumbnail(file_path: str) -> ThumbnailResult:
    """
    Extract thumbnail from a video file using ffmpeg.
    
    Extracts a frame from 1 second into the video (or first frame if shorter).
    
    Args:
        file_path: Path to the video file
        
    Returns:
        ThumbnailResult with JPEG thumbnail data
        
    Raises:
        DependencyError: If ffmpeg is not available
        ExtractionError: If extraction fails
    """
    # Check if ffmpeg is available
    try:
        subprocess.run(
            ['ffmpeg', '-version'],
            capture_output=True,
            check=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        raise DependencyError(
            "ffmpeg is required for video thumbnail extraction. "
            "Please install ffmpeg and ensure it's in your PATH."
        )
    
    if not PIL_AVAILABLE:
        raise DependencyError(
            "Pillow is required for video thumbnail processing. "
            "Install with: pip install Pillow"
        )
    
    # Create temporary file for thumbnail
    with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as tmp:
        tmp_path = tmp.name
    
    try:
        # Extract frame at 1 second (or first frame)
        # -ss before -i for fast seeking
        # -vf scale with aspect ratio preservation
        max_w, max_h = THUMBNAIL_MAX_SIZE
        
        # q:v 10 ≈ JPEG quality 65 (matches THUMBNAIL_JPEG_QUALITY)
        cmd = [
            'ffmpeg',
            '-ss', '1',  # Seek to 1 second
            '-i', file_path,
            '-vframes', '1',  # Extract 1 frame
            '-vf', f'scale=w={max_w}:h={max_h}:force_original_aspect_ratio=decrease',
            '-q:v', '10',  # JPEG quality ~65
            '-y',  # Overwrite output
            tmp_path
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=30  # 30 second timeout
        )
        
        # If seeking to 1s failed (video too short), try first frame
        if result.returncode != 0 or not os.path.exists(tmp_path) or os.path.getsize(tmp_path) == 0:
            cmd[2] = '0'  # Seek to 0 instead
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=30
            )
        
        if result.returncode != 0:
            stderr = result.stderr.decode('utf-8', errors='replace')
            raise ExtractionError(f"ffmpeg failed: {stderr[:200]}")
        
        if not os.path.exists(tmp_path) or os.path.getsize(tmp_path) == 0:
            raise ExtractionError("ffmpeg produced no output")
        
        # Read JPEG directly - no re-encoding needed
        with open(tmp_path, 'rb') as f:
            thumbnail_data = f.read()
        
        # Get dimensions from the JPEG (PIL only for reading, no encoding)
        with Image.open(io.BytesIO(thumbnail_data)) as img:
            width, height = img.size
        
        return ThumbnailResult(
            data=thumbnail_data,
            width=width,
            height=height,
            media_type=MediaType.VIDEO
        )
            
    except subprocess.TimeoutExpired:
        raise ExtractionError("ffmpeg timed out while extracting video thumbnail")
    except ExtractionError:
        raise
    except Exception as e:
        raise ExtractionError(f"Failed to extract video thumbnail: {e}")
    finally:
        # Clean up temporary file
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def _extract_thumbnail_from_bytes(data: bytes, media_type: MediaType) -> ThumbnailResult:
    """
    Extract thumbnail from raw file bytes.
    
    Args:
        data: Raw file bytes
        media_type: Type of media (IMAGE or VIDEO)
        
    Returns:
        ThumbnailResult with JPEG thumbnail data
        
    Raises:
        UnsupportedFormatError: If media type is not supported
        ExtractionError: If extraction fails
    """
    if media_type == MediaType.IMAGE:
        if not PIL_AVAILABLE:
            raise DependencyError(
                "Pillow is required for image thumbnail extraction. "
                "Install with: pip install Pillow"
            )
        
        try:
            with Image.open(io.BytesIO(data)) as img:
                original_width, original_height = img.size
                
                # Convert to RGB if necessary
                if img.mode in ('RGBA', 'P', 'LA'):
                    background = Image.new('RGB', img.size, (255, 255, 255))
                    if img.mode == 'P':
                        img = img.convert('RGBA')
                    background.paste(img, mask=img.split()[-1] if img.mode == 'RGBA' else None)
                    img = background
                elif img.mode != 'RGB':
                    img = img.convert('RGB')
                
                new_size = _calculate_thumbnail_size(original_width, original_height)
                img.thumbnail(new_size, Image.Resampling.LANCZOS)
                
                output = io.BytesIO()
                img.save(output, format=THUMBNAIL_FORMAT, quality=THUMBNAIL_JPEG_QUALITY, optimize=True)
                
                return ThumbnailResult(
                    data=output.getvalue(),
                    width=img.width,
                    height=img.height,
                    media_type=MediaType.IMAGE,
                    original_width=original_width,
                    original_height=original_height
                )
        except Exception as e:
            raise ExtractionError(f"Failed to extract image thumbnail from bytes: {e}")
    
    elif media_type == MediaType.VIDEO:
        # For video, we need to write to a temp file for ffmpeg
        with tempfile.NamedTemporaryFile(suffix='.mp4', delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        
        try:
            return _extract_video_thumbnail(tmp_path)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
    
    else:
        raise UnsupportedFormatError(f"Unsupported media type: {media_type}")


def extract_thumbnail(file_path: str) -> Optional[ThumbnailResult]:
    """
    Extract thumbnail from a file.
    
    This is the main entry point for thumbnail extraction.
    Automatically detects file type and uses appropriate extraction method.
    
    Args:
        file_path: Path to the source file
        
    Returns:
        ThumbnailResult with JPEG thumbnail data, or None if not supported
        
    Raises:
        ExtractionError: If extraction fails for supported format
        DependencyError: If required dependency is missing
    """
    media_type = get_media_type(file_path)
    
    if media_type == MediaType.UNKNOWN:
        return None
    
    if media_type == MediaType.IMAGE:
        return _extract_image_thumbnail(file_path)
    elif media_type == MediaType.VIDEO:
        return _extract_video_thumbnail(file_path)
    
    return None


def extract_thumbnail_from_bytes(data: bytes, filename: str) -> Optional[ThumbnailResult]:
    """
    Extract thumbnail from raw bytes.
    
    Args:
        data: Raw file bytes
        filename: Original filename (used to determine media type)
        
    Returns:
        ThumbnailResult with JPEG thumbnail data, or None if not supported
        
    Raises:
        ExtractionError: If extraction fails for supported format
        DependencyError: If required dependency is missing
    """
    media_type = get_media_type(filename)
    
    if media_type == MediaType.UNKNOWN:
        return None
    
    return _extract_thumbnail_from_bytes(data, media_type)


class ThumbnailCache:
    """
    Simple LRU cache for thumbnails.
    
    Uses file path + mtime as cache key to invalidate when file changes.
    """
    
    def __init__(self, max_size: int = 500):
        """
        Initialize cache.
        
        Args:
            max_size: Maximum number of thumbnails to cache
        """
        self._cache: dict[str, tuple[float, bytes]] = {}  # key -> (mtime, data)
        self._access_order: list[str] = []  # LRU tracking
        self._max_size = max_size
    
    def _make_key(self, file_path: str) -> str:
        """Create cache key from file path."""
        return os.path.abspath(file_path)
    
    def get(self, file_path: str) -> Optional[bytes]:
        """
        Get cached thumbnail if valid.
        
        Args:
            file_path: Path to the source file
            
        Returns:
            Cached thumbnail bytes or None if not cached/invalid
        """
        key = self._make_key(file_path)
        
        if key not in self._cache:
            return None
        
        cached_mtime, data = self._cache[key]
        
        # Check if file has been modified
        try:
            current_mtime = os.path.getmtime(file_path)
            if current_mtime != cached_mtime:
                # File changed, invalidate cache
                del self._cache[key]
                if key in self._access_order:
                    self._access_order.remove(key)
                return None
        except OSError:
            # File doesn't exist or can't be accessed
            return None
        
        # Update access order for LRU
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)
        
        return data
    
    def put(self, file_path: str, data: bytes) -> None:
        """
        Cache a thumbnail.
        
        Args:
            file_path: Path to the source file
            data: Thumbnail bytes to cache
        """
        key = self._make_key(file_path)
        
        try:
            mtime = os.path.getmtime(file_path)
        except OSError:
            return  # Can't cache if we can't get mtime
        
        # Evict oldest entries if at capacity
        while len(self._cache) >= self._max_size and self._access_order:
            oldest_key = self._access_order.pop(0)
            if oldest_key in self._cache:
                del self._cache[oldest_key]
        
        self._cache[key] = (mtime, data)
        
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)
    
    def clear(self) -> None:
        """Clear all cached thumbnails."""
        self._cache.clear()
        self._access_order.clear()
    
    def size(self) -> int:
        """Get number of cached thumbnails."""
        return len(self._cache)


# Global thumbnail cache (shared across ThumbnailService instances)
_thumbnail_cache = ThumbnailCache(max_size=500)


class ThumbnailService:
    """
    Service class for thumbnail operations.
    
    Provides a higher-level interface for thumbnail extraction
    with caching and error handling capabilities.
    """
    
    def __init__(self, enabled: bool = True, use_cache: bool = True):
        """
        Initialize thumbnail service.
        
        Args:
            enabled: Whether thumbnail extraction is enabled
            use_cache: Whether to use thumbnail cache
        """
        self._enabled = enabled
        self._use_cache = use_cache
        self._check_dependencies()
    
    def _check_dependencies(self) -> dict[str, bool]:
        """Check availability of dependencies."""
        deps = {
            'pillow': PIL_AVAILABLE,
            'ffmpeg': self._check_ffmpeg()
        }
        return deps
    
    def _check_ffmpeg(self) -> bool:
        """Check if ffmpeg is available."""
        try:
            subprocess.run(
                ['ffmpeg', '-version'],
                capture_output=True,
                check=True
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    @property
    def is_enabled(self) -> bool:
        """Check if service is enabled."""
        return self._enabled
    
    @property
    def can_process_images(self) -> bool:
        """Check if image processing is available."""
        return PIL_AVAILABLE
    
    @property
    def can_process_videos(self) -> bool:
        """Check if video processing is available."""
        return PIL_AVAILABLE and self._check_ffmpeg()
    
    def extract(self, file_path: str) -> Optional[ThumbnailResult]:
        """
        Extract thumbnail from a file.
        
        Uses cache to avoid re-extracting thumbnails for unchanged files.
        
        Args:
            file_path: Path to the source file
            
        Returns:
            ThumbnailResult or None if extraction not possible/enabled
        """
        if not self._enabled:
            return None
        
        media_type = get_media_type(file_path)
        
        if media_type == MediaType.UNKNOWN:
            return None
        
        if media_type == MediaType.IMAGE and not self.can_process_images:
            return None
        
        if media_type == MediaType.VIDEO and not self.can_process_videos:
            return None
        
        # Check cache first
        if self._use_cache:
            cached_data = _thumbnail_cache.get(file_path)
            if cached_data is not None:
                # Return cached result (we don't store full ThumbnailResult, just bytes)
                return ThumbnailResult(
                    data=cached_data,
                    width=0,  # Unknown from cache
                    height=0,
                    media_type=media_type
                )
        
        try:
            result = extract_thumbnail(file_path)
            
            # Cache the result
            if result is not None and self._use_cache:
                _thumbnail_cache.put(file_path, result.data)
            
            return result
        except (DependencyError, ExtractionError):
            # Silently fail - thumbnails are optional
            return None
    
    def extract_safe(self, file_path: str) -> tuple[Optional[ThumbnailResult], Optional[str]]:
        """
        Extract thumbnail with error information.
        
        Args:
            file_path: Path to the source file
            
        Returns:
            Tuple of (result, error_message)
        """
        if not self._enabled:
            return None, "Thumbnail extraction is disabled"
        
        try:
            result = extract_thumbnail(file_path)
            return result, None
        except DependencyError as e:
            return None, str(e)
        except ExtractionError as e:
            return None, str(e)
        except Exception as e:
            return None, f"Unexpected error: {e}"


# Singleton instance
_thumbnail_service: Optional[ThumbnailService] = None


def get_thumbnail_service(enabled: bool = True, use_cache: bool = True) -> ThumbnailService:
    """
    Get singleton ThumbnailService instance.
    
    Avoids creating multiple instances and redundant dependency checks.
    
    Args:
        enabled: Whether thumbnail extraction is enabled
        use_cache: Whether to use thumbnail cache
        
    Returns:
        Shared ThumbnailService instance
    """
    global _thumbnail_service
    
    if _thumbnail_service is None:
        _thumbnail_service = ThumbnailService(enabled=enabled, use_cache=use_cache)
    
    return _thumbnail_service
