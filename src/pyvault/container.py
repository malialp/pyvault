"""
PyVault Container Format Module

This module handles the binary container format for .enc files.
Version 3 introduces a structured header with explicit offsets for all sections.

Container Format v3:
┌────────────────────────────────────────────────────────┐
│ HEADER (48 bytes fixed)                                │
├────────────────────────────────────────────────────────┤
│ magic          : 4 bytes  : b"ENCF"                    │
│ version        : 1 byte   : uint8 (3)                  │
│ flags          : 1 byte   : uint8 (bitfield)           │
│ reserved       : 2 bytes  : uint16                     │
│ thumbnail_off  : 4 bytes  : uint32                     │
│ thumbnail_size : 4 bytes  : uint32                     │
│ filename_off   : 4 bytes  : uint32                     │
│ filename_size  : 4 bytes  : uint32                     │
│ salt_off       : 4 bytes  : uint32                     │
│ salt_size      : 4 bytes  : uint32                     │
│ data_off       : 8 bytes  : uint64                     │
│ data_size      : 8 bytes  : uint64                     │
├────────────────────────────────────────────────────────┤
│ SECTIONS (variable, accessed via offsets)              │
│ - Salt section                                         │
│ - Thumbnail section (optional, encrypted)              │
│ - Filename section (encrypted)                         │
│ - Data section (encrypted)                             │
└────────────────────────────────────────────────────────┘

Flags bitfield:
  bit 0: has_thumbnail (1 = yes, 0 = no)
  bit 1: media_type (1 = image, 0 = video/other)
  bit 2-7: reserved for future use
"""

import struct
from dataclasses import dataclass
from typing import Optional, BinaryIO
from enum import IntFlag


# Constants
MAGIC_BYTES = b"ENCF"
CONTAINER_VERSION = 3
HEADER_SIZE = 48
HEADER_FORMAT = "<4sBBHIIIIIIQQ"

# Legacy format constants (v1/v2)
LEGACY_SALT_HASH_SIZE = 32


class ContainerFlags(IntFlag):
    """Flags for container metadata."""
    NONE = 0
    HAS_THUMBNAIL = 1 << 0
    IS_IMAGE = 1 << 1
    # Reserved bits 2-7 for future use


class ContainerVersion:
    """Container version constants."""
    LEGACY = 1  # Original format without header
    V3 = 3      # New structured format


class ContainerError(Exception):
    """Base exception for container operations."""
    pass


class InvalidMagicError(ContainerError):
    """Raised when magic bytes don't match."""
    pass


class UnsupportedVersionError(ContainerError):
    """Raised when container version is not supported."""
    pass


class CorruptedContainerError(ContainerError):
    """Raised when container data is corrupted."""
    pass


@dataclass
class ContainerHeader:
    """
    Represents the header of an encrypted container file.
    
    All offsets are absolute positions from the start of the file.
    All sizes are in bytes.
    """
    version: int
    flags: ContainerFlags
    thumbnail_offset: int
    thumbnail_size: int
    filename_offset: int
    filename_size: int
    salt_offset: int
    salt_size: int
    data_offset: int
    data_size: int
    
    @property
    def has_thumbnail(self) -> bool:
        """Check if container has an embedded thumbnail."""
        return bool(self.flags & ContainerFlags.HAS_THUMBNAIL)
    
    @property
    def is_image(self) -> bool:
        """Check if the original file was an image."""
        return bool(self.flags & ContainerFlags.IS_IMAGE)
    
    def to_bytes(self) -> bytes:
        """Serialize header to bytes."""
        return struct.pack(
            HEADER_FORMAT,
            MAGIC_BYTES,
            self.version,
            int(self.flags),
            0,  # reserved
            self.thumbnail_offset,
            self.thumbnail_size,
            self.filename_offset,
            self.filename_size,
            self.salt_offset,
            self.salt_size,
            self.data_offset,
            self.data_size
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "ContainerHeader":
        """
        Deserialize header from bytes.
        
        Args:
            data: Raw header bytes (must be at least HEADER_SIZE bytes)
            
        Returns:
            ContainerHeader instance
            
        Raises:
            InvalidMagicError: If magic bytes don't match
            UnsupportedVersionError: If version is not supported
            CorruptedContainerError: If header data is corrupted
        """
        if len(data) < HEADER_SIZE:
            raise CorruptedContainerError(
                f"Header too small: expected {HEADER_SIZE} bytes, got {len(data)}"
            )
        
        try:
            unpacked = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
        except struct.error as e:
            raise CorruptedContainerError(f"Failed to unpack header: {e}")
        
        magic = unpacked[0]
        if magic != MAGIC_BYTES:
            raise InvalidMagicError(
                f"Invalid magic bytes: expected {MAGIC_BYTES!r}, got {magic!r}"
            )
        
        version = unpacked[1]
        if version > CONTAINER_VERSION:
            raise UnsupportedVersionError(
                f"Unsupported container version: {version}. "
                f"Maximum supported version is {CONTAINER_VERSION}. "
                f"Please update PyVault."
            )
        
        return cls(
            version=version,
            flags=ContainerFlags(unpacked[2]),
            thumbnail_offset=unpacked[4],
            thumbnail_size=unpacked[5],
            filename_offset=unpacked[6],
            filename_size=unpacked[7],
            salt_offset=unpacked[8],
            salt_size=unpacked[9],
            data_offset=unpacked[10],
            data_size=unpacked[11]
        )


@dataclass
class ContainerSections:
    """
    Holds the actual content of container sections.
    
    All byte fields store encrypted data except salt which is plaintext.
    """
    salt: bytes
    encrypted_filename: bytes
    encrypted_thumbnail: Optional[bytes] = None
    encrypted_data: Optional[bytes] = None  # Only used for small files in memory


class ContainerBuilder:
    """
    Builder for creating new encrypted containers.
    
    Usage:
        builder = ContainerBuilder()
        builder.set_salt(salt_bytes)
        builder.set_encrypted_filename(encrypted_name)
        builder.set_encrypted_thumbnail(thumb_bytes)  # optional
        header, sections_data = builder.build()
    """
    
    def __init__(self):
        self._salt: Optional[bytes] = None
        self._encrypted_filename: Optional[bytes] = None
        self._encrypted_thumbnail: Optional[bytes] = None
        self._data_size: int = 0
        self._flags: ContainerFlags = ContainerFlags.NONE
    
    def set_salt(self, salt: bytes) -> "ContainerBuilder":
        """Set the salt for key derivation."""
        self._salt = salt
        return self
    
    def set_encrypted_filename(self, encrypted_filename: bytes) -> "ContainerBuilder":
        """Set the encrypted original filename."""
        self._encrypted_filename = encrypted_filename
        return self
    
    def set_encrypted_thumbnail(self, encrypted_thumbnail: bytes, is_image: bool = True) -> "ContainerBuilder":
        """Set the encrypted thumbnail data."""
        self._encrypted_thumbnail = encrypted_thumbnail
        self._flags |= ContainerFlags.HAS_THUMBNAIL
        if is_image:
            self._flags |= ContainerFlags.IS_IMAGE
        return self
    
    def set_data_size(self, size: int) -> "ContainerBuilder":
        """Set the size of encrypted data section."""
        self._data_size = size
        return self
    
    def set_flags(self, flags: ContainerFlags) -> "ContainerBuilder":
        """Set container flags directly."""
        self._flags = flags
        return self
    
    def build(self) -> tuple[ContainerHeader, bytes]:
        """
        Build the container header and pre-data sections.
        
        Returns:
            Tuple of (header, sections_bytes) where sections_bytes contains
            salt + thumbnail + filename in order, ready to write before data.
            
        Raises:
            ValueError: If required sections are not set
        """
        if self._salt is None:
            raise ValueError("Salt is required")
        if self._encrypted_filename is None:
            raise ValueError("Encrypted filename is required")
        
        # Calculate offsets - sections come immediately after header
        current_offset = HEADER_SIZE
        
        # Salt section
        salt_offset = current_offset
        salt_size = len(self._salt)
        current_offset += salt_size
        
        # Thumbnail section (optional)
        if self._encrypted_thumbnail:
            thumbnail_offset = current_offset
            thumbnail_size = len(self._encrypted_thumbnail)
            current_offset += thumbnail_size
        else:
            thumbnail_offset = 0
            thumbnail_size = 0
        
        # Filename section
        filename_offset = current_offset
        filename_size = len(self._encrypted_filename)
        current_offset += filename_size
        
        # Data section starts after all metadata
        data_offset = current_offset
        
        header = ContainerHeader(
            version=CONTAINER_VERSION,
            flags=self._flags,
            thumbnail_offset=thumbnail_offset,
            thumbnail_size=thumbnail_size,
            filename_offset=filename_offset,
            filename_size=filename_size,
            salt_offset=salt_offset,
            salt_size=salt_size,
            data_offset=data_offset,
            data_size=self._data_size
        )
        
        # Build sections bytes
        sections = bytearray()
        sections.extend(self._salt)
        if self._encrypted_thumbnail:
            sections.extend(self._encrypted_thumbnail)
        sections.extend(self._encrypted_filename)
        
        return header, bytes(sections)


class ContainerReader:
    """
    Reader for parsing encrypted container files.
    
    Supports both legacy format (v1/v2) and new format (v3).
    """
    
    def __init__(self, file: BinaryIO):
        """
        Initialize reader with a file object.
        
        Args:
            file: Binary file object opened for reading
        """
        self._file = file
        self._header: Optional[ContainerHeader] = None
        self._is_legacy: bool = False
    
    def detect_format(self) -> bool:
        """
        Detect container format (legacy vs new).
        
        Returns:
            True if new format (v3+), False if legacy format
        """
        self._file.seek(0)
        magic = self._file.read(4)
        self._file.seek(0)
        
        self._is_legacy = (magic != MAGIC_BYTES)
        return not self._is_legacy
    
    @property
    def is_legacy(self) -> bool:
        """Check if this is a legacy format container."""
        return self._is_legacy
    
    def read_header(self) -> Optional[ContainerHeader]:
        """
        Read and parse the container header.
        
        For legacy format, returns None.
        For new format, returns ContainerHeader.
        
        Returns:
            ContainerHeader or None for legacy format
        """
        if self._is_legacy:
            return None
        
        self._file.seek(0)
        header_data = self._file.read(HEADER_SIZE)
        self._header = ContainerHeader.from_bytes(header_data)
        return self._header
    
    def read_salt(self, legacy_salt_size: int = LEGACY_SALT_HASH_SIZE) -> bytes:
        """
        Read salt from container.
        
        Args:
            legacy_salt_size: Size of salt in legacy format
            
        Returns:
            Salt bytes
        """
        if self._is_legacy:
            self._file.seek(0)
            return self._file.read(legacy_salt_size)
        
        if self._header is None:
            self.read_header()
        
        self._file.seek(self._header.salt_offset)
        return self._file.read(self._header.salt_size)
    
    def read_encrypted_filename(self, legacy_filename_size: int) -> bytes:
        """
        Read encrypted filename from container.
        
        Args:
            legacy_filename_size: Size of encrypted filename in legacy format
            
        Returns:
            Encrypted filename bytes
        """
        if self._is_legacy:
            self._file.seek(LEGACY_SALT_HASH_SIZE)
            return self._file.read(legacy_filename_size)
        
        if self._header is None:
            self.read_header()
        
        self._file.seek(self._header.filename_offset)
        return self._file.read(self._header.filename_size)
    
    def read_encrypted_thumbnail(self) -> Optional[bytes]:
        """
        Read encrypted thumbnail from container.
        
        Returns:
            Encrypted thumbnail bytes or None if no thumbnail
        """
        if self._is_legacy:
            return None
        
        if self._header is None:
            self.read_header()
        
        if not self._header.has_thumbnail:
            return None
        
        self._file.seek(self._header.thumbnail_offset)
        return self._file.read(self._header.thumbnail_size)
    
    def get_data_offset(self, legacy_filename_size: int) -> int:
        """
        Get the offset where encrypted data starts.
        
        Args:
            legacy_filename_size: Size of encrypted filename in legacy format
            
        Returns:
            Byte offset to data section
        """
        if self._is_legacy:
            return LEGACY_SALT_HASH_SIZE + legacy_filename_size
        
        if self._header is None:
            self.read_header()
        
        return self._header.data_offset
    
    def seek_to_data(self, legacy_filename_size: int) -> int:
        """
        Seek file pointer to start of encrypted data.
        
        Args:
            legacy_filename_size: Size of encrypted filename in legacy format
            
        Returns:
            Byte offset where data starts
        """
        offset = self.get_data_offset(legacy_filename_size)
        self._file.seek(offset)
        return offset


class ContainerWriter:
    """
    Writer for creating encrypted container files.
    
    Usage:
        with open('file.enc', 'wb') as f:
            writer = ContainerWriter(f)
            writer.write_header(header)
            writer.write_sections(sections_bytes)
            # Then write encrypted data chunks directly to file
    """
    
    def __init__(self, file: BinaryIO):
        """
        Initialize writer with a file object.
        
        Args:
            file: Binary file object opened for writing
        """
        self._file = file
        self._data_start: int = 0
    
    def write_header(self, header: ContainerHeader) -> int:
        """
        Write container header.
        
        Args:
            header: ContainerHeader to write
            
        Returns:
            Number of bytes written
        """
        header_bytes = header.to_bytes()
        self._file.write(header_bytes)
        return len(header_bytes)
    
    def write_sections(self, sections: bytes) -> int:
        """
        Write pre-data sections (salt, thumbnail, filename).
        
        Args:
            sections: Concatenated section bytes
            
        Returns:
            Number of bytes written
        """
        self._file.write(sections)
        self._data_start = self._file.tell()
        return len(sections)
    
    def write_container(self, header: ContainerHeader, sections: bytes) -> int:
        """
        Write complete container header and sections.
        
        Args:
            header: ContainerHeader to write
            sections: Concatenated section bytes
            
        Returns:
            Total bytes written (header + sections)
        """
        written = self.write_header(header)
        written += self.write_sections(sections)
        return written
    
    @property
    def data_start_position(self) -> int:
        """Get the file position where data section starts."""
        return self._data_start


def is_new_format(file_path: str) -> bool:
    """
    Check if a file uses the new container format.
    
    Args:
        file_path: Path to .enc file
        
    Returns:
        True if new format, False if legacy
    """
    with open(file_path, 'rb') as f:
        magic = f.read(4)
        return magic == MAGIC_BYTES


def get_container_version(file_path: str) -> int:
    """
    Get the container format version of a file.
    
    Args:
        file_path: Path to .enc file
        
    Returns:
        Version number (1 for legacy, 3+ for new format)
    """
    with open(file_path, 'rb') as f:
        magic = f.read(4)
        if magic != MAGIC_BYTES:
            return ContainerVersion.LEGACY
        
        version = struct.unpack('B', f.read(1))[0]
        return version

