"""
PyVault - Secure File Encryption Tool

A CLI-based file encryption application with support for:
- AES encryption via Fernet
- Embedded thumbnails for images and videos
- Versioned container format for forward compatibility
"""

from .settings import APP_VERSION, APP_NAME

__version__ = APP_VERSION
__app_name__ = APP_NAME

# Public API exports
from .vault import (
    init_vault,
    encrypt_vault,
    decrypt_vault,
    get_config,
    set_config,
    get_files,
    get_thumbnail,
    get_file_info,
)

from .container import (
    ContainerHeader,
    ContainerBuilder,
    ContainerReader,
    ContainerWriter,
    ContainerFlags,
    ContainerVersion,
    is_new_format,
    get_container_version,
)

from .crypto import (
    CryptoService,
    LegacyCryptoService,
    generate_salt,
    hash_salt,
)

from .thumbnail import (
    ThumbnailService,
    extract_thumbnail,
    is_thumbnail_supported,
    MediaType,
)

__all__ = [
    # Version info
    "__version__",
    "__app_name__",
    
    # Vault operations
    "init_vault",
    "encrypt_vault",
    "decrypt_vault",
    "get_config",
    "set_config",
    "get_files",
    "get_thumbnail",
    "get_file_info",
    
    # Container format
    "ContainerHeader",
    "ContainerBuilder",
    "ContainerReader",
    "ContainerWriter",
    "ContainerFlags",
    "ContainerVersion",
    "is_new_format",
    "get_container_version",
    
    # Cryptography
    "CryptoService",
    "LegacyCryptoService",
    "generate_salt",
    "hash_salt",
    
    # Thumbnails
    "ThumbnailService",
    "extract_thumbnail",
    "is_thumbnail_supported",
    "MediaType",
]

