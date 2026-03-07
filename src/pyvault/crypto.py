"""
PyVault Cryptography Module

This module handles all encryption and decryption operations.
It provides a clean interface for key derivation and data encryption
with support for multiple encryption contexts (data, thumbnail, filename).

Encryption scheme:
- Key derivation: PBKDF2HMAC with SHA256
- Encryption: Fernet (AES-128-CBC with HMAC)
- Iterations: 480,000 (OWASP 2023 recommendation)
"""

import base64
import hashlib
from typing import Optional
from dataclasses import dataclass
from enum import Enum

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


# Constants
PBKDF2_ITERATIONS = 480000
PBKDF2_KEY_LENGTH = 32
SALT_SIZE = 16
SALT_HASH_SIZE = 32  # SHA256 output size


class EncryptionContext(Enum):
    """
    Different encryption contexts use different derived keys.
    
    This ensures that compromising one context doesn't compromise others.
    Each context derives a unique key by combining the base salt with a context-specific suffix.
    """
    DATA = b"pyvault_data_v3"
    FILENAME = b"pyvault_filename_v3"
    THUMBNAIL = b"pyvault_thumbnail_v3"


class CryptoError(Exception):
    """Base exception for cryptography operations."""
    pass


class InvalidPasswordError(CryptoError):
    """Raised when password verification fails."""
    pass


class DecryptionError(CryptoError):
    """Raised when decryption fails."""
    pass


class EncryptionError(CryptoError):
    """Raised when encryption fails."""
    pass


@dataclass
class EncryptedChunk:
    """Represents an encrypted data chunk."""
    data: bytes
    is_last: bool = False


def generate_salt() -> bytes:
    """
    Generate a new random salt.
    
    Returns:
        16 bytes of cryptographically secure random data
    """
    import os
    return os.urandom(SALT_SIZE)


def hash_salt(salt: bytes) -> bytes:
    """
    Create SHA256 hash of salt for verification.
    
    Args:
        salt: Raw salt bytes
        
    Returns:
        32-byte SHA256 hash of the salt
    """
    hash_obj = hashes.Hash(hashes.SHA256())
    hash_obj.update(salt)
    return hash_obj.finalize()


def derive_key(password: str, salt: bytes, context: EncryptionContext = EncryptionContext.DATA) -> bytes:
    """
    Derive encryption key from password and salt.
    
    Uses PBKDF2HMAC with SHA256 and context-specific salt derivation.
    
    Args:
        password: User password
        salt: Base salt bytes
        context: Encryption context for key isolation
        
    Returns:
        URL-safe base64 encoded key suitable for Fernet
    """
    # Combine salt with context for key isolation
    context_salt = salt + context.value
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=PBKDF2_KEY_LENGTH,
        salt=context_salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key


def create_fernet(password: str, salt: bytes, context: EncryptionContext = EncryptionContext.DATA) -> Fernet:
    """
    Create a Fernet instance for encryption/decryption.
    
    Args:
        password: User password
        salt: Base salt bytes
        context: Encryption context
        
    Returns:
        Configured Fernet instance
    """
    key = derive_key(password, salt, context)
    return Fernet(key, backend=default_backend())


def derive_master_key(password: str, salt: bytes) -> bytes:
    """
    Derive a master key from password using PBKDF2.
    
    This is the expensive operation (~1-2 seconds with 480k iterations).
    The master key should then be used with HKDF to derive context-specific keys.
    
    Args:
        password: User password
        salt: Base salt bytes
        
    Returns:
        32-byte master key
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=PBKDF2_KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))


def derive_context_key(master_key: bytes, context: EncryptionContext) -> bytes:
    """
    Derive a context-specific key from master key using HKDF.
    
    This is very fast (~microseconds) compared to PBKDF2.
    
    Args:
        master_key: Master key from derive_master_key()
        context: Encryption context for key isolation
        
    Returns:
        URL-safe base64 encoded key suitable for Fernet
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=PBKDF2_KEY_LENGTH,
        salt=context.value,  # Use context as salt for HKDF
        info=b"pyvault-key-derivation",
        backend=default_backend()
    )
    derived = hkdf.derive(master_key)
    return base64.urlsafe_b64encode(derived)


def create_fernet_from_master_key(master_key: bytes, context: EncryptionContext) -> Fernet:
    """
    Create a Fernet instance from a pre-derived master key.
    
    This is fast because it uses HKDF instead of PBKDF2.
    
    Args:
        master_key: Master key from derive_master_key()
        context: Encryption context
        
    Returns:
        Configured Fernet instance
    """
    key = derive_context_key(master_key, context)
    return Fernet(key, backend=default_backend())


class CryptoService:
    """
    Service class for encryption and decryption operations.
    
    Provides a unified interface for all cryptographic operations
    with support for multiple encryption contexts.
    
    Performance: Uses single PBKDF2 + HKDF for fast multi-context key derivation.
    Instead of 3x PBKDF2 (~3-6 seconds), we do 1x PBKDF2 + 3x HKDF (~1-2 seconds).
    """
    
    def __init__(self, password: str, salt: bytes):
        """
        Initialize crypto service.
        
        Args:
            password: User password
            salt: Base salt for key derivation
        """
        self._password = password
        self._salt = salt
        self._salt_hash = hash_salt(salt)
        
        # Derive master key once (expensive PBKDF2 operation)
        master_key = derive_master_key(password, salt)
        
        # Create Fernet instances for each context using fast HKDF
        self._data_fernet = create_fernet_from_master_key(master_key, EncryptionContext.DATA)
        self._filename_fernet = create_fernet_from_master_key(master_key, EncryptionContext.FILENAME)
        self._thumbnail_fernet = create_fernet_from_master_key(master_key, EncryptionContext.THUMBNAIL)
    
    @property
    def salt(self) -> bytes:
        """Get the base salt."""
        return self._salt
    
    @property
    def salt_hash(self) -> bytes:
        """Get the SHA256 hash of the salt."""
        return self._salt_hash
    
    def verify_salt_hash(self, salt_hash: bytes) -> bool:
        """
        Verify if a salt hash matches our salt.
        
        Args:
            salt_hash: Salt hash to verify
            
        Returns:
            True if hashes match
        """
        return salt_hash == self._salt_hash
    
    # --- Data Encryption/Decryption ---
    
    def encrypt_data(self, data: bytes) -> bytes:
        """
        Encrypt data using the DATA context.
        
        Args:
            data: Plaintext data
            
        Returns:
            Encrypted data
            
        Raises:
            EncryptionError: If encryption fails
        """
        try:
            return self._data_fernet.encrypt(data)
        except Exception as e:
            raise EncryptionError(f"Failed to encrypt data: {e}")
    
    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt data using the DATA context.
        
        Args:
            encrypted_data: Encrypted data
            
        Returns:
            Decrypted plaintext data
            
        Raises:
            DecryptionError: If decryption fails
        """
        try:
            return self._data_fernet.decrypt(encrypted_data)
        except InvalidToken:
            raise DecryptionError("Invalid password or corrupted data")
        except Exception as e:
            raise DecryptionError(f"Failed to decrypt data: {e}")
    
    # --- Filename Encryption/Decryption ---
    
    def encrypt_filename(self, filename: str, max_length: int = 256) -> bytes:
        """
        Encrypt a filename using the FILENAME context.
        
        Args:
            filename: Original filename
            max_length: Maximum filename length (padded to this length)
            
        Returns:
            Encrypted filename bytes
            
        Raises:
            EncryptionError: If encryption fails
        """
        try:
            # Truncate and pad filename
            filename_truncated = filename[:max_length]
            filename_padded = filename_truncated.ljust(max_length, '\x00')
            filename_bytes = filename_padded.encode('utf-8')
            
            return self._filename_fernet.encrypt(filename_bytes)
        except Exception as e:
            raise EncryptionError(f"Failed to encrypt filename: {e}")
    
    def decrypt_filename(self, encrypted_filename: bytes) -> str:
        """
        Decrypt a filename using the FILENAME context.
        
        Args:
            encrypted_filename: Encrypted filename bytes
            
        Returns:
            Decrypted filename string
            
        Raises:
            DecryptionError: If decryption fails
        """
        try:
            decrypted = self._filename_fernet.decrypt(encrypted_filename)
            # Remove null padding
            return decrypted.decode('utf-8').rstrip('\x00')
        except InvalidToken:
            raise DecryptionError("Invalid password or corrupted filename")
        except Exception as e:
            raise DecryptionError(f"Failed to decrypt filename: {e}")
    
    # --- Thumbnail Encryption/Decryption ---
    
    def encrypt_thumbnail(self, thumbnail_data: bytes) -> bytes:
        """
        Encrypt thumbnail using the THUMBNAIL context.
        
        Args:
            thumbnail_data: Raw thumbnail bytes (JPEG)
            
        Returns:
            Encrypted thumbnail bytes
            
        Raises:
            EncryptionError: If encryption fails
        """
        try:
            return self._thumbnail_fernet.encrypt(thumbnail_data)
        except Exception as e:
            raise EncryptionError(f"Failed to encrypt thumbnail: {e}")
    
    def decrypt_thumbnail(self, encrypted_thumbnail: bytes) -> bytes:
        """
        Decrypt thumbnail using the THUMBNAIL context.
        
        Args:
            encrypted_thumbnail: Encrypted thumbnail bytes
            
        Returns:
            Decrypted thumbnail bytes (JPEG)
            
        Raises:
            DecryptionError: If decryption fails
        """
        try:
            return self._thumbnail_fernet.decrypt(encrypted_thumbnail)
        except InvalidToken:
            raise DecryptionError("Invalid password or corrupted thumbnail")
        except Exception as e:
            raise DecryptionError(f"Failed to decrypt thumbnail: {e}")


class LegacyCryptoService:
    """
    Legacy crypto service for backward compatibility with v1/v2 containers.
    
    Uses the original key derivation without context separation.
    """
    
    def __init__(self, password: str, salt: bytes):
        """
        Initialize legacy crypto service.
        
        Args:
            password: User password
            salt: Salt bytes from config
        """
        self._password = password
        self._salt = salt
        self._salt_hash = hash_salt(salt)
        self._fernet = self._create_legacy_fernet()
    
    def _create_legacy_fernet(self) -> Fernet:
        """Create Fernet instance using legacy key derivation."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=PBKDF2_KEY_LENGTH,
            salt=self._salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(self._password.encode('utf-8')))
        return Fernet(key, backend=default_backend())
    
    @property
    def salt_hash(self) -> bytes:
        """Get the SHA256 hash of the salt."""
        return self._salt_hash
    
    @property
    def fernet(self) -> Fernet:
        """Get the Fernet instance for legacy operations."""
        return self._fernet
    
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data using legacy scheme."""
        return self._fernet.encrypt(data)
    
    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data using legacy scheme."""
        try:
            return self._fernet.decrypt(data)
        except InvalidToken:
            raise DecryptionError("Invalid password or corrupted data")
