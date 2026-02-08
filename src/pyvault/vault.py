"""
PyVault Vault Module

This module provides the main vault operations: initialization,
encryption, and decryption of files.

Supports both legacy format (v1/v2) and new container format (v3).
"""

import os
import json
from typing import Optional

from .utils import progressbar, random_string
from .settings import (
    ENCRYPT_CHUNK_SIZE,
    DECRYPT_CHUNK_SIZE,
    FILENAME_ENCRYPT_CHUNK_SIZE,
    FILENAME_DECRYPT_CHUNK_SIZE,
    EXCLUDED_FILES,
    APP_VERSION
)
from .container import (
    ContainerBuilder,
    ContainerReader,
    ContainerWriter,
    ContainerFlags,
    ContainerVersion,
    HEADER_SIZE,
)
from .crypto import (
    LegacyCryptoService,
    hash_salt,
)
from .thumbnail import (
    ThumbnailService,
    MediaType,
    get_media_type,
)


def init_vault(path: str) -> dict:
    """
    Initialize a new vault at the given path.
    
    Creates the vault directory and config.json with a random salt.
    
    Args:
        path: Directory path for the vault
        
    Returns:
        Config dictionary
    """
    base_path = os.path.abspath(path)
    os.makedirs(base_path, exist_ok=True)

    config = {
        "version": APP_VERSION,
        "salt": os.urandom(16).hex(),
        "user_excluded_files": [],
    }

    config_path = os.path.join(base_path, "config.json")
    set_config(config, config_path)
    
    return config


def get_config() -> dict:
    """
    Read vault configuration from config.json.
    
    Returns:
        Config dictionary
    """
    with open("config.json") as f:
        config = json.load(f)
        return config


def set_config(config: dict, path: str = "config.json") -> None:
    """
    Write vault configuration to config.json.
    
    Args:
        config: Config dictionary to write
        path: Path to config file
    """
    if os.path.exists(path):
        os.chmod(path, 0o666)
    
    with open(path, "w") as f:
        json.dump(config, f, indent=4)
    
    os.chmod(path, 0o444)


def get_fernet(password: str):
    """
    Create a Fernet instance for legacy operations.
    
    This function is kept for backward compatibility.
    New code should use CryptoService.
    
    Args:
        password: User password
        
    Returns:
        Fernet instance
    """
    config = get_config()
    salt = bytes.fromhex(config["salt"])
    
    legacy_crypto = LegacyCryptoService(password, salt)
    return legacy_crypto.fernet


def encrypt_file(filename: str, f, salthash: bytes) -> Optional[str]:
    """
    Encrypt a single file using the new container format (v3).
    
    Creates a .enc file with embedded thumbnail (if supported),
    encrypted filename, and encrypted data.
    
    Args:
        filename: Path to file to encrypt
        f: Fernet instance (for legacy compatibility signature)
        salthash: Salt hash bytes
        
    Returns:
        Status string or None on success
    """
    config = get_config()
    salt = bytes.fromhex(config["salt"])
    
    # Extract password from fernet for new crypto service
    # We need to recreate crypto service since we only have fernet
    # This is a bridge between old and new architecture
    new_filename = random_string(16) + '.enc'
    
    try:
        # Get file info
        filesize = os.path.getsize(filename)
        
        # Extract thumbnail if supported
        thumbnail_service = ThumbnailService(enabled=True)
        thumbnail_result = thumbnail_service.extract(filename)
        
        # Determine flags
        flags = ContainerFlags.NONE
        media_type = get_media_type(filename)
        
        encrypted_thumbnail = None
        if thumbnail_result is not None:
            flags |= ContainerFlags.HAS_THUMBNAIL
            if media_type == MediaType.IMAGE:
                flags |= ContainerFlags.IS_IMAGE
            # Encrypt thumbnail with Fernet (same key as data for now)
            encrypted_thumbnail = f.encrypt(thumbnail_result.data)
        
        # Encrypt filename (using legacy method for compatibility)
        filename_bytes = bytes(
            filename[:FILENAME_ENCRYPT_CHUNK_SIZE].ljust(FILENAME_ENCRYPT_CHUNK_SIZE, "0"),
            'utf-8'
        )
        encrypted_filename = f.encrypt(filename_bytes)
        
        # Build container
        builder = ContainerBuilder()
        builder.set_salt(salthash)
        builder.set_encrypted_filename(encrypted_filename)
        builder.set_flags(flags)
        
        if encrypted_thumbnail:
            is_image = media_type == MediaType.IMAGE
            builder.set_encrypted_thumbnail(encrypted_thumbnail, is_image)
        
        # Calculate expected encrypted data size (for progress bar)
        # Fernet overhead: ~57 bytes per chunk (16 IV + 16 timestamp + padding + HMAC)
        num_chunks = (filesize + ENCRYPT_CHUNK_SIZE - 1) // ENCRYPT_CHUNK_SIZE
        estimated_encrypted_size = num_chunks * (ENCRYPT_CHUNK_SIZE + 100)  # rough estimate
        
        header, sections = builder.build()
        
        with open(filename, 'rb') as read_file, open(new_filename, 'wb') as write_file:
            # Write container header and sections
            writer = ContainerWriter(write_file)
            writer.write_container(header, sections)
            
            # Calculate total size for progress bar
            total_progress = filesize + HEADER_SIZE + len(sections)
            
            with progressbar(total_progress, filename) as bar:
                bar.update(HEADER_SIZE + len(sections))
                
                # Encrypt and write data in chunks
                encrypted_data_size = 0
                while True:
                    block = read_file.read(ENCRYPT_CHUNK_SIZE)
                    
                    if not block:
                        break
                    
                    encrypted = f.encrypt(block)
                    write_file.write(encrypted)
                    encrypted_data_size += len(encrypted)
                    bar.update(len(block))
            
            # Update header with actual data size
            # Seek back and rewrite header with correct data_size
            write_file.seek(0)
            header.data_size = encrypted_data_size
            writer.write_header(header)
        
        os.remove(filename)
        return None
        
    except Exception as e:
        # Clean up partial file on error
        if os.path.exists(new_filename):
            os.remove(new_filename)
        return 'abort'


def decrypt_file(filename: str, f, salthash: bytes) -> Optional[str]:
    """
    Decrypt a single .enc file.
    
    Supports both legacy format (v1/v2) and new container format (v3).
    Automatically detects format and uses appropriate decryption method.
    
    Args:
        filename: Path to .enc file
        f: Fernet instance
        salthash: Salt hash for verification
        
    Returns:
        Status string ('wrong_salt', 'abort') or None on success
    """
    new_filename = None
    status = None
    
    try:
        with open(filename, 'rb') as read_file:
            filesize = os.path.getsize(filename)
            
            # Detect format
            reader = ContainerReader(read_file)
            is_new = reader.detect_format()
            
            if is_new:
                # New format (v3)
                status, new_filename = _decrypt_file_v3(filename, f, salthash, read_file, reader, filesize)
            else:
                # Legacy format
                status, new_filename = _decrypt_file_legacy(filename, f, salthash, read_file, filesize)
        
        # File is now closed, safe to remove
        if status is None:
            os.remove(filename)
        
        return status
                
    except Exception:
        if new_filename and os.path.exists(new_filename):
            os.remove(new_filename)
        return 'abort'


def _decrypt_file_legacy(
    filename: str,
    f,
    salthash: bytes,
    read_file,
    filesize: int
) -> tuple[Optional[str], Optional[str]]:
    """
    Decrypt a legacy format .enc file.
    
    Legacy format structure:
    - salt_hash (32 bytes)
    - encrypted_filename (FILENAME_DECRYPT_CHUNK_SIZE bytes)
    - encrypted_data (rest of file)
    
    Returns:
        Tuple of (status, new_filename) where status is None on success
    """
    new_filename = None
    
    try:
        # Read and verify salt hash
        file_salt_hash = read_file.read(32)
        
        if file_salt_hash != salthash:
            return ('wrong_salt', None)
        
        # Read and decrypt filename
        encrypted_filename = read_file.read(FILENAME_DECRYPT_CHUNK_SIZE)
        new_filename = f.decrypt(encrypted_filename).decode('utf-8').rstrip('0')
        
        # Decrypt data
        with open(new_filename, 'wb') as write_file:
            with progressbar(filesize, filename) as bar:
                bar.update(32 + FILENAME_DECRYPT_CHUNK_SIZE)
                
                while True:
                    block = read_file.read(DECRYPT_CHUNK_SIZE)
                    
                    if not block:
                        break
                    
                    decrypted = f.decrypt(block)
                    write_file.write(decrypted)
                    bar.update(len(block))
        
        return (None, new_filename)
        
    except Exception:
        if new_filename and os.path.exists(new_filename):
            os.remove(new_filename)
        return ('abort', None)


def _decrypt_file_v3(
    filename: str,
    f,
    salthash: bytes,
    read_file,
    reader: ContainerReader,
    filesize: int
) -> tuple[Optional[str], Optional[str]]:
    """
    Decrypt a v3 format .enc file.
    
    V3 format uses structured header with explicit offsets.
    
    Returns:
        Tuple of (status, new_filename) where status is None on success
    """
    new_filename = None
    
    try:
        # Read header
        header = reader.read_header()
        
        # Read and verify salt
        file_salt_hash = reader.read_salt()
        
        if file_salt_hash != salthash:
            return ('wrong_salt', None)
        
        # Read and decrypt filename
        encrypted_filename = reader.read_encrypted_filename(FILENAME_DECRYPT_CHUNK_SIZE)
        new_filename = f.decrypt(encrypted_filename).decode('utf-8').rstrip('0')
        
        # Seek to data section
        read_file.seek(header.data_offset)
        
        # Decrypt data
        with open(new_filename, 'wb') as write_file:
            with progressbar(filesize, filename) as bar:
                bar.update(header.data_offset)
                
                bytes_remaining = header.data_size
                
                while bytes_remaining > 0:
                    # Read encrypted chunk
                    to_read = min(DECRYPT_CHUNK_SIZE, bytes_remaining)
                    block = read_file.read(to_read)
                    
                    if not block:
                        break
                    
                    decrypted = f.decrypt(block)
                    write_file.write(decrypted)
                    bytes_remaining -= len(block)
                    bar.update(len(block))
        
        return (None, new_filename)
        
    except Exception:
        if new_filename and os.path.exists(new_filename):
            os.remove(new_filename)
        return ('abort', None)


def get_files() -> dict:
    """
    Get categorized files in the current directory.
    
    Returns:
        Dictionary with keys:
        - excluded_files: Set of files to exclude
        - encrypted_files: Set of .enc files
        - unencrypted_files: Set of non-.enc files
    """
    config = get_config()
    files = [f for f in os.listdir('.') if os.path.isfile(f)]

    excluded_files = set(EXCLUDED_FILES) | set(config['user_excluded_files'])
    encrypted_files = {file for file in files if file.endswith('.enc')}
    unencrypted_files = {file for file in files if not file.endswith('.enc')}

    return {
        "excluded_files": excluded_files,
        "encrypted_files": encrypted_files - excluded_files,
        "unencrypted_files": unencrypted_files - excluded_files,
    }


def encrypt_vault(password: str) -> dict:
    """
    Encrypt all unencrypted files in the vault.
    
    Args:
        password: Encryption password
        
    Returns:
        Dictionary with:
        - succesful_files: List of successfully encrypted files
        - unsuccesful_files: List of files that failed to encrypt
    """
    config = get_config()
    vault_files = get_files()
    
    if len(vault_files['unencrypted_files']) == 0:
        return {
            "succesful_files": [],
            "unsuccesful_files": [],
        }

    f = get_fernet(password)

    salt = bytes.fromhex(config["salt"])
    salt_hash = hash_salt(salt)

    succesful_files = []
    unsuccesful_files = []

    for filename in vault_files['unencrypted_files']:
        status = encrypt_file(filename, f, salt_hash)

        if status == 'abort':
            unsuccesful_files.append(filename)
        else:
            succesful_files.append(filename)
    
    return {
        "succesful_files": succesful_files,
        "unsuccesful_files": unsuccesful_files,
    }


def decrypt_vault(password: str) -> dict:
    """
    Decrypt all encrypted files in the vault.
    
    Args:
        password: Decryption password
        
    Returns:
        Dictionary with:
        - succesful_files: List of successfully decrypted files
        - unsuccesful_files: List of files that failed to decrypt
    """
    config = get_config()
    vault_files = get_files()

    if len(vault_files['encrypted_files']) == 0:
        return {
            "succesful_files": [],
            "unsuccesful_files": [],
        }

    f = get_fernet(password)

    salt = bytes.fromhex(config["salt"])
    salt_hash = hash_salt(salt)

    succesful_files = []
    unsuccesful_files = []

    for filename in vault_files['encrypted_files']:
        status = decrypt_file(filename, f, salt_hash)
        
        if status in ['abort', 'wrong_salt']:
            unsuccesful_files.append(filename)
        else:
            succesful_files.append(filename)
    
    return {
        "succesful_files": succesful_files,
        "unsuccesful_files": unsuccesful_files,
    }


# --- Thumbnail Access Functions (for future GUI use) ---

def get_thumbnail_fast(enc_file_path: str, fernet, salt_hash: bytes) -> Optional[bytes]:
    """
    Extract and decrypt thumbnail from an encrypted file using pre-created fernet.
    
    This is the optimized version that avoids key derivation on each call.
    Use this when loading multiple thumbnails in a batch.
    
    Args:
        enc_file_path: Path to .enc file
        fernet: Pre-created Fernet instance (from get_fernet)
        salt_hash: Pre-computed salt hash for verification
        
    Returns:
        Decrypted thumbnail bytes (JPEG) or None if no thumbnail
    """
    try:
        with open(enc_file_path, 'rb') as f:
            reader = ContainerReader(f)
            
            if not reader.detect_format():
                # Legacy format - no thumbnails
                return None
            
            header = reader.read_header()
            
            if not header.has_thumbnail:
                return None
            
            # Verify salt
            file_salt_hash = reader.read_salt()
            if file_salt_hash != salt_hash:
                return None
            
            # Read and decrypt thumbnail
            encrypted_thumbnail = reader.read_encrypted_thumbnail()
            if encrypted_thumbnail is None:
                return None
            
            return fernet.decrypt(encrypted_thumbnail)
            
    except Exception:
        return None


def get_thumbnail(enc_file_path: str, password: str) -> Optional[bytes]:
    """
    Extract and decrypt thumbnail from an encrypted file.
    
    NOTE: This function performs key derivation on each call which is slow.
    For batch operations, use get_thumbnail_fast() with a pre-created fernet.
    
    Args:
        enc_file_path: Path to .enc file
        password: Decryption password
        
    Returns:
        Decrypted thumbnail bytes (JPEG) or None if no thumbnail
    """
    try:
        # Get fernet for decryption (slow - key derivation)
        fernet = get_fernet(password)
        
        # Get salt hash
        config = get_config()
        salt = bytes.fromhex(config["salt"])
        salt_hash = hash_salt(salt)
        
        return get_thumbnail_fast(enc_file_path, fernet, salt_hash)
            
    except Exception:
        return None


def get_file_info(enc_file_path: str) -> Optional[dict]:
    """
    Get information about an encrypted file without decrypting it.
    
    Args:
        enc_file_path: Path to .enc file
        
    Returns:
        Dictionary with file info or None on error
    """
    try:
        with open(enc_file_path, 'rb') as f:
            reader = ContainerReader(f)
            is_new = reader.detect_format()
            
            if not is_new:
                return {
                    "format_version": ContainerVersion.LEGACY,
                    "has_thumbnail": False,
                    "is_image": False,
                    "file_size": os.path.getsize(enc_file_path)
                }
            
            header = reader.read_header()
            
            return {
                "format_version": header.version,
                "has_thumbnail": header.has_thumbnail,
                "is_image": header.is_image,
                "thumbnail_size": header.thumbnail_size,
                "data_size": header.data_size,
                "file_size": os.path.getsize(enc_file_path)
            }
            
    except Exception:
        return None
