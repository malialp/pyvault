from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

import os
import base64
import json

from .utils import progressbar, random_string
from .settings import ENCRYPT_CHUNK_SIZE, DECRYPT_CHUNK_SIZE, FILENAME_ENCRYPT_CHUNK_SIZE, FILENAME_DECRYPT_CHUNK_SIZE, APP_VERSION


def init_vault(path):
    base_path = os.path.abspath(path)
    os.makedirs(base_path, exist_ok=True)

    config = {
        "version": APP_VERSION,
        "salt": os.urandom(16).hex(),
        "excluded_files": [
            "config.json",
        ],
    }

    config_path = os.path.join(base_path, "config.json")
    set_config(config, config_path)
    
    return config


def get_config():
    with open("config.json") as f:
        config = json.load(f)
        return config


def set_config(config, path):
    if os.path.exists(path):
        os.chmod(path, 0o666)
    
    with open(path, "w") as f:
        json.dump(config, f, indent=4)
    
    os.chmod(path, 0o444)


def get_fernet(password):
    config = get_config()
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes.fromhex(config["salt"]),
        iterations=480000,
        backend=default_backend()
        )
    
    key = base64.urlsafe_b64encode(kdf.derive(bytes(password, "utf-8")))

    return Fernet(key, backend=default_backend())


def encrypt_file(filename, f, salthash):
    new_filename = random_string(16) + '.enc'

    filename_bytes = bytes(filename[:FILENAME_ENCRYPT_CHUNK_SIZE].ljust(FILENAME_ENCRYPT_CHUNK_SIZE, "0"), 'utf-8')
    filename_encrypted = f.encrypt(filename_bytes)
    
    with open(filename, 'rb') as read_file, open(new_filename, 'wb') as write_file:
        filesize = os.path.getsize(filename)
        
        write_file.write(salthash)
        write_file.write(filename_encrypted)
        
        filesize += 32 + FILENAME_DECRYPT_CHUNK_SIZE

        with progressbar(filesize, filename) as bar:
            bar.update(FILENAME_DECRYPT_CHUNK_SIZE + 32)

            while True:
                block = read_file.read(ENCRYPT_CHUNK_SIZE)
                
                if not block:
                    break
                
                encrypted = f.encrypt(block)
                write_file.write(encrypted)
                bar.update(len(block))

    os.remove(filename)


def decrypt_file(filename, f, salthash):
    try:
        with open(filename, 'rb') as read_file:
            filesize = os.path.getsize(filename)
            file_salt_hash = read_file.read(32)

            if file_salt_hash != salthash:
                return 'wrong_salt'

            encrypted_filename = read_file.read(FILENAME_DECRYPT_CHUNK_SIZE)
            new_filename = f.decrypt(encrypted_filename).decode('utf-8').rstrip('0')

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
        
        os.remove(filename)
    except:
        os.remove(new_filename)
        return 'abort'
        

def get_files():
    config = get_config()
    files = os.listdir('.')

    excluded_files = set(config['excluded_files'])
    encrypted_files = {file for file in files if file.endswith('.enc')}
    unencrypted_files = {file for file in files if not file.endswith('.enc')}

    return {
        "excluded_files": excluded_files,
        "encrypted_files": encrypted_files - excluded_files,
        "unencrypted_files": unencrypted_files - excluded_files,
    }


def encrypt_vault(password):
    config = get_config()
    vault_files = get_files()
    
    if len(vault_files) == 0:
        return 'empty'

    f = get_fernet(password)

    salt = bytes.fromhex(config["salt"])
    
    salt_hash_obj = hashes.Hash(hashes.SHA256())
    salt_hash_obj.update(salt)
    salt_hash = salt_hash_obj.finalize()

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


def decrypt_vault(password):
    config = get_config()
    vault_files = get_files()

    if len(vault_files) == 0:
        return 'empty'

    f = get_fernet(password)

    salt = bytes.fromhex(config["salt"])
    
    salt_hash_obj = hashes.Hash(hashes.SHA256())
    salt_hash_obj.update(salt)
    salt_hash = salt_hash_obj.finalize()

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