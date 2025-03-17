from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

import os
import base64
import json

from .utils import progressbar
from .settings import ENCRYPT_CHUNK_SIZE, DECRYPT_CHUNK_SIZE, APP_VERSION


def init_vault(path):
    base_path = os.path.abspath(path)
    os.makedirs(base_path, exist_ok=True)

    config = {
        "version": APP_VERSION,
        "salt": os.urandom(16).hex(),
        "vault_lock_status": False,
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
    with open(filename, 'rb') as read_file, open(filename + '.enc', 'wb') as write_file:
        write_file.write(salthash)
        filesize = os.path.getsize(filename) + 32
        
        with progressbar(filesize, filename) as bar:
            bar.update(32)

            while True:
                block = read_file.read(ENCRYPT_CHUNK_SIZE)
                
                if not block:
                    break
                
                encrypted = f.encrypt(block)
                write_file.write(encrypted)
                bar.update(len(block))

    os.remove(filename)

def decrypt_file(filename, f, salthash):
    new_filename = '.'.join(filename.split('.')[:-1])
    try:
        with open(filename, 'rb') as read_file, open(new_filename, 'wb') as write_file:
            filesize = os.path.getsize(filename)
            file_salt_hash = read_file.read(32)
            
            if file_salt_hash != salthash:
                return 'wrong_salt'
            
            with progressbar(filesize, filename) as bar:
                bar.update(32)

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


def encrypt_vault(password):
    config = get_config()

    if config["vault_lock_status"]:
        return 'already_satisfied'
        
    vault_files = [file for file in os.listdir('.') if file not in config["excluded_files"]]
    
    if len(vault_files) == 0:
        return 'empty'

    f = get_fernet(password)

    salt = bytes.fromhex(config["salt"])
    
    salt_hash_obj = hashes.Hash(hashes.SHA256())
    salt_hash_obj.update(salt)
    salt_hash = salt_hash_obj.finalize()

    for filename in vault_files:
        status = encrypt_file(filename, f, salt_hash)

        if status == 'abort':
            return 'abort'
    
    config["vault_lock_status"] = True
    set_config(config, "config.json")


def decrypt_vault(password):
    config = get_config()
    
    if not config["vault_lock_status"]:
        return 'already_satisfied'

    vault_files = [file for file in os.listdir('.') if file not in config["excluded_files"]]

    if len(vault_files) == 0:
        return 'empty'

    f = get_fernet(password)

    salt = bytes.fromhex(config["salt"])
    
    salt_hash_obj = hashes.Hash(hashes.SHA256())
    salt_hash_obj.update(salt)
    salt_hash = salt_hash_obj.finalize()

    for filename in vault_files:
        status = decrypt_file(filename, f, salt_hash)
        if status in ['abort', 'wrong_salt']:
            return status
    
    config["vault_lock_status"] = False
    set_config(config, "config.json")