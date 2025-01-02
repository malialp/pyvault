from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import os
import base64
import json

from .utils import progressbar

# Constants
ENCRYPT_CHUNK_SIZE = 524288
DECRYPT_CHUNK_SIZE = 699148
MAX_FILE_CHAR_LEN = 30

def init_vault(path):
    base_path = os.path.abspath(path)
    os.makedirs(base_path, exist_ok=True)

    config = config = {
                "vault_path": base_path,
                "salt": os.urandom(16).hex(),
                "excluded_files": [
                    "config.json",
                ],
            }

    with open(os.path.join(base_path, "config.json"), "w") as f:
        f.write(json.dumps(config, indent=4))
    
    return config


def get_config():
    with open("config.json") as f:
        config = json.load(f)
        config["salt"] = bytes.fromhex(config["salt"])
        return config


def get_fernet(password):
    config = get_config()
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=config["salt"],
        iterations=480000,
        )
    
    key = base64.urlsafe_b64encode(kdf.derive(bytes(password, "utf-8")))

    return Fernet(key)


def encrypt_file(filename, f):
    with open(filename, 'rb') as read_file, open(filename + '.enc', 'wb') as write_file:
        filesize = os.path.getsize(filename)
        
        with progressbar(filesize, filename) as bar:
            while True:
                block = read_file.read(ENCRYPT_CHUNK_SIZE)
                
                if not block:
                    break
                
                encrypted = f.encrypt(block)
                write_file.write(encrypted)
                bar.update(len(block))

    os.remove(filename)

def decrypt_file(filename, f):
    new_filename = '.'.join(filename.split('.')[:-1])
    try:
        with open(filename, 'rb') as read_file, open(new_filename, 'wb') as write_file:
            filesize = os.path.getsize(filename)
            
            with progressbar(filesize, filename) as bar:
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
    f = get_fernet(password)
    
    config = get_config()
    vault_path = config["vault_path"]
    vault_files = [file for file in os.listdir(vault_path) if file not in config["excluded_files"]]

    for filename in vault_files:
        status = encrypt_file(filename, f)

        if status == 'abort':
            return 'abort'
        

def decrypt_vault(password):
    f = get_fernet(password)
    
    config = get_config()
    vault_path = config["vault_path"]
    vault_files = [file for file in os.listdir(vault_path) if file not in config["excluded_files"]]

    for filename in vault_files:
        status = decrypt_file(filename, f)
        if status == 'abort':
            return 'abort'