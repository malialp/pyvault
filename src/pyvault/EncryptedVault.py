from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import maskpass
import base64
import math

from colorama import init
from termcolor import colored

init()

# cmd = 'mode 80, 30'
# os.system(cmd)


class EncryptedVault:

    vault_path = 'vault'
    salt_path = 'salt.salt'
    salt = None

    max_file_char_len = 30
    encrypt_chunk_size = 2**19
    decrypt_chunk_size = 699148

    def __init__(self):
        self.load_vault()
        self.load_salt()

    def generate_salt(self):
        salt = os.urandom(16)
        self.salt = salt
        with open('salt.salt', 'wb') as f:
            f.write(salt)        


    def load_salt(self):
        if not os.path.isfile('salt.salt'):
            self.generate_salt()
        else:
            with open(self.salt_path, 'rb') as f:
                self.salt = f.read()
        

    def load_vault(self):
        if not os.path.exists('./vault'):
            os.mkdir('./vault')
            self.vault_path = './vault'


    def get_fernet(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=480000,
            )
        
        key = base64.urlsafe_b64encode(kdf.derive(password))

        return Fernet(key)


    def encrypt_file(self, file_path, f):
        filename = file_path if len(file_path) < self.max_file_char_len else file_path[:self.max_file_char_len] + '...'
        print(f'\r==> {filename}' + ' '*((self.max_file_char_len + 4) - len(filename)) + colored('[NOT ENCRYPTED]', 'white', 'on_light_red'), end='', flush=True)
        # FILE ENCRYPTION

        with open(file_path, 'rb') as read_file, open(file_path + '.enc', 'wb') as write_file:
            file_size = os.path.getsize(file_path)
            progress = 0
            while True:
                percent = progress / file_size
                print(f'\r==> {filename}' + ' '*((self.max_file_char_len + 4) - len(filename)) + colored('[ ECRYPTING...]', 'white', 'on_light_blue') + colored(f'[{"█"*math.floor(percent*20)}{"░"*(20-math.floor(percent*20))}][{math.ceil(percent*100)}%]', 'white', 'on_light_magenta') , end='', flush=True)
                block = read_file.read(self.encrypt_chunk_size)
                
                if not block:
                    break
                
                encrypted = f.encrypt(block)
                write_file.write(encrypted)

                if progress + self.encrypt_chunk_size >= file_size:
                    progress = file_size
                else:
                    progress += self.encrypt_chunk_size


        os.remove(file_path)

        # FILE ENCRYPTION
        print(f'\r==> {filename}' + ' '*((self.max_file_char_len + 4) - len(filename)) + colored('[  ENCRYPTED  ]', 'white', 'on_light_green'), end='\n', flush=True)
        

    def decrypt_file(self, file_path, f):
        filename = file_path if len(file_path) < self.max_file_char_len else file_path[:self.max_file_char_len] + '...'
    
        new_file_path = '.'.join(file_path.split('.')[:-1])
        try: 
            print(f'\r==> {filename}' + ' '*((self.max_file_char_len + 4) - len(filename)) + colored('[  ENCRYPTED  ]', 'white', 'on_light_green'), end='', flush=True)
            # FILE DECRYPTION
            with open(file_path, 'rb') as read_file, open(new_file_path, 'wb') as write_file:
                file_size = os.path.getsize(file_path)
                progress = 0
                while True:
                    percent = progress / file_size
                    print(f'\r==> {filename}' + ' '*((self.max_file_char_len + 4) - len(filename)) + colored('[DECRYPTING...]', 'white', 'on_light_blue') + colored(f'[{"█"*math.floor(percent*20)}{"░"*(20-math.floor(percent*20))}][{math.ceil(percent*100)}%]', 'white', 'on_light_magenta') , end='', flush=True)
                    block = read_file.read(self.decrypt_chunk_size)
                    if not block:
                        break
                    decrypted = f.decrypt(block)
                    write_file.write(decrypted)

                    if progress + self.decrypt_chunk_size >= file_size:
                        progress = file_size
                    else:
                        progress += self.decrypt_chunk_size

                # FILE DECRYPTION
                print(f'\r==> {filename}' + ' '*((self.max_file_char_len + 4) - len(filename)) + colored('[  DECRYPTED  ]', 'white', 'on_light_red'), end='\n', flush=True)

            os.remove(file_path)
        except:
            print(f'\r==> {filename}' + ' '*((self.max_file_char_len + 4) - len(filename)) + colored('[ WRONG  PASS ]', 'white', 'on_light_red') + colored(f'[{"█"*math.floor(percent*20)}{"░"*(20-math.floor(percent*20))}][{math.ceil(percent*100)}%]', 'white', 'on_light_magenta') , end='\n', flush=True)
            os.remove(new_file_path)
            return 'abort'

    def encrypt_vault(self):
        password = bytes(maskpass.askpass('Enter Password: ', '*'), "utf-8")
        f = self.get_fernet(password)
    
        print(colored('COUNTING FILES...', 'white', 'on_blue'))

        vault_files = os.listdir(self.vault_path)

        print(colored(f'{len(vault_files)} FILE COUNTED.', 'white', 'on_blue'))
        print(colored('STARTING ENCRYPTION...', 'white', 'on_blue'))
        print(colored(self.max_file_char_len*3*'-', 'white', 'on_magenta'))
        
        for file_path in vault_files:
            self.encrypt_file(os.path.join(self.vault_path, file_path), f)
        
        print(colored(self.max_file_char_len*3*'-', 'white', 'on_magenta'))
        print(colored('ENCRYPTION COMPLETED.', 'white', 'on_blue'))
        print(colored('VAULT IS LOCKED.', 'white', 'on_light_green'))

    
    def decrypt_vault(self):
        password = bytes(maskpass.askpass('Enter Password: ', '*'), "utf-8")
        f = self.get_fernet(password)

        print(colored('COUNTING FILES...', 'white', 'on_blue'))

        vault_files = os.listdir(self.vault_path)

        print(colored(f'{len(vault_files)} FILE COUNTED.', 'white', 'on_blue'))
        print(colored('STARTING DECRYPTION...', 'white', 'on_blue'))
        print(colored(self.max_file_char_len*3*'-', 'white', 'on_magenta'))

        for file_path in vault_files:
            status = self.decrypt_file(os.path.join(self.vault_path, file_path), f)
            if status == 'abort':
                break

        print(colored(self.max_file_char_len*3*'-', 'white', 'on_magenta'))
        
        if status != 'abort':
            print(colored('DECRYPTION COMPLETED.', 'white', 'on_blue'))
            print(colored('VAULT IS UNLOCKED.', 'white', 'on_light_red'))
        else:
            print(colored('DECRYPTION NOT COMPLETED.', 'white', 'on_red'))
            print(colored('CHECK YOUR PASSWORD AND TRY AGAIN', 'white', 'on_red'))
        

vault = EncryptedVault()

print(colored(41*'-', 'white', 'on_light_cyan'))
print(colored(13*' ' + 'ENCRYPTED VAULT' + 13*' ', 'white', 'on_light_blue'))
print(colored(41*'-', 'white', 'on_light_cyan'))

while True:
    print('\n')
    print('1) ENCRYPT VAULT')
    print('2) DECRYPT VAULT')
    print('3) EXIT', end='\n\n')
    
    choice = input('==> ')
    
    os.system('cls||clear')

    if choice == '1':
        vault.encrypt_vault()
    elif choice == '2':
        vault.decrypt_vault()
    elif choice == '3':
        break
    else:
        print(colored('NOT VALID INPUT', 'white', 'on_red'))