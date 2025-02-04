import click
import maskpass
import os

from .decorators import clear_console, validate_vault
from .vault import init_vault, encrypt_vault, decrypt_vault, get_config

@clear_console
@click.command
@click.argument("path", default="vault")
def init(path):
    click.echo("Initializing vault...")

    config = init_vault(path)

    click.echo(f"Vault location: {click.style(os.path.abspath(path), fg='blue', underline=True, bold=True)}")


@clear_console
@validate_vault
@click.command
@click.option("-k", "--key", help="Key to encrypt the data")
def encrypt(key):
    if not key:
        key1 = maskpass.askpass('Enter password: ', '*')
        key2 = maskpass.askpass('Enter password again: ', '*')
        
        if key1 == key2:
            key = key1
        else:
            click.echo("Keys do not match. Exiting...")
            return
    
    click.echo("Encrypting vault...")
    status = encrypt_vault(key)
    
    if status == 'abort':
        click.echo(click.style("Encryption failed. Exiting...", fg='red'))    
        return
    
    if status == 'empty':
        click.echo(click.style("Vault is empty.", fg='yellow'))
        return
    
    if status == 'already_satisfied':
        click.echo(click.style("Vault is already encrypted.", fg='yellow'))
        return
    
    
    click.echo("🔒 Vault Encrypted successfully.")
    

@clear_console
@validate_vault
@click.command
@click.option("-k", "--key", help="Key to decrypt the data")
def decrypt(key):
    if not key:
        key = maskpass.askpass('Enter password: ', '*')

    click.echo("Decrypting vault...")
    status = decrypt_vault(key)

    if status == 'abort':
        click.echo(click.style("Decryption failed. Exiting...", fg='red'))    
        return
    
    if status == 'empty':
        click.echo(click.style("Vault is empty.", fg='yellow'))
        return
    
    if status == 'already_satisfied':
        click.echo(click.style("Vault is already decrypted.", fg='yellow'))
        return
    
    click.echo("🔓 Vault decrypted successfully.")


@clear_console
@validate_vault
@click.command
def status():
    config = get_config()
    status = config['vault_lock_status']
    click.echo(f'{"🔓" if status == False else "🔒"} Vault is {click.style("UNLOCKED", fg="red") if status == False else click.style("LOCKED", fg="green")}')

# Grouping the commands
@click.group
def cli():
    pass

cli.add_command(init)
cli.add_command(status)
cli.add_command(encrypt)
cli.add_command(decrypt)