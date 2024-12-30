import click
import maskpass
import os

from .decorators import clear_console, validate_vault
from .vault import init_vault, encrypt_vault, decrypt_vault

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

    encrypt_vault(key)
    

@clear_console
@validate_vault
@click.command
@click.option("-k", "--key", help="Key to decrypt the data")
def decrypt(key):
    if not key:
        key = maskpass.askpass('Enter password: ', '*')

    decrypt_vault(key)


# Grouping the commands
@click.group
def cli():
    pass

cli.add_command(encrypt)
cli.add_command(decrypt)
cli.add_command(init)


if __name__ == "__main__":
    cli()