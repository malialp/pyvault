import click
import maskpass
import os
import time

from .utils import clear_console, progressbar

@clear_console
@click.command
@click.argument("path", default="vault")
def init(path):
    click.echo("Initializing vault...")
    click.echo(f"Vault location: {click.style(os.path.abspath(path), fg='blue', underline=True, bold=True)}")


@clear_console
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

    print(f"Key received: {key}")


@clear_console
@click.command
@click.option("-k", "--key", help="Key to decrypt the data")
def decrypt(key):
    if not key:
        key = maskpass.askpass('Enter password: ', '*')

    print(f"Key received: {key}")



@click.group
def cli():
    pass

cli.add_command(encrypt)
cli.add_command(decrypt)
cli.add_command(init)


def main():
    cli()

if __name__ == "__main__":
    main()