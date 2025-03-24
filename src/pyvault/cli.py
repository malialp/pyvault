import click
import maskpass
import os

from .decorators import clear_console, validate_vault
from .vault import init_vault, encrypt_vault, decrypt_vault, get_config
from .settings import APP_VERSION


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
    
    click.echo(f"\n{click.style(len(status['unsuccesful_files']) + len(status['succesful_files']), fg='blue')} files processed.")
    click.echo(f"{click.style(len(status['succesful_files']), fg='green')} files encrypted successfully.")
    click.echo(f"{click.style(len(status['unsuccesful_files']), fg='red')} files failed.")

    if len(status['unsuccesful_files']) > 0:
        click.echo(click.style("\nEncryption failed for the following files:", fg='red'))
        for file in status['unsuccesful_files']:
            click.echo(f"  - {file}")

        return

    click.echo("\n🔒 Vault Encrypted successfully.")
    

@clear_console
@validate_vault
@click.command
@click.option("-k", "--key", help="Key to decrypt the data")
def decrypt(key):
    if not key:
        key = maskpass.askpass('Enter password: ', '*')

    click.echo("Decrypting vault...")
    
    status = decrypt_vault(key)

    click.echo(f"\n{click.style(len(status['unsuccesful_files']) + len(status['succesful_files']), fg='blue')} files processed.")
    click.echo(f"{click.style(len(status['succesful_files']), fg='green')} files decrypted successfully.")
    click.echo(f"{click.style(len(status['unsuccesful_files']), fg='red')} files failed.")

    if len(status['unsuccesful_files']) > 0:
        click.echo(click.style("\nDecryption failed for the following files:", fg='red'))
        for file in status['unsuccesful_files']:
            click.echo(f"  - {file}")

        return
    
    click.echo("\n🔓 Vault decrypted successfully.")



# Grouping the commands
@click.group(invoke_without_command=True)
@click.pass_context
@click.option("-V", "--version", help="Show the version of the package", is_flag=True)
def cli(ctx, version):
    if version:
        click.echo(f"PyVault v{APP_VERSION}")
        return

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        return


cli.add_command(init)
cli.add_command(encrypt)
cli.add_command(decrypt)