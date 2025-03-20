import click
import os
import json

from .settings import APP_VERSION
from .vault import get_config

def clear_console(command):
    @click.pass_context
    def wrapper(ctx, *args, **kwargs):
        click.clear()
        return ctx.invoke(command, *args, **kwargs)
    
    return click.Command(
        name=command.name,
        callback=wrapper,
        params=command.params,
        help=command.help,
    )


def validate_vault(command):
    @click.pass_context
    def wrapper(ctx, *args, **kwargs):
        if not os.path.exists("config.json"):
            click.echo(click.style("Vault not initialized. Please run 'vault init' command to initialize the vault.", fg='red'))
            return
        else:
            config = get_config()

            major_version, minor_version, patch_version = APP_VERSION.split(".")
            config_major_version, config_minor_version, config_patch_version = config.get("version").split(".") 

            if config.get("version") is None or config_major_version != major_version or config_minor_version != minor_version:
                click.echo(click.style("Invalid or outdated config.json found. Please update the app.", fg='red'))
                click.echo(click.style('Run "pip install --upgrade pyvault"', fg='yellow'))
                return

            if config.get("salt") is None or config.get("salt") == "" or len(config.get("salt")) != 32:
                click.echo(click.style("Invalid salt found in config.json. Please reinitialize the vault.", fg='red'))
                return
    
        return ctx.invoke(command, *args, **kwargs)
    
    return click.Command(
        name=command.name,
        callback=wrapper,
        params=command.params,
        help=command.help,
    )
