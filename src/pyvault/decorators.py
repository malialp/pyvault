import click
import os
import json


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
            with open("config.json") as f:
                config = json.load(f)

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
