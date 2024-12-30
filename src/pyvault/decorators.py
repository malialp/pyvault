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
        
        # check if config file exists
        if not os.path.exists("config.json"):
            click.echo("Vault not initialized. Please run 'vault init' command to initialize the vault.")
            return
        else:
            with open("config.json") as f:
                config = json.load(f)
                
                # check if salt valid
                if config.get("salt") is None or config.get("salt") == "" or len(config.get("salt")) != 32:
                    click.echo("Invalid salt found in config.json. Please reinitialize the vault.")
                    return
    
        return ctx.invoke(command, *args, **kwargs)
    
    return click.Command(
        name=command.name,
        callback=wrapper,
        params=command.params,
        help=command.help,
    )
