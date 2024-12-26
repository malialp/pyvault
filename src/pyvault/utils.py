import click

empty_char = "░"
fill_char = "█"

def progressbar(length, label):
    return click.progressbar(length=length, label=label, bar_template="%(label)s [%(bar)s] %(info)s", empty_char=empty_char, fill_char=fill_char)

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


# primary, secondary, danger, warning, success

# black on white
# blue on white
# white on red
# black on yellow

# white on cyan
# white on red
# blue on white
# black on white