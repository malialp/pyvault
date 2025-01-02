import click

EMPTY_CHAR = "░"
FILL_CHAR = "█"
MAX_FILE_CHAR_LEN = 30

def progressbar(filesize, filename):
    filename = (filename if len(filename) < MAX_FILE_CHAR_LEN else filename[:MAX_FILE_CHAR_LEN] + '...') + ' '*((MAX_FILE_CHAR_LEN + 4) - len(filename))
    return click.progressbar(length=filesize, label=filename, bar_template=f"==> %(label)s [{click.style('%(bar)s', bg='blue')}] %(info)s", empty_char=EMPTY_CHAR, fill_char=FILL_CHAR)