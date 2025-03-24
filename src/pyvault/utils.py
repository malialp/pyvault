import click
import random
import string

from .settings import MAX_FILE_CHAR_LEN, EMPTY_CHAR, FILL_CHAR


def progressbar(filesize, filename):
    filename = (filename if len(filename) < MAX_FILE_CHAR_LEN else filename[:MAX_FILE_CHAR_LEN] + '...') + ' '*((MAX_FILE_CHAR_LEN + 3) - len(filename))
    return click.progressbar(length=filesize, label=filename, bar_template=f"==> %(label)s [{click.style('%(bar)s', bg='blue')}] %(info)s", empty_char=EMPTY_CHAR, fill_char=FILL_CHAR)


def random_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))