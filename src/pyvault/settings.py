import os
import toml


# APP SETTINGS
pyproject_path = os.path.join(os.path.dirname(__file__), "../../pyproject.toml")
pyproject_data = toml.load(pyproject_path)

APP_NAME = pyproject_data["project"]["name"]
APP_VERSION = pyproject_data["project"]["version"]

EXCLUDED_FILES = ["config.json"]


# CONSTANTS
ENCRYPT_CHUNK_SIZE = 524288
DECRYPT_CHUNK_SIZE = 699148

FILENAME_ENCRYPT_CHUNK_SIZE = 256
FILENAME_DECRYPT_CHUNK_SIZE = 440

EMPTY_CHAR = "░"
FILL_CHAR = "█"
MAX_FILE_CHAR_LEN = 30

CHECKBOX_TICK_CHAR = "●"
CHECKBOX_TICK_STYLE = "#429ef5"
CHECKBOX_CURSOR_STYLE = "#429ef5"