import os
import toml


# APP SETTINGS

pyproject_path = os.path.join(os.path.dirname(__file__), "../../pyproject.toml")
pyproject_data = toml.load(pyproject_path)


APP_NAME = pyproject_data["project"]["name"]
APP_VERSION = pyproject_data["project"]["version"]


# CONSTANTS

ENCRYPT_CHUNK_SIZE = 524288
DECRYPT_CHUNK_SIZE = 699148

EMPTY_CHAR = "░"
FILL_CHAR = "█"
MAX_FILE_CHAR_LEN = 30