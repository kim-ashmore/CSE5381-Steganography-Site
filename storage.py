"""
storage.py
----------
 per-user folder structure, and for keeping filenames
safe. This will mantain the necrypt/ decrypt files and keys, etc
"""

import os
import uuid
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(__file__)
UPLOAD_ROOT = os.path.join(BASE_DIR, "uploads")
KEYS_ROOT = os.path.join(BASE_DIR, "keys")


def user_upload_dir(user_id):
    path = os.path.join(UPLOAD_ROOT, str(user_id))
    os.makedirs(path, exist_ok=True)
    return path


def user_keys_dir(user_id):
    path = os.path.join(KEYS_ROOT, str(user_id))
    os.makedirs(path, exist_ok=True)
    return path


def unique_name(original_name):
    """Prefix a filename with a short random id so uploads never collide,
    while keeping the human-readable original name for display."""
    safe = secure_filename(original_name) or "file"
    return f"{uuid.uuid4().hex[:10]}_{safe}"


def save_bytes(directory, filename, data_bytes):
    full_path = os.path.join(directory, filename)
    with open(full_path, "wb") as f:
        f.write(data_bytes)
    return full_path


def read_bytes(full_path):
    with open(full_path, "rb") as f:
        return f.read()
