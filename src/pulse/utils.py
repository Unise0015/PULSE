import os
from pathlib import Path


def normalize_user_path(user_input: str) -> str:
    """Normalizes a user-provided file or directory path, stripping surrounding quotes and expanding user home directory."""
    if not user_input:
        return ""

    path_str = str(user_input).strip()
    if (path_str.startswith('"') and path_str.endswith('"')) or (path_str.startswith("'") and path_str.endswith("'")):
        path_str = path_str[1:-1].strip()

    expanded = os.path.expanduser(path_str)
    return str(Path(expanded))
