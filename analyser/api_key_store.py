"""Stores an optional VirusTotal API key locally, so the GUI doesn't need
an environment variable set every time.

The key is written in plain text to a small config file in your home
folder, not encrypted, not hidden from other programs running as you.
That's a reasonable trade for a personal tool checking your own email, but
don't reuse a key you'd want protected more strongly than that, and this
file deliberately lives outside the project folder so it can never end up
committed to a repository by accident.
"""

import json
from pathlib import Path

CONFIG_DIR = Path.home() / ".phishing_analyser"
CONFIG_FILE = CONFIG_DIR / "config.json"


def load_key():
    if not CONFIG_FILE.exists():
        return None
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return data.get("vt_api_key")


def save_key(key):
    CONFIG_DIR.mkdir(exist_ok=True)
    CONFIG_FILE.write_text(json.dumps({"vt_api_key": key}), encoding="utf-8")


def clear_key():
    if CONFIG_FILE.exists():
        CONFIG_FILE.write_text(json.dumps({}), encoding="utf-8")
