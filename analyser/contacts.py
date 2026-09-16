"""Stores a small local list of known contacts and the domain each of
them actually sends from, so the tool can catch a display name being
used to impersonate someone specific. This is the core trick behind most
CEO fraud and business email compromise attempts, and it's a problem
authentication checks and file reputation lookups genuinely can't touch,
see analyser/impersonation.py for why.

Stored in the same local folder as the VirusTotal key, never bundled
into the repository.
"""

import json
from pathlib import Path

CONFIG_DIR = Path.home() / ".phishing_analyser"
CONTACTS_FILE = CONFIG_DIR / "contacts.json"


def load_contacts():
    """Returns a {lowercase name: lowercase domain} dict."""
    if not CONTACTS_FILE.exists():
        return {}
    try:
        return json.loads(CONTACTS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_contacts(contacts):
    CONFIG_DIR.mkdir(exist_ok=True)
    CONTACTS_FILE.write_text(json.dumps(contacts, indent=2), encoding="utf-8")


def add_contact(name, domain):
    contacts = load_contacts()
    contacts[name.strip().lower()] = domain.strip().lower()
    save_contacts(contacts)
    return contacts


def remove_contact(name):
    contacts = load_contacts()
    contacts.pop(name.strip().lower(), None)
    save_contacts(contacts)
    return contacts
