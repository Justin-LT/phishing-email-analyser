"""Handles loading a .eml file and getting at its body content.

Nothing clever here. Python's own email library already knows how to walk
a MIME structure properly, so there's no reason to hand-roll a parser.
"""

import email
from email import policy


def load_email(path):
    with open(path, "rb") as f:
        return email.message_from_binary_file(f, policy=policy.default)


def get_body_text_and_html(msg):
    """Returns (plain_text_body, html_body). Either can be an empty string
    if that part isn't present. Multipart emails often carry both, in which
    case we take the first of each we find."""
    text_body = ""
    html_body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain" and not text_body:
                text_body = part.get_content()
            elif content_type == "text/html" and not html_body:
                html_body = part.get_content()
    else:
        if msg.get_content_type() == "text/html":
            html_body = msg.get_content()
        else:
            text_body = msg.get_content()

    return text_body, html_body
