"""Checks for identity impersonation, the trick behind most business email
compromise (BEC) scams: the display name claims to be a specific person,
but the sending address has nothing to do with them.

This is a genuinely different problem to authentication (auth.py) or file
and link reputation (reputation.py). Both of those check whether the
infrastructure sending the email is legitimate. Neither has anything to
say about whether "James Bailey" is really James Bailey, an email like
that can pass SPF, DKIM and DMARC perfectly well, because it really was
sent through Gmail's genuine servers, by a genuine (if freshly made)
Gmail account. The fraud is in the claimed identity, not the transport,
and no amount of checking the transport will ever catch it.
"""

import email.utils
import re

# Well-known free consumer providers. Not a judgement on anyone who
# genuinely uses one, most people do, just a fact worth knowing when a
# message is presenting itself as coming from someone in a professional
# capacity.
FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
    "aol.com", "mail.com", "protonmail.com", "gmx.com", "live.com",
}

# A rough test for "this reads as a person's full name" rather than a
# company, role, or department name. Two or three capitalised words and
# nothing else.
PERSON_NAME_PATTERN = re.compile(r"^[A-Z][a-zA-Z'-]+(?:\s+[A-Z][a-zA-Z'-]+){1,2}$")


def check_freemail_personal_name(msg):
    """Flags a personal-looking display name sent from a free provider.
    Weak on its own, genuine contacts do this constantly, but it needs no
    setup and catches the general shape of a name-impersonation attempt."""
    display_name, address = email.utils.parseaddr(msg.get("From", ""))
    if not display_name or not address:
        return None

    domain = address.split("@")[-1].lower()
    if domain in FREE_EMAIL_DOMAINS and PERSON_NAME_PATTERN.match(display_name.strip()):
        return (
            f'display name "{display_name}" reads as a personal name, '
            f"sent from a free email address ({address})"
        )
    return None


def check_known_contact_mismatch(msg, contacts):
    """contacts is a {lowercase name: lowercase expected domain} mapping,
    saved locally by the user for people they actually know. A display
    name matching a saved contact, sent from a domain that isn't theirs,
    is about as clear a signal as this kind of tool can give."""
    display_name, address = email.utils.parseaddr(msg.get("From", ""))
    if not display_name or not address:
        return None

    domain = address.split("@")[-1].lower()
    expected_domain = contacts.get(display_name.strip().lower())
    if expected_domain and domain != expected_domain:
        return (
            f'claims to be "{display_name}" but doesn\'t come from their known domain '
            f"({domain} instead of {expected_domain})"
        )
    return None
