"""Wording checks. On their own, none of these prove anything, plenty of
genuine marketing emails use urgent language too. They only earn their
weight in the scorer when combined with the technical checks elsewhere.
"""

import email.utils

URGENCY_PHRASES = [
    "verify your account",
    "act now",
    "immediate action required",
    "account has been suspended",
    "confirm your identity",
    "unusual activity",
    "click here immediately",
    "limited time",
    "update your payment details",
    "account will be closed",
]

GENERIC_GREETINGS = [
    "dear customer",
    "dear user",
    "dear valued customer",
    "dear member",
]

SENSITIVE_REQUESTS = [
    "password",
    "pin number",
    "card number",
    "sort code",
    "national insurance number",
    "login credentials",
]

# A request to move communication onto a phone number is a known pretext
# step in impersonation scams, it gets the conversation off a monitored,
# filtered channel and onto one that isn't. Weak on its own, plenty of
# genuine emails ask for a number too, but worth noting alongside other
# signals.
CONTACT_INFO_REQUESTS = [
    "mobile number",
    "phone number",
    "contact number",
    "cell number",
    "whatsapp",
]


def check_phrases(body, phrase_list):
    body_lower = (body or "").lower()
    return [phrase for phrase in phrase_list if phrase in body_lower]


def check_reply_to_mismatch(msg):
    """A Reply-To on a different domain to the From address means replies
    go somewhere other than where the email claims to be from."""
    reply_to = email.utils.parseaddr(msg.get("Reply-To", ""))[1]
    if not reply_to:
        return False

    from_addr = email.utils.parseaddr(msg.get("From", ""))[1]
    from_domain = from_addr.split("@")[-1].lower()
    reply_domain = reply_to.split("@")[-1].lower()
    return from_domain != reply_domain
