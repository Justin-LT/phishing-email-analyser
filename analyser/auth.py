"""SPF, DKIM and DMARC checks, plus sender alignment.

Worth being clear about what this does and doesn't do. We are not performing
our own SPF/DKIM lookups here, that would mean redoing a DNS check the
receiving mail server already did with far better context (it knows the
connecting IP, the actual signing key, all of it). Instead we read the
Authentication-Results header that server left behind and trust its verdict.
This is the same approach most mail clients use to show their "this looks
suspicious" banners.

The one thing worth doing ourselves is comparing the visible From address
against the Return-Path, since a mismatch there is cheap to spot and a
common sign of spoofing that the receiving server won't always flag.
"""

import re
import email.utils


def parse_authentication_results(msg):
    header = msg.get("Authentication-Results", "")
    results = {}
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"{mechanism}=(\w+)", header, re.IGNORECASE)
        results[mechanism] = match.group(1).lower() if match else "none"
    return results


def check_sender_alignment(msg):
    """True if the From domain and Return-Path domain differ. Returns None
    if there's no Return-Path to compare against."""
    return_path = email.utils.parseaddr(msg.get("Return-Path", ""))[1]
    if not return_path:
        return None

    from_addr = email.utils.parseaddr(msg.get("From", ""))[1]
    from_domain = from_addr.split("@")[-1].lower()
    return_domain = return_path.split("@")[-1].lower()
    return from_domain != return_domain
