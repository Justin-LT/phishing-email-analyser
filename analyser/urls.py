"""Pulls links out of an email and checks them for the usual tricks.

None of these checks are exotic. They're the same handful of things a
careful person would notice if they hovered over a link before clicking:
does it go to a raw IP address, is it hidden behind a shortener, does the
domain use punycode to fake a familiar name, and does the visible link
text actually match where it points.
"""

import re
from urllib.parse import urlparse

URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
IP_HOST_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
ANCHOR_PATTERN = re.compile(
    r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL
)

# A handful of well-known shorteners. Not exhaustive, just enough to catch
# the common ones without pulling in a maintained list from somewhere else.
KNOWN_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}


def extract_urls(text_body, html_body):
    found = set(URL_PATTERN.findall(text_body or ""))
    found |= set(URL_PATTERN.findall(html_body or ""))
    return found


def assess_url(url):
    """Returns a list of plain-English flags for one URL. Empty list means
    nothing obviously wrong, which is not the same as safe."""
    flags = []
    host = (urlparse(url).hostname or "").lower()

    if IP_HOST_PATTERN.match(host):
        flags.append("links to a raw IP address instead of a domain name")
    if host in KNOWN_SHORTENERS:
        flags.append(f"uses a URL shortener ({host}), so the real destination is hidden")
    if host.startswith("xn--") or ".xn--" in host:
        flags.append("domain uses punycode, a common way to fake a lookalike domain")
    if host.count(".") >= 4:
        flags.append("unusually long chain of subdomains")

    return flags


def find_mismatched_anchors(html_body):
    """Looks for <a> tags where the text shown to the reader looks like a
    domain but doesn't match where the link actually goes. This is one of
    the more reliable phishing tells, since a genuine sender has no reason
    to disguise a link this way."""
    if not html_body:
        return []

    mismatches = []
    for href, visible_raw in ANCHOR_PATTERN.findall(html_body):
        visible = re.sub(r"<[^>]+>", "", visible_raw).strip()
        looks_like_a_link = visible.startswith("http") or re.match(r"^[\w.-]+\.\w{2,}", visible)
        if not looks_like_a_link:
            continue

        visible_url = visible if visible.startswith("http") else "http://" + visible
        visible_domain = urlparse(visible_url).netloc.lower()
        href_domain = urlparse(href).netloc.lower()

        if visible_domain and href_domain and visible_domain != href_domain:
            mismatches.append((visible, href))

    return mismatches
