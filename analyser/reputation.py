"""Optional URL reputation checks via the VirusTotal API.

This is opt-in. Without an API key set, every function here does nothing
and the rest of the analysis carries on as normal, a missing key shouldn't
stop the tool working, it just means one fewer signal.

Get a free key at https://www.virustotal.com/gui/join-us. Set it as an
environment variable for the command line tool:

    export VT_API_KEY="your-key-here"

or enter and save it in the GUI, which stores it locally via
analyser/api_key_store.py. Either way, never paste it directly into this
file.

Worth knowing before you rely on this for anything real: submitting a URL
to VirusTotal isn't private, other analysts using the platform can see
what's been submitted. That matters if a link contains a tracking token
or points somewhere you'd rather not surface. Fine for the sort of generic
phishing links this tool is aimed at, worth pausing on for anything more
sensitive.
"""

import base64
import json
import os
import time
import urllib.error
import urllib.request

from . import api_key_store

BASE_URL = "https://www.virustotal.com/api/v3/urls"
MIN_INTERVAL = 15  # seconds between calls, comfortably under the free tier limit

_cache = {}
_last_call = 0.0


def get_api_key():
    """Checks the environment variable first (handy for the command line
    tool), then falls back to the key saved locally by the GUI."""
    return os.environ.get("VT_API_KEY") or api_key_store.load_key()


def is_configured():
    return bool(get_api_key())


def check_url(url):
    """Returns a plain-English flag if VirusTotal's vendors consider the URL
    malicious or suspicious. Returns None if it's clean, unknown, or the
    lookup wasn't possible for any reason, no key, rate limit, network
    error. Failing quietly here is deliberate, a lookup problem shouldn't
    take down the rest of the report."""
    api_key = get_api_key()
    if not api_key:
        return None

    if url in _cache:
        return _cache[url]

    global _last_call
    wait = MIN_INTERVAL - (time.time() - _last_call)
    if wait > 0:
        time.sleep(wait)

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    request = urllib.request.Request(f"{BASE_URL}/{url_id}", headers={"x-apikey": api_key})

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            data = json.loads(response.read())
        _last_call = time.time()
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
        _cache[url] = None
        return None

    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    flag = None
    if malicious > 0:
        flag = f"flagged as malicious by {malicious} security vendor(s) on VirusTotal"
    elif suspicious > 0:
        flag = f"flagged as suspicious by {suspicious} security vendor(s) on VirusTotal"

    _cache[url] = flag
    return flag
