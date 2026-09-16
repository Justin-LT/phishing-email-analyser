# How the checks work

This goes into more depth than the main README on what each check does,
why it's built the way it is, and where it falls short. Worth reading if
you're deciding whether to trust this on real email, tuning the scoring,
or just curious.

## Authentication

Reads the `Authentication-Results` header the receiving mail server
already left behind, rather than redoing SPF/DKIM/DMARC lookups from
scratch. The receiving server has context this tool doesn't, the
connecting IP, the actual signing key, so there's no reason to repeat
that work worse. This is the same approach most mail clients use to show
their own "this looks suspicious" banners.

Also compares the visible `From` address against `Return-Path`, since a
mismatch there is a classic spoofing sign that isn't always caught
upstream.

**Where this falls short:** authentication passing only tells you the
transport is legitimate. It says nothing about whether the person named
in the email is who they claim to be, see Impersonation below.

## Links

Pulls every URL out of the plain text and HTML body and flags:
- links to a raw IP address instead of a domain
- known URL shorteners (the real destination is hidden)
- punycode domains (a common way to fake a lookalike domain)
- link text that shows one domain but points somewhere else entirely

## Wording

Flags urgency phrases ("act now", "account will be closed"), generic
greetings ("Dear Valued Customer"), and requests for sensitive
information or a personal phone number. None of these prove anything on
their own, plenty of genuine marketing email is urgent and plenty of
genuine colleagues ask for a phone number. They only add real weight in
combination with the technical checks.

## Impersonation

This is the one that catches what authentication and reputation checks
genuinely cannot. A message can pass SPF, DKIM and DMARC perfectly and
still be a scam, if it was sent through a real, unspoofed Gmail account
that simply isn't the person it claims to be. That's the mechanism behind
most CEO fraud and business email compromise: pick a trusted name, send
from a disposable free-mail account, keep the first message low-key
("what's your mobile number?"), then move to a channel with no filtering
at all before asking for something urgent.

Two checks aim at this specifically:

- **No setup required.** Flags a display name that reads as a real
  person's full name, sent from a well-known free consumer provider
  (Gmail, Yahoo, Outlook.com, and similar). Weak on its own, plenty of
  genuine contacts use Gmail, but it needs nothing configured and catches
  the general shape of the attempt.
- **Known contacts, optional and much stronger.** Save a colleague's name
  against the domain they actually send from. If a display name matches
  a saved contact but the sending domain doesn't, that's about as clear a
  signal as this kind of tool can give, someone is using a real name
  that isn't theirs to use. Manage this from the GUI's "Known contacts"
  section, or edit `~/.phishing_analyser/contacts.json` directly (a
  simple `{"name": "expected-domain.com"}` mapping).

## Optional: VirusTotal reputation checks

Heuristics catch the obvious tricks, a raw IP address, a mismatched
link, punycode. They won't catch a domain that looks completely ordinary
but has already been flagged by security vendors elsewhere. Set an
environment variable, or save the key in the GUI, and the tool checks
each link against VirusTotal on top of the heuristics.

```bash
export VT_API_KEY="your-key-here"
```

Get a free key at virustotal.com/gui/join-us. Without a key, the tool
runs exactly as before and says so in the output, it never fails or
hangs waiting for a key that isn't there.

Two things worth knowing before you lean on this:
- The free tier allows 4 requests a minute, so an email with several
  links takes a bit longer to check, each one in turn rather than all at
  once.
- Submitting a URL to VirusTotal isn't private. Other analysts using the
  platform can see what's been submitted, which matters if a link
  carries a tracking token or points somewhere sensitive.

The GUI's "quick check" mode never calls VirusTotal at all, regardless
of whether a key is saved, so you always know which mode you're getting.

## Why the weights are what they are

Not derived from a formal model, this is a judgement call: authentication
failures and disguised links carry the most weight because they're the
hardest things for a scammer to fake convincingly. Wording issues carry
the least because urgent language alone is cheap to write. A confirmed
known-contact mismatch carries more than any single link flag, because
"this specific person doesn't send from here" is about as certain a
signal as the tool can produce.

If you run this against your own inbox and it feels too trigger-happy or
too lax, `AUTH_WEIGHTS` and the weights inline in `analyser/scoring.py`
are the place to adjust it.

## Limitations

- A Low score means nothing here tripped an automated rule, not that the
  email is definitely safe. Well-resourced attackers can pass SPF/DKIM/
  DMARC, avoid links entirely, and still be running a scam, that's
  exactly what the impersonation sample demonstrates.
- Authentication passing tells you the transport is legitimate, nothing
  about whether the claimed identity is real. Treat the two as separate
  questions, because they are.
- The known-contacts check is only as good as the list you keep. It
  won't catch someone it's never heard of, and a contact saved against
  the wrong domain will happily wave through the real impersonation.
- The wording lists are a starting point, not a complete list. Real
  phishing and BEC campaigns constantly vary their language.
