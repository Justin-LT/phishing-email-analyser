# Phishing Email Analyser

A small command line tool that takes a raw email (`.eml` file) and checks it
for the usual phishing tells: failed authentication, mismatched sender
addresses, suspicious links, and urgent or credential-harvesting language.
It gives each finding a weight and turns the total into a Low, Medium or
High risk score.

This started as a way to put some structure around the phishing awareness
training I run at work, rather than relying on "does this look dodgy" gut
feel alone.

## What it actually checks

**Authentication**
Reads the `Authentication-Results` header the receiving mail server already
left behind, rather than redoing SPF/DKIM/DMARC lookups from scratch (the
receiving server has context we don't, like the connecting IP). Also
compares the visible `From` address against `Return-Path`, since a mismatch
there is a classic spoofing sign that isn't always caught upstream.

**Links**
Pulls every URL out of the plain text and HTML body and flags:
- links to a raw IP address instead of a domain
- known URL shorteners (the real destination is hidden)
- punycode domains (a common way to fake a lookalike domain)
- link text that shows one domain but points somewhere else entirely

**Wording**
Flags urgency phrases ("act now", "account will be closed"), generic
greetings ("Dear Valued Customer"), and requests for sensitive information
or a personal phone number. None of these prove anything on their own,
they only add real weight in combination with the technical checks above.

**Impersonation**
This is the one that catches what authentication and reputation checks
genuinely cannot. A message can pass SPF, DKIM and DMARC perfectly and
still be a scam, if it was sent through a real, unspoofed Gmail account
that simply isn't the person it claims to be. That's the mechanism behind
most CEO fraud and business email compromise: pick a trusted name, send
from a disposable free-mail account, keep the first message low-key
("what's your mobile number?"), then move to a channel with no filtering
at all before asking for something urgent.

Two checks aim at this specifically:
- **No setup required:** flags a display name that reads as a real
  person's full name, sent from a well-known free consumer provider
  (Gmail, Yahoo, Outlook.com, and similar). Weak on its own, plenty of
  genuine contacts use Gmail, but it needs nothing configured and catches
  the general shape of the attempt.
- **Known contacts (optional, and much stronger):** save a colleague's
  name against the domain they actually send from. If a display name
  matches a saved contact but the sending domain doesn't, that's about as
  clear a signal as this kind of tool can give, someone is using a real
  name that isn't theirs to use. Manage this list from the GUI's "Known
  contacts" section, or edit `~/.phishing_analyser/contacts.json` directly
  (a simple `{"name": "expected-domain.com"}` mapping).

## Optional: VirusTotal reputation checks

Heuristics catch the obvious tricks, a raw IP address, a mismatched link,
punycode. They won't catch a domain that looks completely ordinary but has
already been flagged by security vendors elsewhere. Set an environment
variable and the tool will check each link against VirusTotal on top of
the heuristics:

```bash
export VT_API_KEY="your-key-here"
```

Get a free key at https://www.virustotal.com/gui/join-us. Without a key
set, the tool runs exactly as before and says so in the output, it never
fails or hangs waiting for a key that isn't there.

Two things worth knowing before you lean on this:
- The free tier allows 4 requests a minute, so an email with several links
  takes a bit longer to check, each one is checked in turn rather than all
  at once.
- Submitting a URL to VirusTotal isn't private. Other analysts using the
  platform can see what's been submitted, which matters if a link carries
  a tracking token or points somewhere sensitive. Fine for the generic
  phishing links this tool is aimed at, worth pausing on for anything more
  sensitive than that.

The GUI's "quick check" mode never calls VirusTotal at all, regardless of
whether a key is saved, so you always know which mode you're getting.

## Setup

Requires Python 3.9 or later. No external packages, everything here uses
the standard library, including the graphical interface (`tkinter`, which
is bundled with Python on Windows and Mac).

```bash
git clone https://github.com/<your-username>/phishing-email-analyser.git
cd phishing-email-analyser
python3 cli.py samples/phishing_sample.eml
```

## Graphical interface

For anyone who'd rather not use a terminal, `gui.py` gives you the same
checks in a window: pick a `.eml` file, choose quick (offline) or full
(adds a VirusTotal lookup) checking, and see the result with a coloured
risk banner.

```bash
python3 gui.py
```

The VirusTotal key can be typed into the window and saved for next time,
rather than needing an environment variable, which is stored locally by
`analyser/api_key_store.py` and is never bundled into the repository or
sent anywhere except VirusTotal itself. On Linux, if the window fails to
open with a message about `tkinter` not being found, install it with
`sudo apt install python3-tk` (Windows and Mac installers include it
already).

## Usage (command line)

```bash
python3 cli.py path/to/email.eml
```

To also write an HTML report:

```bash
python3 cli.py path/to/email.eml --html report.html
```

### Getting a .eml file to test with

Most mail clients let you export a single email as `.eml`:
- **Gmail**: open the email, click the three-dot menu, "Show original", then
  "Download original"
- **Outlook**: drag the email out of the message list onto your desktop
- Or use one of the two sample files included in `samples/`

## Example output

Running against the included samples gives three different pictures worth
comparing. The phishing sample fails authentication outright:

```
============================================================
Phishing Email Analyser
============================================================
Subject : Urgent: Unusual activity detected on your account
From    : Northfield Bank Security <security@northfield-bank-alerts.com>
Risk    : High (100/100)
------------------------------------------------------------
  [+25] SPF check failed
  [+25] DKIM check failed
  [+25] link text "www.northfieldbank.example/secure-login" does not match its destination (http://185.203.14.77/secure-login)
  [+20] DMARC check failed
  [+15] From address domain does not match the Return-Path domain
  [+15] Reply-To address is on a different domain to the From address
  [+15] http://185.203.14.77/secure-login links to a raw IP address instead of a domain name
  [+ 8] urgency language: "act now"
  [+ 8] urgency language: "confirm your identity"
  [+ 8] urgency language: "unusual activity"
  [+ 8] urgency language: "click here immediately"
  [+ 5] generic greeting: "dear valued customer"
============================================================
```

The impersonation sample passes authentication cleanly, it really was sent
through Gmail, and has no links to check at all. Without any setup, it
still gets flagged on the identity mismatch alone:

```
Subject : Quick update
From    : Alex Morgan <randomname12345@gmail.com>
Risk    : Medium (21/100)
------------------------------------------------------------
  [+15] display name "Alex Morgan" reads as a personal name, sent from a free email address (randomname12345@gmail.com)
  [+ 6] asks for a personal contact number: "phone number"
```

Save "Alex Morgan" against her real domain as a known contact, and the
same email jumps straight to High:

```
Risk    : High (56/100)
------------------------------------------------------------
  [+50] claims to be "Alex Morgan" but doesn't come from their known domain (gmail.com instead of example-corp.co.uk)
  [+ 6] asks for a personal contact number: "phone number"
```

The legitimate sample gets a Low score with no findings, so the tool
isn't just flagging everything.

## Project structure

```
phishing-email-analyser/
├── cli.py                  command line entry point
├── gui.py                  desktop GUI entry point
├── analyser/
│   ├── parser.py           loads a .eml file and gets at its body
│   ├── auth.py              SPF/DKIM/DMARC and sender alignment checks
│   ├── urls.py              link extraction and red-flag checks
│   ├── language.py          wording checks
│   ├── reputation.py        optional VirusTotal lookups
│   ├── impersonation.py     display-name / identity impersonation checks
│   ├── contacts.py          saves known contacts locally for the GUI
│   ├── api_key_store.py     saves the VirusTotal key locally for the GUI
│   ├── scoring.py           combines everything into one risk score
│   └── report.py            console and HTML output
└── samples/
    ├── phishing_sample.eml
    ├── legitimate_sample.eml
    └── impersonation_sample.eml
```

## A decision worth explaining

The scoring weights aren't derived from any formal model, they're a
judgement call: authentication failures and disguised links carry the most
weight because they're the hardest things for a scammer to fake
convincingly, while wording issues carry the least because urgent language
alone is cheap to write and appears in plenty of genuine marketing email
too. If you run this against your own inbox and it feels too trigger-happy
or too lax, `AUTH_WEIGHTS` in `analyser/scoring.py` is the place to adjust
it.

## Limitations

- A Low score means nothing here tripped an automated rule, not that the
  email is definitely safe. Well-resourced attackers can pass SPF/DKIM/
  DMARC, avoid links entirely, and still be running a scam, that's exactly
  what the impersonation sample demonstrates.
- Authentication passing tells you the transport is legitimate, nothing
  about whether the claimed identity is real. Treat the two as separate
  questions, because they are.
- The known-contacts check is only as good as the list you keep. It won't
  catch someone it's never heard of, and a contact saved against the
  wrong domain will happily wave through the real impersonation.
- The wording lists are a starting point, not a complete list. Real
  phishing and BEC campaigns constantly vary their language.

## Licence

MIT, see `LICENSE`.
