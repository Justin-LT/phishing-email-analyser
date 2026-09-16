"""Combines every check into one risk score.

The weights below are a judgement call, not a formula pulled from a paper.
They're set so that authentication failures and disguised links (the two
hardest things to fake convincingly) carry the most weight, and wording
issues (the easiest thing to fake) carry the least. Tune them if you find
this too trigger-happy, or too lax, once you've run it against your own
sample emails.
"""

from . import auth, urls, language, reputation, impersonation, contacts

AUTH_WEIGHTS = {
    "spf": {"fail": 25, "none": 10},
    "dkim": {"fail": 25, "none": 10},
    "dmarc": {"fail": 20, "none": 8},
}


def run_checks(msg, text_body, html_body, use_reputation=True):
    findings = []  # list of (description, weight)

    auth_results = auth.parse_authentication_results(msg)
    for mechanism, weights in AUTH_WEIGHTS.items():
        result = auth_results.get(mechanism)
        if result in ("fail", "softfail"):
            findings.append((f"{mechanism.upper()} check failed", weights["fail"]))
        elif result in ("none", "neutral"):
            findings.append((f"no {mechanism.upper()} result present", weights["none"]))

    if auth.check_sender_alignment(msg):
        findings.append(("From address domain does not match the Return-Path domain", 15))

    if language.check_reply_to_mismatch(msg):
        findings.append(("Reply-To address is on a different domain to the From address", 15))

    known_contacts = contacts.load_contacts()
    mismatch = impersonation.check_known_contact_mismatch(msg, known_contacts)
    if mismatch:
        findings.append((mismatch, 50))
    else:
        freemail_flag = impersonation.check_freemail_personal_name(msg)
        if freemail_flag:
            findings.append((freemail_flag, 15))

    body_for_text_checks = text_body or html_body

    for url in urls.extract_urls(text_body, html_body):
        for flag in urls.assess_url(url):
            findings.append((f"{url} {flag}", 15))

        if use_reputation:
            reputation_flag = reputation.check_url(url)
            if reputation_flag:
                findings.append((f"{url} {reputation_flag}", 35))

    for visible, href in urls.find_mismatched_anchors(html_body):
        findings.append((f'link text "{visible}" does not match its destination ({href})', 25))

    for phrase in language.check_phrases(body_for_text_checks, language.URGENCY_PHRASES):
        findings.append((f'urgency language: "{phrase}"', 8))

    for phrase in language.check_phrases(body_for_text_checks, language.GENERIC_GREETINGS):
        findings.append((f'generic greeting: "{phrase}"', 5))

    for phrase in language.check_phrases(body_for_text_checks, language.SENSITIVE_REQUESTS):
        findings.append((f'asks for sensitive information: "{phrase}"', 12))

    for phrase in language.check_phrases(body_for_text_checks, language.CONTACT_INFO_REQUESTS):
        findings.append((f'asks for a personal contact number: "{phrase}"', 6))

    score = min(sum(weight for _, weight in findings), 100)
    return findings, score


def risk_category(score):
    if score >= 50:
        return "High"
    if score >= 20:
        return "Medium"
    return "Low"
