"""Content rules — pattern-match the persuasion tactics in the body text.

Each rule matches against the NORMALIZED, merged body (``email.body_norm`` /
``body_full`` via ``evidence_from_raw``) so evasions — zero-width splits,
homoglyphs, full-width forms, HTML-entity encoding, bidi wrapping — collapse to
their intent before matching. The evidence quoted in every Finding is still the
attacker's real text, never the folded skeleton.
"""
from __future__ import annotations

from . import rule
from ..models import Category, Finding, ParsedEmail, Severity
from ..normalize import evidence_from_raw


@rule
def credential_request(email: ParsedEmail):
    hit = evidence_from_raw(email.body_full, [
        r"\b(your )?(account )?password\b", r"\btwo[- ]?factor\b", r"\b2fa\b",
        r"\blog ?in (to|with) your\b", r"\bverify your (account|channel|identity)\b",
    ])
    if hit:
        return Finding(
            id="content.credential_request",
            category=Category.CONTENT, points=30, severity=Severity.HIGH,
            evidence=hit,
            explanation="Asks for credentials or 2FA. No legitimate brand ever needs these.",
            remediation="Never share passwords or 2FA codes. This alone marks the message hostile.",
        )
    return None


@rule
def upfront_fee(email: ParsedEmail):
    hit = evidence_from_raw(email.body_full, [
        r"\b(upfront|advance|shipping|handling)\s+fee\b",
        r"\b(tax|verification|processing)\s+(fee|deposit)\b",
        r"\brefundable deposit\b",
    ])
    if hit:
        return Finding(
            id="content.upfront_fee",
            category=Category.CONTENT, points=20, severity=Severity.HIGH,
            evidence=hit,
            explanation="Requests an upfront payment — a classic advance-fee scam structure.",
            remediation="Brands pay creators, not the other way around. Do not pay anything.",
        )
    return None


@rule
def gift_card_or_crypto(email: ParsedEmail):
    hit = evidence_from_raw(email.body_full, [
        r"\bgift ?card(s)?\b", r"\b(bitcoin|btc|ethereum|eth|usdt|crypto(currency)?)\b",
    ])
    if hit:
        return Finding(
            id="content.gift_card_crypto",
            category=Category.CONTENT, points=15, severity=Severity.MEDIUM,
            evidence=hit,
            explanation="Mentions irreversible, untraceable payment rails.",
            remediation="Legitimate deals don't run on gift cards or crypto transfers.",
        )
    return None


@rule
def brief_download_pretext(email: ParsedEmail):
    hit = evidence_from_raw(email.body_full, [
        r"\b(download|open|extract).{0,30}(creative )?brief\b",
        r"\b(download|open|extract).{0,30}(game )?(demo|build)\b",
        r"\bpassword to (the|open) (the )?(file|archive|zip)\b",
    ])
    if hit:
        return Finding(
            id="content.brief_download_pretext",
            category=Category.CONTENT, points=12, severity=Severity.MEDIUM,
            evidence=hit.strip(),
            explanation="Pretext to get you to open an attachment — usual malware-delivery framing.",
            remediation="Ask for the brief as plain text or a linked doc from the brand's own domain.",
        )
    return None


@rule
def urgency_pressure(email: ParsedEmail):
    hit = evidence_from_raw(email.body_full, [
        r"\b(within|in) \d+ (hours|hrs|days)\b", r"\b(urgent|act now|immediately|expires? (today|soon))\b",
        r"\blimited (time|slots?)\b",
    ])
    if hit:
        return Finding(
            id="content.urgency",
            category=Category.CONTENT, points=8, severity=Severity.LOW,
            evidence=hit,
            explanation="Artificial time pressure to rush you past scrutiny.",
            remediation="Slow down — real deals survive a day of verification.",
        )
    return None


@rule
def text_html_mismatch(email: ParsedEmail):
    """Plain-text and HTML parts carry meaningfully different content.

    A benign ``text/plain`` beside a malicious ``text/html`` is a known way to
    show a scanner the clean part while the victim's client renders the other.
    This is a SOFT signal — legitimate multipart mail diverges too (a plain
    'view in browser' stub beside a rich HTML body) — so it is deliberately
    low-weight, matching the other soft content signals, and the merged-body
    matching above already catches whatever payload the HTML actually carried.
    """
    if not email.text_html_mismatch:
        return None
    return Finding(
        id="content.text_html_mismatch",
        category=Category.CONTENT, points=8, severity=Severity.LOW,
        evidence="plain-text and HTML parts differ substantially",
        explanation="The message shows different content in its plain-text and HTML parts — "
                    "a trick used to hide the real payload from automated scanners.",
        remediation="Read the message as your mail client renders it, and weigh this with the other signals.",
    )
