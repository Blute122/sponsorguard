"""Content rules — pattern-match the persuasion tactics in the body text."""
from __future__ import annotations

import re

from . import rule
from ..models import Category, Finding, ParsedEmail, Severity


def _first_match(text: str, patterns: list[str]) -> str | None:
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(0)
    return None


@rule
def credential_request(email: ParsedEmail):
    hit = _first_match(email.body_text, [
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
    hit = _first_match(email.body_text, [
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
    hit = _first_match(email.body_text, [
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
    hit = _first_match(email.body_text, [
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
    hit = _first_match(email.body_text, [
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
