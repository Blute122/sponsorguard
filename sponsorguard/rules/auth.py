"""Auth rules.

We PARSE the receiving server's Authentication-Results header rather than
re-evaluating SPF/DKIM/DMARC ourselves — the provider already did the crypto,
and DKIM in particular breaks the moment an email is copy-pasted. If the header
is absent (a body-only paste, or a forward), we mark auth 'unavailable' and emit
NOTHING rather than falsely passing the checks.
"""
from __future__ import annotations

import re

from . import rule
from ..models import Category, Finding, ParsedEmail, Severity


def _result(header: str, mechanism: str) -> str | None:
    m = re.search(rf"\b{mechanism}=(\w+)", header, re.IGNORECASE)
    return m.group(1).lower() if m else None


@rule
def spf_fail(email: ParsedEmail):
    if not email.auth_results:
        return None
    res = _result(email.auth_results, "spf")
    if res in {"fail", "softfail"}:
        return Finding(
            id="auth.spf_fail",
            category=Category.AUTH,
            points=20,
            severity=Severity.HIGH,
            evidence=f"spf={res}",
            explanation="The sending server is not authorized to send for the From domain.",
            remediation="Treat the sender address as unverified; do not trust the claimed identity.",
        )
    return None


@rule
def dmarc_fail(email: ParsedEmail):
    if not email.auth_results:
        return None
    res = _result(email.auth_results, "dmarc")
    if res == "fail":
        return Finding(
            id="auth.dmarc_fail",
            category=Category.AUTH,
            points=18,
            severity=Severity.HIGH,
            evidence="dmarc=fail",
            explanation="The message fails the From domain's own DMARC alignment policy.",
            remediation="Strong signal of spoofing — verify the sender through an official channel.",
        )
    if res == "none":
        return Finding(
            id="auth.dmarc_none",
            category=Category.AUTH,
            points=5,
            severity=Severity.LOW,
            evidence="dmarc=none",
            explanation="Domain publishes no enforcing DMARC policy. Common for small brands, so weak alone.",
            remediation="Not conclusive; weigh alongside other signals.",
        )
    return None


@rule
def dkim_fail(email: ParsedEmail):
    if not email.auth_results:
        return None
    res = _result(email.auth_results, "dkim")
    if res == "fail":
        return Finding(
            id="auth.dkim_fail",
            category=Category.AUTH,
            points=12,
            severity=Severity.MEDIUM,
            evidence="dkim=fail",
            explanation="A DKIM signature was present but invalid — content may be altered or forged.",
            remediation="Do not rely on the message contents being authentic.",
        )
    return None
