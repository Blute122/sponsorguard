"""Optional, network-dependent enrichment pass.

Deliberately kept OUT of the pure `@rule` registry: `run_rules` stays
synchronous, pure and offline, and everything that calls it (the API, the
existing rule tests) is unaffected. `analyze(..., enrich=True)` opts in to this
pass, which appends any enrichment findings to the pure ones before scoring.

The single signal today is sender-domain age via RDAP. A lookup that returns
None — timeout, network error, non-200, a TLD that omits the registration date,
an unparseable date — yields NO finding, so a message whose age we cannot
determine scores exactly as it would without the network.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Optional

from ..domains import registrable_domain
from ..models import Category, Finding, ParsedEmail, Severity
from .rdap import lookup_creation_date

__all__ = ["domain_age_finding", "enrich_findings", "lookup_creation_date"]

# Age bands (see the spec): younger than NEW -> high, up to YOUNG -> medium.
_NEW_DAYS = 30
_YOUNG_DAYS = 90

LookupFn = Callable[[str], Optional[datetime]]


def domain_age_finding(
    email: ParsedEmail,
    *,
    lookup: Optional[LookupFn] = None,
    now: Optional[datetime] = None,
) -> Optional[Finding]:
    """Age the sender's registrable domain via RDAP and return a Finding or None.

    `lookup` and `now` are injectable so tests never touch the real network or
    wall clock. `lookup` defaults to the live RDAP call, resolved at call time so
    a monkeypatch of this module's `lookup_creation_date` takes effect.
    """
    if lookup is None:
        lookup = lookup_creation_date

    reg = registrable_domain(email.from_domain)
    if not reg:
        return None

    created = lookup(reg)
    if created is None:
        return None  # unknown age -> neutral; never penalize what we can't verify

    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    age_days = (now - created).days
    if age_days < 0:
        age_days = 0  # registration "in the future" (clock skew) -> treat as new

    if age_days < _NEW_DAYS:
        points, severity = 25, Severity.HIGH
    elif age_days <= _YOUNG_DAYS:
        points, severity = 12, Severity.MEDIUM
    else:
        return None  # established domain -> no finding

    return Finding(
        id="identity.domain_age",
        category=Category.IDENTITY,
        points=points,
        severity=severity,
        evidence=f"{reg} registered {created.date().isoformat()} ({age_days} days ago)",
        explanation="Recently registered domains are a common hallmark of scam campaigns, "
        "which spin up fresh lookalike domains shortly before a blast.",
        remediation="Treat a brand-new sender domain with suspicion; verify the brand "
        "through a channel you already trust.",
    )


def enrich_findings(
    email: ParsedEmail,
    *,
    lookup: Optional[LookupFn] = None,
    now: Optional[datetime] = None,
) -> list[Finding]:
    """The enrichment pass: zero or more findings to append before scoring."""
    finding = domain_age_finding(email, lookup=lookup, now=now)
    return [finding] if finding else []
