"""RDAP domain-age lookup — the project's only network call, fully isolated.

`lookup_creation_date(domain)` returns the domain's registration datetime, or
None. It returns None for *every* failure mode — timeout, network error,
non-200, missing/!registration events, unparseable date — so a caller can treat
"unknown" and "could not reach the network" identically: no finding, no penalty.

Stdlib only (urllib). The core detection engine must never depend on this being
reachable.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Optional

# rdap.org is an aggregator that 302-redirects to the authoritative registry's
# RDAP server; urllib follows the redirect automatically.
RDAP_ENDPOINT = "https://rdap.org/domain/{domain}"

# A few seconds: enough for a healthy registry, short enough not to hang a scan.
DEFAULT_TIMEOUT = 4.0

# Guard against a hostile/broken server streaming an unbounded body.
_MAX_BYTES = 1_000_000

_HEADERS = {
    "User-Agent": "SponsorGuard/0.1 (domain-age enrichment)",
    "Accept": "application/rdap+json, application/json",
}


def lookup_creation_date(domain: str, *, timeout: float = DEFAULT_TIMEOUT) -> Optional[datetime]:
    """Return the registration datetime for `domain`, or None on any failure.

    `domain` should be a registrable domain (eTLD+1). Never raises: every error
    path collapses to None so the caller stays offline-safe.
    """
    domain = (domain or "").strip().lower()
    if not domain:
        return None

    req = urllib.request.Request(RDAP_ENDPOINT.format(domain=domain), headers=_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if getattr(resp, "status", 200) != 200:
                return None
            raw = resp.read(_MAX_BYTES)
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        # Timeout, DNS failure, HTTPError (4xx/5xx), connection reset, invalid
        # JSON — all indistinguishable to us and all mean "age unknown".
        return None

    return _registration_date(data)


def _registration_date(data: object) -> Optional[datetime]:
    """Pull the 'registration' event's date out of an RDAP response body."""
    if not isinstance(data, dict):
        return None
    events = data.get("events")
    if not isinstance(events, list):
        return None
    for event in events:
        if isinstance(event, dict) and event.get("eventAction") == "registration":
            return _parse_date(event.get("eventDate"))
    return None


def _parse_date(value: object) -> Optional[datetime]:
    """Parse an RFC 3339 / ISO 8601 eventDate into an aware datetime, or None."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        # fromisoformat handles offsets; normalize a trailing 'Z' it won't take.
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt
