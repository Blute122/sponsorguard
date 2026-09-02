"""Domain-handling helpers used by several rule modules.

Deliberately stdlib-only. The registrable-domain logic here is a pragmatic
approximation using a small multi-label suffix set, NOT the full Public Suffix
List. That is fine for a skeleton and for the common sponsor brands, but swap in
`tldextract` before you trust this on arbitrary ccTLDs.
"""
from __future__ import annotations

# Common free webmail providers. A brand claiming to be itself never sends from these.
FREEMAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "yahoo.co.uk", "proton.me", "protonmail.com", "icloud.com",
    "aol.com", "gmx.com", "mail.com", "zoho.com", "yandex.com",
}

# A tiny slice of multi-label public suffixes. Extend or replace with tldextract.
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.in", "co.jp", "com.au",
    "com.br", "co.nz", "com.sg", "co.za",
}


def domain_of(address: str) -> str:
    """Extract the bare host from an email address or raw domain."""
    address = (address or "").strip().lower()
    if "@" in address:
        address = address.rsplit("@", 1)[1]
    return address.strip("<>. ")


def registrable_domain(host: str) -> str:
    """Best-effort eTLD+1. `mail.nord-vpn.co.uk` -> `nord-vpn.co.uk`."""
    host = domain_of(host)
    if not host:
        return ""
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    last_three = ".".join(labels[-3:])
    if last_two in _MULTI_LABEL_SUFFIXES:
        return last_three
    return last_two


def is_punycode(host: str) -> bool:
    """True if any label is IDNA/punycode encoded (`xn--`)."""
    return any(label.startswith("xn--") for label in domain_of(host).split("."))


# Common character swaps used in lookalike domains.
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})


def normalize_homoglyphs(label: str) -> str:
    """Fold digit/symbol lookalikes back to letters: `n0rdvpn` -> `nordvpn`."""
    return label.lower().translate(_HOMOGLYPHS)


def levenshtein(a: str, b: str) -> int:
    """Classic edit distance. Small inputs, so the simple DP is plenty."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]
