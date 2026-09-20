"""Identity rules — who the message claims to be from vs. where it actually came from."""
from __future__ import annotations

from . import rule
from ..brands import load_brands
from ..domains import FREEMAIL, levenshtein, normalize_homoglyphs, registrable_domain
from ..models import Category, Finding, ParsedEmail, Severity
from ..normalize import host_skeleton, normalize


def _mentions_brand(text: str):
    """Return the first Brand whose alias appears in the text, else None.

    Matches on the NORMALIZED view so a homoglyph brand name (``Аudible`` with a
    Cyrillic А) or a full-width/zero-width variant still resolves to the brand.
    """
    low = normalize(text)
    for brand in load_brands():
        if any(alias in low for alias in brand.aliases):
            return brand
    return None


@rule
def freemail_claiming_brand(email: ParsedEmail):
    if email.from_domain not in FREEMAIL:
        return None
    brand = _mentions_brand(f"{email.display_name} {email.subject} {email.body_full}")
    if brand:
        return Finding(
            id="identity.freemail_brand",
            category=Category.IDENTITY,
            points=25,
            severity=Severity.HIGH,
            evidence=f"from {email.from_domain} while claiming to be {brand.name}",
            explanation="Real brands send from their own domain, never a free webmail account.",
            remediation=f"Verify by contacting {brand.name} through their official website.",
        )
    return None


@rule
def display_name_impersonation(email: ParsedEmail):
    brand = _mentions_brand(email.display_name)
    if not brand:
        return None
    from_reg = registrable_domain(email.from_domain)
    if from_reg and from_reg not in brand.domains:
        return Finding(
            id="identity.display_name_impersonation",
            category=Category.IDENTITY,
            points=30,
            severity=Severity.HIGH,
            evidence=f'display name "{email.display_name}" but domain {from_reg}',
            explanation=f"The display name claims {brand.name}, but the domain is not one of theirs.",
            remediation="Classic impersonation — do not act on this without out-of-band confirmation.",
        )
    return None


@rule
def typosquat_domain(email: ParsedEmail):
    from_reg = registrable_domain(email.from_domain)
    if not from_reg:
        return None
    for brand in load_brands():
        for legit in brand.domains:
            if from_reg == legit:
                return None  # exact match, definitely fine
            # Edit-distance lookalike (n0rdvpn.com), or brand token embedded in a
            # longer hyphenated domain (nord-vpn-press.com).
            legit_label = legit.split(".")[0]
            from_label = from_reg.split(".")[0]
            # Fold both Unicode confusables (Cyrillic/Greek lookalikes) and the
            # digit swaps (n0rdvpn -> nordvpn) before comparing, so neither a
            # homoglyph nor a digit-swap can slip past. Evidence below still
            # quotes the real registrable domain.
            norm_label = normalize_homoglyphs(host_skeleton(from_label))
            norm_compact = norm_label.replace("-", "")
            dist = levenshtein(norm_label, legit_label)
            embedded = legit_label in norm_compact and from_reg != legit
            if 0 < dist <= 2 or embedded:
                return Finding(
                    id="identity.typosquat",
                    category=Category.IDENTITY,
                    points=30,
                    severity=Severity.HIGH,
                    evidence=f"{from_reg} resembles {legit}",
                    explanation=f"Sender domain is a lookalike of {brand.name}'s real domain.",
                    remediation="Lookalike domains are a hallmark of phishing — do not trust it.",
                )
    return None


@rule
def reply_to_mismatch(email: ParsedEmail):
    if not email.reply_to_domain or not email.from_domain:
        return None
    if registrable_domain(email.reply_to_domain) != registrable_domain(email.from_domain):
        return Finding(
            id="identity.reply_to_mismatch",
            category=Category.IDENTITY,
            points=10,
            severity=Severity.LOW,
            evidence=f"From {email.from_domain}, Reply-To {email.reply_to_domain}",
            explanation="Replies would go to a different domain than the sender. Sometimes legit (agencies), often not.",
            remediation="Check where a reply would actually go before responding.",
        )
    return None
