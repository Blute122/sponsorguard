"""Link rules — where the message actually wants you to go."""
from __future__ import annotations

from . import rule
from ..brands import load_brands
from ..domains import is_punycode, registrable_domain
from ..models import Category, Finding, ParsedEmail, Severity
from ..normalize import host_skeleton

_CRED_KEYWORDS = ("login", "signin", "sign-in", "verify", "confirm", "studio", "account", "secure")


@rule
def link_text_href_mismatch(email: ParsedEmail):
    findings = []
    for link in email.links:
        if link.text_domain and link.href_domain and \
                registrable_domain(link.text_domain) != registrable_domain(link.href_domain):
            findings.append(Finding(
                id="links.text_href_mismatch",
                category=Category.LINKS,
                points=18,
                severity=Severity.HIGH,
                evidence=f'link shows {link.text_domain} but points to {link.href_domain}',
                explanation="The visible link text hides a different real destination.",
                remediation="Hover before clicking; the true destination is what matters.",
            ))
    return findings


@rule
def punycode_link(email: ParsedEmail):
    findings = []
    for link in email.links:
        if link.href_domain and is_punycode(link.href_domain):
            findings.append(Finding(
                id="links.punycode",
                category=Category.LINKS,
                points=25,
                severity=Severity.HIGH,
                evidence=link.href_domain,
                explanation="Punycode/IDN domain used to mimic a real one visually.",
                remediation="Do not open — these are used for lookalike credential-harvest pages.",
            ))
    return findings


@rule
def brand_in_subdomain_only(email: ParsedEmail):
    findings = []
    for link in email.links:
        reg = registrable_domain(link.href_domain)
        if not reg:
            continue
        # Fold confusables so a homoglyph brand token in the host still matches;
        # evidence below quotes the real host and registrable domain.
        host_sk = host_skeleton(link.href_domain)
        reg_sk = host_skeleton(reg)
        for brand in load_brands():
            token = brand.domains[0].split(".")[0] if brand.domains else brand.name.lower()
            # Brand name appears in the host but NOT as the registrable domain.
            if token in host_sk and token not in reg_sk:
                findings.append(Finding(
                    id="links.brand_in_subdomain",
                    category=Category.LINKS,
                    points=20,
                    severity=Severity.HIGH,
                    evidence=f"{link.href_domain} (registrable: {reg})",
                    explanation=f"'{brand.name}' appears only in the subdomain/path; the real owner is {reg}.",
                    remediation="The registrable domain is the real owner — this is not the brand's site.",
                ))
                break
    return findings


@rule
def credential_portal_keywords(email: ParsedEmail):
    for link in email.links:
        low = link.href.lower()
        hit = next((kw for kw in _CRED_KEYWORDS if kw in low), None)
        if hit:
            return Finding(
                id="links.credential_keywords",
                category=Category.LINKS,
                points=15,
                severity=Severity.MEDIUM,
                evidence=f'"{hit}" in {link.href_domain}',
                explanation="URL points at a login/verification portal — common credential-harvest pattern.",
                remediation="Never enter account credentials via an emailed link.",
            )
    return None
