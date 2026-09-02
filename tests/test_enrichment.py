"""Domain-age rule + analyze(enrich=...) wiring. All offline (injected lookups)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import sponsorguard.enrichment as enr
from sponsorguard.enrichment import domain_age_finding, enrich_findings
from sponsorguard.models import ParsedEmail, Severity
from sponsorguard.scoring import analyze

FIX = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 9, 2, tzinfo=timezone.utc)


def _email(domain: str = "brand-new-domain.com") -> ParsedEmail:
    return ParsedEmail(from_domain=domain)


def _aged(days: int):
    """A lookup that reports the domain as registered `days` before NOW."""
    created = NOW - timedelta(days=days)
    return lambda reg: created


# ---- Age bands ----

def test_under_30_days_is_25_high():
    f = domain_age_finding(_email(), lookup=_aged(10), now=NOW)
    assert f is not None
    assert f.id == "identity.domain_age"
    assert f.points == 25
    assert f.severity == Severity.HIGH


def test_30_to_90_days_is_12_medium():
    f = domain_age_finding(_email(), lookup=_aged(60), now=NOW)
    assert f is not None
    assert f.points == 12
    assert f.severity == Severity.MEDIUM


def test_boundary_exactly_30_days_is_medium():
    # 30 is not < 30, so it lands in the 30..90 band.
    assert domain_age_finding(_email(), lookup=_aged(30), now=NOW).points == 12


def test_boundary_exactly_90_days_is_medium():
    assert domain_age_finding(_email(), lookup=_aged(90), now=NOW).points == 12


def test_over_90_days_no_finding():
    assert domain_age_finding(_email(), lookup=_aged(120), now=NOW) is None


# ---- Fail-safe / neutral cases ----

def test_unknown_age_no_finding():
    assert domain_age_finding(_email(), lookup=lambda reg: None, now=NOW) is None


def test_no_from_domain_no_finding():
    called = []
    domain_age_finding(ParsedEmail(from_domain=""), lookup=lambda reg: called.append(reg), now=NOW)
    assert called == []  # short-circuits before any lookup


def test_future_registration_clock_skew_is_treated_as_new():
    f = domain_age_finding(_email(), lookup=_aged(-5), now=NOW)
    assert f is not None and f.points == 25


# ---- enrich_findings wrapper ----

def test_enrich_findings_wraps_and_drops_none():
    hit = enrich_findings(_email(), lookup=_aged(5), now=NOW)
    assert len(hit) == 1 and hit[0].id == "identity.domain_age"
    assert enrich_findings(_email(), lookup=lambda reg: None, now=NOW) == []


# ---- analyze() wiring: disabled == unchanged, enabled == surfaced ----

def test_analyze_default_is_offline_and_omits_domain_age(monkeypatch):
    """Default analyze() must not touch the network and must not add the signal."""
    def _boom(*a, **k):
        raise AssertionError("network lookup must not run when enrichment is disabled")

    monkeypatch.setattr(enr, "lookup_creation_date", _boom)
    report = analyze((FIX / "scam_nordvpn.eml").read_bytes())  # enrich defaults False
    assert all(f["id"] != "identity.domain_age" for f in report.to_dict()["findings"])


def test_analyze_enrich_disabled_matches_default_byte_for_byte():
    for name in ("scam_nordvpn.eml", "legit_brand.eml"):
        raw = (FIX / name).read_bytes()
        assert analyze(raw, enrich=False).to_dict() == analyze(raw).to_dict()


def test_analyze_enrich_true_surfaces_finding_via_to_dict(monkeypatch):
    """With enrichment on and a stubbed recent date, the finding flows through
    report.to_dict() with no special-casing."""
    created = datetime.now(timezone.utc) - timedelta(days=3)
    monkeypatch.setattr(enr, "lookup_creation_date", lambda reg: created)

    report = analyze((FIX / "scam_nordvpn.eml").read_bytes(), enrich=True)
    findings = report.to_dict()["findings"]
    age = [f for f in findings if f["id"] == "identity.domain_age"]
    assert len(age) == 1
    assert age[0]["category"] == "identity"
    assert age[0]["points"] == 25


def test_analyze_enrich_true_with_unknown_age_is_unchanged(monkeypatch):
    """Enrichment ON but lookup returns None -> identical to enrichment OFF."""
    monkeypatch.setattr(enr, "lookup_creation_date", lambda reg: None)
    raw = (FIX / "scam_nordvpn.eml").read_bytes()
    assert analyze(raw, enrich=True).to_dict() == analyze(raw, enrich=False).to_dict()
