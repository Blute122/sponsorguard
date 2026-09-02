"""Fixture + unit tests. The .eml fixtures double as demo material for the UI."""
from __future__ import annotations

from pathlib import Path

import pytest

from sponsorguard.models import Verdict
from sponsorguard.parser import parse_email
from sponsorguard.rules import run_rules
from sponsorguard.scoring import analyze, score_findings

FIX = Path(__file__).parent / "fixtures"


def _finding_ids(email_path: Path) -> set[str]:
    return {f.id for f in run_rules(parse_email(email_path.read_bytes()))}


# ---- End-to-end verdicts ----

def test_scam_email_is_dangerous():
    report = analyze((FIX / "scam_nordvpn.eml").read_bytes())
    assert report.verdict == Verdict.DANGEROUS
    assert report.score >= 60
    assert report.safe_next_step


def test_legit_email_is_low():
    report = analyze((FIX / "legit_brand.eml").read_bytes())
    assert report.verdict == Verdict.LOW
    assert report.score < 15


# ---- The scam fixture should trip a specific cross-section of rules ----

@pytest.mark.parametrize("rule_id", [
    "auth.spf_fail",
    "auth.dmarc_fail",
    "identity.typosquat",
    "identity.reply_to_mismatch",
    "links.brand_in_subdomain",
    "links.credential_keywords",
    "attach.password_protected_archive",
    "content.credential_request",
    "content.upfront_fee",
    "content.brief_download_pretext",
    "content.urgency",
])
def test_scam_trips_rule(rule_id):
    assert rule_id in _finding_ids(FIX / "scam_nordvpn.eml")


def test_legit_trips_nothing():
    assert _finding_ids(FIX / "legit_brand.eml") == set()


# ---- Scoring guardrails ----

def test_hard_flag_forces_dangerous_even_when_total_is_low():
    from sponsorguard.models import Category, Finding, Severity
    tiny = Finding(
        id="attach.executable", category=Category.ATTACH, points=1,
        evidence="x.exe", explanation="", remediation="",
        severity=Severity.HIGH, hard_flag=True,
    )
    report = score_findings([tiny])
    assert report.verdict == Verdict.DANGEROUS


def test_category_cap_limits_one_noisy_dimension():
    from sponsorguard.models import Category, Finding
    many = [
        Finding(id=f"links.x{i}", category=Category.LINKS, points=18,
                evidence="", explanation="", remediation="")
        for i in range(10)  # 180 raw points in one category
    ]
    report = score_findings(many)
    assert report.score == 40  # LINKS cap, not 100
