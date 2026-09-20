"""Regression gate: fail the build if engine quality drops on the labeled corpus.

This runs inside the normal `pytest -q` suite. It measures the engine as-is; it
never tunes it. If a gate fails, the fix is either a genuine engine regression to
investigate or a corpus that has grown a case the engine was never good at --
figure out which before touching a weight.

Thresholds are named constants, seeded conservatively so they pass with headroom
on the small seeded corpus. RATCHET THEM UP as the corpus grows and the numbers
stabilise; that is the whole point of having them here.

Current values on the seeded 5-scam / 5-legit corpus:
    legit at Dangerous      0      (limit 0)
    precision at High risk  100%   (floor 70%)
    recall at Dangerous     80%    (floor 50%)
"""
from __future__ import annotations

import pytest

from run_eval import (
    BANDS,
    DEFAULT_CORPUS,
    HEADLINE_TIER,
    build_results,
    discover,
    evaluate,
)

# --------------------------------------------------------------- thresholds

# Below this many emails per class the corpus can't support a meaningful gate,
# so the tests skip rather than fail. A fresh clone without a corpus is fine.
MIN_CORPUS_PER_CLASS = 3

# HARD INVARIANT. A genuine sponsorship email must never be called "Dangerous".
# That error tells a creator a real paycheck is an attack; it is the one failure
# that destroys trust in the tool outright. This must stay zero.
MAX_LEGIT_AT_DANGEROUS = 0

# Of everything flagged at the High-risk boundary, how much must actually be scam.
MIN_PRECISION_AT_HIGH_RISK = 0.70

# Of all scams, how many must reach the top band. Deliberately lenient: subtle
# scams legitimately land in High risk, and a lower band still warns the user.
MIN_RECALL_AT_DANGEROUS = 0.50

_THRESHOLDS = dict(BANDS)


@pytest.fixture(scope="module")
def report():
    """Evaluate the corpus once for the whole module."""
    if not DEFAULT_CORPUS.is_dir():
        pytest.skip(f"no corpus at {DEFAULT_CORPUS}; skipping eval gate")
    samples = discover(DEFAULT_CORPUS)
    if not samples:
        pytest.skip("corpus contains no .eml files; skipping eval gate")
    evaluate(samples)
    return build_results(samples)


@pytest.fixture(scope="module")
def results(report):
    """The SPONSORSHIP tier only - the trust-critical, claim-backing set.

    phishing-general is deliberately excluded: it is bulk public mail kept as a
    regression signal, not a pass/fail bar, so it can never fail the build.
    """
    tier = report.get("tiers", {}).get(HEADLINE_TIER)
    if not tier or not tier["n"]["total"]:
        pytest.skip(f"no emails in the {HEADLINE_TIER} tier; skipping eval gate")
    return tier


def _require_corpus(results):
    n = results["n"]
    if min(n["scam"], n["legit"]) < MIN_CORPUS_PER_CLASS:
        pytest.skip(
            f"corpus too small for a meaningful gate "
            f"({n['scam']} scam / {n['legit']} legit, "
            f"need >= {MIN_CORPUS_PER_CLASS} each)"
        )


def test_no_legit_email_reaches_dangerous(results):
    """HARD: zero false 'Dangerous' verdicts on genuine mail."""
    _require_corpus(results)
    band = results["bands"]["Dangerous"]
    offenders = band["false_alarms"]
    assert len(offenders) <= MAX_LEGIT_AT_DANGEROUS, (
        f"{len(offenders)} genuine email(s) scored >= {_THRESHOLDS['Dangerous']} "
        f"(Dangerous), limit is {MAX_LEGIT_AT_DANGEROUS}: {offenders}. "
        "Telling a creator a real offer is an attack is the worst error this "
        "tool can make."
    )


def test_precision_at_high_risk_band(results):
    """Of what we flag at High risk, most must genuinely be scam."""
    _require_corpus(results)
    band = results["bands"]["High risk"]
    precision = band["precision"]
    if precision is None:
        pytest.skip("nothing flagged at the High-risk band; precision undefined")
    assert precision >= MIN_PRECISION_AT_HIGH_RISK, (
        f"precision at High risk (>= {_THRESHOLDS['High risk']}) fell to "
        f"{precision:.1%}, floor is {MIN_PRECISION_AT_HIGH_RISK:.0%}. "
        f"False alarms: {band['false_alarms']}"
    )


def test_recall_of_scams_at_dangerous_band(results):
    """Blatant scams must still reach the top band."""
    _require_corpus(results)
    band = results["bands"]["Dangerous"]
    recall = band["recall"]
    if recall is None:
        pytest.skip("no scam emails in corpus; recall undefined")
    assert recall >= MIN_RECALL_AT_DANGEROUS, (
        f"recall at Dangerous (>= {_THRESHOLDS['Dangerous']}) fell to "
        f"{recall:.1%}, floor is {MIN_RECALL_AT_DANGEROUS:.0%}. "
        f"Missed: {band['misses']}"
    )


def test_corpus_is_balanced_enough_to_trust(results):
    """Not a quality gate - a loud reminder when the numbers are still thin."""
    n = results["n"]
    if results["small_sample_warning"]:
        pytest.skip(
            f"corpus is {n['scam']} scam / {n['legit']} legit - metrics are "
            f"indicative only until each class passes {results['meaningful_n']}"
        )
    assert n["scam"] > 0 and n["legit"] > 0
