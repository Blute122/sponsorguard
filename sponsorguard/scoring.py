"""Turn a list of Findings into a scored, banded Report.

Two guardrails keep the number honest:
  * category caps  — one noisy dimension can't dominate the total
  * hard overrides — near-certain-malicious patterns force the top verdict
                     regardless of the arithmetic (an .exe shouldn't be
                     dilutable by an otherwise clean-looking email)
"""
from __future__ import annotations

from .models import Category, Finding, Report, Verdict

# Per-category ceilings on summed points.
CATEGORY_CAPS: dict[Category, int] = {
    Category.AUTH: 40,
    Category.IDENTITY: 60,
    Category.LINKS: 40,
    Category.ATTACH: 60,
    Category.CONTENT: 45,
}

MAX_SCORE = 100

# Verdict thresholds (inclusive lower bound).
_BANDS = [
    (60, Verdict.DANGEROUS),
    (35, Verdict.HIGH),
    (15, Verdict.CAUTION),
    (0, Verdict.LOW),
]

_SAFE_STEP = {
    Verdict.LOW: "Looks consistent, but still verify the brand independently before sharing anything.",
    Verdict.CAUTION: "Mixed signals. Confirm the sender via the brand's official website before replying.",
    Verdict.HIGH: "Likely a scam. Don't click links or open attachments; verify out-of-band or ignore.",
    Verdict.DANGEROUS: "Treat as malicious. Do not click, download, reply, or pay. Delete and report it.",
}


def _band(score: int) -> Verdict:
    for lower, verdict in _BANDS:
        if score >= lower:
            return verdict
    return Verdict.LOW


def score_findings(findings: list[Finding]) -> Report:
    # Sum per category, then clamp each to its cap.
    per_cat: dict[Category, int] = {c: 0 for c in Category}
    for f in findings:
        per_cat[f.category] += f.points
    capped_total = sum(min(per_cat[c], CATEGORY_CAPS[c]) for c in Category)
    score = min(capped_total, MAX_SCORE)

    verdict = _band(score)
    if any(f.hard_flag for f in findings):
        verdict = Verdict.DANGEROUS  # override regardless of total

    ordered = sorted(findings, key=lambda f: f.points, reverse=True)
    top_reasons = [f"{f.evidence} — {f.explanation}" for f in ordered[:3]]

    return Report(
        score=score,
        verdict=verdict,
        top_reasons=top_reasons,
        safe_next_step=_SAFE_STEP[verdict],
        findings=ordered,
    )


def analyze(raw_email: str | bytes, *, enrich: bool = False) -> Report:
    """Convenience end-to-end: raw .eml -> Report.

    Pure and offline by default. Pass ``enrich=True`` to also run the
    network-dependent enrichment pass (currently an RDAP sender-domain-age
    lookup). That pass fails safe to *no finding*, so a network problem — or a
    TLD that hides its registration date — leaves the score exactly as it would
    be with ``enrich=False``. With ``enrich=False`` this is byte-for-byte the
    original pure pipeline.
    """
    from .parser import parse_email
    from .rules import run_rules

    parsed = parse_email(raw_email)
    findings = run_rules(parsed)
    if enrich:
        from .enrichment import enrich_findings

        findings = findings + enrich_findings(parsed)
    return score_findings(findings)
