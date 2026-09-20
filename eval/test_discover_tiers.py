"""Coverage for tiered corpus discovery.

Every test builds a throwaway corpus under tmp_path, so nothing here depends on
the real corpus and nothing touches the network (the engine is never invoked -
these exercise discover() and the tier grouping only).
"""
from __future__ import annotations

import pytest

from run_eval import (
    HEADLINE_TIER,
    TIER_PHISHING,
    TIER_SPONSORSHIP,
    Sample,
    build_results,
    discover,
    split_by_tier,
)

EML = b"From: a@example.com\nTo: b@example.com\nSubject: hi\n\nbody\n"


def _write(root, *parts, name="mail.eml", body=EML):
    folder = root.joinpath(*parts)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_bytes(body)
    return folder / name


# ------------------------------------------------- legacy flat -> sponsorship

def test_legacy_flat_paths_resolve_to_sponsorship(tmp_path):
    """The original corpus/{scam,legit} seeds ARE the sponsorship set."""
    _write(tmp_path, "scam", name="s.eml", body=EML + b"scam\n")
    _write(tmp_path, "legit", name="l.eml", body=EML + b"legit\n")

    samples = discover(tmp_path)

    assert len(samples) == 2
    assert {s.tier for s in samples} == {TIER_SPONSORSHIP}
    assert {s.label for s in samples} == {"scam", "legit"}


def test_legacy_private_resolves_to_sponsorship_and_is_real(tmp_path):
    _write(tmp_path, "private", "scam", name="p.eml", body=EML + b"private\n")

    (sample,) = discover(tmp_path)

    assert sample.tier == TIER_SPONSORSHIP
    assert sample.private is True
    assert sample.source == "real"


# --------------------------------------------------------- explicit tier dirs

@pytest.mark.parametrize("parts,expected_tier,expected_private", [
    (("sponsorship", "scam"), TIER_SPONSORSHIP, False),
    (("sponsorship", "private", "scam"), TIER_SPONSORSHIP, True),
    (("phishing-general", "scam"), TIER_PHISHING, False),
    (("phishing-general", "private", "legit"), TIER_PHISHING, True),
])
def test_tier_directories_are_mapped(tmp_path, parts, expected_tier, expected_private):
    _write(tmp_path, *parts, body=EML + "/".join(parts).encode())

    (sample,) = discover(tmp_path)

    assert sample.tier == expected_tier
    assert sample.private is expected_private


def test_missing_tier_directories_are_skipped_without_error(tmp_path):
    """A corpus with only legacy seeds must behave exactly as it always did."""
    _write(tmp_path, "scam", name="only.eml")

    samples = discover(tmp_path)   # no sponsorship/ or phishing-general/ exists

    assert len(samples) == 1
    assert samples[0].tier == TIER_SPONSORSHIP


def test_completely_empty_corpus_returns_nothing(tmp_path):
    assert discover(tmp_path) == []


def test_private_can_be_excluded(tmp_path):
    _write(tmp_path, "sponsorship", "scam", name="pub.eml", body=EML + b"pub\n")
    _write(tmp_path, "sponsorship", "private", "scam", name="priv.eml", body=EML + b"priv\n")

    assert len(discover(tmp_path, include_private=True)) == 2
    kept = discover(tmp_path, include_private=False)
    assert [s.path.name for s in kept] == ["pub.eml"]


# ------------------------------------------------------------------- dedupe

def test_same_content_under_two_paths_is_counted_once(tmp_path):
    """A legacy seed also copied into sponsorship/ must not be double-counted."""
    body = EML + b"duplicated\n"
    _write(tmp_path, "scam", name="seed.eml", body=body)
    _write(tmp_path, "sponsorship", "scam", name="seed_copy.eml", body=body)

    samples = discover(tmp_path)

    assert len(samples) == 1
    # Discovery order puts the legacy flat path first, so that one wins.
    assert samples[0].path.name == "seed.eml"


# ------------------------------------------------------- manifest provenance

def test_per_tier_manifest_overrides_root_manifest(tmp_path):
    _write(tmp_path, "sponsorship", "scam", name="m.eml", body=EML + b"m\n")
    (tmp_path / "manifest.csv").write_text(
        "filename,source,notes\nm.eml,synthetic,from root\n", encoding="utf-8")
    (tmp_path / "sponsorship" / "manifest.csv").write_text(
        "filename,source,notes\nm.eml,real,from tier\n", encoding="utf-8")

    (sample,) = discover(tmp_path)

    assert sample.source == "real"


# ------------------------------------------------------------- tier grouping

def test_phishing_tier_is_split_out_and_excluded_from_the_headline(tmp_path):
    """The gate reads the headline tier, so phishing mail can never fail it."""
    _write(tmp_path, "sponsorship", "scam", name="s1.eml", body=EML + b"s1\n")
    _write(tmp_path, "sponsorship", "legit", name="l1.eml", body=EML + b"l1\n")
    _write(tmp_path, "phishing-general", "scam", name="p1.eml", body=EML + b"p1\n")
    _write(tmp_path, "phishing-general", "scam", name="p2.eml", body=EML + b"p2\n")

    samples = discover(tmp_path)
    grouped = split_by_tier(samples)

    assert len(grouped[TIER_SPONSORSHIP]) == 2
    assert len(grouped[TIER_PHISHING]) == 2

    for s in samples:            # build_results needs scored samples
        s.score, s.verdict = 0, "Low"
    results = build_results(samples)

    assert results["headline_tier"] == HEADLINE_TIER
    # Headline counts cover the sponsorship tier ONLY.
    assert results["n"]["total"] == 2
    assert set(results["tiers"]) == {TIER_SPONSORSHIP, TIER_PHISHING}
    assert results["tiers"][TIER_PHISHING]["n"]["total"] == 2


def test_tiers_with_no_emails_are_absent_from_the_report(tmp_path):
    _write(tmp_path, "scam", name="s.eml")
    for s in (samples := discover(tmp_path)):
        s.score, s.verdict = 0, "Low"

    results = build_results(samples)

    assert set(results["tiers"]) == {TIER_SPONSORSHIP}


def test_split_by_tier_surfaces_unknown_tiers(tmp_path):
    """An unrecognised tier must not silently vanish from the report."""
    odd = Sample(path=tmp_path / "x.eml", label="scam", source="unspecified", tier="mystery")

    grouped = split_by_tier([odd])

    assert "mystery" in grouped
