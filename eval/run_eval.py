#!/usr/bin/env python3
"""Measure the SponsorGuard engine against a labeled corpus.

Read-only with respect to the engine: this runs `analyze(raw, enrich=False)` and
reports what comes back. It never tunes anything. Metrics are computed by hand -
precision/recall/F1 are three divisions, not a reason to take a dependency.

Offline and deterministic by construction: `enrich=False` keeps the RDAP lookup
switched off, so no run touches the network and two runs over the same corpus
produce byte-identical output.

Usage:
    python eval/run_eval.py
    python eval/run_eval.py --corpus eval/corpus --out eval/report.json
    python eval/run_eval.py --no-private        # public seeds only
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sponsorguard.scoring import analyze  # noqa: E402

# The product's decision lives at the real band boundaries, so evaluate there
# rather than at some arbitrary cutoff. (Mirrors sponsorguard/scoring.py _BANDS;
# duplicated deliberately so a silent change there shows up as a metric shift.)
BANDS: list[tuple[str, int]] = [
    ("Caution", 15),
    ("High risk", 35),
    ("Dangerous", 60),
]

LABELS = ("scam", "legit")

# Below this per class, the numbers are directional at best.
MEANINGFUL_N = 15

DEFAULT_CORPUS = REPO_ROOT / "eval" / "corpus"
DEFAULT_OUT = REPO_ROOT / "eval" / "report.json"


@dataclass
class Sample:
    path: Path
    label: str          # "scam" | "legit"
    source: str         # "synthetic" | "real" | "unspecified"
    private: bool = False
    score: int = 0
    verdict: str = ""
    finding_ids: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.path.name


# ---------------------------------------------------------------- discovery

def _read_manifest(corpus: Path) -> dict[str, str]:
    """filename -> source, from an optional manifest.csv."""
    manifest = corpus / "manifest.csv"
    if not manifest.exists():
        return {}
    out: dict[str, str] = {}
    with manifest.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            name = (row.get("filename") or "").strip()
            source = (row.get("source") or "").strip().lower()
            if name and source in {"synthetic", "real"}:
                out[name] = source
    return out


def discover(corpus: Path, include_private: bool = True) -> list[Sample]:
    """Collect labeled emails. Label comes from the directory name."""
    manifest = _read_manifest(corpus)
    samples: list[Sample] = []

    roots: list[tuple[Path, bool]] = [(corpus, False)]
    private_root = corpus / "private"
    if include_private and private_root.is_dir():
        roots.append((private_root, True))

    for root, is_private in roots:
        for label in LABELS:
            folder = root / label
            if not folder.is_dir():
                continue
            for path in sorted(folder.glob("*.eml")):
                # Manifest wins. Otherwise anything under private/ is assumed
                # real (that directory exists precisely for real mail); public
                # files with no manifest row stay "unspecified" rather than
                # being silently counted as real.
                source = manifest.get(path.name) or ("real" if is_private else "unspecified")
                samples.append(Sample(path=path, label=label, source=source, private=is_private))
    return samples


def evaluate(samples: list[Sample]) -> list[Sample]:
    for s in samples:
        report = analyze(s.path.read_bytes(), enrich=False)
        s.score = report.score
        s.verdict = report.verdict.value
        s.finding_ids = [f.id for f in report.findings]
    return samples


# ------------------------------------------------------------------ metrics

def _div(num: int, den: int):
    """Return None for an undefined ratio rather than a misleading 0.0."""
    return (num / den) if den else None


def metrics_at(samples: list[Sample], threshold: int) -> dict:
    """`scam` is the positive class; a sample is 'flagged' when score >= threshold."""
    tp = fp = tn = fn = 0
    false_alarms: list[str] = []   # legit, flagged
    misses: list[str] = []         # scam, not flagged

    for s in samples:
        flagged = s.score >= threshold
        if s.label == "scam":
            if flagged:
                tp += 1
            else:
                fn += 1
                misses.append(s.name)
        else:
            if flagged:
                fp += 1
                false_alarms.append(s.name)
            else:
                tn += 1

    precision = _div(tp, tp + fp)
    recall = _div(tp, tp + fn)
    if precision is None or recall is None or (precision + recall) == 0:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall)

    return {
        "threshold": threshold,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1,
        "false_alarms": sorted(false_alarms),
        "misses": sorted(misses),
    }


def per_rule_stats(samples: list[Sample]) -> dict[str, dict[str, int]]:
    """How many scam vs legit emails each rule fired on (per email, not per hit).

    Only rules that fired at least once appear - a rule absent from this table
    fired on nothing in this corpus, which is itself worth noticing.
    """
    stats: dict[str, dict[str, int]] = {}
    for s in samples:
        for rid in set(s.finding_ids):
            row = stats.setdefault(rid, {"scam": 0, "legit": 0})
            row[s.label] += 1
    return dict(sorted(stats.items()))


# ------------------------------------------------------------------- output

def _pct(v) -> str:
    return "  n/a " if v is None else f"{v * 100:5.1f}%"


def _rule(width: int = 78) -> str:
    return "-" * width


def render(samples: list[Sample], results: dict) -> str:
    out: list[str] = []
    w = out.append

    n = results["n"]
    w("=" * 78)
    w("SponsorGuard - corpus evaluation")
    w("=" * 78)
    w(f"Corpus: {n['scam']} scam / {n['legit']} legit  ({n['total']} emails)")
    src = results["sources"]
    w(f"Provenance: {src.get('synthetic', 0)} synthetic, {src.get('real', 0)} real, "
      f"{src.get('unspecified', 0)} unspecified")
    w("Engine: analyze(enrich=False) - offline, no network, deterministic.")
    w("")

    if results["small_sample_warning"]:
        w("!! SMALL SAMPLE - INDICATIVE ONLY " + "!" * 44)
        w(f"!! Fewer than {MEANINGFUL_N} emails in at least one class "
          f"({n['scam']} scam / {n['legit']} legit).")
        w("!! These percentages are NOT statistically meaningful. One email moves")
        w("!! them by double digits. Treat them as a smoke test, not a benchmark.")
        w("!" * 78)
        w("")

    # ---- band sweep
    w("PRECISION / RECALL ACROSS THE PRODUCT'S BANDS")
    w("(positive class = scam; 'flagged' = score >= threshold)")
    w(_rule())
    w(f"{'Band':<12}{'>=':>4}  {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3}  "
      f"{'Precision':>9} {'Recall':>9} {'F1':>9}")
    w(_rule())
    for band, _ in BANDS:
        m = results["bands"][band]
        w(f"{band:<12}{m['threshold']:>4}  {m['tp']:>3} {m['fp']:>3} {m['tn']:>3} {m['fn']:>3}  "
          f"{_pct(m['precision']):>9} {_pct(m['recall']):>9} {_pct(m['f1']):>9}")
    w(_rule())
    w("")

    # ---- per-band detail, with the asymmetry spelled out
    for band, _ in BANDS:
        m = results["bands"][band]
        w(f"--- {band} (score >= {m['threshold']}) " + "-" * (78 - 20 - len(band)))
        w("                 flagged   not flagged")
        w(f"  actual scam    {m['tp']:>7}   {m['fn']:>11}")
        w(f"  actual legit   {m['fp']:>7}   {m['tn']:>11}")
        w("")
        if m["false_alarms"]:
            w(f"  FALSE ALARMS ({len(m['false_alarms'])}) - genuine mail we flagged."
              + ("  *** worst kind of error at this band ***" if band == "Dangerous" else ""))
            if band == "Dangerous":
                w("    Telling a creator a real paycheck is an attack costs them money")
                w("    and costs the tool their trust. This should be zero.")
            for name in m["false_alarms"]:
                w(f"    - {name}")
        else:
            w("  FALSE ALARMS: none - no genuine email reached this band.")
        w("")
        if m["misses"]:
            w(f"  MISSES ({len(m['misses'])}) - scams that stayed below this band.")
            w("    Recoverable: a lower band still warns the user.")
            for name in m["misses"]:
                w(f"    - {name}")
        else:
            w("  MISSES: none - every scam reached this band.")
        w("")

    # ---- misclassified roll-up
    w("MISCLASSIFIED EMAILS (by band)")
    w(_rule())
    any_wrong = False
    for band, _ in BANDS:
        m = results["bands"][band]
        for name in m["false_alarms"]:
            any_wrong = True
            w(f"  {band:<12} FALSE ALARM  {name}")
        for name in m["misses"]:
            any_wrong = True
            w(f"  {band:<12} MISS         {name}")
    if not any_wrong:
        w("  (none at any band)")
    w(_rule())
    w("")

    # ---- per-sample scores, useful when a number moves
    w("PER-EMAIL SCORES")
    w(_rule())
    w(f"{'label':<7}{'score':>6}  {'verdict':<11}{'source':<12}file")
    w(_rule())
    for s in sorted(samples, key=lambda x: (x.label, -x.score, x.name)):
        w(f"{s.label:<7}{s.score:>6}  {s.verdict:<11}{s.source:<12}{s.name}")
    w(_rule())
    w("")

    # ---- per-rule
    w("PER-RULE FIRING COUNTS (emails, not occurrences)")
    w("A rule that fires often on legit mail is a false-positive source.")
    w(_rule())
    w(f"{'rule id':<40}{'scam':>6}{'legit':>7}   note")
    w(_rule())
    if not results["per_rule"]:
        w("  (no rule fired on any email)")
    for rid, row in results["per_rule"].items():
        note = ""
        if row["legit"] and not row["scam"]:
            note = "<- fires ONLY on legit mail"
        elif row["legit"]:
            note = "<- also fires on legit"
        w(f"{rid:<40}{row['scam']:>6}{row['legit']:>7}   {note}")
    w(_rule())
    w("")

    # ---- real-only split
    ro = results.get("real_only")
    if ro:
        w("REAL EMAILS ONLY (synthetic seeds excluded)")
        w(f"Corpus: {ro['n']['scam']} scam / {ro['n']['legit']} legit")
        w(_rule())
        w(f"{'Band':<12}{'>=':>4}  {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3}  "
          f"{'Precision':>9} {'Recall':>9} {'F1':>9}")
        w(_rule())
        for band, _ in BANDS:
            m = ro["bands"][band]
            w(f"{band:<12}{m['threshold']:>4}  {m['tp']:>3} {m['fp']:>3} {m['tn']:>3} {m['fn']:>3}  "
              f"{_pct(m['precision']):>9} {_pct(m['recall']):>9} {_pct(m['f1']):>9}")
        w(_rule())
        w("")
    else:
        w("REAL EMAILS ONLY: no emails are marked source=real, so the headline")
        w("numbers above are entirely synthetic. Synthetic seeds are written to be")
        w("caught - they measure that the engine works, not how well it generalises.")
        w("Add real mail (see eval/README.md) before quoting any of this.")
        w("")

    return "\n".join(out)


# --------------------------------------------------------------------- main

def build_results(samples: list[Sample]) -> dict:
    counts = {lab: sum(1 for s in samples if s.label == lab) for lab in LABELS}
    counts["total"] = len(samples)

    sources: dict[str, int] = {}
    for s in samples:
        sources[s.source] = sources.get(s.source, 0) + 1

    results = {
        "n": counts,
        "sources": sources,
        "small_sample_warning": min(counts["scam"], counts["legit"]) < MEANINGFUL_N,
        "meaningful_n": MEANINGFUL_N,
        "bands": {band: metrics_at(samples, thr) for band, thr in BANDS},
        "per_rule": per_rule_stats(samples),
        "samples": [
            {
                "file": s.name,
                "label": s.label,
                "source": s.source,
                "private": s.private,
                "score": s.score,
                "verdict": s.verdict,
                "findings": s.finding_ids,
            }
            for s in sorted(samples, key=lambda x: (x.label, x.name))
        ],
    }

    real = [s for s in samples if s.source == "real"]
    if real:
        real_counts = {lab: sum(1 for s in real if s.label == lab) for lab in LABELS}
        real_counts["total"] = len(real)
        results["real_only"] = {
            "n": real_counts,
            "small_sample_warning": min(real_counts["scam"], real_counts["legit"]) < MEANINGFUL_N,
            "bands": {band: metrics_at(real, thr) for band, thr in BANDS},
            "per_rule": per_rule_stats(real),
        }
    else:
        results["real_only"] = None

    return results


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Evaluate SponsorGuard against a labeled corpus.")
    ap.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS,
                    help="corpus root containing scam/ and legit/ (default: eval/corpus)")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT,
                    help="where to write the JSON report (default: eval/report.json)")
    ap.add_argument("--no-private", action="store_true",
                    help="ignore eval/corpus/private/ even if present")
    ap.add_argument("--no-json", action="store_true", help="skip writing the JSON artifact")
    args = ap.parse_args(argv)

    if not args.corpus.is_dir():
        print(f"No corpus directory at {args.corpus}", file=sys.stderr)
        return 2

    samples = discover(args.corpus, include_private=not args.no_private)
    if not samples:
        print(f"No .eml files found under {args.corpus}/{{scam,legit}}/", file=sys.stderr)
        return 2

    evaluate(samples)
    results = build_results(samples)
    print(render(samples, results))

    if not args.no_json:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        print(f"JSON report written to {args.out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
