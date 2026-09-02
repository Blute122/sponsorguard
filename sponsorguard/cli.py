"""CLI: run SponsorGuard over an .eml file and print the report."""
from __future__ import annotations

import argparse
import json
import sys

from .scoring import analyze

_COLORS = {"Low": "\033[92m", "Caution": "\033[93m", "High risk": "\033[91m", "Dangerous": "\033[41m\033[97m"}
_RESET = "\033[0m"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Scan a sponsorship email (.eml) for scam signals.")
    ap.add_argument("eml", help="path to a raw email file (.eml / Gmail 'Show original')")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    ap.add_argument(
        "--enrich",
        action="store_true",
        help="also run the network-dependent RDAP domain-age lookup (off by default; "
        "fails safe to no finding)",
    )
    args = ap.parse_args(argv)

    with open(args.eml, "rb") as fh:
        report = analyze(fh.read(), enrich=args.enrich)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0

    color = _COLORS.get(report.verdict.value, "")
    print(f"\n{color} {report.verdict.value}  —  score {report.score}/100 {_RESET}\n")
    print("Why:")
    for reason in report.top_reasons:
        print(f"  • {reason}")
    print(f"\nWhat to do: {report.safe_next_step}\n")
    print(f"All findings ({len(report.findings)}):")
    for f in report.findings:
        print(f"  [{f.points:>2}] {f.category.value:<8} {f.id}")
        print(f"       evidence: {f.evidence}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
