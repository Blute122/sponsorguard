# Evaluation harness

Measures the detection engine against a labeled corpus so tuning can be
data-driven instead of vibes-driven. It **measures**, it never tunes: nothing in
here changes a rule, weight, or threshold.

```bash
python eval/run_eval.py                 # table to stdout + eval/report.json
python eval/run_eval.py --no-private     # public seeds only
python eval/run_eval.py --no-json        # stdout only
pytest -q                                # includes the regression gate
```

Runs `analyze(raw, enrich=False)`, so every evaluation is **offline and
deterministic** — the RDAP lookup stays off and two runs over the same corpus
produce identical output. No third-party dependencies; the metrics are three
divisions done by hand.

## Corpus layout

Two attributes come from the path: the **label** (`scam` / `legit`) and the
**tier**. Any directory that doesn't exist is skipped, so the original flat layout
keeps working exactly as before.

```
eval/corpus/
  scam/  legit/                 -> tier: sponsorship   (legacy flat layout)
  private/ scam/  legit/        -> tier: sponsorship   (legacy, gitignored)
  manifest.csv                     optional: filename,source,notes

  sponsorship/                  -> tier: sponsorship   THE HEADLINE TIER
    scam/  legit/
    private/ scam/  legit/         gitignored - your real mail
    manifest.csv                   optional, overrides the root one

  phishing-general/             -> tier: phishing-general   REGRESSION ONLY
    scam/  legit/
    private/ scam/  legit/
    manifest.csv
```

**Tiers** (see [COLLECTION.md](COLLECTION.md) §1): `sponsorship` is the hand-built,
creator-specific set and the **only** one whose numbers back a claim — it is the
headline report and the one the CI gate enforces. `phishing-general` is bulk public
phishing/ham kept purely as a regression signal; it prints in its own section
marked regression-only and is never gated on.

The original flat `corpus/{scam,legit}` seeds *are* the sponsorship set, so they
fold into that tier rather than forming a separate bucket. If the same email is
reachable under two paths (e.g. a legacy seed also copied into `sponsorship/`) it
is counted once.

`manifest.csv` marks each file `synthetic` or `real`. It is optional; the harness
runs fine without it. Files under any `private/` with no manifest row are assumed
`real` (those directories exist for exactly that purpose); public files with no row
are recorded as `unspecified`.

## Adding real emails (the part that actually matters)

The seeded corpus is **entirely synthetic**. Synthetic scams are written to be
caught, so they prove the engine works — they say nothing about how it
generalises. Real mail is the only thing that produces a number worth quoting,
and collecting it is a manual job.

1. In Gmail, open the message → **⋮ → Show original → Download Original**.
   (The `Authentication-Results` header only exists on the copy your own
   provider received — a forward or a body copy-paste loses it, and the auth
   rules then correctly report *skipped*, not *passed*.)
2. Drop the `.eml` into `eval/corpus/private/scam/` or `.../legit/`.
3. Optionally add a row to a manifest with `source=real`.

### Redaction rule

Real emails contain PII. Before saving one, **redact the recipient**:

- **Remove or replace:** `To:`, `Cc:`, `Bcc:`, `Delivered-To:`, your own name in
  the body, and any recipient-identifying token inside tracking URLs.
- **KEEP EXACTLY AS-IS:** `From:`, `Reply-To:`, the sender domain,
  `Authentication-Results:`, `Received:`, all links, and all attachments.

Those kept fields *are* what the engine tests. Redacting the sender domain or the
auth header doesn't anonymise the email, it destroys the sample.

`eval/corpus/private/` is gitignored, so real mail never gets committed. Do not
move real emails into the public `scam/` or `legit/` folders.

## Reading the output

**The two errors are not equal. Do not average them into one number.**

- **FALSE ALARM** — a genuine email that got flagged. At the **Dangerous** band
  this is the worst thing the tool can do: it tells a creator that a real
  paycheck is an attack. They ignore the offer, lose the money, and stop
  trusting the tool. The CI gate holds this at **zero**.
- **MISS** — a scam that stayed below a band. Bad, but recoverable: the email
  usually still surfaces at a lower band, so the user is still warned.

That asymmetry is why the report prints both separately rather than only F1.

The sweep evaluates at the **three real band boundaries** (Caution ≥15, High risk
≥35, Dangerous ≥60) rather than one arbitrary cutoff, because that is where the
product's decision actually lives. Recall naturally drops at the strictest band —
a subtle scam landing in High risk instead of Dangerous is working as designed,
not a bug.

**Per-rule firing counts** are the most actionable section. A rule that fires on
legit mail is a false-positive source; one firing *only* on legit mail is a
tuning candidate. Rules that never fired don't appear at all — also worth
noticing. (On the seeded corpus, `auth.dmarc_none` fires only on legit mail and
`identity.reply_to_mismatch` fires on both. Both are intentionally low-weight, so
neither pushes a legit email over a band — which is the design working, and
exactly the kind of thing this table is meant to make visible.)

### Sample size

The header prints N per class and shouts if either class is under 15. With a
handful of emails one message moves a percentage by double digits. Treat small-N
output as a smoke test. When any email is marked `source=real`, the harness also
prints a **real-only** table so synthetic seeds can't inflate the headline.

## The regression gate

`eval/test_eval_gate.py` runs inside the normal `pytest -q` suite. Thresholds are
named constants at the top of that file, seeded conservatively so they pass with
headroom — **ratchet them up as the corpus grows**:

| Constant | Seed | Actual on seeded corpus |
|---|---|---|
| `MAX_LEGIT_AT_DANGEROUS` | 0 | 0 |
| `MIN_PRECISION_AT_HIGH_RISK` | 0.70 | 1.00 |
| `MIN_RECALL_AT_DANGEROUS` | 0.50 | 0.80 |
| `MIN_CORPUS_PER_CLASS` | 3 | 5 |

The gate **skips** (never fails) if the corpus is missing or under
`MIN_CORPUS_PER_CLASS` per class, so a fresh clone without a corpus doesn't break
CI. If a gate fails, work out whether it's a genuine engine regression or a
corpus that grew a case the engine was never good at — before changing a weight.

## CI

This repo has no CI config yet. When one is added, the whole thing is:

```yaml
- run: pip install -r requirements.txt -r api/requirements.txt
- run: pytest -q                    # includes the eval gate
- run: python eval/run_eval.py      # full report in the build log
```

`eval/report.json` holds the machine-readable version (metrics per band,
confusion matrices, misclassified lists, per-rule stats, per-email scores, N).
It carries no timestamp, so committing it gives you a baseline that diffs cleanly
when the engine changes.
