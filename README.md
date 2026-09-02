# SponsorGuard

A transparent, rule-based scanner that flags **fake brand-deal / sponsorship
scam emails** aimed at content creators — the attack class Google's threat team
has tracked being used to hijack YouTube channels at scale (one campaign
reportedly hit 200,000+ creators via lookalike domains and credential-harvest
pages).

Paste in a raw email (`.eml` / Gmail → *Show original*) and SponsorGuard returns
a scored verdict where **every point is explained by a concrete piece of evidence**
from the message itself. No black box, no ML, no training corpus — just
deterministic detection you can read and justify.

```
 Dangerous  —  score 100/100

Why:
  • display name "NordVPN Partnerships" but domain n0rdvpn-press.com — impersonation
  • n0rdvpn-press.com resembles nordvpn.com — lookalike domain
  • creative_brief.zip (encrypted zip) — password-protected archive to dodge AV

What to do: Treat as malicious. Do not click, download, reply, or pay.
```

## Why rule-based, not ML

This is a deliberate design choice, not a limitation:

- **Explainable.** Each verdict cites the literal offending string (the failing
  SPF result, the punycode host, the encrypted attachment). A creator — or a
  recruiter reading the code — can see exactly *why*.
- **No corpus needed.** The technical signals (auth failure, domain age,
  typosquat distance, password-locked archive) are near-deterministic. You don't
  need thousands of labelled scam emails to be useful on day one.
- **Testable.** Every rule is a pure function over a parsed email, so each has a
  focused unit test against a real `.eml` fixture.

## Architecture

Five stages, one clean module each:

| Stage | Module | What it does |
|-------|--------|--------------|
| Parse | `parser.py` | raw email → `ParsedEmail` (sender, links, attachments, auth header) |
| Rules | `rules/*.py` | pure `ParsedEmail → Finding` functions, self-registered via `@rule` |
| Score | `scoring.py` | weighted sum + **category caps** + **hard-override** flags → verdict |
| Report | `models.py` | per-finding evidence + an overall verdict and one safe next step |
| CLI | `cli.py` | run it over an `.eml`, human or `--json` output |

Rules are grouped by category — `auth`, `identity`, `links`, `attach`,
`content` — and adding one is a single decorated function; the engine is a dumb
loop over the registry.

### Scoring guardrails

- **Category caps** stop one noisy dimension dominating: an email with six
  mismatched links can't outrank one carrying an actual executable.
- **Hard overrides** force the top verdict for near-certain-malicious patterns
  (an `.exe`, a password-protected archive + "download the brief" pretext, a
  credential ask pointing at a non-brand domain), so the arithmetic can't dilute
  them.

## Usage

```bash
pip install -r requirements.txt        # only needed for the tests; core is stdlib
python -m sponsorguard.cli path/to/email.eml
python -m sponsorguard.cli path/to/email.eml --json
python -m sponsorguard.cli path/to/email.eml --enrich   # opt in to the RDAP domain-age lookup
pytest -q
```

Or from Python:

```python
from sponsorguard import analyze
report = analyze(open("email.eml", "rb").read())
print(report.verdict, report.score)
```

### Domain-age enrichment (opt-in, network-dependent)

By default `analyze()` is **pure and offline** — every rule is a function over
the parsed email, no network. One optional signal ages the sender's registrable
domain via [RDAP](https://about.rdap.org/) (a fresh lookalike domain registered
days before a blast is a strong scam tell):

| Sender domain age | Points | Severity |
|-------------------|--------|----------|
| < 30 days         | 25     | high     |
| 30–90 days        | 12     | medium   |
| older, or unknown | —      | *no finding* |

Because it makes a network call it is **off by default**. Enable it explicitly:

```python
report = analyze(raw_email, enrich=True)   # or:  cli … --enrich
```

It **fails safe to neutral**: any timeout, network error, non-200, or missing
data returns no finding, so a domain whose age can't be determined scores
*exactly* as it would with enrichment off. The lookup is isolated in
[`sponsorguard/enrichment/rdap.py`](sponsorguard/enrichment/rdap.py) and never
raises — the core detection never depends on network availability. Note the
honest caveat below: some TLDs omit the registration date in RDAP, which
correctly yields **no finding** rather than a false signal. Caching and
rate-limiting are intentionally out of scope for now (future work).

## Run the web app

The paste-email web UI is the intended product form: paste a raw email, get the
scored report rendered in the browser. No Gmail OAuth, no database, no accounts.

It has two pieces — a thin FastAPI wrapper around the engine, and a Vite + React
front end. The core `sponsorguard/` package stays stdlib-only; the API's
dependencies live in a separate `api/requirements.txt`.

**Backend** (from the repo root):

```bash
pip install -r api/requirements.txt
uvicorn api.main:app --reload --port 8000
```

That serves `POST /analyze` — it takes `{ "email_raw": "<string>" }` and returns
the report dict plus an `auth_available` flag (false when the pasted message had
no `Authentication-Results` header, so the UI can say SPF/DKIM/DMARC were
*skipped*, not passed).

**Frontend** (in a second terminal, from `web/`):

```bash
cd web
npm install
npm run dev
```

Then open the printed URL (default http://localhost:5173). The two example chips
— *a scam email* and *a real offer* — populate the textarea from the bundled
`.eml` fixtures, so it demos with zero typing. The front end talks to the API at
http://localhost:8000 by default; override with a `VITE_API_URL` env var if you
run it elsewhere.

**Tests** (both suites, from the repo root):

```bash
pip install -r requirements.txt -r api/requirements.txt
pytest -q
```

## Evaluating the engine

Detection quality is measured against a labeled corpus rather than asserted:

```bash
python eval/run_eval.py     # precision/recall/F1 + per-rule stats -> eval/report.json
pytest -q                   # includes the regression gate
```

The harness scores every email in `eval/corpus/{scam,legit}/` with
`analyze(enrich=False)` — offline and deterministic — and reports precision,
recall and F1 at the three real band boundaries (Caution ≥15, High risk ≥35,
Dangerous ≥60), plus a confusion matrix, every misclassified filename, and how
often each rule fires on scam vs legit mail.

False alarms and misses are reported separately, never averaged away: wrongly
telling a creator that a real paycheck is an attack is a far worse error than
under-scoring a scam that a lower band still catches. A CI gate holds "no genuine
email reaches Dangerous" at zero.

**The seeded corpus is entirely synthetic**, so the headline numbers only show
the engine works, not how well it generalises. Real mail goes in a gitignored
`eval/corpus/private/` — see [eval/README.md](eval/README.md) for the collection
and redaction rules.

## Honest limitations (read before trusting output)

- **Auth checks depend on a trustworthy `Authentication-Results` header.** That's
  only present if the email is exported from the recipient's own provider. On a
  forwarded or body-only paste the header is absent and auth checks are skipped,
  not passed. (A live-SPF add-on using the earliest `Received` IP is a natural
  next step; live DKIM from pasted text is not reliable and is intentionally
  omitted.)
- **`registrable_domain` is an approximation**, not the full Public Suffix List.
  Swap in `tldextract` before relying on it for arbitrary ccTLDs.
- **Domain-age enrichment (opt-in) is network-dependent and best-effort.** Some
  TLDs don't publish a `registration` event in RDAP; that yields **no finding**
  (neutral), never a false signal, and the same is true of any timeout or error.
  It never lowers a score and never runs unless you pass `enrich=True`.
- **RAR/7z contents aren't inspected** (no stdlib support) — flagged as
  uninspected archives at a lower weight rather than silently passed.
- **The brand list (`data/brands.json`) goes stale.** It's versioned JSON on
  purpose; keep it current with the high-frequency sponsors.
- **Low-confidence signals are low-weight by design** (missing DMARC, a
  Reply-To mismatch, a URL shortener) because legitimate small brands trip them
  too. This is a precision/recall tradeoff, not an oversight.

## Roadmap

- ~~Paste-email web UI (FastAPI + React)~~ — **built** (see *Run the web app*
  above); no Gmail OAuth required, which sidesteps Google's restricted-scope
  security review.
- Live SPF evaluation from the originating IP.
- ~~Domain-age enrichment via RDAP~~ — **built** (see *Domain-age enrichment*
  above); shipped as a sync, opt-in enrichment pass (`analyze(…, enrich=True)`)
  rather than async — one best-effort lookup didn't justify an event loop or a
  new async HTTP dependency. Timeout-guarded, degrades to neutral. Caching /
  rate-limiting still open.
- Optional Gmail add-on (note: reading inboxes needs a restricted-scope OAuth
  app + annual CASA assessment — worth it only past the portfolio stage).

## Scope & ethics

SponsorGuard analyzes emails **you received**. It is a defensive tool: it does
not send, scrape, or profile third parties.
