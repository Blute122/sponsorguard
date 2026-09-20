# Collection tools

Standalone helpers for building the real corpus. Nothing here is part of the eval
harness — these scripts don't score, label, or import anything. They automate
**step 1 of the workflow in [../COLLECTION.md](../COLLECTION.md) §6** (getting raw
email onto your machine) and stop there.

## `fetch_gmail.py`

Searches your own Gmail for sponsorship-shaped mail across **Spam, Trash and All
Mail**, and drops each raw message as an `.eml` into a gitignored review queue for
you to triage by hand.

Stdlib only (`imaplib`, `email`, `hashlib`, `csv`). No dependencies.

### What it will not do

- **It will not label anything.** Every message lands in one `review/` directory
  with a blank `label` column. The folder a message came from is recorded as
  metadata, never as a class: **"it was in Spam" is not evidence that it is a
  scam**, and plenty of real sponsorship offers get spam-filtered. Labeling is a
  human judgement call — see [COLLECTION.md §4](../COLLECTION.md).
- **It will not redact anything.** Redaction happens when *you* move a message into
  the corpus, per [COLLECTION.md §3](../COLLECTION.md).
- **It will not modify your mailbox.** Mailboxes are opened `readonly=True` and
  bodies fetched with `BODY.PEEK[]`, so messages are never even marked as read.
  The script issues no `STORE`, `COPY`, `MOVE`, `EXPUNGE` or `DELETE`.

### Prerequisites

1. **Enable IMAP.** Gmail → Settings → *See all settings* → **Forwarding and
   POP/IMAP** → *Enable IMAP* → Save.
2. **Turn on 2-Step Verification** on the Google account. App Passwords do not
   exist without it.
3. **Create an App Password.** Google Account → Security → **2-Step Verification** →
   **App passwords**. Generate one and copy the 16-character value.

> Your normal account password **will not work** over IMAP. Google blocks basic
> password auth for mail clients; the App Password is the supported path. If login
> fails, the script tells you which of these three is usually the cause.

### Credentials

Read from environment variables. The script never writes them to disk, never logs
them, and there is no config file to leak.

```bash
export GMAIL_ADDRESS='you@gmail.com'
export GMAIL_APP_PASSWORD='abcd efgh ijkl mnop'
```

```powershell
$env:GMAIL_ADDRESS='you@gmail.com'
$env:GMAIL_APP_PASSWORD='abcd efgh ijkl mnop'
```

Set them in your shell for the session. If you'd rather keep them in a file, use a
`.env` that you source yourself — `*.env` and `.env` are gitignored — but never
commit one, and never pass a password on the command line where it lands in shell
history.

### Usage

**Always dry-run first.** It connects and searches but writes nothing, so you can
see how many messages your query actually matches before pulling hundreds.

```bash
python eval/tools/fetch_gmail.py --dry-run
```

Then fetch for real, in small batches:

```bash
python eval/tools/fetch_gmail.py --limit 50
```

| Flag | Default | Purpose |
|---|---|---|
| `--dry-run` | off | Report per-folder counts, write nothing |
| `--limit N` | 200 | Cap on **new** messages saved per run |
| `--folders` | all three | Subset of `spam trash all_mail` |
| `--query` | see below | Override with any Gmail search syntax |

Default query (Gmail syntax, via the `X-GM-RAW` IMAP extension — plain IMAP
`SEARCH` can't express this):

```
subject:(sponsorship OR collaboration OR "brand deal" OR partnership OR
"promote our" OR "paid promotion" OR sponsor) OR
body:("sponsor your channel" OR "creative brief" OR "brand deal")
```

Narrow or widen it freely — anything you can type into the Gmail search box works:

```bash
python eval/tools/fetch_gmail.py --dry-run --query 'subject:sponsorship after:2026/01/01'
python eval/tools/fetch_gmail.py --folders spam --limit 25
```

### Output

```
eval/corpus/sponsorship/review/
  20260115_n0rdvpn-press.com_9deead1d.eml    <- raw, untouched
  _queue.csv                                  <- triage worksheet
eval/tools/.seen_ids                          <- dedupe store
```

Filenames are `<date>_<sender-domain>_<short-hash>.eml`. The sender domain is kept
because it's signal (that's the half COLLECTION.md tells you *not* to redact); no
recipient information goes into the name.

`_queue.csv` columns:

| Column | Filled by | Notes |
|---|---|---|
| `filename` | script | |
| `fetched_from` | script | `spam` / `trash` / `all_mail` — provenance, **not** a label |
| `date`, `from_domain`, `subject` | script | at-a-glance triage |
| `has_auth_results` | script | `no` means the auth rules can't be exercised |
| `has_attachments` | script | attachment-bearing specimens are the scarce ones |
| `label` | **you** | blank on purpose |
| `notes` | **you** | why you labeled it, especially for borderline cases |

Sort by `has_attachments` and `has_auth_results` to find the highest-value
specimens first — a message with both exercises every pillar of the engine.

**Deduplication.** Messages are keyed by `Message-ID`, falling back to a SHA-256 of
the raw bytes when a message has none. Keys accumulate in `eval/tools/.seen_ids`,
so re-runs never refetch, and the same message appearing in both All Mail and Spam
is saved once. Run it weekly; collection becomes passive.

### After it runs — the part that matters

The script stops at raw files. Everything below is yours, per
[COLLECTION.md](../COLLECTION.md):

1. **Read and label** by *security threat*, not deal quality (§4). A real brand
   with a lousy offer is `legit`; a polished fake NordVPN is `scam`. **When in
   doubt, skip** — a mislabeled legit is worse than a missing one, because the
   harness's trust-critical invariant is "no legit email reaches Dangerous".
2. **Redact the recipient side** (§3): `To`/`Cc`/`Bcc`, your name, personal
   identifiers → bracket tokens. **Keep** `From`, `Reply-To`,
   `Authentication-Results`, `Received`, and every link — those are what the engine
   actually tests.
3. **Move** it to `eval/corpus/sponsorship/private/{scam,legit}/` with a descriptive
   name, and add a manifest row with `source=real` and your reasoning.
4. Delete anything you decided to skip. Re-run `python eval/run_eval.py` and watch
   the real-only table.

### Note on the harness

The tiered layout is **live end to end**. `run_eval.py` discovers all of these,
skipping any that don't exist:

```
corpus/{scam,legit}                          -> sponsorship  (legacy flat)
corpus/private/{scam,legit}                  -> sponsorship  (legacy flat)
corpus/sponsorship/{scam,legit}
corpus/sponsorship/private/{scam,legit}
corpus/phishing-general/{scam,legit}
corpus/phishing-general/private/{scam,legit}
```

Emails you triage into `sponsorship/private/{scam,legit}` appear in the report
immediately — they land in the **headline** tier, and in the real-only table once
marked `source=real`. `phishing-general` is reported in its own section marked
regression-only and is never gated on.

### Scope

Gmail via IMAP + App Password, by design — no OAuth, no Gmail API, no
`credentials.json`, no consent screen, no restricted-scope review. For another
provider, point `IMAP_HOST` at its IMAP server; the `X-GM-RAW` search is
Gmail-specific and would need replacing with standard IMAP `SEARCH` terms.
