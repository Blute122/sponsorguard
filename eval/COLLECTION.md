# Corpus Collection Guide

How to build the real email corpus that turns the eval harness from scaffolding
into proof. This is not a coding task — it's careful, slow collection. The goal
is a small, honest, diverse set of real emails, not a large set of synthetic
ones.

**Target: ~30–50 real emails per class eventually.** Even 15 per class flips the
harness's headline metrics from "indicative only" to genuinely meaningful.
Diversity matters more than volume — 20 emails covering every attack pattern beat
100 copies of the same fake-NordVPN scam.

## 1. The two tiers

Keep two separate corpus tiers, reported separately by the harness:

- `corpus/phishing-general/` — bulk public phishing (Nazario, Nigerian Fraud) plus
  benign (SpamAssassin ham, Enron). This is a **regression set**: it proves the
  engine handles real hostile mail without choking or over-flagging legitimate
  mail. Import it via the bulk loader (CSV/mbox). It does not back any marketing
  claim, because none of it is sponsorship scam.
- `corpus/sponsorship/` — the hand-built set this guide is about. Small, real,
  creator-specific. **This is the only tier whose numbers you may ever quote.**

Everything below concerns the sponsorship tier.

### The harness understands both tiers

`run_eval.py` scans every path below, skipping any that don't exist:

```
corpus/{scam,legit}                            -> sponsorship  (legacy flat)
corpus/private/{scam,legit}                    -> sponsorship  (legacy flat)
corpus/sponsorship/{scam,legit}
corpus/sponsorship/private/{scam,legit}
corpus/phishing-general/{scam,legit}
corpus/phishing-general/private/{scam,legit}
```

The original flat `corpus/{scam,legit}` seeds **are** the sponsorship set, so they
fold into that tier rather than forming a separate bucket — the flat layout keeps
working unchanged, and you can migrate to the explicit `sponsorship/` directories
whenever you like.

**Sponsorship is the headline.** Its metrics are the top-level report and the ones
the CI gate enforces. **phishing-general prints in its own section, labelled
regression-only, and is never gated on** — it cannot fail the build, and it cannot
inflate a number you might quote. A `manifest.csv` inside a tier directory
overrides the root one for those files.

## 2. Where to find real sponsorship scams

The best specimen is a raw email with full headers (`From`, `Reply-To`,
`Authentication-Results`, Received chain, links, attachment metadata). Most public
posts are screenshots — useful but header-less, so they only exercise the
body/content rules, not the auth pillar. Prioritize sources that give you raw
source.

**Best — raw headers available:**

- **Your own inbox / spam / Promotions folder.** You'll receive these; creators and
  anyone with a public contact address get them constantly. Export via Gmail →
  open message → ⋮ → **Show original → Download Original** (`.eml`), or Outlook →
  Save As → `.eml`.
- **Creator friends who forward you the raw source.** Give them the exact "Show
  original → download" steps above — a forwarded email loses the original headers,
  so ask for the downloaded original, not a forward.
- **A honeypot address.** Put a dedicated contact email on a small channel/site and
  collect what arrives over weeks. Slow but yields pristine specimens.

**Useful — usually body/screenshot only (header-less tier):**

- Subreddits where people paste the email: r/creatorscams, r/youtubers,
  r/NewTubers, r/Twitch, r/smallstreamers, r/PartneredYouTube.
- Creator Discord servers with a "scams" / "report" channel.
- X/Twitter and YouTube "exposing sponsor scams" posts where creators show the
  email text.

For header-less specimens, reconstruct a minimal `.eml` from what's visible (From
line, Subject, body, links) and mark them clearly in the manifest so you know the
auth pillar wasn't exercised.

**Legit sponsorships (the scarce, harder class — don't neglect it):** This class is
harder to collect and just as important — it's what catches false positives.
Sources: your own real sponsor emails, creator friends' real deals (raw source),
and real brand outreach routed through an ESP (Mailchimp, SendGrid, Braze).
Deliberately hunt for ESP-routed and agency-intermediary legit mail — those are the
ones most likely to trip a naive rule, so they're the most valuable legit
specimens you can add.

## 3. Redaction rules (do this before anything leaves your machine)

You're handling other people's mail. **The sender is the attacker — their info is
signal, keep it. The recipient is the victim — protect them.**

**KEEP (the engine needs these):**

- Sender `From` address and domain, `Reply-To`
- `Authentication-Results` and sender-side `Received` headers
- `Subject`, body text, all links (full URLs), attachment names/types
- `Message-ID`, `Return-Path`

**REDACT — replace with a bracket token, don't delete** (keeps structure intact):

- Recipient `To:` address → `[RECIPIENT]`
- The victim's real name / channel name in the body → `[CREATOR_NAME]`
- Any personal identifiers of the victim (phone, address, real name)
- If sourced from someone else, anything that ties them to "I got scammed"

**Hard rules:**

- The gitignored `corpus/sponsorship/private/` dir is where real mail lives.
  Nothing here is committed. Redact only what you might later move into a
  committed, curated set.
- Only analyze emails you received, or that the recipient gave you permission to
  use. For anything from a third party, anonymize and get consent.
- Never commit anything that publicly links a named person to being scammed.
- When unsure whether something is PII, redact it. Over-redacting the recipient
  side costs the engine nothing — it doesn't score recipient identity.

## 4. Labeling — the rule that keeps the corpus honest

**Label by security threat, not by deal quality.** Your engine judges whether an
email is trying to harm the recipient — not whether it's a good business offer. A
real brand making a lowball offer is `legit`/safe. A fake NordVPN with a
perfect-sounding $5k deal is `scam`. Keep this straight or the corpus stops
measuring what the engine measures.

**Clear `scam/`:** brand impersonation, lookalike/typosquat domains, credential or
2FA requests, malware/locked attachments, advance/"refundable" fees, fake login
links.

**Clear `legit/`:** verifiably real brand, real domain, passes authentication, no
credential/payment asks — even if the deal itself is unattractive or the tone is
pushy.

**Borderline cases → how to resolve**

- **Pushy-but-real agency outreach** (real intermediary, uses a link shortener,
  Reply-To differs) → **legit**, and a valuable one: it's a "hard legit" that
  stress-tests false positives. Add it.
- **Real brand via ESP** (Mailchimp/SendGrid) → **legit**. Include it — it tests
  whether you over-flag legitimate bulk-sender infrastructure.
- **Grey affiliate/MLM recruitment** ("promote us for commission") → judge by the
  security test, not the ick factor. Asks for payment / credentials / has malware
  → `scam`. Just a bad-value real offer → `legit` or skip.
- **Generic marketing / newsletter** that isn't a sponsorship pitch → **skip**. Out
  of scope; don't pollute either class.
- **Legit-looking but unverifiable** (tiny brand, no DMARC, can't confirm the
  domain is really theirs) → **skip**. Never guess a legit label.

**When in doubt, skip.** A mislabeled email poisons the metric worse than a missing
one — especially a wrongly-labeled legit, since the harness's trust-critical
invariant is "no legit email reaches Dangerous." Verify before you file to
`legit/`:

- Confirm the sender domain is the brand's actual domain (check the brand's
  official site).
- Confirm links resolve to the real domain.
- Ideally, confirm the recipient actually engaged and it was real.

Record **why** you labeled each borderline case in the manifest `notes` column.
Future-you will want the reasoning.

## 5. Diversity checklist

Aim to cover each pattern at least twice before adding duplicates of any one.

**Scam patterns:** brand-impersonation display name · typosquat/lookalike domain ·
credential/login-harvest link · malware/locked attachment · advance/refundable fee
· pure urgency-and-pressure · homoglyph/punycode link · body-only (header-less)
specimen.

**Legit patterns:** direct email from brand's real domain · ESP-routed
(Mailchimp/SendGrid) · agency/intermediary outreach · short informal DM-style offer
· a "hard legit" that superficially looks risky (shortener, Reply-To mismatch) but
is genuine.

## 6. Workflow

1. Get the raw email (`.eml` via Show original → Download Original).
2. Redact the recipient side per §3.
3. Decide the label per §4. If unsure, skip.
4. Save to `corpus/sponsorship/private/{scam,legit}/` with a descriptive name,
   e.g. `scam_fake-audible-typosquat.eml`, `legit_esp-routed-squarespace.eml`.
5. Add a manifest row: `filename, source=real, notes` (pattern covered + why you
   labeled it, especially for borderline).
6. Re-run the harness periodically. Watch the **real-only** table — it appears once
   anything is marked `source=real` and is the only one that counts.

Collect slowly and continuously. The milestone is ~15 real per class (metrics
become meaningful) and the goal is ~30–50 per class (metrics become quotable).
Until then, the harness's job is catching regressions, not producing a headline —
and no number leaves the repo until the real set backs it.

---

## Automated collection (step 1 only)

[`eval/tools/fetch_gmail.py`](tools/fetch_gmail.py) automates **step 1 of §6 only**:
it pulls candidate messages out of your own Gmail into a gitignored review queue.

It deliberately does **not** do steps 2–5. It never labels, never redacts, and
never writes into `scam/` or `legit/`. Everything it fetches lands unlabeled in
`corpus/sponsorship/review/`, and the judgement calls in §3 and §4 remain yours.
See [`eval/tools/README.md`](tools/README.md).
