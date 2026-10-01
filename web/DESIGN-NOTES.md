# Design notes

The frontend is positioned for **talent agencies and creator-management teams**:
people who screen inbound sponsorship email on behalf of a roster. The visual
system is a "case file" — each screened email becomes an exhibit with a verdict,
a reference number and an evidence ledger.

## System

- **Palette:** bone paper (`--paper`), ink (`--ink`), deep bottle-green
  (`--green`) for brand/verified, and vermilion (`--signal`) reserved strictly
  for threat evidence. Verdict colours (`--safe`, `--caution`, `--high`,
  `--danger`) are used only for verdict bands, pills and the case-file header.
- **Type:** Instrument Serif for display, Geist for UI, Geist Mono for evidence
  strings, rule IDs and index labels. All three are **self-hosted from npm**
  (`@fontsource/*`) — the page makes no third-party font request, which fits the
  "nothing leaves" posture.
- **Icons:** inline SVG in `src/icons.jsx`, all `currentColor`. No icon library.

## Sections

1. **Hero** (dark) — centred statement over an annotated rendering of the real
   `scam_nordvpn.eml` fixture; the specimen bleeds into the next section.
2. **The threat** (paper) — oversized 200,000+ numeral and an "anatomy" list
   where every line is tied to the rule ID that catches it.
3. **Screening desk** — paste box, optional talent/channel label, specimens.
4. **Case file** — verdict band + score dial, recommended action, evidence
   ledger (rule ID, quoted evidence, points), message headers, per-category
   check states, **Export case file** (print stylesheet) and **Copy summary**.
5. **Triage queue** (dark) — drop up to 50 `.eml` files; each is screened
   (3 concurrent requests), ranked by risk, and opens into its own case file.
   "Load sample inbox" uses the eval corpus via `import.meta.glob(..., '?raw')`.
6. **Method** — gapless bento of the five rule categories with real rule IDs,
   plus the verdict bands.
7. **Proof** — numbers read directly from `eval/report.json`, including the
   harness's own small-sample warning. Nothing is hard-coded.
8. **Closing CTA + footer.**

## Invariants kept

- Real `POST /analyze` call; the API contract is unchanged.
- Every email-derived string (evidence, headers, subjects, file names) renders
  as a React text child. `dangerouslySetInnerHTML` appears nowhere in `web/src`.
- The clean-result checklist is derived, not asserted: a tick only for
  categories with no findings. Sender authentication is shown as **Skipped**
  (never passed) when `auth_available` is `false`, and sender identity is
  **Skipped** when the paste has no From header.
- The triage drop zone ignores new files while a batch is running, so two
  batches never race each other.
- `src/email.js` reads From / Reply-To / Subject for display only — the engine
  still does all real parsing server-side.
- Motion is one reveal on the case file plus scroll-to, both respecting
  `prefers-reduced-motion`.
- The talent/channel label stays in the browser tab; it is never sent to the API.

`design-comps/` holds one rendered image per section, taken from this build.
