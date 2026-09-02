# Design notes

The frontend implements the "reassuring security + creator energy" system:
bright canvas (`--bg`), deep-emerald identity (green = safe/verified), a lime
marker accent, and one bold colour-blocked verdict moment.

- **Type:** Bricolage Grotesque (700/800) for headings, Hanken Grotesk for
  body/UI, JetBrains Mono for the paste box and evidence strings only. Loaded via
  a Google Fonts `<link>` in `index.html` — no npm dependency added.
- **Icons:** inline SVG in `src/icons.jsx`, all `currentColor`. No icon library.
- **Structure:** `src/copy.js` holds verdict framing, the rule-ID → plain-English
  map, and the clean-result checklist; `src/App.jsx` is the page; `src/styles.css`
  is the single plain stylesheet.

## Choices made where the spec met the existing code

**Verdict header gradients.** Amber and orange are darkened from the flat tokens
(`--g-caution-*`, `--g-high-*`) so white body text clears WCAG AA on the lightest
gradient stop. The flat `--caution` / `--high` tokens are used unchanged wherever
they appear as text or tint on light backgrounds. Green and coral-red needed no
adjustment (4.55:1 and 4.76:1 against white).

**"Why we flagged this" reads `findings`, not `top_reasons`.** `top_reasons` are
pre-joined `"evidence — explanation"` strings; the design calls for friendly
plain-English rows, so the top 3 come from `findings` (already sorted by points
by the scorer) mapped through `FINDING_COPY`.

**Clean-result checklist is derived, not asserted.** The engine emits no positive
signals, so a tick is shown for each *category that produced no findings*. The
sender-verification tick is suppressed when `auth_available` is `false`, so the
UI never claims a check passed that never ran — the skipped-auth note covers that
case instead.

**Friendlier category labels** in the breakdown ("Who it's from", "What it asks
for") rather than the engine's internal names. The rule IDs and raw evidence are
still shown verbatim in each row.

**Unmapped rule IDs** fall back to the raw ID as the title (as specified), with
the engine's own `explanation` as the description rather than a blank line.

## Unchanged

- Real `POST /analyze` call; example chips still load the actual
  `tests/fixtures/*.eml` via Vite `?raw`, so UI and tests can't drift.
- Every email-derived string renders as a React text child.
  `dangerouslySetInnerHTML` appears nowhere in `web/src` except the comment
  warning against it.
- Motion is one reveal on the verdict card plus the scroll-to, both gated behind
  `prefers-reduced-motion`.
