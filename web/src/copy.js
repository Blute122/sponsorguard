// Human-facing copy: verdict framing and plain-English names for rule IDs.
// The engine's own strings (evidence, explanation) are still shown verbatim in
// the detailed breakdown — this layer only makes the summary readable.

export const VERDICT_META = {
  Low: {
    key: 'safe',
    label: "You're good",
    line: 'This looks like a real offer — safe to reply.',
  },
  Caution: {
    key: 'caution',
    label: 'Double-check this',
    line: "A few things don't add up. Verify before you reply.",
  },
  'High risk': {
    key: 'high',
    label: 'Likely a scam',
    line: "This is probably a scam — don't click or download anything.",
  },
  Dangerous: {
    key: 'danger',
    label: "Don't touch this",
    line: "This is built to hijack your channel. Don't engage.",
  },
}

export const FINDING_COPY = {
  'identity.display_name_impersonation': {
    title: 'Pretending to be a real brand',
    desc: "The sender's name claims a big brand, but the email domain isn't theirs.",
  },
  'identity.typosquat': {
    title: 'Lookalike web address',
    desc: "The sender's domain is a near-copy of the real brand's.",
  },
  'identity.reply_to_mismatch': {
    title: 'Replies go somewhere else',
    desc: 'Your reply would land in a different inbox.',
  },
  'attach.password_protected_archive': {
    title: 'Suspicious locked attachment',
    desc: 'A password-protected file — a classic way to sneak malware past antivirus.',
  },
  'content.credential_request': {
    title: 'Asking for your login',
    desc: 'Real sponsors never need your password or 2FA codes.',
  },
  'content.upfront_fee': {
    title: 'Asking you to pay first',
    desc: 'Brands pay you. Any upfront deposit is a scam.',
  },
  'content.brief_download_pretext': {
    title: "'Download the brief' bait",
    desc: 'Pushing you to open an attachment is the usual malware setup.',
  },
  'content.urgency': {
    title: 'Fake urgency',
    desc: "Pressure to act 'today' is meant to stop you thinking.",
  },
  'content.gift_card_crypto': {
    title: 'Gift card or crypto payment',
    desc: "Untraceable rails legitimate deals don't use.",
  },
  'auth.spf_fail': {
    title: 'Failed sender verification',
    desc: "The email wasn't authorized by the domain it claims.",
  },
  'auth.dmarc_fail': {
    title: 'Failed anti-spoofing check',
    desc: "Fails the brand domain's own protection rules.",
  },
  'auth.dkim_fail': {
    title: 'Tampered signature',
    desc: "The email's integrity signature is invalid.",
  },
  'links.brand_in_subdomain': {
    title: 'Fake brand link',
    desc: 'The link only looks like the brand — it points elsewhere.',
  },
  'links.credential_keywords': {
    title: 'Login-harvesting link',
    desc: 'Points at a sign-in page built to steal credentials.',
  },
  'links.punycode': {
    title: 'Disguised link',
    desc: 'A special-character address used to imitate a real one.',
  },
}

/** Unmapped IDs fall back to the raw id as the title (spec'd behaviour). */
export function humanize(finding) {
  const mapped = FINDING_COPY[finding.id]
  if (mapped) return mapped
  return { title: finding.id, desc: finding.explanation || '' }
}

export const CATEGORY_ORDER = ['auth', 'identity', 'links', 'attach', 'content']

export const CATEGORY_LABEL = {
  auth: 'Sender verification',
  identity: "Who it's from",
  links: 'Links',
  attach: 'Attachments',
  content: 'What it asks for',
}

// Shown for a clean result: each category with zero findings becomes a green
// tick. `needsAuth` items are omitted when the paste had no auth header, so we
// never claim a check passed that never ran.
export const PASS_CHECKS = [
  { cat: 'auth', text: 'Sender verification passed', needsAuth: true },
  { cat: 'identity', text: 'Sender identity matches the brand' },
  { cat: 'links', text: 'No deceptive links' },
  { cat: 'attach', text: 'No risky attachments' },
  { cat: 'content', text: 'No password, payment, or urgency pressure' },
]

export const RED_FLAGS = [
  'A password-protected attachment "brief"',
  "A login link that isn't the brand's real domain",
  'An upfront deposit or "refundable" fee',
  'Pressure to sign today',
  'Replies routed to a free webmail address',
]
