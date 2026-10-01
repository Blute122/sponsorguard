// Human-facing copy: verdict framing and plain-English names for rule IDs.
// The engine's own strings (evidence, explanation) are still shown verbatim in
// the evidence ledger — this layer only makes the summary readable.

export const VERDICT_META = {
  Low: {
    key: 'safe',
    label: 'Clear to reply',
    short: 'Clear',
    line: 'Consistent with a genuine offer. Verify the brand independently, then proceed.',
  },
  Caution: {
    key: 'caution',
    label: 'Verify first',
    short: 'Verify',
    line: "Some signals don't add up. Confirm the sender through the brand's own site before anyone replies.",
  },
  'High risk': {
    key: 'high',
    label: 'Likely a scam',
    short: 'Likely scam',
    line: 'Hold this one. No clicks, no downloads, no replies until it is verified out-of-band.',
  },
  Dangerous: {
    key: 'danger',
    label: 'Do not engage',
    short: 'Malicious',
    line: 'Built to take over a creator account. Quarantine it and warn the talent.',
  },
}

export const FINDING_COPY = {
  'identity.display_name_impersonation': {
    title: 'Impersonates a real brand',
    desc: "The sender name claims a known brand; the sending domain isn't theirs.",
  },
  'identity.typosquat': {
    title: 'Lookalike domain',
    desc: "The sender's domain is a near-copy of the brand's real one.",
  },
  'identity.freemail_brand': {
    title: 'Brand name on a free webmail account',
    desc: "Brands send partnership mail from their own domain, not Gmail or Outlook.",
  },
  'identity.reply_to_mismatch': {
    title: 'Replies are rerouted',
    desc: 'A reply would land in a different inbox from the one that sent it.',
  },
  'identity.domain_age': {
    title: 'Newly registered domain',
    desc: 'The sending domain is only days or weeks old — typical of a scam blast.',
  },
  'attach.password_protected_archive': {
    title: 'Password-locked attachment',
    desc: 'An encrypted archive is the standard way to slip malware past scanners.',
  },
  'attach.executable_in_archive': {
    title: 'Program hidden in an archive',
    desc: 'The “brief” contains an executable file, not a document.',
  },
  'attach.executable': {
    title: 'Executable attachment',
    desc: 'A directly runnable or macro-enabled file. No brief needs one.',
  },
  'attach.double_extension': {
    title: 'Disguised file type',
    desc: 'A double extension dresses an executable up as a document.',
  },
  'attach.uninspected_archive': {
    title: 'Archive that cannot be inspected',
    desc: 'A compressed file whose contents could not be checked — a common malware wrapper.',
  },
  'content.credential_request': {
    title: 'Asks for a login',
    desc: 'Genuine sponsors never need a password, 2FA code or account sign-in.',
  },
  'content.upfront_fee': {
    title: 'Asks the creator to pay',
    desc: 'Brands pay talent. Any deposit or “refundable” fee is a scam.',
  },
  'content.brief_download_pretext': {
    title: '“Download the brief” pretext',
    desc: 'Pushing the reader to open a file is the usual malware set-up.',
  },
  'content.urgency': {
    title: 'Manufactured urgency',
    desc: "Deadlines like 'within 24 hours' exist to stop anyone checking.",
  },
  'content.gift_card_crypto': {
    title: 'Gift card or crypto payment',
    desc: "Untraceable payment rails that legitimate deals don't use.",
  },
  'content.text_html_mismatch': {
    title: 'Two versions of the message',
    desc: 'The plain-text and HTML parts say different things — a filter-evasion trick.',
  },
  'auth.spf_fail': {
    title: 'SPF failed',
    desc: "The sending server wasn't authorised by the domain it claims.",
  },
  'auth.dkim_fail': {
    title: 'DKIM signature invalid',
    desc: "The message's integrity signature doesn't verify.",
  },
  'auth.dmarc_fail': {
    title: 'DMARC failed',
    desc: "Fails the domain's own anti-spoofing policy.",
  },
  'auth.dmarc_none': {
    title: 'No DMARC protection',
    desc: 'The domain publishes no anti-spoofing policy. Weak on its own.',
  },
  'links.brand_in_subdomain': {
    title: 'Brand name used as a decoy',
    desc: 'The link only looks like the brand — the real destination is elsewhere.',
  },
  'links.credential_keywords': {
    title: 'Sign-in harvesting link',
    desc: 'Points at a login or verification page on a non-brand domain.',
  },
  'links.punycode': {
    title: 'Disguised characters in a link',
    desc: 'A special-character address built to imitate a real one.',
  },
  'links.text_href_mismatch': {
    title: 'Link text lies about its destination',
    desc: 'The visible address differs from where the link actually goes.',
  },
  'links.known_malware_url': {
    title: 'Known malware link',
    desc: 'Listed on the URLhaus malware feed.',
  },
  'links.known_phishing_url': {
    title: 'Known phishing link',
    desc: 'Listed on the OpenPhish community feed.',
  },
  'links.safe_browsing_flagged': {
    title: 'Flagged by Safe Browsing',
    desc: 'Google Safe Browsing reports this destination as unsafe.',
  },
}

/** Unmapped IDs fall back to the raw id as the title. */
export function humanize(finding) {
  const mapped = FINDING_COPY[finding.id]
  if (mapped) return mapped
  return { title: finding.id, desc: finding.explanation || '' }
}

export const CATEGORY_ORDER = ['auth', 'identity', 'links', 'attach', 'content']

export const CATEGORY_LABEL = {
  auth: 'Sender authentication',
  identity: 'Sender identity',
  links: 'Links',
  attach: 'Attachments',
  content: 'The ask',
}

// Shown for a clean result: each category with zero findings becomes a tick.
// The case file drops `auth` when the paste had no Authentication-Results
// header and `identity` when it had no From header, so we never claim a check
// passed that never ran.
export const PASS_CHECKS = [
  { cat: 'auth', text: 'SPF, DKIM and DMARC raised no failures' },
  { cat: 'identity', text: 'Sender identity is consistent with the brand' },
  { cat: 'links', text: 'No deceptive or credential-harvesting links' },
  { cat: 'attach', text: 'No risky attachments' },
  { cat: 'content', text: 'No login, payment or urgency pressure' },
]

// The anatomy list in the threat section — each line is tied to the rule that
// catches it, so the marketing copy can't claim coverage the engine lacks.
export const RED_FLAGS = [
  { text: 'A password-locked “creative brief” attachment', rule: 'attach.password_protected_archive' },
  { text: "A sign-in link on a domain that isn't the brand's", rule: 'links.credential_keywords' },
  { text: 'A sender domain one character off the real one', rule: 'identity.typosquat' },
  { text: 'A “refundable” deposit before the deal starts', rule: 'content.upfront_fee' },
  { text: 'Replies quietly routed to a webmail inbox', rule: 'identity.reply_to_mismatch' },
]

// The five lenses in the method section. Rule IDs listed are real registry IDs.
export const LENSES = [
  {
    cat: 'auth',
    title: 'Sender authentication',
    body: 'Reads the receiving server’s SPF, DKIM and DMARC results. Skipped — and labelled as skipped — when the paste has no Authentication-Results header.',
    rules: ['auth.spf_fail', 'auth.dkim_fail', 'auth.dmarc_fail', 'auth.dmarc_none'],
  },
  {
    cat: 'identity',
    title: 'Sender identity',
    body: 'Brand names in the display name against the domain that actually sent it. Lookalikes, webmail impersonation, rerouted replies.',
    rules: ['identity.display_name_impersonation', 'identity.typosquat', 'identity.freemail_brand', 'identity.reply_to_mismatch'],
  },
  {
    cat: 'links',
    title: 'Links',
    body: 'Where each link really goes, not what it says. Decoy subdomains, punycode, sign-in pages.',
    rules: ['links.brand_in_subdomain', 'links.credential_keywords', 'links.punycode', 'links.text_href_mismatch'],
  },
  {
    cat: 'attach',
    title: 'Attachments',
    body: 'Opens archives without executing them. Encrypted zips, programs inside “briefs”, double extensions.',
    rules: ['attach.password_protected_archive', 'attach.executable_in_archive', 'attach.double_extension'],
  },
  {
    cat: 'content',
    title: 'The ask',
    body: 'What the email wants the creator to do: log in, pay a deposit, download now, pay in gift cards.',
    rules: ['content.credential_request', 'content.upfront_fee', 'content.brief_download_pretext', 'content.urgency'],
  },
]
