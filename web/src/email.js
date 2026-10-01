// Minimal, display-only header reader. The engine does the real parsing on the
// server; this only pulls From / Reply-To / To / Subject so a case file can say
// which message it is about. Every value is rendered as a React text child.

const WANTED = ['from', 'reply-to', 'to', 'subject']
const MAX = 160

export function readHeaders(raw) {
  const out = {}
  if (!raw) return out
  const head = raw.split(/\r?\n\r?\n/, 1)[0]
  // Unfold continuation lines (RFC 5322 §2.2.3).
  const lines = head.replace(/\r?\n[ \t]+/g, ' ').split(/\r?\n/)
  for (const line of lines) {
    const i = line.indexOf(':')
    if (i < 1) continue
    const name = line.slice(0, i).trim().toLowerCase()
    if (WANTED.includes(name) && !(name in out)) {
      const v = line.slice(i + 1).trim()
      out[name] = v.length > MAX ? `${v.slice(0, MAX)}…` : v
    }
  }
  return out
}

/** Short, stable reference for a pasted message (not a security hash). */
export function caseRef(raw) {
  let h = 5381
  for (let i = 0; i < raw.length; i++) h = ((h << 5) + h + raw.charCodeAt(i)) >>> 0
  return `SG-${h.toString(36).toUpperCase().slice(-5).padStart(5, '0')}`
}

export function summaryText(report, headers, ref) {
  const lines = [
    `SponsorGuard case file ${ref}`,
    `Verdict: ${report.verdict} (${report.score}/100)`,
  ]
  if (headers.from) lines.push(`From: ${headers.from}`)
  if (headers.subject) lines.push(`Subject: ${headers.subject}`)
  lines.push('', `Action: ${report.safe_next_step}`)
  if (report.findings?.length) {
    lines.push('', 'Evidence:')
    for (const f of report.findings) lines.push(`  +${f.points}  ${f.id}  —  ${f.evidence}`)
  }
  if (report.auth_available === false) {
    lines.push('', 'Note: SPF/DKIM/DMARC were skipped (no Authentication-Results header).')
  }
  return lines.join('\n')
}
