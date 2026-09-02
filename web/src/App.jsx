import { useMemo, useState } from 'react'
import { EXAMPLES } from './examples.js'

const API_BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

// Verdict string -> CSS modifier for the color band.
const VERDICT_CLASS = {
  Low: 'low',
  Caution: 'caution',
  'High risk': 'high',
  Dangerous: 'danger',
}

// Display order + labels for the finding categories the engine emits.
const CATEGORY_ORDER = ['auth', 'identity', 'links', 'attach', 'content']
const CATEGORY_LABEL = {
  auth: 'Email authentication',
  identity: 'Sender identity',
  links: 'Links',
  attach: 'Attachments',
  content: 'Message content',
}

function groupByCategory(findings) {
  const groups = new Map()
  for (const f of findings) {
    if (!groups.has(f.category)) groups.set(f.category, [])
    groups.get(f.category).push(f)
  }
  // Known categories first (in a stable order), then anything unexpected.
  const keys = [
    ...CATEGORY_ORDER.filter((c) => groups.has(c)),
    ...[...groups.keys()].filter((c) => !CATEGORY_ORDER.includes(c)),
  ]
  return keys.map((c) => [c, groups.get(c)])
}

export default function App() {
  const [emailRaw, setEmailRaw] = useState('')
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const grouped = useMemo(
    () => (report ? groupByCategory(report.findings) : []),
    [report],
  )

  async function analyze() {
    setLoading(true)
    setError('')
    setReport(null)
    try {
      const resp = await fetch(`${API_BASE}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email_raw: emailRaw }),
      })
      const data = await resp.json().catch(() => null)
      if (!resp.ok) {
        setError(data?.detail || `Request failed (${resp.status}).`)
        return
      }
      setReport(data)
    } catch (e) {
      setError(
        `Could not reach the API at ${API_BASE}. Is the backend running? (${e.message})`,
      )
    } finally {
      setLoading(false)
    }
  }

  function loadExample(raw) {
    setEmailRaw(raw)
    setReport(null)
    setError('')
  }

  return (
    <div className="page">
      <header className="site-head">
        <h1>SponsorGuard</h1>
        <p className="tagline">
          Paste a raw sponsorship email and see exactly why it&rsquo;s safe — or
          not. Every point is backed by evidence from the message itself.
        </p>
      </header>

      <section className="input-card">
        <div className="example-row">
          <span className="example-label">No email handy?</span>
          {EXAMPLES.map((ex) => (
            <button
              key={ex.key}
              type="button"
              className="ghost-btn"
              onClick={() => loadExample(ex.raw)}
              title={ex.hint}
            >
              {ex.label}
            </button>
          ))}
        </div>

        <label htmlFor="email-raw" className="field-label">
          Raw email (.eml or Gmail &rarr; &ldquo;Show original&rdquo;)
        </label>
        <textarea
          id="email-raw"
          value={emailRaw}
          onChange={(e) => setEmailRaw(e.target.value)}
          placeholder="Paste the full raw email here, including headers…"
          spellCheck={false}
          rows={14}
        />

        <div className="actions">
          <button
            type="button"
            className="primary-btn"
            onClick={analyze}
            disabled={loading || !emailRaw.trim()}
          >
            {loading ? 'Analyzing…' : 'Analyze'}
          </button>
          {emailRaw && (
            <button
              type="button"
              className="ghost-btn"
              onClick={() => {
                setEmailRaw('')
                setReport(null)
                setError('')
              }}
            >
              Clear
            </button>
          )}
        </div>

        {error && <p className="error-banner">{error}</p>}
      </section>

      {report && <Report report={report} grouped={grouped} />}
    </div>
  )
}

function Report({ report, grouped }) {
  const band = VERDICT_CLASS[report.verdict] || 'caution'
  return (
    <section className="report" aria-live="polite">
      <div className={`verdict-card verdict-${band}`}>
        <div className="verdict-main">
          <span className="verdict-word">{report.verdict}</span>
          <span className="verdict-score">
            {report.score}
            <span className="verdict-score-max">/100</span>
          </span>
        </div>
        <p className="safe-step">{report.safe_next_step}</p>
      </div>

      {report.auth_available === false && (
        <div className="auth-notice" role="note">
          <strong>Email-authentication checks were skipped.</strong> This paste
          had no <code>Authentication-Results</code> header, so SPF / DKIM /
          DMARC could not be evaluated (they were skipped, not passed). For the
          full check, export the message with Gmail &rarr; &ldquo;Show
          original&rdquo; instead of forwarding or copying the body.
        </div>
      )}

      {report.top_reasons?.length > 0 && (
        <div className="panel">
          <h2>Why</h2>
          <ul className="reasons">
            {report.top_reasons.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="panel">
        <h2>
          Findings{' '}
          <span className="count">
            ({report.findings.length}
            {report.findings.length === 1 ? ' signal' : ' signals'})
          </span>
        </h2>
        {report.findings.length === 0 ? (
          <p className="empty">
            No suspicious signals fired on this message.
          </p>
        ) : (
          grouped.map(([category, items]) => (
            <div key={category} className="cat-group">
              <h3 className="cat-title">
                {CATEGORY_LABEL[category] || category}
              </h3>
              <ul className="finding-list">
                {items.map((f, i) => (
                  <Finding key={`${f.id}-${i}`} finding={f} />
                ))}
              </ul>
            </div>
          ))
        )}
      </div>
    </section>
  )
}

function Finding({ finding }) {
  return (
    <li className={`finding sev-${finding.severity}`}>
      <div className="finding-head">
        <span className="finding-id">{finding.id}</span>
        <span className="finding-points">+{finding.points}</span>
      </div>
      {/*
        SECURITY: `evidence` (and every other field below) is derived from
        untrusted, possibly-hostile email content. It is rendered as a React
        text child, which is HTML-escaped automatically. Never swap this for
        dangerouslySetInnerHTML — a phishing sample must not be able to run
        script in this tool.
      */}
      <div className="finding-evidence">{finding.evidence}</div>
      <p className="finding-explain">{finding.explanation}</p>
      {finding.remediation && (
        <p className="finding-remediate">
          <span className="remediate-label">What to do:</span>{' '}
          {finding.remediation}
        </p>
      )}
    </li>
  )
}
