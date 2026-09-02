import { useEffect, useMemo, useRef, useState } from 'react'
import { EXAMPLES } from './examples.js'
import {
  CATEGORY_LABEL,
  CATEGORY_ORDER,
  PASS_CHECKS,
  RED_FLAGS,
  VERDICT_META,
  humanize,
} from './copy.js'
import {
  CategoryIcon,
  Check,
  ChevronDown,
  Flag,
  Lock,
  ShieldCheck,
} from './icons.jsx'

const API_BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

function groupByCategory(findings) {
  const groups = new Map()
  for (const f of findings) {
    if (!groups.has(f.category)) groups.set(f.category, [])
    groups.get(f.category).push(f)
  }
  const keys = [
    ...CATEGORY_ORDER.filter((c) => groups.has(c)),
    ...[...groups.keys()].filter((c) => !CATEGORY_ORDER.includes(c)),
  ]
  return keys.map((c) => [c, groups.get(c)])
}

function prefersReducedMotion() {
  return (
    typeof window !== 'undefined' &&
    window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
  )
}

function scrollToId(id) {
  document.getElementById(id)?.scrollIntoView({
    behavior: prefersReducedMotion() ? 'auto' : 'smooth',
    block: 'start',
  })
}

export default function App() {
  const [emailRaw, setEmailRaw] = useState('')
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const verdictRef = useRef(null)

  const grouped = useMemo(
    () => (report ? groupByCategory(report.findings) : []),
    [report],
  )

  // The one piece of motion: bring the verdict into view once it lands.
  useEffect(() => {
    if (!report || !verdictRef.current) return
    verdictRef.current.scrollIntoView({
      behavior: prefersReducedMotion() ? 'auto' : 'smooth',
      block: 'start',
    })
  }, [report])

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
    scrollToId('tool')
  }

  return (
    <>
      <SiteNav />

      <main>
        <section className="hero">
          <div className="wrap hero-inner">
            <p className="kicker">
              <span className="kicker-dot" aria-hidden="true" />
              Free · Nothing stored
            </p>
            <h1 className="hero-title">
              Know if that brand deal is{' '}
              <span className="swipe">real</span>.
            </h1>
            <p className="hero-sub">
              Paste a sponsorship email and get a straight answer in seconds —
              with the exact reasons behind it.
            </p>
          </div>
        </section>

        <section className="tool-wrap" id="tool">
          <div className="wrap">
            <div className="tool">
              <label htmlFor="email-raw" className="tool-label">
                Paste the email
                <span className="tool-hint">
                  .eml file, or Gmail → &ldquo;Show original&rdquo;
                </span>
              </label>
              <textarea
                id="email-raw"
                value={emailRaw}
                onChange={(e) => setEmailRaw(e.target.value)}
                placeholder="Paste the full email here, including the headers…"
                spellCheck={false}
                rows={11}
              />

              <div className="tool-actions">
                <button
                  type="button"
                  className="btn-primary btn-lg"
                  onClick={analyze}
                  disabled={loading || !emailRaw.trim()}
                >
                  {loading ? 'Checking…' : 'Check this email'}
                </button>
                {emailRaw && (
                  <button
                    type="button"
                    className="btn-quiet"
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

              <div className="chips">
                <span className="chips-label">Or try</span>
                {EXAMPLES.map((ex) => (
                  <button
                    key={ex.key}
                    type="button"
                    className={`chip chip-${ex.tone}`}
                    onClick={() => loadExample(ex.raw)}
                    title={ex.hint}
                  >
                    {ex.label}
                  </button>
                ))}
              </div>

              {error && (
                <p className="error" role="alert">
                  {error}
                </p>
              )}

              <p className="privacy">
                <Lock size={15} />
                Checked in memory and never stored. Nothing leaves your machine
                but the text you paste.
              </p>
            </div>
          </div>
        </section>

        {report && (
          <div ref={verdictRef}>
            <Verdict report={report} grouped={grouped} />
          </div>
        )}

        <HowItWorks />
        <WhyItMatters />
        <TrustStrip />
      </main>

      <SiteFooter />
    </>
  )
}

function SiteNav() {
  return (
    <header className="nav">
      <div className="wrap nav-inner">
        <a className="logo" href="#top">
          <span className="logo-mark">
            <ShieldCheck size={20} strokeWidth={2.4} />
          </span>
          <span className="logo-word">SponsorGuard</span>
        </a>
        <nav className="nav-links">
          <a href="#how">How it works</a>
          <a href="#why">Why it matters</a>
        </nav>
        <button
          type="button"
          className="btn-primary"
          onClick={() => scrollToId('tool')}
        >
          Check an email
        </button>
      </div>
    </header>
  )
}

function Verdict({ report, grouped }) {
  const [showAll, setShowAll] = useState(false)
  const meta = VERDICT_META[report.verdict] ?? VERDICT_META.Caution
  const findings = report.findings ?? []
  const isClean = findings.length === 0
  const top = findings.slice(0, 3)

  const flaggedCats = new Set(findings.map((f) => f.category))
  const passed = PASS_CHECKS.filter(
    (c) => !flaggedCats.has(c.cat) && !(c.needsAuth && report.auth_available === false),
  )

  return (
    <section className="verdict-section" aria-live="polite">
      <div className="wrap">
        <article className={`verdict verdict-${meta.key}`}>
          <div className="verdict-head">
            <span className="verdict-icon" aria-hidden="true">
              <ShieldCheck size={30} strokeWidth={2.2} />
            </span>
            <div className="verdict-head-text">
              <h2 className="verdict-label">{meta.label}</h2>
              <p className="verdict-line">{meta.line}</p>
            </div>
            <span className="risk-pill">Risk {report.score}/100</span>
          </div>

          <div className="verdict-body">
            <div className="todo">
              <h3>What to do</h3>
              <p>{report.safe_next_step}</p>
            </div>

            {report.auth_available === false && (
              <p className="auth-note" role="note">
                Email-authentication checks were skipped — this paste had no{' '}
                <code>Authentication-Results</code> header, so SPF, DKIM and
                DMARC could not be checked (skipped, not passed). Use Gmail →
                &ldquo;Show original&rdquo; for the full check.
              </p>
            )}

            {isClean ? (
              <div className="passed">
                <h3>What checked out</h3>
                <ul className="pass-list">
                  {passed.map((c) => (
                    <li key={c.cat}>
                      <span className="pass-tick" aria-hidden="true">
                        <Check size={16} />
                      </span>
                      {c.text}
                    </li>
                  ))}
                </ul>
              </div>
            ) : (
              <>
                <div className="why">
                  <h3>Why we flagged this</h3>
                  <ul className="why-list">
                    {top.map((f, i) => {
                      const copy = humanize(f)
                      return (
                        <li key={`${f.id}-${i}`}>
                          <span
                            className={`why-icon sev-${f.severity}`}
                            aria-hidden="true"
                          >
                            <CategoryIcon category={f.category} size={18} />
                          </span>
                          <span className="why-text">
                            <strong>{copy.title}</strong>
                            <span>{copy.desc}</span>
                          </span>
                        </li>
                      )
                    })}
                  </ul>
                </div>

                <button
                  type="button"
                  className="expander"
                  aria-expanded={showAll}
                  onClick={() => setShowAll((v) => !v)}
                >
                  <span className={`expander-caret ${showAll ? 'open' : ''}`}>
                    <ChevronDown size={17} />
                  </span>
                  {showAll ? 'Hide the full breakdown' : `See all ${findings.length} signals`}
                </button>

                {showAll && (
                  <div className="breakdown">
                    {grouped.map(([category, items]) => (
                      <div key={category} className="bd-group">
                        <h4 className="bd-title">
                          {CATEGORY_LABEL[category] || category}
                        </h4>
                        <ul className="bd-list">
                          {items.map((f, i) => {
                            const copy = humanize(f)
                            return (
                              <li key={`${f.id}-${i}`} className="bd-item">
                                <div className="bd-head">
                                  <span className="bd-name">{copy.title}</span>
                                  <span className="bd-points">+{f.points}</span>
                                </div>
                                {copy.desc && (
                                  <p className="bd-desc">{copy.desc}</p>
                                )}
                                {/*
                                  SECURITY: `evidence` comes from untrusted,
                                  possibly-hostile email content. It is rendered
                                  as a React text child and therefore escaped.
                                  Never switch this to dangerouslySetInnerHTML.
                                */}
                                <code className="bd-evidence">{f.evidence}</code>
                              </li>
                            )
                          })}
                        </ul>
                      </div>
                    ))}
                  </div>
                )}
              </>
            )}
          </div>
        </article>
      </div>
    </section>
  )
}

const STEPS = [
  {
    n: '1',
    title: 'Paste the email',
    body: 'Open the message, choose "Show original" (or save the .eml), and drop the whole thing in.',
  },
  {
    n: '2',
    title: 'We read the signals',
    body: 'Sender verification, lookalike domains, link destinations, attachments and the ask itself — all checked locally.',
  },
  {
    n: '3',
    title: 'You get a straight answer',
    body: 'One clear verdict, plus every reason behind it quoted from the message itself.',
  },
]

function HowItWorks() {
  return (
    <section className="how" id="how">
      <div className="wrap">
        <h2 className="section-title">How it works</h2>
        <div className="steps">
          {STEPS.map((s) => (
            <div className="step" key={s.n}>
              <span className="step-badge">{s.n}</span>
              <h3>{s.title}</h3>
              <p>{s.body}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

function WhyItMatters() {
  return (
    <section className="why-matters" id="why">
      <div className="wrap why-inner">
        <div className="why-stat">
          <span className="stat-num">200,000+</span>
          <span className="stat-cap">
            creators reportedly targeted in a single campaign that used lookalike
            domains and fake brand deals to hijack YouTube channels.
          </span>
        </div>
        <div className="why-flags">
          <h3>What these emails look like</h3>
          <ul>
            {RED_FLAGS.map((f) => (
              <li key={f}>
                <span className="flag-icon" aria-hidden="true">
                  <Flag size={16} />
                </span>
                {f}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  )
}

const TRUST = [
  'Checks only what you paste',
  'Never stored, never forwarded',
  'Every verdict shows its reasons',
]

function TrustStrip() {
  return (
    <section className="trust">
      <div className="wrap trust-inner">
        {TRUST.map((t) => (
          <div className="trust-item" key={t}>
            <span className="trust-icon" aria-hidden="true">
              <Check size={17} />
            </span>
            {t}
          </div>
        ))}
      </div>
    </section>
  )
}

function SiteFooter() {
  return (
    <footer className="footer">
      <div className="wrap footer-inner">
        <span className="logo">
          <span className="logo-mark logo-mark-sm">
            <ShieldCheck size={16} strokeWidth={2.4} />
          </span>
          <span className="logo-word">SponsorGuard</span>
        </span>
        <p>
          A defensive tool for creators. It analyses emails you already received
          — it never sends, scrapes, or profiles anyone.
        </p>
      </div>
    </footer>
  )
}
