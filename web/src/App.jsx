import { useEffect, useMemo, useRef, useState } from 'react'
import { EXAMPLES, SAMPLE_INBOX } from './examples.js'
import { caseRef, readHeaders, summaryText } from './email.js'
import evalReport from '../../eval/report.json'
import {
  CATEGORY_LABEL,
  CATEGORY_ORDER,
  LENSES,
  PASS_CHECKS,
  RED_FLAGS,
  VERDICT_META,
  humanize,
} from './copy.js'
import {
  ArrowRight,
  CategoryIcon,
  Check,
  ChevronDown,
  CopyIcon,
  Lock,
  Minus,
  Printer,
  ShieldCheck,
  Upload,
} from './icons.jsx'

// Dev talks to the local uvicorn server; the production build is served from
// the same origin as the API (see app.py), so it uses the relative /api path.
const API_BASE = import.meta.env.VITE_API_URL ?? (import.meta.env.DEV ? 'http://localhost:8000' : '/api')

const MAX_BATCH = 50
const BATCH_CONCURRENCY = 3

async function analyzeRaw(raw) {
  let resp
  try {
    resp = await fetch(`${API_BASE}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email_raw: raw }),
    })
  } catch (e) {
    throw new Error(`Could not reach the scanner at ${API_BASE}. Is the API running? (${e.message})`)
  }
  const data = await resp.json().catch(() => null)
  if (!resp.ok) throw new Error(data?.detail || `Request failed (${resp.status}).`)
  return data
}

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
  const [talent, setTalent] = useState('')
  // `active` is the case file on screen: { report, raw, talent, source }.
  const [active, setActive] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const caseRefEl = useRef(null)

  useEffect(() => {
    if (!active || !caseRefEl.current) return
    caseRefEl.current.scrollIntoView({
      behavior: prefersReducedMotion() ? 'auto' : 'smooth',
      block: 'start',
    })
  }, [active])

  async function screen() {
    setLoading(true)
    setError('')
    setActive(null)
    try {
      const report = await analyzeRaw(emailRaw)
      setActive({ report, raw: emailRaw, talent: talent.trim(), source: 'desk' })
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  function loadExample(raw) {
    setEmailRaw(raw)
    setActive(null)
    setError('')
  }

  return (
    <>
      <SiteNav />

      <main>
        <Hero />
        <ThreatBrief />

        <section className="desk" id="scanner" aria-labelledby="desk-title">
          <div className="wrap">
            <header className="desk-head">
              <p className="index-label">01 — Screening desk</p>
              <h2 id="desk-title" className="display-2">
                Paste the email. <em>Get the case file.</em>
              </h2>
              <p className="desk-sub">
                Use the raw message — Gmail <span className="nowrap">→ “Show original”</span>, Outlook
                “View source”, or a saved <code>.eml</code> — so sender authentication can be checked too.
              </p>
            </header>

            <div className="console">
              <div className="console-bar">
                <span className="console-dots" aria-hidden="true"><i /><i /><i /></span>
                <span className="console-title">New screening</span>
                <span className="console-meta">
                  <Lock size={13} /> Analysed in memory · never stored
                </span>
              </div>

              <div className="console-body">
                <div className="console-main">
                  <label htmlFor="email-raw" className="field-label">
                    Raw message
                    <span className="field-hint">headers + body</span>
                  </label>
                  <textarea
                    id="email-raw"
                    value={emailRaw}
                    onChange={(e) => setEmailRaw(e.target.value)}
                    placeholder={'From: Brand Partnerships <partners@brand.com>\nSubject: Paid integration — Q3\nAuthentication-Results: …\n\nPaste the full message here.'}
                    spellCheck={false}
                    rows={13}
                  />
                </div>

                <aside className="console-side">
                  <div className="field">
                    <label htmlFor="talent" className="field-label">
                      Talent or channel
                      <span className="field-hint">optional</span>
                    </label>
                    <input
                      id="talent"
                      type="text"
                      value={talent}
                      onChange={(e) => setTalent(e.target.value)}
                      placeholder="e.g. Priya · Tech reviews"
                      maxLength={60}
                      autoComplete="off"
                    />
                    <p className="field-note">Printed on the case file. Stays in this browser tab.</p>
                  </div>

                  <div className="field">
                    <span className="field-label">Try a specimen</span>
                    <div className="specimen-picks">
                      {EXAMPLES.map((ex) => (
                        <button
                          key={ex.key}
                          type="button"
                          className={`pick pick-${ex.tone}`}
                          onClick={() => loadExample(ex.raw)}
                        >
                          <span className="pick-dot" aria-hidden="true" />
                          {ex.label}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="console-actions">
                    <button
                      type="button"
                      className="btn btn-primary btn-block"
                      onClick={screen}
                      disabled={loading || !emailRaw.trim()}
                    >
                      {loading ? 'Screening…' : 'Screen this email'}
                      {!loading && <ArrowRight size={17} />}
                    </button>
                    {emailRaw && (
                      <button
                        type="button"
                        className="btn-text"
                        onClick={() => {
                          setEmailRaw('')
                          setActive(null)
                          setError('')
                        }}
                      >
                        Clear
                      </button>
                    )}
                  </div>

                  {error && (
                    <p className="error" role="alert">
                      {error}
                    </p>
                  )}
                </aside>
              </div>
            </div>
          </div>
        </section>

        {active && (
          <div ref={caseRefEl} className="case-anchor">
            <CaseFile key={caseRef(active.raw)} {...active} />
          </div>
        )}

        <TriageQueue onOpen={(row) => setActive(row)} />
        <Method />
        <Proof />
        <Closing />
      </main>

      <SiteFooter />
    </>
  )
}

/* ------------------------------------------------------------------ nav */

function SiteNav() {
  return (
    <header className="nav">
      <div className="wrap nav-inner">
        <a className="logo" href="#top" aria-label="SponsorGuard home">
          <span className="logo-mark">
            <ShieldCheck size={18} strokeWidth={2.2} />
          </span>
          <span className="logo-word">SponsorGuard</span>
        </a>
        <nav className="nav-links" aria-label="Sections">
          <a href="#threat">The threat</a>
          <a href="#triage">Triage</a>
          <a href="#method">Method</a>
          <a href="#proof">Proof</a>
        </nav>
        <button type="button" className="btn btn-light btn-sm" onClick={() => scrollToId('scanner')}>
          Open the desk
        </button>
      </div>
    </header>
  )
}

/* ----------------------------------------------------------------- hero */

function Hero() {
  return (
    <section className="hero" aria-labelledby="hero-title">
      <div className="hero-grid" aria-hidden="true" />
      <div className="wrap hero-inner">
        <p className="hero-kicker">Inbound deal screening for talent teams</p>
        <h1 id="hero-title" className="hero-title">
          Vet every brand deal <em>before</em> your talent opens it.
        </h1>
        <p className="hero-sub">
          SponsorGuard reads sponsorship email the way a security analyst would — sender
          authentication, lookalike domains, link destinations, attachments — and shows its
          working on every verdict.
        </p>
        <div className="hero-ctas">
          <button type="button" className="btn btn-light" onClick={() => scrollToId('scanner')}>
            Screen an email <ArrowRight size={17} />
          </button>
          <button type="button" className="btn-link btn-link-light" onClick={() => scrollToId('triage')}>
            Triage a whole inbox
          </button>
        </div>

        <Specimen />
      </div>
    </section>
  )
}

// A static rendering of the real tests/fixtures/scam_nordvpn.eml, annotated.
function Specimen() {
  return (
    <figure className="specimen" aria-label="An annotated scam email, as SponsorGuard sees it">
      <div className="specimen-sheet">
        <div className="sheet-head">
          <span className="sheet-tag">Exhibit A</span>
          <span className="sheet-file">scam_nordvpn.eml</span>
        </div>
        <dl className="sheet-meta">
          <div><dt>From</dt><dd>NordVPN Partnerships &lt;partnerships@<mark data-n="1">n0rdvpn-press.com</mark>&gt;</dd></div>
          <div><dt>Reply-To</dt><dd><mark data-n="2">nordvpn.deals@gmail.com</mark></dd></div>
          <div><dt>Subject</dt><dd>NordVPN Sponsorship Offer — $5000 Deal (Action Required within 24 hours)</dd></div>
          <div><dt>Auth</dt><dd><mark data-n="3">spf=fail · dkim=fail · dmarc=fail</mark></dd></div>
        </dl>
        <div className="sheet-body">
          <p>Hi! We at NordVPN want to sponsor your channel for $5000.</p>
          <p>To confirm, please <u>verify your account</u> here. Download the creative brief (password in the file). Offer expires today — act now!</p>
          <p className="sheet-attach">
            <mark data-n="4">creative_brief.zip</mark>
            <span>encrypted · contains creative_brief.exe</span>
          </p>
        </div>
      </div>

      <ol className="callouts">
        <li><b>1</b><span>Lookalike of nordvpn.com</span><code>identity.typosquat</code></li>
        <li><b>2</b><span>Replies go to Gmail</span><code>identity.reply_to_mismatch</code></li>
        <li><b>3</b><span>Fails all three auth checks</span><code>auth.*_fail</code></li>
        <li><b>4</b><span>Password-locked “brief”</span><code>attach.password_protected_archive</code></li>
      </ol>

      <div className="stamp" aria-hidden="true">
        <span className="stamp-k">Verdict</span>
        <span className="stamp-v">Do not engage</span>
        <span className="stamp-s">100 / 100 · 13 signals</span>
      </div>
    </figure>
  )
}

/* --------------------------------------------------------------- threat */

function ThreatBrief() {
  return (
    <section className="threat" id="threat" aria-labelledby="threat-title">
      <div className="wrap threat-grid">
        <div className="threat-num" aria-hidden="true">
          200,000<span>+</span>
        </div>
        <div className="threat-copy">
          <p className="index-label">The threat</p>
          <h2 id="threat-title" className="display-2">
            The sponsorship inbox is now an attack surface.
          </h2>
          <p className="lede">
            Creators were reportedly targeted in a single campaign that used lookalike domains and
            fake brand deals to hijack YouTube channels. The emails are polished, the offers are
            plausible, and they arrive in the same inbox as your real deals.
          </p>
        </div>
        <div className="anatomy">
          <h3 className="anatomy-title">Anatomy of a fake deal</h3>
          <ol>
            {RED_FLAGS.map((f, i) => (
              <li key={f.rule}>
                <span className="anatomy-n">{String(i + 1).padStart(2, '0')}</span>
                <span className="anatomy-t">{f.text}</span>
                <code className="anatomy-r">{f.rule}</code>
              </li>
            ))}
          </ol>
        </div>
      </div>
    </section>
  )
}

/* ------------------------------------------------------------ case file */

function CaseFile({ report, raw, talent }) {
  const [copied, setCopied] = useState(false)
  const [showAll, setShowAll] = useState(false)
  const meta = VERDICT_META[report.verdict] ?? VERDICT_META.Caution
  const findings = report.findings ?? []
  const isClean = findings.length === 0
  const headers = useMemo(() => readHeaders(raw), [raw])
  const ref = useMemo(() => caseRef(raw), [raw])
  const grouped = useMemo(() => groupByCategory(findings), [findings])
  const flaggedCats = new Set(findings.map((f) => f.category))
  const authSkipped = report.auth_available === false
  // With no From header there is no sender to compare against a brand.
  const identitySkipped = !headers.from
  const skippedCats = new Set([authSkipped && 'auth', identitySkipped && 'identity'].filter(Boolean))
  const passed = PASS_CHECKS.filter((c) => !flaggedCats.has(c.cat) && !skippedCats.has(c.cat))
  const LEDGER_PREVIEW = 5

  async function copySummary() {
    try {
      await navigator.clipboard.writeText(summaryText(report, headers, ref))
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    } catch {
      setCopied(false)
    }
  }

  return (
    <section className={`case case-${meta.key}`} aria-live="polite" aria-label="Case file">
      <div className="wrap">
        <article className="case-file">
          <header className="case-band">
            <div className="case-band-left">
              <p className="case-ref">
                Case file <span>{ref}</span>
                {talent && <span className="case-talent">· {talent}</span>}
              </p>
              <h2 className="case-verdict">{meta.label}</h2>
              <p className="case-line">{meta.line}</p>
            </div>
            <ScoreDial score={report.score} verdict={report.verdict} />
          </header>

          <div className="case-grid">
            <div className="case-main">
              <div className="case-action">
                <span className="index-label">Recommended action</span>
                <p>{report.safe_next_step}</p>
              </div>

              {authSkipped && (
                <p className="auth-note" role="note">
                  Sender authentication was <strong>skipped, not passed</strong> — this paste had no{' '}
                  <code>Authentication-Results</code> header. Paste the raw message (Gmail → “Show
                  original”) for the full check.
                </p>
              )}

              {isClean ? (
                <div className="clear-list">
                  <span className="index-label">What checked out</span>
                  <ul>
                    {passed.map((c) => (
                      <li key={c.cat}>
                        <span className="tick" aria-hidden="true"><Check size={15} /></span>
                        {c.text}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : (
                <div className="ledger">
                  <div className="ledger-head">
                    <span className="index-label">Evidence ledger</span>
                    <span className="ledger-count">{findings.length} signal{findings.length === 1 ? '' : 's'}</span>
                  </div>
                  <ol className={`ledger-rows ${showAll ? '' : 'is-collapsed'}`}>
                    {findings.map((f, i) => {
                      const copy = humanize(f)
                      return (
                        <li
                          key={`${f.id}-${i}`}
                          className={`ledger-row sev-${f.severity}${i >= LEDGER_PREVIEW ? ' is-extra' : ''}`}
                        >
                          <span className="lr-icon" aria-hidden="true">
                            <CategoryIcon category={f.category} size={17} />
                          </span>
                          <div className="lr-text">
                            <strong>{copy.title}</strong>
                            {copy.desc && <span>{copy.desc}</span>}
                            <code className="lr-id">{f.id}</code>
                          </div>
                          {/*
                            SECURITY: `evidence` comes from untrusted, possibly
                            hostile email content. It is rendered as a React text
                            child and therefore escaped. Never switch this to
                            dangerouslySetInnerHTML.
                          */}
                          <code className="lr-evidence">{f.evidence}</code>
                          <span className="lr-points">+{f.points}</span>
                        </li>
                      )
                    })}
                  </ol>
                  {findings.length > LEDGER_PREVIEW && (
                    <button
                      type="button"
                      className="expander"
                      aria-expanded={showAll}
                      onClick={() => setShowAll((v) => !v)}
                    >
                      <span className={`expander-caret ${showAll ? 'open' : ''}`}>
                        <ChevronDown size={16} />
                      </span>
                      {showAll ? 'Show fewer' : `Show all ${findings.length} signals`}
                    </button>
                  )}
                </div>
              )}
            </div>

            <aside className="case-rail">
              <div className="rail-block">
                <span className="index-label">Message</span>
                <dl className="msg-meta">
                  {headers.from && (<div><dt>From</dt><dd>{headers.from}</dd></div>)}
                  {headers['reply-to'] && (<div><dt>Reply-To</dt><dd>{headers['reply-to']}</dd></div>)}
                  {headers.subject && (<div><dt>Subject</dt><dd>{headers.subject}</dd></div>)}
                  {!headers.from && !headers.subject && (
                    <div><dt>—</dt><dd>No headers found in the paste.</dd></div>
                  )}
                </dl>
              </div>

              <div className="rail-block">
                <span className="index-label">Checks</span>
                <ul className="check-list">
                  {CATEGORY_ORDER.map((cat) => {
                    const n = grouped.find(([c]) => c === cat)?.[1].length ?? 0
                    const skipped = skippedCats.has(cat) && n === 0
                    const state = skipped ? 'skip' : n ? 'flag' : 'ok'
                    return (
                      <li key={cat} className={`check-${state}`}>
                        <span className="check-ic" aria-hidden="true">
                          {state === 'ok' ? <Check size={13} /> : state === 'skip' ? <Minus size={13} /> : n}
                        </span>
                        <span>{CATEGORY_LABEL[cat]}</span>
                        <span className="check-state">
                          {state === 'ok' ? 'Clear' : state === 'skip' ? 'Skipped' : 'Flagged'}
                        </span>
                      </li>
                    )
                  })}
                </ul>
              </div>

              <div className="rail-actions">
                <button type="button" className="btn btn-outline btn-sm" onClick={() => window.print()}>
                  <Printer /> Export case file
                </button>
                <button type="button" className="btn-text" onClick={copySummary}>
                  <CopyIcon /> {copied ? 'Copied' : 'Copy summary'}
                </button>
              </div>
            </aside>
          </div>
        </article>
      </div>
    </section>
  )
}

function ScoreDial({ score, verdict }) {
  const pct = Math.max(0, Math.min(100, score))
  return (
    <div className="dial" role="img" aria-label={`Risk score ${score} out of 100, ${verdict}`}>
      <div className="dial-num">
        {score}
        <span>/100</span>
      </div>
      <div className="dial-track" aria-hidden="true">
        <span className="dial-fill" style={{ width: `${pct}%` }} />
        <i style={{ left: '15%' }} />
        <i style={{ left: '35%' }} />
        <i style={{ left: '60%' }} />
      </div>
      <div className="dial-scale" aria-hidden="true">
        <span>Clear</span><span>Verify</span><span>Scam</span><span>Malicious</span>
      </div>
    </div>
  )
}

/* --------------------------------------------------------------- triage */

function TriageQueue({ onOpen }) {
  const [rows, setRows] = useState([])
  const [busy, setBusy] = useState(false)
  const [dragging, setDragging] = useState(false)
  const [notice, setNotice] = useState('')
  const inputRef = useRef(null)

  async function run(items) {
    const list = items.slice(0, MAX_BATCH)
    setNotice(items.length > MAX_BATCH ? `Only the first ${MAX_BATCH} emails were queued.` : '')
    const base = list.map((it, i) => ({
      id: `${Date.now()}-${i}`,
      name: it.name,
      raw: it.raw,
      headers: readHeaders(it.raw),
      status: 'queued',
    }))
    setRows(base)
    setBusy(true)
    let next = 0
    async function worker() {
      while (next < base.length) {
        const idx = next++
        const row = base[idx]
        try {
          const report = await analyzeRaw(row.raw)
          setRows((rs) => rs.map((r) => (r.id === row.id ? { ...r, status: 'done', report } : r)))
        } catch (e) {
          setRows((rs) => rs.map((r) => (r.id === row.id ? { ...r, status: 'error', error: e.message } : r)))
        }
      }
    }
    await Promise.all(Array.from({ length: BATCH_CONCURRENCY }, worker))
    setBusy(false)
  }

  async function fromFiles(fileList) {
    // A second batch would race the first one's workers and clear `busy` early.
    if (busy) return
    const files = [...fileList].filter((f) => /\.(eml|txt)$/i.test(f.name) || f.type === 'message/rfc822')
    if (!files.length) {
      setNotice('Drop .eml files — one email per file.')
      return
    }
    const items = await Promise.all(files.map(async (f) => ({ name: f.name, raw: await f.text() })))
    run(items)
  }

  const sorted = useMemo(() => {
    const score = (r) => (r.status === 'done' ? r.report.score : r.status === 'error' ? -1 : -2)
    return [...rows].sort((a, b) => score(b) - score(a))
  }, [rows])

  const done = rows.filter((r) => r.status === 'done')
  const attention = done.filter((r) => r.report.verdict !== 'Low').length

  return (
    <section className="triage" id="triage" aria-labelledby="triage-title">
      <div className="wrap">
        <header className="triage-head">
          <div>
            <p className="index-label">02 — Triage queue</p>
            <h2 id="triage-title" className="display-2">
              One inbox, <em>many creators.</em>
            </h2>
          </div>
          <p className="triage-sub">
            Drop a stack of <code>.eml</code> files from a shared partnerships inbox. Each one is
            screened, ranked by risk, and opens into its own case file.
          </p>
        </header>

        <div className="triage-board">
          <div
            className={`dropzone ${dragging ? 'is-over' : ''}`}
            onDragOver={(e) => {
              e.preventDefault()
              if (!busy) setDragging(true)
            }}
            onDragLeave={(e) => {
              // Moving onto a child element fires dragleave on the zone itself.
              if (!e.currentTarget.contains(e.relatedTarget)) setDragging(false)
            }}
            onDrop={(e) => {
              e.preventDefault()
              setDragging(false)
              fromFiles(e.dataTransfer.files)
            }}
          >
            <span className="dz-icon" aria-hidden="true"><Upload /></span>
            <p className="dz-title">Drop .eml files here</p>
            <p className="dz-note">Up to {MAX_BATCH} at a time. Nothing is stored.</p>
            <div className="dz-actions">
              <button type="button" className="btn btn-light btn-sm" onClick={() => inputRef.current?.click()} disabled={busy}>
                Choose files
              </button>
              <button
                type="button"
                className="btn-link btn-link-light"
                onClick={() => run(SAMPLE_INBOX)}
                disabled={busy}
              >
                Load sample inbox ({SAMPLE_INBOX.length})
              </button>
            </div>
            <input
              ref={inputRef}
              type="file"
              accept=".eml,.txt,message/rfc822"
              multiple
              hidden
              onChange={(e) => {
                fromFiles(e.target.files)
                e.target.value = ''
              }}
            />
          </div>

          <div className="queue">
            <div className="queue-head">
              <span>
                {rows.length
                  ? `${done.length} of ${rows.length} screened`
                  : 'Queue is empty'}
              </span>
              {done.length > 0 && (
                <span className="queue-attn">
                  <b>{attention}</b> need attention
                </span>
              )}
            </div>
            {notice && <p className="queue-notice">{notice}</p>}
            {rows.length === 0 ? (
              <div className="queue-empty">
                <p>Screened emails appear here, highest risk first.</p>
              </div>
            ) : (
              <table className="queue-table">
                <thead>
                  <tr>
                    <th scope="col">Sender</th>
                    <th scope="col">Subject</th>
                    <th scope="col">Verdict</th>
                    <th scope="col" className="num">Risk</th>
                    <th scope="col"><span className="sr-only">Open</span></th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((r) => {
                    const meta = r.status === 'done' ? VERDICT_META[r.report.verdict] ?? VERDICT_META.Caution : null
                    return (
                      <tr key={r.id} className={meta ? `row-${meta.key}` : `row-${r.status}`}>
                        <td className="q-sender">
                          <span>{r.headers.from || r.name}</span>
                          <small>{r.name}</small>
                        </td>
                        <td className="q-subject"><span>{r.headers.subject || '—'}</span></td>
                        <td>
                          {meta ? (
                            <span className={`vpill vpill-${meta.key}`}>{meta.short}</span>
                          ) : r.status === 'error' ? (
                            <span className="vpill vpill-error" title={r.error}>Error</span>
                          ) : (
                            <span className="vpill vpill-wait">Screening…</span>
                          )}
                        </td>
                        <td className="num">
                          {r.status === 'done' ? (
                            <span className="q-score">
                              <span className="q-bar" aria-hidden="true"><i style={{ width: `${r.report.score}%` }} /></span>
                              {r.report.score}
                            </span>
                          ) : '—'}
                        </td>
                        <td className="q-open">
                          {r.status === 'done' && (
                            <button
                              type="button"
                              className="q-open-btn"
                              onClick={() => onOpen({ report: r.report, raw: r.raw, talent: '', source: 'triage' })}
                              aria-label={`Open case file for ${r.name}`}
                            >
                              Open <ArrowRight size={14} />
                            </button>
                          )}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </section>
  )
}

/* --------------------------------------------------------------- method */

function Method() {
  return (
    <section className="method" id="method" aria-labelledby="method-title">
      <div className="wrap">
        <header className="method-head">
          <p className="index-label">03 — Method</p>
          <h2 id="method-title" className="display-2">
            Five lenses. <em>No black box.</em>
          </h2>
          <p className="method-sub">
            Every verdict is a sum of named rules, each one quoting the exact string that tripped it.
            Category caps stop one noisy signal from dominating; near-certain attacks — an executable,
            a locked “brief”, a credential ask — force the top verdict outright.
          </p>
        </header>

        <div className="bento">
          {LENSES.map((l, i) => (
            <article key={l.cat} className={`lens lens-${i + 1}`}>
              <div className="lens-top">
                <span className="lens-ic" aria-hidden="true"><CategoryIcon category={l.cat} size={20} /></span>
                <span className="lens-n">{String(i + 1).padStart(2, '0')}</span>
              </div>
              <h3>{l.title}</h3>
              <p>{l.body}</p>
              <ul className="lens-rules">
                {l.rules.map((r) => <li key={r}><code>{r}</code></li>)}
              </ul>
            </article>
          ))}
          <article className="lens lens-band">
            <h3>Verdict bands</h3>
            <ol className="bands">
              <li className="band-safe"><span>0–14</span>Clear to reply</li>
              <li className="band-caution"><span>15–34</span>Verify first</li>
              <li className="band-high"><span>35–59</span>Likely a scam</li>
              <li className="band-danger"><span>60+</span>Do not engage</li>
            </ol>
          </article>
        </div>
      </div>
    </section>
  )
}

/* ---------------------------------------------------------------- proof */

function pct(x) {
  return `${Math.round(x * 100)}%`
}

function Proof() {
  // Numbers come straight from eval/report.json, written by eval/run_eval.py,
  // so this section can't drift from the harness.
  const n = evalReport?.n ?? {}
  const caution = evalReport?.bands?.Caution
  const danger = evalReport?.bands?.Dangerous
  const small = evalReport?.small_sample_warning
  return (
    <section className="proof" id="proof" aria-labelledby="proof-title">
      <div className="wrap">
        <div className="proof-top">
          <p className="index-label">04 — Proof</p>
          {caution && (
            <dl className="metrics">
              <div>
                <dt>Scams flagged</dt>
                <dd>{caution.tp}<span>/{caution.tp + caution.fn}</span></dd>
                <p>at the Verify-first threshold</p>
              </div>
              <div>
                <dt>False alarms</dt>
                <dd>{caution.fp}<span>/{caution.fp + caution.tn}</span></dd>
                <p>genuine offers wrongly flagged</p>
              </div>
              {danger && (
                <div>
                  <dt>Reached “Do not engage”</dt>
                  <dd>{danger.tp}<span>/{danger.tp + danger.fn}</span></dd>
                  <p>recall {pct(danger.recall)} at the top band</p>
                </div>
              )}
              <div>
                <dt>Labelled emails</dt>
                <dd>{n.total}</dd>
                <p>{n.scam} scam · {n.legit} genuine</p>
              </div>
            </dl>
          )}
        </div>

        <div className="proof-bottom">
          <h2 id="proof-title" className="display-2">
            Measured, <em>and honest about it.</em>
          </h2>
          <div className="proof-notes">
            <p>
              Every rule ships with a unit test against a real <code>.eml</code>, and an evaluation
              harness re-scores a labelled corpus on each change.
              {small && ' The current corpus is synthetic and small — the harness flags it as such — so read these as a regression gate, not a field accuracy claim.'}
            </p>
            <ul className="posture">
              <li><Lock size={15} /> Stateless — messages are analysed in memory and never stored</li>
              <li><Check size={15} /> Deterministic — the same email always gets the same verdict</li>
              <li><Check size={15} /> Read-only — never follows a link or runs an attachment</li>
            </ul>
          </div>
        </div>
      </div>
    </section>
  )
}

/* -------------------------------------------------------------- closing */

function Closing() {
  return (
    <section className="closing" aria-labelledby="closing-title">
      <div className="wrap closing-inner">
        <span className="closing-mark" aria-hidden="true"><ShieldCheck size={26} strokeWidth={1.8} /></span>
        <h2 id="closing-title" className="closing-title">
          Screen the next offer <em>before</em> it reaches them.
        </h2>
        <button type="button" className="btn btn-primary" onClick={() => scrollToId('scanner')}>
          Open the screening desk <ArrowRight size={17} />
        </button>
      </div>
    </section>
  )
}

function SiteFooter() {
  return (
    <footer className="footer">
      <div className="wrap footer-inner">
        <span className="logo logo-dark">
          <span className="logo-mark">
            <ShieldCheck size={15} strokeWidth={2.2} />
          </span>
          <span className="logo-word">SponsorGuard</span>
        </span>
        <p>
          A defensive tool. It analyses emails you already received — it never sends, scrapes, or
          profiles anyone.
        </p>
      </div>
    </footer>
  )
}
