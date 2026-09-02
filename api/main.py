"""FastAPI app exposing the SponsorGuard engine over one POST endpoint.

Design notes:
  * The scoring engine is reused verbatim — this module never re-implements a
    rule or a threshold. It parses the raw email exactly once, runs the rules,
    scores them, and serialises the resulting Report.
  * `auth_available` is derived from that single parse: it is True only when the
    message carried an `Authentication-Results` header. When it is False the UI
    can honestly tell the user that SPF/DKIM/DMARC checks were *skipped*, not
    passed (a forwarded or body-only paste lacks the header).
  * Empty / oversized / unparseable input yields a clean 400, never a 500.
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from sponsorguard.parser import parse_email
from sponsorguard.rules import run_rules
from sponsorguard.scoring import score_findings

# A raw email (headers + base64 attachments) is normally a few KB. Cap well
# above that so a genuine message with an attachment fits, but a paste that is
# clearly not an email can't tie up the parser.
MAX_EMAIL_BYTES = 2_000_000

# The Vite dev server. Both spellings so `localhost` and `127.0.0.1` both work.
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

app = FastAPI(
    title="SponsorGuard API",
    version="0.1.0",
    description="Paste a raw email, get a scored sponsorship-scam report.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    email_raw: str


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/analyze")
def analyze_email(req: AnalyzeRequest) -> dict:
    raw = req.email_raw

    if not raw or not raw.strip():
        raise HTTPException(
            status_code=400,
            detail="No email provided. Paste a raw email (.eml / Gmail 'Show original').",
        )

    if len(raw.encode("utf-8", errors="ignore")) > MAX_EMAIL_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"Email is too large (limit {MAX_EMAIL_BYTES // 1000} KB). "
            "Paste just the message you want scanned.",
        )

    try:
        parsed = parse_email(raw)
        report = score_findings(run_rules(parsed))
    except Exception:
        # Malformed / non-email garbage: report a clean client error, not a 500.
        raise HTTPException(
            status_code=400,
            detail="Could not parse that as an email. Make sure you pasted the full raw message.",
        )

    result = report.to_dict()
    # True only when the message actually carried an Authentication-Results
    # header — the single source of truth for whether auth checks even ran.
    result["auth_available"] = parsed.auth_results is not None
    return result
