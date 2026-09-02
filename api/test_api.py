"""API-layer tests, driven through FastAPI's TestClient.

These verify the HTTP contract (status codes, the `auth_available` flag, error
handling) — the rule/scoring behaviour itself is covered by tests/test_rules.py
and is deliberately not re-asserted here.
"""
from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient

from api.main import app

FIX = Path(__file__).resolve().parent.parent / "tests" / "fixtures"

client = TestClient(app)


def _post(email_raw: str):
    return client.post("/analyze", json={"email_raw": email_raw})


def test_scam_is_dangerous_with_auth_available():
    raw = (FIX / "scam_nordvpn.eml").read_text()
    resp = _post(raw)
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "Dangerous"
    assert body["score"] >= 60
    # The scam fixture carries an Authentication-Results header, so auth ran.
    assert body["auth_available"] is True
    assert body["safe_next_step"]


def test_legit_is_low():
    raw = (FIX / "legit_brand.eml").read_text()
    resp = _post(raw)
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "Low"
    assert body["score"] < 15
    assert body["auth_available"] is True


def test_body_only_paste_reports_auth_unavailable_and_skips_auth_rules():
    """Stripping the Authentication-Results header simulates a forwarded /
    body-only paste: auth is unavailable and no auth.* finding should fire."""
    raw = (FIX / "scam_nordvpn.eml").read_text()
    stripped = re.sub(r"(?im)^Authentication-Results:.*\r?\n", "", raw)
    assert "Authentication-Results" not in stripped

    resp = _post(stripped)
    assert resp.status_code == 200
    body = resp.json()

    assert body["auth_available"] is False
    auth_findings = [f for f in body["findings"] if f["id"].startswith("auth.")]
    assert auth_findings == []
    # It's still clearly malicious on the non-auth signals alone.
    assert body["verdict"] == "Dangerous"


def test_empty_input_is_400():
    resp = _post("   \n  ")
    assert resp.status_code == 400
    assert "detail" in resp.json()


def test_oversized_input_is_400():
    resp = _post("x" * 2_000_001)
    assert resp.status_code == 400


def test_missing_field_is_422():
    # Pydantic validation — a clean structured error, never a 500.
    resp = client.post("/analyze", json={})
    assert resp.status_code == 422
