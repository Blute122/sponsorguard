"""RDAP lookup tests. Every one stubs urllib — the real network is never hit."""
from __future__ import annotations

import json
import socket
import urllib.error

from sponsorguard.enrichment import rdap


class _FakeResp:
    """Minimal stand-in for the urlopen context-manager response."""

    def __init__(self, body: str, status: int = 200):
        self._body = body.encode("utf-8")
        self.status = status

    def read(self, n: int = -1) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _patch(monkeypatch, fn):
    monkeypatch.setattr(rdap.urllib.request, "urlopen", fn)


def _body(events) -> str:
    return json.dumps({"objectClassName": "domain", "events": events})


def test_parses_registration_event(monkeypatch):
    body = _body([
        {"eventAction": "last changed", "eventDate": "2025-01-01T00:00:00Z"},
        {"eventAction": "registration", "eventDate": "2023-05-01T12:00:00Z"},
    ])
    _patch(monkeypatch, lambda req, timeout=None: _FakeResp(body))
    dt = rdap.lookup_creation_date("example.com")
    assert dt is not None
    assert (dt.year, dt.month, dt.day) == (2023, 5, 1)
    assert dt.tzinfo is not None  # normalized to an aware datetime


def test_date_without_timezone_is_assumed_utc(monkeypatch):
    body = _body([{"eventAction": "registration", "eventDate": "2023-05-01"}])
    _patch(monkeypatch, lambda req, timeout=None: _FakeResp(body))
    dt = rdap.lookup_creation_date("example.com")
    assert dt is not None and dt.tzinfo is not None


def test_non_200_returns_none(monkeypatch):
    def _raise(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)

    _patch(monkeypatch, _raise)
    assert rdap.lookup_creation_date("nope.example") is None


def test_204_status_returns_none(monkeypatch):
    # A 2xx that isn't 200 (no body) -> unknown, not an error path.
    _patch(monkeypatch, lambda req, timeout=None: _FakeResp("", status=204))
    assert rdap.lookup_creation_date("empty.example") is None


def test_timeout_returns_none(monkeypatch):
    def _timeout(req, timeout=None):
        raise socket.timeout("timed out")

    _patch(monkeypatch, _timeout)
    assert rdap.lookup_creation_date("slow.example") is None


def test_network_error_returns_none(monkeypatch):
    def _err(req, timeout=None):
        raise urllib.error.URLError("name resolution failed")

    _patch(monkeypatch, _err)
    assert rdap.lookup_creation_date("dead.example") is None


def test_missing_events_returns_none(monkeypatch):
    _patch(monkeypatch, lambda req, timeout=None: _FakeResp(json.dumps({"objectClassName": "domain"})))
    assert rdap.lookup_creation_date("noevents.example") is None


def test_events_not_a_list_returns_none(monkeypatch):
    _patch(monkeypatch, lambda req, timeout=None: _FakeResp(json.dumps({"events": "oops"})))
    assert rdap.lookup_creation_date("weird.example") is None


def test_no_registration_action_returns_none(monkeypatch):
    body = _body([{"eventAction": "last changed", "eventDate": "2025-01-01T00:00:00Z"}])
    _patch(monkeypatch, lambda req, timeout=None: _FakeResp(body))
    assert rdap.lookup_creation_date("changedonly.example") is None


def test_malformed_date_returns_none(monkeypatch):
    body = _body([{"eventAction": "registration", "eventDate": "not-a-real-date"}])
    _patch(monkeypatch, lambda req, timeout=None: _FakeResp(body))
    assert rdap.lookup_creation_date("baddate.example") is None


def test_invalid_json_returns_none(monkeypatch):
    _patch(monkeypatch, lambda req, timeout=None: _FakeResp("<html>not json</html>"))
    assert rdap.lookup_creation_date("html.example") is None


def test_empty_domain_returns_none_without_calling_network(monkeypatch):
    def _boom(req, timeout=None):
        raise AssertionError("urlopen must not be called for an empty domain")

    _patch(monkeypatch, _boom)
    assert rdap.lookup_creation_date("") is None
