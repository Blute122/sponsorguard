"""Threat-intel enrichment — providers, snapshot/live, fail-safe wiring.

Every test is OFFLINE. The one network seam (`threatintel._fetch`) is stubbed;
snapshots are written into a tmp cache dir. The real feeds are never contacted.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

import sponsorguard.enrichment as enr
import sponsorguard.enrichment.threatintel as ti
from sponsorguard.models import Link, ParsedEmail
from sponsorguard.scoring import analyze

NOW = datetime(2026, 9, 20, tzinfo=timezone.utc)
FIX = __import__("pathlib").Path(__file__).parent / "fixtures"


def _email(*hrefs: str) -> ParsedEmail:
    return ParsedEmail(links=[Link(href=h, href_domain=ti._url_host(h)) for h in hrefs])


def _stub_fetch(mapping):
    """A fake _fetch: url -> bytes, or raises for a url mapped to an Exception."""
    def fetch(url, *, data=None, timeout=None, headers=None):
        val = mapping.get(url)
        if val is None:
            raise OSError(f"no stub for {url}")
        if isinstance(val, Exception):
            raise val
        return val if isinstance(val, bytes) else val.encode("utf-8")
    return fetch


def _write_snapshot(cache_dir, provider, *, hosts=(), urls=(), fetched=NOW):
    payload = {"feed": provider.name, "fetched": fetched.isoformat(),
               "count": len(urls) or len(hosts), "hosts": list(hosts), "urls": list(urls)}
    p = provider.snapshot_path(cache_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload), encoding="utf-8")


# --------------------------------------------------------------- feed hits

def test_urlhaus_hit_produces_finding(tmp_path):
    prov = ti.URLhausProvider()
    _write_snapshot(tmp_path, prov, hosts=["evil-malware.com"])
    findings = ti.threatintel_findings(
        _email("http://evil-malware.com/payload"),
        providers=[prov], cache_dir=tmp_path, now=NOW)
    assert len(findings) == 1
    f = findings[0]
    assert f.id == "links.known_malware_url"
    assert f.category.value == "links"
    assert f.points == 35
    assert "URLhaus" in f.evidence and "evil-malware" in f.evidence


def test_openphish_hit_produces_finding(tmp_path):
    prov = ti.OpenPhishProvider()
    _write_snapshot(tmp_path, prov, hosts=["phish-login.net"])
    findings = ti.threatintel_findings(
        _email("https://phish-login.net/verify"),
        providers=[prov], cache_dir=tmp_path, now=NOW)
    assert len(findings) == 1 and findings[0].id == "links.known_phishing_url"


def test_clean_link_no_finding(tmp_path):
    prov = ti.URLhausProvider()
    _write_snapshot(tmp_path, prov, hosts=["evil-malware.com"])
    findings = ti.threatintel_findings(
        _email("https://www.skillshare.com/partners"),
        providers=[prov], cache_dir=tmp_path, now=NOW)
    assert findings == []


def test_url_exact_match(tmp_path):
    prov = ti.URLhausProvider()
    _write_snapshot(tmp_path, prov, urls=["http://host.example/a/b?c=1"])
    findings = ti.threatintel_findings(
        _email("http://host.example/a/b?c=1"),
        providers=[prov], cache_dir=tmp_path, now=NOW)
    assert len(findings) == 1


# ------------------------------------------------ homoglyph / punycode match

def test_punycode_variant_of_known_bad_host_still_matches(tmp_path):
    # Feed lists the ASCII host; the email links its Cyrillic homoglyph (as
    # punycode). host_skeleton folds both to the same skeleton.
    prov = ti.URLhausProvider()
    _write_snapshot(tmp_path, prov, hosts=["paypal-secure.com"])
    # 'pаypal-secure' with a Cyrillic а, as it travels on the wire: punycode.
    puny_label = "pаypal-secure".encode("idna").decode("ascii")
    href = f"http://{puny_label}.com/login"
    findings = ti.threatintel_findings(
        _email(href), providers=[prov], cache_dir=tmp_path, now=NOW)
    assert len(findings) == 1
    assert findings[0].id == "links.known_malware_url"


def test_leetspeak_digit_host_matches(tmp_path):
    prov = ti.URLhausProvider()
    _write_snapshot(tmp_path, prov, hosts=["evil.com"])  # skeleton 'evil.com'
    findings = ti.threatintel_findings(
        _email("http://3vil.com/x"), providers=[prov], cache_dir=tmp_path, now=NOW)
    assert len(findings) == 1  # '3vil' -> skeleton 'evil'


# ------------------------------------------------------------ fail-safe cases

def test_missing_snapshot_no_finding_and_status(tmp_path):
    prov = ti.URLhausProvider()  # nothing written
    statuses = []
    findings = ti.threatintel_findings(
        _email("http://evil-malware.com/x"), providers=[prov],
        cache_dir=tmp_path, now=NOW, statuses=statuses)
    assert findings == []
    assert statuses == [("urlhaus", "missing")]


def test_stale_snapshot_no_finding_and_status(tmp_path):
    prov = ti.URLhausProvider()
    _write_snapshot(tmp_path, prov, hosts=["evil-malware.com"],
                    fetched=NOW - timedelta(days=30))  # older than the 7-day threshold
    statuses = []
    findings = ti.threatintel_findings(
        _email("http://evil-malware.com/x"), providers=[prov],
        cache_dir=tmp_path, now=NOW, statuses=statuses)
    assert findings == []
    assert statuses == [("urlhaus", "stale")]


def test_unparseable_snapshot_no_finding(tmp_path):
    prov = ti.URLhausProvider()
    p = prov.snapshot_path(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{ this is not json", encoding="utf-8")
    statuses = []
    findings = ti.threatintel_findings(
        _email("http://evil-malware.com/x"), providers=[prov],
        cache_dir=tmp_path, now=NOW, statuses=statuses)
    assert findings == []
    assert statuses == [("urlhaus", "error")]


def test_provider_raising_does_not_break_scan(tmp_path):
    class Boom(ti.URLhausProvider):
        def load_snapshot(self, *a, **k):
            raise RuntimeError("kaboom")
    findings = ti.threatintel_findings(
        _email("http://evil-malware.com/x"), providers=[Boom()],
        cache_dir=tmp_path, now=NOW)
    assert findings == []


# ---------------------------------------------------------- refresh (stubbed)

def test_refresh_writes_snapshot_then_lookup_hits(tmp_path):
    prov = ti.URLhausProvider()
    feed = "# comment header\nhttp://evil-malware.com/a\nhttp://another-bad.net/b\n"
    prov.refresh(tmp_path, fetch=_stub_fetch({prov.feed_url: feed}), now=NOW)
    # Snapshot now on disk; lookup is fully offline.
    findings = ti.threatintel_findings(
        _email("http://another-bad.net/b"), providers=[prov], cache_dir=tmp_path, now=NOW)
    assert len(findings) == 1


def test_refresh_network_error_keeps_no_snapshot(tmp_path):
    prov = ti.URLhausProvider()
    res = prov.refresh(tmp_path, fetch=_stub_fetch({prov.feed_url: TimeoutError("slow")}), now=NOW)
    assert res.status == "error"
    assert not prov.snapshot_path(tmp_path).exists()
    # A scan against the (absent) snapshot fails safe.
    assert ti.threatintel_findings(_email("http://x.com/"), providers=[prov],
                                   cache_dir=tmp_path, now=NOW) == []


def test_snapshot_mode_never_calls_network(tmp_path, monkeypatch):
    monkeypatch.setattr(ti, "_fetch", lambda *a, **k:
                        (_ for _ in ()).throw(AssertionError("snapshot mode hit the network")))
    prov = ti.URLhausProvider()
    _write_snapshot(tmp_path, prov, hosts=["evil-malware.com"])
    findings = ti.threatintel_findings(
        _email("http://evil-malware.com/x"), providers=[prov], cache_dir=tmp_path, now=NOW)
    assert len(findings) == 1  # and no AssertionError from _fetch


# ------------------------------------------------------------------- GSB

def test_gsb_unkeyed_is_dark(tmp_path, monkeypatch):
    monkeypatch.delenv(ti.GSB_API_KEY_ENV, raising=False)
    prov = ti.SafeBrowsingProvider()
    # snapshot mode: nothing
    assert ti.threatintel_findings(_email("http://evil.com/"), providers=[prov],
                                   cache_dir=tmp_path, now=NOW) == []
    # live mode: no key -> no finding, no error
    assert ti.threatintel_findings(_email("http://evil.com/"), providers=[prov],
                                   cache_dir=tmp_path, now=NOW, mode="live") == []


def test_gsb_keyed_live_hit(tmp_path, monkeypatch):
    monkeypatch.setenv(ti.GSB_API_KEY_ENV, "TESTKEY")
    prov = ti.SafeBrowsingProvider()
    api = prov._API.format(key="TESTKEY")
    match_body = json.dumps({"matches": [{"threatType": "MALWARE"}]})
    monkeypatch.setattr(ti, "_fetch", _stub_fetch({api: match_body}))
    findings = ti.threatintel_findings(
        _email("http://evil.com/bad"), providers=[prov],
        cache_dir=tmp_path, now=NOW, mode="live")
    assert len(findings) == 1 and findings[0].id == "links.safe_browsing_flagged"


def test_gsb_keyed_live_clean(tmp_path, monkeypatch):
    monkeypatch.setenv(ti.GSB_API_KEY_ENV, "TESTKEY")
    prov = ti.SafeBrowsingProvider()
    api = prov._API.format(key="TESTKEY")
    monkeypatch.setattr(ti, "_fetch", _stub_fetch({api: json.dumps({})}))  # no matches
    findings = ti.threatintel_findings(
        _email("http://clean.com/"), providers=[prov],
        cache_dir=tmp_path, now=NOW, mode="live")
    assert findings == []


def test_live_timeout_no_finding(tmp_path, monkeypatch):
    prov = ti.URLhausProvider()
    monkeypatch.setattr(ti, "_fetch",
                        _stub_fetch({prov._LIVE_HOST_API: TimeoutError("t")}))
    findings = ti.threatintel_findings(
        _email("http://evil.com/"), providers=[prov],
        cache_dir=tmp_path, now=NOW, mode="live")
    assert findings == []


# --------------------------------------------------- analyze() wiring guards

def test_analyze_default_makes_no_network_and_omits_threatintel(monkeypatch):
    monkeypatch.setattr(ti, "_fetch", lambda *a, **k:
                        (_ for _ in ()).throw(AssertionError("network in default analyze()")))
    monkeypatch.setattr(enr, "lookup_creation_date", lambda *a, **k:
                        (_ for _ in ()).throw(AssertionError("RDAP in default analyze()")))
    report = analyze((FIX / "scam_nordvpn.eml").read_bytes())  # enrich defaults False
    ids = {f["id"] for f in report.to_dict()["findings"]}
    assert not (ids & {"links.known_malware_url", "links.known_phishing_url",
                       "links.safe_browsing_flagged"})


def test_analyze_enrich_disabled_byte_identical(monkeypatch):
    # Even if a snapshot happened to exist, enrich=False must not consult it.
    for name in ("scam_nordvpn.eml", "legit_brand.eml"):
        raw = (FIX / name).read_bytes()
        assert analyze(raw, enrich=False).to_dict() == analyze(raw).to_dict()


def test_analyze_enrich_true_empty_snapshot_equals_disabled(monkeypatch, tmp_path):
    # No snapshots + RDAP stubbed to None -> enrich=True == enrich=False.
    monkeypatch.setattr(enr, "lookup_creation_date", lambda *a, **k: None)
    monkeypatch.setattr(enr, "DEFAULT_CACHE_DIR", tmp_path, raising=False)
    raw = (FIX / "scam_nordvpn.eml").read_bytes()
    # Point the threatintel default cache at an empty dir for this call.
    monkeypatch.setattr(ti, "DEFAULT_CACHE_DIR", tmp_path)
    assert analyze(raw, enrich=True).to_dict() == analyze(raw, enrich=False).to_dict()


def test_enrich_findings_appends_threatintel_offline(tmp_path, monkeypatch):
    prov = ti.URLhausProvider()
    _write_snapshot(tmp_path, prov, hosts=["nordvpn.verify-portal.ru"])
    email = _email("https://nordvpn.verify-portal.ru/login")
    out = enr.enrich_findings(email, lookup=lambda reg: None, now=NOW,
                              threat_providers=[prov], cache_dir=tmp_path)
    assert [f.id for f in out] == ["links.known_malware_url"]
