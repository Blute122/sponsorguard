"""Threat-intel enrichment: check a message's links against known-bad feeds.

Same fail-safe contract as rdap.py: OPT-IN (enrich=True), OFF by default, and
every failure mode — timeout, network error, a missing/stale/unparseable
snapshot, an absent API key — yields NO finding and never raises out of the
module. A message whose links can't be checked scores exactly as it does today.

Two consult modes behind one interface:

  * SNAPSHOT (default): feeds are downloaded to a local cache by a separate
    `refresh` command; scanning reads that cache OFFLINE and deterministically.
    A scan never downloads a feed and never requests the malicious URL itself.
    A missing or stale snapshot returns no finding plus a status the caller can
    log — it does NOT silently fall back to live, and never penalizes.

  * LIVE (optional): per-lookup API calls for the freshest data. Slower,
    network-dependent, chosen explicitly. Never the default.

Feeds:
  * URLhaus (abuse.ch)     — malware URLs. Keyless download; live host API.
  * OpenPhish community     — phishing URLs. Keyless download; live = re-fetch.
  * Google Safe Browsing    — OPTIONAL, key-gated (env SPONSORGUARD_GSB_API_KEY).
                              Live Lookup API only; fully dark without a key.

Stdlib only (urllib / json). Feed data is cache-only and gitignored — this repo
never bundles a snapshot (feeds are large and licence-bound; see enrichment
docs).
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..domains import domain_of, registrable_domain
from ..models import Category, Finding, ParsedEmail, Severity
from ..normalize import host_skeleton

# --- config -----------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CACHE_DIR = REPO_ROOT / ".threatintel_cache"

DEFAULT_TIMEOUT = 6.0
DEFAULT_MAX_AGE_DAYS = 7           # snapshots older than this fail safe (no finding)
_MAX_BYTES = 32 * 1024 * 1024      # cap a feed download so a broken server can't OOM us

GSB_API_KEY_ENV = "SPONSORGUARD_GSB_API_KEY"

_HEADERS = {"User-Agent": "SponsorGuard/0.1 (threat-intel enrichment)"}
_HOST_RE = re.compile(r"^[a-z0-9+.\-]+://([^/\\?#]+)", re.IGNORECASE)


# --- the single network seam (mirrors rdap.py; monkeypatched in tests) -------

def _fetch(url: str, *, data: Optional[bytes] = None, timeout: float = DEFAULT_TIMEOUT,
           headers: Optional[dict] = None) -> bytes:
    """GET (or POST when `data` is given). Raises on any failure — callers catch."""
    req = urllib.request.Request(url, data=data, headers={**_HEADERS, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if getattr(resp, "status", 200) != 200:
            raise OSError(f"non-200 from {url}")
        return resp.read(_MAX_BYTES)


# --- helpers ----------------------------------------------------------------

def _strip_port(host: str) -> str:
    left, sep, right = (host or "").rpartition(":")
    return left if (sep and right.isdigit()) else host


def _url_host(url: str) -> str:
    """Bare lowercased host of a URL (strips scheme, creds, port, path)."""
    m = _HOST_RE.match(url or "")
    if not m:
        return ""
    return _strip_port(domain_of(m.group(1)))  # domain_of drops user@, brackets


def _defang(s: str) -> str:
    """Neutralize a URL/host for display while keeping it the attacker's real string."""
    return s.replace("http", "hxxp").replace(".", "[.]")


def _now(now: Optional[datetime]) -> datetime:
    return now or datetime.now(timezone.utc)


@dataclass
class Snapshot:
    hosts: frozenset[str] = frozenset()   # host_skeleton-normalized known-bad hosts
    urls: frozenset[str] = frozenset()    # lowercased known-bad full URLs
    fetched: Optional[datetime] = None
    status: str = "missing"               # ok | missing | stale | error


@dataclass
class Hit:
    matched: str        # the email's real link string that matched
    kind: str           # "host" | "url"
    snapshot_date: str   # ISO date or "live"


@dataclass
class RefreshResult:
    name: str
    status: str          # ok | skipped | error
    count: int = 0
    detail: str = ""


# --- providers --------------------------------------------------------------

class _SnapshotFeed:
    """A keyless URL feed: download to a JSON snapshot, look up offline.

    Subclasses set the metadata and override `parse()` for the feed's wire
    format, and optionally `_live_match()` for live mode.
    """

    name: str = ""
    feed_label: str = ""
    finding_id: str = ""
    feed_url: str = ""
    points: int = 35
    severity: Severity = Severity.HIGH
    requires_key: bool = False

    explanation: str = ""
    remediation: str = ""

    # -- refresh (snapshot mode maintenance) --
    def snapshot_path(self, cache_dir: Path) -> Path:
        return Path(cache_dir) / f"{self.name}.json"

    def parse(self, text: str) -> list[str]:
        """Feed text -> list of URLs. Override per feed."""
        raise NotImplementedError

    def refresh(self, cache_dir: Path, *, timeout: float = DEFAULT_TIMEOUT,
                fetch=None, now: Optional[datetime] = None) -> RefreshResult:
        fetch = fetch or _fetch
        try:
            raw = fetch(self.feed_url, timeout=timeout)
            urls = self.parse(raw.decode("utf-8", errors="replace"))
        except Exception as exc:  # download or parse failed -> keep old snapshot
            return RefreshResult(self.name, "error", detail=str(exc)[:200])

        hosts = sorted({h for u in urls if (h := _url_host(u))})
        payload = {
            "feed": self.name,
            "fetched": _now(now).isoformat(),
            "count": len(urls),
            "hosts": hosts,
            "urls": sorted({u.strip().lower() for u in urls if u.strip()}),
        }
        path = self.snapshot_path(cache_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        tmp.replace(path)  # atomic-ish; a scan never sees a half-written file
        return RefreshResult(self.name, "ok", count=len(urls))

    # -- load (offline, scan time) --
    def load_snapshot(self, cache_dir: Path, *, max_age_days: int = DEFAULT_MAX_AGE_DAYS,
                      now: Optional[datetime] = None) -> Snapshot:
        path = self.snapshot_path(cache_dir)
        if not path.exists():
            return Snapshot(status="missing")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            fetched = datetime.fromisoformat(data["fetched"])
            if fetched.tzinfo is None:
                fetched = fetched.replace(tzinfo=timezone.utc)
            hosts = frozenset(host_skeleton(h) for h in data.get("hosts", []) if h)
            urls = frozenset(u.lower() for u in data.get("urls", []) if u)
        except Exception:
            return Snapshot(status="error")

        age = _now(now) - fetched
        if age.days > max_age_days:
            return Snapshot(hosts=hosts, urls=urls, fetched=fetched, status="stale")
        return Snapshot(hosts=hosts, urls=urls, fetched=fetched, status="ok")

    # -- match (pure) --
    def match_snapshot(self, snap: Snapshot, url: str, host: str) -> Optional[Hit]:
        if snap.status != "ok":
            return None
        date = snap.fetched.date().isoformat() if snap.fetched else "?"
        if url and url.strip().lower() in snap.urls:
            return Hit(matched=url, kind="url", snapshot_date=date)
        for candidate in _host_candidates(host):
            if candidate in snap.hosts:
                return Hit(matched=host or url, kind="host", snapshot_date=date)
        return None

    # -- live --
    def live_match(self, url: str, host: str, *, timeout: float = DEFAULT_TIMEOUT,
                   fetch=None, now: Optional[datetime] = None) -> Optional[Hit]:
        return None  # feeds without a live API stay snapshot-only

    # -- finding construction --
    def finding(self, hit: Hit) -> Finding:
        tag = "live" if hit.snapshot_date == "live" else f"snapshot {hit.snapshot_date}"
        return Finding(
            id=self.finding_id,
            category=Category.LINKS,
            points=self.points,
            severity=self.severity,
            evidence=f"{_defang(hit.matched)} — listed by {self.feed_label} ({tag})",
            explanation=self.explanation,
            remediation=self.remediation,
        )


def _host_candidates(host: str) -> list[str]:
    """The host and its registrable domain, both host_skeleton-normalized, so a
    homoglyph/punycode variant of a known-bad host still matches."""
    if not host:
        return []
    out = [host_skeleton(host)]
    reg = registrable_domain(host)
    if reg:
        reg_sk = host_skeleton(reg)
        if reg_sk not in out:
            out.append(reg_sk)
    return [c for c in out if c]


class URLhausProvider(_SnapshotFeed):
    name = "urlhaus"
    feed_label = "URLhaus"
    finding_id = "links.known_malware_url"
    feed_url = "https://urlhaus.abuse.ch/downloads/text/"
    explanation = ("This link appears on URLhaus's list of confirmed "
                   "malware-distribution URLs — known-bad infrastructure, not a real sponsor link.")
    remediation = "Do not open it, and do not download anything it offers."

    _LIVE_HOST_API = "https://urlhaus-api.abuse.ch/v1/host/"

    def parse(self, text: str) -> list[str]:
        # Plaintext feed: one URL per line, '#'-prefixed comment/header lines.
        return [ln.strip() for ln in text.splitlines()
                if ln.strip() and not ln.lstrip().startswith("#")]

    def live_match(self, url, host, *, timeout=DEFAULT_TIMEOUT, fetch=None, now=None):
        fetch = fetch or _fetch
        if not host:
            return None
        body = urllib.parse.urlencode({"host": host}).encode()
        try:
            data = json.loads(fetch(self._LIVE_HOST_API, data=body, timeout=timeout)
                              .decode("utf-8", errors="replace"))
        except Exception:
            return None
        if isinstance(data, dict) and data.get("query_status") == "ok" and data.get("urls"):
            return Hit(matched=host, kind="host", snapshot_date="live")
        return None


class OpenPhishProvider(_SnapshotFeed):
    name = "openphish"
    feed_label = "OpenPhish"
    finding_id = "links.known_phishing_url"
    feed_url = "https://openphish.com/feed.txt"
    explanation = ("This link appears on OpenPhish's community feed of active "
                   "phishing URLs — a page built to steal credentials, not a real sponsor.")
    remediation = "Do not click it or enter anything; treat the sender as hostile."

    def parse(self, text: str) -> list[str]:
        return [ln.strip() for ln in text.splitlines() if ln.strip()]

    def live_match(self, url, host, *, timeout=DEFAULT_TIMEOUT, fetch=None, now=None):
        # OpenPhish has no per-lookup API on the community tier; "live" means
        # fetch the feed fresh and check against it.
        fetch = fetch or _fetch
        try:
            urls = self.parse(fetch(self.feed_url, timeout=timeout).decode("utf-8", errors="replace"))
        except Exception:
            return None
        bad_hosts = {host_skeleton(h) for u in urls if (h := _url_host(u))}
        if any(c in bad_hosts for c in _host_candidates(host)):
            return Hit(matched=host or url, kind="host", snapshot_date="live")
        if url and url.strip().lower() in {u.strip().lower() for u in urls}:
            return Hit(matched=url, kind="url", snapshot_date="live")
        return None


class SafeBrowsingProvider(_SnapshotFeed):
    """Google Safe Browsing — LIVE only, key-gated. Dark without a key.

    GSB is a lookup/update API, not a downloadable blocklist we may cache, so it
    has no snapshot: in snapshot mode it always reports 'no key / live-only' and
    produces nothing. With a key and live mode it queries the v4 Lookup API.
    """

    name = "safebrowsing"
    feed_label = "Google Safe Browsing"
    finding_id = "links.safe_browsing_flagged"
    requires_key = True
    explanation = ("Google Safe Browsing flags this link as unsafe (malware or "
                   "social engineering).")
    remediation = "Do not open it."

    _API = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"

    def api_key(self) -> str:
        return os.environ.get(GSB_API_KEY_ENV, "").strip()

    def refresh(self, cache_dir, *, timeout=DEFAULT_TIMEOUT, fetch=None, now=None):
        if not self.api_key():
            return RefreshResult(self.name, "skipped", detail="no API key set")
        # Nothing to snapshot: GSB is consulted live. Report readiness only.
        return RefreshResult(self.name, "skipped", detail="live-only (no snapshot to refresh)")

    def load_snapshot(self, cache_dir, *, max_age_days=DEFAULT_MAX_AGE_DAYS, now=None):
        return Snapshot(status="error")  # no snapshot -> never fires in snapshot mode

    def match_snapshot(self, snap, url, host):
        return None

    def live_match(self, url, host, *, timeout=DEFAULT_TIMEOUT, fetch=None, now=None):
        key = self.api_key()
        if not key or not url:
            return None  # unkeyed -> fully dark, no error
        fetch = fetch or _fetch
        body = json.dumps({
            "client": {"clientId": "sponsorguard", "clientVersion": "0.1"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }).encode()
        try:
            data = json.loads(fetch(self._API.format(key=key), data=body, timeout=timeout,
                                    headers={"Content-Type": "application/json"})
                              .decode("utf-8", errors="replace"))
        except Exception:
            return None
        if isinstance(data, dict) and data.get("matches"):
            return Hit(matched=url, kind="url", snapshot_date="live")
        return None


def default_providers() -> list[_SnapshotFeed]:
    return [URLhausProvider(), OpenPhishProvider(), SafeBrowsingProvider()]


# --- the enrichment entry point (mirrors rdap's injectable shape) ------------

def threatintel_findings(
    email: ParsedEmail,
    *,
    providers: Optional[list] = None,
    mode: str = "snapshot",
    cache_dir: Optional[Path] = None,
    now: Optional[datetime] = None,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    statuses: Optional[list] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[Finding]:
    """Check every link against each provider; return known-bad findings.

    Fully fail-safe: any provider error is swallowed and yields no finding. In
    snapshot mode nothing touches the network. `statuses` (if given) collects
    (provider, status) so the caller can log snapshot health.
    """
    if providers is None:
        providers = default_providers()
    if cache_dir is None:
        cache_dir = DEFAULT_CACHE_DIR
    if not email.links:
        return []

    # Resolve each link's host once (port-stripped for reliable feed matching).
    links = [(lk.href, _strip_port(lk.href_domain) or _url_host(lk.href)) for lk in email.links]

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()  # (finding_id, matched) dedupe

    for provider in providers:
        try:
            if mode == "snapshot":
                snap = provider.load_snapshot(cache_dir, max_age_days=max_age_days, now=now)
                if statuses is not None:
                    statuses.append((provider.name, snap.status))
                if snap.status != "ok":
                    continue  # missing / stale / error -> no finding, no penalty
                for url, host in links:
                    hit = provider.match_snapshot(snap, url, host)
                    if hit:
                        _add(findings, seen, provider, hit)
            else:  # live
                if getattr(provider, "requires_key", False) and not getattr(provider, "api_key", lambda: "")():
                    if statuses is not None:
                        statuses.append((provider.name, "no-key"))
                    continue
                if statuses is not None:
                    statuses.append((provider.name, "live"))
                for url, host in links:
                    hit = provider.live_match(url, host, timeout=timeout, now=now)
                    if hit:
                        _add(findings, seen, provider, hit)
        except Exception:
            # A provider must never take the scan down with it.
            if statuses is not None:
                statuses.append((getattr(provider, "name", "?"), "error"))
            continue

    return findings


def _add(findings, seen, provider, hit) -> None:
    key = (provider.finding_id, hit.matched)
    if key in seen:
        return
    seen.add(key)
    findings.append(provider.finding(hit))


def snapshot_status(
    *, providers: Optional[list] = None, cache_dir: Optional[Path] = None,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS, now: Optional[datetime] = None,
) -> list[tuple[str, str, str]]:
    """(name, status, detail) per provider, for the CLI/logging."""
    providers = providers or default_providers()
    cache_dir = cache_dir or DEFAULT_CACHE_DIR
    out = []
    for p in providers:
        if getattr(p, "requires_key", False):
            keyed = bool(getattr(p, "api_key", lambda: "")())
            out.append((p.name, "live-only", "keyed" if keyed else f"no {GSB_API_KEY_ENV}"))
            continue
        snap = p.load_snapshot(cache_dir, max_age_days=max_age_days, now=now)
        detail = snap.fetched.date().isoformat() if snap.fetched else "-"
        out.append((p.name, snap.status, detail))
    return out


def refresh_all(
    *, providers: Optional[list] = None, cache_dir: Optional[Path] = None,
    timeout: float = DEFAULT_TIMEOUT, fetch=None, now: Optional[datetime] = None,
) -> list[RefreshResult]:
    providers = providers or default_providers()
    cache_dir = Path(cache_dir or DEFAULT_CACHE_DIR)
    results = []
    for p in providers:
        try:
            results.append(p.refresh(cache_dir, timeout=timeout, fetch=fetch, now=now))
        except Exception as exc:  # refresh itself must never raise
            results.append(RefreshResult(getattr(p, "name", "?"), "error", detail=str(exc)[:200]))
    return results


# --- CLI: python -m sponsorguard.enrichment.threatintel {refresh,status} -----

def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(
        prog="python -m sponsorguard.enrichment.threatintel",
        description="Maintain the offline threat-intel snapshots used by enrich=True scans.",
    )
    sub = ap.add_subparsers(dest="cmd")
    r = sub.add_parser("refresh", help="download/update the keyless feed snapshots")
    r.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    r.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    s = sub.add_parser("status", help="show snapshot freshness")
    s.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    args = ap.parse_args(argv)

    if args.cmd == "status":
        print(f"cache: {args.cache_dir}")
        for name, status, detail in snapshot_status(cache_dir=args.cache_dir):
            print(f"  {name:14} {status:10} {detail}")
        return 0

    if args.cmd == "refresh":
        print(f"Refreshing threat-intel snapshots into {args.cache_dir} ...")
        results = refresh_all(cache_dir=args.cache_dir, timeout=args.timeout)
        for res in results:
            line = f"  {res.name:14} {res.status:8}"
            if res.count:
                line += f" {res.count} entries"
            if res.detail:
                line += f" ({res.detail})"
            print(line)
        # Refresh is best-effort: a feed being unreachable is a warning, not a
        # crash — scans just fail safe to no finding until it is refreshed.
        return 0

    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
