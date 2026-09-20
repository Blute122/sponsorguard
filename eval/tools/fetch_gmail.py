#!/usr/bin/env python3
"""Pull your OWN Gmail for sponsorship-scam specimens into an unlabeled review queue.

This is a COLLECTION tool, not part of the eval harness. It does not score, label,
redact, or import anything into the graded corpus. It fetches raw .eml files into
a gitignored review/ directory and leaves every judgement call to you, per
eval/COLLECTION.md.

Three properties this script guarantees:

  READ-ONLY   Mailboxes are opened with readonly=True and bodies are fetched with
              BODY.PEEK[] so the Seen flag is never set. The script issues no
              STORE, COPY, MOVE, EXPUNGE or DELETE. It cannot modify your mail.

  UNLABELED   Everything lands in one review/ directory. The folder a message came
              from is recorded as metadata only - "it was in Spam" is NOT evidence
              that it is a scam, and "it was in All Mail" is not evidence that it
              is legit. The label column in the queue is left blank for you.

  NO SECRETS  Credentials come from environment variables and are never written to
              disk, logged, or echoed.

Stdlib only.

Usage:
    export GMAIL_ADDRESS='you@gmail.com'
    export GMAIL_APP_PASSWORD='abcd efgh ijkl mnop'   # App Password, not your login
    python eval/tools/fetch_gmail.py --dry-run        # always look first
    python eval/tools/fetch_gmail.py --limit 50
"""
from __future__ import annotations

import argparse
import csv
import email
import hashlib
import imaplib
import os
import re
import sys
from email.header import decode_header, make_header
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
REVIEW_DIR = REPO_ROOT / "eval" / "corpus" / "sponsorship" / "review"
QUEUE_CSV = REVIEW_DIR / "_queue.csv"
SEEN_IDS = Path(__file__).resolve().parent / ".seen_ids"

IMAP_HOST = "imap.gmail.com"

# Gmail's own search syntax, passed through the X-GM-RAW extension. Plain IMAP
# SEARCH cannot express OR-groups over subject and body like this.
DEFAULT_QUERY = (
    'subject:(sponsorship OR collaboration OR "brand deal" OR partnership OR '
    '"promote our" OR "paid promotion" OR sponsor) OR '
    'body:("sponsor your channel" OR "creative brief" OR "brand deal")'
)

# label -> real Gmail mailbox name.
FOLDERS: dict[str, str] = {
    "spam": "[Gmail]/Spam",
    "trash": "[Gmail]/Trash",
    "all_mail": "[Gmail]/All Mail",
}

QUEUE_COLUMNS = [
    "filename", "fetched_from", "date", "from_domain", "subject",
    "has_auth_results", "has_attachments", "label", "notes",
]

DEFAULT_LIMIT = 200


# ------------------------------------------------------------------ helpers

def _imap_quote(value: str) -> str:
    """Quote a string as an IMAP quoted-string (escaping backslash and quote)."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _decode(raw_value: str | None) -> str:
    """Decode RFC 2047 header encoding; never raise on malformed input."""
    if not raw_value:
        return ""
    try:
        return str(make_header(decode_header(raw_value)))
    except Exception:
        return raw_value


def _safe(token: str, max_len: int = 40) -> str:
    """Filesystem-safe token: keep [A-Za-z0-9._-], collapse everything else."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", token or "").strip("-.")
    return (cleaned or "unknown")[:max_len]


def _message_key(msg, raw: bytes) -> str:
    """Stable dedupe key: Message-ID when present, else a hash of the bytes."""
    mid = (msg.get("Message-ID") or "").strip()
    if mid:
        return mid.strip("<>").strip()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _load_seen() -> set[str]:
    if not SEEN_IDS.exists():
        return set()
    return {
        line.strip()
        for line in SEEN_IDS.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }


def _append_seen(keys: list[str]) -> None:
    if not keys:
        return
    SEEN_IDS.parent.mkdir(parents=True, exist_ok=True)
    new_file = not SEEN_IDS.exists()
    with SEEN_IDS.open("a", encoding="utf-8") as fh:
        if new_file:
            fh.write("# Dedupe keys for eval/tools/fetch_gmail.py. Gitignored.\n")
            fh.write("# Message-ID, or sha256:<digest> when the message had none.\n")
        for key in keys:
            fh.write(key + "\n")


def describe(msg) -> dict:
    """Pull only the triage metadata we record. No body content is inspected."""
    _, addr = parseaddr(msg.get("From", ""))
    domain = addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""

    date_raw = msg.get("Date")
    try:
        date_iso = parsedate_to_datetime(date_raw).date().isoformat() if date_raw else ""
    except Exception:
        date_iso = ""

    has_attach = any(part.get_filename() for part in msg.walk())

    return {
        "date": date_iso,
        "from_domain": domain,
        "subject": _decode(msg.get("Subject")).replace("\r", " ").replace("\n", " ").strip(),
        "has_auth_results": "yes" if msg.get("Authentication-Results") else "no",
        "has_attachments": "yes" if has_attach else "no",
    }


def build_filename(meta: dict, raw: bytes) -> str:
    stamp = meta["date"].replace("-", "") if meta["date"] else "nodate"
    domain = _safe(meta["from_domain"] or "no-sender", 40)
    short = hashlib.sha256(raw).hexdigest()[:8]
    return f"{stamp}_{domain}_{short}.eml"


# --------------------------------------------------------------------- imap

def connect(address: str, app_password: str) -> imaplib.IMAP4_SSL:
    imap = imaplib.IMAP4_SSL(IMAP_HOST)
    try:
        imap.login(address, app_password)
    except imaplib.IMAP4.error as exc:
        raise SystemExit(
            f"\nGmail rejected the login: {exc}\n\n"
            "Almost always one of:\n"
            "  * GMAIL_APP_PASSWORD is your normal account password. It must be a\n"
            "    16-character App Password - a normal password cannot work over IMAP.\n"
            "  * 2-Step Verification is off (App Passwords require it).\n"
            "  * IMAP is disabled in Gmail Settings > Forwarding and POP/IMAP.\n"
            "See eval/tools/README.md.\n"
        ) from None
    return imap


def _list_mailboxes(imap) -> list[str]:
    """Best-effort mailbox listing, used to help when folder names are localised."""
    try:
        typ, data = imap.list()
    except Exception:
        return []
    if typ != "OK" or not data:
        return []
    names = []
    for line in data:
        text = line.decode(errors="replace") if isinstance(line, bytes) else str(line)
        m = re.search(r'"([^"]*)"\s*$', text) or re.search(r"(\S+)\s*$", text)
        if m:
            names.append(m.group(1))
    return names


def search_folder(imap, mailbox: str, query: str) -> list[bytes] | None:
    """Select a mailbox READ-ONLY and return matching UIDs, or None if unusable."""
    try:
        typ, _ = imap.select(_imap_quote(mailbox), readonly=True)
    except imaplib.IMAP4.error:
        return None
    if typ != "OK":
        return None
    typ, data = imap.uid("SEARCH", "X-GM-RAW", _imap_quote(query))
    if typ != "OK" or not data or not data[0]:
        return []
    return data[0].split()


def fetch_raw(imap, uid: bytes, headers_only: bool = False) -> bytes | None:
    """Fetch a message with BODY.PEEK[] so the Seen flag is never set."""
    item = "(BODY.PEEK[HEADER])" if headers_only else "(BODY.PEEK[])"
    typ, data = imap.uid("FETCH", uid, item)
    if typ != "OK" or not data:
        return None
    for part in data:
        if isinstance(part, tuple) and len(part) > 1 and part[1]:
            return part[1]
    return None


# --------------------------------------------------------------------- main

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Fetch your own Gmail into an UNLABELED review queue for manual triage.",
        epilog="Nothing this script writes is labeled. See eval/COLLECTION.md.",
    )
    ap.add_argument("--query", default=DEFAULT_QUERY, help="override the Gmail search query")
    ap.add_argument("--limit", type=int, default=DEFAULT_LIMIT,
                    help=f"max NEW messages to save per run (default {DEFAULT_LIMIT})")
    ap.add_argument("--folders", nargs="+", choices=sorted(FOLDERS), default=sorted(FOLDERS),
                    help="subset of folders to search (default: all three)")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what WOULD be fetched, per folder. Writes nothing.")
    args = ap.parse_args(argv)

    address = os.environ.get("GMAIL_ADDRESS", "").strip()
    app_password = os.environ.get("GMAIL_APP_PASSWORD", "").strip()
    if not address or not app_password:
        missing = [n for n, v in
                   (("GMAIL_ADDRESS", address), ("GMAIL_APP_PASSWORD", app_password)) if not v]
        print(
            f"Missing required environment variable(s): {', '.join(missing)}\n\n"
            "This script never stores credentials. Set them for the current shell:\n\n"
            "  bash/zsh:    export GMAIL_ADDRESS='you@gmail.com'\n"
            "               export GMAIL_APP_PASSWORD='abcd efgh ijkl mnop'\n\n"
            "  PowerShell:  $env:GMAIL_ADDRESS='you@gmail.com'\n"
            "               $env:GMAIL_APP_PASSWORD='abcd efgh ijkl mnop'\n\n"
            "GMAIL_APP_PASSWORD must be a 16-character Google App Password, not your\n"
            "normal account password. Setup steps: eval/tools/README.md\n",
            file=sys.stderr,
        )
        return 2

    if args.limit <= 0:
        print("--limit must be positive.", file=sys.stderr)
        return 2

    print(f"Connecting to {IMAP_HOST} as {address} (read-only) ...")
    imap = connect(address, app_password)

    seen = _load_seen()
    print(f"Dedupe store: {len(seen)} message(s) already collected.\n")

    per_folder: dict[str, dict[str, int]] = {}
    new_rows: list[dict] = []
    new_keys: list[str] = []
    run_keys: set[str] = set()          # dedupe across folders within this run
    budget_hit = False

    try:
        for label in args.folders:
            mailbox = FOLDERS[label]
            uids = search_folder(imap, mailbox, args.query)
            if uids is None:
                print(f"  ! could not open {mailbox} - skipping.")
                print("    Gmail localises these names on non-English accounts. Yours are:")
                for name in _list_mailboxes(imap):
                    print(f"      {name}")
                per_folder[label] = {"matched": 0, "new": 0, "seen": 0, "unknown": 0}
                continue

            stats = {"matched": len(uids), "new": 0, "seen": 0, "unknown": 0}

            for uid in uids:
                if len(new_keys) >= args.limit:
                    budget_hit = True
                    break

                raw = fetch_raw(imap, uid, headers_only=args.dry_run)
                if raw is None:
                    continue
                msg = email.message_from_bytes(raw)

                if args.dry_run:
                    mid = (msg.get("Message-ID") or "").strip().strip("<>")
                    if not mid:
                        # Its key is a hash of the full body, which a header-only
                        # fetch cannot compute. Counted honestly as unknown.
                        stats["unknown"] += 1
                        continue
                    if mid in seen or mid in run_keys:
                        stats["seen"] += 1
                    else:
                        stats["new"] += 1
                        run_keys.add(mid)
                        new_keys.append(mid)   # budget accounting only; not persisted
                    continue

                key = _message_key(msg, raw)
                if key in seen or key in run_keys:
                    stats["seen"] += 1
                    continue

                meta = describe(msg)
                filename = build_filename(meta, raw)
                REVIEW_DIR.mkdir(parents=True, exist_ok=True)
                (REVIEW_DIR / filename).write_bytes(raw)

                run_keys.add(key)
                new_keys.append(key)
                stats["new"] += 1
                new_rows.append({
                    "filename": filename,
                    "fetched_from": label,
                    "date": meta["date"],
                    "from_domain": meta["from_domain"],
                    "subject": meta["subject"],
                    "has_auth_results": meta["has_auth_results"],
                    "has_attachments": meta["has_attachments"],
                    "label": "",     # deliberately blank - a human decides
                    "notes": "",
                })

            per_folder[label] = stats
            if budget_hit:
                break
    finally:
        # No close() - that is only needed to expunge, and we never modify anything.
        try:
            imap.logout()
        except Exception:
            pass

    if not args.dry_run and new_rows:
        REVIEW_DIR.mkdir(parents=True, exist_ok=True)
        write_header = not QUEUE_CSV.exists()
        with QUEUE_CSV.open("a", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=QUEUE_COLUMNS)
            if write_header:
                writer.writeheader()
            writer.writerows(new_rows)
        _append_seen(new_keys)

    # ------------------------------------------------------------- summary
    print()
    print("=" * 70)
    print("DRY RUN - nothing written" if args.dry_run else "FETCH COMPLETE")
    print("=" * 70)
    print(f"{'folder':<12}{'matched':>9}{'new':>7}{'already seen':>14}{'unknown':>9}")
    print("-" * 70)
    total = {"matched": 0, "new": 0, "seen": 0, "unknown": 0}
    for label in args.folders:
        s = per_folder.get(label, {"matched": 0, "new": 0, "seen": 0, "unknown": 0})
        print(f"{label:<12}{s['matched']:>9}{s['new']:>7}{s['seen']:>14}{s['unknown']:>9}")
        for k in total:
            total[k] += s[k]
    print("-" * 70)
    print(f"{'TOTAL':<12}{total['matched']:>9}{total['new']:>7}"
          f"{total['seen']:>14}{total['unknown']:>9}")
    print()
    print("Note: the same message appears in All Mail and in Spam/Trash. Cross-folder")
    print("duplicates are collapsed, so 'new' is already the de-duplicated count.")

    if total["unknown"]:
        print(f"\n{total['unknown']} message(s) have no Message-ID; a dry run cannot tell")
        print("whether those are new. A real run dedupes them by content hash.")

    if budget_hit:
        print(f"\nStopped at --limit {args.limit}. Re-run to continue where this left off.")

    if args.dry_run:
        print("\nThis was a dry run. Re-run without --dry-run to save the messages.")
        return 0

    if not new_rows:
        print("\nNo new messages. Nothing written.")
        return 0

    print(f"\nSaved {len(new_rows)} raw .eml file(s) to:")
    print(f"  {REVIEW_DIR}")
    print(f"Queue updated: {QUEUE_CSV}")
    print(f"Dedupe store:  {SEEN_IDS}")
    print()
    print("!" * 70)
    print("NOTHING IS LABELED. The 'label' column is intentionally blank.")
    print("The folder a message came from is NOT its class - plenty of real")
    print("sponsorship offers land in Spam, and plenty of scams reach the inbox.")
    print("!" * 70)
    print("\nNext, by hand, per eval/COLLECTION.md:")
    print("  1. Read each message and decide scam / legit by SECURITY THREAT,")
    print("     not by how good the offer is. When unsure: skip it.")
    print("  2. Redact the recipient side (To/Cc/Bcc, your name, personal IDs).")
    print("     KEEP From, Reply-To, Authentication-Results, Received, links.")
    print("  3. Move it to eval/corpus/sponsorship/private/{scam,legit}/ and add")
    print("     a manifest row with source=real plus why you labeled it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
