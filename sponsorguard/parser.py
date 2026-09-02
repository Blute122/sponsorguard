"""Parse a raw RFC-822 email (.eml / Gmail 'Show original') into a ParsedEmail.

Uses only the stdlib `email` package. Attachment bytes are decoded here so the
attachment rules can inspect archives without re-parsing.
"""
from __future__ import annotations

import re
from email import message_from_bytes, message_from_string
from email.message import Message
from email.utils import parseaddr
from html.parser import HTMLParser

from .domains import domain_of
from .models import Attachment, Link, ParsedEmail

_URL_RE = re.compile(r"https?://[^\s<>\")]+", re.IGNORECASE)


class _AnchorExtractor(HTMLParser):
    """Collect (href, visible_text) pairs from HTML bodies."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._buf = []

    def handle_data(self, data):
        if self._href is not None:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._buf).strip()))
            self._href = None
            self._buf = []


def _link_domain(url: str) -> str:
    m = re.match(r"https?://([^/\\?#]+)", url or "", re.IGNORECASE)
    return domain_of(m.group(1)) if m else ""


def _extract_bodies(msg: Message) -> tuple[str, str]:
    """Return (plain_text, html) walking multipart messages."""
    plain, html = "", ""
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_filename():  # attachment, skip for body
            continue
        ctype = part.get_content_type()
        try:
            payload = part.get_payload(decode=True)
            text = payload.decode(part.get_content_charset() or "utf-8", errors="replace") if payload else ""
        except Exception:
            text = ""
        if ctype == "text/plain":
            plain += text
        elif ctype == "text/html":
            html += text
    return plain, html


def _extract_links(plain: str, html: str) -> list[Link]:
    links: list[Link] = []
    if html:
        parser = _AnchorExtractor()
        parser.feed(html)
        for href, text in parser.links:
            if not href or href.startswith("mailto:"):
                continue
            links.append(Link(
                href=href, text=text,
                href_domain=_link_domain(href),
                text_domain=_link_domain(text) if text.startswith("http") else "",
            ))
    for url in _URL_RE.findall(plain):
        links.append(Link(href=url, text=url, href_domain=_link_domain(url)))
    return links


def _extract_attachments(msg: Message) -> list[Attachment]:
    out: list[Attachment] = []
    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        out.append(Attachment(
            filename=filename,
            content_type=part.get_content_type(),
            size=len(payload),
            payload=payload,
        ))
    return out


def parse_email(raw: str | bytes) -> ParsedEmail:
    msg = message_from_bytes(raw) if isinstance(raw, bytes) else message_from_string(raw)

    display_name, from_addr = parseaddr(msg.get("From", ""))
    _, reply_to = parseaddr(msg.get("Reply-To", ""))
    plain, html = _extract_bodies(msg)
    # Fall back to a stripped-tags view of the HTML if there is no plain part.
    body_raw = plain or re.sub(r"<[^>]+>", " ", html)

    return ParsedEmail(
        from_addr=from_addr.lower(),
        from_domain=domain_of(from_addr),
        display_name=display_name.strip(),
        reply_to=reply_to.lower(),
        reply_to_domain=domain_of(reply_to),
        subject=msg.get("Subject", "").strip(),
        body_text=body_raw.lower(),
        body_raw=body_raw,
        links=_extract_links(plain, html),
        attachments=_extract_attachments(msg),
        auth_results=msg.get("Authentication-Results"),
    )
