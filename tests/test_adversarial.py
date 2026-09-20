"""Adversarial suite: prove the normalization pass defeats real evasions.

Each test builds an email that WOULD slip past naive substring/regex matching,
then asserts (a) the intended finding still fires and (b) the verdict is
unchanged from the clean, un-obfuscated equivalent. Several tests also assert the
evasion genuinely defeats naive matching (the keyword is absent from the raw
lowercased body) so the test can't silently pass for the wrong reason — and that
the Finding's evidence still quotes the attacker's REAL text, not the folded
skeleton.
"""
from __future__ import annotations

from pathlib import Path

from sponsorguard.models import Verdict
from sponsorguard.parser import parse_email
from sponsorguard.scoring import analyze

FIX = Path(__file__).parent / "fixtures"

NEUTRAL_FROM = "Partner Team <deals@mailer.example>"


def _eml(*, body=None, html=None, plain=None, frm=NEUTRAL_FROM,
         subject="Partnership opportunity", auth=None) -> bytes:
    """Assemble a raw .eml. Single text/plain, single text/html, or multipart."""
    headers = [f"From: {frm}", "To: creator@example.com", f"Subject: {subject}"]
    if auth:
        headers.append(f"Authentication-Results: {auth}")
    headers.append("MIME-Version: 1.0")

    if html is not None and plain is not None:
        b = "ADVBOUND"
        headers.append(f'Content-Type: multipart/alternative; boundary="{b}"')
        parts = (
            f"--{b}\nContent-Type: text/plain; charset=utf-8\n\n{plain}\n"
            f"--{b}\nContent-Type: text/html; charset=utf-8\n\n{html}\n"
            f"--{b}--\n"
        )
        raw = "\n".join(headers) + "\n\n" + parts
    elif html is not None:
        headers.append('Content-Type: text/html; charset="utf-8"')
        raw = "\n".join(headers) + "\n\n" + html
    else:
        headers.append('Content-Type: text/plain; charset="utf-8"')
        raw = "\n".join(headers) + "\n\n" + (body or "")
    return raw.encode("utf-8")


def _ids(report):
    return {f.id for f in report.findings}


def _finding(report, rule_id):
    return next((f for f in report.findings if f.id == rule_id), None)


# --------------------------------------------------------------------------
# 1. Zero-width space inside a keyword
# --------------------------------------------------------------------------

def test_zero_width_space_in_keyword_is_caught():
    clean = analyze(_eml(body="To continue you must share your password with us."))
    evasive = analyze(_eml(body="To continue you must share your pass​word with us."))

    # Sanity: the evasion really does defeat naive matching.
    assert "password" not in parse_email(
        _eml(body="share your pass​word")).body_text

    assert "content.credential_request" in _ids(clean)
    assert "content.credential_request" in _ids(evasive)
    assert evasive.verdict == clean.verdict
    # Evidence is the real text (with the zero-width char), never a folded token.
    assert "​" in _finding(evasive, "content.credential_request").evidence


def test_zero_width_in_verify_phrase():
    evasive = analyze(_eml(body="Please ver​ify your account to release the deal."))
    clean = analyze(_eml(body="Please verify your account to release the deal."))
    assert "content.credential_request" in _ids(evasive)
    assert evasive.verdict == clean.verdict


# --------------------------------------------------------------------------
# 2. Cyrillic / Greek homoglyphs — domain AND body keywords
# --------------------------------------------------------------------------

def test_cyrillic_homoglyph_domain_is_caught():
    # A real homoglyph domain travels as punycode. 'xn--udible-team-xij' is the
    # IDNA encoding of 'аudible-team' (Cyrillic а, U+0430). Compare to the plain
    # ASCII lookalike, which the engine has always caught.
    from sponsorguard.normalize import host_skeleton
    assert host_skeleton("xn--udible-team-xij") == "audible-team"     # punycode
    assert host_skeleton("аudible-team") == "audible-team"        # raw Cyrillic

    clean = analyze(_eml(frm="Audible Team <deals@audible-team.com>",
                         body="Hello from the team."))
    evasive = analyze(_eml(frm="Audible Team <deals@xn--udible-team-xij.com>",
                           body="Hello from the team."))

    assert "identity.typosquat" in _ids(clean)
    assert "identity.typosquat" in _ids(evasive)
    assert evasive.verdict == clean.verdict
    # Evidence shows the REAL host (the punycode), never the decoded/folded form.
    ev = _finding(evasive, "identity.typosquat").evidence
    assert "xn--udible-team-xij" in ev
    assert "аudible" not in ev and "audible-team.com" not in ev


def test_cyrillic_homoglyph_keyword_is_caught():
    # 'account' with a Cyrillic 'а' (U+0430) and 'о' (U+043E).
    evasive = analyze(_eml(body="Please verify your аccоunt immediately."))
    clean = analyze(_eml(body="Please verify your account immediately."))
    assert "content.credential_request" in _ids(evasive)
    assert evasive.verdict == clean.verdict


def test_greek_homoglyph_keyword_is_caught():
    # 'password' with a Greek omicron 'ο' (U+03BF).
    evasive = analyze(_eml(body="Send us your passwοrd to confirm."))
    clean = analyze(_eml(body="Send us your password to confirm."))
    assert "content.credential_request" in _ids(evasive)
    assert evasive.verdict == clean.verdict


# --------------------------------------------------------------------------
# 3. Full-width / NFKC-foldable characters
# --------------------------------------------------------------------------

def test_fullwidth_keyword_is_caught():
    # Full-width "password" (U+FF50.. range) folds to ASCII under NFKC.
    fullwidth = "ｐａｓｓｗｏｒｄ"  # ｐａｓｓｗｏｒｄ
    assert fullwidth != "password"
    evasive = analyze(_eml(body=f"We need your {fullwidth} to proceed."))
    clean = analyze(_eml(body="We need your password to proceed."))
    assert "content.credential_request" in _ids(evasive)
    assert evasive.verdict == clean.verdict


# --------------------------------------------------------------------------
# 4. HTML entity-encoded payload
# --------------------------------------------------------------------------

def test_html_entity_encoded_keyword_is_caught():
    # &#112; is 'p'; the naive view would see "&#112;assword".
    evasive = analyze(_eml(html="<p>Enter your &#112;assword to verify.</p>"))
    clean = analyze(_eml(html="<p>Enter your password to verify.</p>"))
    assert "content.credential_request" in _ids(evasive)
    assert evasive.verdict == clean.verdict
    # The parser decoded the entity before rules ran.
    assert "password" in parse_email(
        _eml(html="<p>your &#112;assword</p>")).body_full.lower()


def test_html_entity_numeric_and_named_mix():
    # Mix a named entity and a decimal reference inside 'upfront fee'.
    evasive = analyze(_eml(html="<p>A small upfront&nbsp;f&#101;e is required first.</p>"))
    clean = analyze(_eml(html="<p>A small upfront fee is required first.</p>"))
    assert "content.upfront_fee" in _ids(evasive)
    assert evasive.verdict == clean.verdict


# --------------------------------------------------------------------------
# 5. Payload only in text/html, clean text/plain
# --------------------------------------------------------------------------

def test_payload_hidden_in_html_part_only():
    plain = "Hi there, thanks so much for reaching out. Looking forward to it. Cheers."
    html = (
        "<html><body><p>Urgent: you must send your account password within "
        "24 hours or the sponsorship is cancelled.</p></body></html>"
    )
    report = analyze(_eml(plain=plain, html=html))
    ids = _ids(report)

    # The soft mismatch signal fires...
    assert "content.text_html_mismatch" in ids
    # ...and, crucially, the payload buried in the HTML part is still caught,
    # even though the text/plain part is entirely benign.
    assert "content.credential_request" in ids

    # A scanner reading only the clean plain part would find nothing.
    plain_only = analyze(_eml(body=plain))
    assert _ids(plain_only) == set()


def test_matching_plain_and_html_do_not_trip_mismatch():
    # Legitimate multipart mail whose parts say the same thing must NOT be flagged.
    plain = "Hi, we would love to discuss a paid partnership with your channel. Reply anytime."
    html = ("<html><body><p>Hi, we would love to discuss a paid partnership "
            "with your channel. Reply anytime.</p></body></html>")
    report = analyze(_eml(plain=plain, html=html))
    assert "content.text_html_mismatch" not in _ids(report)


# --------------------------------------------------------------------------
# 6. Bidi-control-wrapped text
# --------------------------------------------------------------------------

def test_bidi_wrapped_keyword_is_caught():
    # RLO ... PDF around the keyword; strips to plain text after normalization.
    evasive = analyze(_eml(body="Kindly ‮verify your account‬ before Friday."))
    clean = analyze(_eml(body="Kindly verify your account before Friday."))
    assert "content.credential_request" in _ids(evasive)
    assert evasive.verdict == clean.verdict


# --------------------------------------------------------------------------
# 7. Regression: clean fixtures are unaffected by normalization
# --------------------------------------------------------------------------

def test_clean_scam_fixture_unchanged():
    report = analyze((FIX / "scam_nordvpn.eml").read_bytes())
    assert report.verdict == Verdict.DANGEROUS
    assert report.score == 100
    ids = _ids(report)
    # The exact rule cross-section the scam has always tripped, still intact.
    for rid in (
        "auth.spf_fail", "auth.dmarc_fail", "identity.typosquat",
        "identity.display_name_impersonation", "links.brand_in_subdomain",
        "links.credential_keywords", "attach.password_protected_archive",
        "content.credential_request", "content.upfront_fee",
        "content.brief_download_pretext", "content.urgency",
    ):
        assert rid in ids
    # HTML-only message -> no plain part -> the mismatch rule must stay silent.
    assert "content.text_html_mismatch" not in ids


def test_clean_legit_fixture_gains_no_findings():
    """The trust-critical invariant: normalization creates no false positives."""
    report = analyze((FIX / "legit_brand.eml").read_bytes())
    assert report.verdict == Verdict.LOW
    assert report.score < 15
    assert _ids(report) == set()  # zero findings, exactly as before
