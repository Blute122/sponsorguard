"""Input normalization: fold away the tricks attackers use to dodge naive matching.

The engine's rules pattern-match on text. A plain `re.search` for ``password``
misses ``pass​word`` (zero-width space), ``раssword`` (Cyrillic а/о),
``ｐａｓｓｗｏｒｄ`` (full-width), and ``&#112;assword`` (HTML entity — decoded in the
parser before we get here). This module produces a *normalized view* the rules
can match against so those evasions collapse back to their intent.

CORE PRINCIPLE: normalization is for MATCHING only. It is never shown to the
user. Findings still quote the real, original text (see ``evidence_from_raw``),
so the report proves itself with the attacker's actual bytes — including the
visible homoglyph or the invisible character that was the trick.

Stdlib only: ``unicodedata`` covers NFKC and category lookups.

Steps, in order (see ``normalize``):
  1. NFKC — folds full-width forms, ligatures, compatibility digits, etc.
  2. Strip zero-width / invisible characters and bidi controls.
  3. Strip remaining format (Cf) and control (Cc) characters, keeping \\n and \\t.
  4. Confusable folding to a Latin skeleton (Cyrillic/Greek/digit lookalikes).
  5. Collapse whitespace runs and casefold.

LIMITATION: step 4 uses a hand-rolled map of the *high-frequency* phishing
confusables, NOT the full Unicode confusables table (UTS #39). It covers the
Cyrillic and Greek Latin-lookalikes and digit-for-letter swaps that show up in
real creator-scam mail; exotic homoglyphs (Armenian, Cherokee, fullwidth-only
scripts, mathematical alphanumerics beyond what NFKC folds) are out of scope.
Widening the map is a data change, not a code change — extend ``_CONFUSABLES``.
"""
from __future__ import annotations

import re
import unicodedata

# Characters that are invisible or reorder text, used to split a keyword in two
# or hide payload. Removed outright (mapped to nothing).
_INVISIBLE = {
    "​",  # zero-width space
    "‌",  # zero-width non-joiner
    "‍",  # zero-width joiner
    "⁠",  # word joiner
    "﻿",  # zero-width no-break space / BOM
    "­",  # soft hyphen
    "‎",  # left-to-right mark
    "‏",  # right-to-left mark
    "‪",  # LRE  ┐
    "‫",  # RLE  │ bidi embedding / override controls: wrap text to
    "‬",  # PDF  │ reverse or disguise its logical order
    "‭",  # LRO  │
    "‮",  # RLO  ┘
    "⁦",  # LRI  ┐
    "⁧",  # RLI  │ bidi isolates (newer than the embedding controls)
    "⁨",  # FSI  │
    "⁩",  # PDI  ┘
}

# High-frequency LETTER confusables -> their Latin base. Case-preserving; the
# final casefold in normalize() handles the rest. A curated subset, not UTS #39.
#
# Digit-for-letter swaps are deliberately NOT here: in body text digits carry
# meaning ("within 48 hours", "$5000", "2fa"), and folding them would both break
# rules that match on `\d` and silently rescore legitimate mail. They belong only
# to hostname comparison (see _DIGIT_CONFUSABLES / skeleton), where a digit
# standing in for a letter (n0rdvpn) is the actual evasion.
_LETTER_CONFUSABLES: dict[str, str] = {
    # --- Cyrillic (lowercase) ---
    "а": "a",  # а
    "е": "e",  # е
    "о": "o",  # о
    "р": "p",  # р
    "с": "c",  # с
    "у": "y",  # у
    "х": "x",  # х
    "і": "i",  # і
    "ј": "j",  # ј
    "ѕ": "s",  # ѕ
    "к": "k",  # к
    "һ": "h",  # һ
    "ԁ": "d",  # ԁ
    "ԛ": "q",  # ԛ
    "ɡ": "g",  # ɡ  latin small script g
    "ɱ": "m",  # ɱ  (approx)
    # --- Cyrillic (uppercase) ---
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "У": "Y", "І": "I", "Ј": "J",
    # --- Greek (lowercase) ---
    "ο": "o",  # ο omicron
    "α": "a",  # α alpha
    "ε": "e",  # ε epsilon
    "ρ": "p",  # ρ rho
    "ν": "v",  # ν nu
    "υ": "u",  # υ upsilon
    "ι": "i",  # ι iota
    "κ": "k",  # κ kappa
    # --- Greek (uppercase) ---
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    # --- other Latin lookalikes ---
    "ı": "i",  # ı dotless i
    "ł": "l",  # ł
}

# Digit / symbol -> letter, for HOSTNAME comparison only (mirrors
# domains.normalize_homoglyphs). Applied in skeleton(), never in normalize().
_DIGIT_CONFUSABLES: dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s",
}

_LETTER_TABLE = str.maketrans(_LETTER_CONFUSABLES)
_SKELETON_TABLE = str.maketrans({**_LETTER_CONFUSABLES, **_DIGIT_CONFUSABLES})
_INVISIBLE_TABLE = str.maketrans({ch: None for ch in _INVISIBLE})
_WS_RE = re.compile(r"\s+")


def _strip_format_controls(text: str) -> str:
    """Drop remaining Cf/Cc chars, but keep the whitespace that carries meaning."""
    out = []
    for ch in text:
        if ch in ("\n", "\t"):
            out.append(ch)
            continue
        cat = unicodedata.category(ch)
        if cat in ("Cf", "Cc"):  # format / control
            continue
        out.append(ch)
    return "".join(out)


def skeleton(text: str) -> str:
    """Visual skeleton for comparison: NFKC + strip invisibles + fold confusables.

    No casefold and no whitespace collapse — this is meant for short tokens like
    a hostname label, where ``nоrdvpn`` (Cyrillic о) must fold to ``nordvpn``
    before an edit-distance/substring check, while the caller still shows the
    real host as evidence.
    """
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_INVISIBLE_TABLE)
    text = _strip_format_controls(text)
    return text.translate(_SKELETON_TABLE)  # letters AND digit lookalikes


def host_skeleton(host: str) -> str:
    """Skeleton of a hostname, decoding IDNA/punycode labels first.

    A homoglyph domain reaches us as punycode (``xn--udible-team-xij.com`` for a
    Cyrillic ``аudible-team``); decoding to Unicode, then folding confusables,
    lets a lookalike collapse to its target for comparison. Callers still quote
    the original host (the ``xn--`` form) as evidence — this is match-only.
    Falls back to the raw label if a label isn't valid IDNA.
    """
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return skeleton(".".join(labels))


def normalize(text: str) -> str:
    """Full matching-surface normalization. See module docstring for the steps.

    Folds LETTER homoglyphs only (step 4). Digits are preserved so body patterns
    that count on them ("within 48 hours", "$5000", "2fa") keep working.
    """
    if not text:
        return ""
    text = unicodedata.normalize("NFKC", text)     # 1
    text = text.translate(_INVISIBLE_TABLE)        # 2
    text = _strip_format_controls(text)            # 3
    text = text.translate(_LETTER_TABLE)           # 4: letter confusables only
    text = _WS_RE.sub(" ", text)                   # 5a: collapse whitespace
    return text.casefold().strip()                 # 5b: casefold


def merge_bodies(plain: str, html_text: str) -> str:
    """Merge the plain-text and HTML-derived views into one raw string.

    A payload present in only one MIME part must still be visible to content
    rules. Non-empty parts only, so an HTML-only message merges to just its HTML
    text (no spurious blank line).
    """
    parts = [p for p in (plain, html_text) if p and p.strip()]
    return "\n\n".join(parts)


def _word_set(norm_text: str) -> set[str]:
    return {w for w in norm_text.split(" ") if w}


def text_html_divergence(plain: str, html_text: str) -> bool:
    """True when a plain part and an HTML part carry meaningfully different content.

    The classic evasion is a benign ``text/plain`` beside a malicious
    ``text/html``, betting the scanner reads the clean one. This is a SOFT signal
    — legitimate multipart mail (e.g. a plain 'view in browser' stub beside a
    rich HTML body) diverges too — so the rule that consumes it is low-weight.

    Returns False unless BOTH parts carry real content, so a single-part message
    never trips it.
    """
    pw = _word_set(normalize(plain))
    hw = _word_set(normalize(html_text))
    if len(pw) < 3 or len(hw) < 3:
        return False
    html_only = hw - pw
    # Substantial content lives in the HTML that the plain part never mentions.
    return len(html_only) >= 6 and len(html_only) / len(hw) >= 0.5


def evidence_from_raw(raw_merged: str, patterns: list[str]) -> str | None:
    """Match ``patterns`` against the NORMALIZED view; quote from the RAW text.

    Detection happens on the normalized surface so evasions are caught. Evidence
    is always real email text, never the folded skeleton:

      1. If a pattern matches the raw text directly (the common, no-evasion
         case), quote that raw substring — real casing, real characters.
      2. Otherwise the match only appeared after normalization (an evasion):
         quote the raw *line* whose normalization matches, so the user sees the
         actual deceptive text (the homoglyph, the zero-width, in place).
    """
    norm = normalize(raw_merged)
    if not any(re.search(p, norm) for p in patterns):
        return None

    for p in patterns:  # (1) direct raw hit -> exact real substring
        m = re.search(p, raw_merged, re.IGNORECASE)
        if m:
            return m.group(0).strip()

    for line in raw_merged.splitlines():  # (2) evasion -> real raw line
        if any(re.search(p, normalize(line)) for p in patterns):
            stripped = line.strip()
            if stripped:
                return stripped

    # Last resort: the collapsed raw body (still real characters, never folded).
    collapsed = _WS_RE.sub(" ", raw_merged).strip()
    return collapsed or None
