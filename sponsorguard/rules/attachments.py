"""Attachment rules — the malware-delivery half of the attack.

Zip contents are inspected directly (encryption flag + inner extensions). RAR/7z
can't be introspected without extra deps, so they're flagged at a lower weight
and noted as uninspected rather than silently passed.
"""
from __future__ import annotations

import io
import re
import zipfile

from . import rule
from ..models import Attachment, Category, Finding, ParsedEmail, Severity

_ARCHIVE_EXT = (".zip", ".rar", ".7z")
_DANGEROUS_EXT = (".exe", ".scr", ".js", ".jse", ".vbs", ".bat", ".cmd",
                  ".com", ".pif", ".lnk", ".docm", ".xlsm", ".pptm", ".jar", ".msi")
_DOUBLE_EXT_RE = re.compile(r"\.(pdf|doc|jpg|png|txt|xls)\.(exe|scr|js|bat|cmd|com|lnk)$", re.IGNORECASE)


def _zip_findings(att: Attachment):
    try:
        zf = zipfile.ZipFile(io.BytesIO(att.payload))
    except Exception:
        return None  # not a readable zip; leave to the generic archive rule
    encrypted = any(info.flag_bits & 0x1 for info in zf.infolist())
    inner_bad = [n for n in zf.namelist() if n.lower().endswith(_DANGEROUS_EXT)]
    if encrypted:
        return Finding(
            id="attach.password_protected_archive",
            category=Category.ATTACH,
            points=30,
            severity=Severity.HIGH,
            hard_flag=True,
            evidence=f"{att.filename} (encrypted zip)",
            explanation="Password-protected archive — the signature trick to smuggle malware past antivirus.",
            remediation="Do not open or extract. Legitimate brands never send password-locked archives.",
        )
    if inner_bad:
        return Finding(
            id="attach.executable_in_archive",
            category=Category.ATTACH,
            points=30,
            severity=Severity.HIGH,
            hard_flag=True,
            evidence=f"{att.filename} contains {inner_bad[0]}",
            explanation="Archive contains an executable/macro file.",
            remediation="Do not extract or run — this is a direct malware-delivery vector.",
        )
    return None


@rule
def dangerous_attachments(email: ParsedEmail):
    findings = []
    for att in email.attachments:
        name = att.filename.lower()

        if _DOUBLE_EXT_RE.search(name):
            findings.append(Finding(
                id="attach.double_extension",
                category=Category.ATTACH, points=25, severity=Severity.HIGH, hard_flag=True,
                evidence=att.filename,
                explanation="Double extension disguises an executable as a document.",
                remediation="Delete without opening.",
            ))
            continue

        if name.endswith(_DANGEROUS_EXT):
            findings.append(Finding(
                id="attach.executable",
                category=Category.ATTACH, points=30, severity=Severity.HIGH, hard_flag=True,
                evidence=att.filename,
                explanation="Directly executable / macro-enabled attachment.",
                remediation="Do not run. No sponsorship brief is ever an executable.",
            ))
            continue

        if name.endswith(".zip"):
            zf = _zip_findings(att)
            if zf:
                findings.append(zf)
            continue

        if name.endswith((".rar", ".7z")):
            findings.append(Finding(
                id="attach.uninspected_archive",
                category=Category.ATTACH, points=12, severity=Severity.MEDIUM,
                evidence=att.filename,
                explanation="Compressed archive whose contents can't be inspected here — a common malware wrapper.",
                remediation="Scan with antivirus before extracting; be wary if it's password-protected.",
            ))
    return findings
