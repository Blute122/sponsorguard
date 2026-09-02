"""Core data structures passed between the parse, rule, scoring and report stages."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Category(str, Enum):
    AUTH = "auth"
    IDENTITY = "identity"
    LINKS = "links"
    ATTACH = "attach"
    CONTENT = "content"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Verdict(str, Enum):
    LOW = "Low"            # 0-14
    CAUTION = "Caution"    # 15-34
    HIGH = "High risk"     # 35-59
    DANGEROUS = "Dangerous"  # 60-100 or any hard flag


@dataclass
class Link:
    href: str            # the actual destination
    text: str = ""       # the visible/display text (may itself be a URL)
    href_domain: str = ""
    text_domain: str = ""


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    payload: bytes = b""  # raw decoded bytes, used for archive inspection


@dataclass
class ParsedEmail:
    from_addr: str = ""
    from_domain: str = ""
    display_name: str = ""
    reply_to: str = ""
    reply_to_domain: str = ""
    subject: str = ""
    body_text: str = ""          # normalized, lowercased plain text for content rules
    body_raw: str = ""           # original text (any casing) for evidence snippets
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    auth_results: Optional[str] = None  # raw Authentication-Results header, or None if absent


@dataclass
class Finding:
    id: str
    category: Category
    points: int
    evidence: str          # the literal offending string — this is what sells the report
    explanation: str       # why this is suspicious
    remediation: str       # what the user should do about it
    severity: Severity = Severity.INFO
    hard_flag: bool = False  # forces the top verdict regardless of total


@dataclass
class Report:
    score: int
    verdict: Verdict
    top_reasons: list[str]
    safe_next_step: str
    findings: list[Finding]

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "verdict": self.verdict.value,
            "top_reasons": self.top_reasons,
            "safe_next_step": self.safe_next_step,
            "findings": [
                {
                    "id": f.id,
                    "category": f.category.value,
                    "severity": f.severity.value,
                    "points": f.points,
                    "evidence": f.evidence,
                    "explanation": f.explanation,
                    "remediation": f.remediation,
                }
                for f in self.findings
            ],
        }
