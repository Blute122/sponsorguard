"""Rule registry.

Every rule is a pure function `ParsedEmail -> Finding | list[Finding] | None`,
registered with @rule. Purity is deliberate: each rule is trivially unit-testable
against an .eml fixture, and the engine stays a dumb loop.

Import the rule modules (below) for their side effect of registering.
"""
from __future__ import annotations

from typing import Callable, Iterable

from ..models import Finding, ParsedEmail

RuleFn = Callable[[ParsedEmail], "Finding | list[Finding] | None"]
_REGISTRY: list[RuleFn] = []


def rule(fn: RuleFn) -> RuleFn:
    _REGISTRY.append(fn)
    return fn


def all_rules() -> list[RuleFn]:
    return list(_REGISTRY)


def run_rules(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    for fn in _REGISTRY:
        result = fn(email)
        if result is None:
            continue
        if isinstance(result, Finding):
            findings.append(result)
        elif isinstance(result, Iterable):
            findings.extend(result)
    return findings


# Register rules by importing the modules. Order does not matter — scoring sorts.
from . import auth, identity, links, attachments, content  # noqa: E402,F401
