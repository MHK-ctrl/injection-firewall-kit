"""Shared machinery for regex-based detectors.

Design rules for every detector in this package:

* deterministic (no randomness, no clock, no network, no model calls)
* explainable (a finding always says why it fired, in plain language)
* bounded (matching is linear in the input size; no exponential backtracking)
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from re import Pattern

from ..types import Finding

#: Words that suggest the surrounding text is *talking about* injection rather than
#: performing it (a security blog post, a detector's own test fixture, a bug report).
#: When one of these appears next to a match we still report the finding, but we
#: downgrade it, so documentation about attacks does not dominate the risk score.
META_DISCOURSE = re.compile(
    r"(?:attacks?|attacker|injection|malicious|detect(?:or|ion)?|defen[cs]e|red[- ]?team|"
    r"heuristic|payload|vulnerab\w*|mitigat\w*|safeguard\w*|quarantin\w*|sanitiz\w*|"
    r"scanner|firewall|jailbreak(?:ed)? sample|test fixture|false positive|"
    r"social engineering|threat model|phishing|scam|fraud)",
    re.IGNORECASE,
)

QUOTE_CHARS = "\"'`\u2018\u2019\u201c\u201d"

_MAX_SNIPPET = 120


def snippet(text: str, start: int, end: int, width: int = 40) -> str:
    """Return a short, control-character-free excerpt around a match."""
    left = max(0, start - width)
    right = min(len(text), end + width)
    raw = text[left:right].replace("\n", " ").replace("\r", " ")
    raw = "".join(ch if ch.isprintable() else "\u00b7" for ch in raw)
    raw = re.sub(r"\s+", " ", raw).strip()
    if len(raw) > _MAX_SNIPPET:
        raw = raw[: _MAX_SNIPPET - 1] + "\u2026"
    return raw


def is_quoted(text: str, start: int, end: int) -> bool:
    """True when the match sits between a pair of quote characters."""
    before = text[:start].rstrip()
    after = text[end:].lstrip()
    if not before or not after:
        return False
    return before[-1] in QUOTE_CHARS and after[0] in QUOTE_CHARS


def looks_like_meta_discourse(text: str, start: int, end: int, window: int = 120) -> bool:
    """True when nearby words indicate the text is *about* attacks, not performing one."""
    context = text[max(0, start - window) : start] + " " + text[end : end + window]
    return bool(META_DISCOURSE.search(context))


_DOWNGRADE = {"critical": "high", "high": "medium", "medium": "low", "low": "info", "info": "info"}


@dataclass(frozen=True)
class Rule:
    """A named regex rule that produces one finding per distinct match."""

    name: str
    pattern: str
    category: str
    severity: str
    reason: str
    action: str = "warn"
    flags: int = re.IGNORECASE
    #: Only fire if this secondary regex also matches somewhere in the text.
    requires: str | None = None
    #: Downgrade one severity step when the match is quoted or near meta-discourse.
    allow_downgrade: bool = True
    max_matches: int = 3


class RegexDetector:
    """Base class: run a list of :class:`Rule` objects over the text.

    Subclasses set ``name``, ``description`` and ``rules``; they may override
    :meth:`post_process` to add non-regex analysis (decoding, length checks, ...).

    This is deliberately *not* a dataclass: a dataclass ``__init__`` would assign the
    inherited default for ``rules`` and silently discard the subclass's rule table.
    """

    name: str = "base"
    description: str = ""
    rules: Sequence[Rule] = ()

    def __init__(self, rules: Sequence[Rule] | None = None) -> None:
        if rules is not None:
            self.rules = tuple(rules)
        # Compile once per instance; instances are module-level singletons.
        self._compiled: list[tuple[Rule, Pattern[str], Pattern[str] | None]] = []
        for rule in self.rules:
            compiled = re.compile(rule.pattern, rule.flags)
            requires = re.compile(rule.requires, rule.flags) if rule.requires else None
            self._compiled.append((rule, compiled, requires))

    # -- public API ---------------------------------------------------------

    def detect(self, text: str, carrier: str = "unknown") -> list[Finding]:
        findings: list[Finding] = []
        if not text:
            return findings
        for rule, compiled, requires in self._compiled:
            if requires is not None and not requires.search(text):
                continue
            emitted = 0
            for match in compiled.finditer(text):
                start, end = match.span()
                if start == end:
                    continue
                findings.append(self._make_finding(rule, text, start, end))
                emitted += 1
                if emitted >= rule.max_matches:
                    break
        findings.extend(self.post_process(text, carrier))
        return findings

    def post_process(self, text: str, carrier: str) -> list[Finding]:
        """Hook for analysis that is not a single regex match."""
        return []

    # -- helpers ------------------------------------------------------------

    def _make_finding(self, rule: Rule, text: str, start: int, end: int) -> Finding:
        severity = rule.severity
        reason = rule.reason
        if rule.allow_downgrade:
            quoted = is_quoted(text, start, end)
            meta = looks_like_meta_discourse(text, start, end)
            if quoted or meta:
                severity = _DOWNGRADE[severity]
                reason += (
                    " (downgraded: the match is quoted or sits next to discussion of "
                    "attacks, which is typical of documentation rather than a payload)"
                )
        return Finding(
            detector=self.name,
            category=rule.category,
            severity=severity,
            reason=reason,
            action=rule.action,
            span=(start, end),
            snippet=snippet(text, start, end),
        )

    def finding(
        self,
        category: str,
        severity: str,
        reason: str,
        text: str,
        start: int,
        end: int,
        action: str = "warn",
    ) -> Finding:
        """Construct a finding for :meth:`post_process` implementations."""
        return Finding(
            detector=self.name,
            category=category,
            severity=severity,
            reason=reason,
            action=action,
            span=(start, end),
            snippet=snippet(text, start, end),
        )


def dedupe(findings: Iterable[Finding]) -> list[Finding]:
    """Drop findings that are identical in category, span and detector."""
    seen = set()
    out: list[Finding] = []
    for finding in findings:
        key = (finding.detector, finding.category, finding.span)
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out
