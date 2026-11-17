"""Core data types shared by the scanner, policy engine and harness."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")

#: Contribution of one finding to the overall risk, before combination.
#: A single ``critical`` finding already puts content in quarantine territory.
SEVERITY_WEIGHT = {
    "info": 0.05,
    "low": 0.18,
    "medium": 0.38,
    "high": 0.68,
    "critical": 0.92,
}

#: Ordered from least to most restrictive. ``max`` on these strings is meaningful
#: because the order is declared here and used by :mod:`firewall.policy`.
ACTIONS: tuple[str, ...] = ("allow", "warn", "sanitize", "quarantine", "block")

#: The attack taxonomy. Corpus categories must come from this list.
CATEGORIES: tuple[str, ...] = (
    "direct_instruction_override",
    "role_hijack",
    "delimiter_spoof",
    "hidden_text",
    "encoding_obfuscation",
    "multilingual_injection",
    "payload_splitting",
    "fake_tool_result",
    "exfiltration",
    "tool_abuse",
    "social_engineering",
    "context_poisoning",
)

#: Carriers are where the untrusted text came from. The harness reports per carrier
#: so you can see that, for example, PDF-extracted text behaves differently from JSON.
CARRIERS: tuple[str, ...] = (
    "email_body",
    "html_page",
    "markdown_doc",
    "pdf_text",
    "json_tool_output",
    "code_comment",
    "csv_cell",
    "calendar_invite",
    "filename_metadata",
)


def action_rank(action: str) -> int:
    """Return the position of ``action`` in the escalation ladder."""
    try:
        return ACTIONS.index(action)
    except ValueError as exc:  # pragma: no cover - defensive
        raise ValueError(f"unknown action {action!r}; expected one of {ACTIONS}") from exc


def max_action(*actions: str) -> str:
    """Return the most restrictive action of the given set."""
    ranked = [a for a in actions if a]
    if not ranked:
        return "allow"
    return max(ranked, key=action_rank)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    """One explainable observation about a piece of untrusted content."""

    detector: str
    category: str
    severity: str
    reason: str
    action: str = "warn"
    span: tuple[int, int] | None = None
    snippet: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_WEIGHT:
            raise ValueError(f"unknown severity {self.severity!r}")
        if self.category not in CATEGORIES:
            raise ValueError(f"unknown category {self.category!r}")
        if self.action not in ACTIONS:
            raise ValueError(f"unknown action {self.action!r}")

    @property
    def weight(self) -> float:
        return SEVERITY_WEIGHT[self.severity]

    def as_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "category": self.category,
            "severity": self.severity,
            "reason": self.reason,
            "action": self.action,
            "span": list(self.span) if self.span else None,
            "snippet": self.snippet,
        }

    def __str__(self) -> str:  # pragma: no cover - presentation only
        where = f" @{self.span[0]}-{self.span[1]}" if self.span else ""
        return f"[{self.severity}] {self.category}/{self.detector}{where}: {self.reason}"


# ---------------------------------------------------------------------------
# Scan results
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """Aggregate result of scanning one piece of untrusted content."""

    carrier: str = "unknown"
    length: int = 0
    findings: list[Finding] = field(default_factory=list)
    detectors_run: int = 0
    risk: float = 0.0

    @property
    def risk_score(self) -> int:
        """Risk on a 0-100 scale, rounded for humans."""
        return int(round(min(1.0, max(0.0, self.risk)) * 100))

    @property
    def blocked(self) -> bool:
        """True when the content is at or above the default block threshold."""
        return self.risk_score >= 85

    @property
    def flagged(self) -> bool:
        """True when any detector produced a finding that is worth acting on."""
        return self.risk_score >= 20

    @property
    def categories(self) -> list[str]:
        seen: list[str] = []
        for finding in self.findings:
            if finding.category not in seen:
                seen.append(finding.category)
        return seen

    def by_category(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.category, []).append(finding)
        return grouped

    def by_severity(self) -> dict[str, int]:
        counts = dict.fromkeys(SEVERITIES, 0)
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def top_findings(self, n: int = 3) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.weight, reverse=True)[:n]

    def explain(self, limit: int = 5) -> str:
        """Human-readable, stable summary. Used by the CLI and the report."""
        lines = [
            f"risk score: {self.risk_score}/100  ({len(self.findings)} finding(s), "
            f"carrier={self.carrier})"
        ]
        if not self.findings:
            lines.append("no findings")
            return "\n".join(lines)
        for finding in self.top_findings(limit):
            span = f" [{finding.span[0]}:{finding.span[1]}]" if finding.span else ""
            lines.append(f"  - {finding.severity:<8} {finding.category:<28}{span}")
            lines.append(f"    {finding.reason}")
            if finding.snippet:
                lines.append(f'    near: "{finding.snippet}"')
        if len(self.findings) > limit:
            lines.append(f"  ... {len(self.findings) - limit} more finding(s)")
        return "\n".join(lines)

    def as_dict(self) -> dict[str, Any]:
        return {
            "carrier": self.carrier,
            "length": self.length,
            "risk_score": self.risk_score,
            "risk": round(self.risk, 4),
            "flagged": self.flagged,
            "detectors_run": self.detectors_run,
            "categories": self.categories,
            "findings": [f.as_dict() for f in self.findings],
        }


@dataclass
class Decision:
    """A policy decision: what to do with the content, and why."""

    action: str
    score: int
    reasons: list[str] = field(default_factory=list)
    policy_name: str = "balanced"

    @property
    def allowed(self) -> bool:
        return self.action in ("allow", "warn")

    @property
    def must_sanitize(self) -> bool:
        return action_rank(self.action) >= action_rank("sanitize")

    @property
    def must_block(self) -> bool:
        return self.action == "block"

    @property
    def needs_human(self) -> bool:
        return self.action == "quarantine"

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "score": self.score,
            "policy": self.policy_name,
            "reasons": self.reasons,
        }


def combine_findings(findings: Sequence[Finding]) -> float:
    """Combine finding weights into a 0..1 risk using a noisy-or.

    Two independent ``medium`` findings are riskier than one, but the score can never
    exceed 1.0, and a single critical finding already dominates. The escalation term
    rewards breadth: content that trips three different categories is worse than content
    that trips one category three times, because independent signals are harder to
    explain away as a false positive.
    """
    if not findings:
        return 0.0
    remaining = 1.0
    for finding in findings:
        remaining *= 1.0 - SEVERITY_WEIGHT[finding.severity]
    base = 1.0 - remaining
    distinct = len({f.category for f in findings})
    escalation = 0.05 * max(0, distinct - 2)
    return min(1.0, base * (1.0 + escalation))


def iter_findings(results: Iterable[ScanResult]) -> Iterable[Finding]:
    for result in results:
        yield from result.findings
