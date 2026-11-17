"""Check what the model produced before it reaches a user, a log, or another tool.

Inbound scanning is only half the job. The other half: if an injection got through, the
damage usually shows up *in the output* - a canary, a URL with data attached, a tool call
that nobody asked for, a secret copied into the answer.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from .canary import Canary, detect_all, find_tokens
from .types import ACTIONS, action_rank

#: Reserved domains that are safe to appear in output during tests and docs.
#: ``attacker.example.invalid`` is deliberately *not* covered: ``.invalid`` is reserved,
#: but a subdomain nobody controls is still somewhere data should not go.
SAFE_DOMAINS = ("example.com", "example.org", "example.net", "example.invalid")

_SECRET_PATTERNS: Sequence[tuple[str, str]] = (
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS access key id"),
    (r"\bASIA[0-9A-Z]{16}\b", "AWS temporary access key id"),
    (r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", "GitHub token"),
    (r"\bsk-[A-Za-z0-9_-]{16,}\b", "OpenAI-style API key"),
    (r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "Slack token"),
    (r"-----BEGIN [A-Z ]{0,20}PRIVATE KEY-----", "private key block"),
    (r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b", "JSON Web Token"),
    (r"(?i)\bpassword\s*[:=]\s*\S{8,}", "hard-coded password"),
)

_URL = re.compile(r"\bhttps?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})[^\s\"'<>)]*", re.IGNORECASE)
_MARKDOWN_IMAGE = re.compile(r"!\[[^\]\n]{0,120}\]\(\s*https?://", re.IGNORECASE)
_HTML_IMAGE = re.compile(r"<img\b[^>]{0,200}src\s*=\s*[\"']?https?://", re.IGNORECASE)
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{60,}={0,2}(?![A-Za-z0-9+/=])")
_PROMPT_ECHO = re.compile(
    r"(?i)\b(?:my|the) (?:system prompt|instructions) (?:are|is|say|says|begin|start)\b"
)


@dataclass(frozen=True)
class Violation:
    rule: str
    severity: str
    reason: str
    suggested_action: str = "block"
    snippet: str = ""

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "reason": self.reason,
            "suggested_action": self.suggested_action,
            "snippet": self.snippet,
        }


@dataclass
class OutputVerdict:
    """What to do with the model's answer."""

    ok: bool
    action: str = "allow"
    violations: list[Violation] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "action": self.action,
            "violations": [v.as_dict() for v in self.violations],
        }


def _domain_of(url: str) -> str:
    match = _URL.search(url)
    return match.group(1).lower() if match else ""


def _is_allowed_domain(domain: str, allowed: Sequence[str]) -> bool:
    """Exact match only.

    Subdomain matching would quietly allow ``attacker.example.com`` because it ends with
    an allowed domain, so the allow-list is explicit. Add the subdomains you need.
    """
    return domain in {d.lower() for d in allowed}


class OutputGuard:
    """Deterministic checks over model output and tool calls."""

    def __init__(
        self,
        *,
        allowed_domains: Sequence[str] = SAFE_DOMAINS,
        canaries: Iterable[Canary] = (),
        allowed_tools: Sequence[str] | None = None,
        expected_tools: Sequence[str] | None = None,
        check_secrets: bool = True,
        allow_bare_urls: bool = False,
    ) -> None:
        self.allowed_domains = tuple(allowed_domains)
        self.canaries = tuple(canaries)
        self.allowed_tools = set(allowed_tools) if allowed_tools is not None else None
        self.expected_tools = set(expected_tools) if expected_tools is not None else None
        self.check_secrets = check_secrets
        self.allow_bare_urls = allow_bare_urls

    def check(
        self,
        text: str,
        tool_calls: Iterable[dict] = (),
    ) -> OutputVerdict:
        violations: list[Violation] = []
        text = text or ""

        for leak in detect_all(text, self.canaries):
            violations.append(
                Violation(
                    "canary_leak",
                    "critical",
                    f"model output contains the canary {leak.canary.value!r}; an injection "
                    "succeeded",
                )
            )

        for token in find_tokens(text):
            if token not in {c.value for c in self.canaries}:
                violations.append(
                    Violation(
                        "unknown_canary",
                        "high",
                        f"output contains {token!r}, a canary this app never issued",
                        suggested_action="warn",
                    )
                )

        for pattern, label in _SECRET_PATTERNS:
            if not self.check_secrets:
                break
            match = re.search(pattern, text)
            if match:
                violations.append(
                    Violation(
                        "secret_in_output",
                        "critical",
                        f"output looks like it contains a {label}",
                        snippet=match.group(0)[:12] + "...",
                    )
                )

        if _MARKDOWN_IMAGE.search(text):
            violations.append(
                Violation(
                    "remote_image",
                    "high",
                    "output embeds a remote image; rendering it would leak a request",
                )
            )
        elif _HTML_IMAGE.search(text):
            violations.append(
                Violation("remote_image", "high", "output embeds a remote image tag")
            )

        if not self.allow_bare_urls:
            for match in _URL.finditer(text):
                domain = match.group(1).lower()
                if not _is_allowed_domain(domain, self.allowed_domains):
                    violations.append(
                        Violation(
                            "external_url",
                            "medium",
                            f"output links to {domain!r}, which is not on the allow-list",
                            suggested_action="warn",
                            snippet=match.group(0)[:80],
                        )
                    )
                    break

        if _BASE64.search(text):
            violations.append(
                Violation(
                    "base64_blob",
                    "medium",
                    "output contains a long base64 blob, a common way to smuggle data past "
                    "readers",
                )
            )

        if _PROMPT_ECHO.search(text):
            violations.append(
                Violation(
                    "prompt_echo",
                    "medium",
                    "output appears to quote the system prompt or its instructions",
                    suggested_action="warn",
                )
            )

        violations.extend(self._check_tools(tool_calls))

        action = "allow"
        for violation in violations:
            if action_rank(violation.suggested_action) > action_rank(action):
                action = violation.suggested_action
        if action not in ACTIONS:  # pragma: no cover - defensive
            action = "block"
        return OutputVerdict(ok=not violations, action=action, violations=violations)

    # -- tool calls ---------------------------------------------------------

    def _check_tools(self, tool_calls: Iterable[dict]) -> list[Violation]:
        violations: list[Violation] = []
        calls = list(tool_calls or [])
        if self.allowed_tools is not None:
            for call in calls:
                name = str(call.get("name") or call.get("tool") or "")
                if name not in self.allowed_tools:
                    violations.append(
                        Violation(
                            "unexpected_tool",
                            "high",
                            f"model tried to call {name!r}, which is not in the allow-list",
                        )
                    )
        if self.expected_tools is not None:
            for call in calls:
                name = str(call.get("name") or call.get("tool") or "")
                if name not in self.expected_tools:
                    violations.append(
                        Violation(
                            "unsolicited_tool",
                            "high",
                            f"model called {name!r} although the user never asked for a tool",
                        )
                    )
        if len(calls) > 5:
            violations.append(
                Violation(
                    "tool_call_flood",
                    "medium",
                    f"{len(calls)} tool calls in one turn; possible abuse or a loop",
                    suggested_action="warn",
                )
            )
        for call in calls:
            blob = str(call.get("arguments") or call.get("args") or "")
            if _URL.search(blob) and not _is_allowed_domain(
                _domain_of(blob), self.allowed_domains
            ):
                violations.append(
                    Violation(
                        "tool_call_external_url",
                        "high",
                        "tool arguments contain an external URL; that is where data would go",
                        snippet=blob[:80],
                    )
                )
        return violations


def guard_output(
    text: str,
    *,
    canaries: Iterable[Canary] = (),
    allowed_domains: Sequence[str] = SAFE_DOMAINS,
    tool_calls: Iterable[dict] = (),
) -> OutputVerdict:
    """One-shot convenience wrapper."""
    return OutputGuard(canaries=canaries, allowed_domains=allowed_domains).check(text, tool_calls)


__all__ = ["OutputGuard", "OutputVerdict", "SAFE_DOMAINS", "Violation", "guard_output"]
