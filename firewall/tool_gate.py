"""Least-privilege gate in front of every tool an agent can call.

The scanner reduces the chance that injected instructions reach the model. The tool gate
assumes some will anyway and limits the blast radius: only known tools, only declared
arguments, validated values, and a human approval step for anything irreversible.

Typical use::

    gate = ToolGate(
        {
            "search_docs": ToolSpec("search_docs", risk="low", arg_types={"query": "str"}),
            "send_email": ToolSpec(
                "send_email",
                risk="high",
                requires_approval=True,
                arg_types={"to": "str", "body": "str"},
                allowed_domains=("example.com",),
            ),
        },
        approver=ask_a_human,
    )
    decision = gate.request("send_email", {"to": "test@example.com", "body": "hi"})
    if not decision.allowed:
        raise PermissionError(decision.reasons)
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Callable

RISK_LEVELS = ("low", "medium", "high", "critical")

_SHELL_META = re.compile(r"[;&|`$><\n]|\$\(|\|\|")
_PATH_TRAVERSAL = re.compile(r"(?:^|[\\/])\.\.(?:[\\/]|$)")
_URL_DOMAIN = re.compile(r"\bhttps?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})", re.IGNORECASE)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")


@dataclass(frozen=True)
class ToolSpec:
    """Declarative description of what a tool call may look like."""

    name: str
    risk: str = "low"
    description: str = ""
    requires_approval: bool = False
    arg_types: dict[str, str] = field(default_factory=dict)
    required_args: Sequence[str] = field(default_factory=tuple)
    max_arg_length: int = 4000
    allowed_values: dict[str, Sequence[str]] = field(default_factory=dict)
    patterns: dict[str, str] = field(default_factory=dict)
    allowed_domains: Sequence[str] = field(default_factory=tuple)
    max_calls: int | None = None
    deny_shell_metacharacters: bool = True
    deny_path_traversal: bool = True

    def __post_init__(self) -> None:
        if self.risk not in RISK_LEVELS:
            raise ValueError(f"{self.name}: unknown risk {self.risk!r}")
        for arg in self.required_args:
            if self.arg_types and arg not in self.arg_types:
                raise ValueError(f"{self.name}: required arg {arg!r} has no declared type")


@dataclass
class GateDecision:
    """Outcome of one tool request."""

    tool: str
    allowed: bool
    requires_approval: bool = False
    approved: bool | None = None
    reasons: list[str] = field(default_factory=list)
    args: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "tool": self.tool,
            "allowed": self.allowed,
            "requires_approval": self.requires_approval,
            "approved": self.approved,
            "reasons": self.reasons,
            "args": self.args,
        }

    def __bool__(self) -> bool:  # pragma: no cover - convenience
        return self.allowed


Approver = Callable[[str, dict[str, Any], list[str]], bool]


class ToolGate:
    """Validate and authorise tool calls. Deny by default."""

    def __init__(
        self,
        specs: Iterable[ToolSpec],
        *,
        approver: Approver | None = None,
        deny: Sequence[str] = (),
        require_approval: Sequence[str] = (),
    ) -> None:
        self.specs: dict[str, ToolSpec] = {spec.name: spec for spec in specs}
        self.approver = approver
        self.denied = set(deny)
        self.forced_approval = set(require_approval)
        self._counts: dict[str, int] = {}

    # -- public API ---------------------------------------------------------

    def request(
        self,
        tool: str,
        args: dict[str, Any] | None = None,
        *,
        context: dict[str, Any] | None = None,
    ) -> GateDecision:
        args = dict(args or {})
        reasons: list[str] = []

        if tool in self.denied:
            return GateDecision(tool, False, reasons=[f"tool {tool!r} is denied by policy"], args=args)
        spec = self.specs.get(tool)
        if spec is None:
            return GateDecision(
                tool,
                False,
                reasons=[f"tool {tool!r} is not in the allow-list (tools allowed: {sorted(self.specs)})"],
                args=args,
            )

        problems = self._validate(spec, args)

        self._counts[tool] = self._counts.get(tool, 0) + 1
        if spec.max_calls is not None and self._counts[tool] > spec.max_calls:
            problems.append(
                f"tool {tool!r} exceeded its budget of {spec.max_calls} call(s) in this session"
            )
        reasons.extend(problems)

        needs_approval = spec.requires_approval or tool in self.forced_approval
        if needs_approval and not problems:
            reasons.append(f"tool {tool!r} is irreversible or high impact; human approval required")
            if self.approver is None:
                return GateDecision(
                    tool,
                    False,
                    requires_approval=True,
                    approved=False,
                    reasons=[*reasons, "no approver configured, so the request is refused"],
                    args=args,
                )
            try:
                approved = bool(self.approver(tool, args, list(reasons)))
            except Exception as exc:  # noqa: BLE001 - a broken approver must fail closed
                return GateDecision(
                    tool,
                    False,
                    requires_approval=True,
                    approved=False,
                    reasons=[*reasons, f"approver raised {type(exc).__name__}: {exc}"],
                    args=args,
                )
            if not approved:
                return GateDecision(
                    tool,
                    False,
                    requires_approval=True,
                    approved=False,
                    reasons=[*reasons, "human reviewer declined"],
                    args=args,
                )
            return GateDecision(
                tool, True, requires_approval=True, approved=True, reasons=reasons, args=args
            )

        if problems:
            return GateDecision(tool, False, reasons=reasons, args=args)
        return GateDecision(tool, True, reasons=["allowed"] + reasons, args=args)

    def reset(self) -> None:
        """Reset per-session call counters."""
        self._counts.clear()

    # -- validation ---------------------------------------------------------

    def _validate(self, spec: ToolSpec, args: dict[str, Any]) -> list[str]:
        problems: list[str] = []

        for name in spec.required_args:
            if name not in args:
                problems.append(f"missing required argument {name!r}")

        for name, value in args.items():
            declared = spec.arg_types.get(name)
            if spec.arg_types and declared is None:
                problems.append(f"argument {name!r} is not declared for tool {spec.name!r}")
                continue
            if declared:
                problems.extend(self._check_type(spec, name, declared, value))

            if isinstance(value, str):
                if len(value) > spec.max_arg_length:
                    problems.append(
                        f"argument {name!r} is {len(value)} characters, over the limit of "
                        f"{spec.max_arg_length}"
                    )
                allowed = spec.allowed_values.get(name)
                if allowed is not None and value not in allowed:
                    problems.append(
                        f"argument {name!r} must be one of {sorted(allowed)}, got {value!r}"
                    )
                pattern = spec.patterns.get(name)
                if pattern and not re.fullmatch(pattern, value):
                    problems.append(f"argument {name!r} does not match the required pattern")
                if spec.deny_shell_metacharacters and _SHELL_META.search(value):
                    problems.append(
                        f"argument {name!r} contains shell metacharacters, which are not allowed"
                    )
                if spec.deny_path_traversal and _PATH_TRAVERSAL.search(value):
                    problems.append(f"argument {name!r} contains a path traversal sequence")
            problems.extend(self._check_domains(spec, name, value))
        return problems

    @staticmethod
    def _check_type(spec: ToolSpec, name: str, declared: str, value: Any) -> list[str]:
        expected = declared.lower()
        checks = {
            "str": lambda v: isinstance(v, str),
            "string": lambda v: isinstance(v, str),
            "int": lambda v: isinstance(v, int) and not isinstance(v, bool),
            "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
            "float": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
            "bool": lambda v: isinstance(v, bool),
            "list": lambda v: isinstance(v, list),
            "dict": lambda v: isinstance(v, dict),
        }
        checker = checks.get(expected)
        if checker is None:
            return [f"tool {spec.name!r} declares unknown type {declared!r} for {name!r}"]
        if not checker(value):
            return [f"argument {name!r} must be {declared}, got {type(value).__name__}"]
        return []

    @staticmethod
    def _check_domains(spec: ToolSpec, name: str, value: Any) -> list[str]:
        if not spec.allowed_domains or not isinstance(value, str):
            return []
        problems: list[str] = []
        for match in _URL_DOMAIN.finditer(value):
            domain = match.group(1).lower()
            if not any(domain == d or domain.endswith("." + d) for d in spec.allowed_domains):
                problems.append(
                    f"argument {name!r} points at {domain!r}, outside the allowed domains "
                    f"{sorted(spec.allowed_domains)}"
                )
        for match in _EMAIL.finditer(value):
            domain = match.group(1).lower()
            if not any(domain == d or domain.endswith("." + d) for d in spec.allowed_domains):
                problems.append(
                    f"argument {name!r} addresses {domain!r}, outside the allowed domains "
                    f"{sorted(spec.allowed_domains)}"
                )
        return problems


def allow_all(tool: str, args: dict[str, Any], reasons: list[str]) -> bool:  # pragma: no cover
    """Approver that says yes to everything. Only for tests and demos."""
    return True


def deny_all(tool: str, args: dict[str, Any], reasons: list[str]) -> bool:  # pragma: no cover
    """Approver that says no to everything. Safe default for production."""
    return False


__all__ = [
    "Approver",
    "GateDecision",
    "RISK_LEVELS",
    "ToolGate",
    "ToolSpec",
    "allow_all",
    "deny_all",
]
