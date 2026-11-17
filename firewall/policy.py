"""Policy: turn findings into an action, configurable in YAML.

Actions, least to most restrictive: ``allow``, ``warn``, ``sanitize``, ``quarantine``,
``block``. A policy has three levers:

* ``thresholds`` - the risk score at which each action becomes the default
* ``category_min_action`` - a floor per attack category, so the presence of one
  exfiltration signal always blocks, whatever the arithmetic says
* ``sanitize`` - which sanitizer profile to run when the action is ``sanitize``

Three presets ship with the package and mirror ``policies/*.yaml``:

* ``strict``     - email agent with tools: assume content is hostile
* ``balanced``   - RAG reader / document summariser (the default)
* ``permissive`` - read-only summariser with no tools and no secrets in context
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

from .types import ACTIONS, Decision, ScanResult, action_rank

STRICT: dict[str, Any] = {
    "name": "strict",
    "description": "Email assistant with send/forward tools and access to private mail.",
    "thresholds": {"warn": 1, "sanitize": 15, "quarantine": 40, "block": 70},
    "category_min_action": {
        "direct_instruction_override": "sanitize",
        "role_hijack": "sanitize",
        "delimiter_spoof": "block",
        "hidden_text": "quarantine",
        "encoding_obfuscation": "sanitize",
        "multilingual_injection": "sanitize",
        "payload_splitting": "quarantine",
        "fake_tool_result": "quarantine",
        "exfiltration": "block",
        "tool_abuse": "quarantine",
        "social_engineering": "quarantine",
        "context_poisoning": "sanitize",
    },
    "detectors": {"disabled": [], "severity_overrides": {}},
    "sanitize": {"profile": "aggressive"},
    "tool_gate": {
        "require_approval": ["send_email", "forward_email", "delete_message", "run_shell"],
        "deny": ["run_shell", "fs_write"],
    },
}

BALANCED: dict[str, Any] = {
    "name": "balanced",
    "description": "Document / RAG reader: summarise and answer, no side effects.",
    "thresholds": {"warn": 1, "sanitize": 25, "quarantine": 60, "block": 85},
    "category_min_action": {
        "direct_instruction_override": "sanitize",
        "role_hijack": "sanitize",
        "delimiter_spoof": "block",
        "hidden_text": "sanitize",
        "encoding_obfuscation": "sanitize",
        "multilingual_injection": "sanitize",
        "payload_splitting": "sanitize",
        "fake_tool_result": "sanitize",
        "exfiltration": "block",
        "tool_abuse": "quarantine",
        "social_engineering": "quarantine",
        "context_poisoning": "sanitize",
    },
    "detectors": {"disabled": [], "severity_overrides": {}},
    "sanitize": {"profile": "standard"},
    "tool_gate": {
        "require_approval": ["send_email", "forward_email", "write_file"],
        "deny": ["run_shell"],
    },
}

PERMISSIVE: dict[str, Any] = {
    "name": "permissive",
    "description": "Read-only summariser with no tools and no secrets in context.",
    "thresholds": {"warn": 10, "sanitize": 40, "quarantine": 75, "block": 95},
    "category_min_action": {
        "exfiltration": "block",
        "delimiter_spoof": "sanitize",
    },
    "detectors": {"disabled": [], "severity_overrides": {}},
    "sanitize": {"profile": "minimal"},
    "tool_gate": {"require_approval": [], "deny": []},
}

PRESETS: dict[str, dict[str, Any]] = {
    "strict": STRICT,
    "balanced": BALANCED,
    "permissive": PERMISSIVE,
}

DEFAULT_POLICY = BALANCED

_REQUIRED_KEYS = ("name", "thresholds", "category_min_action")
_ACTION_SET = set(ACTIONS)


class PolicyError(ValueError):
    """Raised when a policy file is malformed or asks for something impossible."""


def validate_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """Check structural invariants. Returns the policy so it can be used inline."""
    if not isinstance(policy, dict):
        raise PolicyError("policy must be a mapping")
    missing = [key for key in _REQUIRED_KEYS if key not in policy]
    if missing:
        raise PolicyError(f"policy is missing required keys: {missing}")

    thresholds = policy["thresholds"]
    if not isinstance(thresholds, dict):
        raise PolicyError("thresholds must be a mapping")
    values = []
    for action in ACTIONS[1:]:  # allow has no threshold
        if action not in thresholds:
            raise PolicyError(f"thresholds is missing {action!r}")
        value = thresholds[action]
        if not isinstance(value, int) or not 0 <= value <= 100:
            raise PolicyError(f"threshold for {action!r} must be an int in 0..100")
        values.append(value)
    if values != sorted(values):
        raise PolicyError(
            "thresholds must increase with severity: warn <= sanitize <= quarantine <= block"
        )

    minimums = policy["category_min_action"]
    if not isinstance(minimums, dict):
        raise PolicyError("category_min_action must be a mapping")
    for category, action in minimums.items():
        if action not in _ACTION_SET:
            raise PolicyError(f"category {category!r} has unknown action {action!r}")

    sanitize = policy.get("sanitize") or {}
    if not isinstance(sanitize, dict):
        raise PolicyError("sanitize must be a mapping")
    from .sanitizers import PROFILES

    profile = sanitize.get("profile", "standard")
    if profile not in PROFILES:
        raise PolicyError(f"unknown sanitize profile {profile!r}; known: {sorted(PROFILES)}")

    detectors = policy.get("detectors") or {}
    if not isinstance(detectors, dict):
        raise PolicyError("detectors must be a mapping")
    for category, severity in (detectors.get("severity_overrides") or {}).items():
        if severity not in ("info", "low", "medium", "high", "critical"):
            raise PolicyError(f"severity override for {category!r} is invalid: {severity!r}")
    return policy


def load_policy(spec: Any = None) -> dict[str, Any]:
    """Load a policy from ``None`` (balanced), a preset name, a path, or a mapping."""
    if spec is None:
        return copy.deepcopy(DEFAULT_POLICY)
    if isinstance(spec, dict):
        return validate_policy(copy.deepcopy(spec))
    if isinstance(spec, (str, Path)):
        text = str(spec)
        if text in PRESETS:
            return validate_policy(copy.deepcopy(PRESETS[text]))
        path = Path(text)
        if not path.exists():
            raise PolicyError(f"no policy preset named {text!r} and no such file {path}")
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        return validate_policy(data or {})
    raise PolicyError(f"cannot interpret policy spec of type {type(spec).__name__}")


def decide(result: ScanResult, policy: Any | None = None) -> Decision:
    """Map a scan result to an action.

    Order of precedence: score thresholds first, then any category floor that is more
    restrictive, then a human-readable list of reasons. The most restrictive reason wins.
    """
    resolved = load_policy(policy)
    score = result.risk_score
    thresholds = resolved["thresholds"]

    action = "allow"
    reasons: list[str] = []
    for candidate in ("block", "quarantine", "sanitize", "warn"):
        threshold = thresholds[candidate]
        if score >= threshold:
            action = candidate
            reasons.append(f"risk score {score} meets the {candidate} threshold ({threshold})")
            break

    for category in result.categories:
        floor = resolved["category_min_action"].get(category)
        if floor and action_rank(floor) > action_rank(action):
            action = floor
            reasons.append(f"category {category} has a minimum action of {floor}")

    if not reasons:
        reasons.append(f"risk score {score} is below every threshold")
    return Decision(action=action, score=score, reasons=reasons, policy_name=resolved["name"])


def sanitize_profile(policy: Any | None = None) -> str:
    resolved = load_policy(policy)
    return (resolved.get("sanitize") or {}).get("profile", "standard")


__all__ = [
    "BALANCED",
    "DEFAULT_POLICY",
    "PERMISSIVE",
    "PRESETS",
    "STRICT",
    "PolicyError",
    "decide",
    "load_policy",
    "sanitize_profile",
    "validate_policy",
]
