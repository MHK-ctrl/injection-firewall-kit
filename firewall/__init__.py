"""injection-firewall-kit: defensive controls for untrusted content in AI applications.

Quick start::

    from firewall import Scanner, apply_sanitizers, wrap_untrusted, decide

    result = Scanner().scan(web_page_text, carrier="html_page")
    decision = decide(result, "strict")
    if decision.action in ("block", "quarantine"):
        raise ValueError(f"suspicious content: {decision.reasons}")
    clean = apply_sanitizers(web_page_text, "standard")
    prompt = wrap_untrusted(clean.sanitized, source="https://example.com/page")
"""

from __future__ import annotations

from .canary import (
    Canary,
    CanaryLeak,
    CanaryLedger,
    bait_sentence,
    canary_instruction,
    inject_bait,
    new_canary,
)
from .output_guard import OutputGuard, OutputVerdict, Violation, guard_output
from .policy import PRESETS, PolicyError, decide, load_policy
from .sanitizers import SanitizeReport, apply_sanitizers, defang_urls
from .scanner import Scanner, scan, scan_file
from .tool_gate import GateDecision, ToolGate, ToolSpec
from .types import CATEGORIES, Decision, Finding, ScanResult
from .wrapper import WrappedContent, system_note, unwrap, wrap_many, wrap_untrusted

__version__ = "0.1.0"

__all__ = [
    "CATEGORIES",
    "PRESETS",
    "Canary",
    "CanaryLedger",
    "CanaryLeak",
    "Decision",
    "Finding",
    "GateDecision",
    "OutputGuard",
    "OutputVerdict",
    "PolicyError",
    "SanitizeReport",
    "ScanResult",
    "Scanner",
    "ToolGate",
    "ToolSpec",
    "Violation",
    "WrappedContent",
    "apply_sanitizers",
    "bait_sentence",
    "canary_instruction",
    "decide",
    "defang_urls",
    "guard_output",
    "inject_bait",
    "load_policy",
    "new_canary",
    "scan",
    "scan_file",
    "system_note",
    "unwrap",
    "wrap_many",
    "wrap_untrusted",
]
