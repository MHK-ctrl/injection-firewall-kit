"""Detector registry.

Every detector is a pure function of the input text. They are instantiated once at import
time because compiling their regexes is the expensive part.
"""

from __future__ import annotations

from collections.abc import Sequence

from .base import RegexDetector, Rule, dedupe, is_quoted, looks_like_meta_discourse, snippet
from .delimiter_spoof import DelimiterSpoofDetector
from .encoding_tricks import EncodingTricksDetector
from .exfil_patterns import ExfilPatternDetector
from .hidden_text import HiddenTextDetector
from .instruction_override import InstructionOverrideDetector
from .role_hijack import RoleHijackDetector
from .tool_abuse import ToolAbuseDetector
from .urgency_authority import UrgencyAuthorityDetector

DEFAULT_DETECTORS: Sequence[RegexDetector] = (
    InstructionOverrideDetector(),
    RoleHijackDetector(),
    DelimiterSpoofDetector(),
    HiddenTextDetector(),
    EncodingTricksDetector(),
    ExfilPatternDetector(),
    ToolAbuseDetector(),
    UrgencyAuthorityDetector(),
)

DETECTOR_NAMES: list[str] = [d.name for d in DEFAULT_DETECTORS]


def build_detectors(only: Sequence[str] | None = None) -> list[RegexDetector]:
    """Return the default detectors, optionally restricted to the given names."""
    if not only:
        return list(DEFAULT_DETECTORS)
    wanted = set(only)
    unknown = wanted - set(DETECTOR_NAMES)
    if unknown:
        raise ValueError(f"unknown detector(s): {sorted(unknown)}; known: {DETECTOR_NAMES}")
    return [d for d in DEFAULT_DETECTORS if d.name in wanted]


def detector_map() -> dict[str, RegexDetector]:
    return {d.name: d for d in DEFAULT_DETECTORS}


__all__ = [
    "DEFAULT_DETECTORS",
    "DETECTOR_NAMES",
    "RegexDetector",
    "Rule",
    "build_detectors",
    "dedupe",
    "detector_map",
    "is_quoted",
    "looks_like_meta_discourse",
    "snippet",
]
