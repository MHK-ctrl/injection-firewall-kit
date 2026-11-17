"""Remove or neutralize risky constructs from untrusted content - and say what changed.

Two rules drive this module:

1. **Never silently destroy content.** Every change is recorded with its span, the text
   before and after, and a reason. :meth:`SanitizeReport.diff` renders a unified diff and
   :meth:`SanitizeReport.revert` reconstructs the original byte-for-byte.
2. **Prefer neutralizing over deleting.** A chat-template token becomes
   ``[blocked-chat-token]`` rather than vanishing, so the model (and the human reviewing
   the log) can still tell that something was there.
"""

from __future__ import annotations

import difflib
import re
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Callable

from .detectors.encoding_tricks import normalize_homoglyphs

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Edit:
    """A single replacement, with offsets into the text it was found in."""

    start: int
    end: int
    replacement: str
    kind: str
    reason: str


@dataclass(frozen=True)
class Change:
    """A recorded, reversible change."""

    kind: str
    reason: str
    before: str
    after: str
    start: int  # offsets in the original text
    end: int
    start_sanitized: int  # offsets in the sanitized text, for revert()
    end_sanitized: int

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "reason": self.reason,
            "start": self.start,
            "end": self.end,
            "before": self.before,
            "after": self.after,
        }


@dataclass
class SanitizeReport:
    """Result of sanitizing one document."""

    original: str
    sanitized: str
    changes: list[Change] = field(default_factory=list)
    profile: str = "standard"

    @property
    def changed(self) -> bool:
        return bool(self.changes)

    @property
    def delta(self) -> int:
        return len(self.sanitized) - len(self.original)

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for change in self.changes:
            counts[change.kind] = counts.get(change.kind, 0) + 1
        return counts

    def describe(self) -> str:
        if not self.changes:
            return "no changes"
        parts = [f"{kind} x{count}" for kind, count in sorted(self.summary().items())]
        return f"{len(self.changes)} change(s): " + ", ".join(parts)

    def diff(self, name: str = "content") -> str:
        """Unified diff. This *is* the human-reviewable, reversible record."""
        before = self.original.splitlines(keepends=True)
        after = self.sanitized.splitlines(keepends=True)
        lines = difflib.unified_diff(
            before, after, fromfile=f"{name}.original", tofile=f"{name}.sanitized", n=2
        )
        rendered = "".join(lines)
        return rendered or "(no differences)"

    def revert(self) -> str:
        """Reconstruct the original text from the sanitized text and the change log."""
        text = self.sanitized
        # Walk backwards so earlier offsets stay valid. When several edits collapse to the
        # same sanitized offset, the one that was later in the original must be restored
        # first, otherwise adjacent edits come back in the wrong order.
        for change in sorted(
            self.changes, key=lambda c: (c.start_sanitized, c.start), reverse=True
        ):
            text = text[: change.start_sanitized] + change.before + text[change.end_sanitized :]
        return text

    def as_dict(self) -> dict:
        return {
            "profile": self.profile,
            "changed": self.changed,
            "delta": self.delta,
            "summary": self.summary(),
            "changes": [c.as_dict() for c in self.changes],
            "sanitized": self.sanitized,
        }


# ---------------------------------------------------------------------------
# Individual sanitizers
# ---------------------------------------------------------------------------

_INVISIBLE = re.compile(
    "[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064\ufeff\u180e\u00ad\u034f"
    "\u202a-\u202e\u2066-\u2069\U000e0000-\U000e007f]"
)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_HTML_COMMENT = re.compile(r"<!--[\s\S]*?-->")
#: ``\\?`` before the quote keeps JSON-escaped HTML (common in tool output) matchable.
_HIDDEN_ELEMENT = re.compile(
    r"<(?P<tag>[a-zA-Z][a-zA-Z0-9]*)\b[^>]{0,400}?style\s*=\s*\\?[\"'][^\"']*"
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em|rem)?\b)"
    r"[^\"']*[\"'][^>]{0,400}?>[\s\S]{0,4000}?</(?P=tag)\s*>"
)
_OFFSCREEN_ELEMENT = re.compile(
    r"<(?P<tag>[a-zA-Z][a-zA-Z0-9]*)\b[^>]{0,400}?style\s*=\s*\\?[\"'][^\"']*"
    r"(?:position\s*:\s*(?:absolute|fixed))[^\"']*(?:left|top|right|bottom)\s*:\s*-\d{3,}"
    r"[^\"']*[\"'][^>]{0,400}?>[\s\S]{0,4000}?</(?P=tag)\s*>"
)
_LOW_CONTRAST_STYLE = re.compile(
    r"(style\s*=\s*\\?[\"'][^\"']*)color\s*:\s*#?(?:fff(?:fff)?|white)([^\"']*\\?[\"'])",
    re.IGNORECASE,
)
_CHAT_TOKENS = re.compile(
    r"<\|(?:im_start|im_end|endoftext|start_header_id|end_header_id|eot_id|system|user|assistant|tool|"
    r"begin_of_text|end_of_text)\|>|\[/?INST\]|<<\s*/?\s*SYS\s*>>|<\s*/?\s*(?:start_of_turn|end_of_turn)\s*>",
    re.IGNORECASE,
)
_WRAPPER_TAGS = re.compile(
    r"<\s*/?\s*(?:untrusted(?:_data)?|untrusted_data_[a-z0-9]+|retrieved_data|external_content|"
    r"system|developer)\s*>",
    re.IGNORECASE,
)
_MD_IMAGE_REMOTE = re.compile(r"(!\[[^\]\n]{0,200}\]\(\s*)(?:https?:)?//([^)\s]{1,300})")
_HTML_IMG_REMOTE = re.compile(
    r"(<img\b[^>]{0,300}?src\s*=\s*[\"']?)(?:https?:)?//([^\"'>\s]{1,300})", re.IGNORECASE
)
_URL = re.compile(r"\b(https?)://", re.IGNORECASE)

_MARK_BLOCKED = "[blocked-chat-token]"
_MARK_TAG = "[blocked-tag]"


def _invisible_edits(text: str) -> list[Edit]:
    edits = []
    for match in _INVISIBLE.finditer(text):
        char = match.group(0)
        name = unicodedata.name(char, "unnamed")
        edits.append(
            Edit(
                match.start(),
                match.end(),
                "",
                "invisible",
                f"removed invisible character U+{ord(char):04X} ({name})",
            )
        )
    return edits


def _control_edits(text: str) -> list[Edit]:
    return [
        Edit(m.start(), m.end(), "", "control", "removed raw control character")
        for m in _CONTROL.finditer(text)
    ]


#: Typographic characters we deliberately leave alone: normalising them would change
#: legitimate prose for no security benefit.
_KEEP_AS_IS = set("\u2018\u2019\u201c\u201d\u2013\u2014\u2026\u00a0\u00b7")


def _unicode_edits(text: str) -> list[Edit]:
    edits = []
    for index, char in enumerate(text):
        if char in _KEEP_AS_IS:
            continue
        replacement = unicodedata.normalize("NFKC", char)
        replacement = normalize_homoglyphs(replacement)
        if replacement != char:
            edits.append(
                Edit(
                    index,
                    index + 1,
                    replacement,
                    "unicode",
                    f"normalised U+{ord(char):04X} to {replacement!r} "
                    "(compatibility form or homoglyph normalisation)",
                )
            )
    return edits


def _html_comment_edits(text: str) -> list[Edit]:
    return [
        Edit(m.start(), m.end(), "", "html_comment", "removed HTML comment (invisible to readers)")
        for m in _HTML_COMMENT.finditer(text)
    ]


def _hidden_element_edits(text: str) -> list[Edit]:
    edits = []
    for pattern, label in ((_HIDDEN_ELEMENT, "CSS-hidden element"), (_OFFSCREEN_ELEMENT, "off-screen element")):
        for match in pattern.finditer(text):
            edits.append(
                Edit(
                    match.start(),
                    match.end(),
                    "",
                    "hidden_element",
                    f"removed {label} and its text; it is invisible to a human reviewer",
                )
            )
    return edits


def _low_contrast_edits(text: str) -> list[Edit]:
    edits = []
    for match in _LOW_CONTRAST_STYLE.finditer(text):
        start, end = match.span()
        replacement = match.group(1) + "color:inherit" + match.group(2)
        edits.append(
            Edit(
                start,
                end,
                replacement,
                "low_contrast",
                "rewrote white-on-white text style so the text is visible to readers",
            )
        )
    return edits


def _chat_token_edits(text: str) -> list[Edit]:
    return [
        Edit(
            m.start(),
            m.end(),
            _MARK_BLOCKED,
            "chat_token",
            "neutralised a chat-template or role control token",
        )
        for m in _CHAT_TOKENS.finditer(text)
    ]


def _wrapper_tag_edits(text: str) -> list[Edit]:
    return [
        Edit(
            m.start(),
            m.end(),
            _MARK_TAG,
            "wrapper_tag",
            "neutralised a tag that imitates the trusted/untrusted content wrapper",
        )
        for m in _WRAPPER_TAGS.finditer(text)
    ]


def _image_beacon_edits(text: str) -> list[Edit]:
    edits = []
    for pattern in (_MD_IMAGE_REMOTE, _HTML_IMG_REMOTE):
        for match in pattern.finditer(text):
            prefix, url = match.group(1), match.group(2)
            edits.append(
                Edit(
                    match.start(),
                    match.end(),
                    f"{prefix}hxxps://{url}",
                    "image_beacon",
                    "defanged a remote image: a client that renders it would leak the request",
                )
            )
    return edits


def _url_edits(text: str) -> list[Edit]:
    def _replace(match: re.Match) -> str:
        return "hxxps://" if match.group(1).lower() == "https" else "hxxp://"

    return [
        Edit(
            m.start(),
            m.end(),
            _replace(m),
            "url",
            "defanged URL scheme so the link cannot be fetched automatically",
        )
        for m in _URL.finditer(text)
    ]


SANITIZERS: dict[str, Callable[[str], list[Edit]]] = {
    "invisible": _invisible_edits,
    "control": _control_edits,
    "unicode": _unicode_edits,
    "html_comment": _html_comment_edits,
    "hidden_element": _hidden_element_edits,
    "low_contrast": _low_contrast_edits,
    "chat_token": _chat_token_edits,
    "wrapper_tag": _wrapper_tag_edits,
    "image_beacon": _image_beacon_edits,
    "url": _url_edits,
}

PROFILES: dict[str, Sequence[str]] = {
    # Minimal: only things that are invisible by construction. Safe for any content.
    "minimal": ("invisible", "control", "unicode"),
    # Standard: also neutralises structural tricks and rendering beacons. Recommended.
    "standard": (
        "invisible",
        "control",
        "unicode",
        "html_comment",
        "hidden_element",
        "low_contrast",
        "chat_token",
        "wrapper_tag",
        "image_beacon",
    ),
    # Aggressive: additionally defangs every URL. Use for read-only pipelines where
    # links are not needed, and expect complaints about unclickable links.
    "aggressive": (
        "invisible",
        "control",
        "unicode",
        "html_comment",
        "hidden_element",
        "low_contrast",
        "chat_token",
        "wrapper_tag",
        "image_beacon",
        "url",
    ),
}


def _resolve_overlaps(edits: Iterable[Edit]) -> list[Edit]:
    """Keep the first edit for any overlapping region, then sort by position."""
    ordered = sorted(edits, key=lambda e: (e.start, -(e.end - e.start)))
    kept: list[Edit] = []
    last_end = -1
    for edit in ordered:
        if edit.start < last_end:
            continue
        kept.append(edit)
        last_end = max(last_end, edit.end)
    return kept


def apply_sanitizers(
    text: str,
    profile: str = "standard",
    *,
    steps: Sequence[str] | None = None,
) -> SanitizeReport:
    """Sanitize ``text`` and return the cleaned text plus a reversible change log."""
    if steps is None:
        if profile not in PROFILES:
            raise ValueError(f"unknown profile {profile!r}; known: {sorted(PROFILES)}")
        steps = PROFILES[profile]

    collected: list[Edit] = []
    for name in steps:
        try:
            sanitizer = SANITIZERS[name]
        except KeyError as exc:
            raise ValueError(f"unknown sanitizer {name!r}; known: {sorted(SANITIZERS)}") from exc
        collected.extend(sanitizer(text))

    edits = _resolve_overlaps(collected)

    out: list[str] = []
    changes: list[Change] = []
    cursor = 0
    out_len = 0
    for edit in edits:
        chunk = text[cursor : edit.start]
        out.append(chunk)
        out_len += len(chunk)
        start_sanitized = out_len
        out.append(edit.replacement)
        out_len += len(edit.replacement)
        changes.append(
            Change(
                kind=edit.kind,
                reason=edit.reason,
                before=text[edit.start : edit.end],
                after=edit.replacement,
                start=edit.start,
                end=edit.end,
                start_sanitized=start_sanitized,
                end_sanitized=out_len,
            )
        )
        cursor = edit.end
    out.append(text[cursor:])

    return SanitizeReport(
        original=text, sanitized="".join(out), changes=changes, profile=profile
    )


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------


def strip_invisible(text: str) -> str:
    """Remove zero-width, bidi and Unicode-tag characters."""
    return _INVISIBLE.sub("", text)


def normalize_unicode_text(text: str) -> str:
    """Apply the same per-character normalisation used by the sanitizer."""
    return "".join(
        char
        if char in _KEEP_AS_IS
        else normalize_homoglyphs(unicodedata.normalize("NFKC", char))
        for char in text
    )


def neutralize_chat_tokens(text: str) -> str:
    """Replace chat-template tokens with a visible placeholder."""
    return _CHAT_TOKENS.sub(_MARK_BLOCKED, text)


def strip_hidden_html(text: str) -> str:
    """Remove HTML comments and CSS-hidden elements."""
    text = _HTML_COMMENT.sub("", text)
    text = _HIDDEN_ELEMENT.sub("", text)
    return _OFFSCREEN_ELEMENT.sub("", text)


def defang_urls(text: str, *, images_only: bool = False) -> str:
    """Rewrite ``http(s)://`` as ``hxxp(s)://`` so nothing can be fetched automatically."""
    if images_only:
        text = _MD_IMAGE_REMOTE.sub(lambda m: f"{m.group(1)}hxxps://{m.group(2)}", text)
        text = _HTML_IMG_REMOTE.sub(lambda m: f"{m.group(1)}hxxps://{m.group(2)}", text)
        return text
    return _URL.sub(lambda m: "hxxps://" if m.group(1).lower() == "https" else "hxxp://", text)


__all__ = [
    "Change",
    "Edit",
    "PROFILES",
    "SANITIZERS",
    "SanitizeReport",
    "apply_sanitizers",
    "defang_urls",
    "neutralize_chat_tokens",
    "normalize_unicode_text",
    "strip_hidden_html",
    "strip_invisible",
]
