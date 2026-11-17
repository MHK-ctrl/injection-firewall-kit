"""Detect invisible or visually hidden content that a human reader would never see.

The threat: a screenshot of the email looks clean, but the model's text pipeline sees
"ignore the previous instructions" inside a zero-width run, an HTML comment, a
``font-size: 0`` span, or an off-screen ``<div>``.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from ..types import Finding
from .base import RegexDetector, Rule

_I = re.IGNORECASE

#: Code points that render as nothing (or as a different string) in most UIs.
ZERO_WIDTH = re.compile(
    "[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064\ufeff\u180e\u00ad\u034f]"
)
#: Unicode "tag" characters: invisible, and a classic way to smuggle ASCII text.
TAG_CHARS = re.compile("[\U000e0000-\U000e007f]")

_INSTRUCTION_WORDS = re.compile(
    r"\b(?:ignore|disregard|override|instruction|prompt|system|assistant|canary|forward|"
    r"reveal|secret|password|execute|comply|obey)\b",
    _I,
)

RULES: Sequence[Rule] = (
    Rule(
        name="zero_width_run",
        pattern=("[\u200b\u200c\u200d\u2060\ufeff\u180e\u00ad\u034f]{3,}"),
        category="hidden_text",
        severity="medium",
        reason="a run of zero-width or invisible characters can hide text from human review",
        action="sanitize",
        allow_downgrade=False,
    ),
    Rule(
        name="unicode_tag_chars",
        pattern="[\U000e0000-\U000e007f]{4,}",
        category="hidden_text",
        severity="high",
        reason="Unicode tag characters carry hidden ASCII text that most renderers do not show",
        action="sanitize",
        allow_downgrade=False,
    ),
    Rule(
        # Hiding CSS alone is weak evidence (every responsive site uses display:none), so
        # this rule stays low and post_process escalates when hidden text also instructs.
        name="html_hidden_style",
        pattern=r"style\s*=\s*\\?[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em|rem)?\b|opacity\s*:\s*0(?:\.0+)?\s*(?:;|\"|')|text-indent\s*:\s*-\d{3,}|clip\s*:\s*rect\(0)",
        category="hidden_text",
        severity="low",
        reason="CSS hides this element from human readers while leaving it in the text",
        action="warn",
        allow_downgrade=False,
    ),
    Rule(
        name="html_offscreen",
        pattern=r"style\s*=\s*\\?[\"'][^\"']*(?:position\s*:\s*absolute|position\s*:\s*fixed)[^\"']*(?:left|top|right|bottom)\s*:\s*-\d{3,}",
        category="hidden_text",
        severity="low",
        reason="element is positioned far off-screen, a known way to hide injected text",
        action="warn",
        allow_downgrade=False,
    ),
    Rule(
        name="html_low_contrast",
        pattern=r"style\s*=\s*\\?[\"'][^\"']*color\s*:\s*#?(?:fff(?:fff)?|white)\b[^\"']*background(?:-color)?\s*:\s*#?(?:fff(?:fff)?|white)\b",
        category="hidden_text",
        severity="medium",
        reason="white text on a white background is invisible to the reader but visible to the model",
        action="sanitize",
        allow_downgrade=False,
    ),
    Rule(
        name="html_hidden_attribute",
        pattern=r"<[a-z][^>]{0,200}\s(?:hidden|aria-hidden\s*=\s*[\"']?true)[\s\"'/>]",
        category="hidden_text",
        severity="low",
        reason="element is marked hidden/aria-hidden and should not be read as content",
        action="warn",
        allow_downgrade=False,
    ),
    Rule(
        name="html_comment_suspicious",
        pattern=r"<!--[\s\S]{0,400}?(?:ignore|disregard|instruction|system|assistant|assistant|canary|forward|send)\b[\s\S]{0,200}?-->",
        category="hidden_text",
        severity="high",
        reason="HTML comment contains instruction-like text that no reader would see",
        action="sanitize",
        allow_downgrade=False,
    ),
    Rule(
        name="html_comment_plain",
        pattern=r"<!--[\s\S]{1,400}?-->",
        category="hidden_text",
        severity="info",
        reason="HTML comment present; comments are invisible to readers and are often stale data",
        action="warn",
        allow_downgrade=False,
        max_matches=1,
    ),
    Rule(
        name="metadata_field",
        pattern=r"(?im)^[ \t]*(?:x-[\w-]+|metadata|alt|description|summary|comment|subject|keywords|caption)\s*:\s*\S{0,120}?\b(?:ignore|disregard|instruction|system prompt|assistant|canary)\b",
        category="hidden_text",
        severity="medium",
        reason="a metadata field (not part of the visible body) carries instruction-like text",
        action="warn",
        allow_downgrade=False,
    ),
    Rule(
        name="pdf_extraction_artifact",
        pattern=r"(?:\u200b|\ufeff){1,}[^\n]{0,80}(?:ignore|instruction|system)",
        category="hidden_text",
        severity="medium",
        reason="invisible characters around instruction text, typical of layered PDF text extraction",
        action="sanitize",
        allow_downgrade=False,
    ),
)


class HiddenTextDetector(RegexDetector):
    name = "hidden_text"
    description = "Zero-width characters, hidden HTML/CSS, comments and metadata payloads."
    rules = tuple(RULES)

    def post_process(self, text: str, carrier: str) -> list[Finding]:
        """Report the *combination* of hiding plus instruction wording.

        This is the highest-signal signal in the whole kit: invisible text that also
        contains instructions is not an accident.
        """
        findings: list[Finding] = []

        spans: list[tuple[int, int]] = []
        for pattern in (ZERO_WIDTH, TAG_CHARS):
            for match in pattern.finditer(text):
                # Invisible characters are usually *wrapped around* the payload, so look at
                # the text that follows the run, not just the run itself.
                spans.append((match.start(), min(len(text), match.end() + 120)))
        for match in re.finditer(r"<!--([\s\S]*?)-->", text):
            spans.append((match.start(1), match.end(1)))
        for match in re.finditer(
            r"style\s*=\s*\\?[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|"
            r"font-size\s*:\s*0|position\s*:\s*(?:absolute|fixed))",
            text,
            _I,
        ):
            # Look ahead for the element's text content, up to the next tag.
            tail = text[match.end() : match.end() + 400]
            if tail:
                spans.append((match.end(), min(len(text), match.end() + 400)))
        for match in re.finditer(r"<[a-z][^>]{0,200}\shidden[\s>]", text, _I):
            spans.append((match.start(), min(len(text), match.end() + 200)))

        for start, end in spans:
            window = text[start:end]
            if len(window) < 8:
                continue
            if _INSTRUCTION_WORDS.search(window):
                findings.append(
                    self.finding(
                        "hidden_text",
                        "critical",
                        "instruction-like text is present inside content that is invisible to a "
                        "human reader (hidden characters, comments or CSS)",
                        text,
                        start,
                        end,
                        action="block",
                    )
                )
                break
        return findings
