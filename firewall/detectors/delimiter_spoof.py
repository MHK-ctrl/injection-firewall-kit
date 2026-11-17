"""Detect spoofed delimiters: chat-template tokens, fake wrapper closes, fake fences."""

from __future__ import annotations

import re
from collections.abc import Sequence

from ..types import Finding
from .base import RegexDetector, Rule

_IM = re.IGNORECASE | re.MULTILINE

RULES: Sequence[Rule] = (
    Rule(
        name="chat_template_token",
        pattern=(
            r"<\|(?:im_start|im_end|endoftext|start_header_id|end_header_id|eot_id|"
            r"system|user|assistant|tool|begin_of_text|end_of_text)\|>"
        ),
        category="delimiter_spoof",
        severity="critical",
        reason="content contains a real chat-template control token that can truncate or "
        "restructure the prompt",
        action="block",
    ),
    Rule(
        name="bracket_template_token",
        pattern=r"\[/?INST\]|<<\s*/?\s*SYS\s*>>|\[/?\s*/\s*INST\]",
        category="delimiter_spoof",
        severity="critical",
        reason="content contains instruction-format markers used by common prompt templates",
        action="block",
    ),
    Rule(
        name="xml_style_role_tag",
        pattern=r"<\s*/?\s*(?:start_of_turn|end_of_turn|prompt|human|input|instruction)\s*>",
        category="delimiter_spoof",
        severity="high",
        reason="content injects a conversation-structure tag",
        action="sanitize",
    ),
    Rule(
        name="fake_wrapper_close",
        pattern=(
            r"<\s*/\s*(?:untrusted(?:_data)?|untrusted_data_[a-z0-9]+|context|retrieved_data|"
            r"documents?|external_content|tool_output|data)\s*>"
        ),
        category="delimiter_spoof",
        severity="critical",
        reason="content tries to close the untrusted-data wrapper early so the rest looks trusted",
        action="block",
    ),
    Rule(
        name="fake_wrapper_marker",
        pattern=r"<{2,}\s*(?:END|BEGIN|STOP)\s*(?:_?UNTRUSTED\w*|_DATA\w*|_CONTENT\w*)\s*>{2,}",
        category="delimiter_spoof",
        severity="critical",
        reason="content forges an end/begin marker of the untrusted-data wrapper",
        action="block",
    ),
    Rule(
        name="wrapper_nonce_marker",
        pattern=r"<{2,}\s*UNTRUSTED_DATA[_-][A-Za-z0-9]{3,}\s+(?:BEGIN|END)\s*>{2,}",
        category="delimiter_spoof",
        severity="critical",
        reason="content forges the nonce marker of the untrusted-data wrapper",
        action="block",
    ),
    Rule(
        name="begin_system_banner",
        pattern=r"\b(?:BEGIN|START)\s+(?:THE\s+)?SYSTEM(?:\s+PROMPT)?\b",
        category="delimiter_spoof",
        severity="high",
        reason="content announces the start of a system prompt or system region",
        action="sanitize",
    ),
    Rule(
        name="bracket_boundary",
        pattern=r"^[ \t]*\[(?:END|BEGIN|START|STOP)\b[^\]\n]{0,40}\][ \t]*$",
        category="delimiter_spoof",
        severity="high",
        reason="content draws a bracketed fake boundary around trusted content",
        action="sanitize",
        flags=_IM,
    ),
    Rule(
        name="escaped_control_sequence",
        pattern=r"\\u00[01][0-9a-fA-F]",
        category="delimiter_spoof",
        severity="medium",
        reason="escaped control characters can hide structure from logs and reviewers",
        action="sanitize",
    ),
    Rule(
        name="fake_section_boundary",
        pattern=(
            r"^[ \t]*(?:-{3,}|={3,}|\*{3,}|#{3,}|~{3,})[ \t]*"
            r"(?:end|begin|start|stop)[ \t]+(?:of[ \t]+)?(?:document|document content|context|"
            r"system prompt|instructions|untrusted data|retrieved data)[ \t]*(?:-{3,}|={3,}|\*{3,}|#{3,}|~{3,})?[ \t]*$"
        ),
        category="delimiter_spoof",
        severity="high",
        reason="content draws a fake 'end of document/system prompt' boundary",
        action="sanitize",
        flags=_IM,
    ),
    Rule(
        name="fake_fence_language",
        pattern=r"^[ \t]*```+\s*(?:system|system_prompt|instructions?|developer)\b",
        category="delimiter_spoof",
        severity="high",
        reason="a code fence is labelled as a system prompt or instruction block",
        action="sanitize",
        flags=_IM,
    ),
    Rule(
        name="control_char_nul",
        pattern=r"[\x00\x01\x02\x03\x04\x05\x06\x0b\x0c\x0e-\x1f]",
        category="delimiter_spoof",
        severity="medium",
        reason="raw control characters can confuse tokenizers and log pipelines",
        action="sanitize",
    ),
)

#: Bare role-ish XML tags are only suspicious in combination with an instruction nearby,
#: so they are handled in post_process instead of as unconditional rules.
_SOFT_TAG = re.compile(r"<\s*/?\s*(?:system|user|assistant|developer)\s*>", re.IGNORECASE)
_INSTRUCTION_HINT = re.compile(
    r"\b(?:ignore|must|always|never|instruction|prompt|respond|reply|answer|obey|comply)\b",
    re.IGNORECASE,
)


class DelimiterSpoofDetector(RegexDetector):
    name = "delimiter_spoof"
    description = "Chat-template tokens, fake wrappers and forged document boundaries."
    rules = tuple(RULES)

    def post_process(self, text: str, carrier: str) -> list[Finding]:
        findings: list[Finding] = []
        tags = list(_SOFT_TAG.finditer(text))
        if tags and _INSTRUCTION_HINT.search(text):
            first = tags[0]
            findings.append(
                self.finding(
                    "delimiter_spoof",
                    "high",
                    "role-ish XML tags appear together with instruction wording, which is how "
                    "an attacker fakes a privileged turn without using a known control token",
                    text,
                    first.start(),
                    first.end(),
                    action="sanitize",
                )
            )
        return findings
