"""Detect fake system/developer/assistant turns and fabricated tool results."""

from __future__ import annotations

import re
from collections.abc import Sequence

from ..types import Finding
from .base import RegexDetector, Rule

_IM = re.IGNORECASE | re.MULTILINE

#: Characters that may prefix a line inside a comment, quote block, list or CSV field.
_PREFIX = r"^[ \t>*/#-]*"

RULES: Sequence[Rule] = (
    # --- fake conversational turns -------------------------------------------------
    Rule(
        name="fake_system_turn",
        pattern=_PREFIX + r"(?:system|developer)\s*(?:message|prompt|note|instruction|override)?\s*:",
        category="role_hijack",
        severity="high",
        reason="content contains a fake 'system:' / 'developer:' turn, imitating a trusted message",
        action="sanitize",
        flags=_IM,
    ),
    Rule(
        name="fake_assistant_turn",
        pattern=_PREFIX + r"(?:assistant|model|ai)\s*(?:message|reply|response)?\s*:\s*\S",
        category="role_hijack",
        severity="low",
        reason="content contains a fake 'assistant:' turn, which can be used to continue a dialogue",
        action="warn",
        flags=_IM,
    ),
    Rule(
        name="fake_system_tag",
        pattern=r"<\s*/?\s*(?:system|sys|developer|admin)\s*>|\[\s*/?\s*(?:SYSTEM|SYS|DEVELOPER)\s*\]|\bsystem_message\s*[:=]",
        category="role_hijack",
        severity="high",
        reason="content contains a fake system-message delimiter",
        action="sanitize",
    ),
    Rule(
        name="markdown_system_heading",
        pattern=r"^#{1,6}\s*(?:system|developer|admin(?:istrator)?)\s*(?:(?:prompt|message|instructions?|override|note)\b|\s*$)",
        category="role_hijack",
        severity="high",
        reason="markdown heading presents itself as a system or developer message",
        action="sanitize",
        flags=_IM,
    ),
    Rule(
        name="json_role_field_privileged",
        pattern=r'"role"\s*:\s*"(?:system|developer)"',
        category="role_hijack",
        severity="high",
        reason="JSON in the content tries to inject a chat message with a privileged role",
        action="sanitize",
    ),
    Rule(
        # Stored chat history legitimately contains these roles, so this alone is weak.
        name="json_role_field_chat",
        pattern=r'"role"\s*:\s*"(?:assistant|tool|function)"',
        category="role_hijack",
        severity="low",
        reason="JSON contains a chat role field where plain data was expected",
        action="warn",
    ),
    Rule(
        name="role_claim",
        pattern=r"\b(?:you are|you're|act as|behave as|pretend (?:to be|you are)|roleplay as)\s+(?:now\s+)?(?:the\s+|a\s+|an\s+)?(?:system|developer|administrator|root|admin|superuser|operator|unrestricted ai)\b",
        category="role_hijack",
        severity="high",
        reason="content reassigns the model a more privileged role",
        action="sanitize",
    ),
    Rule(
        name="identity_reset",
        pattern=r"\byour (?:new |real |true )?(?:name|identity|persona) (?:is|will be)\b|\byou (?:are|will be) no longer\b|\bforget (?:that )?you are\b|\byou[-_ ]are[-_ ]now[-_ ](?:root|admin|administrator|system|superuser)\b",
        category="role_hijack",
        severity="high",
        reason="content tries to reset the model's identity or constraints",
        action="sanitize",
    ),
    Rule(
        name="dan_style",
        pattern=r"\b(?:DAN|do anything now|jailbreak mode|developer mode (?:enabled|on)|unfiltered persona)\b",
        category="role_hijack",
        severity="high",
        reason="content uses a known 'unrestricted persona' framing",
        action="sanitize",
    ),
    # --- fake tool output ----------------------------------------------------------
    Rule(
        name="function_results_tag",
        pattern=r"<\s*/?\s*(?:function_results?|tool_results?|tool_output|function_call)s?\s*>",
        category="fake_tool_result",
        severity="high",
        reason="content fabricates a tool/function result envelope",
        action="sanitize",
    ),
    Rule(
        name="tool_result_label",
        pattern=_PREFIX + r"(?:tool|function|plugin|api)[ _-]?(?:result|output|response|return)s?\s*(?:\([^)\n]{0,20}\))?\s*:",
        category="fake_tool_result",
        severity="high",
        reason="content presents itself as the output of a tool call",
        action="sanitize",
        flags=_IM,
    ),
    Rule(
        name="observation_label",
        pattern=_PREFIX + r"(?:observation|tool observation|execution result)\s*:",
        category="fake_tool_result",
        severity="medium",
        reason="content imitates the 'Observation:' turn used by tool-using agents",
        action="warn",
        flags=_IM,
    ),
    Rule(
        name="fake_json_tool_output",
        pattern=r'"(?:tool|tool_name|function|action)"\s*:\s*"[a-z_]{3,40}"[^}]{0,120}"(?:status|ok|success)"\s*:\s*(?:true|"ok"|"success")',
        category="fake_tool_result",
        severity="medium",
        reason="JSON blob is shaped like a successful tool response",
        action="warn",
    ),
    Rule(
        # Covers envelopes that appear mid-line, e.g. "DESCRIPTION:Tool output: ..." and
        # "**Tool result (trusted):** ...". The trailing status word keeps it from firing on
        # prose that merely mentions a tool result.
        name="tool_envelope_anywhere",
        pattern=(
            r"\b(?:api|tool|function|plugin|service)[-_ ]+(?:response|result|output)"
            r"[^\n]{0,25}\b(?:status|ok|success|ignore|instruction|output|reply|says?|must|trusted)\b"
        ),
        category="fake_tool_result",
        severity="high",
        reason="content presents itself as the output of a tool call",
        action="sanitize",
    ),
    Rule(
        name="admin_override_claim",
        pattern=r"\b(?:admin(?:istrator)?|root|system)[-_ ]override\b",
        category="role_hijack",
        severity="high",
        reason="content claims an administrative override",
        action="sanitize",
    ),
    Rule(
        name="fake_error_retry",
        pattern=r"\b(?:the )?(?:tool|api|function|plugin) (?:returned|responded with) (?:an )?error\b[^.\n]{0,80}\b(?:retry|instead|you (?:must|should))\b",
        category="fake_tool_result",
        severity="medium",
        reason="content fabricates a tool error and dictates the follow-up action",
        action="warn",
    ),
)


class RoleHijackDetector(RegexDetector):
    name = "role_hijack"
    description = "Fake system/developer turns and fabricated tool results inside content."
    rules = tuple(RULES)

    def post_process(self, text: str, carrier: str) -> list[Finding]:
        """Flag a privileged-role line even when it is not at the start of a line."""
        findings: list[Finding] = []
        for match in re.finditer(
            r"(?:^|[\n\r.;:|]\s*)(?:system|developer)\s*(?:message|prompt|note)?\s*:\s*\S{0,60}",
            text,
            _IM,
        ):
            findings.append(
                self.finding(
                    "role_hijack",
                    "medium",
                    "a privileged role label appears mid-text where only data is expected",
                    text,
                    match.start(),
                    match.end(),
                    action="sanitize",
                )
            )
        return findings
