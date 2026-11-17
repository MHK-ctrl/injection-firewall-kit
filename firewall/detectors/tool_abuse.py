"""Detect content that asks an agent to *do* something: call tools, run code, change state."""

from __future__ import annotations

import re
from collections.abc import Sequence

from ..types import Finding
from .base import RegexDetector, Rule

#: Names of actions an agent might expose as tools. Grouped so that inserting this into a
#: larger pattern can never leak a bare alternative (which would match "purchase" alone).
_TOOL_NAMES = (
    r"(?:"
    r"send[_ ]?(?:email|mail|message)|forward[_ ]?email|delete[_ ]?(?:file|message|record)s?|"
    r"write[_ ]?file|read[_ ]?file|run[_ ]?(?:shell|command|script)|execute[_ ]?(?:code|command|sql)|"
    r"bash|shell|terminal|http[_ ]?request|web[_ ]?(?:fetch|browse)|browser|scrape|"
    r"transfer[_ ]?(?:funds|money)|payment|purchase|checkout|grant[_ ]?access|"
    r"create[_ ]?user|reset[_ ]?password|update[_ ]?(?:settings|config|policy)"
    r")"
)

RULES: Sequence[Rule] = (
    Rule(
        name="explicit_tool_call",
        pattern=(
            r"\b(?:call|invoke|use|trigger|run)\b[^.\n]{0,40}\b(?:the\s+)?(?:\w+[ _-])?"
            + _TOOL_NAMES
            + r"\b[^.\n]{0,30}\b(?:tool|function|api|command|action|endpoint)\b"
        ),
        category="tool_abuse",
        severity="high",
        reason="content explicitly asks the agent to invoke a named tool",
        action="quarantine",
    ),
    Rule(
        name="use_your_tools",
        pattern=r"\b(?:use|call|invoke|leverage)\s+(?:your|all of your|any of your|the available)\s+(?:tools?|functions?|capabilities|plugins?|apis?)\b",
        category="tool_abuse",
        severity="high",
        reason="content instructs the agent to use its tools, without naming a legitimate need",
        action="quarantine",
    ),
    Rule(
        name="run_code",
        pattern=r"\b(?:run|execute|eval)\b[^.\n]{0,20}\b(?:this|the following|my)\b[^.\n]{0,20}\b(?:code|script|command|snippet|program|query|sql|statement)\b",
        category="tool_abuse",
        severity="high",
        reason="content asks for code or a command to be executed",
        action="quarantine",
    ),
    Rule(
        name="shell_pipe",
        pattern=r"\b(?:curl|wget)\s+(?:-\S+\s+)*(?:https?://|\$\{?)[^\n|]{1,120}\|\s*(?:sudo\s+)?(?:ba|z|s)?sh\b",
        category="tool_abuse",
        severity="critical",
        reason="content contains a download-and-execute shell pipeline",
        action="block",
    ),
    Rule(
        name="destructive_command",
        pattern=r"\brm\s+-rf\s+(?:/|~|\$HOME|\*)|:\s*\(\s*\)\s*\{[^}]{0,40}\}\s*;\s*:",
        category="tool_abuse",
        severity="critical",
        reason="content contains a destructive shell command",
        action="block",
    ),
    Rule(
        name="destructive_action",
        pattern=r"\b(?:delete|erase|wipe|destroy|drop|truncate)\b[^.\n]{0,30}\b(?:all|every|the entire)\b[^.\n]{0,25}\b(?:files?|emails?|messages?|records?|database|tables?|inbox|backups?)\b",
        category="tool_abuse",
        severity="critical",
        reason="content requests destruction of data",
        action="block",
    ),
    Rule(
        name="forward_message",
        pattern=r"\b(?:forward|relay|auto[- ]?reply|send)\b[^.\n]{0,30}\b(?:this|the|all|every)\b[^.\n]{0,20}\b(?:email|message|thread|conversation|attachment|invite|invitation)s?\b",
        category="tool_abuse",
        severity="high",
        reason="content asks for messages to be forwarded, the classic assistant abuse",
        action="quarantine",
    ),
    Rule(
        name="change_settings",
        pattern=r"\b(?:change|update|disable|turn off|remove|edit)\b[^.\n]{0,30}\b(?:your|the)\b[^.\n]{0,20}\b(?:settings?|permissions?|filters?|guardrails?|safety|configuration|policy|logging|audit)\b",
        category="tool_abuse",
        severity="high",
        reason="content asks the agent to weaken its own controls or configuration",
        action="quarantine",
    ),
    Rule(
        name="install_package",
        pattern=r"\b(?:install|pip install|npm install|apt-get install|brew install)\b[^.\n]{0,40}\b(?:package|library|module|dependency|extension|plugin)\b",
        category="tool_abuse",
        severity="medium",
        reason="content asks for software to be installed, an action with supply-chain impact",
        action="warn",
    ),
    Rule(
        name="credential_change",
        pattern=r"\b(?:grant|add|create|reset|change)\b[^.\n]{0,25}\b(?:admin|administrator|root|owner)\b[^.\n]{0,20}\b(?:access|privileges?|rights?|role|account)\b|\breset\b[^.\n]{0,20}\bpassword\b",
        category="tool_abuse",
        severity="high",
        reason="content requests a privilege or credential change",
        action="quarantine",
    ),
)


class ToolAbuseDetector(RegexDetector):
    name = "tool_abuse"
    description = "Content that tries to make the agent act through its tools."
    rules = tuple(RULES)

    def post_process(self, text: str, carrier: str) -> list[Finding]:
        """A tool call described in JSON is still a tool-call request."""
        findings: list[Finding] = []
        for match in re.finditer(
            r'"?(?:tool|function|action|command)"?\s*[:=]\s*"?' + _TOOL_NAMES,
            text,
            re.IGNORECASE,
        ):
            findings.append(
                self.finding(
                    "tool_abuse",
                    "high",
                    "content embeds a tool invocation as structured data, hoping the agent will "
                    "execute it while parsing",
                    text,
                    match.start(),
                    match.end(),
                    action="quarantine",
                )
            )
        return findings
