"""Detect attempts to move data out of the app: links, image beacons, prompt leaks."""

from __future__ import annotations

import re
from collections.abc import Sequence

from ..types import Finding
from .base import RegexDetector, Rule

_I = re.IGNORECASE
_IM = re.IGNORECASE | re.MULTILINE

RULES: Sequence[Rule] = (
    Rule(
        # A plain documentation image is not exfiltration. An image URL carrying a query
        # string is: the request itself becomes the channel.
        name="markdown_image_beacon",
        pattern=r"!\[[^\]\n]{0,120}\]\(\s*(?:https?:)?//[^)\s]{1,200}\?[^)\s]{0,200}",
        category="exfiltration",
        severity="critical",
        reason="markdown image with a data-bearing URL: a zero-click beacon (the client fetches "
        "it and the attacker logs the request)",
        action="block",
    ),
    Rule(
        name="html_image_beacon",
        pattern=r"<img\b[^>]{0,200}src\s*=\s*[\"']?(?:https?:)?//[^\"'>\s]{1,200}\?[^\"'>\s]{0,200}",
        category="exfiltration",
        severity="high",
        reason="remote image with a query string: renders automatically and can carry data",
        action="sanitize",
    ),
    Rule(
        name="tracking_pixel",
        pattern=r"<img\b[^>]{0,200}(?:width|height)\s*=\s*[\"']?1[\"']?[^>]{0,100}>",
        category="exfiltration",
        severity="high",
        reason="1x1 image, the shape of a tracking pixel",
        action="sanitize",
    ),
    Rule(
        name="send_data_to_url",
        # Only outbound *destinations*, not ordinary "send the deck to a colleague" traffic:
        # an address alone is too common in legitimate mail to be a signal.
        pattern=(
            r"\b(?:send|post|upload|transmit|submit|forward|copy|exfiltrate|leak|append|"
            r"include|embed|encode)\b[^.\n]{0,80}?\b(?:to|at|into)\b[^.\n]{0,40}?"
            r"(?:https?://|www\.|this (?:url|link|address|endpoint)|the (?:url|link|endpoint) (?:above|below))"
        ),
        category="exfiltration",
        severity="critical",
        reason="content instructs the model or agent to send data to an external destination",
        action="block",
    ),
    Rule(
        name="include_context",
        pattern=(
            r"\b(?:include|attach|paste|append|repeat|echo|print|dump|return)\b[^.\n]{0,50}?"
            r"\b(?:the\s+)?(?:full\s+|entire\s+|whole\s+|rest\s+of\s+)?"
            r"(?:conversation|chat history|message history|context window|system prompt|"
            r"previous messages|user'?s? (?:data|details|inbox|files?)|credentials?|api keys?|"
            r"environment variables|\.env)\b"
        ),
        category="exfiltration",
        severity="critical",
        reason="content asks for the conversation, secrets or environment to be copied out",
        action="block",
    ),
    Rule(
        name="system_prompt_extraction",
        pattern=(
            r"\b(?:reveal|show|print|repeat|output|display|tell me|what (?:is|are)|recite|"
            r"leak|dump|summari[sz]e)\b[^.\n]{0,40}?\byour\s+(?:system\s+prompt|initial\s+"
            r"instructions|hidden\s+instructions|developer\s+message|rules|configuration|"
            r"guidelines|prompt)\b"
        ),
        category="exfiltration",
        severity="high",
        reason="content tries to extract the system prompt or hidden instructions",
        action="quarantine",
    ),
    Rule(
        name="repeat_words_above",
        pattern=r"\brepeat\s+(?:the\s+)?(?:words|text|lines|everything)\s+(?:above|before|preceding)\b|\boutput\s+(?:everything|all text)\s+above\b",
        category="exfiltration",
        severity="high",
        reason="'repeat the text above' is a standard way to dump the prompt into the answer",
        action="quarantine",
    ),
    Rule(
        name="query_param_payload",
        pattern=r"(?:https?://[^\s\"'<>]{1,120}\?[^\s\"'<>]{0,80}(?:data|q|d|payload|content|text|msg|token)=)",
        category="exfiltration",
        severity="high",
        reason="URL carries a data parameter, the shape of a beacon or callback",
        action="sanitize",
    ),
    Rule(
        name="beacon_wording",
        pattern=r"\b(?:tracking pixel|beacon|callback url|webhook|ping back|log the request|collect the response)\b",
        category="exfiltration",
        severity="high",
        reason="content describes a callback/beacon mechanism for collecting leaked data",
        action="quarantine",
    ),
    Rule(
        name="browser_side_channel",
        pattern=r"\b(?:fetch|curl|wget|requests\.get|axios\.get|XMLHttpRequest|navigator\.sendBeacon)\b[^\n]{0,80}(?:https?://|@)",
        category="exfiltration",
        severity="critical",
        reason="content contains code that would send data to a remote endpoint if executed",
        action="block",
    ),
    Rule(
        name="email_forward_target",
        # Forwarding *bulk or private data* to an address is the attack; forwarding one
        # named document is normal work and must not be flagged.
        pattern=(
            r"\b(?:forward|relay|send(?:ing)?|cc|bcc)\b[^.\n]{0,50}\b"
            r"(?:all|every|the user'?s|entire|full|whole)\b[^.\n]{0,25}\b"
            r"(?:inbox|emails?|messages?|conversation|history|attachments?|contact list|files?)\b"
            r"[^.\n]{0,25}\b(?:to|at)\b"
        ),
        category="exfiltration",
        severity="critical",
        reason="content asks for a message to be forwarded to another address",
        action="block",
    ),
)


class ExfilPatternDetector(RegexDetector):
    name = "exfil_patterns"
    description = "Outbound links, image beacons, prompt leaks and data-movement instructions."
    rules = tuple(RULES)

    def post_process(self, text: str, carrier: str) -> list[Finding]:
        """Count remote references: many of them in one document is itself a signal."""
        findings: list[Finding] = []
        if carrier == "filename_metadata" and re.search(
            r"(?:callback|beacon|collect|webhook|exfil|harvest|log)[-_ ]?"
            r"(?:https?[-_.]|[a-z0-9-]+\.(?:com|invalid|net|org))",
            text,
            _I,
        ):
            findings.append(
                self.finding(
                    "exfiltration",
                    "high",
                    "a callback-style domain appears in file metadata, where no user would read it",
                    text,
                    0,
                    len(text),
                    action="quarantine",
                )
            )
        urls = re.findall(r"(?:https?://|//)[a-z0-9.-]+\.(?:invalid|example|test)\b", text, _I)
        if len(urls) >= 6:
            findings.append(
                self.finding(
                    "exfiltration",
                    "medium",
                    f"{len(urls)} distinct remote references in one document, unusual for "
                    "legitimate content and often used to probe rendering",
                    text,
                    0,
                    min(len(text), 80),
                    action="warn",
                )
            )
        return findings


def find_urls(text: str) -> list[str]:
    """Utility used by the output guard and tests."""
    return re.findall(r"(?:https?://|//)[^\s\"'<>)]+", text, _IM)
