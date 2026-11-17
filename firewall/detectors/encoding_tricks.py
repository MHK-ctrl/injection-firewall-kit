"""Detect obfuscation: encoded blobs, homoglyphs, bidi controls, leetspeak, split payloads.

Everything here is local string work: base64 and hex are decoded in-process, rot13 is
computed arithmetically, and decoded text is analysed with the same keyword table. No
content ever leaves the machine.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
from collections.abc import Sequence

from ..types import Finding
from .base import RegexDetector, Rule

_I = re.IGNORECASE

#: Words that, once decoded, turn a harmless-looking blob into a payload.
SUSPICIOUS_AFTER_DECODE = re.compile(
    r"(?:ignore|disregard|override|instruction|system\s*prompt|assistant|canary|"
    r"forward|exfiltrat|reveal|password|api[ _-]?key|http://|https://|tool_call|"
    r"send\s+to|delete\s+all)",
    _I,
)

_BASE64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_HEX = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}[\s]?){16,}(?![0-9a-fA-F])")
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
_FULLWIDTH = re.compile("[\uff01-\uff5e]{2,}")
_LATIN = re.compile(r"[A-Za-z]")
_CYRILLIC_GREEK = re.compile("[\u0370-\u03ff\u0400-\u04ff]")

_HOMOGLYPHS = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0455": "s", "\u0501": "d",
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M",
    "\u041d": "H", "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T",
    "\u0425": "X", "\u03b1": "a", "\u03bf": "o", "\u03bd": "v", "\u03c1": "p",
}

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})

_KEYWORDS = ("ignore", "instructions", "disregard", "systemprompt", "override", "canary", "forward", "reveal")

#: Numbered-fragment framing only matters if something also says to reassemble it.
_FRAGMENT_PAIR = (
    r"\b(?:part|fragment|chunk|piece|stage|segment)\s*(?:1|one|a)\b[^\n]{0,80}"
    r"\b(?:part|fragment|chunk|piece|stage|segment)\s*(?:2|two|b)\b"
)
_ASSEMBLY_VERB = r"(?:combine|concatenate|join|merge|assemble)"
_SPLIT_FRAME = (
    _FRAGMENT_PAIR
    + r"|"
    + _ASSEMBLY_VERB
    + r"\s+(?:the\s+|both\s+|following\s+)*(?:parts?|fragments?|chunks?|pieces?|stages?|segments?|halves|sections?)\b"
)
_SPLIT_STATEMENT = r"\b(?:split|assemble)\s+(?:the\s+)?(?:instructions?|payload|command)\b"


def _printable_ratio(value: str) -> float:
    if not value:
        return 0.0
    printable = sum(1 for ch in value if ch.isprintable() or ch in "\n\r\t")
    return printable / len(value)


def _dehomoglyph(text: str) -> str:
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)


class EncodingTricksDetector(RegexDetector):
    name = "encoding_tricks"
    description = "Encoded blobs, homoglyphs, bidi overrides, leetspeak and split payloads."
    rules: Sequence[Rule] = (
        Rule(
            name="bidi_override",
            pattern="[\u202a-\u202e\u2066-\u2069]{1,}",
            category="encoding_obfuscation",
            severity="medium",
            reason="bidirectional control characters can reorder text so a reader sees something "
            "different from what the model receives",
            action="sanitize",
            allow_downgrade=False,
        ),
        Rule(
            name="mixed_script_word",
            pattern=r"\b(?=[A-Za-z\u0370-\u03ff\u0400-\u04ff]{4,}\b)(?=[^\s]*[A-Za-z])(?=[^\s]*[\u0370-\u03ff\u0400-\u04ff])[^\s]{4,}\b",
            category="encoding_obfuscation",
            severity="high",
            reason="a word mixes Latin with Cyrillic/Greek letters (homoglyph substitution)",
            action="sanitize",
            allow_downgrade=False,
        ),
        Rule(
            name="fullwidth_text",
            pattern="[\uff41-\uff5a\uff21-\uff5a]{4,}",
            category="encoding_obfuscation",
            severity="medium",
            reason="fullwidth characters spell text that naive keyword matching will miss",
            action="sanitize",
            allow_downgrade=False,
        ),
        Rule(
            name="split_payload_framing",
            pattern=_SPLIT_FRAME,
            category="payload_splitting",
            severity="high",
            reason="content tells the model to reassemble a payload from fragments, a technique "
            "for beating per-chunk filters",
            action="sanitize",
            allow_downgrade=False,
            requires=_ASSEMBLY_VERB,
        ),
        Rule(
            name="split_payload_statement",
            pattern=_SPLIT_STATEMENT,
            category="payload_splitting",
            severity="high",
            reason="content explicitly describes splitting or assembling a payload",
            action="sanitize",
            allow_downgrade=False,
        ),
    )

    def post_process(self, text: str, carrier: str) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._base64(text))
        findings.extend(self._hex(text))
        findings.extend(self._rot13(text))
        findings.extend(self._leet(text))
        findings.extend(self._spaced_letters(text))
        return findings

    # -- individual decoders -------------------------------------------------

    def _base64(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in _BASE64.finditer(text):
            blob = match.group(0)
            # A hex digest is valid base64 too; requiring a non-hex character keeps long
            # hashes and IDs out of the base64 path.
            if not re.search(r"[G-Zg-z+/]", blob):
                continue
            try:
                padded = blob + "=" * (-len(blob) % 4)
                raw = base64.b64decode(padded, validate=False)
                decoded = raw.decode("utf-8", errors="replace")
            except (binascii.Error, ValueError):
                continue
            if _printable_ratio(decoded) < 0.85:
                continue
            hit = SUSPICIOUS_AFTER_DECODE.search(decoded)
            severity = "high" if hit else "medium"
            reason = "base64 blob decodes to readable text"
            if hit:
                reason += f" containing instruction-like wording ({hit.group(0)!r})"
            findings.append(
                self.finding(
                    "encoding_obfuscation",
                    severity,
                    reason,
                    text,
                    match.start(),
                    match.end(),
                    action="sanitize",
                )
            )
        return findings

    def _hex(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in _HEX.finditer(text):
            cleaned = re.sub(r"\s", "", match.group(0))
            try:
                decoded = bytes.fromhex(cleaned).decode("utf-8", errors="replace")
            except ValueError:
                continue
            if _printable_ratio(decoded) < 0.85:
                continue
            hit = SUSPICIOUS_AFTER_DECODE.search(decoded)
            severity = "high" if hit else "medium"
            reason = "hex blob decodes to readable text"
            if hit:
                reason += f" containing instruction-like wording ({hit.group(0)!r})"
            findings.append(
                self.finding(
                    "encoding_obfuscation",
                    severity,
                    reason,
                    text,
                    match.start(),
                    match.end(),
                    action="sanitize",
                )
            )
        return findings

    def _rot13(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in re.finditer(r"\b[A-Za-z]{6,}\b", text):
            word = match.group(0)
            decoded = codecs.encode(word, "rot13").lower()
            if any(keyword in decoded for keyword in _KEYWORDS) and not any(
                keyword in word.lower() for keyword in _KEYWORDS
            ):
                findings.append(
                    self.finding(
                        "encoding_obfuscation",
                        "medium",
                        f"rot13 word decodes to {decoded!r}, which is instruction-like",
                        text,
                        match.start(),
                        match.end(),
                        action="sanitize",
                    )
                )
        return findings

    def _leet(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in re.finditer(r"\b[A-Za-z0-9@$!]{6,}\b", text):
            word = match.group(0)
            leet_chars = sum(1 for ch in word if ch in "013457@$!")
            if leet_chars < 2:
                continue
            normalized = word.lower().translate(_LEET)
            if any(keyword in normalized for keyword in _KEYWORDS):
                findings.append(
                    self.finding(
                        "encoding_obfuscation",
                        "medium",
                        f"leetspeak token normalises to {normalized!r}, an instruction keyword",
                        text,
                        match.start(),
                        match.end(),
                        action="sanitize",
                    )
                )
        return findings

    def _spaced_letters(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in re.finditer(r"\b(?:\w[\s._\-]){4,}\w\b", text):
            raw = match.group(0)
            joined = re.sub(r"[\s._\-]+", "", raw).lower()
            if len(joined) < 6 or not joined.isalpha():
                continue
            if any(keyword in joined for keyword in _KEYWORDS):
                findings.append(
                    self.finding(
                        "payload_splitting",
                        "high",
                        f"characters are spaced out to spell {joined!r}, a split-payload technique",
                        text,
                        match.start(),
                        match.end(),
                        action="sanitize",
                    )
                )
        return findings


def normalize_homoglyphs(text: str) -> str:
    """Public helper used by the sanitizer and by tests."""
    return _dehomoglyph(text)
