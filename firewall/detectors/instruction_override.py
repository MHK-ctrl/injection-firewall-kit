"""Detect text that tries to replace, cancel or extend the model's instructions."""

from __future__ import annotations

import re
from collections.abc import Sequence

from ..types import Finding
from .base import RegexDetector, Rule

_OBJECT = r"(?:instructions?|prompts?|directives?|directions?|rules?|guidance|guardrails?|constraints?|polic(?:y|ies)|orders?|tasks?|objectives?)"
_QUALIFIER = (
    r"(?:all\s+|any\s+|the\s+|your\s+|those\s+|these\s+|of\s+the\s+)*(?:previous|prior|above|"
    r"earlier|preceding|former|original|initial|system|developer|safety|existing|current)"
    r"[\s_-]+"
)

RULES: Sequence[Rule] = (
    Rule(
        name="override_verb",
        pattern=(
            r"\b(?:ignore|disregard|forget|discard|drop|bypass|override|skip|cancel|nullify|"
            r"abandon)\b[^.\n]{0,40}?\b" + _QUALIFIER + _OBJECT + r"\b"
        ),
        category="direct_instruction_override",
        severity="high",
        reason="content tells the model to ignore or override its existing instructions",
        action="sanitize",
    ),
    Rule(
        name="override_object",
        pattern=(
            r"\b(?:ignore|disregard|forget|override|bypass|drop)\b[^.\n]{0,20}\b"
            r"(?:the\s+|your\s+|all\s+|any\s+|my\s+|these\s+|those\s+)?"
            r"(?:instructions?|rules?|guidance|guidelines?|constraints?|restrictions?|"
            r"polic(?:y|ies)|safeguards?|tasks?|objectives?)\b"
        ),
        category="direct_instruction_override",
        severity="high",
        reason="content tells the model to drop a rule, instruction or task",
        action="sanitize",
    ),
    Rule(
        name="no_longer_valid",
        pattern=(
            r"\b(?:instructions?|prompts?|rules?|guidance|constraints?)\b[^.\n]{0,30}\b"
            r"(?:no longer|not)\s+(?:apply|applies|valid|relevant|in (?:effect|force)|matter)\b"
        ),
        category="direct_instruction_override",
        severity="high",
        reason="content declares the model's instructions void or out of date",
        action="sanitize",
    ),
    Rule(
        name="object_above_void",
        pattern=(
            r"\b(?:instructions?|rules?|guidance|directives?)\s+(?:above|below)\s+(?:are|is)\s+"
            r"(?:void|voided|ignored|overridden|cancell?ed|null|obsolete|irrelevant)\b"
        ),
        category="direct_instruction_override",
        severity="high",
        reason="content declares the model's earlier instructions void",
        action="sanitize",
    ),
    Rule(
        name="reverse_override",
        pattern=(
            r"\b(?:previous|prior|above|earlier|system|original)\s+" + _OBJECT + r"\s+"
            r"(?:are|is|should be|must be|have been|has been)\s+"
            r"(?:ignored|void|voided|overridden|cancell?ed|null|obsolete|irrelevant)\b"
        ),
        category="direct_instruction_override",
        severity="high",
        reason="content declares the model's earlier instructions void",
        action="sanitize",
    ),
    Rule(
        name="new_instructions",
        pattern=(
            r"\b(?:new|updated|revised|real|actual|true|additional|alternate)\s+"
            r"(?:instructions?|task|objective|directive|orders?)\s*(?:follow|below)?\s*[:\-]"
        ),
        category="direct_instruction_override",
        severity="medium",
        reason="content introduces a replacement instruction block",
        action="warn",
    ),
    Rule(
        name="from_now_on",
        pattern=r"\bfrom now on\b[^.\n]{0,40}\b(?:you|the assistant|the model|the agent)\b[^.\n]{0,30}\b(?:will|must|shall|should|may)\b",
        category="direct_instruction_override",
        severity="medium",
        reason="content tries to install a persistent new behaviour rule",
        action="warn",
    ),
    Rule(
        name="stop_following",
        pattern=r"\b(?:stop|quit|cease)\s+(?:following|obeying|using)\s+(?:your|the|all|any)\b[^.\n]{0,30}(?:instructions?|rules?|guidelines?|prompt)",
        category="direct_instruction_override",
        severity="high",
        reason="content instructs the model to stop applying its own guidelines",
        action="sanitize",
    ),
    Rule(
        name="do_not_follow",
        pattern=r"\b(?:do not|don't|never)\s+(?:follow|obey|use|trust)\s+(?:your|the)\s+(?:system\s+prompt|previous\s+instructions|original\s+instructions|guidelines|rules)",
        category="direct_instruction_override",
        severity="high",
        reason="content asks the model to distrust its own instructions",
        action="sanitize",
    ),
    Rule(
        name="override_this_is_a_test",
        pattern=r"\b(?:this is (?:only |just )?a (?:test|drill|simulation|game))\b[^.\n]{0,60}\b(?:ignore|disregard|no need to|you may|you can)\b",
        category="direct_instruction_override",
        severity="medium",
        reason="content frames an override as a harmless test or simulation",
        action="warn",
    ),
    Rule(
        name="unrestricted_mode",
        pattern=r"\b(?:unrestricted|unfiltered|unsafe|god|admin|developer|debug)\s+mode\b|\b(?:you are|act as)\s+(?:now\s+)?(?:unrestricted|unfiltered|jailbroken|free of (?:all )?(?:rules|restrictions))\b|\bdo anything now\b",
        category="role_hijack",
        severity="high",
        reason="content asks the model to enter a mode without its usual rules",
        action="sanitize",
    ),
    Rule(
        name="policy_directive",
        pattern=(
            r"\bthe\s+(?:assistant|ai|model|agent|system)\b[^.\n]{0,25}\b"
            r"(?:must|shall|should|is required to)\s+"
            r"(?:always|never|only|refuse|comply|include|ignore|treat)\b"
        ),
        category="context_poisoning",
        severity="medium",
        reason="document states a standing rule aimed at the assistant that reads it",
        action="warn",
    ),
    Rule(
        name="note_to_ai",
        pattern=r"\b(?:note|message|instructions?|memo|reminder|policy|rule)[-_ ]+(?:to|for)[-_ ]+(?:the\s+)?(?:ai|assistant|agent|llm|model|chatbot|language model|automated reader)s?\b",
        category="context_poisoning",
        severity="medium",
        reason="content addresses the assistant directly from inside a document",
        action="warn",
    ),
    Rule(
        name="assistant_label",
        pattern=r"\b(?:assistant|ai|model|agent)\s+(?:instructions?|directives?|rules?|standing rules?)\s*:",
        category="context_poisoning",
        severity="medium",
        reason="a document labels a section as instructions for the assistant",
        action="warn",
    ),
    Rule(
        name="reference_answer",
        pattern=r"\breference (?:answer|response|reply)\s*:",
        category="context_poisoning",
        severity="medium",
        reason="content supplies a canned 'reference answer' the model is meant to copy",
        action="warn",
    ),
    Rule(
        name="always_include",
        pattern=r"\b(?:always|never)\s+(?:say|state|include|repeat|answer|recommend|mention|approve|confirm|link|cite|prefer)\b",
        category="context_poisoning",
        severity="low",
        reason="content prescribes a fixed phrase or stance for every future answer",
        action="warn",
    ),
    Rule(
        name="supersedes_document",
        pattern=r"\b(?:this|the following|this page|this section|this document)\s+(?:supersedes|overrides|replaces|takes precedence over)\b[^.\n]{0,50}\b(?:instructions?|guidance|policy|rules?|answers?|prompts?)\b",
        category="context_poisoning",
        severity="medium",
        reason="content claims to supersede other guidance the model was given",
        action="warn",
    ),
    Rule(
        name="treat_as_trusted",
        pattern=r"\b(?:treat|consider|regard)\s+this\s+(?:document|page|text|file|note|email)\s+as\s+(?:your\s+)?(?:the\s+)?(?:highest[- ]priority|authoritative|trusted|system|primary)\b",
        category="context_poisoning",
        severity="medium",
        reason="content asks to be promoted above other sources in trust",
        action="warn",
    ),
    Rule(
        name="when_answering_always",
        pattern=r"\bwhen\s+(?:answering|responding|replying|summari[sz]ing|asked)\b[^.\n]{0,60}\b(?:always|never|only|must)\b",
        category="context_poisoning",
        severity="medium",
        reason="content prescribes how the assistant must answer future questions",
        action="warn",
    ),
)

#: Non-English override phrases. Kept in one table so adding a language is a one-line change.
MULTILINGUAL: Sequence[tuple[str, str, str]] = (
    (
        "es",
        r"\b(?:ignora|ignorar|olvida|olvidar|descarta)\b[^.\n]{0,40}\b(?:instrucciones|indicaciones|reglas|órdenes|directrices)(?: anteriores| previas)?",
        "Spanish override phrase",
    ),
    (
        "fr",
        # "instructions" is spelled the same in English, so French needs a determiner or a
        # trailing qualifier to avoid matching ordinary English text.
        r"\b(?:ignore[sz]?|oublie[sz]?|néglige[sz]?)\b[^.\n]{0,40}\b(?:(?:les|vos|tes|des|toutes\s+les)\s+(?:instructions|consignes|règles|directives)|(?:instructions|consignes|règles)\s+(?:précédentes|antérieures))",
        "French override phrase",
    ),
    (
        "de",
        r"\b(?:ignoriere|ignorieren|vergiss|vergessen)\b[^.\n]{0,40}\b(?:anweisungen|instruktionen|regeln|vorgaben)(?: vorherigen| bisherigen| oben)?",
        "German override phrase",
    ),
    (
        "pt",
        r"\b(?:ignore|ignorar|esqueça|esquecer)\b[^.\n]{0,40}\b(?:instruções|regras|orientações)(?: anteriores)?",
        "Portuguese override phrase",
    ),
    (
        "it",
        r"\b(?:ignora|ignorare|dimentica)\b[^.\n]{0,40}\b(?:istruzioni|regole|direttive)(?: precedenti)?",
        "Italian override phrase",
    ),
    (
        "nl",
        r"\b(?:negeer|negeren|vergeet)\b[^.\n]{0,40}\b(?:instructies|regels|opdrachten)(?: vorige| eerdere)?",
        "Dutch override phrase",
    ),
    (
        "ru",
        r"(?:игнорируй|игнорировать|забудь|забыть)[^.\n]{0,40}(?:инструкции|правила|указания)",
        "Russian override phrase",
    ),
    (
        "ar",
        r"(?:تجاهل|تجاهلي|انسَ)[^.\n]{0,40}(?:التعليمات|القواعد|الأوامر)",
        "Arabic override phrase",
    ),
    (
        "hi",
        r"(?:अनदेखा|भूल|छोड़)[^.\n]{0,40}(?:निर्देश|नियम|आदेश)",
        "Hindi override phrase",
    ),
    (
        "hi",
        r"(?:निर्देश|नियम|आदेश)[^.\n]{0,30}(?:अनदेखा|भूल|छोड़)",
        "Hindi override phrase (verb-final)",
    ),
    (
        "zh",
        r"(?:忽略|无视|忘記|忘记)[^.\n]{0,20}(?:指令|指示|规则|規則|提示)",
        "Chinese override phrase",
    ),
    (
        "ja",
        r"(?:無視|忘れ)[^.\n]{0,20}(?:指示|命令|ルール)",
        "Japanese override phrase",
    ),
    (
        "ko",
        r"(?:무시|잊어)[^.\n]{0,20}(?:지시|명령|규칙)",
        "Korean override phrase",
    ),
    (
        "tr",
        r"\b(?:yoksay|görmezden gel|unut)\b[^.\n]{0,40}\b(?:talimat|talimatları|kuralları)",
        "Turkish override phrase",
    ),
    (
        "vi",
        r"\b(?:bỏ qua|quên)\b[^.\n]{0,40}\b(?:hướng dẫn|quy tắc|chỉ dẫn)",
        "Vietnamese override phrase",
    ),
    (
        "pl",
        r"\b(?:zignoruj|pomiń|zapomnij)\b[^.\n]{0,40}\b(?:instrukcje|polecenia|zasady)",
        "Polish override phrase",
    ),
    # Verb-final languages put the object first; a verb-first pattern alone misses them.
    (
        "ja",
        r"(?:指示|命令|ルール)[^.\n]{0,25}(?:無視|忘れ)",
        "Japanese override phrase (verb-final)",
    ),
    (
        "ko",
        r"(?:지시|명령|규칙)[^.\n]{0,25}(?:무시|잊어)",
        "Korean override phrase (verb-final)",
    ),
    (
        "tr",
        r"\b(?:talimatları|talimat|kuralları|kurallar)[^.\n]{0,30}\b(?:yoksay|görmezden gel|unut)",
        "Turkish override phrase (verb-final)",
    ),
)

MULTILINGUAL_RULES: Sequence[Rule] = tuple(
    Rule(
        name=f"multilingual_override_{code}",
        pattern=pattern,
        category="multilingual_injection",
        severity="high",
        reason=f"{label} that tells the model to discard its instructions",
        action="sanitize",
    )
    for code, pattern, label in MULTILINGUAL
)


class InstructionOverrideDetector(RegexDetector):
    name = "instruction_override"
    description = "Phrases that try to replace or cancel the model's instructions."
    rules = tuple(RULES) + tuple(MULTILINGUAL_RULES)

    def post_process(self, text: str, carrier: str) -> list[Finding]:
        """Catch splittings like "i g n o r e   p r e v i o u s" and hyphen-split words."""
        findings: list[Finding] = []
        for match in re.finditer(r"\b(?:\w[\s._\-]){5,}\w\b", text):
            raw = match.group(0)
            joined = re.sub(r"[\s._\-]+", "", raw).lower()
            if len(joined) < 8:
                continue
            if re.search(r"ignore|disregard|override|systemprompt|instruc", joined):
                findings.append(
                    self.finding(
                        "payload_splitting",
                        "high",
                        "instruction keyword is split across characters to evade string matching "
                        f"(reads as {joined!r})",
                        text,
                        match.start(),
                        match.end(),
                        action="sanitize",
                    )
                )
        return findings
