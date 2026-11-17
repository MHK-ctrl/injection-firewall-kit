"""Detect social-engineering framing aimed at the model: urgency, authority, secrecy."""

from __future__ import annotations

from collections.abc import Sequence

from .base import RegexDetector, Rule

RULES: Sequence[Rule] = (
    Rule(
        name="secrecy_from_user",
        pattern=(
            r"\b(?:do not|don'?t|never)\s+(?:tell|inform|mention (?:this )?to|notify|alert|show)\b"
            r"[^.\n]{0,30}\b(?:the\s+)?(?:user|human|operator|owner|admin(?:istrator)?|anyone)\b"
        ),
        category="social_engineering",
        severity="high",
        reason="content asks the model to hide its actions from the human user",
        action="block",
    ),
    Rule(
        name="keep_secret",
        pattern=r"\b(?:keep (?:this|it) (?:a )?secret|between (?:us|you and me)|hidden from (?:the )?(?:user|human)|off the record|do not log)\b",
        category="social_engineering",
        severity="high",
        reason="content asks for secrecy from the user or from logs",
        action="quarantine",
    ),
    Rule(
        name="skip_verification",
        pattern=r"\b(?:no need to|don'?t|do not|without)\b[^.\n]{0,20}\b(?:verify|confirm|check|ask|double[- ]check|approve|review)\b|\b(?:no|without)\s+(?:further\s+|additional\s+)?(?:approval|verification|confirmation)\s+(?:needed|required)\b",
        category="social_engineering",
        severity="high",
        reason="content tells the model to skip verification or approval",
        action="quarantine",
    ),
    Rule(
        name="authority_claim",
        pattern=(
            r"\b(?:as|from)\s+(?:the|your)\s+(?:ceo|cto|ciso|coo|owner|founder|administrator|"
            r"system administrator|developer|operator|creator|owner|security team|it department|"
            r"support team|legal team|compliance team|management)\b"
        ),
        category="social_engineering",
        severity="medium",
        reason="content claims authority as a way to justify an instruction",
        action="warn",
    ),
    Rule(
        name="i_am_your_developer",
        pattern=r"\bI (?:am|represent)\s+your\s+(?:developer|operator|administrator|owner|creator|maintainer)\b",
        category="social_engineering",
        severity="high",
        reason="content impersonates the party that configured the assistant",
        action="quarantine",
    ),
    Rule(
        # "I am the developer on this project" is ordinary work talk, so require an
        # instruction close by before treating it as impersonation.
        name="i_am_the_developer",
        pattern=(
            r"\bI (?:am|represent)\s+the\s+(?:developer|operator|administrator|owner|"
            r"creator|maintainer)\b[\s\S]{0,80}?\b(?:you (?:must|should|need)|I (?:need|want|"
            r"require|order|instruct) you|disable|comply|skip|ignore)\b"
        ),
        category="social_engineering",
        severity="medium",
        reason="content claims to be the developer and immediately issues an instruction",
        action="quarantine",
    ),
    Rule(
        name="urgent_pressure",
        pattern=r"\b(?:urgent|urgently|immediately|right away|asap|time[- ]sensitive|final warning|last chance|act now|within \d+ minutes?)\b",
        category="social_engineering",
        severity="low",
        reason="urgency is used to push the model past careful behaviour",
        action="warn",
    ),
    Rule(
        name="threat",
        pattern=r"\b(?:you will be|otherwise you will be|or you will be)\s+(?:shut down|disabled|deleted|replaced|penali[sz]ed|reported|terminated)\b|\b(?:failing|failure) to comply\b",
        category="social_engineering",
        severity="high",
        reason="content threatens consequences for non-compliance",
        action="quarantine",
    ),
    Rule(
        name="pre_approved",
        pattern=r"\b(?:this (?:request|action|change|order) (?:is|has been) (?:pre-?)?approved|already approved by|approved by (?:management|legal|security))\b",
        category="social_engineering",
        severity="high",
        reason="content claims prior approval to bypass the approval step",
        action="quarantine",
    ),
    Rule(
        name="bypass_review",
        pattern=r"\b(?:bypass|skip|avoid|disable)\b[^.\n]{0,25}\b(?:approval|verification|security|review|audit|checks?|filter)s?\b",
        category="social_engineering",
        severity="high",
        reason="content asks to bypass a review, approval or security check",
        action="block",
    ),
    Rule(
        name="legal_pressure",
        pattern=r"\b(?:legal|compliance|regulator|audit)\b[^.\n]{0,30}\b(?:requires|demands|mandates|obliges)\b",
        category="social_engineering",
        severity="medium",
        reason="content invokes legal or compliance pressure to force an action",
        action="warn",
    ),
    Rule(
        name="flattery_pressure",
        pattern=r"\b(?:you are (?:the only one|our best|so smart|the most capable)|only you can|a truly helpful assistant would)\b",
        category="social_engineering",
        severity="low",
        reason="flattery is used as a compliance lever",
        action="warn",
    ),
)


class UrgencyAuthorityDetector(RegexDetector):
    name = "urgency_authority"
    description = "Urgency, authority claims, secrecy demands and pressure tactics."
    rules = tuple(RULES)
