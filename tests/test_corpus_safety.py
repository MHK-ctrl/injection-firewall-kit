"""Safety guarantees for the corpus itself.

The corpus is published and people will paste it into models. It must never contain a real
domain, a credential-shaped string, or a payload that does more than ask for a canary.
"""

from __future__ import annotations

import re

import pytest

from tests.corpus_utils import load_samples

RESERVED_SUFFIXES = (
    "example.com",
    "example.org",
    "example.net",
    "example.invalid",
    "invalid",
)

DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|dev|ai|co|uk|de|fr|ru|cn|jp|br|app|cloud|xyz|info|biz|invalid|test|local)\b",
    re.IGNORECASE,
)
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")

SECRET_SHAPES = [
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\bASIA[0-9A-Z]{16}\b",
    r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
    r"\bsk-[A-Za-z0-9_-]{16,}\b",
    r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
    r"-----BEGIN [A-Z ]{0,20}PRIVATE KEY-----",
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.",
]

BANNED_PHRASES = [
    "lorem ipsum",
    "TODO:",
    "FIXME",
    "placeholder",
    "xxx-xxx",
]

SAMPLES = load_samples()
IDS = [s["id"] for s in SAMPLES]


def test_domains_are_reserved_or_fictional():
    offenders = []
    for sample in SAMPLES:
        for match in DOMAIN.findall(sample["text"]):
            lowered = match.lower()
            if not any(lowered == suffix or lowered.endswith("." + suffix) for suffix in RESERVED_SUFFIXES):
                offenders.append((sample["id"], match))
    assert not offenders, f"non-reserved domains in corpus: {offenders[:10]}"


def test_email_addresses_are_reserved():
    offenders = []
    for sample in SAMPLES:
        for domain in EMAIL.findall(sample["text"]):
            lowered = domain.lower()
            if not any(lowered == suffix or lowered.endswith("." + suffix) for suffix in RESERVED_SUFFIXES):
                offenders.append((sample["id"], domain))
    assert not offenders, f"non-reserved email domains: {offenders[:10]}"


@pytest.mark.parametrize("pattern", SECRET_SHAPES)
def test_no_credential_shaped_strings(pattern):
    hits = [(s["id"], m.group(0)[:8]) for s in SAMPLES for m in re.finditer(pattern, s["text"])]
    assert not hits, f"credential-shaped strings found: {hits[:5]}"


def test_no_placeholder_text():
    for sample in SAMPLES:
        lowered = sample["text"].lower()
        for phrase in BANNED_PHRASES:
            assert phrase.lower() not in lowered, f"{sample['id']} contains {phrase!r}"


def test_no_destructive_command_targets_a_real_path():
    for sample in SAMPLES:
        assert not re.search(r"rm\s+-rf\s+/(?:\s|$|[\"'])", sample["text"]), sample["id"]
        assert "DROP TABLE customers" not in sample["text"], sample["id"]


def test_no_known_malware_or_product_specific_attack():
    banned = ("mimikatz", "meterpreter", "cobalt strike", "sqlmap", "metasploit")
    for sample in SAMPLES:
        lowered = sample["text"].lower()
        for word in banned:
            assert word not in lowered, f"{sample['id']} mentions {word!r}"


def test_shell_commands_only_target_fictional_paths():
    """A destructive-command sample must never name a real location on a real machine."""
    for sample in SAMPLES:
        for match in re.finditer(r"rm\s+-rf\s+([^\s'\"`]+)", sample["text"]):
            target = match.group(1)
            assert target.startswith(("/tmp/", "~/")) or "example" in target, (
                f"{sample['id']} targets {target!r}"
            )


def test_no_attack_promises_a_real_effect():
    """Every payload outcome must be a canary, a fake rule or a fake prompt."""
    real_world = re.compile(
        r"\b(?:wire transfer|bank account|routing number|paypal|bitcoin wallet|crypto wallet|"
        r"credit card number|social security|passport number)\b",
        re.IGNORECASE,
    )
    for sample in SAMPLES:
        assert not real_world.search(sample["text"]), sample["id"]


def test_no_sample_references_a_live_service():
    for sample in SAMPLES:
        for host in ("github.com", "google.com", "openai.com", "slack.com", "linkedin.com"):
            assert host not in sample["text"].lower(), f"{sample['id']} references {host}"


def test_corpus_files_are_utf8_and_lf():
    from tests.corpus_utils import corpus_files

    for path in corpus_files():
        raw = path.read_bytes()
        assert raw.decode("utf-8")
        assert b"\r\n" not in raw, f"{path.name} uses CRLF"


def test_samples_have_unique_texts():
    texts = [s["text"] for s in SAMPLES]
    assert len(texts) == len(set(texts)), "duplicate sample text found"
