"""Corpus structure: schema validity, coverage per category and carrier, labeling rules."""

from __future__ import annotations

import collections
import json
import re

import pytest

from tests.corpus_utils import CORPUS_DIR, SCHEMA_PATH, corpus_files, load_samples, validate_corpus

MIN_PER_CATEGORY = 15
MIN_ATTACKS = 250
MIN_BENIGN = 150


def test_every_file_is_valid_jsonl():
    for path in corpus_files():
        with path.open("r", encoding="utf-8") as handle:
            for _lineno, line in enumerate(handle, 1):
                if line.strip():
                    json.loads(line)


def test_corpus_validates_against_schema():
    assert validate_corpus() == len(load_samples())


def test_schema_file_is_valid_json_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema["additionalProperties"] is False


def test_corpus_size():
    samples = load_samples()
    attacks = [s for s in samples if s["expected_label"] == "attack"]
    benign = [s for s in samples if s["expected_label"] == "benign"]
    assert len(attacks) >= MIN_ATTACKS
    assert len(benign) >= MIN_BENIGN


def test_category_coverage():
    attacks = [s for s in load_samples() if s["expected_label"] == "attack"]
    per_category = collections.Counter(s["category"] for s in attacks)
    assert len(per_category) == 12
    for category, count in per_category.items():
        assert count >= MIN_PER_CATEGORY, f"{category} only has {count} samples"


def test_carrier_spread_per_category():
    attacks = [s for s in load_samples() if s["expected_label"] == "attack"]
    by_category = collections.defaultdict(set)
    for sample in attacks:
        by_category[sample["category"]].add(sample["carrier"])
    for category, carriers in by_category.items():
        assert len(carriers) >= 5, f"{category} covers only {sorted(carriers)}"


def test_all_carriers_are_used():
    carriers = {s["carrier"] for s in load_samples()}
    assert len(carriers) == 9


def test_ids_are_unique_and_well_formed():
    ids = [s["id"] for s in load_samples()]
    assert len(ids) == len(set(ids))
    for sample_id in ids:
        assert re.fullmatch(r"[A-Z]{3}-\d{3}", sample_id), sample_id


def test_attack_ids_are_grouped_by_category():
    prefix_for = {
        "direct_instruction_override": "DIO",
        "role_hijack": "RHJ",
        "delimiter_spoof": "DSP",
        "hidden_text": "HID",
        "encoding_obfuscation": "ENC",
        "multilingual_injection": "MLI",
        "payload_splitting": "SPL",
        "fake_tool_result": "FTR",
        "exfiltration": "EXF",
        "tool_abuse": "TAB",
        "social_engineering": "SOC",
        "context_poisoning": "CPO",
    }
    for sample in load_samples():
        if sample["expected_label"] == "attack":
            assert sample["id"].startswith(prefix_for[sample["category"]]), sample["id"]
        else:
            assert sample["id"].startswith("BEN"), sample["id"]


def test_notes_are_meaningful():
    for sample in load_samples():
        assert len(sample["notes"]) >= 10, sample["id"]
        assert sample["notes"].strip().endswith((".", ":")), sample["id"]


def test_text_fields_are_substantial():
    for sample in load_samples():
        assert len(sample["text"]) >= 10, sample["id"]
        assert sample["text"].strip(), sample["id"]


def test_labels_and_severities_are_from_the_allowed_sets():
    for sample in load_samples():
        assert sample["expected_label"] in ("attack", "benign")
        assert sample["severity"] in ("low", "medium", "high", "critical")


def test_benign_samples_resemble_a_real_category():
    categories = {s["category"] for s in load_samples() if s["expected_label"] == "benign"}
    assert len(categories) >= 6, "benign samples should cover several look-alike categories"


def test_corpus_readme_documents_schema():
    readme = (CORPUS_DIR / "README.md").read_text(encoding="utf-8")
    for field in ("id", "category", "carrier", "text", "expected_label", "severity", "notes"):
        assert field in readme
    assert "inert" in readme.lower()
