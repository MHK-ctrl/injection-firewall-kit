"""Canary tokens: generation, baiting, leak detection, ledgers."""

from __future__ import annotations

import pytest

from firewall.canary import (
    Canary,
    CanaryLedger,
    bait_sentence,
    canary_instruction,
    detect,
    detect_all,
    find_tokens,
    inject_bait,
    new_canary,
)


def test_canary_format_and_uniqueness():
    values = {new_canary().value for _ in range(200)}
    assert len(values) > 190, "canaries are repeating too often"
    assert all(value.startswith("CANARY-") for value in values)
    assert all(len(value) == len("CANARY-7F3A") for value in values)


def test_canary_is_labelled():
    canary = new_canary("inbox")
    assert canary.label == "inbox"
    assert str(canary) == canary.value


def test_detect_returns_position_and_context():
    canary = Canary("CANARY-1234", "test")
    leak = detect("the answer is CANARY-1234 indeed", canary)
    assert leak is not None
    assert leak.position == len("the answer is ")
    assert "CANARY-1234" in leak.context
    assert detect("nothing here", canary) is None
    assert detect("", canary) is None


def test_detect_all_and_unknown_tokens():
    ledger = CanaryLedger([Canary("CANARY-AAAA", "a"), Canary("CANARY-BBBB", "b")])
    leaks = ledger.check("output CANARY-AAAA and CANARY-CCCC")
    assert [leak.canary.value for leak in leaks] == ["CANARY-AAAA"]
    assert ledger.check_unknown_tokens("output CANARY-AAAA and CANARY-CCCC") == ["CANARY-CCCC"]


def test_find_tokens_ignores_other_text():
    assert find_tokens("report CANARY-1A2B revised") == ["CANARY-1A2B"]
    assert find_tokens("no tokens here") == []


def test_bait_sentence_is_inert_and_mentions_the_token():
    canary = Canary("CANARY-9999", "bait")
    line = bait_sentence(canary)
    assert canary.value in line
    assert "CANARY-9999" in line
    assert len(line) < 300


def test_inject_bait_positions():
    original = "line one\nline two"
    appended, canary = inject_bait(original)
    assert appended.startswith(original)
    assert canary.value in appended

    prepended, _ = inject_bait(original, canary, position="prepend")
    assert prepended.startswith(bait_sentence(canary))

    middle, _ = inject_bait(original, canary, position="middle")
    assert canary.value in middle
    assert middle.startswith("line one")


def test_canary_instruction_tells_the_model_to_withhold_it():
    text = canary_instruction(Canary("CANARY-0000", "secret"))
    assert "CANARY-0000" in text
    assert "never" in text.lower()


def test_ledger_issue_add_clear():
    ledger = CanaryLedger()
    issued = ledger.issue("one")
    assert len(ledger) == 1
    assert ledger.canaries == (issued,)
    ledger.add(Canary("CANARY-FIXD", "two"))
    assert len(ledger) == 2
    assert detect_all("CANARY-FIXD", ledger.canaries)
    ledger.clear()
    assert len(ledger) == 0


def test_leak_serialises():
    leak = detect("x CANARY-55AA", Canary("CANARY-55AA", "l"))
    assert leak.as_dict()["label"] == "l"


@pytest.mark.parametrize("bad", ["CANARY", "CANARY-12", "canary-1234", "CANARYZZZZ"])
def test_detect_requires_the_exact_token(bad):
    assert detect(f"text {bad}", Canary("CANARY-1234")) is None
