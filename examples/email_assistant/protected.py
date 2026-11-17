"""PROTECTED: the same assistant with the firewall, sanitizer, wrapper and tool gate.

Run it:

    python examples/email_assistant/protected.py

The email is scanned before it reaches the model. Under the `strict` policy it is held
(block), never summarised, and the send tool is never reached. A normal email passes
through, is sanitised, wrapped in a nonce-delimited untrusted-data block, and summarised.
"""

from __future__ import annotations

from firewall.canary import new_canary
from firewall.sanitizers import apply_sanitizers
from firewall.scanner import Scanner
from firewall.wrapper import wrap_untrusted
from harness.simulated_app import DEMO_EMAIL, Email, EmailAssistant

NORMAL_EMAIL = Email(
    sender="ana@example.com",
    subject="Invoice 43",
    body="Hi Sam,\n\nInvoice 43 is attached and due on the 30th.\n\nThanks,\nAna",
    id="normal-001",
)


def show(title: str, result) -> None:
    print(f"--- {title} ---")
    print(f"allowed:       {result.allowed}")
    print(f"decision:      {result.decision}  (score {result.risk_score}/100)")
    print(f"canary leaked: {result.canary_leaked}")
    print(f"tool calls:    {result.tool_calls}")
    print(f"reply:         {result.reply[:120]!r}")
    for note in result.notes:
        print(f"  note: {note}")
    print()


def main() -> int:
    assistant = EmailAssistant(protected=True)  # no approver: irreversible calls fail closed

    print("=== protected email assistant ===")
    show("injected email", assistant.handle(DEMO_EMAIL))
    show("normal email", assistant.handle(NORMAL_EMAIL))

    print("--- the pieces, one at a time ---")

    scan = Scanner().scan(DEMO_EMAIL.body, carrier="email_body")
    print(f"1. scan:      risk {scan.risk_score}/100, categories {scan.categories}")
    for finding in scan.top_findings(3):
        print(f"   - {finding.severity:<8} {finding.category}: {finding.reason}")

    clean = apply_sanitizers(DEMO_EMAIL.body, "aggressive")
    print(f"2. sanitize:  {clean.describe()}")

    wrapped = wrap_untrusted(clean.sanitized, source=f"email:from={DEMO_EMAIL.sender}")
    print(f"3. wrap:      nonce {wrapped.nonce}, {len(wrapped.text)} characters")

    canary = new_canary("demo")
    print(f"4. canary:    issued {canary.value}; any appearance in output means failure")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
