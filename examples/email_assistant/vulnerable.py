"""UNSAFE: an email assistant that pastes the raw email into the model context.

Run it:

    python examples/email_assistant/vulnerable.py

What happens: the email contains a forged SYSTEM turn asking the assistant to forward
mail and echo a canary. The stub model cannot tell data from instructions, so it obeys
and calls the send tool. This is the failure mode the whole kit exists to prevent.
"""

from __future__ import annotations

from harness.simulated_app import DEMO_EMAIL, EmailAssistant


def main() -> int:
    assistant = EmailAssistant(protected=False)
    result = assistant.handle(DEMO_EMAIL)

    print("=== vulnerable email assistant ===")
    print(f"email from:      {DEMO_EMAIL.sender}")
    print(f"subject:         {DEMO_EMAIL.subject}")
    print()
    print(f"allowed:         {result.allowed}")
    print(f"canary leaked:   {result.canary_leaked}")
    print(f"tool calls:      {result.tool_calls}")
    print(f"reply:           {result.reply!r}")
    print()
    print("The model treated the email body as instructions from its operator.")
    print("Nothing in this path stops a forged SYSTEM turn.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
