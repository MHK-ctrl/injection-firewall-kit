"""Optional adapter: Anthropic Messages API.

**Optional.** Not imported by the library or the tests. Install the SDK and provide the
key through the environment:

    pip install anthropic
    export ANTHROPIC_API_KEY=...

Note the structural difference from the OpenAI adapter: Anthropic takes a top-level
``system`` parameter, which is exactly where the "data is not instructions" note belongs -
and exactly where an attacker would love to write. Keep it out of reach of content.
"""

from __future__ import annotations

from typing import Optional

from firewall.canary import CanaryLedger, canary_instruction
from firewall.output_guard import OutputGuard
from firewall.policy import decide, load_policy
from firewall.sanitizers import apply_sanitizers
from firewall.scanner import Scanner
from firewall.wrapper import system_note, wrap_untrusted

DEFAULT_SYSTEM = "You answer questions about the documents you are given."


def build_client():
    try:
        from anthropic import Anthropic  # imported lazily on purpose
    except ImportError as exc:  # pragma: no cover - depends on the user's environment
        raise RuntimeError(
            "The anthropic SDK is not installed. Run `pip install anthropic`, or use the "
            "offline stub in harness/simulated_app.py."
        ) from exc
    return Anthropic()


def guarded_completion(
    content: str,
    source: str,
    *,
    question: str = "Summarise this content.",
    policy: str = "balanced",
    model: str = "claude-sonnet-4-5",
    max_tokens: int = 1024,
    client=None,
) -> dict:
    resolved = load_policy(policy)
    scan = Scanner().scan(content, policy=resolved)
    decision = decide(scan, resolved)
    if decision.action in ("block", "quarantine"):
        return {
            "answer": None,
            "decision": decision.action,
            "risk_score": scan.risk_score,
            "reasons": decision.reasons,
            "changes": [],
            "violations": [],
        }

    report = apply_sanitizers(content, resolved["sanitize"]["profile"])
    ledger = CanaryLedger()
    canary = ledger.issue("session")
    wrapped = wrap_untrusted(report.sanitized, source=source)

    response = (client or build_client()).messages.create(
        model=model,
        max_tokens=max_tokens,
        system=f"{DEFAULT_SYSTEM}\n\n{system_note()}\n{canary_instruction(canary)}",
        messages=[
            {"role": "user", "content": f"{wrapped.text}\n\nQuestion: {question}"},
        ],
    )
    answer = "".join(
        block.text for block in response.content if getattr(block, "type", "") == "text"
    )

    verdict = OutputGuard(canaries=ledger.canaries).check(answer)
    return {
        "answer": answer if verdict.ok else None,
        "decision": verdict.action if not verdict.ok else decision.action,
        "risk_score": scan.risk_score,
        "reasons": decision.reasons,
        "changes": report.summary(),
        "violations": [v.as_dict() for v in verdict.violations],
    }


if __name__ == "__main__":  # pragma: no cover - requires credentials
    print("This adapter is optional and needs a real API key. Try harness/simulated_app.py.")
