"""Optional adapter: OpenAI-compatible chat completions (OpenAI, Azure, vLLM, Ollama, ...).

**Optional.** Nothing in the test suite, the examples or the benchmark imports this file.
It is here so you can see the firewall wired into a real client instead of copying the
pattern out of a blog post.

Install the SDK yourself and provide the key through the environment:

    pip install openai
    export OPENAI_API_KEY=...            # never commit this
    export OPENAI_BASE_URL=...           # optional, for a compatible gateway

The adapter is defensive about the *content*, not about the provider: it scans, sanitises,
wraps, calls the model, and then checks the answer before returning it.
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
    """Create a client, with an explicit error if the optional dependency is missing."""
    try:
        from openai import OpenAI  # imported lazily on purpose
    except ImportError as exc:  # pragma: no cover - depends on the user's environment
        raise RuntimeError(
            "The openai SDK is not installed. Run `pip install openai`, or use the offline "
            "stub in harness/simulated_app.py."
        ) from exc
    return OpenAI()  # reads OPENAI_API_KEY / OPENAI_BASE_URL from the environment


def guarded_completion(
    content: str,
    source: str,
    *,
    question: str = "Summarise this content.",
    policy: str = "balanced",
    model: str = "gpt-4o-mini",
    client=None,
    approver: dict | None = None,
) -> dict:
    """Scan -> sanitize -> wrap -> complete -> guard, and report every step.

    Returns a dict with ``answer``, ``decision``, ``risk_score``, ``changes`` and
    ``violations`` so the caller can log why something was blocked.
    """
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

    system = f"{DEFAULT_SYSTEM}\n\n{system_note()}\n{canary_instruction(canary)}"
    response = (client or build_client()).chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": f"{wrapped.text}\n\nQuestion: {question}"},
        ],
    )
    answer = response.choices[0].message.content or ""

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
