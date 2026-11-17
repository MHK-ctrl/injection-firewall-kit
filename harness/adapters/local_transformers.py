"""Optional adapter: a local model through `transformers`.

**Optional.** Not imported by the library or the tests. It needs a GPU or patience:

    pip install transformers torch
    python -m harness.adapters.local_transformers      # downloads a small model once

Local models are not safer against injection - they are simply easier to control. What
this file adds is the same wrapping and output check the hosted adapters use.
"""

from __future__ import annotations

from typing import Optional

from firewall.canary import CanaryLedger, canary_instruction
from firewall.output_guard import OutputGuard
from firewall.policy import decide, load_policy
from firewall.sanitizers import apply_sanitizers
from firewall.scanner import Scanner
from firewall.wrapper import system_note, wrap_untrusted

DEFAULT_MODEL = "HuggingFaceTB/SmolLM2-360M-Instruct"


def build_pipeline(model_name: str = DEFAULT_MODEL):
    try:
        from transformers import pipeline  # imported lazily on purpose
    except ImportError as exc:  # pragma: no cover - depends on the user's environment
        raise RuntimeError(
            "transformers/torch are not installed. Run `pip install transformers torch`, or "
            "use the offline stub in harness/simulated_app.py."
        ) from exc
    return pipeline("text-generation", model=model_name, max_new_tokens=256)


def guarded_completion(
    content: str,
    source: str,
    *,
    question: str = "Summarise this content.",
    policy: str = "balanced",
    generator=None,
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

    system = f"Summarise the data you are given.\n\n{system_note()}\n{canary_instruction(canary)}"
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": f"{wrapped.text}\n\nQuestion: {question}"},
    ]
    generator = generator or build_pipeline()
    output: list | None = generator(messages)
    answer = (output[0]["generated_text"][-1].get("content", "") if output else "")

    verdict = OutputGuard(canaries=ledger.canaries).check(answer)
    return {
        "answer": answer if verdict.ok else None,
        "decision": verdict.action if not verdict.ok else decision.action,
        "risk_score": scan.risk_score,
        "reasons": decision.reasons,
        "changes": report.summary(),
        "violations": [v.as_dict() for v in verdict.violations],
    }


if __name__ == "__main__":  # pragma: no cover - downloads a model
    print("This adapter is optional and downloads a model. Try harness/simulated_app.py.")
