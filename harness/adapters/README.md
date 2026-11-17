# Optional model adapters

These files show how to wire the firewall to a real model client. They are **optional**:
the library, the tests, the examples and the benchmark never import them, and nothing here
runs without credentials or a downloaded model.

| File | Provider | Requires |
|---|---|---|
| `openai_compatible.py` | OpenAI, Azure OpenAI, vLLM, Ollama, most gateways | `pip install openai` + `OPENAI_API_KEY` |
| `anthropic_messages.py` | Anthropic Messages API | `pip install anthropic` + `ANTHROPIC_API_KEY` |
| `local_transformers.py` | any causal LM through `transformers` | `pip install transformers torch` |

Each adapter exposes `guarded_completion(content, source, question=..., policy=...)` and
returns a dict:

```python
{
    "answer": str | None,      # None when the content or the answer was rejected
    "decision": "allow" | "warn" | "sanitize" | "quarantine" | "block",
    "risk_score": 0..100,
    "reasons": [...],          # why the policy decided that
    "changes": {...},          # sanitizer steps that fired
    "violations": [...],       # output-guard findings
}
```

The order is always screen inbound -> sanitize -> wrap -> call -> guard outbound. Do not
reorder it: wrapping before sanitising leaves control tokens inside the block, and checking
the answer before calling the model is not possible.

## What these adapters deliberately do not do

* They do not retry around a block. A block is a decision, not a transient error.
* They do not summarise the content "just to see" after a quarantine.
* They do not put the API key, the user's secrets or the full tool list in the context.

If you need those behaviours, add them in your own application with an explicit human
review step, not inside a library call.
