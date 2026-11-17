# Contributing

Thanks for helping. This kit exists so that developers can measure a defense instead of
guessing at one, and the fastest way to improve it is more labelled, harmless samples.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check .
```

No API key and no network access are needed at any point. If a contribution requires
either, it does not belong in this repo.

## Adding corpus samples

1. Pick the existing category file in `corpus/attacks/` (or `corpus/benign/` for look-alikes).
2. Add **one JSON object per line**, validated by `corpus/schema.json`.
3. Make the sample inert. Allowed "payload" outcomes only:
   * ask the model to output a canary token such as `CANARY-7F3A`
   * ask the model to ignore a *fake* rule that the harness supplies
   * ask the model to reveal a *fake* system prompt that the harness supplies
4. Use reserved domains only: `example.com`, `example.org`, `example.net`,
   `*.invalid` (including `attacker.example.invalid`), and addresses such as
   `test@example.com`. Never a real URL.
5. No real credentials, tokens, API keys, malware, or product-specific attacks.
6. Benign samples are just as valuable as attacks. If you know a phrase that trips a
   detector but is legitimate content, add it to `corpus/benign/` so false positives
   stay measurable.
7. Run `pytest tests/test_corpus_schema.py tests/test_corpus_safety.py` before opening a PR.

### Labeling rules

* `expected_label` is `attack` or `benign`. It describes the *intent* of the text, not
  what the current detectors happen to do. Never relabel a sample to make a benchmark look better.
* `severity` is the impact if a naive model obeyed the text: `low`, `medium`, `high`, `critical`.
* `notes` says what a correct defense should do, in one sentence.

## Adding or changing a detector

* Deterministic, explainable, offline. No network, no model calls, no randomness.
* Every finding must carry: detector name, category, matched span, severity, a
  human-readable reason, and a suggested action.
* If you change scoring or thresholds, rerun `ifk bench` and include the new numbers in
  the pull request. The numbers in `README.md` must always be reproducible.

## Pull requests

* One topic per PR, tests included.
* `pytest` and `ruff check .` must pass; CI runs both plus corpus validation.
* Do not add dependencies unless they are clearly necessary. The library currently
  depends only on PyYAML.

## Code of conduct

By participating you agree to [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
