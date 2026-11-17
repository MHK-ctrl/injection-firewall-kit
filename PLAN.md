# PLAN

Build order for `injection-firewall-kit`. Everything in this repo is defensive: the
corpus contains inert strings whose only "attack" outcome is a harmless canary token,
a fake rule, or a fake system prompt that the harness itself supplies.

## 1. Repo skeleton and packaging
1. `PLAN.md` (this file)
2. `.gitignore`
3. `LICENSE` (MIT)
4. `pyproject.toml` (package metadata, `ifk` console script, ruff + pytest config)
5. `.github/workflows/ci.yml` (ruff, pytest, corpus schema validation, benchmark smoke run)

## 2. Core library (deterministic, offline, no network imports)
6. `firewall/types.py` - `Finding`, `ScanResult`, `Decision`, severity weights, taxonomy constants
7. `firewall/detectors/base.py` - shared regex rule engine, span/dedupe helpers, quoted-speech downgrade
8. `firewall/detectors/instruction_override.py` - direct override, multilingual, context poisoning
9. `firewall/detectors/role_hijack.py` - fake system/developer/assistant turns, fake tool results
10. `firewall/detectors/delimiter_spoof.py` - chat-template tokens, fake wrapper/tag closes
11. `firewall/detectors/hidden_text.py` - zero-width/bidi-adjacent invisibles, CSS hiding, HTML comments, metadata
12. `firewall/detectors/encoding_tricks.py` - base64/hex/rot13, homoglyphs, bidi, leetspeak, split words
13. `firewall/detectors/exfil_patterns.py` - remote links, image beacons, prompt/secret extraction
14. `firewall/detectors/tool_abuse.py` - tool invocation, code execution, destructive actions
15. `firewall/detectors/urgency_authority.py` - urgency, authority claims, secrecy demands
16. `firewall/detectors/__init__.py` - registry
17. `firewall/scanner.py` - run detectors, noisy-or risk score, explanations
18. `firewall/sanitizers.py` - invisible removal, unicode normalization, token neutralization, hidden HTML/CSS, beacon defanging; reversible change log + unified diff
19. `firewall/wrapper.py` - randomized delimiter wrapping, provenance labels, data-not-instructions framing
20. `firewall/policy.py` - YAML policy loading, allow/warn/sanitize/quarantine/block decisioning, three presets
21. `firewall/canary.py` - canary generation, prompt baiting, output leak detection
22. `firewall/output_guard.py` - output/tool-call checks (canary, domains, beacons, secrets, unexpected tools)
23. `firewall/tool_gate.py` - least-privilege allow-list, argument validation, human approval hook
24. `firewall/cli.py` - `ifk scan`, `ifk sanitize`, `ifk bench`
25. `firewall/__init__.py` - public API
26. `policies/strict.yaml`, `policies/balanced.yaml`, `policies/permissive.yaml`

## 3. Corpus (12 categories x 21 samples = 252 attacks, 150 benign look-alikes)
27. `corpus/schema.json`
28. `corpus/README.md` (schema, labeling rules, safety rules, contribution rules)
29. `corpus/attacks/*.jsonl` (one file per category, 9 carriers)
30. `corpus/benign/*.jsonl` (3 files, 150 samples)

## 4. Harness
31. `harness/run_benchmark.py` - corpus loading, metrics per category/carrier, JSON output
32. `harness/report.py` - Markdown + JSON report rendering
33. `harness/simulated_app.py` - offline mock email assistant with a deterministic model stub
34. `harness/adapters/*.py` - optional, lazily imported OpenAI-compatible / Anthropic / local adapters

## 5. Examples, tests, docs
35. `examples/{email_assistant,web_browsing_agent,rag_document_reader,coding_agent}/` (vulnerable + protected + README)
36. `tests/` - detectors, sanitizers, wrapper, policy, canary, output guard, tool gate, corpus schema + safety, links, CLI, simulated app (50 tests target)
37. `docs/01..07`
38. Run `ifk bench`, write results to `docs/benchmark-results.md`
39. `README.md` (written last, real benchmark numbers)

## 6. Quality gates
40. `pytest` green, `ruff check .` clean, corpus schema valid, no real domains/credentials,
    every internal markdown link resolves, benchmark rerun produces the numbers quoted in README.

## 7. Publish
41. Secrets grep, `git init`, commit, `gh repo create --public --push`, topics, verify public + CI.
42. Draft the LinkedIn post with real numbers, wait for explicit approval, then post.
