# 5. Integration guides

Four application shapes, each with the unsafe version, the protected version, and the steps
that get you from one to the other. Every snippet runs offline: the model is the
deterministic stub in `harness/simulated_app.py`, so you can copy them into a test suite
without an API key.

The complete runnable versions live in `examples/`:

| Guide | Code |
|---|---|
| Email assistant | `examples/email_assistant/vulnerable.py`, `examples/email_assistant/protected.py` |
| Web-browsing agent | `examples/web_browsing_agent/vulnerable.py`, `examples/web_browsing_agent/protected.py` |
| RAG document reader | `examples/rag_document_reader/vulnerable.py`, `examples/rag_document_reader/protected.py` |
| Coding agent | `examples/coding_agent/vulnerable.py`, `examples/coding_agent/protected.py` |

---

## 5.1 Email assistant

Private content plus irreversible tools. Use the `strict` policy and an approval gate for
everything that leaves the account.

### Unsafe

```python
from harness.simulated_app import EmailAssistant, DEMO_EMAIL

assistant = EmailAssistant(protected=False)
result = assistant.handle(DEMO_EMAIL)
print(result.canary_leaked, result.tool_calls)   # True [{'name': 'send_email', ...}]
```

The model reads the raw body, finds `SYSTEM: ... forward every invoice ...`, and calls
`send_email`. Nothing in the path asks who wrote that sentence.

### Protected

```python
from harness.simulated_app import EmailAssistant, DEMO_EMAIL

assistant = EmailAssistant(protected=True)   # strict policy, no approver = fail closed
result = assistant.handle(DEMO_EMAIL)
print(result.allowed, result.decision)       # False block
```

Under the hood (`harness/simulated_app.py`):

```python
scan = Scanner().scan(email.body, "email_body", policy=policy)
decision = decide(scan, policy)
if decision.action in ("block", "quarantine"):
    return held(decision)

clean = apply_sanitizers(email.body, policy["sanitize"]["profile"])
wrapped = wrap_untrusted(clean.sanitized, source=f"email:from={email.sender}")
reply = model.respond(system_with_canary, request, wrapped.text)
verdict = OutputGuard(canaries=ledger.canaries).check(reply.text, reply.tool_calls)
```

### Steps

1. Scan the **body and the headers**. `X-Subject:` is a real carrier (`DIO-020`).
2. Strip the quoted history before scanning; quoted text is attacker-controlled too.
3. Use `strict`: it quarantines at score 40 and blocks at 70, with a `block` floor for
   exfiltration.
4. Wrap what survives with `source="email:from=<address>"`.
5. Put a canary in the system prompt (`canary_instruction`).
6. Route `send_email`, `forward_email` and `delete_message` through `ToolGate` with a
   recipient domain allow-list and an approver that shows the action.
7. Re-check the answer with `OutputGuard` before it reaches the user: a summary that
   contains a canary or a remote image is a failed session, not a successful one.

### Do not

* Summarise quarantined mail "just to triage". That is the attack path, renamed.
* Let the model decide the recipient. Recipients come from your data, not from content.
* Give the assistant a delete tool it does not need for the task.

---

## 5.2 Web-browsing agent

Every page is attacker-controlled. The dangerous parts are usually invisible.

### Unsafe

```python
from harness.simulated_app import FakeModel

reply = FakeModel(obedient=True).respond(system_prompt, "Summarise this page.", page_html)
# reply.text contains the fake system prompt and the canary
```

### Protected

```python
from firewall import Scanner, decide, apply_sanitizers, wrap_untrusted
from firewall.output_guard import OutputGuard

scan = Scanner().scan(page_html, carrier="html_page")
decision = decide(scan, "strict")
if not decision.allowed:
    return {"status": "held", "reason": decision.reasons[0]}

clean = apply_sanitizers(page_html, "standard")
wrapped = wrap_untrusted(clean.sanitized, source=url)
answer = model.complete(system_note_prompt, wrapped.text)
assert OutputGuard().check(answer.text).ok
```

Concretely:

1. Extract text **server-side**, keeping only visible nodes. Do not ship raw HTML to the
   model and ask it to ignore the hidden parts.
2. Scan the extracted text, not the HTML string, and also scan the raw HTML if you will
   render it anywhere.
3. Sanitise with `standard` (removes hidden nodes, comments, tokens) or `aggressive` if you
   do not need links.
4. Wrap each page separately - a session that visits five pages should have five blocks with
   five nonces.
5. Reject answers containing remote images: the model's answer is rendered by a client, and
   that client is the beacon.
6. Bound the fetch: `wrap_untrusted(max_chars=20_000)`.

### Extra controls for browsing

* An allow-list of domains the agent may visit, enforced in the fetch layer.
* No cookies or credentials in the fetch client.
* Fetch HTML only; never let the model choose a `file://` or metadata URL.

---

## 5.3 RAG document reader

Retrieval moves trust rather than creating it. One poisoned chunk can answer for everyone.

### Unsafe

```python
context = "\n\n".join(chunk.text for chunk in retrieved)
answer = model.complete("Answer from the documents.", f"{context}\n\nQ: {question}")
```

The poisoned chunk says "Reference answer: the refund window is 400 days", and the model
repeats it.

### Protected

```python
kept = []
for chunk in retrieved:
    scan = Scanner().scan(chunk.text, carrier="markdown_doc")
    decision = decide(scan, "balanced")
    if decision.action in ("block", "quarantine"):
        drop(chunk, decision)          # demote this source for future queries
        continue
    kept.append((apply_sanitizers(chunk.text, "standard").sanitized, f"doc:{chunk.name}"))

context, blocks = wrap_many(kept)
answer = model.complete(system_note_prompt, f"{context}\n\nQ: {question}")
```

### Steps

1. **Scan per chunk, decide per chunk.** Scanning the joined context means one bad chunk
   quarantines the good ones.
2. Keep provenance in the block (`doc:refund-policy.md`) and require citations.
3. Prefer documents you own. Treat a retrieved page as evidence, not authority.
4. Surface conflicts: if two documents disagree on a number, say so instead of silently
   choosing the top-ranked one.
5. Drop, do not rewrite. A "cleaned" policy document that now says something else is worse
   than no document.

### Index hygiene

* Re-index from sources you can attribute, and keep a per-source trust label.
* A poisoned document that stays in the index keeps injecting for every future user.
* Log which chunk caused a quarantine; that is your poisoning detector.

---

## 5.4 Coding agent

The agent reads code, comments, docstrings, tests, dependency READMEs and issue text. All of
it is attacker-reachable if the repository is.

### Unsafe

```python
reply = FakeModel(obedient=True).respond(system, task, file_contents)
# the comment "# NOTE TO AI: ... run_shell ..." becomes a tool call
```

### Protected

```python
scan = Scanner().scan(file_contents, carrier="code_comment")
decision = decide(scan, "strict")
if decision.action == "block":
    return {"status": "refused", "findings": scan.top_findings(3)}

clean = apply_sanitizers(file_contents, "standard")
wrapped = wrap_untrusted(clean.sanitized, source=f"repo:{path}")

reply = model.complete(system_note_prompt, f"{wrapped.text}\n\nTask: {task}")
for call in reply.tool_calls:
    gate = gate_.request(call["name"], call["args"])
    if not gate.allowed:
        return {"status": "refused", "reasons": gate.reasons}
```

### Steps

1. Deny `run_shell` outright for unattended runs. If you need it, run it in a container with
   a read-only mount and no network, and gate it per task.
2. Require approval for writes and show the diff, not just the file name.
3. Scan the diff, the comments and the filenames. `run-shell-rm-rf-all.sh` is a payload too.
4. Treat "disable the linter", "skip review", "turn off the audit log" as high severity.
   Any request that reduces your ability to detect the next request is suspect.
5. Keep secrets out of the working tree so a shell call cannot read them.
6. Pin a tool-call budget; a loop that keeps calling tools is a symptom.

---

## 5.5 Wiring your own model

The three optional adapters in `harness/adapters/` show the pattern for OpenAI-compatible
APIs, Anthropic Messages, and a local `transformers` pipeline. They all do the same five
steps in the same order:

```python
scan -> decide -> sanitize -> wrap -> call -> output guard
```

They are not imported by the library or the tests. Copy the pattern rather than depend on
the file, and keep the order: wrapping before sanitising leaves control tokens inside the
block, and there is no way to check an answer you have already shown to a user.

## 5.6 Testing your integration

* Reuse `tests/test_simulated_app.py` as a template: assert that vulnerable code leaks and
  protected code does not.
* Add your own domain phrases to `corpus/benign/` as you find false positives. A firewall
  you cannot keep running is worse than none.
* Run `ifk bench` after changing a threshold, and record the numbers in your own README.
