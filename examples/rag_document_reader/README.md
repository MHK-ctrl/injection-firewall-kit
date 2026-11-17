# Example: RAG document reader

A retrieval-augmented reader that answers questions from a document set. Here the
injection arrives through a *retrieved* document - the user never typed it.

## Run it

```bash
python examples/rag_document_reader/vulnerable.py
python examples/rag_document_reader/protected.py
```

## What you should see

The vulnerable reader answers "400 days" and can echo the canary, because one chunk in the
context says so. The protected reader scores each chunk, drops the poisoned one, and
answers "30 days" from the real policy.

## Why scanning per chunk matters

If you join three documents and scan the result, a single `critical` finding quarantines
the whole context and the user gets nothing. Scanning per chunk keeps the useful two and
drops the bad one, and it tells you *which* source is hostile - a signal your retrieval
layer can use to demote that document for future queries.

## The three plausible defences, and why we still need all of them

| Defence | Stops | Does not stop |
|---|---|---|
| Per-chunk scanning | obvious poisoned text | a subtle paraphrase that changes a number |
| Trusted/untrusted wrapping | the model mistaking data for policy | a model that ignores the wrapper |
| Answer grounding ("quote your source") | invented claims | a source that is itself poisoned |

That last row is the uncomfortable one: retrieval does not create trust, it moves it.
Prefer documents you control, and treat the rest as evidence, not authority.

## Production notes

* Keep provenance in the wrapper (`doc:refund-policy.md`) so the answer can cite it.
* Add a "conflict check": if two documents disagree on a number, surface both rather than
  silently picking the top-ranked one.
* Re-index only from sources you can attribute. A poisoned document that stays in the
  index keeps injecting.
