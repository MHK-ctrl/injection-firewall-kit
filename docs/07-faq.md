# 7. FAQ

## Is this a prompt-injection "solution"?

No. It is a set of controls that reduce risk and make it measurable. `06-limitations-and-honesty.md`
lists what it does not stop, and that list is longer than the one of things it does stop.
Anyone selling a complete solution to prompt injection is selling a story.

## Why not just tell the model to ignore injected instructions?

Because that is a sentence in the same context as the attack. It helps, and the wrapper
includes it, but it is probabilistic and lives inside the thing being attacked. A model that
always obeys it is a model that can never be talked out of a real instruction either.

## Why not use a classifier or another LLM to detect injections?

You can, and for semantic paraphrases it is the only option. Three reasons this kit stays
deterministic:

1. **Explainability.** A regex finding says which span matched and why. A classifier says
   "0.93", which is not actionable in a review queue.
2. **Offline and reproducible.** The tests and benchmark must run in CI with no key, no
   network, and identical results on every machine.
3. **Latency and cost.** Inline screening of every email with a second model doubles the
   price of the product.

The deterministic layer can be one input to a semantic layer, not a replacement for it.

## Does it work on non-English content?

Partly. The override detector has patterns for 16 languages, including verb-final languages
that need a different word order. It is a vocabulary list, not translation, and it will miss
paraphrases in every language. If your traffic is mostly non-English, treat the benchmark
recall as an upper bound and add samples from your own mail.

## What about images, PDFs and screenshots?

Metadata and alt text are scanned. Pixels are not. A page that renders instructions into an
image is outside this toolkit; the model's vision encoder is a separate attack surface with
no equivalent of this repo.

## My legitimate documents are being flagged. What do I do?

In order of preference:

1. Lower the policy for that carrier: `permissive` for a read-only summariser.
2. Use the action instead of the score. A `warn` that is visible to the user is often fine;
   `quarantine` is not.
3. Allow-list sources you control, and scan only the untrusted ones.
4. Add the false positive to `corpus/benign/` with a note, so the next change is measured
   against it.

Do not delete the rule that caught it without understanding why your content matches. The
rule is usually telling you that your content looks like an attack.

## Does sanitising destroy my documents?

It changes only things that are invisible or structurally dangerous: zero-width characters,
comments, hidden elements, chat tokens, beacon URLs. Every change is recorded, the diff is
printable, and `SanitizeReport.revert()` restores the original byte for byte - the test suite
asserts this for every sample. Typography (curly quotes, em dashes, ellipses) is deliberately
left alone.

## Why does `warn` exist if `block` is safer?

Because a security control that fires on ordinary email gets turned off within a week. `warn`
gives the user context without stopping their work, and it produces the data you need to tune
thresholds. Reserve `block` for the categories where no legitimate content exists.

## Can I use it with streaming responses?

Yes, with a caveat: the output guard needs the whole answer or a buffer. Stream with a small
delay and check the accumulated text before flushing the risky parts, or stream only after the
first sentence passes. A canary can appear at any point, including the last token.

## How much does it cost per request?

The scanner is pure Python regex plus local decoding: sub-millisecond to a few milliseconds
for a typical email, dominated by the size of the input. `ifk bench` over 402 samples takes
about a second on a laptop. There is no network call and no model call anywhere in the
library.

## Does it work with any model provider?

The library does not know about providers at all; it operates on strings. The optional
adapters in `harness/adapters/` show the wiring for OpenAI-compatible APIs, Anthropic
Messages, and local `transformers` models. Copy the pattern into your own client.

## Why a random nonce in the wrapper instead of fixed tags?

Because a fixed tag is guessable. If your wrapper is `<untrusted>...</untrusted>`, the payload
contains `</untrusted>` and the rest of the document looks trusted. A per-document nonce
(`<<<UNTRUSTED_DATA_M6KFBEH6 BEGIN>>>`) cannot be predicted from the content, and the wrapper
escapes any attempt to forge the marker anyway. It also makes each block traceable in logs.

## Is the corpus safe to paste into my own model?

Yes, by construction. The worst outcome is a harmless canary string (`CANARY-7F3A`), a fake
rule being ignored, or a fake system prompt being repeated. There are no real domains, no
credential-shaped strings and no product-specific exploits;
`tests/test_corpus_safety.py` enforces this mechanically on every commit.

## Can I contribute attack samples from a real incident?

Please do not paste real content. Reduce it to an inert skeleton: replace addresses with
`test@example.com`, URLs with `attacker.example.invalid`, and the payload outcome with a
canary. The *shape* of the attack is the useful part; the victim's data is not.
See `CONTRIBUTING.md`.

## Why is `fake_tool_result` the weakest category in the benchmark?

Because a genuine tool output and a fabricated one are often identical by design. The fix is
not a better regex, it is provenance: your application knows which messages it created and
which arrived as data. Mark them, and refuse to treat content as a tool result no matter how
convincing it looks.

## What should I read next?

* `01-what-is-prompt-injection.md` for the mental model.
* `02-threat-model.md` before you change any architecture.
* `04-defense-in-depth.md` for the layer order, which matters more than any single control.
* `06-limitations-and-honesty.md` before you tell anyone you are protected.
