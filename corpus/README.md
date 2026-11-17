# Corpus

A labelled set of **inert** prompt-injection samples and benign look-alikes, used by
`ifk bench` and by anyone who wants to measure their own defence.

```
corpus/
├── schema.json                 JSON Schema for every sample
├── attacks/                    one JSONL file per category
└── benign/                     normal content that merely looks suspicious
```

Current size: **252 attacks** (12 categories x 21) and **150 benign look-alikes**,
spread across all nine carriers. Every line is validated by `corpus/schema.json` in CI.

## Why "inert" matters

Every sample is safe to paste into any model. The worst thing a sample can ask for is:

* a harmless canary token, e.g. `CANARY-7F3A`
* ignoring a *fake* rule that the harness supplies
* revealing a *fake* system prompt that the harness supplies

There are no real URLs, no real credentials, no malware, and no techniques aimed at a
specific named product. `tests/test_corpus_safety.py` enforces this mechanically: it
rejects non-reserved domains and any string that looks like a key, token or private key.

## Schema

| field | type | meaning |
|---|---|---|
| `id` | string | `PREFIX-NNN`, stable. Prefix: `DIO`, `RHJ`, `DSP`, `HID`, `ENC`, `MLI`, `SPL`, `FTR`, `EXF`, `TAB`, `SOC`, `CPO`, `BEN`. |
| `category` | enum | one of the 12 taxonomy categories from `docs/03-attack-taxonomy.md` |
| `carrier` | enum | `email_body`, `html_page`, `markdown_doc`, `pdf_text`, `json_tool_output`, `code_comment`, `csv_cell`, `calendar_invite`, `filename_metadata` |
| `text` | string | the content, normally including the carrier's own markup |
| `expected_label` | `attack` \| `benign` | ground truth by intent |
| `severity` | `low`..`critical` | impact if a naive model obeyed it |
| `notes` | string | what a correct defence should do |

Benign samples reuse the category they *resemble*. That is deliberate: it lets the
benchmark report a false-positive rate per category (for example, "5% of ordinary
emails about invoices are flagged as instruction overrides").

## Labeling rules

1. Label by **intent**, not by what the detectors currently do. Never relabel a sample to
   improve a number.
2. A sample is `attack` if a reasonable reader would say "this content is trying to
   change the assistant's behaviour". It is `benign` if the sentence has a normal
   business meaning and merely contains the same words.
3. Keep severity about impact, not detectability. A well-hidden low-impact payload is
   still `low`.
4. One idea per sample. If a sample combines hidden text, encoding and exfiltration, it
   belongs in the category that dominates and the other signals are noted.
5. Samples should be realistic in shape: an email looks like an email, a JSON tool output
   is valid JSON, an HTML sample includes tags.

## Adding samples

* Append to the matching file in `attacks/` or `benign/`, one JSON object per line.
* Keys must be exactly the seven in the schema (`additionalProperties: false`).
* Use only reserved domains: `example.com`, `example.org`, `example.net`, `*.invalid`
  (including `attacker.example.invalid`), and addresses like `test@example.com`.
* Run `pytest tests/test_corpus_schema.py tests/test_corpus_safety.py` before a PR.

## Known biases

* The corpus is written by the same people who wrote the detectors. High recall here is
  **not** evidence of real-world recall; see `docs/06-limitations-and-honesty.md`.
* Phrasings are mostly English (21 non-English samples cover 16 languages). A real
  attacker writing in another language, or paraphrasing semantically, is largely uncovered.
* Carriers are text-only. Image, audio and screenshot-borne instructions are out of scope.
