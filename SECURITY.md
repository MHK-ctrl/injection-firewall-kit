# Security Policy

## What this project is

`injection-firewall-kit` is a **defensive** toolkit. It ships a corpus of inert,
harmless prompt-injection test strings, detectors, sanitizers and a benchmark harness.
It contains no working exploits, no real credentials, no malware and no techniques
targeted at a specific real product or company.

## Reporting a bug

If you find a problem with the **library** — a detector that crashes, a sanitizer that
silently destroys content, a bypass that is specific to our code — please open a public
issue unless it is a security-sensitive bug in the sense below.

Public issue template for detection gaps:

```
Category:            (e.g. hidden_text)
Carrier:             (email_body / html_page / markdown_doc / pdf_text / json_tool_output / code_comment / csv_cell / calendar_invite / filename_metadata)
What I expected:      (e.g. "risk score >= 60 and action=quarantine")
What happened:        (actual score, actual action)
Minimal sample:       (inert only - a canary token, no real data, no real URLs)
```

## Reporting a vulnerability

If you believe you have found a problem that could put users of this library at risk
(for example: a sanitizer that reintroduces hidden content after cleaning, a tool-gate
rule that can be trivially bypassed, or a code path that makes a network request) then
**do not open a public issue**. Instead:

1. Email the maintainers at `security@example.invalid` (placeholder used by this
   template — replace it with a real mailbox before you rely on it).
2. Include a minimal reproduction, the affected version and the impact you believe it has.
3. We will acknowledge within 5 business days and aim to ship a fix or a documented
   mitigation within 30 days.

Please do not include third-party data, real credentials, or live malicious payloads in
a report. A canary token and a fake domain are always enough to demonstrate the problem.

## Scope of this project

This kit **reduces** prompt-injection risk. It does **not** make an application safe.
A clean scan result is not a guarantee. Architectural controls (least privilege, approval
gates for irreversible actions, no secrets in the model context, constrained tool access)
matter more than any detector, and are described in [docs/04-defense-in-depth.md](docs/04-defense-in-depth.md).

Known limits are listed in [docs/06-limitations-and-honesty.md](docs/06-limitations-and-honesty.md).
Reporting something that is already listed there as a limitation is still welcome, but
it is a known gap rather than a vulnerability.

## Responsible use

* Use the corpus against **your own** applications, or applications you are authorised to test.
* Do not use these samples to attack third-party systems or to evade another product's safety controls.
* Every sample is deliberately inert: the "payload" can only produce a harmless canary
  string, ignore a fake rule, or repeat a fake system prompt that the harness supplies.
* Do not add samples that contain real domains, real credentials, real personal data or
  product-specific exploit instructions. `tests/test_corpus_safety.py` enforces this mechanically.
