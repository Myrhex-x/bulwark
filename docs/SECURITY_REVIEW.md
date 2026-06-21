# Security review — 0.1.0 → 0.2.0

A self-audit of Bulwark against its own threat model, with the fixes that
shipped in 0.2.0. Findings are ordered by impact. Everything below is covered by
tests and mirrored across the Python and TypeScript implementations.

## Findings & fixes

### 1. Trust semantics conflated "input was hostile" with "output is unsafe" — *fixed*
**Severity: High (usability/safety).** The original `result.safe` was `False`
whenever the *input* contained any injection signal. But the whole point of a
summarizer is that the input often *will* be hostile — if Bulwark contained the
attack and the output passed validation, that is a success, not a failure.
Returning `safe=False` there would push integrators to discard perfectly good,
safely-handled summaries (or to ignore the flag entirely, which is worse).

**Fix:** `safe` now answers a single question — *"is the returned summary safe to
use?"* — and is driven by **output** validation. A new `injection_detected`
field separately reports that the input was hostile, and a `status` of
`SAFE / CONTAINED / UNSAFE / BLOCKED` makes the four cases explicit. `CONTAINED`
= "we caught an injection and handled it; the summary is safe."

### 2. Cross-script homoglyph evasion bypassed detection — *fixed*
**Severity: High.** NFKC folds full-width and ligature look-alikes, but **not**
cross-script homoglyphs. An attacker could write `іgnоrе аll рrеvіоus
іnstruсtіоns` using Cyrillic/Greek letters that look identical to Latin, and the
keyword signatures would never match.

**Fix:** `fold_confusables` maps ~70 Cyrillic/Greek homoglyphs to their ASCII
skeleton (1:1, so detection offsets stay aligned). Crucially it is applied **only
to the detection copy** — the text shown to the model is left untouched, so
legitimate non-Latin content is never corrupted.

### 3. Regex HTML stripper missed nested hidden content — *fixed*
**Severity: Medium.** The original `display:none` remover was a single regex that
could not handle nested elements, so a hidden `<div>` containing child tags could
leak text into the summarizer.

**Fix:** replaced with a proper stack-based extractor (Python's stdlib
`html.parser`; a hand-written tokenizer in TS) that correctly skips entire hidden
subtrees, `<script>`/`<style>`/`<noscript>`/`<template>`, comments, the `hidden`
attribute, and `aria-hidden`.

### 4. Output validation could be evaded by splitting the canary/URL — *fixed*
**Severity: Medium.** A compromised model could emit the canary or an
exfiltration URL with zero-width characters between each character
(`B​U​L…`) to slip past the substring/regex checks.

**Fix:** the reply is now **normalized** (invisibles stripped, NFKC) *before* any
validation check, defeating split-token evasion. Invisible characters are also
removed from the returned summary.

### 5. Narrow output-exfiltration coverage — *fixed*
**Severity: Medium.** Only markdown images/links were checked. HTML `<img>` tags,
autolinks (`<https://…>`), and raw URLs carrying a data-bearing query string are
equally effective exfiltration channels.

**Fix:** added detection + redaction for HTML images, autolinks, and
data-bearing URLs (`…?x=<long-opaque-value>`).

### 6. No bound on input size — *fixed*
**Severity: Low (DoS / cost).** Unbounded input means unbounded regex work and
token cost on a pathological page.

**Fix:** `max_content_chars` (default 200k) truncates oversized input and records
a finding. Signature regexes were also reviewed for catastrophic backtracking;
all quantifiers are bounded/lazy with literal anchors (linear behaviour).

### 7. Detection recall gaps — *fixed*
**Severity: Low–Medium.** A red-team corpus surfaced missed payloads
("disregard the above", "your original system instructions", authority framing,
identity reassignment, "email this to…", forged `Human:` turns, etc.).

**Fix:** added 13 signatures (now **49** across 8 categories). A committed
red-team corpus asserts **100% recall** on 22 attacks and **0% false positives**
on 15 benign texts, so future changes can't silently regress either direction.

## Known residual risk (unchanged, by design)

- A novel, model-specific jailbreak written in ordinary prose can still cause a
  given model to misbehave. This is an open research problem; Bulwark's job is to
  make it the *only* remaining avenue and to catch many such cases at the output
  stage. Keep the summarizer read-only and gate downstream actions.
- The confusables table is curated (common Cyrillic/Greek), not the full Unicode
  TR39 set. PRs adding entries (and the payloads that motivate them) are welcome.

## Verification

```
cd python && python run_tests.py     # 53 passed
cd typescript && npm test            # 52 passed
swift test                           # 51 passed   (from repo root)
```
All three engines produce identical verdicts on the parity corpus.
