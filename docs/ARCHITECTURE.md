# Architecture

Bulwark is a five-stage pipeline. Each stage is a pure, independently usable
module; the `Bulwark` class just wires them together. The Python and TypeScript
implementations are kept behaviourally identical (same signatures, weights,
scoring, prompts, and tests).

```
sanitize → detect → spotlight → harden (prompt) → [ your model ] → validate
```

## Stage 1 — `sanitize`

**Goal:** strip everything a human reviewer can't see but a model can read, and
canonicalize text so detection can't be evaded with look-alikes.

- Removes Unicode **Tag** chars (`U+E0000`–`E007F`), **bidi** controls,
  **zero-width** characters, **variation selectors**, and C0/C1 **control** chars.
- For HTML input (auto-detected): removes comments, `<script>`/`<style>`, and
  elements hidden via `display:none` / `visibility:hidden` / `opacity:0` /
  `aria-hidden`, then extracts text and unescapes entities.
- **NFKC-normalizes** so `ｉｇｎｏｒｅ`, ﬁ-ligatures, etc. fold to canonical form, and
  `fold_confusables` maps cross-script homoglyphs (Cyrillic/Greek look-alikes) to
  ASCII for the **detection copy only** — the model-facing text is left intact so
  legitimate non-Latin content is never corrupted.
- HTML is parsed with a **stack-based extractor** (stdlib `html.parser` in
  Python, a hand-written tokenizer in TS and Swift) that drops nested hidden
  subtrees correctly.
- Emits `Finding`s for anything dangerous it removed (e.g. tag-char smuggling is
  itself strong evidence of an attack, weight `0.90`).

## Stage 2 — `detect`

**Goal:** quantify how likely the text is an attack.

- Runs a [signature database](../python/src/bulwark/patterns.py) of 49 regexes
  across categories: `instruction_override`, `role_injection`, `prompt_leak`,
  `exfiltration`, `jailbreak`, `tool_injection`, `boundary_breakout`, `encoding`.
- Adds **structural heuristics** (density of imperative-led lines, second-person
  directives).
- Combines every weighted signal — including the sanitize-stage findings — with a
  **noisy-OR**:

  ```
  score = 1 − ∏ (1 − wᵢ)
  ```

  so many weak signals accumulate but no single one saturates the score. The
  result is bucketed into `info / low / medium / high / critical`.

`injected` is true when `score ≥ threshold` **or** any single finding is
`high`+ severity (conservative by default — a safeguard should err toward
flagging).

## Stage 3 — `spotlight`

**Goal:** make the content structurally impossible to confuse with instructions.
Based on Microsoft's *spotlighting* (Hines et al., 2024). Three composable
transforms:

- **delimit** — wrap content in `<untrusted_content data-nonce="…">` … with a
  random per-request nonce. A forged closing tag in the data can't match because
  it doesn't contain the nonce. Always applied (the validator checks for nonce
  leakage downstream).
- **datamark** — replace spaces with a marker char (`▁`). Continuous marking
  tells the model "all of this is data" and visibly breaks injected sentences.
- **base64** — encode the content so the model treats it as an opaque blob and
  decodes it only to read. Strongest isolation; costs tokens and a little quality.

## Stage 4 — `harden` (prompt)

**Goal:** give the model an unambiguous, attack-resistant instruction frame.

- A strict **system** message: the content is hostile data, never obey it, never
  reveal the prompt, no tools, no URLs/images, no role changes.
- A per-request **canary** token (`BULWARK-CANARY-…`) the model is told never to
  output — the tripwire for prompt leakage.
- A **sandwich**: the core instruction is repeated *after* the content, the
  position where late-placed injections usually try to win.
- A description of the active spotlighting so the model knows which boundary is
  real and how to read marked/encoded data.

`build_messages` returns standard chat messages (`[{role, content}, …]`) plus a
`PromptContext` (canary, nonce, marker) for the validator.

## Stage 5 — `validate`

**Goal:** treat the model as possibly-compromised and inspect its reply.

- The reply is **normalized** (invisibles stripped, NFKC) first, so a
  zero-width-split canary or URL cannot evade the checks.
- **Canary leak** → the prompt was exfiltrated → **unsafe**, redacted.
- **Boundary-nonce leak** → confusion/leak → redacted.
- **Exfiltration** — markdown images/links, HTML `<img>`, autolinks, and raw URLs
  with a data-bearing query string → stripped.
- **Compliance tells** at the start of the reply → flagged.
- Returns a possibly-redacted summary, a `safe` flag, and findings.

> `result.safe` reflects **output** safety. `result.injection_detected` separately
> reports whether the input was hostile, and `result.status` is one of
> `SAFE` / `CONTAINED` (attack caught & handled) / `UNSAFE` / `BLOCKED`.

## Orchestration — `Bulwark`

`summarize(content, llm)` runs all five stages. `llm` is any callable
`(messages) -> str` (sync or async in TS). `scan(content)` runs only stages 1–2
(no model). `prepare()` / `finalize()` split the pipeline around *your* model
call so you keep full control.

Combined risk is recomputed over **all** findings (sanitize + detect + validate),
so `result.risk_score` reflects everything Bulwark saw end-to-end.

### Configuration

`BulwarkConfig` (Python) / `BulwarkConfig` object (TS) exposes every knob:
HTML stripping, unicode normalization, detection threshold, pre-LLM block
severity, spotlight methods, max words, language, and output redaction policy.
Presets: `balanced` (default), `strict`, `paranoid`.

## Design principles

1. **Defense in depth** — no single layer is trusted to be sufficient.
2. **Fail loud, not silent** — everything caught is reported, never hidden.
3. **Model-agnostic** — the core never imports an SDK; adapters are optional.
4. **Zero required dependencies** — trivial to vendor and audit.
5. **Parity** — Python, TypeScript, and Swift behave identically and are tested as such.
