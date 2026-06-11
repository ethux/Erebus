# Privacy Invariant Matrix

The whole product enforces one invariant:

> **Tokens only on the model side; real values only in real-world sinks.**

That invariant is global but implemented across many modules. This doc is the
single place that states, per channel, where the boundary must intercept text
and which direction each path runs. Keep it in sync when adding a channel — the
executable mirror of this table is `tests/boundary/test_invariant_properties.py`
(P1/P2/P3).

## Directions

- **to-model** (world → model): raw values in, tokens out. Entry: `Boundary.to_model` / `to_model_many`.
- **from-model** (model → world): tokens in, raw values out. Entry: `Boundary.from_model` / `from_model_payload`.
- A **sink** is any place a real value legitimately lands: a file on disk, a shell command, a tool result acted on, the user's screen.

## Channel matrix

| Channel | Direction | Where it's tokenized / resolved | Notes |
|---|---|---|---|
| Chat `messages[].content` (string + blocks) | to-model | `proxy/chat.py:_tokenize_messages` | OpenAI + Anthropic |
| Anthropic top-level `system` (string + blocks) | to-model | `proxy/chat.py:_tokenize_chat_non_message_fields` | **was leaking pre-2026-06-11** |
| `tools[].description` / function schemas | to-model | `chat.py` (chat) + `responses.py` non-input | tool *names* are NOT tokenized (routing) |
| Assistant `tool_calls[].function.arguments` | to-model | `chat.py:_tokenize_messages` | usually model-generated; defense-in-depth |
| Responses `input[]` items | to-model | `proxy/responses.py:_tokenize_responses_input` | per-item message cache |
| Responses `instructions` / non-input | to-model | `responses.py:_tokenize_responses_non_input` | content-hash cached (big, stable) |
| Claude tool results (file reads, cmd output) | to-model | `shim/outgoing.py:_process_tool_result_block` | |
| User-typed prompt text | to-model | `shim/outgoing.py:_process_text_block` | apply-on-change, not on-mint |
| Streaming response deltas | from-model | `proxy/stream.py` | tokens can split across chunks → buffered |
| Non-streaming response body | from-model | `proxy/regular.py`, `core/streaming.py` | |
| Files an AI tool wrote | from-model | `shim/incoming.py:_detokenize_completed_writes` | **only tracked Write/Edit targets** |
| Unknown token recovery | from-model | `Boundary._detokenize` → `KnownValueDB.resolve_missing` (audit log) | FR-018 |

## Caches are part of the privacy model

A cache hit can bypass detection, so every cache path must re-assert the invariant:

- **Message cache** (`core/message_cache.py`): on a hit, `apply_message_cache_entry`
  re-runs the known-value pre-scan over **every** text field of the applied item
  (`retokenize_item`), not just patched fields — a zero-patch entry (detector
  missed the value at store time) would otherwise replay it raw forever.
- **Boundary result cache** (`core/boundary.py`): re-runs the pre-scan on every hit.
- **Degraded turns are never cached** (`store_message_cache_entry` skips them) so an
  under-filtered result can't be replayed.

## Streaming is hostile to local reasoning

Correctness depends on accumulated buffers + emitted-length accounting, not the
current chunk. A token split across deltas (`[PERSON_` + `1_abc123]`) is only
resolvable once buffered. The bug surface is "what has already been emitted."

## Escapes & allowances (to-model opt-outs)

`~`-escaped values and `allowed_names` must be honored **before** the pre-scan
(else a known value can't be escaped). Parsed in `Boundary._pre_detector`;
active allowances are read from the KV DB so they survive across a turn.

## Glossary

- **token** — a `[LABEL_n_hex]` placeholder that stands in for a real value on the model side.
- **known value** — a value the KV DB has already minted a token for; retokenized deterministically by the pre-scan, detector-independent.
- **mirror** (`TOKEN_MAP`) — the legacy in-memory/JSON compat copy of token↔value, kept in sync around boundary calls; slated for removal.
- **transient** — a token kept in memory only (degraded DB, or a degenerate <2-char value) — resolvable but never persisted.
- **resolved** — a token that `from_model` mapped back to its value.
- **recovered** — a token resolved via the audit log because the KV view didn't have it (FR-018).
- **retokenized** — an already-known value swapped back to its existing token by the pre-scan (no new mint).
- **detokenized** — model→world replacement of a token with its value.
- **escaped** — a value the user opted out of tokenizing for this turn (`~`); grants a time-boxed allowance.
- **allowance** — a time-boxed DB record that exempts a value from tokenization.
- **sink** — a real-world destination where a real value legitimately lands (file, shell, screen).
