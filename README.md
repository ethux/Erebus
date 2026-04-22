# Erebus

> **Work in progress** — this is an early beta. Features may break, APIs may change. Contributions and bug reports welcome!

Privacy-first PII filter for AI code editors. Tokenizes sensitive data before it leaves your machine, de-tokenizes responses so you see real values. Works with **Mistral Vibe**, **Cursor**, **Windsurf**, **Codex**, **Claude Code**, and any OpenAI/Anthropic-compatible editor.

**By [ETHUX](https://ethux.net)** | MIT License

## Quick start

```bash
# Install
uv tool install erebus

# Set up for your editor
erebus-setup --editor vibe      # Mistral Vibe
erebus-setup --editor cursor    # Cursor
erebus-setup --editor windsurf  # Windsurf
erebus-setup --editor codex     # OpenAI Codex
erebus-setup --editor all       # all editors + proxy service
```

## What it does

- **Tokenizes PII** in prompts — names, emails, IBANs, phone numbers, addresses, credit cards, SSNs (via [GLiNER](https://github.com/urchade/gliner))
- **Catches secrets** — API keys, tokens, passwords, private keys (regex, zero deps)
- **De-tokenizes responses** — the editor works with tokens, you see real values
- **Guards file reads** — blocks `.env`, credentials, keys using pattern matching + local LLM
- **Scans images** — checks screenshots for sensitive content via Ministral 3B vision
- **Logs everything** — full audit trail in local SQLite
- **Repo-aware** — per-project config via `.erebus/pii-filter.json`
- **GDPR-friendly** — all processing happens locally, nothing leaves your machine unfiltered

## How it works

```
You type a prompt in your editor
        |
  Erebus intercepts (proxy / stdin shim)
        |
  GLiNER NER ---> detect names, emails, IBANs, orgs, ...
  Regex ---------> detect API keys, tokens, passwords, ...
        |
  Replace: john@corp.com --> [EMAIL_ADDRESS_1_a3f2c1]
        |
  Tokenized prompt sent to the AI provider
        |
  AI responds using [EMAIL_ADDRESS_1_a3f2c1]
        |
  Erebus de-tokenizes
        |
You see: john@corp.com in the response
```

### Proxy mode (recommended)

The proxy runs on `http://127.0.0.1:4747` and works with any editor that calls an API endpoint.

```
                    +-------------------+
                    | GLiNER Daemon     |  <-- loads model once (~1.8GB)
                    | (Unix socket)     |      shared across all sessions
                    +-------------------+
                           ^
                           |
  +----------+    +--------+--------+    +---------------+
  | Editor   |--->| Erebus Proxy    |--->| AI Provider   |
  | (Vibe,   |<---| :4747           |<---| API endpoint  |
  | Cursor…) |    +-----------------+    +---------------+
  +----------+    regex + socket call
```

| Editor | Setup |
|--------|-------|
| **Mistral Vibe** | `erebus-setup --editor vibe` |
| **Cursor** | `erebus-setup --editor cursor` |
| **Windsurf** | `erebus-setup --editor windsurf` |
| **OpenAI Codex** | `erebus-setup --editor codex` |

The proxy auto-starts on login (macOS launchd / Linux systemd) and transparently tokenizes PII in all `/v1/chat/completions` and `/messages` requests.

### Binary shim mode (Claude Code)

For Claude Code, the wrapper can also operate as a binary shim that intercepts stdin/stdout:

```bash
erebus-setup    # wraps the claude binary directly
```

## Install

```bash
# Install the package
uv tool install erebus

# Or from source
git clone https://github.com/ethux/erebus.git
cd erebus
uv tool install .

# Install Ollama + model for file guard / image scanning (optional)
brew install ollama
ollama pull ministral-3:3b

# Run setup for your editor(s)
erebus-setup --editor vibe
```

## Models

| Model | Purpose | Size | Source |
|-------|---------|------|--------|
| **[GLiNER multi-PII v1](https://huggingface.co/urchade/gliner_multi_pii-v1)** | NER-based PII detection (names, emails, IBANs, orgs, phones, addresses, credit cards, SSNs, etc.) | ~1.8 GB | HuggingFace |
| **[Ministral 3B](https://ollama.com/library/ministral-3)** | File guard decisions + image scanning for sensitive content (via Ollama) | ~2 GB | Ollama |

GLiNER runs as a persistent daemon (Unix socket) — loaded once, shared across all sessions. Ministral 3B is optional and only invoked for contextual file access checks and screenshot scanning.

## Filter modes

Erebus supports three filter modes that control how aggressively PII is tokenized:

| Mode | Names | Organizations | Secrets & structured PII |
|------|-------|---------------|--------------------------|
| **strict** | Full name tokenized | All orgs tokenized | Always tokenized |
| **balanced** (default) | First name kept, last name tokenized | Single-word orgs kept, multi-word tokenized | Always tokenized |
| **relaxed** | Names kept | Orgs kept | Always tokenized |

Set the mode in `.erebus/pii-filter.json`:

```json
{
  "mode": "balanced"
}
```

**Examples** (balanced mode):

| Input | Output |
|-------|--------|
| `Ask John Smith about it` | `Ask John [PERSON_1_a3f2c1] about it` |
| `Send to Google` | `Send to Google` (single-word org — kept) |
| `Contract with Acme Corp` | `Contract with [ORGANIZATION_1_b4d2e1]` (multi-word org — tokenized) |
| `password: Secret123!` | `[PASSWORD_1_c5e3f1]` (always tokenized) |

Secrets (API keys, tokens, passwords, IBANs, emails, etc.) are **always tokenized** regardless of mode.

## Per-repo config

Add `.erebus/pii-filter.json` to any repo:

```json
{
  "sensitive_entities": ["Acme BV", "Project Phoenix"],
  "allowed_names": ["GitHub", "VSCode", "Anthropic"],
  "context": "Financial services client — revenue data is sensitive",
  "block_file_patterns": [
    "**/.env*",
    "**/contracts/**",
    "**/partner-data/**"
  ],
  "mode": "balanced",
  "log_enabled": true
}
```

- `sensitive_entities` — exact strings to always tokenize
- `allowed_names` — values to never tokenize (public names, tools, services)
- `block_file_patterns` — files the editor is never allowed to read
- `context` — description of the project for the file guard LLM
- `mode` — filter aggressiveness: `strict`, `balanced` (default), or `relaxed`

## Hard blacklist

For terms that must **never** reach the AI — regardless of filter mode, NER confidence, or whether GLiNER even runs — Erebus supports a plaintext blacklist. It's the GDPR-safe layer: matches are always tokenized, and the blacklist files themselves are auto-added to `block_file_patterns` so the AI can never read them back.

Two scopes:

| File | Scope |
|------|-------|
| `~/.erebus/blacklist.txt` | Global — applies to every project |
| `<repo>/.erebus/blacklist.txt` | Per-repo — scoped to one project |

One term per line, `#` comments and blank lines ignored, matches are case-insensitive and word-bounded.

```bash
erebus-blacklist add "Jan Jansen"          # global
erebus-blacklist add "Acme BV" --repo      # current repo only
erebus-blacklist list                      # global + repo
erebus-blacklist remove "Jan Jansen"
erebus-blacklist path                      # show the file paths
```

Tokens generated from blacklist hits carry an inferred kind so the AI knows what shape of value to expect in the token's place:

| Term example | Token shape |
|--------------|-------------|
| `Jan Jansen` | `[BLACKLIST_PERSON_1_a3f2c1]` |
| `jan@example.com` | `[BLACKLIST_EMAIL_1_b4d2e1]` |
| `NL91ABNA0417164300` | `[BLACKLIST_IBAN_1_c5e3f1]` |
| `+31 6 12345678` | `[BLACKLIST_PHONE_1_d6f4g1]` |
| `192.168.1.15` | `[BLACKLIST_IP_1_e7g5h1]` |

> The global blacklist lives in your home directory and is not tied to any repo — keep personal names, home address, or family details there. Use the per-repo blacklist for project-specific codenames, partner names, or client data.

## Inline escape

Append `~` to a word to prevent it from being tokenized in that message:

```
Send this to Mistral~ — they need it for the Vibe~ release
```

Works with punctuation: `Smith~.` `Smith~,` `Smith~)` — the `~` is stripped and the word passes through.

For multi-word names, the `~` escapes up to 4 preceding words:

```
Ask Jan Willem de Vries~ about the contract
```

This escapes "Jan", "Willem", "de", "Vries", and all combined phrases like "Jan Willem de Vries".

## View logs

```bash
erebus-log                    # last 20 events
erebus-log -n 50              # last 50 events
```

## Token usage

Every turn through Erebus is logged with its full Anthropic / OpenAI `usage` block — input, output, cache creation, cache read — so you can track spend and cache efficiency across all your sessions.

```bash
erebus-log --usage                    # all-time totals + top 5 sessions
erebus-log --usage --days 7           # last 7 days
erebus-log --usage --session abc12345 # one session
```

Output:

```
  turns logged:         42
  input_tokens                                 1,204
  output_tokens                                8,931
  cache_creation_input_tokens                102,450
  cache_read_input_tokens                  3,881,002
  ────────────────────────────────────────────────
  TOTAL                                    3,993,587
  cache hit ratio                              95.1%
```

Usage tracking is independent of PII detection — every API turn is counted, even in sessions where nothing was tokenized.

## GDPR controls

Erebus writes three sensitive files: the SQLite log, the token map, and the blacklists. All of them are chmod'd to `0600` (the containing `~/.erebus/` directory is `0700`), so a second user on the same machine can't read your tokenized data at rest.

**Retention — Article 5(1)(e):**

```bash
erebus-log --prune --days 30   # delete every event older than 30 days
```

**Right to erasure — Article 17:**

```bash
erebus-forget "Jan Jansen"              # remove every log entry mentioning the value
erebus-forget "jan@example.com" --yes   # skip confirmation
```

Matching is case-insensitive and searches raw prompts, sanitized copies, token maps, and metadata. Use it when a data subject asks you to delete their information, or just as routine hygiene.

**Token-map rotation:** `~/.erebus/token_map.json` is age-capped. Entries older than 7 days are wiped on the next load — the file can never accumulate a month of PII mappings just because you forgot to clean it up.

## Uninstall

```bash
erebus-uninstall --editor all   # restore all editor configs
erebus-uninstall                # restore claude binary
uv tool uninstall erebus
```

## Kill switch

Bypass all filtering for a single session:

```bash
EREBUS_BYPASS=1 claude
```

## Development

```bash
git clone https://github.com/ethux/erebus.git
cd erebus
uv tool install --editable .
```

## License

MIT
