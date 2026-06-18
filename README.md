# Erebus

Privacy-first PII filter for AI code editors. Tokenizes sensitive data before it leaves your machine, de-tokenizes responses so you see real values. Works with **Claude Code**, **Mistral Vibe**, **Codex**, and any OpenAI/Anthropic-compatible editor.

**By [ETHUX](https://ethux.net)** | MIT License

---

## Project status

Erebus is a v1.0.1 release, but it is still young software. Expect possible
bugs, editor-specific edge cases, and cases where unusual payloads need another
pass. Keep a human review loop around sensitive workflows and please open an
issue if something looks off.

---

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/ethux/erebus/main/install.sh | bash
```

Or manually:

```bash
uv tool install git+https://github.com/ethux/erebus.git
erebus-setup --editor vibe      # or: claude, codex, all
```

That's it. Start your editor and PII is filtered automatically.

---

## What it does

```
You type: "Ask John Smith at john@corp.com about the contract"
    |
    Erebus intercepts
    |
AI sees: "Ask John [PERSON_1_a3f2c1] at [EMAIL_1_b4d2e1] about the contract"
    |
    AI responds using tokens
    |
You see: real values restored in the response
```

- **Names, emails, phones, IBANs, addresses, SSNs** detected by [GLiNER](https://github.com/urchade/gliner) NER
- **API keys, tokens, passwords, private keys** caught by regex
- **File guards** block `.env`, credentials, keys from being read by the AI
- **Image scanning** checks screenshots for sensitive content (optional, via Ollama)
- **Full audit trail** in local SQLite
- **GDPR-friendly** - everything runs locally, nothing leaves your machine unfiltered

---

## Commands

```bash
erebus-log                        # view recent activity
erebus-log --usage                # token usage stats
erebus-log --latency              # per-editor latency breakdown
erebus-blacklist add "term"       # always tokenize a term
erebus-forget "name"              # GDPR erasure - delete all log entries mentioning a value
erebus-log --prune --days 30      # GDPR retention - delete old events
erebus-update                     # update package and restart proxy services
erebus-uninstall --editor all     # remove Erebus from all editors
```

---

## Update

```bash
erebus-update
```

This upgrades the installed Erebus tool, stops the old GLiNER daemon, and
restarts the local proxy services so running editors use the new code.

For local development builds:

```bash
erebus-update --from .
```

---

## Configuration

Add `.erebus/pii-filter.json` to any repo:

```json
{
  "mode": "balanced",
  "sensitive_entities": ["Acme BV", "Project Phoenix"],
  "allowed_names": ["GitHub", "VSCode"],
  "block_file_patterns": ["**/.env*", "**/contracts/**"]
}
```

### Filter modes

| Mode | Names | Secrets |
|------|-------|---------|
| **strict** | All tokenized | Always tokenized |
| **balanced** (default) | First name kept, last name tokenized | Always tokenized |
| **relaxed** | Names kept | Always tokenized |

### Blacklist

For terms that must never reach the AI, regardless of NER confidence:

```bash
erebus-blacklist add "Jan Jansen"          # global (~/.erebus/blacklist.txt)
erebus-blacklist add "Acme BV" --repo      # per-repo (.erebus/blacklist.txt)
```

---

## PII catalog

`erebus-catalog` builds a local known-value catalog from approved structured sources. It is useful when you already know customer or user data in a database or API and want those exact values removed before AI-bound prompts leave your machine, even when normal PII detection would miss them.

SQLite is built in:

```bash
erebus-catalog source add sqlite customers ./customers.db \
  --scope "customers:first_name,last_name,email,phone,account_id"
erebus-catalog scan customers
erebus-catalog findings list --status candidate
erebus-catalog findings accept 42
erebus-catalog policy set --name-mode balanced --allow-first-name true
erebus-catalog reveal 42 --reason "support task" --minutes 10
erebus-catalog refresh customers
erebus-catalog forget "customer name" --yes
```

Enable catalog enforcement per repo:

```json
{
  "mode": "balanced",
  "pii_catalog": {
    "enabled": true,
    "enforce_known_values": true,
    "source_names": ["customers"],
    "name_mode": "balanced",
    "allow_first_name": true,
    "strict_near_identifiers": true
  }
}
```

External APIs use trusted local source connectors. Connectors normalize any transport or response shape into collections, fields, and records; Erebus owns detection, review, policy, enforcement, and audit. An Odoo connector can expose models like `res.partner`:

```bash
erebus-catalog source add odoo odoo-prod \
  --setting base_url=https://odoo.example.com \
  --setting database=prod \
  --secret-env credential=ODOO_CREDENTIAL_ENV \
  --scope "res.partner:name,email,phone,mobile,street"
```

Privacy notes: sources are read-only, secrets are referenced through environment variables, normal CLI output masks raw PII, catalog/log files stay under `~/.erebus/` with restricted permissions, and review/reveal/refresh/forget actions are audited locally.

---

## Inline escape

Append `~` to a word to skip tokenization for that message:

```
Send this to Smith~ at Acme~ — they need the update
```

---

## Architecture

```
  +----------+    +--------+--------+    +---------------+
  | Editor   |--->| Erebus Proxy    |--->| AI Provider   |
  | (Vibe,   |<---| :4747           |<---| API endpoint  |
  | Cursor…) |    +-----------------+    +---------------+
  +----------+          |
                  +-----+-----+
                  | GLiNER    |  loads model once, shared
                  | Daemon    |  across all sessions
                  +-----------+
```

Proxy mode (recommended) works with any editor that calls an API endpoint. Claude Code uses a binary shim that intercepts stdin/stdout.

---

## Verifiers (optional)

For extra GDPR coverage, add a second-pass verifier on top of GLiNER:

| Verifier | What | Hardware |
|----------|------|----------|
| `piiranha` | mdeberta-v3 NER (17 PII types, 6 languages) | CPU |
| `openai-pf` | 1.5B sparse MoE token classifier | GPU |
| `gemma` | Gemma 3 1B via Ollama (catches contextual leaks) | CPU/GPU |

Enable in `.erebus/pii-filter.json`:

```json
{ "verifier": "piiranha" }
{ "verifier": "piiranha,gemma" }
```

---

## Development

```bash
git clone https://github.com/ethux/erebus.git
cd erebus
uv tool install . --force
erebus-setup --editor codex
```

On macOS, avoid `uv tool install --editable .` when the repo lives in `~/Documents`,
`~/Desktop`, or `~/Downloads`. LaunchAgents cannot reliably read those
TCC-protected source folders, so the proxy can crash-loop. For live editable
development, keep the repo somewhere like `~/dev/Erebus`; otherwise reinstall
with `erebus-update --from .` after proxy changes.

### Linting and git hooks

```bash
make dev     # install dev tools (ruff, pylint, vulture) and enable the committed git hooks
make lint    # ruff + pylint max-module-lines + dead-code scan (same as CI)
make fix     # auto-fix what ruff can fix safely
make test    # full test suite
```

Pre-commit hooks live in `.githooks/` and run on every commit once enabled
via `make hooks` (sets `core.hooksPath`). CI enforces the same checks:
`ruff check`, a 600-line-per-module cap (pylint `C0302`; legacy files carry
an explicit `# pylint: disable=too-many-lines` pragma until the restructure
shrinks them), and a `vulture` dead-code scan.

---

## Environment variables

| Variable | Default | What it controls |
|----------|---------|------------------|
| `EREBUS_GLINER_THREADS` | `min(8, CPU cores - 2)` | CPU threads the GLiNER detector may use. PII detection runs on every prompt and tool result and, by default, spreads across most of your cores for speed, so you may see several cores hit 100% during a turn. Lower it (e.g. `2` to `4`) to cap CPU use, at the cost of slightly slower detection on large inputs. |
| `EREBUS_GLINER_DEVICE` | `mps` on Apple Silicon, else `cpu` | Inference device for the detector: `mps`, `cpu`, or `cuda`. On Apple Silicon, MPS (the GPU) runs detection roughly 3x faster than CPU. |
| `EREBUS_BYPASS` | unset | Set to `1` to bypass all filtering for one session (kill switch): `EREBUS_BYPASS=1 claude`. |

`EREBUS_GLINER_THREADS` and `EREBUS_GLINER_DEVICE` are read when the GLiNER
daemon starts. To make a change persist for editor-launched sessions on macOS:

```bash
launchctl setenv EREBUS_GLINER_THREADS 4   # GUI apps inherit it on next launch
```

Then restart the daemon (it respawns on demand) and your editor.

---

## License

MIT
