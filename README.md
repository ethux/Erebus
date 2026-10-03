# Erebus

Privacy-first PII filter for AI code editors. Tokenizes sensitive data before it leaves your machine, de-tokenizes responses so you see real values. Works with **Claude Code**, **Mistral Vibe**, **Codex**, and any OpenAI/Anthropic-compatible editor.

**By [ETHUX](https://ethux.net)** | AGPL-3.0 (core) · Elastic License 2.0 (pro/)

---

## Project status

The current release is v1.2.0-beta.1 (see the [CHANGELOG](CHANGELOG.md)). Erebus is still young software. Expect possible
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

## Deployable Gateway (beta)

The single-machine proxy above protects one developer's machine. The **deployable
gateway** is a self-hosted server that sits between a whole organization and its
cloud AI provider: it tokenizes PII on egress, forwards only tokens upstream, and
restores real values in the responses your developers see. Users never hold
provider API keys. The operator holds one central credential per tenant, and the
gateway injects it on the live request path.

This is a beta. The [changelog](CHANGELOG.md) lists what each release adds, fixes
and changes; read it before upgrading.

### Operator prerequisites

- A reachable **PostgreSQL** database (the shared state all replicas point at).
- A **GLiNER detection daemon** reachable for production detection, or set
  `EREBUS_DISABLE_GLINER=1` to run regex-only. Regex-only still tokenizes emails,
  international phone numbers, IBANs, API keys, private keys and `key=value` secrets;
  names, addresses, organisations and national phone formats need GLiNER. A GLiNER
  outage never falls back to regex-only: requests fail closed with 503.
- A base64 software **master key** for key custody:

  ```bash
  python -c "import secrets,base64;print(base64.b64encode(secrets.token_bytes(32)).decode())"
  ```

### Install

The recommended self-hosted path is the published image with Docker Compose
(Postgres + gateway):

```bash
docker pull ghcr.io/ethux/erebus-gateway:beta
cp deploy/gateway.env.example gateway.env   # fill in the required values
docker compose -f deploy/docker-compose.yml up
```

Add `--build` to build the image from source. The compose file does not run the
GLiNER daemon yet; set `EREBUS_DISABLE_GLINER=1` to run regex-only. Without
Docker:

```bash
python -m pip install '.[gateway]' ./pro   # FastAPI, uvicorn, psycopg, httpx, cryptography, Pro
```

### Required configuration

The gateway is configured entirely from the environment. No code change is ever
required to deploy.

| Variable | Required | Meaning |
|----------|----------|---------|
| `EREBUS_PG_DSN` | yes | Shared-state Postgres DSN (every replica points at one store) |
| `EREBUS_GATEWAY_MASTER_KEY` | yes | base64 software master key for key custody (never logged) |
| `EREBUS_GATEWAY_PROVIDER` | yes | Default upstream provider, e.g. `openai` |
| `EREBUS_GATEWAY_HOST` | no (`0.0.0.0`) | Bind host |
| `EREBUS_GATEWAY_PORT` | no (`8080`) | Bind port |
| `EREBUS_GATEWAY_MODEL_MAP` | no | JSON `model -> provider` routing overrides |
| `EREBUS_DISABLE_GLINER` | no (off) | Run regex-only detection without GLiNER; `/readyz` reports `regex-only` |
| `EREBUS_GATEWAY_CONCURRENCY` | no (`0`) | Per-tenant concurrency cap (`0` = unlimited) |
| `EREBUS_GATEWAY_HTTP_TIMEOUT` | no (`30`) | Upstream HTTP timeout, seconds |
| `EREBUS_GATEWAY_CATALOG_POLL_S` | no (`5`) | Seconds between checks for changed tenant known values |
| `EREBUS_LICENSE_KEY` | no | Erebus Pro license key; without one only core features run |
| `EREBUS_LICENSE_FILE` | no | Path to a file holding the license key (e.g. a mounted secret); used when `EREBUS_LICENSE_KEY` is unset |

### Launch

```bash
export EREBUS_PG_DSN=postgresql:///erebus_gateway
export EREBUS_GATEWAY_MASTER_KEY=<base64 32 bytes>
export EREBUS_GATEWAY_PROVIDER=openai
erebus-gateway          # validates config + deps, runs migrations, serves on :8080
```

`erebus-gateway` validates its configuration and probes its critical dependencies
(database reachable, master key usable, GLiNER reachable unless
`EREBUS_DISABLE_GLINER` is set) before binding. If anything is wrong it prints the
precise problem and **exits non-zero without serving** so the service never runs
half-open.

### Create the first operator

Admin routes need an operator credential. Create the first one inside the running
container. It reads `EREBUS_PG_DSN` and `EREBUS_GATEWAY_MASTER_KEY` from the container's
environment; the master key is never sent over HTTP and no route accepts it.

```bash
docker compose -f deploy/docker-compose.yml exec gateway erebus-gateway create-operator --label ops-alice
```

Outside Docker, run `erebus-gateway create-operator` with both variables exported. It
prints an `egw_` token once on stdout (put it in a secret manager) and the credential id
on stderr (revoke by it). Use `exec`, not `run`, so the token stays out of container logs.
If the master key does not unseal the existing scope keys, it exits non-zero and writes
nothing. An operator issues more operator credentials with `POST /v1/admin/operators`
(body `{"label":"..."}`; returns `credential_id` and `api_credential`).

Upgrading an existing deployment: every existing credential becomes tenant-only, so run
`create-operator` once before using the admin routes.

### Onboard a tenant (no restart)

A new team becomes servable in one operator call, with no restart or redeploy:

```bash
curl -sX POST localhost:8080/v1/admin/tenants \
  -H 'Authorization: Bearer <operator-credential>' \
  -d '{"scope_key":"acme/payments",
       "provider":"openai",
       "central_credential":"sk-...",
       "routes":[{"base_url":"https://api.openai.com","model_allowlist":["gpt-4o"]}],
       "quota":{"rate_limit":600,"spend_budget":1000,"window_seconds":60}}'
# -> {"scope_id":"...","credential_id":"...","api_credential":"egw_..."}   (api_credential is shown ONCE)
```

Admin routes (`/v1/admin/*`, `/v1/audit`, `/v1/reveal`, `/metrics`) need an operator
credential; no credential gets 401 and a tenant credential gets 403. A body `role`, an
`X-Role` header or a query parameter grants nothing: privilege comes only from the
credential. Onboarding always issues tenant credentials. Scope keys starting with `_` are
reserved. Audit, key and reveal calls name their target with `scope_key`.
Revoke any credential with `DELETE /v1/admin/tenants/{credential_id}`.

### Use it (transparent to the developer)

```bash
curl -sX POST localhost:8080/v1/chat/completions \
  -H 'Authorization: Bearer egw_...' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"email Jan at jan@acme.nl"}]}'
# The upstream provider sees only tokens; the response you get back has real values restored.
```

The request carries the tenant's central credential to an approved route; a
client-supplied provider credential is never forwarded, and an unapproved model or
route is refused fail-closed. Set `"stream": true` for SSE streaming with restored
values; a mid-stream failure aborts fail-closed without emitting raw or
partial-token output.

A tenant's **known values** (names, emails and other values in its catalog) are always
tokenized, also when detection would miss them. They match whole words, case-insensitive,
next to detection; where both find overlapping text the longer span wins, a tie goes to the
known value. Each replica holds them in memory only and reloads a tenant within
`EREBUS_GATEWAY_CATALOG_POLL_S` of a change. A tenant whose values are not loaded (still
loading, crypto-erased or not active) gets 503 without using quota. Edge mode refuses a
payload holding a known value.

Size replicas for known values as described under [Connectors](#connectors).

### Health and readiness

| Endpoint | Purpose |
|----------|---------|
| `GET /healthz` | Liveness. Returns 200 whenever the process is up. |
| `GET /readyz` | Readiness. Returns 200 only when shared state, key custody, and detection are all healthy, else 503. The body's `detection` field is `available` (regex + GLiNER) or `regex-only`. `known_values` is `loading` (503) until every tenant's known values are loaded at startup, then `ready`, or `degraded` (still 200) when a reload failed and the previous values keep matching. |

Point your load balancer health check at `GET /readyz`: it drains a replica when a
critical dependency is unhealthy, so requests fail closed rather than leaking PII.
Scale by running more `erebus-gateway` replicas against the same `EREBUS_PG_DSN`; a
token minted by one replica restores on another. Operational telemetry is masked
(no raw PII or secrets).

### Connectors

Connect the databases that hold a tenant's customer data, and the names, emails, phone
numbers and addresses in them become **known values**: the gateway always replaces them
with a token, also when detection would miss them. A connector only reads.

| | Free | Erebus Pro |
|---|---|---|
| Sources | SQLite, Postgres, MySQL | also Snowflake and BigQuery (features `connectors.snowflake`, `connectors.bigquery`) |
| Syncs | a sample when a source is added or changed, then a full sync of the accepted fields; "sync now" | also scheduled syncs (feature `sync.schedule`) |

Everything is managed through the admin API below, which only an operator credential
can use; a tenant credential gets 403 on every source route. When a Pro license lapses,
values already synced keep matching and "sync now" keeps working for free sources; only
scheduled syncs and syncs of Pro sources stop.

Sizing: each gateway replica holds every tenant's known values in memory, about 90 MB per
100,000 values summed over all tenants, plus the same again for a tenant being reloaded.
A replica reports ready only after it has loaded every tenant, so keep that load within
your health check window (about 80 seconds in the compose file).

### Sync worker

`erebus-sync` reads the systems a tenant connects (SQLite, Postgres, MySQL; with Pro also
Snowflake and BigQuery) and keeps
that tenant's known values in step with them. It is the only process that contacts
those systems. It runs from the same image (the `sync-worker` service in the compose
file) and needs `EREBUS_PG_DSN` and `EREBUS_GATEWAY_MASTER_KEY`, not the provider
settings. It serves no traffic, but it holds the master key: give it the same secret
store and host hardening as the gateway.

A sample job maps a source's fields; a full sync stores the distinct values of the
accepted fields. Values retire only after a full sync reads everything: a sync that
fails, stops early or hits a cap keeps every value. An unreachable source is retried
(1, 5 and 15 minutes by default); wrong credentials, a refused host or a cap fail the
job at once and mark the source for attention. Job rows and logs hold fixed error
text only, never a credential or value.

Before connecting, the worker resolves the source host once and refuses it when any
address is on the deny list (by default the gateway's own database host, loopback,
link-local and cloud metadata addresses) or off the allow list when one is set.

| Variable | Default | Meaning |
|----------|---------|---------|
| `EREBUS_SYNC_POLL_S` | `5` | Seconds between polls for queued jobs |
| `EREBUS_SYNC_CONCURRENCY` | `2` | Jobs run at once |
| `EREBUS_SYNC_HEARTBEAT_S` / `EREBUS_SYNC_LEASE_S` | `30` / `600` | Heartbeat interval; a job silent for the lease is re-queued (the third time it fails) |
| `EREBUS_SYNC_BACKOFF_S` | `60,300,900` | Retry waits for an unreachable source or failed query |
| `EREBUS_SYNC_LIMIT_WAIT_S` | `172800` | How long a job may wait on a source's rate limit |
| `EREBUS_SYNC_TENANT_MAX_VALUES` | `1000000` | Most active known values per tenant |
| `EREBUS_SYNC_DENIED_HOSTS` | see above | Hosts, addresses and networks never contacted; setting it replaces the default |
| `EREBUS_SYNC_ALLOWED_HOSTS` | unset | When set, the only hosts, addresses and networks contacted |
| `EREBUS_SYNC_SQLITE_DIR` | unset (SQLite off) | Directory SQLite sources must resolve inside |

Several workers can run against one database; each job runs on one of them.

### Connecting a database

| Type | Settings | Credentials |
|------|----------|-------------|
| `sqlite` | `path` (inside `EREBUS_SYNC_SQLITE_DIR`), `collections` | none |
| `postgres`, `mysql` | `host`, `port`, `dbname`, `user`, `sslmode`, `schemas`, `collections` | `password` |

`sslmode` is `disable`, `prefer`, `require`, `verify-ca` or `verify-full` (the default,
checked against the system CAs). Collections are named `schema.table`; without
`schemas` the worker reads every user schema. A raw DSN, file paths and driver options
are refused. The worker opens every session read-only with a 10-minute statement
limit, but the read-only account below is the real guard. Grant only the tables that
hold customer data:

```sql
-- Postgres
CREATE ROLE erebus_sync LOGIN PASSWORD '<password>';
ALTER ROLE erebus_sync SET default_transaction_read_only = on;
GRANT CONNECT ON DATABASE crm TO erebus_sync;
GRANT USAGE ON SCHEMA public TO erebus_sync;
GRANT SELECT ON public.customers, public.contacts TO erebus_sync;

-- MySQL
CREATE USER 'erebus_sync'@'%' IDENTIFIED BY '<password>' REQUIRE SSL;
GRANT SELECT ON crm.customers TO 'erebus_sync'@'%';
GRANT SELECT ON crm.contacts TO 'erebus_sync'@'%';
```

### Connecting a warehouse (Pro)

Needs erebus-pro (in the published image) and a license with `connectors.snowflake` or
`connectors.bigquery` in the sync worker's environment. Without the feature the source's
syncs fail with `requires Erebus Pro (feature connectors.<type>)`; its values keep matching.

| Type | Settings | Credentials |
|------|----------|-------------|
| `snowflake` | `account` (`orgname-account`), `user`, `database`, `warehouse`, `role`, `schemas`, `collections` | `private_key` (PEM), `private_key_passphrase` if it is encrypted |
| `bigquery` | `project`, `location`, `max_bytes_billed`, `auth` (`key` or `attached`), `schemas` (datasets), `collections` | `service_account_key` (the JSON key file); none with `auth: attached` |

Neither takes a host: the driver derives it from the account or project, so the
worker's host lists do not apply to them. Collections are `SCHEMA.TABLE` and
`dataset.table`. Costs:

- Snowflake: a sync resumes the warehouse, billed at least 60 seconds per resume.
- BigQuery: each table is read in one query, billed at least 10 MB. `max_bytes_billed`
  caps every query on on-demand pricing (slot pricing ignores it); a capped query fails
  the sync and keeps every value. Sample rows come from the free table-read API.

The read-only role is the only guard on a warehouse:

```sql
-- Snowflake: a service user with a key pair (openssl genrsa 2048 | openssl pkcs8 -topk8 -nocrypt)
CREATE ROLE erebus_reader;
GRANT USAGE ON WAREHOUSE sync_wh TO ROLE erebus_reader;
GRANT USAGE ON DATABASE crm TO ROLE erebus_reader;
GRANT USAGE ON SCHEMA crm.public TO ROLE erebus_reader;
GRANT SELECT ON TABLE crm.public.customers TO ROLE erebus_reader;
CREATE USER erebus_sync TYPE = SERVICE DEFAULT_ROLE = erebus_reader RSA_PUBLIC_KEY = '<public key>';
GRANT ROLE erebus_reader TO USER erebus_sync;
```

BigQuery: give the service account BigQuery Job User on the project and BigQuery Data
Viewer only on the datasets that hold customer data. `auth: attached` uses the identity
attached to the worker (on GCP); workload identity federation is not supported yet.

### Managing sources

Source routes live under `/v1/admin/scopes/{scope_id}` (the `scope_id` onboarding
returned) and need an operator credential. Credentials are write-only: no response
returns them.

```bash
curl -sX POST localhost:8080/v1/admin/scopes/<scope_id>/sources \
  -H 'Authorization: Bearer <operator-credential>' \
  -d '{"name":"crm","type":"postgres",
       "settings":{"host":"db.internal","dbname":"crm","user":"erebus_sync"},
       "credentials":{"password":"..."},
       "credentials_expire_at":"2027-08-31T00:00:00Z"}'
# -> {"source":{"id":"...","status":"active",...},"job":{"kind":"sample","status":"queued",...}}
```

| Method and path | Does |
|---|---|
| `POST /sources` | Create a source; queues a sample job |
| `GET /sources` | List sources with status and credential expiry |
| `PATCH /sources/{id}` | Change `name`, `settings`, `credentials` (replaced whole), `status` (`active`/`paused`), `credentials_expire_at` or `max_values`; a settings or credentials change queues a sample |
| `DELETE /sources/{id}` | Remove a source and retire the values only it held; 409 while a job runs |
| `POST /sources/{id}/sample` | Re-run the sample job |
| `POST /sources/{id}/sync` | Sync now: queue a full sync, or return the job already queued or running |
| `GET /sources/{id}/fields` | The field mapping with decisions and reasons |
| `PATCH /sources/{id}/fields/{field_id}` | `{"decision":"confirmed"}` or `"ignored"`; queues a full sync |
| `GET /sync-jobs?source_id=&limit=` | Job status and counts, newest first |
| `POST /known-values/erase` | `{"value":"..."}`: remove a value under every label, with its tokens, and keep syncs from adding it back |

A paused source queues no jobs (409 on sample and sync). Another tenant's source is 404.
When a job is already running, or the source is paused, the sample or full sync a change
needs is kept as the source's `pending_job` and queued when that job ends or the source resumes.

### Scheduled syncs (Pro)

With a license carrying `sync.schedule` in the environment of both the gateway and the
sync worker, the worker gives every source a daily full sync. Change or turn it off per source:

```bash
curl -sX PUT localhost:8080/v1/admin/scopes/<scope_id>/sources/<source_id>/schedule \
  -H 'Authorization: Bearer <operator-credential>' \
  -d '{"full_minutes":720}'
# -> {"schedule":{"source_id":"...","full_minutes":720,"next_full_at":"...",...}}
```

`full_minutes` is 60 to 43200; `null` turns scheduled syncs off and an empty body
restores the default. Database sources have no incremental syncs, so
`incremental_minutes` must stay unset. The first run is one interval after the change. A
source that is busy waits for the next check (every minute); a paused one is skipped.
Without the feature the route returns 403 `requires Erebus Pro (feature sync.schedule)`.

### Run the release gate

Before pointing production traffic at the gateway, run the strict release gate. It
gives each test its own fresh database, never self-skips, and hard-fails without
Postgres:

```bash
EREBUS_PG_DSN=postgresql:///postgres make gateway-test
```

The connector contract suite runs against SQLite and Postgres; set
`EREBUS_TEST_MYSQL_DSN=mysql://root:<password>@127.0.0.1:3306` to include a throwaway
MySQL (skipped otherwise).

The end-to-end acceptance (real uvicorn + a mock provider + real Postgres) verifies
token-only egress, correct restoration, per-tenant central-credential egress, and
fail-closed behavior. A second one runs `erebus-gateway` and `erebus-sync` as real
processes: a synced Postgres value is tokenized in a chat, and no log, job row, audit
event or admin response holds a synced value or a source password. Both bind
localhost, so run them where localhost binds are permitted.

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

Everything outside `pro/` is licensed under the [GNU AGPL v3.0](LICENSE).
Everything inside `pro/` is licensed under the [Elastic License 2.0](pro/LICENSE):
the source is public, but using Pro features requires a license key from ETHUX.
Versions up to and including 1.1.0-beta.1 were released under MIT and remain so.
Commercial licensing: info@ethux.net.
