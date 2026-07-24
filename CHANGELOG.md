# Changelog

All notable changes to Erebus are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0-beta.1] - 2026-07-24

First beta of the **deployable enterprise gateway**: a self-hosted server that sits
between an organization and its cloud AI provider, tokenizing PII on egress and
restoring values on responses for whole teams rather than a single machine.

### Added

- **Deployable gateway service.** The `erebus-gateway` console script launches a
  long-running FastAPI/uvicorn service from operator environment alone, with no
  code changes to deploy. Install with `pip install '.[gateway]'`.
- **Per-tenant central-credential egress on the live request path.** Outbound
  provider requests carry the organization-held, per-tenant central credential to
  an approved route; a client-supplied provider credential is never forwarded, and
  an unapproved model or route is refused fail-closed.
- **Restart-safe key custody.** A pluggable key-custody interface backed by an
  operator-supplied software master key (software envelope encryption); only KEKs
  wrapped by the master key are persisted, so custody survives restarts and an
  external KMS/HSM can be dropped in later without changing the tenant model.
- **Dynamic tenant onboarding.** `POST /v1/admin/tenants` provisions a tenant
  end-to-end (scope, central credential, approved routes, quota, policy, API
  credential) and makes it servable immediately with no restart or redeploy;
  `DELETE /v1/admin/tenants/{credential_id}` revokes a credential. Tenants resolve
  live from shared state, so replicas need no redeploy to serve a new team.
- **Fail-closed operability.** Liveness (`GET /healthz`) and readiness
  (`GET /readyz`) endpoints; readiness reflects shared state, key custody, and
  detection health so a load balancer drains an unhealthy replica. Startup
  validates configuration and probes critical dependencies and refuses to serve
  half-open. Detection-disabled mode is an explicit, recorded posture, never a
  silent fallback. Graceful shutdown drains in-flight work and aborts streams
  fail-closed.
- **Masked telemetry.** Per-scope operational counters with no raw PII or secrets,
  sufficient to observe health, throughput, refusals, and degradation.
- **Network end-to-end acceptance gate.** `make gateway-test` runs the strict
  release gate (fresh database per test, no self-skip, hard-fail without Postgres),
  including an end-to-end acceptance over real HTTP (uvicorn + mock provider + real
  Postgres) that verifies token-only egress, restoration, per-tenant credential
  egress, and fail-closed behavior.
- **Self-hosted deployment artifact.** A Docker Compose deployment brings up
  Postgres, the GLiNER detection daemon, and the gateway together for the
  recommended self-hosted beta path.
- **Always-warm detection daemon service.** `erebus-setup` now installs the
  GLiNER detection daemon as a supervised KeepAlive service (macOS LaunchAgent,
  Linux systemd user unit), so the model stays resident and there is no
  cold-start degraded window. The daemon's singleton lock keeps the supervised
  instance and on-demand spawns from double-loading.
- **International phone-number backstop.** A GLiNER-independent regex pattern
  now catches `+CC`-form phone numbers (including space/paren/hyphen grouping),
  so those numbers are redacted even during a detector-down window.

### Fixed

- **Detection daemon crash loop closed.** The GLiNER daemon had crash-looped
  hundreds of times, and each crash opened a window where detection silently
  fell back to regex/blacklist only. All four identified causes are fixed:
  - Fork-after-initialize aborts on macOS (the dominant cause): the daemon now
    runs with `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` and
    `TOKENIZERS_PARALLELISM=false` in its spawn and service environments.
  - A client disconnecting mid-request or a dependency error surfacing from the
    inference path no longer kills the serve loop; per-connection faults are
    isolated and transient `accept()` errors are ignored.
  - A transient network or DNS failure during model load no longer crashes
    startup; the daemon retries from the local HuggingFace cache
    (`local_files_only`) when the hub is unreachable.
  - Two requests racing to start the daemon no longer collide on the Unix
    socket; a stale socket is reclaimed under the exclusive singleton lock.

### Notes

- **Backward compatibility.** The single-machine PII filter and all 1.0.x behavior
  are unchanged. The gateway is additive: its dependencies live behind the
  `gateway` optional extra, and the 007 framework guarantees (per-scope crypto
  isolation, shared-state tokenization, governance) are integrated, not respecified.
- **Operator prerequisites.** A reachable PostgreSQL database (the shared state), a
  base64 software master key, and either a reachable GLiNER detection daemon or the
  explicit `EREBUS_DISABLE_GLINER=1` regex-only posture. Provisioning Postgres and
  standing up the detection daemon are operator prerequisites.
- Beta deployment posture is self-hosted on the customer's own infrastructure; a
  managed/hosted offering is a future direction.

## [1.0.1] - 2026-06-17

### Changed

- Privacy-filter prompt: the assistant may now ask the user what a token refers
  to when it cannot tell from context, and it suggests the `~` inline escape
  when a value was redacted that should not have been. Previously the prompt
  told the assistant never to ask about tokens.
- The MCP server reports its version from the installed package metadata instead
  of a hard-coded string, so the reported version can no longer drift from the
  release.

### Fixed

- Stop unbounded GLiNER daemon memory growth on the MPS (Apple Silicon) device.

### Removed

- Dead `_get_cached_tokenize_result` helper from the `erebus.filter` facade. It
  had no callers; the live `_get_cached_tokenize_result_detail` is unchanged.
- Redundant `wheel` entry from the build-system requirements; the
  `setuptools.build_meta` backend already provides it.

### Documentation

- Documented the `EREBUS_GLINER_THREADS` and `EREBUS_GLINER_DEVICE` environment
  variables, including how to cap the detector's CPU usage.

## [1.0.0] - 2026-06-11

- Initial public release: local PII tokenization for Claude Code, Mistral Vibe,
  Codex, and OpenAI/Anthropic-compatible editors. GLiNER plus regex detection,
  file guards, optional image scanning, the PII catalog, and a local SQLite
  audit trail.
