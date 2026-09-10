# Changelog

All notable changes to Erebus are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.3] - 2026-09-10

Codex proxy latency. Measured over 431 Codex turns (2026-09-05) the proxy added
avg 4.7 s (p95 14.5 s) before the upstream call, and long streams stalled until
Codex hit its SSE idle timeout. GLiNER was not the cause; the proxy's own
bookkeeping was. Detection output is unchanged.

Measured after the fixes over 302 live Codex turns: the proxy's own bookkeeping
fell from the dominant cost to 12% of the tokenize pass, and the multi-second
stalls are gone. What remains is detector time.

### Fixed

- **Audit-log recovery no longer scans the whole log on every turn.** A cached
  history item whose tokens no longer resolved triggered a full scan of
  `log.db` (3.4 GB live, ~18 s) on every request. Recovery now reads only the
  newest 5000 rows, remembers misses for five minutes, and evicts the cached
  item so it is tokenized afresh instead of replaying a token whose value is lost.
- **Expired escape allowances are swept** on store open and hourly; 174k
  expired rows had accumulated and were re-read on every store write. Re-granting
  an allowance that is still active is no longer a write.
- **`~` escapes match words only.** Code and markdown such as `~/path`,
  `~~strike~~`, `a~b` and `=~` no longer count as escapes; each false match was
  a store write plus a rewrite of the legacy token map.
- **Known-value pre-scan probes only candidate values** (leading-trigram index)
  instead of every stored value per cached item.
- **Tokenization runs off the event loop** on a single worker thread, so a slow
  turn no longer freezes other in-flight Codex streams.
- **Streaming detokenization scales with the text, not the token store.** Each
  SSE delta probed all ~13k stored tokens against the whole buffer (45 ms per
  10 KB); it now resolves only the tokens present in the text.
- **New tokens are stored in one transaction per turn** instead of one per token
  (each transaction rewrote the legacy export).
- **`erebus-update --from <path>` rebuilds from source.** uv reused the wheel it
  had built for the same version, so a local update could silently install stale
  code. The command now passes `--reinstall`.
- **Large tool outputs are cacheable.** A history item over 16 KB whose sanitized
  text reused an earlier token (known-value pre-scan, result-cache hit) could never
  be stored in the message cache (`uncacheable_patch`), so it went back through
  GLiNER on every turn: 1981 of 2466 misses live were 74 such items. Span patches
  are now derived by aligning the original and sanitized texts with every token's
  value, and the span cap is 2048. Items that are still uncacheable now record
  why (`uncacheable_patch:<reason>`) in the perf log.

## [1.0.2] - 2026-07-31

Detection-availability release. The GLiNER detection daemon had been crash-looping,
and every crash opened a window where detection silently fell back to the
regex/blacklist passes only, so PII that only the model catches could slip through.
This closes those windows. Nothing about *what* is detected or *how* values are
redacted changes, only *whether the detector is available*.

### Added

- **Always-warm detection daemon service.** `erebus-setup` now installs the GLiNER
  detection daemon as a supervised KeepAlive service (macOS LaunchAgent, Linux
  systemd user unit), so the model stays resident and there is no cold-start
  degraded window. The daemon's singleton lock keeps the supervised instance and
  any on-demand spawn from double-loading.
- **International phone-number backstop.** A GLiNER-independent regex pattern now
  catches `+CC`-form phone numbers (including space, paren, and hyphen grouping),
  so those numbers are redacted even during a detector-down window. Short `+`
  tokens such as `C++` are not over-matched.

### Fixed

- **Detection daemon crash loop closed.** All four identified causes are fixed:
  - Fork-after-initialize aborts on macOS (the dominant cause): the daemon now
    runs with `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` and
    `TOKENIZERS_PARALLELISM=false` in both its spawn and service environments.
  - A client disconnecting mid-request, or a dependency error surfacing from the
    inference path, no longer kills the serve loop. Per-connection faults are
    isolated and transient `accept()` errors are ignored.
  - A transient network or DNS failure during model load no longer crashes
    startup. The daemon retries from the local HuggingFace cache
    (`local_files_only`) when the hub is unreachable.
  - Two requests racing to start the daemon no longer collide on the Unix socket.
    A stale socket is reclaimed under the exclusive singleton lock.

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
