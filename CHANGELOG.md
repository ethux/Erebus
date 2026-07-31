# Changelog

All notable changes to Erebus are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
