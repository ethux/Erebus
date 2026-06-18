# Changelog

All notable changes to Erebus are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
