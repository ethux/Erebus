"""Boundary facade — the ONLY interface adapters may use (contracts/boundary-api.md).

One Boundary per process per adapter role. ``from_config`` performs scope
resolution and opens/owns the Known-Value DB internally; adapters never see a
DB handle. Construction never raises on a missing daemon/DB; first use
degrades per FR-006/FR-018.

to_model pipeline (design §3, T027 slice):
  escape allowances    ``~`` markers are honored inside tokenize() for now;
                       time-boxed allowances are wired in a later phase
  known-value pre-scan the unconditional FR-011 pre-scan is wired in a later
                       phase; this phase ports the proxy's exact-replacement
                       retokenization of already-known values (longest first)
  catalog matcher      cataloging.matcher.apply_catalog_matches
  detector + cache     core.cache.cached_tokenize(_many), degraded-tolerant
  mint persistence     new tokens are ingested into the KnownValueDB before
                       to_model returns
"""
from __future__ import annotations

import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .. import config
from ..perf import log_perf_event
from . import cache, cache_disk, clock, message_cache, state
from .escapes import _parse_escapes
from .knownvalues import KnownValueDB, KnownValueView, open_known_values
from .message_cache import repo_config_cache_signature, stable_json_hash
from .modes import DEFAULT_MODE
from .patterns import TOKEN_RE
from .prescan import KnownValuePrescan


def _merge_tokenizer_results(base_text: str, base_tokens: dict,
                             detector_sanitized: str, detector_tokens: dict) -> tuple[str, dict]:
    """Port of proxy._merge_tokenizer_results: detector output wins when it
    minted tokens; otherwise keep the pre-detector text."""
    tokens = dict(base_tokens)
    tokens.update(detector_tokens)
    if detector_tokens:
        return detector_sanitized, tokens
    if tokens:
        return base_text, tokens
    return detector_sanitized, tokens


def _mask_value(value: str) -> str:
    """First char + '*' per remaining char: status output is a real-world sink
    but should not casually display full PII."""
    return value[:1] + "*" * max(len(value) - 1, 0)


class TurnState:
    """Read-only view of the current detection turn (adapter-visible)."""

    @property
    def degraded(self) -> bool:
        return state.turn_degraded()

    @property
    def degraded_reason(self) -> str:
        return state.turn_degraded_reason()


@dataclass
class Boundary:
    """World <-> model PII boundary for one adapter role (FR-001..FR-018)."""

    repo_config: Any
    project_dir: str
    source: str = ""
    _db: KnownValueDB | None = field(default=None, repr=False)
    _view: KnownValueView = field(default_factory=KnownValueView, repr=False)
    _prescan: KnownValuePrescan = field(default_factory=KnownValuePrescan, repr=False)
    # (generation, recheck_after, excluded_values) — see _allowance_exclusions.
    _allowance_cache: tuple = field(default=(-1, None, frozenset()), repr=False)

    @classmethod
    def from_config(cls, repo_config, project_dir: str, source: str = "") -> Boundary:
        """Resolve scope (FR-015) and open the Known-Value DB. Never raises."""
        boundary = cls(repo_config, str(project_dir), source)
        boundary._get_db()
        return boundary

    # -- internals -------------------------------------------------------------

    def _get_db(self) -> KnownValueDB | None:
        if self._db is None:
            try:
                self._db = open_known_values(self.repo_config, self.project_dir)
            except Exception as exc:
                print(f"erebus: known-value store unavailable: {exc}", file=sys.stderr)
        return self._db

    def _refresh_view(self) -> KnownValueView:
        if (db := self._get_db()) is not None:
            try:
                self._view = db.revalidate(self._view)
            except Exception:
                pass
        return self._view

    def _detector_params(self) -> dict[str, Any]:
        from ..verifiers import parse_verifier_list
        cfg = self.repo_config
        return {
            "extra_entities": getattr(cfg, "sensitive_entities", None),
            "allowed_names": getattr(cfg, "allowed_names", None),
            "mode": getattr(cfg, "mode", DEFAULT_MODE),
            "blacklist": getattr(cfg, "blacklist", []),
            "verifiers": parse_verifier_list(getattr(cfg, "verifier", "")),
            "verifier_llm_model": getattr(cfg, "verifier_llm_model", "gemma3:1b"),
            "verifier_openai_pf_url": getattr(cfg, "verifier_openai_pf_url", ""),
        }

    def _retokenize_known_values(self, text: str, escaped: frozenset[str] = frozenset()) -> str:
        """Replace already-known values with their existing tokens before the
        detector runs (longest value first, never inside an existing token).

        Delegates to a per-Boundary generation-cached index (FR-011, T039) so
        the store is sorted once per generation, not once per call. Values the
        user opted out of (``~`` escapes, active allowances, allowed_names) are
        excluded — without this the "unconditional" pre-scan made known values
        impossible to escape, because tokenize() parses ``~`` only later."""
        view = self._refresh_view()
        excluded = escaped | self._allowance_exclusions(view.generation)
        return self._prescan.apply(text, view, excluded)

    def retokenize_known(self, text: str) -> tuple[str, dict[str, str]]:
        """Re-run the known-value pre-scan over already-sanitized text (a
        message-cache replay). Returns (text, inserted) where inserted maps
        each token newly introduced by this pass to its value, so the caller
        records them. Honors active allowances and allowed_names; existing
        tokens in the text are never rewritten (FR-011)."""
        if not text:
            return text, {}
        before = set(TOKEN_RE.findall(text))
        result = self._retokenize_known_values(text)
        if result == text:
            return text, {}
        view = self._refresh_view()
        inserted = {tok: value for tok in set(TOKEN_RE.findall(result)) - before
                    if (value := view.token_view.get(tok)) is not None}
        return result, inserted

    def _allowance_exclusions(self, generation: int) -> frozenset[str]:
        """Lowercased values the pre-scan must skip: allowed_names config plus
        active ``~`` allowances. Cached per store generation (any allowance
        grant bumps it) and rechecked when the soonest allowance expires."""
        cached_gen, recheck_after, cached = self._allowance_cache
        now = clock.now()
        if cached_gen == generation and (recheck_after is None or now < recheck_after):
            return cached
        values = {name.lower() for name in getattr(self.repo_config, "allowed_names", None) or []}
        recheck = None
        if (db := self._get_db()) is not None:
            try:
                allowances = db.active_allowances()
                values.update(v.lower() for v in allowances)
                recheck = min(allowances.values()) if allowances else None
            except Exception:  # allowances must never break tokenization
                pass
        result = frozenset(values)
        self._allowance_cache = (generation, recheck, result)
        return result

    def _escape_exclusions(self, text: str) -> frozenset[str]:
        """Parse ``~`` escapes BEFORE the pre-scan runs: grant each one its
        time-boxed allowance (FR-013) and return the values to shield from
        this call. The marker itself is stripped later by tokenize()'s own
        escape pass; without this early hook, known values were impossible
        to escape because the pre-scan replaced them before parsing."""
        escaped, _cleaned = _parse_escapes(text)
        for value in escaped:
            self.grant_escape(value)
        return frozenset(escaped)

    def _pre_detector(self, text: str) -> tuple[str, dict]:
        """Escape grants -> catalog matcher -> known-value retokenization."""
        from ..cataloging import matcher as catalog_matcher
        escaped = self._escape_exclusions(text)
        catalog_text, catalog_tokens, _matches = catalog_matcher.apply_catalog_matches(text, self.repo_config)
        return self._retokenize_known_values(catalog_text, escaped), catalog_tokens

    # -- result cache (pipeline step 6: keyed on the RAW input text) -------------

    def _result_cache_key(self, text: str) -> tuple:
        """Cache key for one to_model result: raw input + full config signature
        (detector AND catalog fields), so any config change invalidates."""
        return ("boundary_to_model",
                cache._cache_text_identity(text),
                stable_json_hash(repo_config_cache_signature(self.repo_config)))

    def _result_cache_get(self, text: str) -> tuple[str, dict[str, str]] | None:
        """Cache hit. Stored pairs the current DB does not know yet are
        (re)ingested and reported as new, so every token in the returned text
        resolves; pairs already known come back as no new tokens. The
        known-value pre-scan still runs on the way out (unconditional, FR-011)
        so values learned since the entry was stored are retokenized."""
        cached, _src = cache._get_cached_tokenize_result_detail(self._result_cache_key(text), text)
        if cached is None:
            return None
        sanitized, tokens = cached
        view = self._refresh_view()
        new_tokens = {t: v for t, v in tokens.items() if t not in view.token_view}
        self._ingest_new_tokens(new_tokens)
        # The raw input may carry ``~`` escapes; honor them on the way out too,
        # or a cache hit would retokenize a value the user just opted out of.
        return self._retokenize_known_values(sanitized, self._escape_exclusions(text)), new_tokens

    def _result_cache_store(self, text: str, sanitized: str, tokens: dict, save: bool = True) -> None:
        """Store the final pipeline result; degraded turns are never cached."""
        cache._store_tokenize_result(self._result_cache_key(text), sanitized, tokens,
                                     save=save, original_text=text)

    def _ingest_new_tokens(self, tokens: dict) -> None:
        if not tokens or (db := self._get_db()) is None:
            return
        try:
            for token, value in tokens.items():
                db.ingest(token, value, source=self.source)
        except Exception as exc:
            print(f"erebus: known-value ingest failed: {exc}", file=sys.stderr)

    # -- world -> model ----------------------------------------------------------

    def to_model(self, text: str) -> tuple[str, dict[str, str]]:
        """Tokenize one model-bound string. Returns (tokenized_text, new_tokens);
        new_tokens are persisted to the Known-Value DB before return."""
        if (hit := self._result_cache_get(text)) is not None:
            return hit
        base_text, base_tokens = self._pre_detector(text)
        detector_sanitized, detector_tokens = cache.cached_tokenize(base_text, **self._detector_params())
        sanitized, tokens = _merge_tokenizer_results(base_text, base_tokens,
                                                     detector_sanitized, detector_tokens)
        self._ingest_new_tokens(tokens)
        self._result_cache_store(text, sanitized, tokens)
        return sanitized, tokens

    def to_model_many(self, texts: list[str]) -> list[tuple[str, dict[str, str]]]:
        """Batch to_model: same per-item guarantees, detector batching preserved."""
        results: list[tuple[str, dict[str, str]] | None] = [
            self._result_cache_get(text) for text in texts]
        misses = [i for i, result in enumerate(results) if result is None]
        if misses:
            pre = [self._pre_detector(texts[i]) for i in misses]
            base_texts = [base_text for base_text, _tokens in pre]
            detector_results = cache.cached_tokenize_many(base_texts, **self._detector_params())
            for i, (base_text, base_tokens), (detector_sanitized, detector_tokens) in zip(
                    misses, pre, detector_results, strict=True):
                sanitized, tokens = _merge_tokenizer_results(base_text, base_tokens,
                                                             detector_sanitized, detector_tokens)
                self._ingest_new_tokens(tokens)
                self._result_cache_store(texts[i], sanitized, tokens, save=False)
                results[i] = (sanitized, tokens)
            cache_disk._save_disk_cache()
        return results  # type: ignore[return-value]

    # -- model -> world ----------------------------------------------------------

    def _detokenize(self, text: str) -> tuple[str, list[str]]:
        """Resolve + replace without the FR-018 warning (shared with streaming)."""
        needed = {match.group(0) for match in TOKEN_RE.finditer(text)}
        if not needed:
            return text, []
        view = self._refresh_view()
        resolved = {t: v for t in needed if (v := view.token_view.get(t)) is not None}
        missing = needed - resolved.keys()
        if missing and (db := self._get_db()) is not None:
            try:
                resolved.update(db.resolve_missing(missing))
            except Exception as exc:
                print(f"erebus: token recovery failed: {exc}", file=sys.stderr)
        for token in sorted(resolved, key=len, reverse=True):
            text = text.replace(token, resolved[token])
        return text, sorted(needed - resolved.keys())

    def unresolved_action(self) -> str:
        """FR-018 policy: 'warn' (default, proceed with literal token) or
        'block' (the adapter must drop the side effect). Read here so every
        adapter consults one place instead of re-reading the config."""
        return getattr(self.repo_config, "unresolved_token_action", "warn") or "warn"

    def block_on_unresolved(self) -> bool:
        """True when FR-018 policy requires dropping the side effect."""
        return self.unresolved_action() == "block"

    def _warn_unresolved(self, unresolved: list[str]) -> None:
        """FR-018: warn loudly, never raise; the adapter enforces the action."""
        action = self.unresolved_action()
        shown = ", ".join(unresolved[:5]) + ("..." if len(unresolved) > 5 else "")
        print(f"[erebus] WARNING: {len(unresolved)} unresolved token(s) left literal "
              f"in model output: {shown} (unresolved_token_action={action})",
              file=sys.stderr, flush=True)
        log_perf_event("unresolved_tokens", count=len(unresolved), action=action,
                       source=self.source)

    def from_model(self, text: str) -> tuple[str, list[str]]:
        """Detokenize one world-bound string. Returns (text, unresolved_tokens);
        unresolved tokens stay literal and have been warned about (FR-017/FR-018)."""
        detokenized, unresolved = self._detokenize(text)
        if unresolved:
            self._warn_unresolved(unresolved)
        return detokenized, unresolved

    def from_model_payload(self, value: Any) -> tuple[Any, list[str]]:
        """Recursive JSON-walk variant of from_model for decoded payloads."""
        unresolved: list[str] = []
        result = self._walk_payload(value, unresolved)
        unresolved = sorted(set(unresolved))
        if unresolved:
            self._warn_unresolved(unresolved)
        return result, unresolved

    def _walk_payload(self, value: Any, unresolved: list[str]) -> Any:
        if isinstance(value, str):
            text, missing = self._detokenize(value)
            unresolved.extend(missing)
            return text
        if isinstance(value, list):
            return [self._walk_payload(item, unresolved) for item in value]
        if isinstance(value, dict):
            return {k: self._walk_payload(v, unresolved) for k, v in value.items()}
        return value

    # -- compat TOKEN_MAP mirror (contracts/compat-surface.md; slated for removal
    # with the mirror itself). These are the ONLY store entry points the proxy /
    # shim adapters may use to keep their passive mirrors synced (FR-008). -------

    @staticmethod
    def load_legacy_export() -> dict[str, str]:
        """Tokens from the legacy token_map.json export ({} on any error), so
        the compat mirrors can seed themselves without opening the DB."""
        try:
            tokens = config.load_token_map()
        except Exception:
            return {}
        return tokens if isinstance(tokens, dict) else {}

    @staticmethod
    def export_mirror(mirror: dict) -> None:
        """Write-through export of a compat mirror to the legacy JSON (0600
        perms + age-based rotation live in config.save_token_map)."""
        config.save_token_map(mirror)

    def sync_view_into(self, mirror: dict) -> set[str]:
        """Merge the revalidated known-value view + legacy JSON export into
        ``mirror`` in place (mirror entries win, then JSON, then view).

        Returns the view tokens the legacy export does not hold, so callers
        can tell whether a persist pass is needed to re-sync the exported file.
        """
        view = self._refresh_view().token_view
        persisted = self.load_legacy_export()
        merged = dict(view)
        merged.update(persisted)
        merged.update(mirror)
        mirror.clear()
        mirror.update(merged)
        return set(view) - persisted.keys()

    def persist_mirror(self, mirror: dict) -> None:
        """Sync the mirror, ingest pairs the store does not hold (a degraded
        DB only buffers transients), then write-through export the legacy JSON
        so mirror-only entries survive sessions where ingest cannot land."""
        self.sync_view_into(mirror)
        view = self._view.token_view
        self._ingest_new_tokens({t: v for t, v in mirror.items() if view.get(t) != v})
        self.export_mirror(mirror)

    def recover_tokens(self, tokens: set) -> dict[str, str]:
        """Resolve unknown tokens via the DB (includes audit-log recovery,
        FR-018); falls back to the bare audit-log lookup when the store is down."""
        if not tokens:
            return {}
        if (db := self._get_db()) is None:
            return self.audit_lookup(tokens)
        try:
            return db.resolve_missing(set(tokens))
        except Exception as exc:
            print(f"erebus: token recovery failed: {exc}", file=sys.stderr)
            return self.audit_lookup(tokens)

    @staticmethod
    def audit_lookup(tokens: set) -> dict[str, str]:
        """Last-resort token recovery straight from the audit log (FR-018)."""
        from ..audit.logger import lookup_token_values
        return lookup_token_values(set(tokens))

    # -- turn lifecycle ----------------------------------------------------------

    @contextmanager
    def turn(self):
        """Wrap one request/message cycle: reset the turn-degraded signal on
        enter; on exit warn (debounced) if the turn degraded and flush pending
        cache saves."""
        state.begin_detection_turn()
        try:
            yield TurnState()
        finally:
            if state.turn_degraded():
                state.warn_detection_degraded(state.turn_degraded_reason())
            cache_disk._save_disk_cache()
            message_cache.save_message_cache()

    # -- escapes (FR-013/FR-014) ---------------------------------------------------

    def grant_escape(self, value: str) -> None:
        """Record a user ``~`` escape; window from settings (FR-013)."""
        if not value or (db := self._get_db()) is None:
            return
        window = int(getattr(self.repo_config, "escape_window_minutes", 5) or 5)
        db.grant_allowance(value, window, source=self.source)

    def active_allowances(self) -> list[tuple[str, datetime]]:
        """[(value_masked, expires_at)] for every non-expired allowance."""
        if (db := self._get_db()) is None:
            return []
        try:
            allowances = db.active_allowances()
        except Exception:
            return []
        return sorted((_mask_value(value), expires) for value, expires in allowances.items())
