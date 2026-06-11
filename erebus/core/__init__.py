"""The PII boundary core.

Everything that mints, resolves, stores, or decides about PII tokens lives in
this package. Adapters (Claude shim, Codex launcher, HTTP proxy) may import
ONLY the public names re-exported here; reaching into submodules from outside
erebus/core/ is a static-audit violation (FR-008).

Public API grows phase by phase (specs/004-core-pii-boundary/plan.md):
  P1: KnownValueDB-backed token store
  P3: Boundary facade (to_model/from_model/turn), StreamDetokenizer
  P4: detection entry points + message-cache surface (adapter compat)
"""
from .boundary import Boundary, TurnState
from .detect import predict_entities, predict_entities_many
from .knownvalues import KnownValueDB, KnownValueView, open_known_values
from .message_cache import (
    _set_path_value,
    apply_text_span_patches,
    collect_text_patches,
    collect_token_span_patch,
    drop_message_cache_file,
    get_path_value,
    load_message_cache,
    message_cache_file_is_too_large,
    message_cache_key,
    normalize_message_cache_entry,
    normalize_message_cache_patch,
    repo_config_cache_signature,
    save_message_cache,
    stable_json_hash,
    stable_json_size,
    store_message_cache_entry,
    token_keys_from_patches,
)
from .patterns import TOKEN_RE
from .streaming import StreamDetokenizer

__all__ = [
    "TOKEN_RE",
    "Boundary",
    "KnownValueDB",
    "KnownValueView",
    "StreamDetokenizer",
    "TurnState",
    "_set_path_value",
    "apply_text_span_patches",
    "collect_text_patches",
    "collect_token_span_patch",
    "drop_message_cache_file",
    "get_path_value",
    "load_message_cache",
    "message_cache_file_is_too_large",
    "message_cache_key",
    "normalize_message_cache_entry",
    "normalize_message_cache_patch",
    "open_known_values",
    "predict_entities",
    "predict_entities_many",
    "repo_config_cache_signature",
    "save_message_cache",
    "stable_json_hash",
    "stable_json_size",
    "store_message_cache_entry",
    "token_keys_from_patches",
]
