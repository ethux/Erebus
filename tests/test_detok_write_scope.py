"""detokenize-on-write must only rewrite files the assistant actually wrote.

Regression for 2026-06-11: the strategy-2 regex fallback in
_detokenize_completed_writes detokenized ANY path it found in tool-result
text, silently corrupting unrelated source files merely mentioned in output
(e.g. a test runner echoing `tests/foo.py`) by replacing token literals with
their TOKEN_MAP values. It is now gated on the tracked Write/Edit target set.
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from erebus.shim import incoming

# Split-literal: immune to detokenize-on-write rewriting this source file.
TOKEN = "[PERSON_1_" + "abc123]"


def _tool_result_msg(text: str) -> dict:
    return {"type": "user", "message": {"content": [
        {"type": "tool_result", "tool_use_id": "toolu_x", "content": text}]}}


def test_untracked_mentioned_file_is_not_rewritten():
    """A file merely MENTIONED in tool output (not a tracked write) is left alone."""
    bystander = Path(tempfile.mktemp(suffix="-bystander.py"))
    bystander.write_text(f'assert token == "{TOKEN}"\n', encoding="utf-8")
    try:
        incoming._PENDING_WRITE_PATHS.clear()
        incoming.TOKEN_MAP.clear()
        incoming.TOKEN_MAP[TOKEN] = "Jansen"
        # tool output mentions the bystander path but nothing wrote it
        incoming._detokenize_completed_writes(
            _tool_result_msg(f"ran {bystander} and 3 tests passed"))
        after = bystander.read_text(encoding="utf-8")
        assert TOKEN in after, f"untracked file was corrupted: {after!r}"
        assert "Jansen" not in after
    finally:
        bystander.unlink(missing_ok=True)
        incoming.TOKEN_MAP.clear()
        incoming._PENDING_WRITE_PATHS.clear()
    print("  ✓ a merely-mentioned file is never rewritten")


def test_tracked_write_target_is_detokenized():
    """A genuinely tracked Write target still gets detokenized (strategy 1)."""
    written = Path(tempfile.mktemp(suffix="-handover.md"))
    written.write_text(f"owner: {TOKEN}\n", encoding="utf-8")
    try:
        incoming._PENDING_WRITE_PATHS.clear()
        incoming.TOKEN_MAP.clear()
        incoming.TOKEN_MAP[TOKEN] = "Jansen"
        # assistant requested the Write; track it like _track_pending_writes does
        incoming._PENDING_WRITE_PATHS["toolu_x"] = str(written)
        incoming._detokenize_completed_writes(_tool_result_msg("File written"))
        after = written.read_text(encoding="utf-8")
        assert "Jansen" in after, f"tracked write not detokenized: {after!r}"
        assert TOKEN not in after
    finally:
        written.unlink(missing_ok=True)
        incoming.TOKEN_MAP.clear()
        incoming._PENDING_WRITE_PATHS.clear()
    print("  ✓ a tracked write target is detokenized")


if __name__ == "__main__":
    tests = [
        test_untracked_mentioned_file_is_not_rewritten,
        test_tracked_write_target_is_detokenized,
    ]
    print("\n=== detokenize-on-write scope (2026-06-11) ===\n")
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as exc:
            print(f"  FAIL {t.__name__}: {exc}")
    print(f"\n{passed}/{len(tests)} passed\n")
    sys.exit(0 if passed == len(tests) else 1)
