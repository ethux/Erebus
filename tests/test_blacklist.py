"""
Tests for the hard blacklist feature.

The blacklist is the GDPR-safe layer: plaintext terms in
~/.erebus/blacklist.txt (global) or <repo>/.erebus/blacklist.txt (per-repo)
are always tokenized, regardless of filter mode or NER detection. Both
blacklist files are also auto-added to block_file_patterns so the AI can
never read them via a file-read tool.
"""
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from erebus import config
from erebus import filter as erebus_filter
from erebus.filter import tokenize, detokenize


def _no_gliner(fn):
    """Decorator: run fn with GLiNER stubbed out so only the regex + blacklist
    passes execute. Needed because GLiNER will otherwise eagerly tokenize any
    name-like or code-like string and hide what the blacklist layer does.
    """
    def wrapper(*a, **kw):
        with patch.object(erebus_filter, "_predict_entities", return_value=[]):
            return fn(*a, **kw)
    wrapper.__name__ = fn.__name__
    return wrapper


# ── Tokenizer: blacklist replacement ─────────────────────────────────────────

@_no_gliner
def test_blacklist_replaces_case_insensitive():
    text = "Email Jan Jansen about the deal, and cc JAN about it too."
    sanitized, tokens = tokenize(text, blacklist=["Jan Jansen", "jan"])
    assert "Jan Jansen" not in sanitized
    assert "JAN" not in sanitized
    # Detokenize should restore original casing for each occurrence
    assert "Jan Jansen" in detokenize(sanitized, tokens)
    assert "JAN" in detokenize(sanitized, tokens)
    print(f"  ✓ case-insensitive match + casing preserved: {sanitized}")


@_no_gliner
def test_blacklist_word_boundary():
    """'QX' must not match inside 'QXRay' — word boundaries only.

    Uses made-up tokens instead of real names so GLiNER doesn't also
    pick them up as entities.
    """
    text = "QXRay is fine; QX is blocked."
    sanitized, tokens = tokenize(text, blacklist=["QX"])
    assert "QXRay" in sanitized, f"substring 'QX' inside 'QXRay' got replaced: {sanitized}"
    assert "QX is" not in sanitized, f"standalone 'QX' was not replaced: {sanitized}"
    assert any(t.startswith("[BLACKLIST_") for t in tokens)
    print(f"  ✓ word boundary respected: {sanitized}")


@_no_gliner
def test_blacklist_always_tokenized_relaxed_mode():
    """Blacklist must ignore filter mode — even in relaxed mode it fires."""
    text = "Contact Jan Jansen please."
    sanitized, tokens = tokenize(text, mode="relaxed", blacklist=["Jan Jansen"])
    assert "Jan Jansen" not in sanitized
    assert any(t.startswith("[BLACKLIST_") for t in tokens)
    print(f"  ✓ blacklist fires in relaxed mode: {sanitized}")


@_no_gliner
def test_blacklist_empty_noop():
    text = "Hello world"
    sanitized, tokens = tokenize(text, blacklist=[])
    assert sanitized == text
    assert tokens == {}
    print("  ✓ empty blacklist is a no-op")


@_no_gliner
def test_blacklist_multiple_occurrences():
    # Use a made-up product code GLiNER won't recognize as an entity, so
    # the blacklist pass is the only thing that can tokenize it.
    text = "Widget-QX7 here, widget-qx7 there, WIDGET-QX7 everywhere"
    sanitized, tokens = tokenize(text, blacklist=["Widget-QX7"])
    assert "Widget-QX7" not in sanitized and "widget-qx7" not in sanitized.lower()
    assert len([t for t in tokens if t.startswith("[BLACKLIST_")]) == 3
    print("  ✓ all 3 occurrences tokenized with distinct tokens")


@_no_gliner
def test_blacklist_phrase_with_regex_metacharacters():
    """Terms containing regex metacharacters must not crash."""
    text = "Reference: Project.X (2024) is confidential"
    sanitized, tokens = tokenize(text, blacklist=["Project.X (2024)"])
    assert "Project.X" not in sanitized
    print(f"  ✓ regex metacharacters escaped: {sanitized}")


@_no_gliner
def test_blacklist_token_includes_kind():
    """Token labels include an inferred kind: PERSON, EMAIL, PHONE, IBAN, ..."""
    cases = [
        ("Contact jan@example.com today", "jan@example.com", "EMAIL"),
        ("IBAN NL91ABNA0417164300 please", "NL91ABNA0417164300", "IBAN"),
        ("Call +31 6 12345678 please", "+31 6 12345678", "PHONE"),
        ("Server at 192.168.1.15 hosts it", "192.168.1.15", "IP"),
        ("Meet Jan Jansen tomorrow", "Jan Jansen", "PERSON"),
    ]
    for text, term, kind in cases:
        _sanitized, tokens = tokenize(text, blacklist=[term])
        keys = list(tokens.keys())
        assert keys, f"no token produced for {term!r}"
        assert any(k.startswith(f"[BLACKLIST_{kind}_") for k in keys), \
            f"expected BLACKLIST_{kind} for {term!r}, got {keys}"
    print("  ✓ token kind inferred from term shape (PERSON/EMAIL/IBAN/PHONE/IP)")


# ── Config: file loading + auto-block ────────────────────────────────────────

def _with_tmp_paths(fn):
    """Run fn with isolated global + repo blacklist paths."""
    def wrapper():
        tmp = Path(tempfile.mkdtemp(prefix="erebus-bl-test-"))
        original_global = config.GLOBAL_BLACKLIST_PATH
        config.GLOBAL_BLACKLIST_PATH = tmp / "global_blacklist.txt"
        # Ensure the _BLACKLIST_BLOCK_PATTERNS includes the test path so
        # block_file_patterns reflects the real global file location.
        patterns_before = config._BLACKLIST_BLOCK_PATTERNS[:]
        config._BLACKLIST_BLOCK_PATTERNS = patterns_before + [str(config.GLOBAL_BLACKLIST_PATH)]
        try:
            fn(tmp)
        finally:
            config.GLOBAL_BLACKLIST_PATH = original_global
            config._BLACKLIST_BLOCK_PATTERNS = patterns_before
    wrapper.__name__ = fn.__name__
    return wrapper


@_with_tmp_paths
def test_load_global_blacklist(tmp: Path):
    config.GLOBAL_BLACKLIST_PATH.write_text("Alice\n# comment\n\nBob Smith\n")
    cfg = config.load_repo_config(cwd=str(tmp))
    assert cfg.blacklist == ["Alice", "Bob Smith"]
    print("  ✓ global blacklist loaded, comments/blanks stripped")


@_with_tmp_paths
def test_load_repo_blacklist(tmp: Path):
    (tmp / ".erebus").mkdir(parents=True, exist_ok=True)
    (tmp / ".erebus" / "blacklist.txt").write_text("Acme BV\nProject Phoenix\n")
    cfg = config.load_repo_config(cwd=str(tmp))
    assert cfg.blacklist == ["Acme BV", "Project Phoenix"]
    print("  ✓ repo blacklist loaded")


@_with_tmp_paths
def test_global_and_repo_merged_deduped(tmp: Path):
    config.GLOBAL_BLACKLIST_PATH.write_text("Alice\nShared\n")
    (tmp / ".erebus").mkdir(parents=True, exist_ok=True)
    (tmp / ".erebus" / "blacklist.txt").write_text("Shared\nBob\n")
    cfg = config.load_repo_config(cwd=str(tmp))
    assert cfg.blacklist == ["Alice", "Shared", "Bob"]
    print("  ✓ global + repo merged, duplicates removed")


@_with_tmp_paths
def test_blacklist_files_in_block_patterns(tmp: Path):
    cfg = config.load_repo_config(cwd=str(tmp))
    # The global path and any of the repo-relative patterns should be present.
    assert str(config.GLOBAL_BLACKLIST_PATH) in cfg.block_file_patterns
    assert any("blacklist.txt" in p for p in cfg.block_file_patterns)
    print("  ✓ blacklist files auto-added to block_file_patterns")


@_with_tmp_paths
def test_existing_block_patterns_preserved(tmp: Path):
    (tmp / ".erebus").mkdir(parents=True, exist_ok=True)
    (tmp / ".erebus" / "pii-filter.json").write_text(
        '{"block_file_patterns": ["**/contracts/**"]}'
    )
    cfg = config.load_repo_config(cwd=str(tmp))
    assert "**/contracts/**" in cfg.block_file_patterns
    assert any("blacklist.txt" in p for p in cfg.block_file_patterns)
    print("  ✓ existing block patterns preserved, blacklist paths appended")


# ── CLI ──────────────────────────────────────────────────────────────────────

def _run_cli(args, cwd: Path):
    """Import blacklist CLI and invoke it with args, capturing stdout."""
    from erebus import blacklist as bl
    import io
    buf = io.StringIO()
    old_cwd = os.getcwd()
    os.chdir(cwd)
    try:
        with patch("sys.argv", ["erebus-blacklist"] + args), patch("sys.stdout", buf):
            rc = bl.main()
    finally:
        os.chdir(old_cwd)
    return rc, buf.getvalue()


@_with_tmp_paths
def test_cli_add_then_list_global(tmp: Path):
    rc, _ = _run_cli(["add", "Jan Jansen"], cwd=tmp)
    assert rc == 0
    assert config.GLOBAL_BLACKLIST_PATH.exists()
    assert "Jan Jansen" in config.GLOBAL_BLACKLIST_PATH.read_text()

    rc, out = _run_cli(["list"], cwd=tmp)
    assert rc == 0
    assert "Jan Jansen" in out
    print("  ✓ CLI add (global) + list")


@_with_tmp_paths
def test_cli_add_repo_flag(tmp: Path):
    rc, _ = _run_cli(["add", "Acme BV", "--repo"], cwd=tmp)
    assert rc == 0
    repo_file = tmp / ".erebus" / "blacklist.txt"
    assert repo_file.exists()
    assert "Acme BV" in repo_file.read_text()
    # Global file should NOT have been written
    assert not config.GLOBAL_BLACKLIST_PATH.exists() or \
           "Acme BV" not in config.GLOBAL_BLACKLIST_PATH.read_text()
    print("  ✓ CLI add --repo writes to repo file only")


@_with_tmp_paths
def test_cli_add_duplicate_is_noop(tmp: Path):
    _run_cli(["add", "Alice"], cwd=tmp)
    size_before = config.GLOBAL_BLACKLIST_PATH.stat().st_size
    rc, _ = _run_cli(["add", "ALICE"], cwd=tmp)  # case-insensitive dedup
    assert rc == 0
    assert config.GLOBAL_BLACKLIST_PATH.stat().st_size == size_before
    print("  ✓ CLI add ignores case-insensitive duplicates")


@_with_tmp_paths
def test_cli_remove(tmp: Path):
    _run_cli(["add", "Alice"], cwd=tmp)
    _run_cli(["add", "Bob"], cwd=tmp)
    rc, _ = _run_cli(["remove", "Alice"], cwd=tmp)
    assert rc == 0
    remaining = config._load_blacklist_file(config.GLOBAL_BLACKLIST_PATH)
    assert "Alice" not in remaining
    assert "Bob" in remaining
    print("  ✓ CLI remove drops a term, keeps others")


@_with_tmp_paths
def test_cli_remove_missing_term_nonzero_exit(tmp: Path):
    config.GLOBAL_BLACKLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    config.GLOBAL_BLACKLIST_PATH.write_text("Alice\n")
    rc, _ = _run_cli(["remove", "Zed"], cwd=tmp)
    assert rc == 1
    print("  ✓ CLI remove of missing term exits 1")


# ── Runner ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_blacklist_replaces_case_insensitive,
        test_blacklist_word_boundary,
        test_blacklist_always_tokenized_relaxed_mode,
        test_blacklist_empty_noop,
        test_blacklist_multiple_occurrences,
        test_blacklist_phrase_with_regex_metacharacters,
        test_blacklist_token_includes_kind,
        test_load_global_blacklist,
        test_load_repo_blacklist,
        test_global_and_repo_merged_deduped,
        test_blacklist_files_in_block_patterns,
        test_existing_block_patterns_preserved,
        test_cli_add_then_list_global,
        test_cli_add_repo_flag,
        test_cli_add_duplicate_is_noop,
        test_cli_remove,
        test_cli_remove_missing_term_nonzero_exit,
    ]
    print("\n=== Blacklist Tests ===\n")
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed\n")
    sys.exit(0 if passed == len(tests) else 1)
