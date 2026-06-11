"""Tests for Codex setup helpers.

These cover the reversible wrapper shape and the TOML config block without
touching the real ~/.codex directory or the real codex binary.
"""

import os
import stat
import sys
import tempfile
import tomllib
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from erebus.setup import editors


def test_codex_config_adds_provider_and_preserves_existing_tables():
    content = """model = "gpt-5.5"
model_reasoning_effort = "xhigh"

[mcp_servers.unityMCP]
url = "http://127.0.0.1:8080/mcp"

[projects."/tmp/project"]
trust_level = "trusted"
"""
    updated, state = editors._apply_codex_config(content)
    parsed = tomllib.loads(updated)

    assert parsed["model"] == "gpt-5.5"
    assert parsed["model_provider"] == "erebus-openai"
    provider = parsed["model_providers"]["erebus-openai"]
    assert provider["base_url"] == "http://127.0.0.1:4748"
    assert provider["requires_openai_auth"] is True
    assert provider["supports_websockets"] is False
    assert parsed["projects"]["/tmp/project"]["trust_level"] == "trusted"
    assert state["had_model_provider"] is False
    print("  ✓ Codex config adds Erebus provider")


def test_codex_config_uninstall_restores_previous_model_provider():
    content = """model = "gpt-5.5"
model_provider = "openai"

[features]
rmcp_client = true
"""
    updated, state = editors._apply_codex_config(content)
    restored = editors._remove_codex_config(updated, state)
    parsed = tomllib.loads(restored)

    assert parsed["model_provider"] == "openai"
    assert "model_providers" not in parsed
    print("  ✓ Codex config uninstall restores previous provider")


def test_codex_wrapper_install_uninstall_round_trip():
    with tempfile.TemporaryDirectory() as tmp:
        bin_dir = Path(tmp)
        codex = bin_dir / "codex"
        codex.write_text("#!/bin/sh\necho real codex\n")
        codex.chmod(codex.stat().st_mode | stat.S_IEXEC)

        with patch.dict(os.environ, {"PATH": str(bin_dir)}):
            real = editors._install_binary_wrapper("codex", "/usr/local/bin/erebus-codex")
            assert real == (bin_dir / "codex-real").resolve()
            assert real.exists()
            assert "real codex" in real.read_text()
            assert "erebus-codex" in codex.read_text()

            editors._uninstall_binary_wrapper("codex")
            assert codex.exists()
            assert not real.exists()
            assert "real codex" in codex.read_text()
    print("  ✓ Codex wrapper install/uninstall round-trip")


if __name__ == "__main__":
    tests = [
        test_codex_config_adds_provider_and_preserves_existing_tables,
        test_codex_config_uninstall_restores_previous_model_provider,
        test_codex_wrapper_install_uninstall_round_trip,
    ]
    print("\n=== Codex Setup Tests ===\n")
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed\n")
    sys.exit(0 if passed == len(tests) else 1)
