"""Tests for file guard pattern matching (no Ollama needed)."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unittest.mock import patch
from erebus.config import RepoConfig


# Patch ollama so tests run without it installed
def _mock_ollama_allow(*args, **kwargs):
    return {"message": {"content": '{"decision": "allow", "reason": "test"}'}}


def _run_check(filepath, repo_config):
    with patch("erebus.guards.files.ollama.chat", side_effect=_mock_ollama_allow):
        from erebus.guards.files import check_file
        return check_file(filepath, "read file", repo_config)


def test_env_file_blocked():
    result = _run_check("/project/.env", RepoConfig())
    assert result["decision"] == "block"
    print(f"  ✓ .env blocked: {result['reason']}")


def test_env_local_blocked():
    result = _run_check("/project/.env.local", RepoConfig())
    assert result["decision"] == "block"
    print(f"  ✓ .env.local blocked")


def test_pem_key_blocked():
    result = _run_check("/home/user/id_rsa.pem", RepoConfig())
    assert result["decision"] == "block"
    print(f"  ✓ .pem file blocked")


def test_private_key_blocked():
    result = _run_check("/home/user/id_rsa", RepoConfig())
    assert result["decision"] == "block"
    print(f"  ✓ id_rsa blocked")


def test_custom_pattern_blocked():
    config = RepoConfig(block_file_patterns=["**/contracts/**"])
    result = _run_check("/project/contracts/acme-q3.json", config)
    assert result["decision"] == "block"
    print(f"  ✓ Custom pattern blocked: contracts/")


def test_source_file_allowed():
    result = _run_check("/project/src/main.py", RepoConfig())
    assert result["decision"] == "allow"
    print(f"  ✓ Source file allowed")


if __name__ == "__main__":
    tests = [
        test_env_file_blocked,
        test_env_local_blocked,
        test_pem_key_blocked,
        test_private_key_blocked,
        test_custom_pattern_blocked,
        test_source_file_allowed,
    ]
    print("\n=== File Guard Pattern Tests ===\n")
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed\n")
