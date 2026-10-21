"""The shim's Claude Code tool hooks: tokenize tool output, restore tool input.

Regression for 2026-10-16: Claude Code runs tools itself, so tool output never
crossed the stdio shim and file contents reached the model unfiltered.

Uses a stub boundary — no detector, no model, no real Known-Value DB.
"""
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from erebus.shim import _state, hooks

NAME = "Jan Modaal"            # synthetic fixture, never a real name
TOKEN = "[PERSON_1_" "bbbbbb]"  # split literal: immune to detokenize-on-write


class _StubBoundary:
    def __init__(self, mint: bool = True):
        self.mint = mint

    def to_model_many(self, texts):
        return [(t.replace(NAME, TOKEN), {TOKEN: NAME} if self.mint and NAME in t else {}) for t in texts]

    def from_model_payload(self, value):
        return json.loads(json.dumps(value).replace(TOKEN, NAME)), []

    @contextmanager
    def turn(self):
        yield SimpleNamespace(degraded=False, degraded_reason="")


@contextmanager
def _stubbed(boundary):
    with patch.object(_state, "get_boundary", return_value=boundary), \
         patch.object(_state, "_persist_mirror"), \
         patch.object(hooks.REPO_CONFIG, "log_enabled", False):
        yield


def test_post_tool_use_tokenizes_output_and_keeps_its_shape():
    response = {"type": "text", "file": {"filePath": "/tmp/a.txt", "content": f"Owner: {NAME}"},
                "extra": [{"type": "image", "data": f"base64 {NAME}"},
                          {"type": "pdf", "file": {"base64": f"pdf {NAME}"}},
                          {"base64": f"raw {NAME}"}, f"data:image/png;base64,{NAME}"]}
    with _stubbed(_StubBoundary()):
        out = hooks.post_tool_use({"tool_name": "Read", "tool_response": response})["hookSpecificOutput"]
    updated = out["updatedToolOutput"]
    assert updated["file"]["content"] == f"Owner: {TOKEN}", updated
    assert updated["type"] == "text" and updated["file"]["filePath"] == "/tmp/a.txt"
    assert updated["extra"] == response["extra"], "binary payloads (image, pdf, base64) must stay untouched"
    assert TOKEN in out["additionalContext"], "new tokens need the model-facing hint"
    print("  ✓ PostToolUse tokenizes tool output and keeps its shape")


def test_post_tool_use_without_pii_changes_nothing():
    with _stubbed(_StubBoundary()):
        assert hooks.post_tool_use({"tool_response": {"stdout": "all clear", "stderr": ""}}) == {}
    print("  ✓ PostToolUse leaves clean output alone")


def test_pre_tool_use_restores_real_values():
    with _stubbed(_StubBoundary()):
        out = hooks.pre_tool_use({"tool_name": "Bash", "tool_input": {"command": f"grep -c '{TOKEN}' a.txt"}})
        assert hooks.pre_tool_use({"tool_name": "Bash", "tool_input": {"command": "ls"}}) == {}
    assert out["hookSpecificOutput"]["updatedInput"] == {"command": f"grep -c '{NAME}' a.txt"}
    assert "permissionDecision" not in out["hookSpecificOutput"], "must never auto-approve a tool"
    print("  ✓ PreToolUse restores real values without approving the call")


def test_post_tool_use_withholds_output_when_the_filter_fails():
    class _Broken(_StubBoundary):
        def to_model_many(self, texts):
            raise RuntimeError("store down")

    with _stubbed(_Broken()):
        out = hooks.post_tool_use({"tool_response": {"stdout": f"Owner: {NAME}", "interrupted": False}})
    updated = out["hookSpecificOutput"]["updatedToolOutput"]
    assert NAME not in json.dumps(updated) and updated["interrupted"] is False, updated
    print("  ✓ a failing filter withholds the output instead of sending it raw")


def test_pre_tool_use_keeps_tokens_for_model_facing_tools_and_failing_edits():
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write(f"Owner: {NAME}\n")
    edit = {"file_path": fh.name, "old_string": f"Owner: {TOKEN}", "new_string": "Owner: x"}
    try:
        with _stubbed(_StubBoundary()):
            agent = hooks.pre_tool_use({"tool_name": "Agent", "tool_input": {"prompt": f"ask {TOKEN}"}})
            applies = hooks.pre_tool_use({"tool_name": "Edit", "tool_input": edit})
            fails = hooks.pre_tool_use({"tool_name": "Edit", "tool_input": {**edit, "old_string": f"Boss: {TOKEN}"}})
    finally:
        os.unlink(fh.name)
    assert agent == {}, "a subagent prompt must never receive real values"
    assert applies["hookSpecificOutput"]["updatedInput"]["old_string"] == f"Owner: {NAME}"
    assert fails == {}, "a failing edit echoes old_string to the model, so it must keep its tokens"
    print("  ✓ model-facing tools and failing edits keep their tokens")


def test_settings_route_only_local_tools_and_keep_the_secret_out_of_argv():
    settings = hooks.start()
    pre = settings["hooks"]["PreToolUse"][0]
    assert re.fullmatch(pre["matcher"], "Bash") and not re.fullmatch(pre["matcher"], "Agent")
    assert os.environ[hooks.SECRET_ENV] not in json.dumps(settings)
    print("  ✓ only local tools get real values; the secret stays out of argv")


def test_server_rejects_calls_without_the_secret():
    url = hooks.start()["hooks"]["PreToolUse"][0]["hooks"][0]["url"]
    body = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": TOKEN}}).encode()

    def call(secret):
        req = urllib.request.Request(url, data=body, headers={"Authorization": f"Bearer {secret}"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())

    with _stubbed(_StubBoundary()):
        try:
            call("wrong")
            raise AssertionError("a call without the secret was answered")
        except urllib.error.HTTPError as exc:
            assert exc.code == 403
        out = call(os.environ[hooks.SECRET_ENV])
    assert out["hookSpecificOutput"]["updatedInput"] == {"command": NAME}
    print("  ✓ the hook server answers only callers with the session secret")


if __name__ == "__main__":
    tests = [
        test_post_tool_use_tokenizes_output_and_keeps_its_shape,
        test_post_tool_use_without_pii_changes_nothing,
        test_pre_tool_use_restores_real_values,
        test_post_tool_use_withholds_output_when_the_filter_fails,
        test_pre_tool_use_keeps_tokens_for_model_facing_tools_and_failing_edits,
        test_settings_route_only_local_tools_and_keep_the_secret_out_of_argv,
        test_server_rejects_calls_without_the_secret,
    ]
    for test in tests:
        test()
    print(f"\n{len(tests)}/{len(tests)} passed")
