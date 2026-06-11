"""Boundary tests: outbound shell-command detokenization (spec FR-010a).

THE historical regression: a token inside a shell command string or
here-document crossed the boundary unresolved and was executed literally,
landing token-shaped strings in real-world artifacts. These tests resolve a
Bash tool payload through the boundary, then actually execute the resolved
command and assert the produced file bytes are clean.

All assertions run against real-world artifacts (the resolved command line
that gets executed, and the file the command writes) or against absence of
real values in model-bound payloads. All fixture values are synthetic.
"""
from __future__ import annotations

import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from helpers import (
    TOKEN_RE,
    IsolatedBoundaryHome,
    assert_no_tokens_in_file,
    assert_value_absent,
    daemon_stub,
    fake_clock,
    person_entity,
)

# Synthetic fixtures only (README rule 2): fake Dutch-sounding name + .test email.
NAME = "Jan Modaal"
EMAIL = "fake@example.test"


def _entities(text: str) -> list[dict]:
    """Detector stub: every occurrence of NAME is a person, EMAIL an email."""
    spans = person_entity(text, NAME)
    start = 0
    while True:
        idx = text.find(EMAIL, start)
        if idx < 0:
            break
        spans.append({"start": idx, "end": idx + len(EMAIL),
                      "label": "email_address", "text": EMAIL})
        start = idx + len(EMAIL)
    return spans


def _make_boundary(h: IsolatedBoundaryHome):
    from erebus.core import Boundary
    # strict mode so the person name always tokenizes
    return Boundary.from_config(h.repo_config(mode="strict"), str(h.project),
                                source="test")


def _mint_seed_tokens(boundary) -> tuple[str, str]:
    """Seed NAME and EMAIL through to_model; return their minted tokens."""
    seed_text = f"Contact {NAME} at {EMAIL} about the invoice."
    tokenized, new_tokens = boundary.to_model(seed_text)

    # model-bound output must not carry the real values
    assert_value_absent(tokenized, NAME)
    assert_value_absent(tokenized, EMAIL)

    by_value = {value: token for token, value in new_tokens.items()}
    assert NAME in by_value, f"name was not minted via to_model: {new_tokens}"
    assert EMAIL in by_value, f"email was not minted via to_model: {new_tokens}"
    tok_name, tok_email = by_value[NAME], by_value[EMAIL]
    assert TOKEN_RE.fullmatch(tok_name), f"bad token shape: {tok_name!r}"
    assert TOKEN_RE.fullmatch(tok_email), f"bad token shape: {tok_email!r}"
    assert tok_name in tokenized and tok_email in tokenized
    return tok_name, tok_email


# -- tests ---------------------------------------------------------------------


def test_heredoc_tokens_resolved_before_execution():
    """FR-010a, the historical Bash gap: tokens inside a quoted here-document
    are resolved by from_model_payload before the command runs, and the file
    the executed command produces contains only real values."""
    with IsolatedBoundaryHome() as h, fake_clock(), \
            daemon_stub("up", entities_for=_entities):
        boundary = _make_boundary(h)
        tok_name, tok_email = _mint_seed_tokens(boundary)

        # Spec example targets /tmp/out.txt; rewritten into the isolated
        # project dir so the side effect stays inside the sandboxed home.
        out_path = h.project / "out.txt"
        payload = {
            "name": "Bash",
            "input": {
                "command": (
                    f"cat <<'EOF' > {out_path}\n"
                    f"Contact {tok_name} at {tok_email}\n"
                    f"EOF"
                ),
            },
        }
        # fixture hygiene: the model-side payload never held real values
        assert_value_absent(payload, NAME)
        assert_value_absent(payload, EMAIL)

        resolved_payload, unres = boundary.from_model_payload(payload)

        assert unres == [], f"unexpected unresolved tokens: {unres}"
        assert resolved_payload["name"] == "Bash"
        cmd = resolved_payload["input"]["command"]
        assert NAME in cmd, f"real name missing from resolved command: {cmd!r}"
        assert EMAIL in cmd, f"real email missing from resolved command: {cmd!r}"
        leftover = TOKEN_RE.findall(cmd)
        assert leftover == [], f"token(s) {leftover} survived into command: {cmd!r}"

        # The regression was in the side effect: actually execute the resolved
        # command and assert on the bytes it writes ('EOF' is quoted, so the
        # shell expands nothing -- whatever is in the command lands verbatim).
        proc = subprocess.run(["bash", "-c", cmd], capture_output=True,
                              text=True, cwd=str(h.project))
        assert proc.returncode == 0, f"resolved command failed: {proc.stderr}"
        assert out_path.read_text(encoding="utf-8") == (
            f"Contact {NAME} at {EMAIL}\n")
        assert_no_tokens_in_file(out_path)


def test_plain_command_argument_tokens_resolved():
    """FR-010a also covers tokens in an ordinary command line (no heredoc):
    a token inside a single-quoted printf argument resolves before execution."""
    with IsolatedBoundaryHome() as h, fake_clock(), \
            daemon_stub("up", entities_for=_entities):
        boundary = _make_boundary(h)
        tok_name, tok_email = _mint_seed_tokens(boundary)

        out_path = h.project / "plain.txt"
        payload = {
            "name": "Bash",
            "input": {
                "command": (
                    f"printf '%s\\n' 'Contact {tok_name} at {tok_email}' "
                    f"> {out_path}"
                ),
            },
        }
        assert_value_absent(payload, NAME)
        assert_value_absent(payload, EMAIL)

        resolved_payload, unres = boundary.from_model_payload(payload)

        assert unres == [], f"unexpected unresolved tokens: {unres}"
        cmd = resolved_payload["input"]["command"]
        assert NAME in cmd and EMAIL in cmd, f"real values missing: {cmd!r}"
        leftover = TOKEN_RE.findall(cmd)
        assert leftover == [], f"token(s) {leftover} survived into command: {cmd!r}"

        proc = subprocess.run(["bash", "-c", cmd], capture_output=True,
                              text=True, cwd=str(h.project))
        assert proc.returncode == 0, f"resolved command failed: {proc.stderr}"
        assert out_path.read_text(encoding="utf-8") == (
            f"Contact {NAME} at {EMAIL}\n")
        assert_no_tokens_in_file(out_path)


if __name__ == "__main__":
    from helpers import run
    run([
        test_heredoc_tokens_resolved_before_execution,
        test_plain_command_argument_tokens_resolved,
    ], "Outbound shell-command detokenization (FR-010a)")
