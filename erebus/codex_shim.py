#!/usr/bin/env python3
"""Codex binary launcher for Erebus.

This wrapper keeps Codex running as Codex: it does not inspect terminal
stdin/stdout. The privacy boundary is the local Erebus Responses API proxy.
"""

from __future__ import annotations

import os
import sys

from .config import get_real_codex_binary

PROVIDER_ARGS = [
    "-c", 'model_provider="erebus-openai"',
    "-c", 'model_providers.erebus-openai.name="OpenAI via Erebus"',
    "-c", 'model_providers.erebus-openai.base_url="http://127.0.0.1:4748"',
    "-c", "model_providers.erebus-openai.requires_openai_auth=true",
    "-c", "model_providers.erebus-openai.supports_websockets=false",
    "-c", 'model_providers.erebus-openai.wire_api="responses"',
]


def main() -> None:
    real_binary = get_real_codex_binary()
    user_args = sys.argv[1:]

    if os.environ.get("EREBUS_BYPASS", "").strip().lower() in ("1", "true", "yes"):
        os.execv(real_binary, [real_binary] + user_args)  # noqa: RUF005

    if any(arg.startswith("--codex-") for arg in user_args):
        os.execv(real_binary, [real_binary] + user_args)  # noqa: RUF005

    os.execv(real_binary, [real_binary] + PROVIDER_ARGS + user_args)  # noqa: RUF005


if __name__ == "__main__":
    main()
