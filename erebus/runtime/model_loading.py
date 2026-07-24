"""
GLiNER model loading for the detection daemon: thread/device selection and
hub-failure-tolerant weight loading (spec 011, FR-003).
"""

import os
import sys

_MODEL_ID = "urchade/gliner_multi_pii-v1"


def _default_threads() -> int:
    """Detector thread count. Defaults to most of the box so batched windows
    (specs/003-proxy-tokenize-latency) parallelise; override via env."""
    env = os.environ.get("EREBUS_GLINER_THREADS")
    if env:
        try:
            return max(1, int(env))
        except ValueError:
            pass
    cpu = os.cpu_count() or 4
    return max(1, min(8, cpu - 2))


def _detector_device() -> str:
    """Inference device: EREBUS_GLINER_DEVICE overrides, else MPS when present.

    Measured on M-series: MPS runs GLiNER ~3x faster than CPU with identical
    outputs, which is the difference between sub-second and multi-second
    tokenization on novel interactive turns.
    """
    env = os.environ.get("EREBUS_GLINER_DEVICE")
    if env:
        return env
    try:
        import torch
        if torch.backends.mps.is_available():
            return "mps"
    except Exception:
        pass
    return "cpu"


def _load_gliner_weights():
    """Load the GLiNER model, treating hub reachability as optional (FR-003).

    ``from_pretrained`` contacts the HuggingFace hub for update checks; a DNS
    blip ("nodename nor servname provided") or any offline start would otherwise
    crash the daemon. The model is present locally after the first run, so on a
    network/name-resolution failure we retry once forced offline
    (``local_files_only``) and serve the cached weights. Only a genuinely
    missing local cache (first-ever run with no network) can still fail.
    """
    from gliner import GLiNER
    try:
        return GLiNER.from_pretrained(_MODEL_ID)
    except Exception as exc:
        if not _is_network_error(exc):
            raise
        print(f"GLiNER hub unreachable ({exc}); loading from local cache.",
              file=sys.stderr, flush=True)
        return GLiNER.from_pretrained(_MODEL_ID, local_files_only=True)


def _is_network_error(exc: Exception) -> bool:
    """True for a name-resolution / connection failure to the model hub.

    Matches by exception type where the hub/requests stack is importable and by
    message otherwise, so an offline start is treated as non-fatal without
    hard-depending on any one library's exception hierarchy."""
    network_types: tuple[type, ...] = (OSError,)
    try:
        import requests.exceptions as rexc
        network_types += (rexc.ConnectionError, rexc.Timeout)
    except Exception:
        pass
    try:
        from huggingface_hub.errors import (
            LocalEntryNotFoundError,
            OfflineModeIsEnabled,
        )
        network_types += (LocalEntryNotFoundError, OfflineModeIsEnabled)
    except Exception:
        pass
    if isinstance(exc, network_types):
        return True
    text = f"{type(exc).__name__}: {exc}".lower()
    needles = ("nodename nor servname", "name or service not known",
               "temporary failure in name resolution", "failed to establish",
               "connection error", "max retries", "getaddrinfo", "offline")
    return any(n in text for n in needles)


def _load_model():
    import torch
    torch.set_num_threads(_default_threads())
    model = _load_gliner_weights()
    device = _detector_device()
    if device != "cpu":
        try:
            model = model.to(device)
            print(f"GLiNER running on {device}.", file=sys.stderr, flush=True)
        except Exception as exc:
            print(f"GLiNER {device} unavailable ({exc}); staying on CPU.",
                  file=sys.stderr, flush=True)
    return model
