"""pytest runs the script-style suite in one process. Isolate it from the real
~/.erebus the way tests/run_tests.sh does: fixture tokens that leak into the
live Known-Value DB get detokenized into real files on later AI write-backs."""
import atexit
import os
import shutil
import tempfile

# Every path under ~/.erebus derives from Path.home() at import, so this must run
# before any test imports erebus. Keep the model cache so GLiNER isn't re-downloaded.
os.environ.setdefault("HF_HOME", os.path.join(os.path.expanduser("~"), ".cache", "huggingface"))
os.environ.setdefault("EREBUS_GLINER_THREADS", "2")
os.environ["HOME"] = tempfile.mkdtemp(prefix="erebus-pytest-")
atexit.register(shutil.rmtree, os.environ["HOME"], ignore_errors=True)


import pytest  # noqa: E402  (after the HOME switch on purpose)


@pytest.fixture(autouse=True)
def _fresh_detection_state():
    """Each script in run_tests.sh starts with a clean detector; under pytest a
    degraded flag from an earlier test would make the caches skip storing."""
    from erebus.core import knownvalues, state
    state._reset_detector_state()
    state.begin_detection_turn()
    # Process-local degraded-mode fallback: one test's transient tokens would
    # otherwise show up in the next test's fresh Known-Value store.
    knownvalues._TRANSIENT_TOKENS.clear()
    knownvalues._TRANSIENT_PAIRS.clear()
    knownvalues._TRANSIENT_ALLOWANCES.clear()
