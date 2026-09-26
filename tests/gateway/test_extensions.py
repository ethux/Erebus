"""Gateway extension loading via the erebus.gateway.extensions entry point group.

Pure logic: fake entry points stand in for installed distributions. A missing
extension is a no-op; broken extension code must stop startup (fail closed).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from erebus.gateway.extensions import GROUP, load_extensions

_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


class _EP:
    def __init__(self, name, fn):
        self.name = name
        self._fn = fn

    def load(self):
        return self._fn


def _boom(_app, _config):
    raise RuntimeError("broken extension")


def main():
    check("group name is stable", GROUP == "erebus.gateway.extensions")

    calls = []
    loaded = load_extensions("APP", "CFG", eps=[_EP("a", lambda app, cfg: calls.append((app, cfg)))])
    check("extension receives app and config", calls == [("APP", "CFG")])
    check("loaded extension names are returned", loaded == ["a"])

    check("no installed extensions is a no-op", load_extensions("APP", "CFG", eps=[]) == [])

    try:
        load_extensions("APP", "CFG", eps=[_EP("bad", _boom)])
        raised = False
    except RuntimeError:
        raised = True
    check("broken extension code stops startup", raised)

    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
