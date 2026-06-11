"""Tests for service setup safety checks."""

import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from erebus import setup as setup_cli
from erebus.setup import services


class DirectUrlDistribution:
    def __init__(self, payload: str):
        self.payload = payload

    def read_text(self, name: str) -> str:
        assert name == "direct_url.json"
        return self.payload


def direct_url(source: str, editable: bool = True) -> str:
    return json.dumps({"url": source, "dir_info": {"editable": editable}})


def test_editable_install_source_reads_direct_url_metadata():
    dist = DirectUrlDistribution(direct_url("file:///Users/alice/Documents/Erebus"))

    with patch.object(services.metadata, "distribution", return_value=dist):
        source = services._editable_install_source()

    assert source == Path("/Users/alice/Documents/Erebus")
    print("  ok editable install source is read from direct_url.json")


def test_editable_install_source_ignores_non_editable_metadata():
    dist = DirectUrlDistribution(direct_url("file:///Users/alice/Documents/Erebus", editable=False))

    with patch.object(services.metadata, "distribution", return_value=dist):
        assert services._editable_install_source() is None
    print("  ok non-editable install metadata is ignored")


def test_launchd_blocker_flags_editable_install_from_documents():
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp).resolve()
        source = home / "Documents" / "Erebus"

        with (
            patch.object(services.Path, "home", return_value=home),
            patch.object(services, "_editable_install_source", return_value=source),
        ):
            reason = services._launchd_editable_install_blocker()

    assert reason is not None
    assert "~/Documents/Erebus" in reason
    assert "uv tool install . --force" in reason
    print("  ok launchd blocks editable installs from Documents")


def test_launchd_blocker_allows_editable_install_outside_tcc_dirs():
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp).resolve()
        source = home / "dev" / "Erebus"

        with (
            patch.object(services.Path, "home", return_value=home),
            patch.object(services, "_editable_install_source", return_value=source),
        ):
            reason = services._launchd_editable_install_blocker()

    assert reason is None
    print("  ok launchd allows editable installs outside protected folders")


def test_update_install_command_uses_uv_upgrade_or_local_source():
    assert setup_cli.update_install_command(None, True) == ["uv", "tool", "upgrade", "erebus", "--reinstall"]
    assert setup_cli.update_install_command(".", True) == ["uv", "tool", "install", "--force", "."]

    pip_cmd = setup_cli.update_install_command(None, False)
    assert pip_cmd[-5:] == ["-m", "pip", "install", "--upgrade", "erebus"]
    print("  ok update command chooses uv upgrade or local source reinstall")


def test_local_update_cleans_setuptools_build_artifacts():
    with tempfile.TemporaryDirectory() as tmp:
        project = Path(tmp)
        build = project / "build"
        egg_info = project / "erebus.egg-info"
        (project / "pyproject.toml").write_text("[project]\nname = \"erebus\"\n", encoding="utf-8")
        build.mkdir()
        egg_info.mkdir()
        (build / "stale.py").write_text("old", encoding="utf-8")
        (egg_info / "SOURCES.txt").write_text("old", encoding="utf-8")

        removed = setup_cli.clean_local_build_artifacts(str(project))

    assert {path.name for path in removed} == {"build", "erebus.egg-info"}
    assert not build.exists()
    assert not egg_info.exists()
    print("  ok local update cleans setuptools build artifacts")


def _fake_launchctl(responses):
    """Build a _sp.run fake; `responses` maps a command prefix tuple to a returncode."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        for prefix, rc in responses.items():
            if tuple(cmd[:len(prefix)]) == prefix and (len(prefix) < 3 or cmd[2] == prefix[2]):
                return SimpleNamespace(returncode=rc, stdout="", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    return calls, fake_run


def test_reload_skips_bootstrap_without_gui_session():
    """Headless/SSH installs must not abort: RunAtLoad covers the next login."""
    calls, fake_run = _fake_launchctl({("launchctl", "print", "gui/501"): 112})

    with (
        patch.object(services.os, "getuid", return_value=501),
        patch.object(services._sp, "run", side_effect=fake_run),
    ):
        assert services._launchctl_reload(Path("/tmp/x.plist"), "com.ethux.erebus-proxy", 4747)

    assert calls == [["launchctl", "print", "gui/501"]]
    print("  ok reload without a gui session defers to next login instead of failing")


def test_reload_enables_label_and_bootstraps_fresh_definition():
    label = "com.ethux.erebus-proxy"
    calls, fake_run = _fake_launchctl({("launchctl", "print", f"gui/501/{label}"): 113})

    with (
        patch.object(services.os, "getuid", return_value=501),
        patch.object(services._sp, "run", side_effect=fake_run),
        patch.object(services, "describe_port_holder", return_value=None),
    ):
        assert services._launchctl_reload(Path("/tmp/x.plist"), label, 4747)

    assert calls == [
        ["launchctl", "print", "gui/501"],
        ["launchctl", "bootout", f"gui/501/{label}"],
        ["launchctl", "print", f"gui/501/{label}"],
        ["launchctl", "enable", f"gui/501/{label}"],
        ["launchctl", "bootstrap", "gui/501", "/tmp/x.plist"],
    ]
    print("  ok reload boots out, clears the disabled flag, and bootstraps from the plist")


def test_reload_reports_bootstrap_failure_without_raising():
    label = "com.ethux.erebus-proxy"
    _calls, fake_run = _fake_launchctl({
        ("launchctl", "print", f"gui/501/{label}"): 113,
        ("launchctl", "bootstrap"): 5,
    })

    with (
        patch.object(services.os, "getuid", return_value=501),
        patch.object(services._sp, "run", side_effect=fake_run),
        patch.object(services, "describe_port_holder", return_value=None),
    ):
        assert services._launchctl_reload(Path("/tmp/x.plist"), label, 4747) is False
    print("  ok bootstrap failure is reported, not raised")


def test_install_warns_but_continues_when_reload_fails():
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp).resolve()

        with (
            patch.object(services.Path, "home", return_value=home),
            patch.object(services, "_reap_legacy_launch_agents"),
            patch.object(services, "_launchctl_reload", return_value=False),
        ):
            services._install_launchd("/bin/echo", "com.ethux.erebus-proxy", 4747, None, "proxy")

        plist = home / "Library" / "LaunchAgents" / "com.ethux.erebus-proxy.plist"
        assert plist.exists(), "plist must be written even when the reload fails"
        assert "<key>ExitTimeOut</key>" in plist.read_text()
    print("  ok install completes with a warning when launchd reload fails")


def test_reaper_only_touches_known_legacy_labels():
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp).resolve()
        agents = home / "Library" / "LaunchAgents"
        agents.mkdir(parents=True)
        legacy = agents / "com.ethux.pii-proxy.plist"
        current = agents / "com.ethux.erebus-proxy-openai.plist"
        bystander = agents / "com.ethux.some-other-product.plist"
        for plist in (legacy, current, bystander):
            plist.write_text("<plist/>")
        calls, fake_run = _fake_launchctl({})

        with (
            patch.object(services.Path, "home", return_value=home),
            patch.object(services.os, "getuid", return_value=501),
            patch.object(services._sp, "run", side_effect=fake_run),
        ):
            services._reap_legacy_launch_agents()

        assert not legacy.exists()
        assert (home / ".erebus" / "legacy-launchagents" / legacy.name).exists()
        assert current.exists() and bystander.exists(), "non-legacy plists must be untouched"
        assert calls == [["launchctl", "bootout", "gui/501/com.ethux.pii-proxy"]]
    print("  ok reaper removes only known legacy labels")


def test_update_reloads_from_plist_instead_of_kickstarting():
    """Kickstart resurrects launchd's cached args; update must reload from disk."""
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp).resolve()
        agents = home / "Library" / "LaunchAgents"
        agents.mkdir(parents=True)
        (agents / f"{services.OPENAI_PROXY_LABEL}.plist").write_text("<plist/>")
        reloaded, kickstarted = [], []

        with (
            patch.object(services.Path, "home", return_value=home),
            patch.object(services.platform, "system", return_value="Darwin"),
            patch.object(services, "_reap_legacy_launch_agents"),
            patch.object(services, "_launchctl_reload",
                         side_effect=lambda p, label, port: reloaded.append(label) or True),
            patch.object(services, "restart_launchd_service",
                         side_effect=lambda label: kickstarted.append(label) or True),
        ):
            assert services.restart_proxy_services()

        assert reloaded == [services.OPENAI_PROXY_LABEL]
        assert kickstarted == [services.PROXY_LABEL], "no plist on disk -> kickstart fallback"
    print("  ok update reloads services from their plists")


def test_restart_launchd_service_kickstarts_loaded_label():
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        assert kwargs["capture_output"] is True
        if cmd[:2] == ["launchctl", "print"]:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    with (
        patch.object(services.os, "getuid", return_value=501),
        patch.object(services._sp, "run", side_effect=fake_run),
    ):
        assert services.restart_launchd_service("com.ethux.erebus-proxy")

    assert calls == [
        ["launchctl", "print", "gui/501/com.ethux.erebus-proxy"],
        ["launchctl", "kickstart", "-k", "gui/501/com.ethux.erebus-proxy"],
    ]
    print("  ok launchd restart kickstarts loaded service")


if __name__ == "__main__":
    tests = [
        test_editable_install_source_reads_direct_url_metadata,
        test_editable_install_source_ignores_non_editable_metadata,
        test_launchd_blocker_flags_editable_install_from_documents,
        test_launchd_blocker_allows_editable_install_outside_tcc_dirs,
        test_update_install_command_uses_uv_upgrade_or_local_source,
        test_local_update_cleans_setuptools_build_artifacts,
        test_reload_skips_bootstrap_without_gui_session,
        test_reload_enables_label_and_bootstraps_fresh_definition,
        test_reload_reports_bootstrap_failure_without_raising,
        test_install_warns_but_continues_when_reload_fails,
        test_reaper_only_touches_known_legacy_labels,
        test_update_reloads_from_plist_instead_of_kickstarting,
        test_restart_launchd_service_kickstarts_loaded_label,
    ]
    print("\n=== Setup Service Tests ===\n")
    passed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as exc:
            print(f"  FAIL {test.__name__}: {exc}")
    print(f"\n{passed}/{len(tests)} passed\n")
    sys.exit(0 if passed == len(tests) else 1)
