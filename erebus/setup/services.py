"""
System service installation (macOS launchd / Linux systemd).
"""

import json
import os
import platform
import shutil
import subprocess as _sp
import time
from importlib import metadata
from pathlib import Path
from urllib.parse import unquote, urlparse

from ..runtime.ports import describe_port_holder
from ..ui.colors import bold, info, ok, warn

TCC_PROTECTED_DIRS = {"Desktop", "Documents", "Downloads"}
PROXY_LABEL = "com.ethux.erebus-proxy"
OPENAI_PROXY_LABEL = "com.ethux.erebus-proxy-openai"
PROXY_SERVICE_NAME = "erebus-proxy"
OPENAI_PROXY_SERVICE_NAME = "erebus-proxy-openai"
PROXY_PORT = 4747
OPENAI_PROXY_PORT = 4748
# Labels from older generations of this product that may survive in launchd
# (with or without a plist on disk, e.g. the ethux-code-pii-wrapper era).
# Reaped on every install/update so they stop spawn-looping dead binaries
# and racing the current services for their ports. Only labels listed here
# are ever touched — never the whole com.ethux.* namespace.
KNOWN_LEGACY_LABELS = ("com.ethux.pii-proxy",)


def _find_proxy_binary() -> str:
    uv_path = Path.home() / ".local" / "share" / "uv" / "tools" / "erebus" / "bin" / "erebus-proxy"
    if uv_path.exists():
        return str(uv_path)
    return shutil.which("erebus-proxy") or "erebus-proxy"


def _editable_install_source(distribution_name: str = "erebus") -> Path | None:
    try:
        dist = metadata.distribution(distribution_name)
    except metadata.PackageNotFoundError:
        return None

    direct_url = dist.read_text("direct_url.json")
    if not direct_url:
        return None

    try:
        data = json.loads(direct_url)
    except json.JSONDecodeError:
        return None

    if not data.get("dir_info", {}).get("editable"):
        return None

    url = data.get("url")
    if not url:
        return None

    parsed = urlparse(url)
    if parsed.scheme == "file":
        return Path(unquote(parsed.path)).expanduser().resolve()
    if not parsed.scheme:
        return Path(url).expanduser().resolve()
    return None


def _is_macos_tcc_protected_source(path: Path) -> bool:
    try:
        relative = path.resolve().relative_to(Path.home().resolve())
    except ValueError:
        return False
    return bool(relative.parts) and relative.parts[0] in TCC_PROTECTED_DIRS


def _format_home_path(path: Path) -> str:
    try:
        return f"~/{path.resolve().relative_to(Path.home().resolve())}"
    except ValueError:
        return str(path)


def _launchd_editable_install_blocker() -> str | None:
    source = _editable_install_source()
    if source is None or not _is_macos_tcc_protected_source(source):
        return None

    source_path = _format_home_path(source)
    return (
        f"Erebus is installed editable from {source_path}. macOS launchd cannot "
        "read TCC-protected source folders reliably, so the proxy would crash-loop. "
        "Reinstall with `uv tool install . --force`, then rerun setup."
    )


def install_proxy_service():
    """Install proxy as a system service (macOS launchd or Linux systemd)."""
    print(bold("\nConfiguring proxy service...\n"))
    _install_proxy_service(
        label=PROXY_LABEL,
        service_name=PROXY_SERVICE_NAME,
        port=PROXY_PORT,
        target=None,
        log_suffix="proxy",
    )


def install_openai_proxy_service():
    """Install the OpenAI/Codex proxy as a separate system service."""
    print(bold("\nConfiguring Codex OpenAI proxy service...\n"))
    _install_proxy_service(
        label=OPENAI_PROXY_LABEL,
        service_name=OPENAI_PROXY_SERVICE_NAME,
        port=OPENAI_PROXY_PORT,
        target="https://chatgpt.com/backend-api/codex",
        log_suffix="proxy-openai",
    )


def _install_proxy_service(label: str, service_name: str, port: int,
                           target: str | None, log_suffix: str):
    proxy_bin = _find_proxy_binary()
    system = platform.system()

    if system == "Darwin":
        blocker = _launchd_editable_install_blocker()
        if blocker:
            print(warn(blocker))
            raise SystemExit(1)
        _install_launchd(proxy_bin, label, port, target, log_suffix)
    elif system == "Linux":
        _install_systemd(proxy_bin, service_name, port, target)
    else:
        target_arg = f" --target {target}" if target else ""
        print(warn(f"Auto-start not supported on {system} — run manually: erebus-proxy --port {port}{target_arg}"))


def _install_launchd(proxy_bin: str, label: str, port: int,
                     target: str | None, log_suffix: str):
    plist_path = Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    target_args = ""
    if target:
        target_args = f"""
        <string>--target</string>
        <string>{target}</string>"""
    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{proxy_bin}</string>
        <string>--port</string>
        <string>{port}</string>{target_args}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ExitTimeOut</key>
    <integer>5</integer>
    <key>StandardOutPath</key>
    <string>{Path.home()}/.erebus/{log_suffix}.log</string>
    <key>StandardErrorPath</key>
    <string>{Path.home()}/.erebus/{log_suffix}.err</string>
</dict>
</plist>"""
    plist_path.write_text(plist)
    _reap_legacy_launch_agents()
    if _launchctl_reload(plist_path, label, port):
        print(ok(f"macOS LaunchAgent installed — {label} auto-starts on login"))
    else:
        print(warn(f"{label} is installed but not running yet — it will start at next "
                   f"login, or run: launchctl bootstrap gui/{os.getuid()} {plist_path}"))
    print(info(f"Proxy: http://127.0.0.1:{port}"))


def _reap_legacy_launch_agents():
    """Boot out LaunchAgents left behind by older generations of this product.

    Old labels keep spawn-looping dead binaries and race the current services
    for their ports. Only KNOWN_LEGACY_LABELS are touched; their plists are
    moved to ~/.erebus/legacy-launchagents/ rather than deleted, and labels
    with no plist left on disk are booted out of launchd too.
    """
    agents_dir = Path.home() / "Library" / "LaunchAgents"
    backup_dir = Path.home() / ".erebus" / "legacy-launchagents"
    for label in KNOWN_LEGACY_LABELS:
        _sp.run(["launchctl", "bootout", launchd_target(label)], capture_output=True)
        plist = agents_dir / f"{label}.plist"
        if not plist.exists():
            continue
        try:
            backup_dir.mkdir(parents=True, exist_ok=True)
            backup = backup_dir / plist.name
            if backup.exists():
                backup.unlink()
            plist.rename(backup)
            print(ok(f"Removed legacy LaunchAgent {label} (plist saved to {backup_dir})"))
        except OSError as exc:
            print(warn(f"Could not move legacy plist {plist}: {exc}"))


def _gui_domain_available() -> bool:
    """True when the per-user gui launchd domain exists (console/Aqua session)."""
    result = _sp.run(["launchctl", "print", f"gui/{os.getuid()}"], capture_output=True)
    return result.returncode == 0


def _launchctl_reload(plist_path: Path, label: str, port: int) -> bool:
    """Make launchd's in-memory job definition match the plist on disk.

    Uses bootout/bootstrap instead of legacy unload/load: unload can fail
    silently, leaving a stale definition whose old ProgramArguments resurface
    on every kickstart, and the SIGTERM it sends lets a proxy wedged in
    graceful shutdown keep its port. bootout escalates to SIGKILL and
    bootstrap reports errors instead of swallowing them.
    """
    if not _gui_domain_available():
        # Headless/SSH install: the plist is on disk and RunAtLoad starts the
        # service at the next console login, so this is not a failure.
        print(warn(f"No console session for gui/{os.getuid()} — "
                   f"{label} will start at next login."))
        return True
    _sp.run(["launchctl", "bootout", launchd_target(label)], capture_output=True)
    # bootout is asynchronous. The wait is capped by the *loaded* job's
    # ExitTimeOut (launchd default 20s for pre-existing installs; 5s once
    # this plist generation is in place), so poll past 20s with margin.
    for _ in range(60):
        if not launchd_service_loaded(label):
            break
        time.sleep(0.5)
    else:
        print(warn(f"{label} is still loaded after bootout — reboot, or run: "
                   f"launchctl bootout {launchd_target(label)}"))
        return False
    holder = describe_port_holder(port)
    if holder:
        print(warn(f"Port {port} is held by {holder} — the service will crash-loop "
                   f"until that process exits. Kill it to recover immediately."))
    # Clear any persisted disabled flag (launchctl disable / unload -w from the
    # legacy era); a disabled label makes bootstrap fail with an opaque rc=5.
    _sp.run(["launchctl", "enable", launchd_target(label)], capture_output=True)
    result = _sp.run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(plist_path)],
                     capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        print(warn(f"Could not load {label}: {detail or 'launchctl bootstrap failed'}"))
        return False
    return True


def _install_systemd(proxy_bin: str, service_name: str, port: int, target: str | None):
    unit_dir = Path.home() / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    unit_path = unit_dir / f"{service_name}.service"
    target_arg = f" --target {target}" if target else ""
    unit = f"""[Unit]
Description={service_name}
After=network.target

[Service]
ExecStart={proxy_bin} --port {port}{target_arg}
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
"""
    unit_path.write_text(unit)
    _sp.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
    _sp.run(["systemctl", "--user", "enable", "--now", f"{service_name}.service"], capture_output=True)
    print(ok("systemd user service installed — proxy auto-starts on login"))
    print(info(f"Proxy: http://127.0.0.1:{port}"))
    print(info(f"Status: systemctl --user status {service_name}"))


def uninstall_proxy_service():
    _uninstall_proxy_service(PROXY_LABEL, PROXY_SERVICE_NAME)


def uninstall_openai_proxy_service():
    _uninstall_proxy_service(OPENAI_PROXY_LABEL, OPENAI_PROXY_SERVICE_NAME)


def _uninstall_proxy_service(label: str, service_name: str):
    system = platform.system()
    if system == "Darwin":
        plist_path = Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"
        _sp.run(["launchctl", "bootout", launchd_target(label)], capture_output=True)
        if plist_path.exists():
            plist_path.unlink()
            print(ok(f"macOS LaunchAgent removed: {label}"))
    elif system == "Linux":
        _sp.run(["systemctl", "--user", "disable", "--now", f"{service_name}.service"], capture_output=True)
        unit_path = Path.home() / ".config" / "systemd" / "user" / f"{service_name}.service"
        if unit_path.exists():
            unit_path.unlink()
            _sp.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
            print(ok(f"systemd user service removed: {service_name}"))


def launchd_target(label: str) -> str:
    return f"gui/{os.getuid()}/{label}"


def launchd_service_loaded(label: str) -> bool:
    result = _sp.run(["launchctl", "print", launchd_target(label)], capture_output=True, text=True)
    return result.returncode == 0


def restart_launchd_service(label: str) -> bool:
    if not launchd_service_loaded(label):
        print(warn(f"macOS LaunchAgent not loaded: {label}"))
        return False
    result = _sp.run(["launchctl", "kickstart", "-k", launchd_target(label)], capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        print(warn(f"Could not restart {label}: {detail or 'launchctl failed'}"))
        return False
    print(ok(f"Restarted {label}"))
    return True


def restart_systemd_service(service_name: str) -> bool:
    unit = f"{service_name}.service"
    result = _sp.run(["systemctl", "--user", "restart", unit], capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        print(warn(f"Could not restart {unit}: {detail or 'systemctl failed'}"))
        return False
    print(ok(f"Restarted {unit}"))
    return True


def _reload_or_restart(label: str, port: int) -> bool:
    """Refresh a service from its on-disk plist, falling back to kickstart.

    erebus-update must not kickstart launchd's cached job definition: a stale
    definition is exactly how an obsolete --target once came back from the
    dead. Reloading from the plist keeps the running job equal to disk state.
    """
    plist_path = Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"
    if not plist_path.exists():
        return restart_launchd_service(label)
    if _launchctl_reload(plist_path, label, port):
        print(ok(f"Restarted {label}"))
        return True
    return False


def restart_proxy_services() -> bool:
    """Restart installed proxy services after an Erebus package update."""
    system = platform.system()
    print(bold("\nRestarting Erebus services...\n"))
    if system == "Darwin":
        _reap_legacy_launch_agents()
        results = [
            _reload_or_restart(PROXY_LABEL, PROXY_PORT),
            _reload_or_restart(OPENAI_PROXY_LABEL, OPENAI_PROXY_PORT),
        ]
        return any(results)
    if system == "Linux":
        results = [
            restart_systemd_service(PROXY_SERVICE_NAME),
            restart_systemd_service(OPENAI_PROXY_SERVICE_NAME),
        ]
        return any(results)
    print(warn(f"Auto-restart not supported on {system}"))
    return False
