"""
System service installation (macOS launchd / Linux systemd).
"""

import shutil
import platform
import subprocess as _sp
from pathlib import Path
from ..ui.colors import ok, warn, info, bold


def _find_proxy_binary() -> str:
    uv_path = Path.home() / ".local" / "share" / "uv" / "tools" / "erebus" / "bin" / "erebus-proxy"
    if uv_path.exists():
        return str(uv_path)
    return shutil.which("erebus-proxy") or "erebus-proxy"


def install_proxy_service():
    """Install proxy as a system service (macOS launchd or Linux systemd)."""
    print(bold("\nConfiguring proxy service...\n"))
    proxy_bin = _find_proxy_binary()
    system = platform.system()

    if system == "Darwin":
        _install_launchd(proxy_bin)
    elif system == "Linux":
        _install_systemd(proxy_bin)
    else:
        print(warn(f"Auto-start not supported on {system} — run manually: erebus-proxy"))


def _install_launchd(proxy_bin: str):
    plist_path = Path.home() / "Library" / "LaunchAgents" / "com.ethux.erebus-proxy.plist"
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ethux.erebus-proxy</string>
    <key>ProgramArguments</key>
    <array>
        <string>{proxy_bin}</string>
        <string>--port</string>
        <string>4747</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{Path.home()}/.erebus/proxy.log</string>
    <key>StandardErrorPath</key>
    <string>{Path.home()}/.erebus/proxy.err</string>
</dict>
</plist>"""
    plist_path.write_text(plist)
    _sp.run(["launchctl", "unload", str(plist_path)], capture_output=True)
    _sp.run(["launchctl", "load", str(plist_path)], capture_output=True)
    print(ok(f"macOS LaunchAgent installed — proxy auto-starts on login"))
    print(info(f"Proxy: http://127.0.0.1:4747"))


def _install_systemd(proxy_bin: str):
    unit_dir = Path.home() / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    unit_path = unit_dir / "erebus-proxy.service"
    unit = f"""[Unit]
Description=erebus proxy
After=network.target

[Service]
ExecStart={proxy_bin} --port 4747
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
"""
    unit_path.write_text(unit)
    _sp.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
    _sp.run(["systemctl", "--user", "enable", "--now", "erebus-proxy.service"], capture_output=True)
    print(ok("systemd user service installed — proxy auto-starts on login"))
    print(info("Proxy: http://127.0.0.1:4747"))
    print(info("Status: systemctl --user status erebus-proxy"))


def uninstall_proxy_service():
    system = platform.system()
    if system == "Darwin":
        plist_path = Path.home() / "Library" / "LaunchAgents" / "com.ethux.erebus-proxy.plist"
        if plist_path.exists():
            _sp.run(["launchctl", "unload", str(plist_path)], capture_output=True)
            plist_path.unlink()
            print(ok("macOS LaunchAgent removed"))
    elif system == "Linux":
        _sp.run(["systemctl", "--user", "disable", "--now", "erebus-proxy.service"], capture_output=True)
        unit_path = Path.home() / ".config" / "systemd" / "user" / "erebus-proxy.service"
        if unit_path.exists():
            unit_path.unlink()
            _sp.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
            print(ok("systemd user service removed"))
