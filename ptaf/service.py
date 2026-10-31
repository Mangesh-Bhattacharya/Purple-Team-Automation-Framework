"""Generate (never silently install) native service definitions.

``ptaf service print --os <windows|linux|macos>`` writes the unit file /
launchd plist / scheduled-task command to stdout so an operator can review it
and install it deliberately. PTAF does not modify system service managers.
"""

from __future__ import annotations

import sys
from xml.sax.saxutils import escape


def render(os_name: str, python: str | None = None, interval_s: int = 3600) -> str:
    py = python or sys.executable
    if os_name == "linux":
        return f"""[Unit]
Description=PTAF Sentinel - continuous detection validation
After=network.target

[Service]
ExecStart={py} -m ptaf monitor --interval {interval_s}
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=%h/.ptaf
Environment=PTAF_HOME=%h/.ptaf

[Install]
WantedBy=default.target
# Install (user scope):  systemctl --user enable --now ptaf-sentinel.service
"""
    if os_name == "macos":
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>io.ptaf.sentinel</string>
  <key>ProgramArguments</key><array>
    <string>{escape(py)}</string><string>-m</string><string>ptaf</string>
    <string>monitor</string><string>--interval</string><string>{interval_s}</string>
  </array>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
</dict></plist>
<!-- Install: cp to ~/Library/LaunchAgents/io.ptaf.sentinel.plist && launchctl load it -->
"""
    if os_name == "windows":
        return (
            f'schtasks /Create /TN "PTAF Sentinel" /SC ONLOGON /RL LIMITED '
            f'/TR "\\"{py}\\" -m ptaf monitor --interval {interval_s}"\n'
        )
    raise ValueError(f"unsupported os: {os_name}")
