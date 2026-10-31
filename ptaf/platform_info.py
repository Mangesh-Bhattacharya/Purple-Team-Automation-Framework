"""Host fingerprinting: OS family, architecture and virtualization context.

Everything here is best-effort and read-only; a failed probe yields
``None``/``"unknown"`` rather than an exception so the agent runs the same
way on bare metal, VMs (VMware, VirtualBox, KVM/QEMU, Hyper-V, Parallels,
Xen), cloud instances and containers.
"""

from __future__ import annotations

import platform
import socket
import subprocess  # nosec B404 - fixed argv probes only, never shell=True
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

_VM_SIGNATURES = {
    "vmware": "VMware",
    "virtualbox": "VirtualBox",
    "innotek": "VirtualBox",
    "kvm": "KVM/QEMU",
    "qemu": "KVM/QEMU",
    "microsoft corporation": "Hyper-V",
    "hyper-v": "Hyper-V",
    "parallels": "Parallels",
    "xen": "Xen",
    "amazon ec2": "AWS EC2",
    "google compute engine": "GCE",
    "apple virtualization": "Apple Virtualization",
}


@dataclass
class HostInfo:
    os: str  # windows | linux | macos
    os_version: str
    arch: str
    hostname: str
    python: str
    virtualization: str  # "none" | hypervisor name | "unknown"
    container: str | None  # docker / podman / kubernetes / wsl / None

    def to_dict(self) -> dict:
        return asdict(self)


def _run(argv: list[str], timeout: float = 5.0) -> str:
    try:
        out = subprocess.run(  # nosec B603 - constant argv, no shell
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
        return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return ""


def _os_family() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def _match_vendor(blob: str) -> str | None:
    blob = blob.lower()
    for needle, name in _VM_SIGNATURES.items():
        if needle in blob:
            return name
    return None


def _detect_virtualization(os_name: str) -> str:
    if os_name == "linux":
        dmi = " ".join(
            _read(f"/sys/class/dmi/id/{f}")
            for f in ("product_name", "sys_vendor", "board_vendor", "bios_vendor")
        )
        vendor = _match_vendor(dmi)
        if vendor:
            return vendor
        if " hypervisor" in _read("/proc/cpuinfo").lower():
            return "unknown-hypervisor"
        return "none" if dmi.strip() else "unknown"
    if os_name == "macos":
        if _run(["sysctl", "-n", "kern.hv_vmm_present"]) == "1":
            return _match_vendor(_run(["sysctl", "-n", "hw.model"])) or "unknown-hypervisor"
        return "none"
    out = _run(
        [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "(Get-CimInstance Win32_ComputerSystem | "
            "ForEach-Object { $_.Manufacturer + ' ' + $_.Model })",
        ]
    )
    return _match_vendor(out) or ("none" if out else "unknown")


def _detect_container(os_name: str) -> str | None:
    if os_name != "linux":
        return None
    if "microsoft" in platform.release().lower():
        return "wsl"
    if Path("/.dockerenv").exists():
        return "docker"
    cgroup = _read("/proc/1/cgroup").lower()
    for name in ("kubepods", "docker", "containerd", "podman"):
        if name in cgroup:
            return "kubernetes" if name == "kubepods" else name
    return None


def collect_host_info() -> HostInfo:
    os_name = _os_family()
    return HostInfo(
        os=os_name,
        os_version=platform.platform(),
        arch=platform.machine(),
        hostname=socket.gethostname(),
        python=platform.python_version(),
        virtualization=_detect_virtualization(os_name),
        container=_detect_container(os_name),
    )
