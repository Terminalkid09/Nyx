"""Platform-specific packet manipulation backends.

Passive capture is intentionally NOT platform-specific anymore: it uses
scapy's AsyncSniffer (see core.network.capture), the same layer-2 sniffing
pattern dns_spoof.py uses, which works everywhere scapy + Npcap/libpcap is
available. Only packet injection/modification still needs platform code.
"""

import platform


def create_manipulator_backend(interface: str) -> "PacketManipulatorBackend":
    """Create the platform-appropriate packet manipulator backend."""
    sys_platform = platform.system().lower()

    if sys_platform == "windows":
        from core.network.platform.windows import WindowsManipulatorBackend
        return WindowsManipulatorBackend(interface)
    elif sys_platform == "linux":
        from core.network.platform.linux import LinuxManipulatorBackend
        return LinuxManipulatorBackend(interface)
    else:
        raise NotImplementedError(
            f"Manipulator backend not implemented for platform '{sys_platform}' "
            "(supported: windows, linux)"
        )


__all__ = [
    "create_manipulator_backend",
]
