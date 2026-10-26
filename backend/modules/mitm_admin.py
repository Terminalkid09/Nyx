"""Host plumbing the MITM session needs: privileges, firewall, redirects, probes.

These helpers only touch the operating system. They live here instead of inside
``api/routes/mitm.py`` so the route module is about session orchestration, and
so the OS-specific behaviour can be read (and tested) in one place.

Nothing in this module keeps session state: every function takes what it needs
and returns it.
"""
from __future__ import annotations

import asyncio
import logging
import os
import platform
import subprocess

from core.proxy.engine import setup_transparent_redirect
from modules.ndp_spoof import is_ipv6

logger = logging.getLogger(__name__)


def is_admin() -> bool:
    try:
        if platform.system().lower() == "windows":
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception as exc:  # noqa: BLE001 — unknown platform is not an error
        logger.warning("Failed to check admin status: %s", exc)
        return False


def ensure_windows_firewall(port: int, protocol: str = "TCP", rule_prefix: str = "Nyx Proxy") -> bool:
    """Open a port for LAN devices if Windows Firewall would block it.

    Windows Firewall silently drops inbound connections on public/private
    profiles to ports that aren't explicitly allowed — the #1 reason a phone
    on the same Wi-Fi "sees" the proxy but nothing is ever intercepted.
    """
    if platform.system().lower() != "windows":
        return True
    rule_name = f"{rule_prefix} {protocol} {port}"
    try:
        check = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
            capture_output=True, text=True, timeout=20,
        )
        # Rule may not exist — query by name only finds it if present.
        if f"Rule Name:\n{rule_name}".replace("\0", "") in check.stdout or rule_name in check.stdout:
            logger.info("Firewall rule '%s' already present", rule_name)
            return True
        result = subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in", "action=allow", "protocol=" + protocol, f"localport={port}",
                "profile=any", "enable=yes",
            ],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            logger.info("Added firewall rule '%s' (port %d)", rule_name, port)
            return True
        logger.warning("Firewall rule failed (rc=%d): %s", result.returncode, result.stderr.strip()[:200])
        return False
    except Exception as exc:  # noqa: BLE001 — firewall trouble must not break the session
        logger.warning("Firewall rule error: %s", exc)
        return False


def remove_windows_firewall(proxy_port: int, protocol: str = "TCP", rule_prefix: str = "Nyx Proxy") -> None:
    if platform.system().lower() != "windows":
        return
    rule_name = f"{rule_prefix} {protocol} {proxy_port}"
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
            capture_output=True, text=True, timeout=20,
        )
        logger.info("Removed firewall rule '%s'", rule_name)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Firewall rule removal error: %s", exc)


def exec_darwin_redirect(cmd: str) -> None:
    """Execute a macOS redirect command without shell=True.

    The old code used ``shell=True`` for pipe commands like
    ``echo 'rule' | pfctl -ef -``. We now pipe the rule text directly into
    pfctl's stdin via subprocess, which is both injection-safe and shell-free.
    """
    if "|" in cmd:
        # Pipe command: decompose into left (echo/producer) and right (consumer)
        left_str, right_str = cmd.split("|", 1)
        left_str = left_str.strip()
        right_str = right_str.strip()
        if left_str.startswith("echo "):
            # ``echo 'rule text'`` → extract the rule and feed it to pfctl stdin
            rule_text = left_str[5:].strip("\"'")
            subprocess.run(
                right_str.split(), input=rule_text.encode(),
                check=True, capture_output=True,
            )
        else:
            producer = subprocess.run(left_str.split(), capture_output=True, check=True)
            subprocess.run(right_str.split(), input=producer.stdout, check=True, capture_output=True)
    else:
        subprocess.run(cmd.split(), check=True, capture_output=True)


def exec_admin_redirect(proxy_port: int, enable: bool) -> list[str]:
    """Apply (or remove) the transparent redirect rules, when we are allowed to."""
    commands = setup_transparent_redirect(proxy_port, enable)
    if not is_admin():
        return commands
    executed: list[str] = []
    for cmd in commands:
        try:
            system = platform.system().lower()
            if system == "linux" and (cmd.startswith("iptables") or cmd.startswith("sysctl")):
                subprocess.run(cmd.split(), check=True, capture_output=True)
                executed.append(cmd)
            elif system == "darwin":
                exec_darwin_redirect(cmd)
                executed.append(cmd)
        except subprocess.CalledProcessError as exc:
            logger.warning("Redirect command failed (may already be set): %s -> %s", cmd, exc)
    return executed


def probe_one_target(ip: str, timeout: float = 1.0) -> str | None:
    """Probe a single target; returns the IP if it did NOT respond."""
    try:
        if is_ipv6(ip):
            # IPv6: ICMPv6 echo via scapy (Neighbor Solicitation is
            # already handled by the NDP spoofer at runtime).
            from scapy.all import ICMPv6EchoRequest, IPv6, sr1

            clean = ip.split("%")[0]
            reply = sr1(IPv6(dst=clean) / ICMPv6EchoRequest(), timeout=timeout, verbose=0)
            return ip if reply is None else None
        from scapy.all import ARP, Ether, srp

        answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=timeout, verbose=0)
        return ip if not answered else None
    except Exception as exc:  # noqa: BLE001 — a failed probe proves nothing
        logger.debug("Reachability probe failed for %s: %s", ip, exc)
        return ip


async def probe_target_reachability(target_ips: list[str]) -> list[str]:
    """Best-effort client-isolation check (AP isolation / client isolation).

    Probes each target in PARALLEL with ARP who-has (IPv4) or ICMPv6 echo
    (IPv6); if a target answers none of the probes it may be isolated from us
    by the AP — which would make ARP/NDP spoofing useless. Returns the list
    of targets that did NOT respond. False positives are possible (sleeping
    device, firewall dropping probes), hence the result is surfaced as a
    warning, not a hard failure.
    """
    results = await asyncio.gather(
        *(asyncio.to_thread(probe_one_target, ip) for ip in target_ips)
    )
    return [ip for ip in results if ip]
