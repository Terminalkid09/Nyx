"""Unit tests for the rogue DHCP spoofer (modules/dhcp_spoof.py).

No real sockets are bound and no packets are sent: socket/subprocess calls
are monkeypatched. scapy is only used to build/parse in-memory packets.
"""

import socket as _socket

import pytest


def _dgram_only_factory(mock_cls):
    """Return a socket.socket replacement that only mocks AF_INET/SOCK_DGRAM
    sockets (the DHCP server's), delegating everything else (e.g. asyncio's
    internal socketpair for the event loop) to the real implementation.
    Otherwise the patched class breaks asyncio teardown.
    """
    real_socket = _socket.socket

    def factory(*a, **k):
        fam = a[0] if a else k.get("family", _socket.AF_INET)
        typ = a[1] if len(a) > 1 else k.get("type", _socket.SOCK_STREAM)
        if fam == _socket.AF_INET and typ == _socket.SOCK_DGRAM:
            return mock_cls(*a, **k)
        return real_socket(*a, **k)

    return factory


def make_spoofer(**kw):
    from modules.dhcp_spoof import DHCPSpoofer

    defaults = dict(gateway_ip="192.168.1.50", dns_ip="192.168.1.1")
    defaults.update(kw)
    return DHCPSpoofer(**defaults)


class TestNetworkHelpers:
    def test_network_and_broadcast(self):
        spoofer = make_spoofer()
        assert str(spoofer._network()) == "192.168.1.0/24"
        assert spoofer._broadcast() == "192.168.1.255"

    def test_pick_ip_returns_requested_when_in_subnet(self):
        spoofer = make_spoofer()
        ip = spoofer._pick_ip("192.168.1.100")
        assert ip == "192.168.1.100"

    def test_pick_ip_rejects_out_of_subnet(self):
        spoofer = make_spoofer()
        ip = spoofer._pick_ip("10.0.0.5")
        assert ip != "10.0.0.5"
        # must be inside our /24
        assert ip.startswith("192.168.1.")

    def test_pick_ip_never_offers_the_gateway_itself(self):
        # gateway = our IP; the offered IP must never equal it
        spoofer = make_spoofer(gateway_ip="192.168.1.50")
        ip = spoofer._pick_ip("192.168.1.50")
        assert ip != "192.168.1.50"
        ip2 = spoofer._pick_ip(None)
        assert ip2 != "192.168.1.50"

    def test_pick_ip_default_low_address(self):
        spoofer = make_spoofer()
        assert spoofer._pick_ip(None) == "192.168.1.10"


class TestDetectSubnetMask:
    def test_windows_ipconfig_parsing(self, monkeypatch):
        import platform
        from modules import dhcp_spoof as m

        ipconfig_out = (
            "Ethernet adapter Ethernet:\n\n"
            "   Connection-specific DNS Suffix  . :\n"
            "   IPv4 Address. . . . . . . . . . . : 192.168.1.50\n"
            "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
            "   Default Gateway . . . . . . . . . : 192.168.1.1\n"
        )
        monkeypatch.setattr(platform, "system", lambda: "Windows")
        monkeypatch.setattr(
            m.subprocess, "check_output", lambda *a, **k: ipconfig_out.encode(),
        )
        assert m.detect_subnet_mask("192.168.1.50") == "255.255.255.0"

    def test_linux_ip_parsing(self, monkeypatch):
        import platform
        from modules import dhcp_spoof as m

        ip_out = (
            "3: wlan0    inet 192.168.1.50/24 brd 192.168.1.255 "
            "scope global dynamic noprefixroute wlan0\n"
        )
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        monkeypatch.setattr(
            m.subprocess, "check_output", lambda *a, **k: ip_out.encode(),
        )
        assert m.detect_subnet_mask("192.168.1.50") == "255.255.255.0"

    def test_macos_hex_netmask_parsing(self, monkeypatch):
        import platform
        from modules import dhcp_spoof as m

        ifconfig_out = (
            "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST>\n"
            "    inet 192.168.1.50 netmask 0xffffff00 broadcast 192.168.1.255\n"
        )
        monkeypatch.setattr(platform, "system", lambda: "Darwin")
        monkeypatch.setattr(
            m.subprocess, "check_output", lambda *a, **k: ifconfig_out.encode(),
        )
        assert m.detect_subnet_mask("192.168.1.50") == "255.255.255.0"

    def test_fallback_to_24(self, monkeypatch):
        import platform
        from modules import dhcp_spoof as m

        def boom(*a, **k):
            raise OSError("no ip command")

        monkeypatch.setattr(platform, "system", lambda: "Linux")
        monkeypatch.setattr(m.subprocess, "check_output", boom)
        assert m.detect_subnet_mask("192.168.1.50") == "255.255.255.0"


class TestParseMessage:
    def _discover(self, hostname=b"Galaxy-S25", xid=0x12345678):
        """Return the UDP PAYLOAD (BOOTP+DHCP) — exactly what a UDP socket
        delivers to recvfrom() (no IP/UDP headers)."""
        from scapy.all import BOOTP, DHCP

        pkt = (
            BOOTP(
                op=1,
                htype=1,
                hlen=6,
                xid=xid,
                chaddr=bytes.fromhex("aabbccddeeff"),
            )
            / DHCP(options=[("message-type", "discover"), ("hostname", hostname), ("end")])
        )
        return bytes(pkt)

    def test_parses_discover(self):
        spoofer = make_spoofer()
        msg = spoofer._parse_message(self._discover())
        assert msg["valid"] is True
        assert msg["type"] == 1  # DISCOVER
        assert msg["xid"] == 0x12345678
        assert msg["mac"] == "aa:bb:cc:dd:ee:ff"
        assert msg["hostname"] == "Galaxy-S25"
        assert msg["client_ip"] is None

    def test_rejects_non_dhcp_payload(self):
        spoofer = make_spoofer()
        # An IP-header first byte (0x45) is not a BOOTP op — must be rejected.
        msg = spoofer._parse_message(b"\x45\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        assert msg["valid"] is False

    def test_rejects_bootp_without_dhcp_cookie(self):
        spoofer = make_spoofer()
        # 240+ bytes starting with BOOTREQUEST but no DHCP magic cookie.
        payload = b"\x01" + b"\x00" * 239
        msg = spoofer._parse_message(payload)
        assert msg["valid"] is False


class TestBuildReply:
    def _msg(self):
        spoofer = make_spoofer()
        from scapy.all import BOOTP, DHCP

        pkt = (
            BOOTP(op=1, htype=1, hlen=6, xid=0xABCDEF01, chaddr=bytes.fromhex("001122334455"))
            / DHCP(options=[("message-type", "discover"), ("end")])
        )
        return spoofer._parse_message(bytes(pkt))

    @staticmethod
    def _opts(options):
        """Safe option dict (skips the bare b'end' marker)."""
        out = {}
        for item in options:
            if isinstance(item, tuple) and len(item) == 2:
                out[item[0]] = item[1]
        return out

    @staticmethod
    def _parse_reply(reply: bytes):
        """Dissect a payload-only BOOTP/DHCP reply (kernel adds IP/UDP)."""
        from scapy.all import BOOTP

        bootp = BOOTP(reply)
        # scapy attaches the DHCP options layer as BOOTP's payload.
        return bootp, bootp.payload

    def test_offer_has_correct_options(self):

        spoofer = make_spoofer()
        msg = self._msg()
        reply = spoofer._build_reply(msg, 2, "192.168.1.100")
        assert reply is not None
        bootp, dhcp = self._parse_reply(reply)
        assert bootp.yiaddr == "192.168.1.100"
        opts = self._opts(dhcp.options)
        assert opts["message-type"] == 2  # OFFER
        assert opts["server_id"] == "192.168.1.50"  # Nyx as gateway
        assert opts["router"] == "192.168.1.50"
        # DNS must point at the REAL resolver, never at Nyx itself
        assert opts["name_server"] == "192.168.1.1"
        assert opts["subnet_mask"] == "255.255.255.0"
        assert opts["lease_time"] == 86400

    def test_ack_keeps_requested_ip(self):

        spoofer = make_spoofer()
        msg = self._msg()
        reply = spoofer._build_reply(msg, 5, "192.168.1.77")
        bootp, dhcp = self._parse_reply(reply)
        assert bootp.yiaddr == "192.168.1.77"
        opts = self._opts(dhcp.options)
        assert opts["message-type"] == 5  # ACK

    def test_reply_is_payload_only_not_full_ip_packet(self):
        """Regression: the reply must NOT contain an IP header — sending a
        full IP packet through the UDP socket nests a second IP header inside
        the UDP payload and every DHCP client drops it (nothing intercepted).
        """
        from scapy.all import IP

        spoofer = make_spoofer()
        msg = self._msg()
        reply = spoofer._build_reply(msg, 2, "192.168.1.100")
        assert reply is not None
        # The payload starts with the BOOTP op field (1 byte = 2 for reply),
        # not with an IP version nibble (0x45).
        assert reply[0] == 2
        # Parsing the payload as an IP packet must fail (it is not IP).
        try:
            IP(reply)
            assert False, "reply should not parse as a full IP packet"
        except Exception:
            pass


class TestHandleDhcpExchange:
    """End-to-end in-memory exchange: DISCOVER -> OFFER, REQUEST(us) -> ACK
    (lease granted), REQUEST(router) for a TARGET -> NAK, for a non-target ->
    ignored."""

    TARGET_MAC = "aa:bb:cc:dd:ee:ff"
    OTHER_MAC = "11:22:33:44:55:66"

    class FakeSock:
        def __init__(self):
            self.sent: list[bytes] = []

        def sendto(self, data, addr):
            self.sent.append(bytes(data))

    def _spoofer(self):
        from modules.dhcp_spoof import DHCPSpoofer

        spoofer = DHCPSpoofer(
            gateway_ip="192.168.1.50",
            dns_ip="192.168.1.1",
            target_macs={self.TARGET_MAC},
        )
        spoofer._sock = self.FakeSock()
        return spoofer

    @staticmethod
    def _request_payload(mac_hex: str, server_id: str | None, xid=0xDEADBEEF):
        from scapy.all import BOOTP, DHCP

        opts = [("message-type", "request"), ("end")]
        if server_id is not None:
            opts = [("message-type", "request"), ("server_id", server_id), ("end")]
        return bytes(
            BOOTP(
                op=1, htype=1, hlen=6, xid=xid, chaddr=bytes.fromhex(mac_hex)
            )
            / DHCP(options=opts)
        )

    @staticmethod
    def _discover_payload(mac_hex: str, xid=0x12345678):
        from scapy.all import BOOTP, DHCP

        return bytes(
            BOOTP(op=1, htype=1, hlen=6, xid=xid, chaddr=bytes.fromhex(mac_hex))
            / DHCP(options=[("message-type", "discover"), ("end")])
        )

    @staticmethod
    def _opts(options):
        out = {}
        for item in options:
            if isinstance(item, tuple) and len(item) == 2:
                out[item[0]] = item[1]
        return out

    def test_discover_sends_offer_and_counts(self):
        from scapy.all import BOOTP

        spoofer = self._spoofer()
        spoofer._handle(self._discover_payload(self.TARGET_MAC.replace(":", "")), None)

        assert spoofer.offers_sent == 1
        assert spoofer.lease_requests == 0
        assert len(spoofer._sock.sent) == 1
        reply = spoofer._sock.sent[0]
        bootp = BOOTP(reply)
        opts = self._opts(bootp.payload.options)
        assert opts["message-type"] == 2  # OFFER
        assert bootp.yiaddr == "192.168.1.10"

    def test_request_with_server_us_grants_lease(self):
        from scapy.all import BOOTP

        spoofer = self._spoofer()
        spoofer._handle(
            self._request_payload(self.TARGET_MAC.replace(":", ""), "192.168.1.50"),
            None,
        )

        assert spoofer.lease_requests == 1
        assert spoofer.naks_sent == 0
        assert len(spoofer.granted_leases) == 1
        assert spoofer.granted_leases[0]["mac"] == self.TARGET_MAC
        assert spoofer.granted_leases[0]["ip"] == "192.168.1.10"
        bootp = BOOTP(spoofer._sock.sent[0])
        assert self._opts(bootp.payload.options)["message-type"] == 5  # ACK

    def test_init_reboot_request_without_server_grants_lease(self):
        spoofer = self._spoofer()
        spoofer._handle(
            self._request_payload(self.TARGET_MAC.replace(":", ""), None),
            None,
        )
        assert spoofer.lease_requests == 1
        assert len(spoofer.granted_leases) == 1

    def test_request_to_router_for_target_sends_nak(self):
        from scapy.all import BOOTP

        spoofer = self._spoofer()
        spoofer._handle(
            self._request_payload(self.TARGET_MAC.replace(":", ""), "192.168.1.1"),
            None,
        )

        assert spoofer.naks_sent == 1
        assert spoofer.lease_requests == 0
        assert spoofer.offers_sent == 0
        bootp = BOOTP(spoofer._sock.sent[0])
        assert self._opts(bootp.payload.options)["message-type"] == 6  # NAK
        # A NAK must not offer an address (RFC 2131 §4.3.2).
        assert str(bootp.yiaddr) == "0.0.0.0"

    def test_request_to_router_for_foreign_device_ignored(self):
        spoofer = self._spoofer()
        spoofer._handle(
            self._request_payload(self.OTHER_MAC.replace(":", ""), "192.168.1.1"),
            None,
        )
        assert spoofer.naks_sent == 0
        assert spoofer.lease_requests == 0
        assert spoofer._sock.sent == []

    def test_manual_parse_rejects_full_ip_packet(self):
        """The hot path parses the UDP PAYLOAD only — a full IP packet
        (as a socket delivers none) must be rejected, not misinterpreted."""
        from scapy.all import IP, UDP

        payload = self._discover_payload(self.TARGET_MAC.replace(":", ""))
        full = bytes(IP(src="192.168.1.100", dst="255.255.255.255") / UDP(sport=68, dport=67) / payload)
        spoofer = self._spoofer()
        msg = spoofer._parse_message(full)
        assert msg["valid"] is False


class TestUniqueLeaseAllocation:
    """Two intercepted devices must never receive the same lease address."""

    def test_two_macs_get_different_ips(self):
        spoofer = make_spoofer()
        ip1 = spoofer._pick_ip(None, "aa:bb:cc:dd:ee:01")
        spoofer.granted_leases.append({"mac": "aa:bb:cc:dd:ee:01", "ip": ip1, "ts": 0})
        ip2 = spoofer._pick_ip(None, "aa:bb:cc:dd:ee:02")
        assert ip1 != ip2

    def test_same_mac_regets_its_own_ip(self):
        spoofer = make_spoofer()
        ip1 = spoofer._pick_ip("192.168.1.77", "aa:bb:cc:dd:ee:01")
        spoofer.granted_leases.append({"mac": "aa:bb:cc:dd:ee:01", "ip": ip1, "ts": 0})
        # Renewal from the same client: its own address stays available.
        assert spoofer._pick_ip("192.168.1.77", "aa:bb:cc:dd:ee:01") == "192.168.1.77"

    def test_requested_ip_taken_by_other_client_is_skipped(self):
        spoofer = make_spoofer()
        spoofer.granted_leases.append(
            {"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.1.100", "ts": 0}
        )
        # A different client asking for the leased address gets another one.
        ip2 = spoofer._pick_ip("192.168.1.100", "aa:bb:cc:dd:ee:02")
        assert ip2 != "192.168.1.100"
        assert ip2.startswith("192.168.1.")


class TestHealResponder:
    """Post-stop lease healing: NAK only renewals of OUR leases; never
    answer DISCOVER (new devices must not be hijacked after stop)."""

    TARGET_MAC = "aa:bb:cc:dd:ee:ff"
    OTHER_MAC = "11:22:33:44:55:66"

    class FakeSock:
        def __init__(self):
            self.sent: list[bytes] = []

        def sendto(self, data, addr):
            self.sent.append(bytes(data))

    def _spoofer_with_lease(self):
        spoofer = make_spoofer(target_macs={self.TARGET_MAC})
        spoofer.granted_leases.append(
            {"mac": self.TARGET_MAC, "ip": "192.168.1.10", "ts": 0}
        )
        return spoofer

    def _request(self, mac_hex: str, server_id: str | None):
        from scapy.all import BOOTP, DHCP

        opts = [("message-type", "request")]
        if server_id is not None:
            opts.append(("server_id", server_id))
        opts.append("end")
        return bytes(
            BOOTP(op=1, htype=1, hlen=6, xid=0xCAFE0001, chaddr=bytes.fromhex(mac_hex))
            / DHCP(options=opts)
        )

    def _discover(self, mac_hex: str):
        from scapy.all import BOOTP, DHCP

        return bytes(
            BOOTP(op=1, htype=1, hlen=6, xid=0xCAFE0002, chaddr=bytes.fromhex(mac_hex))
            / DHCP(options=[("message-type", "discover"), ("end")])
        )

    def _opts(self, options):
        out = {}
        for item in options:
            if isinstance(item, tuple) and len(item) == 2:
                out[item[0]] = item[1]
        return out

    def test_renewal_of_our_lease_gets_nak(self):
        from scapy.all import BOOTP

        spoofer = self._spoofer_with_lease()
        sock = self.FakeSock()
        spoofer._heal_handle(sock, self._request(self.TARGET_MAC.replace(":", ""), "192.168.1.50"), {self.TARGET_MAC})

        assert spoofer.healed_leases == 1
        assert len(sock.sent) == 1
        bootp = BOOTP(sock.sent[0])
        assert self._opts(bootp.payload.options)["message-type"] == 6  # NAK

    def test_discover_is_never_answered_in_heal_mode(self):
        spoofer = self._spoofer_with_lease()
        sock = self.FakeSock()
        spoofer._heal_handle(sock, self._discover(self.TARGET_MAC.replace(":", "")), {self.TARGET_MAC})

        assert sock.sent == []
        assert spoofer.healed_leases == 0

    def test_unknown_client_renewal_is_ignored(self):
        spoofer = self._spoofer_with_lease()
        sock = self.FakeSock()
        spoofer._heal_handle(sock, self._request(self.OTHER_MAC.replace(":", ""), "192.168.1.50"), {self.TARGET_MAC})

        assert sock.sent == []
        assert spoofer.healed_leases == 0

    def test_renewal_to_real_router_is_ignored(self):
        spoofer = self._spoofer_with_lease()
        sock = self.FakeSock()
        spoofer._heal_handle(sock, self._request(self.TARGET_MAC.replace(":", ""), "192.168.1.1"), {self.TARGET_MAC})

        assert sock.sent == []
        assert spoofer.healed_leases == 0


class TestStartBindDetection:
    """start() must report whether UDP/67 actually bound (anti-blackhole)."""

    @pytest.mark.asyncio
    async def test_start_returns_false_when_bind_fails(self, monkeypatch):
        from modules import dhcp_spoof as m

        class FailingSock:
            def __init__(self, *a, **k):
                pass

            def setsockopt(self, *a, **k):
                pass

            def bind(self, *a, **k):
                raise PermissionError("admin required")

        monkeypatch.setattr(m.socket, "socket", _dgram_only_factory(FailingSock))
        spoofer = make_spoofer()

        ok = await spoofer.start()
        await spoofer.stop()
        assert ok is False

    @pytest.mark.asyncio
    async def test_start_returns_true_when_bind_succeeds(self, monkeypatch):
        from modules import dhcp_spoof as m

        class OkSock:
            def __init__(self, *a, **k):
                pass

            def setsockopt(self, *a, **k):
                pass

            def bind(self, *a, **k):
                pass

            def close(self):
                pass

            def recvfrom(self, n):
                raise OSError("stop loop for test")

        monkeypatch.setattr(m.socket, "socket", _dgram_only_factory(OkSock))
        spoofer = make_spoofer()

        ok = await spoofer.start()
        assert spoofer._bound.is_set()
        await spoofer.stop()
        assert ok is True


class TestDualBindPlatform:
    """The DHCP server must NOT create the interface-pinned reply socket on
    Windows: a second SO_REUSEADDR bind on the same UDP port steals the port
    from the DISCOVER socket, so the rogue server never hears a request."""

    @staticmethod
    def _spoof(m, monkeypatch, system):
        import platform

        binds: list = []
        created: list = []

        class RecSock:
            def __init__(self, *a, **k):
                created.append(self)

            def setsockopt(self, *a, **k):
                pass

            def bind(self, addr):
                binds.append(addr)

            def close(self):
                pass

            def recvfrom(self, n):
                raise OSError("stop loop for test")

        monkeypatch.setattr(platform, "system", lambda: system)
        monkeypatch.setattr(m.socket, "socket", _dgram_only_factory(RecSock))
        return created, binds

    @pytest.mark.asyncio
    async def test_windows_uses_single_socket_only(self, monkeypatch):
        from modules import dhcp_spoof as m

        created, binds = self._spoof(m, monkeypatch, "Windows")
        spoofer = make_spoofer()

        ok = await spoofer.start()
        assert ok is True
        # Only one dgram socket, bound to the wildcard — never a second
        # bind that would steal the port on Windows.
        assert len(created) == 1
        assert binds == [("0.0.0.0", 67)]
        await spoofer.stop()

    @pytest.mark.asyncio
    async def test_posix_keeps_interface_pinned_tx_socket(self, monkeypatch):
        from modules import dhcp_spoof as m

        created, binds = self._spoof(m, monkeypatch, "Linux")
        spoofer = make_spoofer()  # gateway_ip = 192.168.1.50

        ok = await spoofer.start()
        assert ok is True
        # rx socket + interface-pinned tx socket (safe on POSIX).
        assert len(created) == 2
        assert binds == [("0.0.0.0", 67), ("192.168.1.50", 67)]
        await spoofer.stop()
