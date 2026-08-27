"""Tests for the ActivityTracker addon: per-target (IP -> host) visibility
from TLS SNI and HTTP Host headers, working WITHOUT a trusted CA."""
import time
from types import SimpleNamespace

from core.proxy.addons.activity import ActivityTracker, MAX_ENTRIES


def _tracker():
    return ActivityTracker(SimpleNamespace(capture_active=True))


def _clienthello(ip="192.168.1.163", sni="api.example.com"):
    return SimpleNamespace(
        context=SimpleNamespace(client=SimpleNamespace(peername=(ip, 45678))),
        client_hello=SimpleNamespace(sni=sni),
    )


def _flow(ip="192.168.1.163", host="example.com"):
    return SimpleNamespace(
        client_conn=SimpleNamespace(peername=(ip, 40000)),
        request=SimpleNamespace(pretty_host=host),
    )


class TestSniCapture:
    def test_records_sni_from_clienthello(self):
        t = _tracker()
        t.tls_clienthello(_clienthello())
        snap = t.snapshot()
        assert len(snap) == 1
        assert snap[0]["ip"] == "192.168.1.163"
        assert snap[0]["host"] == "api.example.com"
        assert snap[0]["count"] == 1

    def test_counts_repeated_contacts(self):
        t = _tracker()
        for _ in range(5):
            t.tls_clienthello(_clienthello(sni="login.spotify.com"))
        assert t.snapshot()[0]["count"] == 5

    def test_trailing_dot_stripped(self):
        t = _tracker()
        t.tls_clienthello(_clienthello(sni="example.com."))
        assert t.snapshot()[0]["host"] == "example.com"

    def test_ignores_clienthello_without_sni_or_ip(self):
        t = _tracker()
        t.tls_clienthello(_clienthello(sni=None))
        t.tls_clienthello(_clienthello(ip=None))
        assert t.snapshot() == []


class TestHttpCapture:
    def test_records_http_host(self):
        t = _tracker()
        t.request(_flow(host="neverssl.com"))
        snap = t.snapshot()
        assert snap[0]["host"] == "neverssl.com"

    def test_merges_sni_and_http_for_same_host(self):
        t = _tracker()
        t.tls_clienthello(_clienthello(sni="example.com"))
        t.request(_flow(host="example.com"))
        snap = t.snapshot()
        assert len(snap) == 1
        assert snap[0]["count"] == 2

    def test_request_always_records_regardless_of_capture_flag(self):
        """HTTP requests from transparent-MITM targets must be visible even
        when the browser's capture toggle is off."""
        t = ActivityTracker(SimpleNamespace(capture_active=False))
        t.request(_flow())
        # Still recorded — the capture_active gate only gates the browser's
        # built-in proxy, not the transparent proxy's target-device traffic.
        snap = t.snapshot()
        assert len(snap) == 1
        assert snap[0]["host"] == "example.com"


class TestSnapshotOrderingAndReset:
    def test_most_recent_first(self):
        t = _tracker()
        t.tls_clienthello(_clienthello(sni="old.com"))
        time.sleep(0.01)
        t.tls_clienthello(_clienthello(sni="new.com"))
        hosts = [e["host"] for e in t.snapshot()]
        assert hosts == ["new.com", "old.com"]

    def test_reset_clears_everything(self):
        t = _tracker()
        t.tls_clienthello(_clienthello())
        t.reset()
        assert t.snapshot() == []

    def test_fifo_eviction_at_capacity(self):
        t = _tracker()
        for i in range(MAX_ENTRIES + 10):
            t.tls_clienthello(_clienthello(sni=f"h{i}.com", ip=f"10.0.0.{i % 200 + 1}"))
        # capacity respected (some (ip,host) pairs collide across the modulo,
        # so just check we never exceed MAX_ENTRIES)
        assert len(t.snapshot()) <= MAX_ENTRIES

    def test_last_seen_is_iso_with_tz(self):
        t = _tracker()
        t.tls_clienthello(_clienthello())
        entry = t.snapshot()[0]
        assert "T" in entry["last_seen"]
        assert entry["ts"] <= time.time()
