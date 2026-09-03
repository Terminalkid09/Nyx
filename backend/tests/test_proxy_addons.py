"""Unit tests for the TLS-failure tracker addon."""
from types import SimpleNamespace

import pytest

from core.proxy.addons.tls_fail import TlsFailTracker


def _flow(client_ip="192.168.1.163", host="example.com"):
    return SimpleNamespace(
        client_conn=SimpleNamespace(peername=(client_ip, 40000)),
        request=SimpleNamespace(pretty_host=host),
        response=None,
    )


def _failed(data):
    return TlsFailTracker(SimpleNamespace()).tls_failed_client(data)


class TestTlsFailTracker:
    def test_records_failed_handshake_with_sni(self):
        tracker = TlsFailTracker(SimpleNamespace())
        tracker.tls_failed_client(
            SimpleNamespace(
                conn=SimpleNamespace(
                    sni="api.example.com",
                    server_address=("93.184.216.34", 443),
                    error="certificate unknown",
                )
            )
        )
        count, hosts = tracker.snapshot()
        assert count == 1
        assert hosts[0]["host"] == "api.example.com"
        assert hosts[0]["error"] == "certificate unknown"

    def test_falls_back_to_server_address_when_no_sni(self):
        tracker = TlsFailTracker(SimpleNamespace())
        tracker.tls_failed_client(
            SimpleNamespace(
                conn=SimpleNamespace(
                    sni=None,
                    server_address=("93.184.216.34", 443),
                    error="handshake failed",
                )
            )
        )
        _, hosts = tracker.snapshot()
        assert hosts[0]["host"] == "93.184.216.34:443"

    def test_unknown_host_when_nothing_available(self):
        tracker = TlsFailTracker(SimpleNamespace())
        tracker.tls_failed_client(SimpleNamespace(conn=SimpleNamespace(sni=None, server_address=None, error=None)))
        _, hosts = tracker.snapshot()
        assert hosts[0]["host"] == "unknown"

    def test_deque_limited_to_max_failed_hosts(self):
        tracker = TlsFailTracker(SimpleNamespace())
        for i in range(25):
            tracker.tls_failed_client(
                SimpleNamespace(
                    conn=SimpleNamespace(sni=f"h{i}.com", server_address=None, error="err")
                )
            )
        count, hosts = tracker.snapshot()
        assert count == 25
        assert len(hosts) == 20  # deque maxlen
        assert hosts[0]["host"] == "h24.com"  # most recent first

    def test_reset_clears_state(self):
        tracker = TlsFailTracker(SimpleNamespace())
        tracker.tls_failed_client(
            SimpleNamespace(conn=SimpleNamespace(sni="a.com", server_address=None, error="e"))
        )
        tracker.reset()
        count, hosts = tracker.snapshot()
        assert count == 0
        assert hosts == []

    def test_snapshot_does_not_leak_mutation(self):
        tracker = TlsFailTracker(SimpleNamespace())
        tracker.tls_failed_client(
            SimpleNamespace(conn=SimpleNamespace(sni="a.com", server_address=None, error="e"))
        )
        _, hosts = tracker.snapshot()
        hosts.append({"host": "b.com", "error": "x", "ts": 0})
        assert len(tracker.snapshot()[1]) == 1