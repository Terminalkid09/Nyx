"""Regression tests for two MITM visibility bugs:

1. Request timestamps are stored as naive UTC by SQLite but serialized
   without an offset — the frontend parsed them as local time, showing
   fresh MITM captures as "2h ago" (the "testfire never appears in the
   Proxy tab" bug).
2. The Activity Monitor recorded every device whose traffic flows through
   the proxy (including leftover ARP caches from previous sessions), not
   just the selected targets.
"""
import uuid
from datetime import datetime, timezone

import pytest


class TestRequestTimestampSerialization:
    def test_naive_utc_timestamp_gets_utc_offset(self):
        from api.schemas.requests import RequestResponse

        req = RequestResponse(
            id=uuid.uuid4(),
            session_id=uuid.uuid4(),
            timestamp=datetime(2026, 8, 25, 16, 10, 52),  # naive, actually UTC
            method="GET",
            url="http://testfire.net/index.jsp",
            host="testfire.net",
            path="/index.jsp",
            http_version="HTTP/1.1",
            request_headers={},
            request_body=None,
            response_status=200,
            response_reason="OK",
            response_headers={},
            response_body="",
            response_content_type="text/html",
            response_size_bytes=0,
            response_time_ms=1,
            is_flagged=False,
            tags=[],
            api_type=None,
            tls_version=None,
            tls_cipher=None,
            notes=None,
        )
        out = req.model_dump_json()
        # Must carry an explicit UTC marker so JS parses it as UTC, not local.
        assert "2026-08-25T16:10:52" in out
        assert "+00:00" in out or "Z" in out

    def test_aware_timestamp_serializes_with_offset(self):
        from api.schemas.requests import RequestResponse

        req = RequestResponse(
            id=uuid.uuid4(),
            session_id=uuid.uuid4(),
            timestamp=datetime(2026, 8, 25, 18, 10, 52, tzinfo=timezone.utc),
            method="GET",
            url="http://x/",
            host="x",
            path="/",
            http_version="HTTP/1.1",
            request_headers={},
            request_body=None,
            response_status=None,
            response_reason=None,
            response_headers=None,
            response_body=None,
            response_content_type=None,
            response_size_bytes=None,
            response_time_ms=None,
            is_flagged=False,
            tags=[],
            api_type=None,
            tls_version=None,
            tls_cipher=None,
            notes=None,
        )
        out = req.model_dump_json()
        assert "+00:00" in out or "Z" in out


class _FakeEngine:
    def __init__(self, entries):
        self._entries = entries

    def activity_snapshot(self):
        return list(self._entries)


class TestActivityFilteredToTargets:
    def _snapshot(self):
        return [
            {"ip": "192.168.1.6", "host": "testfire.net", "count": 3},
            {"ip": "192.168.1.60", "host": "pagead2.googlesyndication.com", "count": 2},
            {"ip": "192.168.1.163", "host": "z-m-gateway.facebook.com", "count": 31},
            {"ip": "192.168.1.171", "host": "unagi-eu.amazon.com", "count": 1},
        ]

    def test_filters_to_selected_targets(self, monkeypatch):
        from api.routes import mitm as mitm_route

        class FakeSpoofer:
            target_ips = ["192.168.1.6", "192.168.1.60"]

        monkeypatch.setattr(mitm_route, "_spoofer", FakeSpoofer())
        monkeypatch.setattr(mitm_route, "_ndp_spoofer", None)
        monkeypatch.setattr(mitm_route, "_dhcp_spoofer", None)

        result = mitm_route._activity_for_targets(_FakeEngine(self._snapshot()))
        ips = {e["ip"] for e in result}
        assert ips == {"192.168.1.6", "192.168.1.60"}

    def test_no_targets_returns_full_snapshot(self, monkeypatch):
        from api.routes import mitm as mitm_route

        monkeypatch.setattr(mitm_route, "_spoofer", None)
        monkeypatch.setattr(mitm_route, "_ndp_spoofer", None)
        monkeypatch.setattr(mitm_route, "_dhcp_spoofer", None)

        result = mitm_route._activity_for_targets(_FakeEngine(self._snapshot()))
        assert len(result) == 4

    def test_includes_dhcp_lease_ips(self, monkeypatch):
        from api.routes import mitm as mitm_route

        class FakeDHCP:
            granted_leases = [{"ip": "192.168.1.99", "mac": "aa:bb:cc:dd:ee:ff"}]

        monkeypatch.setattr(mitm_route, "_spoofer", None)
        monkeypatch.setattr(mitm_route, "_ndp_spoofer", None)
        monkeypatch.setattr(mitm_route, "_dhcp_spoofer", FakeDHCP())

        result = mitm_route._activity_for_targets(
            _FakeEngine(self._snapshot() + [{"ip": "192.168.1.99", "host": "foo.com", "count": 1}])
        )
        ips = {e["ip"] for e in result}
        assert ips == {"192.168.1.99"}

    def test_engine_none_returns_empty(self, monkeypatch):
        from api.routes import mitm as mitm_route

        monkeypatch.setattr(mitm_route, "_spoofer", None)
        monkeypatch.setattr(mitm_route, "_ndp_spoofer", None)
        monkeypatch.setattr(mitm_route, "_dhcp_spoofer", None)

        assert mitm_route._activity_for_targets(None) == []
