"""A busy port must move, not crash.

Every listener Nyx opens can collide with something already on the machine: a
dev server on 8000, another tool on 8080, an old Nyx instance still shutting
down on 18081. These tests pin the fallback and the fact that the WebSocket
origin check follows the API to whichever port it ends up on.
"""
import os
import socket
from types import SimpleNamespace

import pytest

from core.netports import is_port_free, pick_free_port
from core.proxy import engine as engine_module


def _hold_port(host: str = "127.0.0.1") -> tuple[socket.socket, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, 0))
    sock.listen(1)
    return sock, sock.getsockname()[1]


@pytest.mark.skipif(os.name != "nt", reason="SO_REUSEADDR hijack is Windows-specific")
def test_is_port_free_sees_a_reuseaddr_listener_on_the_wildcard_probe():
    """Regression: a 127.0.0.1 listener with SO_REUSEADDR looked free on 0.0.0.0.

    Windows let the probe bind the wildcard anyway, so the proxy reported
    "ready" on a port another process was still serving.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    try:
        assert is_port_free(port, host="0.0.0.0") is False
    finally:
        sock.close()


def test_is_port_free_reports_a_listening_socket():
    sock, port = _hold_port()
    try:
        assert is_port_free(port) is False
    finally:
        sock.close()
    assert is_port_free(port) is True


def test_pick_free_port_moves_past_the_busy_one():
    sock, port = _hold_port()
    try:
        chosen = pick_free_port(port)
        assert chosen != port
        assert is_port_free(chosen)
    finally:
        sock.close()


def _engine(port: int, mode: str = "regular"):
    class _Bus:
        pass

    return engine_module.ProxyEngine(_Bus(), host="127.0.0.1", port=port, mode=mode)


def test_engine_moves_the_proxy_when_its_port_is_taken(monkeypatch):
    monkeypatch.setattr(engine_module, "_port_in_use", lambda port: port == 8080)
    monkeypatch.setattr(engine_module, "pick_free_port", lambda start, host=None: 8081)

    engine = _engine(8080)
    try:
        assert engine._preflight_ports() is None
        assert engine.port == 8081
        # The firewall rules, PAC file and settings endpoint read this value.
        assert engine_module.settings.PROXY_PORT == 8081
    finally:
        engine_module.settings.PROXY_PORT = 8080


def test_engine_reports_when_no_neighbouring_port_is_free(monkeypatch):
    monkeypatch.setattr(engine_module, "_port_in_use", lambda port: True)
    monkeypatch.setattr(engine_module, "pick_free_port", lambda start, host=None: start - 1)

    engine = _engine(8080)
    message = engine._preflight_ports()
    assert message is not None
    assert "8080" in message


def test_engine_still_refuses_a_taken_transparent_port(monkeypatch):
    monkeypatch.setattr(engine_module, "_port_in_use", lambda port: port == engine_module.TRANSPARENT_PORT)
    monkeypatch.setattr(engine_module, "pick_free_port", lambda start, host=None: start + 1)

    engine = _engine(8080, mode="transparent")
    message = engine._preflight_ports()
    assert message is not None
    assert str(engine_module.TRANSPARENT_PORT) in message


def test_ca_portal_moves_to_the_next_free_port():
    from modules import ca_portal

    # The portal binds 0.0.0.0, so the blocker must hold the wildcard address.
    sock, busy = _hold_port("0.0.0.0")
    manager = ca_portal.CAPortalManager(port=busy)
    try:
        bound = manager.start()
        assert bound is not None
        assert bound != busy
        assert bound > busy
        # QR codes and the status payload build their URL from this value; a
        # stale DEFAULT_PORT would point phones at a port Nyx never opened.
        assert ca_portal.active_port() == bound
    finally:
        manager.stop()
        sock.close()


class _Url:
    def __init__(self, port):
        self.port = port
        self.scheme = "ws"


def test_ws_origin_allowed_on_the_same_fallback_port():
    from core.api_auth import validate_ws_origin

    ws = SimpleNamespace(
        headers={"origin": "http://127.0.0.1:8123"},
        url=_Url(8123),
    )
    assert validate_ws_origin(ws) is True


def test_ws_origin_still_rejects_a_different_local_port():
    from core.api_auth import validate_ws_origin

    ws = SimpleNamespace(
        headers={"origin": "http://127.0.0.1:9999"},
        url=_Url(8123),
    )
    assert validate_ws_origin(ws) is False
