"""Host plumbing extracted from the MITM route: privileges, firewall, probes."""
import platform
import subprocess

import pytest

from modules import mitm_admin


@pytest.fixture
def linux(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    return monkeypatch


def test_is_admin_follows_euid_on_posix(linux):
    linux.setattr(mitm_admin.os, "geteuid", lambda: 0, raising=False)
    assert mitm_admin.is_admin() is True
    linux.setattr(mitm_admin.os, "geteuid", lambda: 1000, raising=False)
    assert mitm_admin.is_admin() is False


def test_is_admin_is_false_when_the_check_itself_fails(linux):
    def explode():
        raise OSError("no geteuid here")

    linux.setattr(mitm_admin.os, "geteuid", explode, raising=False)
    assert mitm_admin.is_admin() is False


def test_firewall_helpers_are_noops_off_windows(linux):
    calls = []
    linux.setattr(subprocess, "run", lambda *a, **k: calls.append(a))
    assert mitm_admin.ensure_windows_firewall(8080) is True
    mitm_admin.remove_windows_firewall(8080)
    assert calls == []


def test_windows_firewall_passes_arguments_without_a_shell(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    calls = []

    class Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return Completed()

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert mitm_admin.ensure_windows_firewall(8080) is True
    argv, kwargs = calls[0]
    assert argv[:4] == ["netsh", "advfirewall", "firewall", "show"]
    assert "shell" not in kwargs

    assert mitm_admin.ensure_windows_firewall(8080) is True
    argv, _ = calls[-1]
    assert "add" in argv and "localport=8080" in argv
    # A shell string would be one element and would re-open SEC-01.
    assert isinstance(argv, list) and all(isinstance(part, str) for part in argv)


def test_darwin_pipe_is_rewritten_without_a_shell(monkeypatch):
    calls = []

    class Completed:
        stdout = b""
        returncode = 0

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return Completed()

    monkeypatch.setattr(subprocess, "run", fake_run)
    mitm_admin.exec_darwin_redirect("echo 'rdr pass on en0 proto tcp to port 443 -> 127.0.0.1 port 8082' | pfctl -ef -")

    argv, kwargs = calls[0]
    assert argv == ["pfctl", "-ef", "-"]
    assert kwargs["input"].startswith(b"rdr pass")
    assert "shell" not in kwargs


def test_reachability_returns_only_unanswered_targets(monkeypatch):
    def fake_probe(ip, timeout=1.0):
        return ip if ip.endswith(".66") else None

    monkeypatch.setattr(mitm_admin, "probe_one_target", fake_probe)

    import asyncio

    silent = asyncio.run(mitm_admin.probe_target_reachability(["10.0.0.5", "10.0.0.66"]))
    assert silent == ["10.0.0.66"]


def test_probe_failure_counts_as_unreachable(monkeypatch):
    import scapy.all

    def explode(*args, **kwargs):
        raise RuntimeError("no raw sockets")

    monkeypatch.setattr(scapy.all, "srp", explode)
    assert mitm_admin.probe_one_target("10.0.0.7") == "10.0.0.7"
