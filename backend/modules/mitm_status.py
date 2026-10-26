"""The status snapshot the MITM page polls.

Every value the UI needs to decide "is interception actually working" is
assembled here from the current session objects. The session objects are passed
in explicitly instead of being read from module globals, so this file has no
hidden state: it turns a snapshot into the JSON the UI consumes.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

from core.proxy.engine import quic_dropped_count, windivert_forwarded_count, windivert_last_forwarded
from core.storage.traffic import MITM_SESSION_ID
from modules.ca_portal import DEFAULT_PORT as CA_PORTAL_PORT


def activity_for_targets(engine, spoofer, ndp_spoofer, dhcp_spoofer) -> list[dict]:
    """Activity snapshot restricted to the currently selected targets.

    The ActivityTracker records every flow that reaches the proxy, which
    includes devices with *leftover* ARP caches from previous sessions (their
    traffic still flows through Nyx even though they are no longer targets).
    The monitor is labelled "domains contacted by each target", so it should
    only show the devices the user actually selected.
    """
    targets: set[str] = set()
    if spoofer is not None:
        targets.update(getattr(spoofer, "target_ips", []) or [])
    if ndp_spoofer is not None:
        targets.update(getattr(ndp_spoofer, "target_ips", []) or [])
    if dhcp_spoofer is not None:
        leases = getattr(dhcp_spoofer, "granted_leases", []) or []
        targets.update(lease.get("ip") for lease in leases if lease.get("ip"))
        # NOTE: DHCP targets are identified by MAC, so until a lease is
        # granted the monitor stays empty (no IP to match yet) — honest.
    if engine is None:
        return []
    snapshot = engine.activity_snapshot() or []
    if not targets:
        return snapshot[:60]
    filtered = [entry for entry in snapshot if entry.get("ip") in targets]
    # If every entry was filtered out, the phone is probably on a new DHCP IP
    # — surface that instead of showing an empty monitor.
    return filtered[:60]


async def captured_flows_since(session_started_ts: datetime | None) -> tuple[int, str | None]:
    """Count the flows the proxy captured during THIS MITM session."""
    try:
        from sqlalchemy import func, select

        from core.storage.database import AsyncSessionLocal
        from core.storage.models import Request

        async with AsyncSessionLocal() as db:
            query = select(func.count(), func.max(Request.timestamp)).where(
                Request.session_id == MITM_SESSION_ID
            )
            if session_started_ts is not None:
                query = query.where(Request.timestamp >= session_started_ts)
            result = await db.execute(query)
            count, latest = result.one()
            if latest is not None:
                # SQLite returns naive UTC datetimes — tag them so the
                # frontend parses the timestamp correctly.
                if latest.tzinfo is None:
                    latest = latest.replace(tzinfo=timezone.utc)
                return count or 0, latest.astimezone(timezone.utc).isoformat()
            return count or 0, None
    except Exception:  # noqa: BLE001 — a status poll must never 500
        return 0, None


async def build_status(
    *,
    engine,
    spoofer,
    ndp_spoofer,
    dhcp_spoofer,
    dns_spoofer,
    dns_spoof_error: str | None,
    redirect_active: bool,
    mitm_session_started_ts: datetime | None,
    dhcp_started_ts: float | None,
    dhcp_grace_no_discover: float,
    dhcp_grace_race_lost: float,
    admin_mode: bool,
    local_ip: str | None,
) -> dict:
    arp_running = spoofer is not None and getattr(spoofer, "_running", False)
    ndp_running = ndp_spoofer is not None and getattr(ndp_spoofer, "_running", False)
    dhcp_running = dhcp_spoofer is not None
    dns_running = dns_spoofer is not None and getattr(dns_spoofer, "_running", False)

    # How many requests the proxy has captured during the CURRENT MITM
    # session (since the last start). The dedicated MITM session accumulates
    # across runs, so counting its whole history would show old data as
    # "flows captured" right after a fresh start.
    proxy_count, last_traffic_seen = (
        await captured_flows_since(mitm_session_started_ts) if engine else (0, None)
    )

    transport_ready = bool(engine and getattr(engine, "transport_ready", False))
    # "active" = an interception session is currently running (spoofers live).
    # This drives the UI's Start/Stop button — the user must always be able to
    # stop, even if the transport is degraded.
    session_active = bool(
        spoofer is not None or dns_spoofer is not None or ndp_spoofer is not None or dhcp_spoofer is not None
    )

    # Seconds until the auto-mode ARP fallback kicks in (None when DHCP is
    # not waiting on anything: converted, already fell back, or not auto).
    dhcp_fallback_in: float | None = None
    if (
        dhcp_spoofer is not None
        and spoofer is None
        and dhcp_spoofer.lease_requests == 0
        and dhcp_started_ts is not None
    ):
        elapsed = time.time() - dhcp_started_ts
        if dhcp_spoofer.offers_sent == 0:
            dhcp_fallback_in = max(0.0, dhcp_grace_no_discover - elapsed)
        else:
            dhcp_fallback_in = max(0.0, dhcp_grace_race_lost - elapsed)

    last_arp_sent: str | None = None
    if spoofer is not None and spoofer.last_send_ts:
        last_arp_sent = datetime.fromtimestamp(spoofer.last_send_ts, tz=timezone.utc).isoformat()

    last_forwarded = windivert_last_forwarded()
    return {
        "active": session_active,
        "transport_ready": transport_ready,
        "arp_spoofing": arp_running,
        "ndp_spoofing": ndp_running,
        "dhcp_spoofing": dhcp_running,
        "dhcp_offers": dhcp_spoofer.offers_sent if dhcp_spoofer else 0,
        "dhcp_lease_requests": dhcp_spoofer.lease_requests if dhcp_spoofer else 0,
        "dhcp_naks": dhcp_spoofer.naks_sent if dhcp_spoofer else 0,
        "dhcp_granted_ips": [lease["ip"] for lease in dhcp_spoofer.granted_leases] if dhcp_spoofer else [],
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
            datetime.fromtimestamp(last_forwarded, tz=timezone.utc).isoformat() if last_forwarded else None
        ),
        # TLS handshakes the TARGET rejected (CA not trusted): the phone tried
        # to reach these hosts but aborted before any flow existed. Count +
        # recent hosts let the UI show "requests" even when no flow decrypts.
        "tls_handshake_failures": engine.tls_failures()[0] if engine else 0,
        "tls_failed_hosts": engine.tls_failures()[1] if engine else [],
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
        # Filtered to the *selected* targets: the tracker records every device
        # whose traffic flows through the proxy (leftover ARP caches from past
        # sessions included), which made the monitor show unrelated phones.
        "activity": activity_for_targets(engine, spoofer, ndp_spoofer, dhcp_spoofer) if engine else [],
        "dns_spoofing": dns_running,
        "dns_spoof_error": dns_spoof_error,
        "target_ips": spoofer.target_ips if spoofer else (ndp_spoofer.target_ips if ndp_spoofer else []),
        "gateway_ip": spoofer.gateway_ip if spoofer else (ndp_spoofer.gateway_ip6 if ndp_spoofer else None),
        "admin_mode": admin_mode,
        "proxy_mode": engine.mode if engine else None,
        "redirect_active": redirect_active,
        "captured_flows": proxy_count,
        # Last time the proxy actually handled a flow — lets the UI warn when
        # "active" but nothing has flowed for a while (firewall/CA/QUIC/DoH).
        "last_traffic_seen": last_traffic_seen,
        # Stealth (manual proxy) helper data — lets the UI show exactly how
        # to point a target device at Nyx without ARP spoofing.
        "local_ip": local_ip if local_ip != "127.0.0.1" else None,
        "proxy_host": engine.host if engine else None,
        "proxy_port": engine.port if engine else None,
        # User-controlled: True = decrypt HTTPS with the Nyx CA (target must
        # trust the CA via DeployBox); False = HTTPS tunnelled untouched, only
        # plain HTTP is intercepted. Toggle via POST /api/mitm/tls.
        "tls_mitm": engine.tls_mitm if engine else True,
    }
