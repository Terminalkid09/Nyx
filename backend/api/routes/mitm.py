import asyncio
import ipaddress as _ipaddress
import logging
import os
import platform
import subprocess

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.proxy.engine import ProxyEngine, setup_transparent_redirect
from modules.arp_spoof import ARPSpoofer, _get_local_ip, _get_mac, _get_hostname
from modules.dns_spoof import DNSSpoofer

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/mitm", tags=["mitm"])

_engine: ProxyEngine | None = None
_spoofer: ARPSpoofer | None = None
_dns_spoofer: DNSSpoofer | None = None
_redirect_active = False
_captured_request_count: int = 0


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
        _ensure_windows_firewall(8082)


async def shutdown_mitm():
    """Release MITM resources at backend shutdown (firewall rules, redirects)."""
    global _spoofer, _dns_spoofer, _redirect_active
    if _dns_spoofer:
        await _dns_spoofer.stop()
        _dns_spoofer = None
    if _spoofer:
        await _spoofer.stop()
        _spoofer = None
    if _redirect_active and _engine is not None:
        _exec_admin_redirect(_engine.port, enable=False)
        _redirect_active = False
    if _engine:
        _remove_windows_firewall(_engine.port)
        _remove_windows_firewall(8082)
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


def _ensure_windows_firewall(port: int) -> bool:
    """Open the proxy port for LAN devices if Windows Firewall would block it.

    Windows Firewall silently drops inbound connections on public/private
    profiles to ports that aren't explicitly allowed — the #1 reason a phone
    on the same Wi-Fi "sees" the proxy but nothing is ever intercepted.
    """
    if platform.system().lower() != "windows":
        return True
    rule_name = f"Nyx Proxy TCP {port}"
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
                "dir=in", "action=allow", "protocol=TCP", f"localport={port}",
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


def _remove_windows_firewall(proxy_port: int):
    if platform.system().lower() != "windows":
        return
    rule_name = f"Nyx Proxy TCP {proxy_port}"
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
            # NOTE: renamed from `sys` to avoid shadowing the stdlib `sys` module
            sys_platform = platform.system().lower()
            if sys_platform == "linux" and (cmd.startswith("iptables") or cmd.startswith("sysctl")):
                subprocess.run(cmd.split(), check=True, capture_output=True)
                executed.append(cmd)
            elif sys_platform == "darwin" and (cmd.startswith("pfctl") or cmd.startswith("sysctl") or cmd.startswith("echo")):
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
                executed.append(cmd)
        except subprocess.CalledProcessError as e:
            logger.warning("Redirect command failed (may already be set): %s -> %s", cmd, e)
    return executed


class MITMStartRequest(BaseModel):
    target_ips: list[str]
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


class NetworkDevice(BaseModel):
    ip: str
    mac: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    is_local: bool = False


_KNOWN_VENDORS = {
    # Networking & routers
    "00:00:0c": "Cisco", "00:1a:a0": "Cisco", "00:17:9a": "Cisco",
    "00:1e:58": "Cisco", "00:1f:9e": "Cisco", "00:23:32": "Cisco",
    "14:58:d0": "Cisco", "cc:31:47": "Cisco",
    "00:18:71": "TP-Link", "00:1e:65": "TP-Link", "00:21:6a": "TP-Link",
    "08:8e:8f": "TP-Link", "0c:da:41": "TP-Link", "1c:5f:2b": "TP-Link",
    "20:20:c7": "TP-Link", "50:c7:bf": "TP-Link", "54:e6:fc": "TP-Link",
    "00:0a:e4": "Netgear", "00:10:db": "Netgear", "00:19:cb": "Netgear",
    "00:1d:72": "Netgear", "18:1d:ea": "Netgear", "1c:06:f3": "Netgear",
    "1c:0f:cf": "Netgear", "a0:40:41": "Netgear",
    "00:09:5b": "D-Link", "00:1f:33": "D-Link", "14:5a:5d": "D-Link",
    "00:05:5d": "Zyxel", "00:13:10": "Aruba", "00:14:5c": "Ruckus",
    "00:12:17": "Linksys",
    "08:74:02": "Intel",
    # Smartphones — Apple
    "00:03:93": "Apple", "00:18:4d": "Apple", "00:1c:c0": "Apple",
    "00:1d:60": "Apple", "00:1e:52": "Apple", "00:1f:3a": "Apple",
    "00:1f:45": "Apple", "00:1f:c6": "Apple", "00:21:63": "Apple",
    "00:21:91": "Apple", "00:22:3f": "Apple", "00:22:75": "Apple",
    "00:22:b0": "Apple", "00:23:14": "Apple",
    "0c:9d:92": "Apple", "0c:9e:c4": "Apple", "18:00:4d": "Apple",
    "1c:23:2c": "Apple",
    # Smartphones — Samsung
    "00:18:39": "Samsung", "00:1d:7e": "Samsung", "00:23:d4": "Samsung",
    "08:e6:89": "Samsung", "08:fc:88": "Samsung", "0c:54:15": "Samsung",
    "0c:ae:7d": "Samsung", "0c:fa:c4": "Samsung",
    "10:2e:af": "Samsung", "10:8c:cf": "Samsung", "14:68:13": "Samsung",
    "14:7d:da": "Samsung", "14:99:e2": "Samsung",
    "18:31:bf": "Samsung", "18:3d:a2": "Samsung", "18:6f:42": "Samsung",
    "18:b7:9e": "Samsung", "18:b8:1f": "Samsung", "18:f6:43": "Samsung",
    "1c:cc:d8": "Samsung", "1c:db:44": "Samsung",
    "20:08:ed": "Samsung", "20:4c:03": "Samsung", "20:68:9d": "Samsung",
    "20:7c:14": "Samsung", "20:95:8b": "Samsung", "20:be:c8": "Samsung",
    "20:c0:8b": "Samsung", "20:d9:06": "Samsung", "20:da:22": "Samsung",
    "24:4c:ab": "Samsung", "24:ab:81": "Samsung",
    "28:98:7b": "Samsung", "2c:2d:48": "Samsung", "2c:61:04": "Samsung",
    "30:cd:a7": "Samsung", "34:12:f9": "Samsung", "34:a8:4e": "Samsung",
    "38:bc:01": "Samsung", "3c:7d:3e": "Samsung", "3c:8c:f8": "Samsung",
    "4c:5f:70": "Samsung", "50:02:91": "Samsung",
    "54:8c:a0": "Samsung", "54:be:f7": "Samsung",
    "5c:49:79": "Samsung", "5c:51:4f": "Samsung",
    "60:a4:d0": "Samsung", "64:1c:67": "Samsung", "64:6e:69": "Samsung",
    "6c:6d:05": "Samsung",
    "70:4d:7b": "Samsung", "70:85:c2": "Samsung",
    "74:2f:68": "Samsung", "74:75:e3": "Samsung",
    "78:52:1a": "Samsung",
    "7c:2a:88": "Samsung", "7c:b3:7e": "Samsung",
    "80:30:dc": "Samsung", "84:61:a2": "Samsung",
    "88:6b:6f": "Samsung",
    "8c:2e:a0": "Samsung", "8c:59:36": "Samsung",
    "90:17:ac": "Samsung",
    "98:80:bb": "Samsung", "9c:2a:70": "Samsung", "9c:93:4e": "Samsung",
    "ac:5f:3e": "Samsung",
    "b0:4c:05": "Samsung", "b4:07:f9": "Samsung", "b4:51:d9": "Samsung",
    "b8:8d:12": "Samsung", "bc:72:b1": "Samsung",
    "c0:7b:bc": "Samsung", "c4:22:46": "Samsung", "c8:94:bb": "Samsung",
    "cc:3d:82": "Samsung",
    "d0:17:6a": "Samsung", "d4:5d:62": "Samsung", "d8:08:8b": "Samsung",
    "dc:0b:34": "Samsung",
    "e0:63:da": "Samsung", "e4:5c:51": "Samsung", "e8:84:29": "Samsung",
    "ec:1f:72": "Samsung",
    "f0:27:65": "Samsung", "f4:03:bf": "Samsung", "f8:08:4f": "Samsung",
    "fc:af:6a": "Samsung",
    # Smartphones — others
    "00:28:37": "Google", "1c:b9:c4": "Google", "3c:5a:b4": "Google",
    "1c:3a:4f": "HTC", "1c:91:80": "OnePlus", "1c:bf:ce": "OnePlus",
    "14:c1:4e": "Xiaomi", "1c:7b:21": "Xiaomi", "1c:9d:72": "Xiaomi",
    "1c:bd:b9": "Xiaomi", "f0:03:8c": "Xiaomi",
    "20:3c:ae": "Huawei", "38:f9:d3": "Huawei", "40:ed:00": "Huawei",
    "14:73:a2": "LG", "18:87:96": "LG", "18:c5:4a": "LG", "00:22:2d": "LG",
    "1c:87:76": "Motorola", "18:8b:9d": "Motorola",
    # Chipset / SoC (often appears in phones)
    "00:0a:f5": "Qualcomm", "98:ce:bb": "Qualcomm", "b0:e7:54": "Qualcomm",
    "c0:ee:fb": "Qualcomm", "dc:37:14": "Qualcomm", "e0:e7:6a": "Qualcomm",
    "00:1a:45": "MediaTek", "10:6f:d9": "MediaTek", "1c:60:7e": "MediaTek",
    "2c:f0:ee": "MediaTek", "38:2c:4a": "MediaTek",
    "a4:99:47": "Broadcom",
    # PCs & servers
    "00:0c:29": "VMware", "08:00:27": "Oracle (VirtualBox)",
    "00:15:5d": "Microsoft", "00:23:4e": "Microsoft", "00:50:56": "VMware",
    "00:17:31": "HP", "1c:ba:8c": "HP", "18:b4:30": "HP", "00:23:5a": "HP",
    "00:12:bf": "Dell", "00:14:22": "Dell", "00:1a:6b": "Dell",
    "00:21:cc": "Dell", "00:22:41": "Dell", "1c:db:96": "Dell",
    "18:66:da": "Dell", "00:22:55": "Lenovo", "1c:1b:68": "Lenovo",
    "00:20:a6": "IBM",
    "00:16:36": "Intel", "00:1a:3f": "Intel", "00:1c:bf": "Intel",
    "00:1f:3c": "Intel", "00:22:a4": "Intel",
    "14:14:4b": "Intel", "14:22:db": "Intel", "14:ab:c5": "Intel",
    "14:b3:1f": "Intel", "18:26:26": "Intel", "18:65:90": "Intel",
    "1c:15:1f": "Intel", "1c:1b:0d": "Intel", "1c:5c:55": "Intel",
    "1c:aa:07": "Intel", "20:1a:06": "Intel", "20:47:47": "Intel",
    "20:4e:7f": "Intel", "20:d5:bf": "Intel", "20:db:ab": "Intel",
    "08:00:46": "Intel", "08:be:09": "Intel", "08:d4:2b": "Intel",
    "08:f6:b8": "Intel", "0c:4b:54": "Intel", "08:9e:01": "Intel",
    # IoT & embedded
    "00:26:68": "Raspberry Pi", "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "08:b2:2e": "Amazon", "08:ed:b9": "Amazon", "0c:7a:3e": "Amazon",
    "0c:8b:fd": "Amazon (Echo)", "18:a9:05": "Amazon",
    "00:1b:63": "Nintendo", "0c:b4:ef": "Nintendo", "a4:52:6f": "Nintendo",
    "08:c5:e1": "ASUS", "00:22:fa": "Asus", "10:7c:61": "ASUS",
    "00:1b:21": "Broadcom", "00:19:07": "Atheros", "00:1c:10": "Belkin",
    "0c:6e:8a": "Liteon",
    # Other
    "00:18:0a": "Sony", "14:c8:8b": "Sony", "00:22:6b": "Sony",
    "00:10:18": "3COM", "00:01:42": "Nortel",
    "00:04:0e": "Ericsson", "00:04:de": "LG",
    "00:1b:2f": "Sharp", "00:21:2f": "Vizio",
    "18:56:80": "Xerox", "00:1a:2b": "Panasonic",
    "00:0e:f6": "Xbox", "dc:2b:61": "Xbox", "5c:f9:38": "PlayStation",
    "10:06:1c": "Petkit", "c8:d7:78": "BSH (Bosch/Siemens)",
    "20:b0:01": "Vantiva (Technicolor)", "ec:2e:98": "AzureWave",
}


def _lookup_vendor_online(mac: str) -> str | None:
    try:
        import urllib.request
        url = f"https://api.macvendors.com/{mac}"
        resp = urllib.request.urlopen(url, timeout=3)
        if resp.status == 200:
            return resp.read().decode("utf-8").strip()
    except Exception as e:
        logger.debug("Vendor lookup failed for %s: %s", mac, e)
    return None


def _is_randomized_mac(mac: str) -> bool:
    first = mac.split(":")[0]
    try:
        b = int(first, 16)
        return bool(b & 0x02)
    except Exception as e:
        logger.debug("Failed to check randomized MAC for %s: %s", mac, e)
        return False

_HOSTNAME_VENDORS = [
    (r"(?i)\bS25\b", "Samsung Galaxy S25"),
    (r"(?i)\bS24\b", "Samsung Galaxy S24"),
    (r"(?i)\bS23\b", "Samsung Galaxy S23"),
    (r"(?i)\bS22\b", "Samsung Galaxy S22"),
    (r"(?i)\bS21\b", "Samsung Galaxy S21"),
    (r"(?i)\bA33\b", "Samsung Galaxy A33"),
    (r"(?i)\bA34\b", "Samsung Galaxy A34"),
    (r"(?i)\bA35\b", "Samsung Galaxy A35"),
    (r"(?i)\bA5[1-5]\b", "Samsung Galaxy A"),
    (r"(?i)\bGalaxy\b", "Samsung Galaxy"),
    (r"(?i)\bSamsung\b", "Samsung"),
    (r"(?i)\biPhone\b", "Apple iPhone"),
    (r"(?i)\biPad\b", "Apple iPad"),
    (r"(?i)\bMacBook\b", "Apple MacBook"),
    (r"(?i)\bApple\b", "Apple"),
    (r"(?i)\bPixel\b", "Google Pixel"),
    (r"(?i)\bNexus\b", "Google"),
    (r"(?i)\bOnePlus\b", "OnePlus"),
    (r"(?i)\bXiaomi\b", "Xiaomi"),
    (r"(?i)\bRedmi\b", "Xiaomi Redmi"),
    (r"(?i)\bPOCO\b", "Xiaomi POCO"),
    (r"(?i)\bHuawei\b", "Huawei"),
    (r"(?i)\bHonor\b", "Honor"),
    (r"(?i)\bOppo\b", "OPPO"),
    (r"(?i)\bVivo\b", "vivo"),
    (r"(?i)\bPetkit\b", "Petkit"),
    (r"(?i)\bRoomba\b", "iRobot Roomba"),
    (r"(?i)\bModemTIM\b", "TIM Modem (Vantiva)"),
    (r"(?i)\bmihome\b", "Xiaomi Mi Home"),
]


def _guess_vendor_from_hostname(hostname: str | None) -> str | None:
    if not hostname:
        return None
    for pattern, name in _HOSTNAME_VENDORS:
        import re
        if re.search(pattern, hostname):
            return name
    return None


async def _lookup_vendor(mac: str, hostname: str | None = None) -> str | None:
    if not mac:
        return None
    prefix = mac[:8].lower()
    cached = _KNOWN_VENDORS.get(prefix)
    if cached:
        return cached
    # If MAC is randomized (locally administered), skip OUI lookup
    if _is_randomized_mac(mac):
        vendor = _guess_vendor_from_hostname(hostname)
        if vendor:
            _KNOWN_VENDORS[prefix] = vendor
        return vendor
    vendor = await asyncio.to_thread(lambda: _lookup_vendor_online(mac))
    if vendor:
        _KNOWN_VENDORS[prefix] = vendor
    return vendor


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
    global _spoofer, _dns_spoofer, _redirect_active

    if _engine is None:
        raise HTTPException(status_code=500, detail="Proxy engine not initialized")

    if _spoofer is not None or _dns_spoofer is not None:
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
        ok, msg = _engine.switch_to_transparent()
        if not ok:
            logger.error("Failed to switch to transparent mode: %s", msg)
            raise HTTPException(500, detail=f"Failed to switch proxy to transparent mode: {msg}")

    _redirect_active = True
    if platform.system().lower() == "windows":
        logger.info("WinDivert handles port redirection on Windows — no iptables redirect needed")
        firewall_ok = False
        for p in {_engine.port, 8082}:
            if _ensure_windows_firewall(p):
                firewall_ok = True
        if not firewall_ok:
            warnings.append(
                "Could not add Windows Firewall rule for the proxy port — "
                "the target device may not reach the proxy. Launch Nyx as "
                "Administrator or allow the port manually."
            )
    else:
        cmds = _exec_admin_redirect(_engine.port, enable=True)
        if not cmds:
            logger.warning("No redirect commands executed. ARP + transparent proxy may not capture traffic.")
            _redirect_active = False
        else:
            logger.info("Port redirection commands executed: %s", cmds)
            _redirect_active = True

    _spoofer = ARPSpoofer(target_ips=req.target_ips, gateway_ip=req.gateway_ip)
    try:
        await _spoofer.start()
    except Exception as e:
        logger.error("ARP spoofing failed to start: %s", e)
        _spoofer = None
        raise HTTPException(500, detail=f"ARP spoofing failed: {e}")

    dns_active = False
    if req.enable_dns_spoof:
        # spoof_ip must be OUR local IP so targets resolve domains to us.
        # Using "0.0.0.0" here was a bug — it caused the target to get
        # unreachable addresses instead of routing traffic through Nyx.
        local_ip = _get_local_ip()
        _dns_spoofer = DNSSpoofer(spoof_ip=local_ip)
        try:
            await _dns_spoofer.start()
            dns_active = True
            logger.info("DNS spoofing active: all DNS queries -> %s", local_ip)
        except Exception as e:
            logger.error("DNS spoofing failed to start: %s", e)
            _dns_spoofer = None
            warnings.append("DNS spoofing failed to start.")

    if not admin:
        warnings.append("Not running as administrator. ARP spoofing and port redirection require admin rights.")
    if not _redirect_active:
        warnings.append("Port redirection not active. Traffic on port 80/443 will not reach the proxy.")

    targets_str = ", ".join(req.target_ips)
    return MITMStartResponse(
        status="ok",
        message=(
            f"MITM active against {len(req.target_ips)} target(s): {targets_str}. "
            f"ARP spoofing {_spoofer.gateway_ip} <-> {targets_str}. "
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
        # Disable the redirect using the real proxy port — setup_transparent_redirect
        # keys its rules off the port, so passing 0 would build nonsensical commands.
        if _engine is not None:
            _exec_admin_redirect(_engine.port, enable=False)
        _redirect_active = False

    # NOTE: the Windows Firewall rule for the proxy port is intentionally NOT
    # removed here. It stays open for the whole backend lifetime so devices
    # configured with a manual proxy (Stealth Mode) can still reach Nyx after
    # interception is stopped; it is only removed at shutdown (shutdown_mitm).

    return MITMStopResponse(
        status="ok",
        message="MITM stopped. Traffic restored.",
    )


@router.get("/status")
async def mitm_status():
    global _spoofer, _dns_spoofer, _captured_request_count
    arp_running = _spoofer is not None and getattr(_spoofer, '_running', False)
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
                    from datetime import datetime, timezone
                    last_traffic_seen = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        except Exception:
            proxy_count = 0
    local_ip = _get_local_ip()
    # "active" only when traffic is actually being redirected into Nyx —
    # ARP/DNS merely being started as tasks isn't sufficient (e.g. a raw
    # socket that failed to open, or iptables redirect that couldn't be set).
    capture_working = _redirect_active and (arp_running or dns_running)
    return {
        "active": capture_working,
        "arp_spoofing": arp_running,
        "dns_spoofing": dns_running,
        "target_ips": _spoofer.target_ips if _spoofer else [],
        "gateway_ip": _spoofer.gateway_ip if _spoofer else None,
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
    }
