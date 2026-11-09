# -*- mode: python ; coding: utf-8 -*-
import sys
import os
from pathlib import Path
import site

ROOT = Path(os.getcwd())
BACKEND = ROOT / "backend"

# Find asyncpg.pgproto .pyd file for bundled inclusion
_asyncpg_pgproto_pyd = None
for _dir in site.getsitepackages():
    _p = Path(_dir) / "asyncpg" / "pgproto"
    if _p.is_dir():
        for _f in _p.iterdir():
            if _f.suffix == ".pyd" and _f.name.startswith("pgproto"):
                _asyncpg_pgproto_pyd = str(_f)
                break
    if _asyncpg_pgproto_pyd:
        break

# Find pydivert windivert_dll files for bundled inclusion (Windows only)
_pydivert_binaries = []
_site_pkgs = site.getsitepackages()
if hasattr(site, "getusersitepackages"):
    _site_pkgs.append(site.getusersitepackages())

for _dir in _site_pkgs:
    _p = Path(_dir) / "pydivert" / "windivert_dll"
    if _p.is_dir():
        for _f in _p.iterdir():
            if _f.suffix in [".dll", ".sys"]:
                _pydivert_binaries.append((str(_f), "pydivert/windivert_dll"))
        break

block_cipher = None

a = Analysis(
    [str(BACKEND / "main.py")],
    pathex=[str(BACKEND)],
    binaries=(
        [(_asyncpg_pgproto_pyd, "asyncpg/pgproto")] if _asyncpg_pgproto_pyd else []
    ) + _pydivert_binaries,
    datas=[
        # NOTE: backend/data/ is intentionally NOT bundled. It is gitignored
        # (contains nyx.secret and machine-local state) and every consumer
        # self-heals it at runtime (mkdir + defaults). Bundling it crashed
        # PyInstaller on clean checkouts (release CI) and would risk leaking
        # local secrets into distributed binaries.
        (str(BACKEND / "alembic.ini"), "."),
        (str(BACKEND / "alembic"), "alembic"),
        (str(BACKEND / "wordlists"), "wordlists"),
        (str(BACKEND / "modules/fuzzer/wordlists"), "modules/fuzzer/wordlists"),
        (str(BACKEND / "reporter/templates"), "reporter/templates"),
    ],
    hiddenimports=[
        "uvicorn",
        "uvicorn.logging",
        "uvicorn.loops.auto",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.websockets.auto",
        "sqlalchemy",
        "sqlalchemy.ext.asyncio",
        "sqlalchemy.sql",
        "sqlalchemy.dialects.sqlite",
        "aiosqlite",
        "httpx",
        "pydantic",
        "pydantic_settings",
        "jinja2",
        "mitmproxy",
        "mitmproxy.tools.dump",
        "scapy",
        "scapy.all",
        "modules.scanner.passive.scanner",
        "modules.scanner.active.scanner",
        "modules.scanner.scan_depth",
        "modules.scanner.active.checks.active_oast",
        "modules.scanner.active.checks.active_xss_context",
        "modules.scanner.active.checks.active_sqli_blind",
        "modules.scanner.active.checks.active_time_blind",
        "modules.scanner.passive.checks.passive_info_disclosure",
        "modules.scanner.passive.checks.passive_tech_fingerprint",
        "modules.fuzzer.service",
        "modules.decoder.service",
        "modules.sequencer.service",
        "modules.interceptor.engine",
        "modules.session_handling.engine",
        "modules.match_replace.engine",
        "modules.automation.engine",
        "modules.pipeline.orchestrator",
        "modules.live_audit.service",
        "modules.automations.scheduled_scans",
        "modules.automations.webhooks",
        "modules.automations.scan_templates",
        "modules.proxy_config.service",
        "modules.arp_spoof",
        "modules.ndp_spoof",
        "modules.dns_spoof",
        "modules.dhcp_spoof",
        "modules.vendor_lookup",
        "modules.clickbandit.service",
        "modules.auth.models",
        "modules.auth.store",
        "reporter.service",
        "modules.content_discovery.service",
        "modules.fuzzer.wordlists",
        "modules.crawler.service",
        "modules.http_client",
        "modules.auto_exploit.engine",
        "core.proxy.addons.logger",
        "core.events.bus",
        "core.storage.database",
        "core.storage.models",
        "core.storage.traffic",
        "core.storage.finding_events",
        "core.scope",
        "api.routes",
        "api.routes.mitm",
        "api.routes.settings",
        "api.routes.auth_scan",
        "api.websocket.manager",
        "api.deps",
        "core.proxy.addons",
        "core.proxy.addons.logger",
        "pydivert",
        "pydivert.windivert_dll",
        "pydivert.windivert_dll.structs",
        "core.proxy.addons.logger",
        "core.proxy.addons.activity",
        "core.api_auth",
        "qrcode",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "PyQt5",
        "PySide2",
        "PySide6",
        "numpy",
        "matplotlib",
        "scipy",
        "pandas",
        "cv2",
        "IPython",
        "jupyter",
        "notebook",
        "test",
        "unittest",
        "pytest",
        "distutils",
        "setuptools",
        "wheel",
        "pip",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="nyx-backend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)