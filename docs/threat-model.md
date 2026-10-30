# Nyx Threat Model (STRIDE)

**Version:** 2.0
**Date:** 2026-10-30
**Author:** Nyx Developer

## Scope

This threat model covers Nyx — a desktop security testing suite with:
- A local FastAPI backend (ports 8000, 8080, 8082, 8085)
- An Electron shell with embedded Chromium renderer
- MITM interception (ARP, DHCP, DNS, NDP spoofing + transparent proxy)
- A local SQLite database
- A CA certificate for TLS decryption

**Out of scope:** The collaborator service (separate binary), network
infrastructure outside Nyx's control, and the target device's OS.

## Trust Boundaries

```
┌─────────────────────────────────────────────┐
│          Trust Boundary: Nyx Process         │
│                                               │
│  ┌─────────┐   HTTP    ┌──────────────┐      │
│  │Electron │◄────────►│ FastAPI       │      │
│  │Renderer │  WS       │ Backend       │      │
│  └─────────┘           └──────┬───────┘      │
│                               │               │
│                    ┌──────────▼──────────┐    │
│                    │   mitmproxy Engine   │    │
│                    └──────────┬──────────┘    │
│                               │               │
│                    ┌──────────▼──────────┐    │
│                    │   SQLite nyx.db      │    │
│                    └─────────────────────┘    │
│                                               │
│  ┌──────────────────────────────────────────┐ │
│  │         Trust Boundary: OS               │ │
│  │  ┌────────┐  ┌──────────┐ ┌───────────┐  │ │
│  │  │nyx.secret│  │CA cert   │ │Temp logs   │  │ │
│  │  └────────┘  └──────────┘ └───────────┘  │ │
│  └──────────────────────────────────────────┘ │
└─────────────────────────────────────────────┘

External (untrusted):
  • Target devices (LAN, MITM targets)
  • Websites contacted through the proxy
  • Other software on the same machine
```

## Threat Analysis

### 1. Spoofing

| Threat | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Attacker on LAN impersonates Nyx's API | Low (localhost only) | High | API binds to 127.0.0.1 (not 0.0.0.0). Only CA portal binds to 0.0.0.0. |
| Attacker forges CA certificate to match Nyx | Low | High | `isNyxMitmCert()` in Electron main verifies leaf against CA's public key cryptographically, not by name. |
| Attacker on LAN spoofs the CA portal (port 18081) | Low | Medium | CA portal serves static pages only; certificate download requires the user to trust and install. |

### 2. Tampering

| Threat | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Attacker modifies `nyx.db` to inject malicious data | Low (requires filesystem access) | Medium | SQLite WAL mode with busy_timeout. No external write access in normal operation. |
| Attacker modifies `nyx.secret` to control API keys | Low (requires filesystem access) | High | File is `chmod 0o600`, single-writer with threading lock. |
| MITM target modifies intercepted traffic | Medium | Low | mitmproxy validates TLS certificates; Nyx only intercepts traffic it chooses to. |
| Attacker modifies Nyx binary/installer | Low | High | Code signing (Windows Authenticode via electron-builder). Users should verify signatures. |

### 3. Repudiation

| Threat | Likelihood | Impact | Mitigation |
|---|---|---|---|
| User denies performing a scan/interception | Low | Low | Audit trail logs all significant actions (MITM start/stop, scan launch, project changes) with timestamps. |
| No proof of traffic interception for compliance reports | Medium | Low | PCAP export provides cryptographic proof at network layer. Database provides application-layer proof. |

### 4. Information Disclosure

| Threat | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `nyx-backend.log` in %TEMP% contains credentials in cleartext | Medium | High | Sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`) are redacted to `[REDACTED]` before storage. Structured JSON logging available for SIEM integration. |
| `nyx.db` contains all intercepted traffic in cleartext | Medium | Critical | Retention policy: max 100k requests or 7-day TTL. Full disk encryption (BitLocker/FileVault) is the user's responsibility. |
| WebSocket leaks traffic to foreign browser tabs | Low | High | `validate_ws_origin()` checks the `Origin` header against loopback hosts and the local UI/Vite ports. |
| Local process opens `/ws/traffic` with no Origin and streams captured traffic | Low | High | `validate_ws_token()` requires the per-boot token in token mode (`X-Nyx-Token` header, or `?token=` because browsers cannot set WS headers); a rejected upgrade is closed with code 1008 before any event is sent. |
| `/api/auth/key` hands the API key to any local process | Low | Medium | No longer in `_TOKEN_EXEMPT_PATHS`: the route requires the same per-boot token as the rest of the API in token mode. Only the CA download/QR/uninstall pages and `/api/mitm/portal*` stay exempt (a target device's browser must reach them). |
| CA private key exposed | Low | Critical | CA is generated by mitmproxy and stored in `~/.mitmproxy/`. Standard filesystem permissions apply. In production deployments, the CA should be stored in an HSM. |
| API key exposed in URL query string | Low | Medium | API key is passed in `X-API-Key` header, never in URL. |
| CSP bypass allows XSS in Nyx UI | Low | High | CSP header: `default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'`. No `unsafe-eval` or `unsafe-inline` for scripts. |

### 5. Denial of Service

| Threat | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Buggy React frontend hammers /api/proxy/requests at 1 kHz | Low | Medium | Token-bucket rate limiter per IP: remote callers get `RATE_LIMIT_RPS`/`RATE_LIMIT_BURST` (default 100 rps, burst 50), loopback and trusted-proxy callers get `RATE_LIMIT_RPS_LOCAL`/`RATE_LIMIT_BURST_LOCAL` (default 600 rps, burst 300) so legitimate sweeps are not throttled; the UI retries idempotent calls on 429 with backoff. |
| Burp import padded with ~5 KB of comments smuggles a DOCTYPE past the prefix check, expanding internal entities | Low | Medium | `modules/importer/burp.py` scans the **whole** document for `<!DOCTYPE`/`<!ENTITY` and rejects it before parsing; a Burp export never contains one. |
| EventBus handler blocks the event loop | Low | High | Bounded semaphore (max 50 concurrent tasks). Timeout of 5s per task acquisition. |
| Database grows unbounded until disk is full | Medium | High | Janitor loop purges old requests every 10 minutes. Configurable limits: `MAX_STORED_REQUESTS=100000`, `REQUEST_RETENTION_HOURS=168`. |
| WinDivert proxy leaves orphaned API on port 8085 | Low | Medium | `_stop_windivert()` explicitly calls `api.server_close()`. The startup check detects foreign API instances and refuses. |
| MITM spoofing blackholes target's internet | Medium | High | Startup guard: transparent transport must be ready BEFORE spoofing starts. IP forwarding is verified after enabling. |

### 6. Elevation of Privilege

| Threat | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Malware on the same machine uses Nyx's API to intercept traffic | Low (requires local access) | High | API key for non-localhost connections, plus the per-boot token in token mode (`API_REQUIRE_SESSION_TOKEN`): a local process that cannot read `NYX_HOME/session.token` gets 403 even on loopback. |
| A client omits `session_id` (or sends a malformed one) and probes a target outside the engagement scope | Medium | High | `core/authorization.py::authorize(..., require_session=True)` fails closed; `api/deps.py::ensure_authorized` maps `missing_session`/`invalid_session` to 400 and `out_of_scope`/`roe` to 403. Mandatory on active scanner, verifier, auto-exploit execute, crawler, A/B, content discovery, auth scan and repeater. |
| Scope preview answers with another session's rule and misleads the operator into an unauthorized probe | Low | Medium | `POST /api/scope/check` accepts `session_id` and filters to that session plus the legacy global (`session_id IS NULL`) rules. |
| Renderer process escapes Electron sandbox | Low | Critical | `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`. Preload only exposes 4 safe IPC methods. |
| Malicious website intercepted by Nyx exploits mitmproxy | Low | High | mitmproxy is a mature, audited library. Nyx runs it in its own thread with no shared memory. |

## Risk Matrix

| | Low Impact | Medium Impact | High Impact | Critical Impact |
|---|---|---|---|---|
| **High Likelihood** | — | — | — | — |
| **Medium Likelihood** | MITM target tampering | DB unbounded growth | MITM blackhole | DB cleartext traffic |
| **Low Likelihood** | Repudiation | Log file exposure | API key disclosure | CA key exposure, Sandbox escape |

## Residual Risks (Accepted)

1. **SQLite stores traffic in cleartext by default.** Full-disk encryption
   (BitLocker/FileVault/LUKS) on the host is an explicit requirement of running
   Nyx, not an optional nicety: header redaction cannot reach secrets inside a
   body. SQLCipher is available as an opt-in (`NYX_SQLCIPHER_KEY` +
   `pysqlcipher3`); when the key is set but the driver is missing, Nyx logs a
   warning and falls back to plaintext, which the startup log makes visible.
2. **CA portal on 0.0.0.0:18081 is reachable from LAN.** The portal only
   serves static pages; an attacker on the LAN could serve a malicious CA,
   but the user must explicitly trust and install it. The portal is essential
   for the DeployBox CA installation flow.
3. **No multi-user access control.** Nyx is a single-user desktop tool.
   Adding RBAC would require authentication infrastructure disproportionate
   to the threat model.

## Review Cadence

This threat model should be reviewed:
- After every major release (v1.x → v2.0)
- When a new network-facing feature is added
- When a new dependency is introduced
- At minimum, every 6 months