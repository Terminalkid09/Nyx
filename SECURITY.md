# Security Policy

Nyx is a security testing tool. It ships a local API, a traffic-interception
proxy and (optionally) a transparent MITM stack, so a vulnerability here can
compromise the operator's machine and the devices under test.

## Supported versions

| Version | Supported |
|---|---|
| `main` (v1.x) | ✅ |
| Older tags | ❌ — use the latest release |

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's private reporting flow: *Security* → *Report a vulnerability*
(Security Advisories) on
[github.com/Terminalkid09/Nyx](https://github.com/Terminalkid09/Nyx/security/advisories/new).

Please include:

- affected version or commit,
- the component (`backend/`, `desktop/`, `frontend/`, `collaborator/`),
- reproduction steps or a proof of concept,
- impact you believe it has (local privilege, remote target, data exposure),
- whether the default configuration is affected.

We aim to acknowledge within 5 working days and to ship a fix or a documented
mitigation for confirmed high-severity issues as soon as practical. Please give
us a reasonable window before public disclosure.

## In scope

- The local API (`127.0.0.1:8000`): auth bypass, DNS-rebinding paths, command
  injection through request bodies, path traversal in downloads/exports.
- The proxy and MITM engine (`8080`, WinDivert/iptables, ARP/DHCP/NDP spoofing,
  WiFi AP mode): privilege escalation, unsafe shell invocation, certificate
  handling, traffic leaking outside the configured scope.
- The Electron shell and the integrated browser (`desktop/`): renderer
  isolation, remote content escaping the guards, unsafe preload/IPC surfaces,
  update channel abuse.
- The scanner and fuzzer: payloads that execute locally, findings that bypass
  the Rules-of-Engagement gate, denial of service of the operator's machine.
- Storage: findings/requests stored or exported in a way that leaks them to an
  unintended party.

## Out of scope

- Vulnerabilities in the **targets** you test with Nyx.
- Running Nyx with `DEBUG=true` or `SECRET_KEY=dev-secret` against untrusted
  networks.
- Operating-system level attacks that already require administrator/root.
- Missing hardening headers on the local SPA when it is only reachable from
  loopback.
- Reports produced by the user's own data (e.g. findings containing payloads).

## Safe defaults you should keep

- The API and proxy bind to `127.0.0.1` unless you deliberately change it.
- `SECRET_KEY` must be generated per install; the desktop app does this
  automatically.
- `TRUSTED_PROXY_CIDRS` is only for a reverse proxy you control.
- The SQLite database is **plaintext** unless `NYX_SQLCIPHER_KEY` is set and
  `pysqlcipher3` is installed — enable full-disk encryption if that matters.
- The Nyx CA certificate grants traffic decryption: install it only on devices
  you are authorized to test and remove it when the engagement ends.
