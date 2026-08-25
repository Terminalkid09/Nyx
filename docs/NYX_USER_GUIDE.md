# Nyx User Guide

> **Version:** 1.0.0  
> **Platform:** Windows / macOS / Linux

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [Dashboard](#2-dashboard)
3. [Proxy & Traffic Interception](#3-proxy--traffic-interception)
4. [Crawler](#4-crawler)
5. [Scanner](#5-scanner)
6. [Repeater](#6-repeater)
7. [Decoder](#7-decoder)
8. [Fuzzer](#8-fuzzer)
9. [Session Handling](#9-session-handling)
10. [Report Generation](#10-report-generation)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Getting Started

### Desktop App (Recommended)

1. Install and launch Nyx
2. The Electron app starts the backend automatically and opens the UI
3. You should see the **Dashboard** with live stats

### Development Mode

**Terminal 1 — Backend:**
```bash
cd backend
uvicorn main:app --host 127.0.0.1 --port 8000
```

**Terminal 2 — Frontend:**
```bash
cd frontend
npm run dev
# Opens at http://localhost:5173
```

---

## 2. Dashboard

The Dashboard shows real-time security testing stats.

**Quick Action buttons:**
- **Browser** (Electron only) — Launches a proxied browser window
- **New Scan** — Start a new active scan
- **Proxy** — View intercepted traffic
- **Findings** — View security findings
- **Repeater** — Replay HTTP requests
- **Fuzzer** — Parameter fuzzing
- **Automation** — Scheduled scans
- **Live** — Live audit mode

**Stats Cards:**
- Total Findings — all vulnerabilities discovered
- Active Scans — currently running scans
- Endpoints — total discovered endpoints
- Proxy Today — proxy requests today
- Scan History — historical scan jobs

**Charts:**
- Findings by Severity (donut chart)
- 14-Day Finding Trend (line chart)
- Top Vulnerability Types (bar chart)

---

## 3. Proxy & Traffic Interception

### Start Interception

1. Go to **Proxy Config**
2. Set **Proxy Host** to `0.0.0.0`
3. Set **Proxy Port** to `8080`
4. Set **Mode** to `transparent`
5. Click **Start Interception**

### MITM (Man-in-the-Middle)

For intercepting traffic from other devices:

1. Go to **MITM** from the sidebar
2. **Scan Network** (or type the **Target IP**, e.g. phone on same WiFi)
3. Set **Gateway IP** (your router)
4. Choose the interception method: **Auto** (default) = rogue DHCP first (stealth, no "suspicious network" alert), with automatic **ARP fallback** if DHCP does not convert within ~20s; **ARP** = instant spoofing but the target may show a "suspicious network" alert (pick **ARP mode: Reactive** to answer only when the target asks — no flooding, virtually undetectable); **DHCP** = rogue DHCP only; **WiFi AP mode** = Nyx creates its own hotspot (**Nyx** SSID) — the target connects to you and you become the legitimate gateway, so no spoofing occurs at all and even client-isolated networks work
5. Enable **DNS Spoof** if needed
6. Click **Start**

> **💡 Already-connected target?** A Wi-Fi toggle only renews the old lease directly with the router (Nyx never sees it). Ask the target to **"forget the network"** and rejoin, or wait for the automatic ARP fallback. During the DHCP phase Nyx also NAKs the target's renewals to force it back to DISCOVER.

### View Captured Traffic

Go to **Proxy** → all requests appear in real-time.
Filter by method, host, or status code.
Click a request to view headers and body.

### Stop Interception

Go to **MITM** → click **Stop**. Traffic is restored.

---

## 4. Crawler

The crawler uses Playwright to spider websites, auto-fill forms, and handle JavaScript.

### Start a Crawl

1. Go to **Crawler** from the sidebar
2. Enter a **Target URL** (e.g., `https://example.com`)
3. Configure settings:
   - **Max Depth** (default: 3)
   - **Max Pages** (default: 50)
   - **Scope Include** — only crawl matching paths
   - **Scope Exclude** — skip matching paths
   - **Form Auto-Fill** — credentials for forms
   - **Custom Headers** — additional HTTP headers
   - **Login Macro** — pre-auth login steps
   - **Respect robots.txt**
4. Click **Start Crawl**

### Monitor Progress

The left panel shows:
- Status (Running/Completed/Stopped/Failed)
- Progress bar with pages crawled
- Speed (pages/sec) and elapsed time

The right panel shows:
- Discovered URLs list
- Discovered forms
- Crawl Jobs history

### Login Macro

For sites requiring authentication, add login steps:
1. **Step 1**: POST to login endpoint with credentials
2. Subsequent steps for multi-factor or redirects
3. The crawler captures cookies/tokens after each step

### Stop a Crawl

Click **Stop** on the active job, or use the **X** button on a running job in the list.

---

## 5. Scanner

### Passive Scanner

Runs automatically on proxied traffic:
- 210+ vulnerability checks
- Findings appear in **Scanner → Passive Findings**
- Filter by severity (Critical, High, Medium, Low, Info)
- Click a finding for details, evidence, and remediation
- Use **Retest** to verify if the vulnerability persists

### Active Scanner

1. Go to **Scanner → Active Scanner**
2. Select a proxied request from the dropdown
3. Choose checks to run:
   - SQL Injection (SQLi)
   - Cross-Site Scripting (XSS)
   - SSRF, Open Redirect, LFI, IDOR, SSTI, XXE
4. Click **Run Scan**
5. Results appear below with title, description, and evidence

### Custom Checks

Create custom regex-based checks:
1. Go to **Scanner → Custom Checks**
2. Define match patterns against responses
3. Test inline with the test runner
4. Enable/disable as needed

---

## 6. Repeater

Replay and modify HTTP requests:

1. Go to **Repeater**
2. Create a new tab or send a request from Proxy
3. Edit URL, method, headers, body
4. Click **Send**
5. View the response (status, headers, body)
6. Browse request history

---

## 7. Decoder

Transform and analyze data:

| Input | Codec | Output |
|---|---|---|
| `dGVzdA==` | Base64 Decode | `test` |
| `hello world` | URL Encode | `hello%20world` |
| JWT token | JWT Decode | Header + Payload |
| Any string | Smart Decode | Auto-detected encoding |
| Any string | Hex Dump | Hex output |
| Any string | Hash | MD5, SHA1, SHA256 |

---

## 8. Fuzzer

Parameter fuzzing with multiple attack modes:

1. Go to **Fuzzer**
2. Click **New Job**
3. Configure:
   - Target URL with position markers
   - Attack type: Sniper, Pitchfork, Cluster Bomb
   - Wordlist or custom payloads
   - Grep matches and response extractors
4. Click **Start**
5. Results stream in real-time

---

## 9. Session Handling

### Cookie Jar

View, search, and clear intercepted cookies.

### Macros

Create sequences of automated requests:
1. Add steps (URL, method, body)
2. Run the macro to execute all steps
3. Cookies are captured and shared across steps

### Session Check Rules

Define rules to detect valid/invalid sessions:
- Match on response headers, body, or status code
- Supported operators: equals, contains, regex, exists

### Match & Replace

Real-time request/response rewriting:
1. Create a rule with a regex pattern
2. Enter replacement text
3. Choose scope (request/response/both)
4. Toggle rules on/off

### Interceptor

Pause and modify traffic in real-time:
1. Enable the interceptor toggle
2. Requests/responses pause for inspection
3. Choose **Forward** (with edits) or **Drop**

---

## 10. Report Generation

1. Go to **Reporter** or click **Generate Report** from Dashboard
2. Select a session (or generate from all findings)
3. Choose format: JSON, HTML, or PDF
4. Reports include:
   - Executive summary
   - Findings matrix with severity
   - Technical evidence
   - Remediation recommendations

---

## 11. Troubleshooting

### Common Issues

| Issue | Solution |
|---|---|
| Dashboard shows "Failed to load" | Check backend is running on port 8000 |
| No traffic in Proxy | Verify proxy settings (host 0.0.0.0, port 8080) |
| Crawler shows error boundary | Refresh the page and try a valid URL |
| Active Scanner no results | Select a request from proxy first |
| Electron app won't start | Run as administrator (Windows) or check Python install |
| MITM not intercepting | Ensure target and gateway IPs are correct on the same subnet |

### Known Limitations

- Active scanner checks run sequentially (not parallel)
- Crawler requires Playwright browsers (`playwright install chromium`)
- HTTPS interception requires CA certificate installation
- ARP spoofing requires admin/root privileges

### Logs

- Backend logs: `backend/nyx.log`
- Desktop logs: Viewable via Electron DevTools (Ctrl+Shift+I)
- Frontend console: Browser DevTools (F12)
