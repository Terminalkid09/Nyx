# Nyx — Automated Web Security Testing Suite

**Version:** 0.1.x  
**Project Root:** `C:\Users\ilysm\Desktop\GitHub\nyx\`  
**Blueprint:** `NYX_BLUEPRINT_V2.md` (3321 lines, Phase 1-5)  
**Architecture:** Python (FastAPI + mitmproxy) backend + React/TypeScript frontend + Postgres (optionally Go collaborator)

---

## Architecture Overview

```
nyx/
├── backend/
│   ├── main.py                          # FastAPI app entry point
│   ├── core/
│   │   ├── config.py                    # Settings (pydantic-settings)
│   │   ├── proxy/
│   │   │   ├── engine.py                # mitmproxy wrapper
│   │   │   └── addons/
│   │   │       ├── logger.py            # Request/response capture
│   │   │       └── ...                  # Interceptor, session handling
│   │   ├── events/bus.py                # Async event bus (pub/sub)
│   │   ├── proxy_utils.py               # Global HTTP client hub
│   │   ├── storage/
│   │   │   ├── database.py              # SQLAlchemy + Alembic
│   │   │   ├── models.py                # 18+ DB tables
│   │   │   └── crud/                    # CRUD helpers
│   │   └── security_checks.py           # Reusable check utilities
│   ├── api/
│   │   ├── schemas/                     # Pydantic models
│   │   └── routes/                      # 34 route files (28 active)
│   ├── modules/                         # 18 modules
│   │   ├── scanner/                     # Passive (209) + Active (109) checks
│   │   ├── crawler/                     # JS-aware spider
│   │   ├── fuzzer/                      # Parameter fuzzing
│   │   ├── decoder/                     # 15+ codecs, smart decode
│   │   ├── sequencer/                   # Token entropy (NIST FIPS 140-2)
│   │   ├── automation/                  # AutoScanEngine
│   │   ├── automations/                 # Webhooks, templates, schedules
│   │   ├── pipeline/                    # Scan pipeline orchestrator
│   │   ├── live_audit/                  # Interactive live audit
│   │   ├── ... and 8 more modules
│   ├── wordlists/                       # Content discovery wordlists
│   ├── data/                            # Runtime data (reports, configs)
│   └── tests/                           # 122 tests (pytest)
├── frontend/
│   └── src/
│       ├── components/                  # 38 component files
│       ├── api/endpoints/               # 15 API client modules
│       ├── store/                       # Zustand stores
│       └── hooks/                       # Custom React hooks
├── docker-compose.yml                   # postgres + backend + frontend
├── .gitlab-ci.yml                       # 3-stage CI pipeline
└── Makefile                             # 11 targets
```

---

## Module Inventory

### Core Infrastructure

| Module | Status | Lines | Description |
|--------|--------|-------|-------------|
| Proxy Engine | MVP | ~300 | mitmproxy wrapper, event emission, addon registration |
| Event Bus | Done | 33 | Async pub/sub with fire-and-forget task tracking |
| Database | Done | ~150 | SQLAlchemy async, Alembic migrations via subprocess |
| Proxy Utils | Done | ~60 | Global httpx/playwright proxy config hub |
| Config | Done | ~60 | Pydantic settings (env-based) |

### Security Testing Modules

| Module | Status | Lines | Key Features |
|--------|--------|-------|-------------|
| Passive Scanner | MVP | ~450 | 209 checks across 30+ categories |
| Active Scanner | MVP | ~400 | 109 active vulnerability checks |
| Fuzzer | In Progress | ~350 | Wordlist-based parameter fuzzing with grep/extract |
| Crawler | In Progress | ~500 | JS/AJAX crawling, auth macros, scope rules |
| Decoder | MVP | ~830 | 15+ codecs, smart decode, hash identifier, hex dump |
| Sequencer | MVP | ~400 | NIST FIPS 140-2, entropy analysis, token prediction |
| Session Handling | Done | ~200 | Cookie/header session management |
| Interceptor | Done | ~260 | Request/response interception with modification |

### Automation & Orchestration

| Module | Status | Lines | Description |
|--------|--------|-------|-------------|
| AutoScan Engine | Done | ~270 | Traffic-based auto scanning with scope learning |
| Live Audit Service | Done | ~120 | Interactive scan controls with stats/audit log |
| Scan Pipeline | Done | ~200 | 6-step orchestrator (crawl → report) |
| Automations | Done | ~500 | CSRF PoC, param discovery, webhooks, schedules, |
| | | | scan templates, auto-report generation |
| Smart Triage | Done | ~100 | Finding grouping, retest, statistics |

### UI & Productivity

| Module | Status | Lines | Description |
|--------|--------|-------|-------------|
| Content Discovery | Done | ~170 | Wordlist-based path/file brute force |
| Match & Replace | Done | ~200 | Regex/string rules for proxy rewriting |
| Organizer | Done | ~150 | Finding tagging, notes, colors, filtering |
| Inspector | Done | ~200 | Request/response analysis with security checks |
| Clickbandit | Done | ~100 | Clickjacking PoC HTML generator |
| Target Scope | Done | ~100 | URL inclusion/exclusion rules |
| Upstream Proxy | Done | ~150 | Proxy config with global cache + test connection |
| Dashboard | Done | ~300 | Stats, quick actions, active pipelines, findings |
| Onboarding | Done | ~200 | 7-step wizard (localStorage-backed) |
| Unified Progress | Done | ~100 | Multi-step progress bar with color segments |
| Reporter | MVP | ~150 | HTML/JSON report generation |

### UI Components (Frontend)

| Component | Status | Key Features |
|-----------|--------|--------------|
| Dashboard | Done | Stats row, quick actions, pipelines, findings |
| ProxyLog | Done | Live traffic table, filter bar, request detail |
| Repeater | Done | Request editor, response viewer, history |
| Scanner | Done | Passive findings + active scan panels |
| Fuzzer | Done | Position editor, results table with grep |
| Decoder | Done | Smart decode, hash identify, hex dump |
| Sequencer | Done | Token analysis, live capture, FIPS results |
| Crawler | Done | Start/stop, progress, URL/forms display |
| Comparer | Done | Side-by-side diff (text + hex) |
| Interceptor | Done | Paused requests table, forward/drop/modify |
| LiveAudit | Done | Stats, config, audit log (polling) |
| Organizer | Done | Table with tags/colors/notes, filtering |
| ContentDiscovery | Done | Wordlist selection, extensions, results |
| MatchReplace | Done | Rule CRUD with drag-and-drop ordering |
| Inspector | Done | Request/response/combined analysis |
| Clickbandit | Done | PoC builder with iframe canvas preview |
| TargetScope | Done | Include/exclude URL rule management |
| ProxyConfig | Done | Proxy CRUD with test connection |
| PipelineConfig | Done | 6-step config, progress display |
| OnboardingWizard | Done | 7-step modal overlay tour |
| AuthTester/ScanJobs | Done | Authentication testing, job management |
| GlobalSearch | Done | Cross-module search |
| WebSocketViewer | Done | WS message stream display |
| SessionHandling | Done | Cookie/session CRUD |
| ProjectManager | Done | Project-based workspace management |
| HexViewer | Done | Byte-level hex dump component |

---

## Statistics

### Codebase

| Metric | Value |
|--------|-------|
| Python files (backend) | 438 |
| Python lines of code | ~23,200 |
| TS/TSX files (frontend) | 65 |
| TS/TSX lines of code | ~10,957 |
| **Total Lines of Code** | **~34,157** |
| Module directories | 18 |
| Frontend component files | 38 |
| API route files | 28 |
| Database tables | 18+ |

### Scanner Coverage

| Category | Passive Checks | Active Checks | Total |
|----------|:--------------:|:-------------:|:-----:|
| XSS | 16 | 8 | 24 |
| SQL Injection | 18 | 5 | 23 |
| SSTI | 12 | — | 12 |
| Path Traversal | 5 | 3 | 8 |
| SSRF | 4 | 2 | 6 |
| XXE | 9 | 2 | 11 |
| Command Injection | 3 | 3 | 6 |
| Open Redirect | 2 | — | 2 |
| JWT | 9 | — | 9 |
| CORS | 9 | — | 9 |
| Info Disclosure | 10 | — | 10 |
| Cache Poisoning | 10 | — | 10 |
| Auth | 10 | 3 | 13 |
| CORS | 9 | 2 | 11 |
| GraphQL | 8 | 2 | 10 |
| WebSocket | 8 | — | 8 |
| Business Logic | 9 | 6 | 15 |
| HTTP Smuggling | 8 | — | 8 |
| Race Conditions | — | 6 | 6 |
| Protocol/TLS | — | 8 | 8 |
| Framework detect | — | 8 | 8 |
| API Security | — | 8 | 8 |
| LDAP/NoSQL/XPath | 3 | 5 | 8 |
| Prototype Pollution | 3 | 2 | 5 |
| Cookie Security | 3 | — | 3 |
| CSP | 2 | — | 2 |
| Other (HPP, method, SSI, etc.) | 12 | — | 12 |
| **Total** | **209** | **109** | **318** |

### Testing

| Metric | Value |
|--------|-------|
| Test files | 6 |
| Test functions | 122 |
| Test pass rate | 100% |
| Framework | pytest + pytest-asyncio |
| Linting | ruff |
| Type checking | mypy --strict |

### Infrastructure

| Component | Details |
|-----------|---------|
| Database | PostgreSQL 16 (Docker) |
| Proxy | mitmproxy (127.0.0.1:8080) |
| Backend API | FastAPI (0.0.0.0:8000) |
| Frontend | React + Vite + Tailwind (port 80) |
| WebSocket | ws://localhost:8000/ws/traffic |
| CI/CD | GitLab CI (3 stages, 4 jobs) |
| Containerization | Docker Compose (3 services) |

---

## Recent Fixes (Robustness Audit)

| # | Issue | File | Fix |
|---|-------|------|-----|
| C1 | Event type mismatch (`request_captured` vs `request.captured`) | `automation/engine.py:38` | Changed subscription to `request.captured` |
| C2 | Regex `IndexError` in `html_decode_full` | `decoder/service.py:760` | Changed `m.group(2)` to `m.group(1)` |
| C3 | Shared DB session across concurrent fuzzer tasks | `fuzzer/service.py:225-343` | Moved `AsyncSessionLocal()` inside each task |
| C4 | `uuid.UUID("")` crash on missing metadata | `proxy/addons/logger.py:41` | Added guard for empty `nyx_request_id` |
| C5 | Hardcoded external URL in proxy test | `api/routes/proxy_config.py:215` | Made configurable via `NYX_PROXY_TEST_URL` env var |
| H2 | PassiveScanner.register() never called | `main.py:49` + `passive/scanner.py` | Created scanner, called `register()` |
| H4 | Fire-and-forget tasks subject to GC | `core/events/bus.py:17` | Added task tracking set with done callback |
| H6 | Startup calls without error handling | `main.py:69-71` | Wrapped each in try/except with logging |
| H7 | Unvalidated UUID in WS handler | `routes/websocket_intercept.py:113-115` | Added try/except around `uuid.UUID()` |
| H8 | New CrawlerService per stop request | `routes/crawler.py:159-161` | Stored instance in job dict |
| H3 | `{FUZZ}` replacement was no-op | `content_discovery/service.py:67` | Removed broken replace call |

---

## Quick Start

```bash
cp .env.example .env
docker compose up --build -d
```

Backend API: http://localhost:8000  
Frontend UI: http://localhost:80  
Proxy: http://127.0.0.1:8080  

---

## Run Tests

```bash
cd backend
python -m pytest tests/ -v
```

---

## Key Design Decisions

1. **No authentication** — local security tool, all API routes public
2. **Alembic via subprocess** — `init_db()` calls `alembic upgrade head` with `PYTHONPATH=/app`
3. **Global proxy config hub** — `core/proxy_utils.py` centralizes httpx/playwright proxy configuration
4. **Fire-and-forget events** — EventBus uses `asyncio.create_task` with task tracking set
5. **Onboarding in localStorage** — no backend needed, flag `nyx_onboarding_complete`
6. **Dashboard as landing page** — replaces `/` redirect to `/proxy`

---

## Next Steps

1. 🚧 Go collaborator service (user writes to learn Go)
2. 🚧 Collaborator tab in frontend (token generator + interaction log)
3. 🚧 Additional scanner checks (expand active checks for max coverage)
4. 🌱 Docker Compose collaborator service integration
