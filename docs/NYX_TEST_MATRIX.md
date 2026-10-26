# Nyx — matrice di copertura API

Generata da `.live_test/build_matrix.py` contro `http://127.0.0.1:8000`.

- Operazioni registrate e sondate: **291**
- Con almeno un riferimento nei test: **114** (39%)
- Risposte 5xx dal live: **0**
- Backend caduto durante lo sweep: **no**

Colonna `live`: `GET` reale per gli endpoint di lettura, `OPTIONS` per gli altri (nessun effetto collaterale). Gli endpoint che cambiano lo stato della macchina sono marcati `skip`.

## Dettaglio per router

### `active_scanner` — 2 operazioni, 0 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/active-scanner/depths` | sì | 200 |
| POST | `/api/active-scanner/run` | sì | 405 |

### `api_inspector` — 1 operazioni, 1 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/api-inspector/requests` | no | 200 |

### `attack_path` — 1 operazioni, 1 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/attack-path/{session_id}` | no | 200 |

### `auth_testing` — 13 operazioni, 9 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| POST | `/api/auth/jwt/analyze` | no | 405 |
| POST | `/api/auth/jwt/brute` | sì | skip — skipped (unsafe) |
| POST | `/api/auth/jwt/crack` | sì | skip — skipped (unsafe) |
| POST | `/api/auth/jwt/decode` | no | 405 |
| GET | `/api/auth/key` | sì | 200 |
| POST | `/api/auth/login/record` | sì | 405 |
| POST | `/api/auth/oauth/debug` | no | 405 |
| GET | `/api/auth/profiles` | no | 200 |
| POST | `/api/auth/profiles` | no | 405 |
| DELETE | `/api/auth/profiles/{profile_id}` | no | 405 |
| GET | `/api/auth/profiles/{profile_id}` | no | 404 |
| PUT | `/api/auth/profiles/{profile_id}` | no | 405 |
| POST | `/api/auth/scan` | no | 405 |

### `automation` — 4 operazioni, 1 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/automation/config` | sì | 200 |
| POST | `/api/automation/config` | sì | 405 |
| GET | `/api/automation/discovered` | sì | 200 |
| GET | `/api/automation/pending` | no | 200 |

### `automations` — 23 operazioni, 23 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| POST | `/api/automations/csrf-poc/generate` | no | 405 |
| POST | `/api/automations/csrf-poc/generate-from-request/{request_id}` | no | 405 |
| POST | `/api/automations/param-discovery/chain` | no | 405 |
| POST | `/api/automations/param-discovery/start` | no | 405 |
| GET | `/api/automations/reports` | no | 200 |
| POST | `/api/automations/reports/generate` | no | 405 |
| POST | `/api/automations/reports/save` | no | 405 |
| GET | `/api/automations/reports/{filename}` | no | 404 |
| GET | `/api/automations/schedules` | no | 200 |
| POST | `/api/automations/schedules` | no | 405 |
| DELETE | `/api/automations/schedules/{schedule_id}` | no | 405 |
| PUT | `/api/automations/schedules/{schedule_id}` | no | 405 |
| POST | `/api/automations/schedules/{schedule_id}/toggle` | no | 405 |
| GET | `/api/automations/templates` | no | 200 |
| POST | `/api/automations/templates` | no | 405 |
| DELETE | `/api/automations/templates/{template_id}` | no | 405 |
| GET | `/api/automations/templates/{template_id}` | no | 404 |
| PUT | `/api/automations/templates/{template_id}` | no | 405 |
| GET | `/api/automations/webhooks` | no | 200 |
| POST | `/api/automations/webhooks` | no | 405 |
| POST | `/api/automations/webhooks/test/{config_id}` | no | 405 |
| DELETE | `/api/automations/webhooks/{config_id}` | no | 405 |
| PUT | `/api/automations/webhooks/{config_id}` | no | 405 |

### `backup` — 10 operazioni, 5 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/backup` | sì | skip — skipped (unsafe) |
| GET | `/api/ca-certificate` | sì | skip — skipped (unsafe) |
| GET | `/api/ca-qr` | no | skip — skipped (unsafe) |
| GET | `/api/ca-uninstall` | no | skip — skipped (unsafe) |
| GET | `/api/ca-uninstall-qr` | no | skip — skipped (unsafe) |
| POST | `/api/ca/remove` | sì | skip — skipped (unsafe) |
| GET | `/api/ca/status` | sì | skip — skipped (unsafe) |
| POST | `/api/export/findings` | no | skip — skipped (unsafe) |
| POST | `/api/shutdown` | sì | skip — skipped (unsafe) |
| GET | `/api/stats` | no | 200 |

### `clickbandit` — 7 operazioni, 7 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/clickbandit/` | no | 200 |
| POST | `/api/clickbandit/` | no | 405 |
| POST | `/api/clickbandit/generate` | no | 405 |
| DELETE | `/api/clickbandit/{config_id}` | no | 405 |
| GET | `/api/clickbandit/{config_id}` | no | 404 |
| PUT | `/api/clickbandit/{config_id}` | no | 405 |
| POST | `/api/clickbandit/{config_id}/generate` | no | 405 |

### `collaborator` — 3 operazioni, 1 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/collaborator/generate-token` | sì | 200 |
| GET | `/api/collaborator/health` | no | 200 |
| GET | `/api/collaborator/interactions` | sì | 200 |

### `comparer` — 4 operazioni, 1 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/comparer/compare/{item_id}` | no | 404 |
| GET | `/api/comparer/items` | sì | 200 |
| POST | `/api/comparer/items` | sì | 405 |
| DELETE | `/api/comparer/items/{item_id}` | sì | 405 |

### `compliance` — 5 operazioni, 0 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/compliance/full` | sì | 200 |
| GET | `/api/compliance/gdpr` | sì | 200 |
| GET | `/api/compliance/owasp` | sì | 200 |
| GET | `/api/compliance/pci-dss` | sì | 200 |
| GET | `/api/compliance/status` | sì | 200 |

### `content_discovery` — 9 operazioni, 9 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/content-discovery/jobs` | no | 200 |
| POST | `/api/content-discovery/start` | no | 405 |
| GET | `/api/content-discovery/status/{job_id}` | no | 404 |
| POST | `/api/content-discovery/stop/{job_id}` | no | 405 |
| GET | `/api/content-discovery/wordlists` | no | 200 |
| GET | `/api/content-discovery/wordlists/meta` | no | 200 |
| POST | `/api/content-discovery/wordlists/upload` | no | 405 |
| DELETE | `/api/content-discovery/wordlists/{name}` | no | 405 |
| GET | `/api/content-discovery/wordlists/{name}/preview` | no | 404 |

### `crawler` — 5 operazioni, 5 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/crawler/forms/{job_id}` | no | 404 |
| GET | `/api/crawler/jobs` | no | 200 |
| POST | `/api/crawler/start` | no | 405 |
| GET | `/api/crawler/status/{job_id}` | no | 404 |
| POST | `/api/crawler/stop/{job_id}` | no | 405 |

### `custom_scanner` — 5 operazioni, 1 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/scanner/custom/` | sì | 200 |
| POST | `/api/scanner/custom/` | sì | 405 |
| POST | `/api/scanner/custom/run` | no | 405 |
| DELETE | `/api/scanner/custom/{check_id}` | sì | 405 |
| PUT | `/api/scanner/custom/{check_id}` | sì | 405 |

### `dashboard` — 1 operazioni, 1 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/dashboard/stats` | no | 200 |

### `decoder` — 11 operazioni, 9 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| POST | `/api/decoder/charset-detect` | no | 405 |
| POST | `/api/decoder/convert` | no | 405 |
| POST | `/api/decoder/hash` | no | 405 |
| POST | `/api/decoder/hash-identify` | no | 405 |
| POST | `/api/decoder/hex-dump` | no | 405 |
| POST | `/api/decoder/html-encode` | sì | 405 |
| POST | `/api/decoder/jwt-decode` | no | 405 |
| POST | `/api/decoder/recipe` | no | 405 |
| POST | `/api/decoder/recursive-decode` | no | 405 |
| POST | `/api/decoder/smart-decode` | no | 405 |
| POST | `/api/decoder/transform` | sì | 405 |

### `fuzzer` — 9 operazioni, 4 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/fuzzer/attack-types` | no | 200 |
| GET | `/api/fuzzer/jobs` | sì | 200 |
| POST | `/api/fuzzer/jobs` | sì | 405 |
| GET | `/api/fuzzer/jobs/{job_id}` | sì | 404 |
| POST | `/api/fuzzer/jobs/{job_id}/cancel` | sì | 405 |
| GET | `/api/fuzzer/jobs/{job_id}/results` | sì | 404 |
| POST | `/api/fuzzer/preview` | no | 405 |
| GET | `/api/fuzzer/processors` | no | 200 |
| GET | `/api/fuzzer/wordlists` | no | 200 |

### `inspector` — 3 operazioni, 3 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| POST | `/api/inspector/analyze-request` | no | 405 |
| POST | `/api/inspector/analyze-response` | no | 405 |
| POST | `/api/inspector/inspect` | no | 405 |

### `interceptor` — 9 operazioni, 5 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| POST | `/api/interceptor/drop/{item_id}` | sì | 405 |
| POST | `/api/interceptor/forward/{item_id}` | sì | 405 |
| GET | `/api/interceptor/paused` | sì | 200 |
| GET | `/api/interceptor/rules` | no | 200 |
| POST | `/api/interceptor/rules` | no | 405 |
| DELETE | `/api/interceptor/rules/{rule_id}` | no | 405 |
| PUT | `/api/interceptor/rules/{rule_id}` | no | 405 |
| GET | `/api/interceptor/status` | sì | 200 |
| POST | `/api/interceptor/toggle` | no | 405 |

### `live_audit` — 7 operazioni, 7 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| POST | `/api/live-audit/clear-log` | no | 405 |
| POST | `/api/live-audit/clear-stats` | no | 405 |
| GET | `/api/live-audit/config` | no | 200 |
| PUT | `/api/live-audit/config` | no | 405 |
| POST | `/api/live-audit/start` | no | 405 |
| GET | `/api/live-audit/status` | no | 200 |
| POST | `/api/live-audit/stop` | no | 405 |

### `match_replace` — 7 operazioni, 1 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/match-replace/` | sì | 200 |
| POST | `/api/match-replace/` | sì | 405 |
| PATCH | `/api/match-replace/reorder` | no | 405 |
| DELETE | `/api/match-replace/{rule_id}` | sì | 405 |
| PUT | `/api/match-replace/{rule_id}` | sì | 405 |
| PUT | `/api/match-replace/{rule_id}/test` | sì | 405 |
| PATCH | `/api/match-replace/{rule_id}/toggle` | sì | 405 |

### `mitm` — 15 operazioni, 5 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/mitm/packets` | sì | 200 |
| GET | `/api/mitm/packets/{seq}` | sì | 422 |
| GET | `/api/mitm/portal` | no | 200 |
| GET | `/api/mitm/portal/checkin` | no | 200 |
| GET | `/api/mitm/quic` | sì | skip — skipped (unsafe) |
| POST | `/api/mitm/quic` | sì | skip — skipped (unsafe) |
| GET | `/api/mitm/scan-network` | sì | skip — skipped (unsafe) |
| POST | `/api/mitm/start` | sì | skip — skipped (unsafe) |
| GET | `/api/mitm/status` | sì | 200 |
| POST | `/api/mitm/stop` | sì | skip — skipped (unsafe) |
| POST | `/api/mitm/tls` | sì | skip — skipped (unsafe) |
| GET | `/api/mitm/udp` | sì | skip — skipped (unsafe) |
| POST | `/api/mitm/udp/clear` | no | skip — skipped (unsafe) |
| POST | `/api/mitm/udp/rules` | no | skip — skipped (unsafe) |
| DELETE | `/api/mitm/udp/rules/{index}` | no | skip — skipped (unsafe) |

### `network` — 11 operazioni, 2 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| POST | `/api/network/capture/start` | sì | skip — skipped (unsafe) |
| POST | `/api/network/capture/stop` | sì | skip — skipped (unsafe) |
| GET | `/api/network/export` | sì | skip — skipped (unsafe) |
| GET | `/api/network/frames` | sì | 200 |
| GET | `/api/network/interfaces` | no | 200 |
| GET | `/api/network/packets` | sì | 200 |
| GET | `/api/network/packets/{seq}` | sì | 422 |
| GET | `/api/network/quic` | no | 200 |
| GET | `/api/network/status` | sì | 200 |
| GET | `/api/network/streams` | sì | 200 |
| GET | `/api/network/streams/{stream_id}/frames` | sì | 200 |

### `organizer` — 7 operazioni, 7 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/organizer/` | no | 200 |
| POST | `/api/organizer/` | no | 405 |
| POST | `/api/organizer/from-request` | no | 405 |
| DELETE | `/api/organizer/{item_id}` | no | 405 |
| GET | `/api/organizer/{item_id}` | no | 404 |
| PUT | `/api/organizer/{item_id}` | no | 405 |
| POST | `/api/organizer/{item_id}/duplicate` | no | 405 |

### `pipeline` — 4 operazioni, 1 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/pipeline` | sì | 200 |
| POST | `/api/pipeline/start` | no | 405 |
| GET | `/api/pipeline/{pipeline_id}` | sì | 404 |
| POST | `/api/pipeline/{pipeline_id}/cancel` | sì | 405 |

### `projects` — 6 operazioni, 0 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/projects` | sì | 200 |
| POST | `/api/projects` | sì | 405 |
| POST | `/api/projects/import` | sì | 405 |
| DELETE | `/api/projects/{project_id}` | sì | 405 |
| PUT | `/api/projects/{project_id}` | sì | 405 |
| POST | `/api/projects/{project_id}/export` | sì | 405 |

### `proxy` — 4 operazioni, 0 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/proxy/capture` | sì | skip — skipped (unsafe) |
| POST | `/api/proxy/capture` | sì | skip — skipped (unsafe) |
| GET | `/api/proxy/session` | sì | 200 |
| PATCH | `/api/proxy/session` | sì | 405 |

### `proxy_config` — 8 operazioni, 8 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/proxy-config/` | no | 200 |
| POST | `/api/proxy-config/` | no | 405 |
| GET | `/api/proxy-config/active` | no | 404 |
| GET | `/api/proxy-config/local-ips` | no | 200 |
| POST | `/api/proxy-config/test` | no | 405 |
| DELETE | `/api/proxy-config/{proxy_id}` | no | 405 |
| PUT | `/api/proxy-config/{proxy_id}` | no | 405 |
| POST | `/api/proxy-config/{proxy_id}/toggle` | no | 405 |

### `recommendations` — 5 operazioni, 5 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/recommendations` | no | 200 |
| POST | `/api/recommendations/dismiss` | no | 405 |
| POST | `/api/recommendations/dismiss-all` | no | 405 |
| POST | `/api/recommendations/execute` | no | 405 |
| GET | `/api/recommendations/stats` | no | 200 |

### `repeater` — 7 operazioni, 6 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| POST | `/api/repeater/send` | sì | 405 |
| GET | `/api/repeater/tabs` | no | 200 |
| POST | `/api/repeater/tabs` | no | 405 |
| DELETE | `/api/repeater/tabs/{tab_id}` | no | 405 |
| GET | `/api/repeater/tabs/{tab_id}` | no | 404 |
| GET | `/api/repeater/tabs/{tab_id}/history` | no | 404 |
| POST | `/api/repeater/tabs/{tab_id}/send` | no | 405 |

### `reporter` — 1 operazioni, 0 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| POST | `/api/reports/generate` | sì | 405 |

### `requests` — 3 operazioni, 0 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/requests` | sì | 200 |
| GET | `/api/requests/export/har` | sì | skip — skipped (unsafe) |
| GET | `/api/requests/{request_id}` | sì | 404 |

### `roe` — 6 operazioni, 6 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/roe` | no | 200 |
| POST | `/api/roe` | no | 405 |
| GET | `/api/roe/{profile_id}` | no | 404 |
| POST | `/api/roe/{profile_id}/activate` | no | 405 |
| POST | `/api/roe/{profile_id}/deactivate` | no | 405 |
| POST | `/api/roe/{profile_id}/verify` | no | 405 |

### `scan_jobs` — 7 operazioni, 0 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/scan-jobs` | sì | 200 |
| POST | `/api/scan-jobs` | sì | 405 |
| GET | `/api/scan-jobs/queue` | sì | 200 |
| GET | `/api/scan-jobs/{job_id}` | sì | 404 |
| POST | `/api/scan-jobs/{job_id}/cancel` | sì | 405 |
| POST | `/api/scan-jobs/{job_id}/priority` | sì | 405 |
| POST | `/api/scan-jobs/{job_id}/start` | sì | 405 |

### `scan_policies` — 5 operazioni, 0 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/scan-policies` | sì | 200 |
| POST | `/api/scan-policies` | sì | 405 |
| DELETE | `/api/scan-policies/{policy_id}` | sì | 405 |
| GET | `/api/scan-policies/{policy_id}` | sì | 404 |
| PUT | `/api/scan-policies/{policy_id}` | sì | 405 |

### `scanner` — 1 operazioni, 0 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/findings` | sì | 200 |

### `search` — 1 operazioni, 1 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/search` | no | 422 |

### `sequencer` — 12 operazioni, 12 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| POST | `/api/sequencer/analyze` | no | 405 |
| POST | `/api/sequencer/analyze-detailed` | no | 405 |
| POST | `/api/sequencer/bit-analysis` | no | 405 |
| POST | `/api/sequencer/chart-data` | no | 405 |
| POST | `/api/sequencer/chi-square` | no | 405 |
| POST | `/api/sequencer/fips-140-2` | no | 405 |
| GET | `/api/sequencer/live/capturing/{session_id}` | no | 200 |
| POST | `/api/sequencer/live/clear` | no | 405 |
| POST | `/api/sequencer/live/start` | no | 405 |
| POST | `/api/sequencer/live/stop` | no | 405 |
| GET | `/api/sequencer/live/tokens/{session_id}` | no | 200 |
| POST | `/api/sequencer/monte-carlo` | no | 405 |

### `session_handling` — 19 operazioni, 19 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/session/cookies` | no | 200 |
| POST | `/api/session/cookies` | no | 405 |
| DELETE | `/api/session/cookies/{cookie_id}` | no | 405 |
| POST | `/api/session/macros/from-requests` | no | 405 |
| POST | `/api/session/macros/run` | no | 405 |
| POST | `/api/session/recording/start` | no | 405 |
| POST | `/api/session/recording/stop` | no | 405 |
| GET | `/api/session/recording/{session_id}` | no | 200 |
| GET | `/api/session/rules` | no | 200 |
| POST | `/api/session/rules` | no | 405 |
| DELETE | `/api/session/rules/{rule_id}` | no | 405 |
| PUT | `/api/session/rules/{rule_id}` | no | 405 |
| PUT | `/api/session/rules/{rule_id}/macro-steps` | no | 405 |
| PUT | `/api/session/rules/{rule_id}/scope` | no | 405 |
| GET | `/api/session/tokens` | no | 200 |
| DELETE | `/api/session/variables` | no | 405 |
| GET | `/api/session/variables` | no | 200 |
| POST | `/api/session/variables/load/{name}` | no | 405 |
| POST | `/api/session/variables/save/{name}` | no | 405 |

### `sessions` — 6 operazioni, 0 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/sessions` | sì | 200 |
| POST | `/api/sessions` | sì | 405 |
| DELETE | `/api/sessions/{session_id}` | sì | 405 |
| GET | `/api/sessions/{session_id}` | sì | 200 |
| PUT | `/api/sessions/{session_id}` | sì | 405 |
| DELETE | `/api/sessions/{session_id}/data` | sì | 405 |

### `settings` — 3 operazioni, 0 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/settings/` | sì | 200 |
| GET | `/api/settings/proxy` | sì | skip — skipped (unsafe) |
| PUT | `/api/settings/proxy` | sì | skip — skipped (unsafe) |

### `smart_triage` — 4 operazioni, 0 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/triage/findings/grouped` | sì | 422 |
| GET | `/api/triage/findings/recent` | sì | 422 |
| GET | `/api/triage/findings/{finding_id}/retest` | sì | 404 |
| GET | `/api/triage/stats` | sì | 422 |

### `target_scope` — 8 operazioni, 3 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/scope/` | sì | 200 |
| POST | `/api/scope/` | sì | 405 |
| POST | `/api/scope/check` | no | 405 |
| GET | `/api/scope/suggestions` | no | 200 |
| POST | `/api/scope/validate-regex` | no | 405 |
| DELETE | `/api/scope/{rule_id}` | sì | 405 |
| PUT | `/api/scope/{rule_id}` | sì | 405 |
| PATCH | `/api/scope/{rule_id}/toggle` | sì | 405 |

### `verifier` — 7 operazioni, 6 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| POST | `/api/auto-exploit/analyze` | no | 405 |
| GET | `/api/auto-exploit/cwes` | no | 200 |
| POST | `/api/auto-exploit/execute` | no | 405 |
| POST | `/api/auto-exploit/generate` | no | 405 |
| POST | `/api/auto-exploit/generate/single` | no | 405 |
| GET | `/api/auto-exploit/languages` | no | 200 |
| POST | `/api/auto-exploit/verify` | sì | 405 |

### `websocket_intercept` — 2 operazioni, 2 senza test

| Metodo | Path | Test | Live |
|---|---|---|---|
| GET | `/api/ws/messages` | no | 200 |
| DELETE | `/api/ws/messages/{msg_id}` | no | 405 |
