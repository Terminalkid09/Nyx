# Nyx v1.0.0 — Revisione tecnica, sicurezza e piano di lavoro

| | |
|---|---|
| **Oggetto** | Nyx — Web Security Testing Suite |
| **Versione analizzata** | v1.0.0 (`777f495`, branch `main`) |
| **Data revisione** | 21 ottobre 2026 |
| **Scope** | Backend Python (~57.5k righe), frontend React/TS (~22k), desktop Electron, collaborator Go, modulo nativo C++, CI/release, docs |
| **Tipo** | Revisione statica del codice + esecuzione della suite di test. Nessun exploit attivo eseguito contro il backend in esecuzione. |
| **Destinatari** | Maintainer del progetto |

---

## 0. Stato di avanzamento (aggiornato al 24 ottobre 2026)

Legenda: **FATTO** = codice + test verdi; **PARZIALE** = nucleo implementato, UI/integrazione mancante; **APERTO** = non iniziato.

| Area | Ticket | Stato |
|---|---|---|
| Igiene | `pytest.ini` (suite verde senza flag), CI senza `--asyncio-mode` | FATTO |
| v1.1 P0 | SEC-01 (validazione SSID/passphrase, `shell=False`, config hostapd) | FATTO |
| v1.1 P0 | SEC-02 (path traversal report) | FATTO |
| v1.1 P1 | SEC-03a (Host allowlist, `Sec-Fetch-Site`), SEC-04 (escaping Fuzzer), SEC-05 (plugin rimossi), SEC-06 (README/threat model onesti), SEC-07 (Docker: proxy fidato, WS porta 80, `npm ci` + `.npmrc`) | FATTO |
| v1.1 bug | BUG-01 (retention per timestamp), BUG-02 (dedupe per parametro), BUG-03+16 (toggle Live Audit, sessione corretta), BUG-04 fase A (worker pool, client condiviso, cap/troncamento), BUG-05 (publish dopo commit), BUG-08 (path DB assoluto), BUG-09 (TTL flow in pausa), BUG-10 (noise domini configurabili + metrica), BUG-11 (`events_dropped_total`), BUG-12, BUG-13, BUG-14 (icacls), BUG-15 (quoting PRAGMA key) | FATTO |
| v1.2 | BUG-06 (scope+RoE come barriera in scanner, auto-scan e **fuzzer**; `session_id` passato da Auth Scan e Pipeline), BUG-07 (timeout per check), F-02 (CLI `nyx_cli.py scan --fail-on`), evidence (curl + estratto risposta) | FATTO |
| v1.2 residuo | SEC-03b (token per-boot via IPC), split `mitm.py` (`mitm_admin`/`mitm_status`), registry automatico dei check attivi | FATTO |
| v1.2 | BUG-04 fase B (tabella `fuzz_results`, scrittura a batch, endpoint con paging, cleanup di sessione) | FATTO |
| Sessione 24/10 (2) | Endpoint privilegiati provati live (MITM/capture/CA/export) + CA rimozione verificata + `attack-path` limitato | Vedi §0.2 |
| v1.3 | F-01 (profili RoE firmati, matcher, rate gate, API, pagina RoE), F-03 (attack path graph + `/api/attack-path/{session_id}` + vista grafo), F-04 (verifier differenziale + endpoint + pagina Verifier) | FATTO (nucleo + UI) |
| v1.3 | Import OpenAPI 2.0/3.x (inventario endpoint + warning di contratto, API `POST /api/import/openapi`, comando `nyx import openapi`, applicazione dei server allo scope di sessione) | FATTO |
| v1.3 | Multi-ruolo A/B (`POST /api/ab-test/run`: due set di header + gamba anonima, diff normalizzato → `suspected_idor`/`isolated`/`unauthenticated_access`; nucleo senza UI) | FATTO (nucleo) |
| v1.3 | Report NIS2 Art. 21(2) e ISO/IEC 27001:2022 Annex A (mapping dai finding, stato `NOT_ASSESSED` per le misure non osservabili, endpoint `/api/compliance/nis2|iso27001`, tab nella pagina Compliance) | FATTO |
| v1.3 | UI multi-ruolo A/B, pagina Import API (OpenAPI + Burp XML), triage con falso positivo, override di severità e retest registrato | FATTO |
| v1.3 residuo | Import di una sessione ZAP (formato a database, non un export piatto) | APERTO |
| v2.0 | AP Range: allowlist MAC, `macaddr_acl=1`, DHCP `tag:!known`, rifiuto allowlist vuota, Linux-only | PARZIALE (config/validazione, senza multi-BSSID/shaping) |
| v2.0 residuo | F-05 Sensor, F-06 mobile kit, F-08 import PCAP, F-09 QUIC visibility, F-10 plugin SDK | APERTO |
| Network layer (TT) | NET-01, NET-02, F-05, F-08, F-09 | Non toccati (perimetro dell'altro maintainer) |
| Sessione 24/10 | Test live completo (A-F), browser integrato, sessioni, report, docs/config | Vedi §0.1 |

### 0.1 Sessione di verifica del 24 ottobre 2026

Test eseguito sul backend reale avviato da Electron, senza Docker: matrice di
copertura su **291 operazioni** (`docs/NYX_TEST_MATRIX.md`), sweep di lettura e
scrittura, 17 flussi end-to-end, smoke test del browser integrato, suite backend
(**1216 passed, 1 skipped**) e frontend (type-check, 35 test, build).

**Bug trovati e corretti**

| ID | Area | Problema | Fix |
|---|---|---|---|
| BUG-17 | Storage | Le migrazioni Alembic fallivano ad ogni avvio su un DB creato da `create_all` (`table ... already exists`), lasciando `alembic_version` vuota per sempre | Adozione dello schema con `alembic stamp head` quando manca una revisione (`tests/test_db_baseline.py`) |
| BUG-18 | Scanner passivo | Regex `<!\[CDATA` non escapata: `xxe_soap` sollevava `unterminated character set` su ogni corpo SOAP | Pattern corretto + regression test |
| BUG-19 | Sessioni | `DELETE /api/sessions/{id}` rispondeva **500** se la sessione aveva traffico (il cascade ORM tentava `NULL` su `requests.session_id NOT NULL`) | Delete esplicito delle tabelle di sessione + test |
| BUG-20 | Report | `format=pdf` senza `weasyprint` restituiva HTML con `Content-Type: application/pdf` → file `.pdf` illeggibile | 400 con messaggio chiaro; `Content-Disposition` e content-type corretti |
| BUG-21 | Proxy config | `PUT /api/settings/proxy` accettava qualsiasi `mode`, riavviava il motore e **lasciava il listener morto** (WinError 64) se il restart falliva | Validazione modalità/porta + rollback alla configurazione precedente |
| BUG-22 | Pipeline | `GET /api/pipeline` rispondeva 500 (`AttributeError: event_bus`) invece di 503 | 503 con dettaglio |
| BUG-23 | UI/Attribuzione | 4 schermate (Clickbandit, Organizer, ScanJobs, SessionHandling) scrivevano sulla sessione hardcoded `0000…0001` | Usano la sessione attiva |
| BUG-24 | Test legacy | 5 test rotti per mock senza `.text` e gate RoE non considerato; suite non isolata (leggeva `nyx.db`) | `tests/conftest.py` ermetico + mock aggiornati |

**Hardening browser integrato**: preload dedicato (`browser-preload.js`), badge
proxy reale invece di "PROXIED" fisso, CSP sulla pagina di chrome, script
esternalizzato (`browser-renderer.js`), popup negati (`setWindowOpenHandler`),
permessi device negati (tranne fullscreen), `will-attach-webview`/`will-navigate`
limitati a http(s), indirizzi LAN/IP riconosciuti nella barra.

**Copertura**: nuovo `tests/test_api_route_contracts.py` (108 GET × nessun 500),
`tests/test_sessions_api.py`, `tests/test_reports_api.py`,
`tests/test_proxy_settings.py`, `tests/test_db_baseline.py` + smoke test
`.live_test/*` (matrice, sweep, e2e, browser).

**Verifica**: `cd backend && python -m pytest -q` → 1000+ test verdi senza flag; `cd frontend && npm run type-check && npm test && npm run build` verdi. Docker: `docker compose config` valido, immagine frontend costruita; il build completo dell'immagine backend non è stato completato in questa sessione (timeout), quindi l'end-to-end `docker compose up` resta da confermare.

### 0.2 Seconda sessione del 24 ottobre 2026 — endpoint privilegiati, CA, fuzzer

**Endpoint che richiedono Administrator** (prima esclusi dagli sweep perché
cambiano lo stato della macchina, non per un login): provati live con un
backend avviato elevato (`admin_mode: true`), con un nuovo script
`.live_test/privileged_sweep.py` (38/41 check; i 3 restanti erano lo stato
non-elevato della seconda esecuzione). Coperti: `PUT /api/settings/proxy`
(validazione + riavvio + rollback), `/api/mitm/tls`, `/api/mitm/quic`,
`/api/mitm/udp[/rules|/clear]`, `/api/mitm/scan-network` (12 device),
`/api/mitm/start` + `/api/mitm/stop`, `/api/network/capture/start|stop`,
`/api/network/export`, `/api/export/findings`, `/api/requests/export/har`,
`/api/backup` (20 MB), `/api/ca-certificate`, `/api/ca/status`,
`/api/ca/remove`, `POST /api/shutdown`. L'e2e resta 17/17.

**Bug trovati e corretti in questa sessione**

| ID | Area | Problema | Fix |
|---|---|---|---|
| BUG-04b | Fuzzer/DB | I risultati vivevano in una colonna JSON della job: 100k payload = centinaia di MB in un solo blob, UI bloccata, nessun paging | Tabella `fuzz_results` (migrazione `9a1c4b7d2e05`), scrittura a batch da 100 durante il run, `/jobs/{id}/results` con `limit/offset/status_filter`, fallback alle job legacy, cleanup esplicito con la sessione |
| BUG-25 | Attack path | Il grafo era O(n²) su tutte le finding: su una sessione longeva costruiva milioni di edge e il backend moriva esaurendo la memoria (`GET /api/attack-path/{session_id}` lasciava l'API muta, processo ancora vivo sulle porte proxy) | Cap a 500 nodi (severità più alta) e 100 edge per host, raggruppamento per `request_id`/host al posto del doppio ciclo. Riprodotto live: matrix `dead=1` → `dead=0` |
| BUG-26 | MITM/UX | `POST /api/mitm/start` senza privilegi rispondeva **500** ("WinDivert not available") invece di spiegare cosa fare | 400 con messaggio azionabile (avviare elevato o usare Stealth Mode) prima di toccare il motore |
| BUG-27 | CA | `POST /api/ca/remove` dichiarava successo dopo un delete best-effort: una CA rimasta in `LocalMachine` (nessun admin) o una PowerShell interrotta risultavano "rimosse" | `remove_ca_verified()`: rimozione per store + rilettura, conteggi before/after, `removed=false` finché una store tiene la CA; esposto anche `GET /api/ca/status` (per store) e stato in UI. Verificato live: non-elevato → `removed=false` con `still_present`, elevato → `removed=true` 0/0 |

**CA: installazione su target, non sull'operatore.** Il flusso corretto è
quello già documentato: il target apre il portale LAN (`:18081`) e installa la
CA lì. Installarla sul PC dell'operatore serve solo a navigare lui stesso
attraverso Nyx, è manuale (dialogo di consenso del sistema) e Nyx non la
installa mai da sola; la UI ora mostra lo stato di fiducia per store e la
rimozione verificata. Resta separato il trust di Firefox (store NSS) e dei
keystore Java: dichiarati, non toccati.

**Resta aperto**: UI per RoE/verifier/attack-path, import Burp/ZAP, UI del
multi-ruolo A/B, AP range multi-BSSID (vedi §14). Il crash del backend osservato con Electron
durante gli sweep era BUG-21 (endpoint `settings/proxy`) più BUG-25
(`attack-path`) sul database di lavoro.

**Verifica**: `cd backend && python -m pytest -q` → **1216 passed, 1 skipped**; frontend `type-check` pulito, **35 test**, build ok; matrice rigenerata su DB pulito (**291 operazioni, 114 con riferimenti nei test, 0 risposte 5xx, 0 processi morti**); e2e live 17/17; `.live_test/privileged_sweep.py` 38/41 (le 3 differenze erano le prove eseguite su un backend non elevato).

---

### 0.3 Sessione del 27 ottobre 2026 — workflow chiuso, numeri riallineati

**Chiuso**

- **SEC-03b**: token per-boot scritto in `NYX_HOME/session.token`, imposto
  dalla shell solo nelle build pacchettizzate; il renderer lo riceve via IPC e
  lo allega a ogni chiamata, con retry singolo dopo un riavvio del backend.
- **UI multi-ruolo A/B** (`/ab-test`) e **pagina Import API** (`/import`):
  entrambe le funzionalità avevano solo endpoint e CLI, quindi non erano
  raggiungibili dall'interfaccia.
- **Triage**: `PATCH /api/triage/findings/{id}` registra stato e override di
  severità; il falso positivo esce dalla vista raggruppata e dai report ma
  conserva l'evidenza; il retest registra l'esito e passa dal gate scope/RoE
  (prima re-inviava la richiesta senza alcun controllo).
- **Import Burp XML**: `POST /api/import/burp` produce lo stesso inventario
  dell'import OpenAPI, deduplicando per (method, path) e conservando i
  parametri di query; DOCTYPE/ENTITY vengono rifiutati prima del parser.
- **Migrazione** `a3f1c9d7b2e4` per `triage_status`/`severity_override`,
  verificata in upgrade, downgrade e nuovo upgrade su un DB creato da Alembic.
- **Matrice rigenerata**: 280 operazioni, 114 con un riferimento nei test
  (40%), **0 risposte 5xx**, 0 processi morti.

**Verifica**: backend `python -m pytest -q` → **1112 passed, 1 skipped**;
frontend `tsc --noEmit` pulito, **19 test**, build ok; riprova live di gate
token, import OpenAPI/Burp e `PATCH` su finding inesistente (404).

**Ancora aperto (nostro)**: import di una sessione ZAP, AP Range multi-BSSID e
shaping per client, mobile kit (F-06), plugin SDK (F-10). I numeri di §0.1 e
§0.2 sono lo snapshot di quelle sessioni; i valori correnti sono in §2.

---

## 1. Executive summary (la versione da 5 minuti)

Nyx a v1.0.0 **non è un progetto amatoriale**. È un prodotto con architettura reale: 24 moduli backend, 138 check attivi registrati, 211 file di check passivi, ~1200 test, CI, threat model, Electron hardened. Il livello medio del codice è alto e i commenti che spiegano i bug passati ("perché `local=False` su WinDivert", "perché `create_all` dopo alembic") sono documentazione di guerra che vale più di mille righe di README.

I problemi sono di **natura diversa**: il progetto è cresciuto più velocemente della sua ingegnerizzazione. In sintesi:

1. **Due bug di sicurezza gravi nel codice del maintainer principale** (command injection nel WiFi AP, path traversal nei report). Il secondo è stato **confermato eseguendo il codice**.
2. **Tre feature che sembrano complete e non lo sono**: plugin (esegue codice ma nessun hook viene chiamato), Live Audit (4 toggle su 6 inerti), Docker (l'API risponde 401 a tutto).
3. **Il collo di bottiglia non è il numero di check, è il motore**: scansione attiva sequenziale senza timeout, fuzzer che crea una coroutine e un client TLS per ogni payload, deduplica che perde finding reali.
4. **Il posizionamento del prodotto è più forte del prodotto stesso**: la nicchia "intercetto il traffico di un telefono/IoT in 30 secondi, senza essere un network engineer" è poco presidiata. Burp non fa LAN zero-config, Bettercap non ha workflow, ZAP è ostico. **Questo** è il moat, non i 148 check.

**Raccomandazione strategica**: 6-8 settimane di feature freeze per una release `v1.1 "Trust"` (solo fix + allineamento docs/deploy), poi `v1.2 "Engine"` (motore di scansione e CLI), poi il backlog feature.

---

## 2. Stato del progetto in numeri

Valori rimisurati il 27 ottobre 2026.

| Area | Misura |
|---|---|
| Backend Python | 583 file, ~57.500 righe |
| Frontend React/TS | 109 file, ~22.000 righe |
| Check passivi | 212 file in `backend/modules/scanner/passive/checks/` |
| Check attivi | 135 file, **138 registrati** dal registry automatico |
| Test | 82 file, **1113 test** (1112 passed, 1 skipped), ~63 s |
| Moduli backend | 24 package in `backend/modules/` |
| Collaborator (OAST) | 6 file Go, ~650 righe |
| Modulo nativo | 2 file C++ (parser gRPC) |
| File più grandi | `core/proxy/engine.py` 1155, `api/routes/mitm.py` 901, `main.py` 554 |
| Funzione più lunga | `_mitm_start_locked` — **369 righe** |
| `except Exception:` nudi (senza test) | **236** occorrenze |
| `print()` nel backend | **13**, solo in `nyx_cli.py` |

**I claim del README sono onesti** (210+ passive, 110+ active, 900+ test): verificati per conteggio. È raro e va detto.

### Esecuzione test

```
$ cd backend && python -m pytest tests -q --asyncio-mode=auto
884 passed, 1 skipped in 80.51s     ✅

$ cd backend && python -m pytest tests -q
1 failed, 884 passed, 1 skipped     ❌ (test async senza marcatore)
```

Il fallimento **non è un bug di codice**: `pytest-asyncio` in modalità strict richiede `@pytest.mark.asyncio`, e non esiste un `pytest.ini` che imposti `asyncio_mode = auto` (la CI passa il flag a riga di comando). Va aggiunto il file, altrimenti chiunque cloni il repo e lanci `pytest` vede un rosso che non esiste.

---

## 3. Cosa è fatto oggettivamente bene

Da non toccare, e da usare come esempio per le parti nuove:

- **Threat model scritto** (`docs/threat-model.md`) con rischi residui dichiarati e matrice di rischio. Il 90% dei tool OSS non ce l'ha.
- **Electron hardening corretto**: `nodeIntegration:false`, `contextIsolation:true`, `sandbox:true`, preload che espone 4 sole funzioni.
- **Redaction degli header** prima di DB e WebSocket; `hmac.compare_digest` per la API key; rate limiting token-bucket; origin check sui WebSocket; exception handler globale che non leakka traceback ma correla con un `request_id`.
- **Secrets store centralizzato** con lock: il classico bug del doppio write al primo boot è già risolto.
- **Emergency cleanup** su `atexit`/SIGINT/SIGTERM/SIGBREAK: IP forwarding, WinDivert, proxy di sistema, regole firewall. Questa è la parte che quasi tutti sbagliano e che lascia la macchina dell'utente senza internet dopo un crash.
- **Network layer passivo** (vedi §13, autore: traynertunder2047): deques con `maxlen`, eviction idle + hard cap sulle tabelle stream, contabilità incrementale O(1) per frame, decoders per TLS/HTTP/HTTP2/DNS/QUIC. È la parte più "da ingegnere" del repo.
- **Isolamento dei test**: DB temporaneo in `conftest.py`, reset del rate limiter per test. Molti progetti non lo fanno e hanno test flaky.
- **Commenti che spiegano il perché** di scelte controintuitive. Da preservare: sono il modo più economico di non regredire.

---

## 4. Metodologia e limiti

**Fatto**:
- Lettura di: `main.py`, `core/config.py`, `core/api_auth.py`, `core/scope.py`, `core/proxy/engine.py`, `core/proxy/addons/logger.py`, `core/storage/{database,traffic,models}.py`, `core/events/bus.py`, `core/storage/finding_events.py`, `modules/interceptor/engine.py`, `modules/automation/engine.py`, `modules/live_audit/service.py`, `modules/fuzzer/service.py`, `modules/scanner/active/scanner.py`, `api/routes/{mitm,plugins,auto_exploit,backup,network,requests,automations}.py`, `reporter/service.py`, `modules/wifi_ap.py`, `modules/content_discovery/service.py`, `desktop/{main.js,preload.js,browser.html}`, `frontend/{index.html,src/api/client.ts,src/hooks/useWebSocket.ts,src/components/Fuzzer/Fuzzer.tsx}`, `frontend/nginx.conf`, `docker-compose.yml`, `.github/workflows/ci.yml`.
- Esecuzione della suite completa (esiti sopra).
- Verifica empirica del path traversal eseguendo `ReporterService.get_report_content` con un path relativo che esce dalla directory dei report → **file letto con successo**.
- `grep` su tutto il repo per confermare che `_loaded_plugins` non abbia consumatori e che i toggle di Live Audit non siano letti.

**Non fatto**:
- Nessun exploit inviato a un backend in esecuzione (nessuna richiesta HTTP malevola, nessuna modifica a firewall/AP/IP forwarding della macchina).
- Non ho eseguito il command injection del WiFi AP: richiede privilegi di amministratore e tocca la rete. Il finding è dedotto dal codice (f-string in `shell=True` con input non validato) ed è deterministico.
- Non ho testato il comportamento su macOS/Linux reali: i finding su `pfctl`/`iptables` sono da intendersi come review statica.
- Revisione non copre esaustivamente i 212 check passivi e i 145 attivi uno per uno: sono stati campionati e verificati i pattern ricorrenti.

---

## 5. Findings — tabella riassuntiva

Legenda gravità: **P0** = da correggere prima di qualunque release; **P1** = correggere nella prossima release; **P2** = backlog pianificato.

| ID | Gravità | Categoria | Sintesi | File principali | Owner |
|---|---|---|---|---|---|
| SEC-01 | **P0** | RCE | Command injection via SSID/passphrase WiFi AP | `modules/wifi_ap.py:219-226`, `api/routes/mitm.py:685-687` | CL |
| SEC-02 | **P0** | Path traversal | Download report legge file arbitrari `*.json/html/md` | `reporter/service.py:154-161` | CL |
| SEC-03 | P1 | Auth | Bypass API key da localhost + nessuna validazione Host/Origin | `core/api_auth.py:70-71` | CL |
| SEC-04 | P1 | XSS latente | HTML del target iniettato nel DOM (Fuzzer) | `frontend/src/components/Fuzzer/Fuzzer.tsx:312,380` | CL |
| SEC-05 | P1 | Superficie inutile | Plugin: esegue codice, hook mai invocati | `api/routes/plugins.py:52` | CL |
| SEC-06 | P1 | Disclosure | README dice "SQLCipher AES-256", il DB è in chiaro | `README.md`, `docs/threat-model.md:118` | CL |
| SEC-07 | P1 | Deploy | Docker: API 401 su tutto, WebSocket rifiutato | `frontend/nginx.conf`, `core/api_auth.py:94` | CL |
| BUG-01 | P1 | Data loss | Janitor retention ordina per UUID, non per timestamp | `core/storage/traffic.py:81-87` | CL |
| BUG-02 | P1 | False negative | Deduplica check attivi ignora il parametro | `modules/scanner/active/scanner.py:388` | CL |
| BUG-03 | P1 | Feature finta | Live Audit: 4 toggle su 6 inerti | `modules/live_audit/service.py` | CL |
| BUG-04 | P1 | Perf/DB | Fuzzer: N coroutine + N client TLS, risultati interi in JSON | `modules/fuzzer/service.py:441,519` | CL |
| BUG-05 | P2 | Race | `finding.created` pubblicato prima del commit | `core/storage/finding_events.py:39-44` | CL |
| BUG-06 | P2 | Sicurezza/legale | Active scanner non verifica lo scope prima dei probe | `modules/scanner/active/scanner.py:342` | CL |
| BUG-07 | P2 | Robustezza | Nessun timeout per check: un probe appeso blocca tutto | `modules/scanner/active/scanner.py:370` | CL |
| BUG-08 | P2 | Config | `DATABASE_URL` relativo alla CWD → DB duplicati | `core/config.py:16` | CL |
| BUG-09 | P2 | UX | Paused flow senza TTL: connessione del target appesa per sempre | `modules/interceptor/engine.py` | CL |
| BUG-10 | P2 | UX | `NOISE_DOMAINS` scarta in silenzio traffico verso github.com e simili | `core/proxy/addons/logger.py:16` | CL |
| BUG-11 | P2 | Osservabilità | EventBus droppa handler in silenzio dopo 5 s di saturazione | `core/events/bus.py:43-47` | CL |
| BUG-12 | P2 | Crash | `m.lastindex` può essere `None` → `TypeError` nell'extractor | `modules/fuzzer/service.py:488` | CL |
| BUG-13 | P2 | Qualità dati | URL relativi scoperti con `host=''` | `modules/automation/engine.py:139` | CL |
| BUG-14 | P2 | Hardening | `chmod 600` è no-op su Windows | `core/secrets_store.py:45` | CL |
| BUG-15 | P2 | Hardening | `PRAGMA key = '{key}'` interpolato | `core/storage/encrypted.py:62` | CL |
| NET-01 | P2 | Robustezza | `limit` non limitato nelle API network | `api/routes/network.py:454,475,520` | TT |
| NET-02 | P2 | Robustezza | `bpf_filter` dall'API non validato (lunghezza/charset) | `api/routes/network.py:315-330` | TT |

> **Nota di equità**: i due P0 e la maggior parte dei P1 sono nel codice del maintainer principale (CL). La parte di traynertunder2047 (network layer) è la più solida del repo: i suoi finding sono di robustezza, non di sicurezza.

---

## 6. Dettaglio finding P0

### SEC-01 — Command injection via SSID/passphrase del WiFi AP

**Dove**

```python
# backend/modules/wifi_ap.py:219-226
set_cmd = (
    f'netsh wlan set hostednetwork mode=allow '
    f'ssid="{self.ssid}" key="{self.passphrase}"'
)
subprocess.run(set_cmd, shell=True, check=True, timeout=15, capture_output=True)
```

```python
# backend/api/routes/mitm.py:302-303 (nessuna validazione)
wifi_ap_ssid: str = "Nyx"
wifi_ap_passphrase: str = "nyxmitm2026"

# backend/api/routes/mitm.py:685-687
wifi_ap_manager = WiFiAPManager(
    ssid=req.wifi_ap_ssid or "Nyx",
    passphrase=req.wifi_ap_passphrase or "nyxmitm2026",
)
```

**Perché è P0**

`wifi_ap_ssid` e `wifi_ap_passphrase` arrivano grezzi dal body di `POST /api/mitm/start`, senza `Field(max_length=...)`, senza pattern, senza escaping. Vengono interpolati in una stringa eseguita con `shell=True`. Un SSID come:

```
x" & whoami & rem "
```

esegue comandi arbitrari **con i privilegi del backend**, che per fare MITM sono tipicamente amministratore. Si combina con SEC-03: qualunque processo locale (e, in teoria, una pagina web via DNS rebinding) può arrivare a esecuzione di codice.

Su Linux il percorso non è shell ma è **config injection**: un `\n` nell'SSID inietta righe arbitrarie in `hostapd.conf` (es. `interface=`, `bridge=`, `wpa=0`).

**Riproduzione (solo su macchina di test, mai su rete reale)**

```bash
curl -X POST http://127.0.0.1:8000/api/mitm/start \
  -H 'Content-Type: application/json' \
  -d '{"target_ips":["192.168.1.50"],"enable_wifi_ap":true,
       "wifi_ap_ssid":"x\" & calc & rem \"","wifi_ap_passphrase":"12345678"}'
```

**Fix**

1. Validazione nel modello Pydantic:
   - `ssid`: 1-32 caratteri, niente `"`, `\n`, `\r`, `\x00`.
   - `passphrase`: 8-63 caratteri, set ristretto `[A-Za-z0-9!@#$%^&*._-]`.
2. `subprocess.run([...], shell=False)` sul path Windows (argomenti separati).
3. Linux: scrivere `hostapd.conf` con i valori sanitizzati e righe generate da template, mai concatenazione.
4. Test: `test_wifi_ap_rejects_injection_payloads` (SSID con `"&`, `\n`, backtick; passphrase corta).
5. Verifica che il messaggio di risposta non riecheggi la passphrase (`mitm.py:691` la stampa in chiaro nei warning: ok in locale, ma non metterla nei log persistiti).

**Sforzo stimato**: 2-3 ore incluse le test.

---

### SEC-02 — Path traversal nel download dei report

**Dove**

```python
# backend/reporter/service.py:154-161
def get_report_content(self, filename: str) -> dict | None:
    filepath = self.reports_dir / filename
    if not filepath.exists() or filepath.suffix not in (".json", ".html", ".md"):
        return None
    ...
```

Esposto da `GET /api/automations/reports/{filename}` (`api/routes/automations.py:327`).

**Perché è P0**

Nessun `resolve()`, nessun `relative_to()`. Un path assoluto vince sul join (`Path("/a") / "/etc/x.json"`), e `..%2F` viene decodificato da Starlette nel path param. Il controllo sull'estensione limita a `json/html/md`, ma questo basta per leggere config, backup, altri report di engagement, `package.json`, `manifest.json` di estensioni, ecc.

**Verificato empiricamente** (non teorico):

```
payload filename: ../../../../../AppData/Local/Temp/nyx_outside_secret.json
result: {'secret': 'leaked'}
TRAVERSAL_CONFIRMED: True
```

**Fix**

```python
base = self.reports_dir.resolve()
candidate = (base / filename).resolve()
try:
    candidate.relative_to(base)
except ValueError:
    return None
if candidate.name != filename:      # blocca "..", path assoluti, separatori
    return None
if candidate.suffix not in (".json", ".html", ".md"):
    return None
```

Test: `test_get_report_content_rejects_traversal` con `../`, assoluto, `%2e%2e%2f`.

**Sforzo stimato**: 1 ora + test.

---

## 7. Dettaglio finding P1

### SEC-03 — Bypass API key da localhost e nessuna validazione dell'Host

```python
# backend/core/api_auth.py:70-71
if client_host in ("127.0.0.1", "::1", "localhost"):
    return await call_next(request)      # nessuna API key
```

Il modello "localhost = fidato" è lo stesso di Burp, ed è **accettabile come design**, ma qui convive con un'API che fa ARP/DHCP spoofing, regole firewall e shell. Due conseguenze:

1. Qualunque malware o processo locale ha controllo completo, senza key. (Accettato dal threat model, ma va documentato che la key non protegge da codice locale.)
2. **DNS rebinding**: una pagina malevola che risolve su `127.0.0.1` parla col backend come `client_host=127.0.0.1`. Le POST JSON sono bloccate dal preflight (non c'è CORS: bene), ma i GET con effetti collaterali e i **WebSocket** (nessun preflight) restano raggiungibili. `/api/auth/key` restituisce la key a chiunque risulti localhost.

**Fix minimo (mezza giornata)**

- Validare `Host` header contro `127.0.0.1:8000|localhost:8000` su tutte le rotte.
- Rifiutare `Sec-Fetch-Site: cross-site`.
- Generare un token per-boot, consegnato al renderer via IPC (l'infrastruttura esiste già: `nyxDesktop.getApiKey`).
- Non restituire la key da `/api/auth/key` se `Sec-Fetch-Site` è presente (i.e. richiesta da browser).

**Stato (SEC-03a + SEC-03b)**: tutti e quattro i punti sono implementati.
`API_REQUIRE_SESSION_TOKEN` (alzato dalla shell Electron solo nelle build
pacchettizzate) fa sì che anche un chiamante loopback debba presentare
`X-Nyx-Token`: il backend genera il token all'avvio, lo scrive in
`NYX_HOME/session.token` con permessi del solo owner (riusa `restrict_to_owner`,
quindi `icacls` su Windows) e lo rigenera a ogni boot, così non è riutilizzabile
dopo un riavvio né leggibile da un altro account. Il main process lo rilegge da
disco a ogni richiesta e lo passa al renderer via `nyxDesktop.getSessionToken`;
`frontend/src/api/client.ts` lo allega a ogni chiamata, invalida la cache su un
403 con quel detail e ritenta una volta (riavvio del backend). Restano esenti
token e API key solo le rotte che un browser semplice deve aprire: portale MITM
e download/rimozione della CA. Test: `tests/test_api_auth.py`
(403 senza/con token errato, 200 col token, gate spento di default, file
persistito).

### SEC-04 — HTML del target renderizzato come markup nel Fuzzer

```tsx
// frontend/src/components/Fuzzer/Fuzzer.tsx:312-315
const highlightedTemplate = template.replace(
  /§([^§]+)§/g,
  '<mark class="bg-purple-700 text-purple-200 rounded px-0.5">§$1§</mark>'
)
// :380
<div dangerouslySetInnerHTML={{ __html: highlightedTemplate + ' ' }} />
```

`template` contiene il body della richiesta catturata, cioè **contenuto controllato dal target**. Il replace non fa escaping. Una richiesta con `<img src=x onerror=...>` finisce nel DOM del renderer Electron, che ha `window.nyxDesktop` (`getApiKey`, `downloadCA`, `setProxyCapture`).

**Stato attuale**: il CSP (`frontend/index.html`, `script-src 'self'`) blocca gli handler inline, quindi **non è sfruttabile oggi**. Ma è una bomba a orologeria: basta un `'unsafe-inline'`, un `<svg><animate>`, o un `form-action` non ristretto (CSP3 non lo eredita da `default-src`) e la catena si chiude in XSS → API key → controllo del backend.

**Fix**: escaping **prima** del replace dei marcatori, poi wrappare. Una funzione da 5 righe, zero downside.

### SEC-05 — Il sistema di plugin esegue codice e non fa nulla

`_loaded_plugins` in `api/routes/plugins.py:52` è scritto e **mai letto**: nessun hook viene invocato nel backend (verificato con grep su tutto il repo). Quindi:

- la pagina Plugins è cosmetica;
- `register_plugin` fa `spec.loader.exec_module(module)` di un `.py` in-process con i privilegi del backend (admin durante il MITM);
- il path è confinato a `backend/plugins` (bene) ma resta **superficie di code-exec con zero beneficio**.

**Decisione da prendere** (una delle due, non entrambe):

- **A — completarlo**: addon mitmproxy che chiama `on_request`/`on_response` dei moduli caricati, con timeout, try/except e un `PluginAPI` stabile (`flow`, `helpers`, `config`).
- **B — rimuoverlo** dalla UI e dalle rotte fino a quando non c'è un contratto vero.

Per la v1.1 consiglio **B**, per la v2.0 **A**.

### SEC-06 — Il DB è in chiaro, il README dice "SQLCipher AES-256"

- `README.md` (tabella Security Hardening): "SQLCipher AES-256 encryption at-rest".
- `docs/threat-model.md:118`: "Encryption at rest via SQLCipher would add a build dependency…".
- `backend/requirements.txt`: `# pysqlcipher3>=1.2.0  # uncomment to enable at-rest encryption`.
- `core/storage/encrypted.py` esiste ma è opt-in via `NYX_SQLCIPHER_KEY`.

Due affermazioni contraddittorie nella stessa repo, e la realtà è "in chiaro di default". Inoltre la redaction copre **solo gli header**: i token nei body JSON, le password nei form e i cookie nei payload restano in chiaro. Per un tool che intercetta traffico è inevitabile, ma va detto.

**Fix**: o abiliti davvero SQLCipher nelle release (build wheel per ogni target) o correggi il README. Aggiungi un warning al primo avvio: "il DB locale contiene credenziali in chiaro; usa la cifratura del disco".

### SEC-07 — Il deployment Docker è rotto

`frontend/nginx.conf` fa `proxy_pass` senza iniettare `X-API-Key`. Il backend vede `client_host` = IP del container nginx (non localhost) → **401 su ogni chiamata API**. Nel browser `window.nyxDesktop` non esiste, quindi la SPA non ha modo di ottenere la key. In più il WebSocket viene rifiutato perché l'Origin è `http://localhost:80` e `_WS_ALLOWED_PORTS = (8000, 5173)`.

**Fix**: nginx `proxy_set_header X-API-Key $nyx_api_key` da template/env, oppure una variabile `TRUSTED_PROXIES` che autorizza la rete docker; aggiungere la porta 80 alle porte WS consentite quando il proxy è trusted. Test end-to-end: `docker compose up` → dashboard carica i dati.

---

## 8. Bug logici (dettaglio P1)

### BUG-01 — La retention cancella richieste a caso (data loss)

```python
# backend/core/storage/traffic.py:81-87
cutoff_result = await db.execute(
    select(Request.id).order_by(Request.id.asc()).offset(excess).limit(1)
)
cutoff_id = cutoff_result.scalar()
result = await db.execute(delete(Request).where(Request.id < cutoff_id))
```

`Request.id` è `uuid4()` **random** (`core/storage/models.py:51`). Ordinare per UUID non ordina per tempo: il janitor sceglie un ID casuale e cancella tutto ciò che ha UUID "minore" — circa metà del DB, indipendentemente dall'età. Con `MAX_STORED_REQUESTS=100_000` a regime è un troncamento casuale della storia, e alcune FK sono `ondelete=CASCADE` (es. `websocket_messages`), quindi porta via anche dati collegati.

**Fix**

```python
cutoff_ts = (await db.execute(
    select(Request.timestamp).order_by(Request.timestamp.desc())
    .offset(max_req - 1).limit(1)
)).scalar()
await db.execute(delete(Request).where(Request.timestamp < cutoff_ts))
```

Test: crea 10 richieste con timestamp crescenti e UUID random, verifica che sopravvivano le 5 più recenti.

### BUG-02 — La deduplica dell'active scanner ignora il parametro

```python
# backend/modules/scanner/active/scanner.py:386-391
# Deduplication key: CWE + Title + Param
dedup_key = f"{r.cwe}_{r.title}"
```

Il commento dice "Param", il codice no. Se `id` e `user_id` sono entrambi vulnerabili a SQLi sullo stesso URL, **viene riportato solo il primo**. Perdita di finding reali: il tipo di bug che fa perdere fiducia in uno scanner.

**Fix**: aggiungere il parametro a `CheckResult` e usarlo nella chiave: `f"{r.cwe}_{r.title}_{r.param}"`.

### BUG-03 — Live Audit: 4 toggle su 6 non fanno niente

In `modules/live_audit/service.py`, `active_scan`, `param_discovery`, `fuzz_discovered`, `scope_only` sono nella config, esposti dalla UI (`frontend/src/components/LiveAudit.tsx`), ma **nessuno li legge**. `active_scans_queued`/`active_scans_completed` restano a 0. `start()` imposta `auto_scan_engine._running = True` ma non tocca `auto_active_scan` (che è `False`), quindi l'audit live non scansiona mai attivamente.

**Fix**: o colleghi i toggle al `AutoScanEngine` (con scope check obbligatorio), o li rimuovi dalla UI. La seconda è più onesta e costa 20 minuti.

### BUG-04 — Fuzzer: nessun limite di concorrenza, un client TLS per payload, tutto in memoria

```python
# backend/modules/fuzzer/service.py:441
async with httpx.AsyncClient(verify=False, timeout=10) as client:

# :519-520
tasks = [send_one(pm) for pm in payload_mappings]
done = await asyncio.gather(*tasks)
```

Con una wordlist da 100k voci: **100k coroutine** create istantaneamente, ognuna con il proprio `AsyncClient` (quindi zero connection reuse: un handshake TCP+TLS per payload), e alla fine:

```python
job.results = results_list   # request+response COMPLETI in una colonna JSON
```

→ DB che esplode e UI che si blocca.

**Fix**: worker pool (`asyncio.Queue` + 20 worker), client condiviso con `httpx.Limits(max_connections=20)`, risultati in tabella dedicata con body troncati (64 KB), streaming di `fuzz.progress` ogni N. È il singolo intervento con il miglior rapporto impatto/sforzo del progetto.

---

## 9. Debito tecnico e igiene

| Voce | Misura | Rischio |
|---|---|---|
| `except Exception:` nudi | 236 (esclusi i test) | errori inghiottiti: difficile capire perché una cattura manca |
| `api/routes/mitm.py` | 901 righe, funzione da 369 | ogni modifica al MITM rischia regressioni su ARP/DHCP/AP/firewall |
| `main.py::lifespan` | 170 righe | startup non testabile, ordine degli effetti implicito |
| Registrazione check | risolta: discovery per classe, 138 check da 135 file, un superseded dichiarato | aggiungere un check ora è un solo file |
| `print()` nel backend | 13, tutti in `nyx_cli.py` | nessun log non strutturato nel servizio |
| `pytest.ini` | presente (`asyncio_mode = auto`) | risolto |
| Copertura | nessuna soglia in CI | nulla impedisce che le parti nuove scendano sotto la media |
| Attribuzione sessioni | risolta (BUG-08) | `DATABASE_URL` è ancorato a una directory stabile |

**Interventi a basso costo, alto ritorno**

1. `pytest.ini` con `asyncio_mode = auto`, `testpaths = tests`, `filterwarnings`.
2. Ruff/mypy in CI (i cache `.ruff_cache`/`.mypy_cache` suggeriscono che li usate già in locale: rendeteli bloccanti).
3. Soglia di copertura minima solo sui moduli *nuovi* (`--cov-fail-under` per package), non sull'intero repo.
4. Registry automatico dei check via `pkgutil.iter_modules` + un decoratore `@register`.
5. Spezzare `mitm.py` in `services/mitm/{spoofing,redirect,firewall,ap,status}.py`.

---

## 10. Cosa NON è un problema (per non sprecare tempo)

Da evitare come "fix", perché sono scelte deliberate e corrette:

- **`verify=False` nei check attivi.** Un proxy di pentest deve parlare con target che hanno certificati rotti o self-signed. Va documentato, non "corretto". Da rivedere solo per le chiamate *infrastrutturali* (webhook, update): là `verify=True` è già il default.
- **API key non richiesta da localhost.** È il modello di Burp. Da irrobustire contro DNS rebinding (SEC-03), non da eliminare.
- **SQLite in locale, Postgres in Docker.** Scelta sensata.
- **Nessun RBAC / multi-utente.** Dichiarato nel threat model: è un tool desktop single-user.
- **ARW/DHCP/NDP spoofing "aggressivi".** È il core del prodotto: la mitigazione è il consenso e lo scope (§12), non la rimozione.

---

## 11. Gap funzionali rispetto a Burp (feature esistenti da irrobustire)

In ordine di leva, non di difficoltà:

| # | Intervento | Perché |
|---|---|---|
| 1 | **Scope come barriera, non come filtro.** `check_scope()` prima di ogni probe/richiesta; rifiuto esplicito fuori scope. | Burp ha solo il filtro UI. Qui puoi essere *più sicuro* di Burp, ed è la base legale di tutto (incl. AP Range). |
| 2 | **Motore di scansione serio**: pool per host, rate limit per-host, timeout per check, ripresa, dedupe per `(endpoint, param, cwe)`, cancel reale. | Oggi è sequenziale e fragile: un check appeso blocca la scansione. |
| 3 | **Evidence per finding**: snapshot request/response + `curl` riproducibile + "invia in Repeater". | Il finding non porta con sé la prova: costringe a ricercare nella history. |
| 4 | **Testing multi-ruolo A/B**: due sessioni, replay con A e con B, diff risposte → IDOR/tenant isolation automatica. | È *la* feature che spinge a pagare Burp Pro. |
| 5 | **Import**: Burp XML, ZAP session, OpenAPI/Swagger (→ inventario endpoint e scan del contratto). | Oggi esporti e basta. L'import OpenAPI è poco codice e molto valore. |
| 6 | **CLI headless + CI mode**: `nyx scan --target … --fail-on high --out report.json`. | Senza questo non entri nei pipeline DevSecOps, dove i tool sopravvivono. |
| 7 | **GraphQL e WebSocket**: testing schema-driven (mutation, depth/alias bombing) e replay/fuzz dei frame WS. | Introspezione ok; il resto manca. |
| 8 | **Report**: falso positivo, edit severità/CVSS, tracking retest con data, template brandizzabili. Aggiungere NIS2/ISO 27001 a OWASP/PCI/GDPR. | I compliance report sono un differenziale già oggi. |
| 9 | **Igiene interna** (§9): split di `mitm.py`, registry check, `pytest.ini`. | Rende sostenibile tutto il resto. |

---

## 12. Nuove feature — backlog ragionato

| ID | Feature | Impatto | Sforzo | Owner proposto |
|---|---|---|---|---|
| F-01 | **Authorization Firewall (RoE engine)** — artefatto firmato per engagement (allowlist target, finestra temporale, rate cap, esclusioni) che blocca *fisicamente* il traffico fuori scope a ogni layer: proxy, scanner, MITM, DHCP/AP. Audit log firmato. | Altissimo (differenziatore + legalità) | M | CL |
| F-02 | **CLI + CI mode** (§11.6) | Altissimo (adozione) | S/M | CL |
| F-03 | **Attack Path Graph** — correla i finding in catene ("chiave API leakkata → endpoint admin → IDOR") con grafo navigabile. Burp non lo fa. | Alto | M | CL |
| F-04 | **Exploit verifier** — dopo il PoC generato, verifica che sia davvero sfruttabile (status/body/timing differenziale) e marca il finding `confirmed`/`probable`. | Alto (uccide i falsi positivi) | M | CL |
| F-05 | **Nyx Sensor** — binario Go leggero che fa capture/probe da una seconda macchina o Raspberry Pi e invia al controller. | Alto (engagement remoti, segmenti diversi) | L | TT |
| F-06 | **Mobile kit** — generatore script Frida per bypass pinning, wizard proxy Android/iOS, ADB automation per il CA. | Alto nel mercato reale | M | CL |
| F-07 | **Data-flow / privacy map** — dal traffico passivo: quali domini ricevono quali identificatori (email, device ID, token). Vista GDPR. | Medio-alto, molto vendibile | M | CL |
| F-08 | **Import PCAP** — `PCAPReader` esiste già ed è testato ma non è esposto: caricare un `.pcap` nella UI e passarlo ai decoder già scritti. | Medio, costo bassissimo | S | **TT** |
| F-09 | **QUIC visibility invece di blocking** — oggi si droppa UDP/443 per forzare il fallback TCP. Con il decoder QUIC aggregato per connection ID già presente: estrarre SNI/ALPN/versione dagli Initial e mostrare le connessioni HTTP/3 senza decifrare. | Medio-alto, differenziante | M | **TT** |
| F-10 | **Plugin SDK reale + check come policy YAML** — hook veri, timeout, sandbox; check dichiarativi per la community. | Medio (ecosistema) | M | CL (dopo F-01) |

> **Nota**: F-05, F-08, F-09 sono assegnate a TT perché sono estensioni naturali del network layer che ha già scritto. F-09 in particolare riusa `core/network/protocols/quic.py` e elimina un compromesso (drop di QUIC) che oggi è un punto debole dichiarato nel README.

---

## 13. Analisi dell'idea "router a largo raggio" → **Nyx AP Range**

### L'idea originale

> Un router con raggio molto grande che fa connettere automaticamente molti dispositivi, senza intasare la rete, ognuno con la propria connessione; con regole per collegare solo il target specifico, per restare etico e legale.

### Verdetto onesto

**L'istinto è giusto, tre premesse non reggono come sono formulate.**

**1. "Raggio molto grande" — non è realizzabile come promessa.**

In EU l'EIRP è limitato a 20 dBm (100 mW) in 2.4 GHz. La distanza si guadagna solo con antenna direzionale ad alto guadagno, che **stringe il lobo**: copri più lontano in una direzione, non "molti dispositivi sparsi". Realistico indoor: 30-80 m con antenna decente, un piano. Un raggio grande con tanti client significa anche **airtime condiviso**: la congestione non si risolve con la banda, si risolve con lo scheduling.

**2. "Si connettono automaticamente molti dispositivi" — solo in due casi.**

- SSID **aperto** e dispositivo con auto-join attivo. Ma Android 10+/iOS 14+ mostrano avvisi "weak security" e chiedono sempre più spesso conferma; Samsung/Play Protect segnalano reti sospette.
- **Evil twin di un SSID noto con la stessa PSK**, che non conosci — a meno che la rete non sia aperta o WPA-Enterprise (dove serve crackare o relayare MSCHAPv2).

Quindi "automatico" è un mito, tranne che per reti aperte o dopo un onboarding manuale. E un AP aperto raccoglie **passanti**: intercettare i loro dati è un reato, non un bug.

**3. "Ognuno con la propria connessione senza intasare" — questa parte è fattibile e interessante.**

SSID multipli sullo stesso radio (multi-BSSID), VLAN per client, policy routing verso uplink diversi, shaping per-client con `tc`, isolamento client-to-client (`ap_isolate=1`) mantenendo il forwarding verso il gateway.

### Proposta: `Nyx AP Range` (target-scoped)

```
hostapd:  bss= per ogni target/SSID, wpa2 + PMF, macaddr_acl=1 + accept_mac_file,
          max_num_sta=N, ap_isolate=1, nl80211, canali 1/6/11 o 5 GHz con DFS
dnsmasq:  dhcp-host=<MAC>,<IP> per target; dhcp-ignore=tag:!known   (solo allowlist)
nftables: drop di tutto ciò che non è in allowlist a L2/L3 (non solo DHCP)
tc/HTB:   shaping per client (es. 10 Mbit garantiti, burst) + fq_codel
ip rule:  policy routing per-client verso uplink diversi (se hai 2+ WAN)
mitm:     una istanza per client, o session attribution via peername;
          ogni flow taggato con il device → UI per-device
ROE gate: se l'allowlist è vuota l'AP NON parte; ogni associazione è audit-logged;
          auto-teardown a fine finestra + lease healing (già implementato per DHCP)
```

**Perché così è etico e legale**: il controllo non è una checkbox ma un **hard enforcement** a tre livelli (hostapd MAC ACL, DHCP allowlist, nftables). Puoi dire onestamente "questo AP non può servire dispositivi fuori dall'allowlist". Insieme a F-01 (RoE firmato) diventa una feature difendibile anche in un contesto professionale.

### Dettagli tecnici da sapere subito

- **Windows è il punto debole**: `netsh wlan set hostednetwork` è deprecato e su Windows 11 con molti driver risponde `Hosted network supported: No`. La strada corretta oggi è la **Mobile Hotspot API** (`Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager`) via WinRT/PowerShell. Senza questo, l'AP mode su Windows è fragile — ed è anche il vettore di SEC-01.
- Due radio = due canali; una radio = multi-BSSID sullo stesso canale. Per "molti dispositivi" servono 2-3 adattatori USB.
- Il caso d'uso killer **non è il pentest singolo** (dove ti servono 1-3 device), è **training/lab e demo**: 20 telefoni di studenti connessi, ognuno col suo profilo e il suo shaping. Lì "raggio grande" non serve, serve **densità**.
- Non promettere "raggio": pubblica una guida antenna/canali/EIRP per paese. È più credibile e ti distingue.

### Piano di realizzazione (dopo v1.1)

1. **Settimana 1**: estrarre `WiFiAPManager` in un servizio con backend multipli (`linux_hostapd`, `windows_hotspot`, `macos_sharing`), con interfaccia comune e test su config generation.
2. **Settimana 2**: multi-BSSID + MAC ACL + allowlist DHCP + nftables. Test: un client fuori allowlist non ottiene lease e non raggiunge il gateway.
3. **Settimana 3**: shaping per-client + policy routing + attribuzione per-device nei flow.
4. **Settimana 4**: UI (tabella device, stato per client, kill switch), integrazione con F-01, docs legali.

**Verdetto**: idea buona, nome e promessa sbagliati. Da "router potente" a "AP orchestrato, target-scoped, con shaping e RoE" diventa una feature vera, difendibile, e riusa `modules/wifi_ap.py` che esiste già.

---

## 14. Roadmap consigliata

| Release | Tema | Contenuto | Durata |
|---|---|---|---|
| **v1.1 "Trust"** | Nessuna feature nuova | SEC-01…07, BUG-01, BUG-02, BUG-03, BUG-04, `pytest.ini`, README allineato (SEC-06), Docker funzionante (SEC-07), escaping Fuzzer (SEC-04) | 2-4 settimane |
| **v1.2 "Engine"** | Il motore | Pool + rate limit per host + timeout + scope enforcement + evidence per finding + CLI headless (F-02) + BUG-06/07 | 3-4 settimane |
| **v1.3 "Workflow"** | Il flusso di lavoro | F-01 (RoE), F-03 (attack path), F-04 (verifier), import OpenAPI, multi-ruolo A/B, import PCAP (F-08) | 4-6 settimane |
| **v2.0 "Platform"** | La piattaforma | Nyx AP Range, Nyx Sensor (F-05), mobile kit (F-06), QUIC visibility (F-09), plugin SDK (F-10) | 6-10 settimane |

Regola: **una release non parte se la precedente ha finding P0 aperti**. La v1.1 non introduce feature: serve a rendere credibile tutto il resto.

---

## 15. Divisione del lavoro in due

### 15.1 Mappa di proprietà ricostruita da git

Commit totali: 65. Autori umani: 2 (+ un'identità dello stesso maintainer con email diversa).

| Autore | Commit | File toccati | Area |
|---|---|---|---|
| **CL** / Terminalkid09 | 62 | ~753 | Proxy engine, MITM (ARP/DHCP/NDP/AP), scanner, auto-exploit, fuzzer, desktop Electron, CI/release, native gRPC, collaborator, docs |
| **traynertunder2047 (TT)** | 5 | ~215 | **Network layer passivo**: `core/network/*` (capture, pcap, reassemble, protocols, stats, platform), `modules/network/*` (engine, arp_guard, icmp_detector, udp_modifier, tasks, mitm_integration), `api/routes/network.py`, `frontend/src/components/Network/*`, test del network layer |

Dettaglio dei commit di TT:

| Commit | Contenuto |
|---|---|
| `8df7029` | Decoder di protocollo (TLS, HTTP, HTTP/2, DNS, QUIC) — 903 righe |
| `2a86670` | Reassemblaggio stream TCP/UDP + statistiche live — 465 righe |
| `636290f` | `PCAP/PCAPNG writer and reader` — 215 righe |
| `70dbfe0` | Overhaul network layer: capture adattiva con watchdog interfaccia, QUIC aggregato per connection ID, packet detail Wireshark-style, eviction stream/flow — 5.899 righe |
| `57e6d42` | `sync working tree with dev-web + network layer` — commit di sincronizzazione, 204 file. **Contenuto misto**: non usarlo per attribuire proprietà. |

> **Onestà sull'attribuzione**: 4 commit su 5 sono chiaramente del network layer. Il quinto è un sync che ha trascinato dentro decine di componenti frontend (Compliance, Metrics, ActivityMonitor, …): per quei file git non permette di dire con certezza chi ha scritto cosa. La mappa sotto segue le 4 commit pulite e, per il resto, l'ipotesi "CL" (autore del 95% del repo). Da correggere se sbagliata.

### 15.2 Proprietà dei file (regola operativa)

| Area / path | Owner | Chi può toccarlo |
|---|---|---|
| `backend/core/proxy/**` | CL | CL |
| `backend/modules/{arp_spoof,dhcp_spoof,ndp_spoof,dns_spoof,wifi_ap,ca_portal}.py` | CL | CL |
| `backend/api/routes/mitm.py` | CL | CL (TT solo per il feed pacchetti, con PR separata) |
| `backend/modules/scanner/**`, `modules/auto_exploit/**`, `modules/fuzzer/**` | CL | CL |
| `backend/core/network/**`, `backend/modules/network/**` | **TT** | TT |
| `backend/api/routes/network.py` | **TT** | TT |
| `backend/tests/test_network_*.py`, `frontend/src/components/Network/**` | **TT** | TT |
| `backend/reporter/**`, `backend/modules/compliance/**` | CL | CL |
| `desktop/**`, `native/**`, `collaborator/**`, `.github/**` | CL | CL |
| `backend/core/storage/**` | CL | CL (DB condiviso: annunciare le migrazioni) |
| `frontend/src/App.tsx`, `useWebSocket.ts`, `types/index.ts` | CL | chiedere prima (file contesi) |
| `docs/**` | entrambi | PR piccole, review dell'altro |

**File contesi da trattare con protocollo esplicito**: `backend/main.py`, `backend/core/config.py`, `backend/core/storage/models.py`, `frontend/src/App.tsx`, `frontend/src/types/index.ts`, `frontend/src/hooks/useWebSocket.ts`.

Protocollo: chi tocca un file conteso apre una PR piccola (max ~150 righe) e avvisa l'altro **prima** di iniziare, non dopo. Una migrazione alembic per volta, e chi la scrive la annuncia.

### 15.3 Fase 0 — "Stop the bleeding" (settimana 1-2)

Obiettivo: chiudere i P0 e i P1 che bloccano una release credibile. **Un ticket per persona alla volta**, review incrociata obbligatoria.

**CL**
- [x] SEC-01 command injection WiFi AP + test (2-3 h)
- [x] SEC-02 path traversal report + test (1 h)
- [x] SEC-03 auth hardening: Host/`Sec-Fetch-Site`/token per-boot (4-6 h)
- [x] BUG-01 janitor per timestamp + test (2 h)
- [x] SEC-04 escaping Fuzzer (1 h)
- [x] SEC-06 allineare README/threat model alla realtà encryption (2 h)
- [x] BUG-02 dedupe con parametro (2 h)

**TT**
- [ ] SEC-07 Docker: iniezione API key + porte WS + test `docker compose up` (4-6 h)
- [ ] `pytest.ini` + verifica che `pytest` pulito passi in locale e CI (1 h)
- [ ] NET-01 limiti `Query(le=…)` sulle API network (1 h)
- [ ] NET-02 validazione `bpf_filter` (lunghezza, charset, messaggio d'errore chiaro) (2 h)
- [ ] **Audit di sicurezza del proprio network layer**: path di scrittura pcap (`PCAPWriter` con path da config), gestione memoria delle tabelle stream sotto flood, `decoder` con input malformato (fuzz dei parser) (1-2 giorni)
- [ ] BUG-11 aggiungere metrica `events_dropped` all'EventBus (2 h) — *condiviso, ma il codice è in `core/` → lo fa CL se preferite rispettare la proprietà*

> Nota: la somma CL è ~2 giorni, TT ~2-3 giorni. Se TT finisce prima, passa a F-08 (import PCAP) che è suo e a costo quasi zero.

### 15.4 Fase 1 — "Engine" (settimana 3-5)

**CL**
- [ ] BUG-06 + BUG-07: scope enforcement e timeout per check nel motore di scansione
- [ ] BUG-04: worker pool + client condiviso + risultati in tabella (il pezzo più grosso)
- [ ] BUG-05: publish dopo commit
- [ ] F-02 CLI headless, primo comando `nyx scan`
- [ ] Evidence per finding (request/response + curl) — §11.3

**TT**
- [ ] F-08 import PCAP nella UI (riusa `PCAPReader` + decoder esistenti)
- [ ] F-09 QUIC visibility (SNI/ALPN/versione dagli Initial, tabella connessioni HTTP/3)
- [ ] Hardening dei decoder: fuzz dei parser con payload malformati (hypothesis o corpus)
- [ ] Docs del network layer (è la parte meno documentata: protocolli supportati, limiti, formato PCAP)

### 15.5 Fase 2 — "Workflow" (settimana 6-9)

**CL**
- [ ] F-01 Authorization Firewall (RoE): schema, enforcement, audit log, UI
- [ ] F-03 Attack Path Graph (dipende da F-01 per lo scoring)
- [ ] F-04 Exploit verifier

**TT**
- [ ] F-05 Nyx Sensor: protocollo di forwarding, agent Go, pairing, test end-to-end
- [ ] Integrazione sensor ↔ network layer (stessi decoder, stesso formato frame)

### 15.6 Fase 3 — "Platform" (settimana 10+)

**CL**: Nyx AP Range (§13), mobile kit, plugin SDK.
**TT**: QUIC avanzato, supporto IPv6/NDP visibility, export/import formati esterni.

### 15.7 Perché questa divisione funziona

1. **Segue la proprietà reale del codice**: TT ha scritto il network layer, quindi i suoi ticket stanno lì (dove conosce ogni riga) e i fix di sicurezza stanno da CL (che ha scritto MITM e scanner).
2. **Zero overlap nelle Fasi 0-1**: nessun file toccato da entrambi tranne i contesi, gestiti col protocollo.
3. **Bilanciamento**: Fase 0 è 2 gg vs 2-3 gg; Fase 1 è ~2 settimane vs ~1,5. Se sbilanciato, TT prende F-08 (costo basso, valore medio) e poi aiuta sui test.
4. **Review incrociata con ruoli chiari**: TT revisiona il codice di sicurezza di CL (SEC-01…04) perché ha occhio da parser/network; CL revisiona il codice di TT per memory safety e gestione errori nei decoder.
5. **Nessuna riscrittura**: tutto è incrementale sul codice esistente.

---

## 16. Processo di lavoro (regole per non pestarsi i piedi)

**Branch e commit**
- `main` protetto: solo merge da `dev` a release.
- Branch per ticket: `fix/SEC-01-wifi-ap-injection`, `feat/F-02-cli`.
- Conventional commits (già usati: `fix:`, `feat:`, `ci:`, `docs:`).
- Una PR = un ticket = un finding/feature. Max ~400 righe di diff, esclusi test e lockfile.

**PR template minimo**

```
## Cosa
(1-3 righe)

## Ticket
SEC-01

## Come è stato verificato
- [ ] test aggiunto: <nome>
- [ ] pytest completo verde in locale (senza flag extra)
- [ ] se tocca l'OS: provato su <piattaforma>

## Rischio / rollback
(1-2 righe)
```

**Definition of Done** (per ogni ticket)
1. Test che **falliscono prima** del fix e passano dopo.
2. `python -m pytest backend/tests -q` verde **senza flag** (dopo `pytest.ini`).
3. Nessun nuovo `except Exception: pass` senza log.
4. Se tocca una feature documentata: docs aggiornate nello stesso commit.
5. Se tocca un file conteso: review dell'altro approvata.

**Regole anti-riscrittura**
- Nessun refactor "estetico" dentro una PR di fix.
- Un refactor strutturale (es. split di `mitm.py`) è un ticket a sé, con test esistenti verdi prima e dopo.
- Prima di aggiungere un check, verificare che non esista già un check equivalente (i duplicati sono un problema noto, §9).

**Rituale settimanale (30 min)**
- Cosa è chiuso, cosa è bloccato, chi tocca quali file contesi la settimana dopo.
- Aggiornare `docs/NYX_REVIEW_v1.0.0.md` con lo stato dei finding (checkbox), così il documento resta la single source of truth.

---

## 17. Appendice A — Comandi di verifica

```bash
# Suite completa (come in CI)
cd backend && python -m pytest tests -q --asyncio-mode=auto

# Dopo l'aggiunta di pytest.ini, deve bastare:
cd backend && python -m pytest -q

# Lint/typecheck backend (se configurati)
cd backend && ruff check . && mypy core api modules

# Frontend
cd frontend && npm run type-check && npm run lint && npm test && npm run build

# Docker end-to-end (dopo SEC-07)
docker compose up -d --build && curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1/

# Verifica rapida SEC-02 (a backend avviato)
curl -s 'http://127.0.0.1:8000/api/automations/reports/..%2F..%2Fpackage.json'
# atteso dopo il fix: 404
```

## 18. Appendice B — Checklist P0 prima della release

- [x] SEC-01: SSID/passphrase validati, `shell=False`, test di injection verdi
- [x] SEC-02: `resolve()` + `relative_to()` + `name` check, test traversal verdi
- [x] SEC-03: Host/Origin/Sec-Fetch-Site validati; `/api/auth/key` non risponde a richieste browser; token per-boot in build pacchettizzata
- [x] SEC-04: escaping prima del replace nel Fuzzer
- [x] SEC-06: README e threat model coerenti con l'implementazione reale
- [ ] SEC-07: `docker compose up` → dashboard carica dati e WebSocket connesso
- [x] BUG-01: janitor per timestamp con test
- [x] BUG-02: dedupe con parametro con test
- [x] `pytest` pulito verde senza flag
- [x] Nessun segreto in `git ls-files` (`.env`, `nyx.db`, `nyx.secret`, `*.pem`)

---

*Documento generato dalla revisione del 21 ottobre 2026. Le checkbox di §15 e §18 sono pensate per essere aggiornate durante il lavoro: questo file è la single source of truth dello stato dei fix.*
