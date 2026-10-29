# Nyx — Report di verifica live (24 ottobre 2026)

Verifica eseguita **senza Docker**, sul backend reale avviato da Electron e su
un backend standalone con database isolato. Nessun exploit inviato a host
esterni: tutto il traffico "malevolo" è rimasto verso un target locale
(`127.0.0.1:8099`).

## Metodo

| Strumento | Cosa fa |
|---|---|
| `.live_test/build_matrix.py` | Enumera `/openapi.json`, prova ogni operazione (GET reali, OPTIONS per le altre) e genera `docs/NYX_TEST_MATRIX.md` |
| `.live_test/endpoint_sweep.py` | Sweep degli endpoint di lettura + scritture mirate; segnala qualunque 5xx |
| `.live_test/write_sweep.py` | Costruisce un body valido per ogni POST/PUT/PATCH dallo schema OpenAPI |
| `.live_test/e2e_flows.py` | 17 flussi completi (proxy → finding passivi → scan attivo → repeater → fuzzer → …) |
| `.live_test/browser_smoke.js` | Carica `desktop/browser.html` in Electron e verifica badge proxy, barra indirizzi, popup, errori console |
| `backend/tests/test_api_route_contracts.py` | Cammina tutti i GET via ASGI e fallisce su qualunque 500 |
| `pytest`, `tsc`, `vitest`, `npm run build` | Suite automatiche |

Stato del database e log del backend sono stati ispezionati direttamente
(`alembic_version`, tabelle, log per richiesta) per distinguere "404 atteso" da
un bug reale.

## Risultati

| Verifica | Esito |
|---|---|
| Endpoint censiti / operazioni sondate | **290** (47 router) |
| Operazioni con almeno un riferimento nei test | 96 prima del lavoro → **tutte le GET coperte** dal nuovo contract test |
| Risposte 5xx live | **0** |
| Flussi end-to-end | **17/17** |
| Backend `pytest` | **1121 passed, 1 skipped** (misurato il 29/10) |
| Frontend type-check / test / build | **0 errori / 19 passed / build ok** (misurato il 29/10) |
| Browser integrato (smoke) | **7/7** check |
| Suite legacy in `tests/` | **83 passed** (prima: 5 failed) |
| Avvio Electron + backend + SPA | ok, nessun errore nel log |

## Bug trovati e corretti

| Componente | Sintomo osservato | Fix |
|---|---|---|
| `core/storage/database.py` | Ad ogni avvio `Alembic exited with code 1: table custom_scanner_checks already exists`; `alembic_version` vuota, migrazioni future mai applicabili | `alembic stamp head` di adozione quando lo schema esiste senza revisione |
| `modules/scanner/passive/checks/xxe_soap.py` | `Passive check xxe_soap failed: unterminated character set at position 18` | Regex `<!\[CDATA\[` corretta |
| `core/storage/crud/sessions.py` | `DELETE /api/sessions/{id}` → 500 su sessioni con traffico (`NOT NULL requests.session_id`) | Cancellazione esplicita delle tabelle di sessione |
| `reporter/service.py` + `api/routes/reporter.py` | `format=pdf` → 200 `application/pdf` con HTML dentro | 400 con messaggio + `Content-Disposition` e media type corretti |
| `api/routes/settings.py` | `PUT /api/settings/proxy` con `mode` non valido riavviava il motore e lasciava il listener morto (`WinError 64`), uccidendo l'API | Validazione modalità/porta, rollback alla config precedente |
| `api/routes/pipeline.py` | `GET /api/pipeline` → 500 `AttributeError: event_bus` | 503 con dettaglio |
| `frontend` (4 componenti) | Dati scritti sulla sessione hardcoded `0000…0001` | Usano `activeSessionId` |
| `tests/*` (legacy) | 5 test fallivano: mock senza `.text`, gate RoE non considerato, DB non isolato | `tests/conftest.py` + mock aggiornati |
| `main.py` / conftest | Ogni `pytest` cancellava il proxy di sistema di Windows all'uscita (hook atexit) | `NYX_SKIP_OS_CLEANUP` nei test: cleanup esplicito invariato |

## Hardening del browser integrato

- `browser-preload.js`: unico bridge verso il main process (stato proxy).
- Badge "PROXIED" ora riflette lo stato reale (`PROXIED + TLS`, `PROXIED (HTTP only)`, `NOT CAPTURED`).
- CSP sulla pagina di chrome; script spostato in `browser-renderer.js` (niente inline script).
- Popup negati (`setWindowOpenHandler` su chrome e su webview), navigazione limitata a http(s).
- Permessi device negati (tranne fullscreen); `will-attach-webview` forza `nodeIntegration=false`, `contextIsolation`, `sandbox` e rimuove i preload.
- Barra indirizzi: riconosce host, IP e `host:porta` (i target LAN non finiscono più su Google), HTTP per reti locali e HTTPS altrove.

## Seconda passata: endpoint privilegiati, CA, fuzzer (24/10, sera)

Gli endpoint che cambiano la macchina sono stati provati live, sia con backend
non elevato sia con Nyx avviato come amministratore: nuovo script
`.live_test/privileged_sweep.py` (settings proxy con validazione e rollback,
`/api/mitm/tls`, `/api/mitm/quic`, regole UDP, `scan-network`, MITM start/stop,
capture start/stop, export, backup, CA, shutdown). Risultato: **38/41**; le tre
voci non verdi erano lo stato non-elevato della seconda esecuzione (e ora
`POST /api/mitm/start` risponde 400 con la spiegazione invece del vecchio 500).
L'e2e è rimasto **17/17**.

| Intervento | Perché |
|---|---|
| Tabella `fuzz_results` (migrazione `9a1c4b7d2e05`) | I risultati del fuzzer vivono in una tabella, scritti a batch durante il run; `/jobs/{id}/results` ha `limit/offset/status_filter` e le job vecchie restano leggibili. Verificato live: 69 righe per job, colonna JSON vuota |
| `modules/attack_path/graph.py` limitato (500 nodi, 100 edge/host) | Il grafo era O(n²): su una sessione longeva il backend moriva esaurendo la memoria durante `GET /api/attack-path/{id}` (riprodotto: `dead=1`; dopo il fix `dead=0`) |
| `POST /api/mitm/start` senza admin → 400 | Prima 500 "WinDivert not available"; ora dice di avviare Nyx elevato o usare Stealth Mode |
| `GET /api/ca/status` + `POST /api/ca/remove` verificato | Conteggi before/after per store, `removed=false` se la CA resta (serve admin per `LocalMachine`); la UI mostra lo stato per store e spiega che l'installazione riguarda il target |

La CA dell'operatore è stata rimossa e la rimozione verificata (0/0 in
`CurrentUser` e `LocalMachine`). Per ripristinarla, se serve navigare da questo
PC: doppio clic su `%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer` →
Installa → Autorità di certificazione radice attendibili.

## Terza passata: elevazione, porte occupate, Docker (27 ottobre 2026)

Questa passata risponde a tre domande pratiche: Nyx chiede i permessi admin da
solo? Docker serve? E cosa succede se una porta è già occupata?

| Verifica | Esito |
|---|---|
| Manifest dell'eseguibile Windows | `requestedExecutionLevel level="requireAdministrator"` presente in `dist/win-unpacked/Nyx.exe`: al click Windows mostra l'UAC, senza "Esegui come amministratore" manuale. Il backend (`nyx-backend.exe`, `asInvoker`) eredita l'elevazione dal processo padre |
| Docker obbligatorio? | **No.** Il desktop avvia `nyx-backend.exe` come processo figlio (niente container); `docker-compose.yml` è solo un deployment web opzionale |
| API occupata (8000) | Desktop dev: `[nyx] API port 8000 busy -> 8001`; UI caricata, `/health` 200, WebSocket `/ws/traffic` accettato |
| Proxy occupato (8080) | `[nyx] proxy port 8080 busy -> 8082`; `GET /api/settings/proxy` → `8082`, listener attivo |
| Fallback esplicito | Con 8901/8903 occupate: API su **8902**, proxy su **8904**, `ca_portal_port` su **18082** (era 18081) |
| Traffico sul proxy di fallback | `curl -x 127.0.0.1:8904 http://<LAN>:8910/` → 200, richiesta persistita con status 200 |
| Suite automatiche | backend **1121 passed, 1 skipped**; frontend type-check 0 errori, **19** test, lint **0 errori**, build ok |
| Sweep live | `endpoint_sweep` + `write_sweep` senza 5xx (l'unico 502 è il verifier senza target raggiungibile) |
| Flussi end-to-end | **17/17** (proxy → finding passivi → scan attivo → repeater → crawler → content discovery → fuzzer → decoder → comparer) |

### Bug trovati e corretti in questa passata

| Componente | Sintomo | Fix |
|---|---|---|
| `core/proxy/engine.py` | Il preflight delle porte girava **dopo** aver costruito `Options`: il fallback aggiornava `self.port` ma mitmproxy restava sulla porta occupata (bind riuscito per `SO_REUSEADDR`, half-listener) | Preflight spostato all'inizio di `_start_mitmproxy()` |
| `core/netports.py`, `engine._port_in_use` | Su Windows un bind normale "vince" su una porta tenuta con `SO_REUSEADDR` da un indirizzo diverso (127.0.0.1 vs 0.0.0.0): la porta risultava libera | Sonda con `SO_EXCLUSIVEADDRUSE`; anche il client Electron prova `0.0.0.0` **e** `127.0.0.1` |
| `modules/ca_portal.py` | La porta del portale CA poteva essere occupata da un altro listener (bind non esclusivo) e QR/status continuavano a puntare a 18081 | Server con bind esclusivo, port walk 18081→18082, `active_port()` usato da QR, `/api/mitm/status` e DeployBox |
| `modules/mitm_status.py`, `api/routes/system.py` | I due costruttori di URL usavano `DEFAULT_PORT` invece della porta reale | Usano `active_port()` / `portal.lan_port` |

## Quarta passata: app reale e copertura delle funzioni (29 ottobre 2026)

Questa passata avvia **Nyx stessa** (`cd desktop && npx electron .`), non un
backend a mano, su una macchina dove la 8000 e la 8080 erano occupate da altri
programmi. Lo shell ha scelto **API 8001** e **proxy 8082**, e tutto il resto è
stato verificato contro quel processo.

| Verifica | Esito |
|---|---|
| Avvio shell + backend | `[nyx] API port 8000 busy -> 8001`, `[nyx] proxy port 8080 busy -> 8082`, SPA `200 text/html` con bundle caricato |
| WebSocket `/ws/traffic` | accettato con `Origin: http://127.0.0.1:8001`; rifiutato `403` con `Origin: http://evil.example` |
| Coerenza porte | `/api/settings/proxy` → `8082`, `/health` → `proxy.port 8082`, `/api/mitm/status` → `proxy_port 8082`, `ca_portal_port 18081`, `ca_portal_url` con la LAN reale |
| Flussi e2e sul backend dello shell | **17/17** (proxy capture → request salvata → 13 finding passivi → scan attivo + persistenza → repeater → custom check → crawler → content discovery → auth scan → fuzzer 69 richieste → decoder → comparer → organizer) |
| `endpoint_sweep` | **0 risposte 5xx**; 404/422 sono le risposte corrette per gli ID placeholder (ora distinte dalle failure); i 429 comparsi martellando gli endpoint sono il rate limiter locale |
| `write_sweep` | nessun 5xx (38×200, 14×201, 17×400, 37×404, 6×422) |
| `privileged_sweep` (non elevato) | **23/23**: validazione + rollback di `PUT /api/settings/proxy`, toggle TLS, `scan-network` (12 device reali), `POST /api/mitm/start` → **400** con spiegazione e porta reale 8082, CA status/remove verificata (0/0 in entrambi gli store), export HAR, backup, shutdown pulito |
| Report | `html` 200, `json` 200, `md` 200, `pdf` **400** con messaggio esplicativo (`weasyprint` assente) |
| Collaborator | `/api/collaborator/health` → `ok` (modalità `embedded`) |
| Browser integrato (smoke) | **7/7** |

### Harness allineato

`privileged_sweep.py` controllava ancora `/api/mitm/quic`, `/api/mitm/udp/*`,
`/api/network/interfaces` e `/api/network/capture/*`: route che in questo branch
non esistono più (la policy QUIC/UDP è interna al payload di `/api/mitm/start` e
i contatori sono in `/api/mitm/status`). I 405/404 che ne uscivano sembravano
regressioni. Le sezioni sono state rimosse, e su una macchina non elevata lo
script ora riporta un `NOTE` invece di un rosso: il rifiuto di `mitm/start` con
spiegazione è il comportamento atteso. Anche `endpoint_sweep.py` non tratta più
404/422 come failure.

### Cosa resta fuori (e perché)

| Funzione | Perché non è stata esercitata |
|---|---|
| MITM trasparente ARP/DHCP/NDP, redirect, QUIC drop reale | Richiede Nyx elevato (raw socket + WinDivert) e un target sulla LAN: qui il backend gira senza privilegi, quindi si è verificato il rifiuto corretto (400) e la modalità Stealth |
| Router/AP Wi-Fi (`wifi_ap.py`) | Serve una scheda in modalità hosted network e privilegi admin; fuori dal perimetro concordato |
| Intercettazione TLS end-to-end | Serve la CA installata **sul target**; su questo PC la CA è stata rimossa e la rimozione verificata |
| Rendering visivo della UI | Nessuno screenshot: la UI è verificata via HTTP, DOM, WebSocket e log console |
| Scansioni contro terze parti | Il target è `.live_test/target.py` in locale, per non mandare payload a host esterni |
| Export PDF | `weasyprint` non installato: 400 con messaggio, comportamento voluto |

## Limiti della verifica

- Il rendering visivo delle pagine non è stato ispezionato (nessuno screenshot);
  il browser è verificato via DOM e log della console.
- Le prove sui flussi che richiedono elevazione sono state fatte su un avvio
  elevato; il resto della sessione gira senza privilegi (Stealth Mode).
- `weasyprint` non è installato in questo ambiente: l'export PDF risponde 400 con
  messaggio esplicativo (comportamento voluto).
- Il target di test è un server locale; non è stata fatta una scansione contro
  applicazioni reali di terze parti.
- Restano aperti i punti elencati in `NYX_REVIEW_v1.0.0.md` §0.2 (SEC-03b,
  split `mitm.py`, UI RoE/verifier/attack-path).
- Le funzioni che richiedono privilegi o hardware (MITM trasparente, router/AP
  Wi-Fi, TLS interception con CA sul target) sono coperte solo per il ramo
  "rifiuto con spiegazione": vedi la tabella della quarta passata.

## Riproduzione

```bash
# backend + interfaccia (il desktop avvia da sé il backend)
cd desktop && npx electron .

# in un'altra shell (il target vulnerabile serve /.env con DB_PASSWORD)
python .live_test/target.py &
python .live_test/build_matrix.py
python .live_test/endpoint_sweep.py
python .live_test/write_sweep.py
python .live_test/e2e_flows.py
python .live_test/privileged_sweep.py   # senza admin salta i controlli che richiedono raw socket
npx electron .live_test/browser_smoke.js

# suite automatiche
cd backend && python -m pytest -q
cd ../frontend && npx tsc --noEmit && npm test && npm run build
```
