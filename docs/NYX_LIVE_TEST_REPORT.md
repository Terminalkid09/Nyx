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
| Backend `pytest` | **1205 passed, 1 skipped** |
| Frontend type-check / test / build | **0 errori / 35 passed / build ok** |
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

## Riproduzione

```bash
# backend + interfaccia (il desktop avvia da sé il backend)
cd desktop && npx electron .

# in un'altra shell
python .live_test/build_matrix.py
python .live_test/endpoint_sweep.py
python .live_test/write_sweep.py
python .live_test/e2e_flows.py
python .live_test/privileged_sweep.py   # richiede Nyx avviato come amministratore
npx electron .live_test/browser_smoke.js

# suite automatiche
cd backend && python -m pytest -q
cd ../frontend && npx tsc --noEmit && npm test && npm run build
```
