# Nyx Desktop — Guida al Test Completo

> **Versione:** 1.0.0 | **Backend:** FastAPI + mitmproxy | **Frontend:** React + Electron

---

## 1. Avvio

### Opzione A — Versione installata (packaged)

1. Esegui `Nyx Setup 1.0.0.exe` (installer) → installa con privilegi admin
2. Avvia Nyx dal menu Start / desktop shortcut
3. L'Electron app avvia automaticamente il backend (porta 8000) e apre la UI

### Opzione B — Sviluppo (dev mode)

```powershell
# Terminale 1 — Backend (NON admin, proxy già in transparent)
cd backend
uvicorn main:app --host 127.0.0.1 --port 8000

# Terminale 2 — Frontend
cd frontend
npm run dev        # → http://localhost:5173 (proxato su :8000)

# Oppure: Desktop Electron (non serve frontend separato)
cd desktop
npm start          # avvia backend + finestra Electron
```

---

## 2. Test MITM — Intercettazione Traffico

> **Prerequisiti:** PC e telefono sulla stessa rete WiFi.
> **PC:** `192.168.1.155` | **Telefono:** `192.168.1.210` | **Gateway:** `192.168.1.1`

### 2.1 Avvia Intercettazione

Dalla sidebar → **Proxy Config**

| Campo | Valore |
|---|---|
| Proxy Host | `0.0.0.0` |
| Proxy Port | `8080` |
| Mode | `transparent` |

Poi clicca **Start Interception** (o vai in sidebar → **MITM**)

Nella schermata MITM:
- **Target IP:** `192.168.1.210`
- **Gateway IP:** `192.168.1.1`
- **DNS Spoof:** ✅ ON
- Clicca **Start**

> ✅ **Verifica:** La dashboard mostra "MITM Active" con target e gateway.
> Il backend avvia:
> 1. ARP spoofing (PC impersona il gateway verso il telefono)
> 2. DNS spoofing (cattura tutte le richieste DNS)
> 3. Proxy trasparente in ascolto su `0.0.0.0:8080`

### 2.2 Genera Traffico

Usa il telefono (`192.168.1.210`) per navigare su **siti HTTP** (non HTTPS, a meno di aver installato il CA):

- `http://example.com`
- `http://httpbin.org/get`
- Qualsiasi sito HTTP

> ❗ **HTTPS** richiede installazione del certificato CA:
> - Dalla UI → clicca **Download CA** (o `GET /api/ca-certificate`)
> - Installa sul telefono come certificato attendibile
> - Su Android: Impostazioni → Sicurezza → Certificati → Installa

### 2.3 Verifica Cattura

Dalla sidebar → **Proxy**

- I request/response appaiono in tempo reale (WebSocket)
- Usa il filtro (method, host, status code)
- Clicca su un request per vedere dettagli (headers, body)

### 2.4 Ferma Intercettazione

- Torna su **MITM** → clicca **Stop**
- Il traffico viene ripristinato (ARP restore, DNS restore)
- Le sessioni catturate rimangono salvate

---

## 3. Test Scanner (Passivo + Attivo)

### 3.1 Scanner Passivo

Dalla sidebar → **Scanner** (o **Passive Findings**)

- I finding generati automaticamente dal traffico proxy appaiono qui
- Ordinabili per severità (Critical, High, Medium, Low, Info)
- Clicca su un finding → dettagli con evidenza e remediation
- Pulsante **Retest** → riconferma se la vulnerabilità persiste
- Pulsante **Send to Repeater** → invia il request originale al Repeater

### 3.2 Scanner Attivo

Dalla sidebar → **Scanner → Active Scanner**

1. Seleziona un request dalla lista proxy
2. Scegli i check da eseguire:
   - SQL Injection (SQLi)
   - Cross-Site Scripting (XSS)
   - Server-Side Request Forgery (SSRF)
   - Open Redirect
   - Local File Inclusion (LFI)
   - Insecure Direct Object Reference (IDOR)
   - Server-Side Template Injection (SSTI)
   - XML External Entity (XXE)
3. Clicca **Run Scan**
4. I risultati appaiono in tempo reale

> ✅ **API testato:** `POST /api/active-scanner/run` con `base_request` + `target_params`

### 3.3 Live Audit

Dalla sidebar → **Live Audit**

- Abilita auditing continuo sul traffico proxy
- Configura throttle, scope-only, check types
- I finding vengono generati automaticamente

---

## 4. Test Strumenti Principali

### 4.1 Repeater

Sidebar → **Repeater**

1. Crea un tab → incolla URL, method, headers, body
2. Clicca **Send**
3. Vedi la risposta (status, headers, body)
4. Naviga cronologia (History)

> ✅ **API testato:** `POST /api/repeater/send`, `GET/POST /api/repeater/tabs`

### 4.2 Decoder

Sidebar → **Decoder**

Prova tutte le trasformazioni:

| Input | Codec | Output atteso |
|---|---|---|
| `dGVzdA==` | `base64_decode` | `test` |
| `hello world` | `url_encode` | `hello%20world` |
| `hello%20world` | `url_decode` | `hello world` |
| `dGVzdA==` | Smart Decode | Rileva base64 |
| Qualsiasi stringa | Hex Dump | Output esadecimale |
| Qualsiasi stringa | Charset Detect | Encoding rilevato |

> ✅ **API testato:** Tutti i decoder endpoint funzionanti

### 4.3 Sequencer

Sidebar → **Sequencer**

1. Incolla almeno 100 token (es. da CSRF, session ID)
2. Scegli analisi:
   - **Analyze** — analisi base
   - **Detailed** — bit entropy, compression
   - **FIPS 140-2** — test standard
   - **Chi-Square, Monte Carlo, Bit Analysis** — test statistici
3. Clicca **Run**

> ✅ **API testato:** `POST /api/sequencer/analyze` con 100+ token

### 4.4 Fuzzer

Sidebar → **Fuzzer**

1. Clicca **New Job**
2. Configura target URL, positions, wordlist
3. Scegli attack type (Sniper, Pitchfork, Cluster Bomb)
4. Configura grep match / extractors
5. Clicca **Start**
6. I risultati appaiono in tempo reale

### 4.5 Crawler

Sidebar → **Crawler**

1. Inserisci URL target
2. Configura max depth, max pages, scope
3. Abilita form fill / login macro se serve
4. Clicca **Start**
5. Monitora progresso

### 4.6 Comparer

Sidebar → **Comparer**

1. Aggiungi due items da confrontare
2. Scegli confronto word-level
3. Vedi le differenze highlightate

### 4.7 Auth Tester

Sidebar → **Auth**

- JWT Decode — decodifica JWT token
- JWT Analyze — analisi header+payload
- JWT Brute Force — brute force secret
- JWT Crack — cracking con wordlist
- OAuth Debug — debug flusso OAuth

### 4.8 Content Discovery

Sidebar → **Content Discovery**

1. Inserisci URL target
2. Scegli wordlist
3. Clicca **Start**
4. Scopre directory/file nascosti

---

## 5. Test Gestione Sessioni

### 5.1 Session Handling

Sidebar → **Session Handling**

- **Cookie Jar:** vedi/cancella cookie intercettati
- **Macro:** crea macro (sequenze di request) e run
- **Session Check Rules:** definisci regole per sessioni valide

### 5.2 Match & Replace

Sidebar → **M&R Rules**

1. Crea regola → campo da matchare + sostituzione
2. Abilita/disabilita con toggle
3. Le regole si applicano automaticamente al traffico proxy

### 5.3 Interceptor

Sidebar → **Interceptor**

1. Attiva interceptor con toggle
2. I request/response vengono messi in pausa
3. Scegli: Forward (con modifiche) oppure Drop
4. Utile per manipolare traffico in tempo reale

---

## 6. Test Report

### 6.1 Genera Report

Sidebar → **Reporter**

1. Seleziona sessione
2. Scegli formato: JSON / HTML / PDF
3. Clicca **Generate**
4. Il report include: executive summary, findings matrix, recommendations

> ✅ **API testato:** `POST /api/reports/generate?session_id={uuid}&format=json`

### 6.2 Export Dati

Sidebar → Dashboard → pulsanti export:

- **Export CSV** — eventi in formato tabellare
- **Export JSON** — dati grezzi
- **Export PDF** — report formattato

---

## 7. Test Automazione

### 7.1 AutoScan & Alerts

Sidebar → **AutoScan**

- Crea template di scan automatizzato
- Configura webhook (Slack, Discord, email)
- Schedule scans periodiche

### 7.2 Scan Pipeline

Sidebar → **Scan Pipeline**

1. Crea pipeline (es. Crawl → Passive Scan → Active Scan → Report)
2. Avvia pipeline
3. Monitora progresso step-by-step

---

## 8. Verifica Finale — Checklist

| # | Test | Pass/Fail |
|---|---|---|
| 1 | Nyx Desktop si avvia (loading → UI) | □ |
| 2 | Health check funziona | □ |
| 3 | MITM Start → ARP spoof attivo | □ |
| 4 | Traffico HTTP catturato (Proxy log) | □ |
| 5 | MITM Stop → traffico ripristinato | □ |
| 6 | Scanner passivo → findings visibili | □ |
| 7 | Scanner attivo → check eseguiti | □ |
| 8 | Repeater → request/response funziona | □ |
| 9 | Decoder → tutte le trasformazioni OK | □ |
| 10 | Sequencer → analisi token funziona | □ |
| 11 | Fuzzer → job eseguito con risultati | □ |
| 12 | Crawler → crawling completato | □ |
| 13 | Comparer → diff funzionante | □ |
| 14 | Auth → JWT decode/analyze OK | □ |
| 15 | Content Discovery → risultati visibili | □ |
| 16 | Session Handling → cookie/macro OK | □ |
| 17 | Match & Replace → regole applicate | □ |
| 18 | Interceptor → pause/forward/drop OK | □ |
| 19 | Report → generato con findings | □ |
| 20 | Export CSV/JSON/PDF → download OK | □ |

---

## 9. Note Tecniche

### API Testate (riepilogo)

```
19/22 API endpoint testati con successo
Proxy:       OK   (GET/PUT /api/settings/proxy)
Decoder:     OK   (POST /api/decoder/transform, smart-decode, hex-dump, charset-detect)
Auth Scan:   OK   (GET/POST /api/auth/profiles)
Scanner:     OK   (POST /api/active-scanner/run)
Collaborator:OK   (GET /api/collaborator/generate-token, /health)
Sequencer:   OK   (POST /api/sequencer/analyze)
Dashboard:   OK   (GET /api/dashboard/stats)
MITM:        OK   (GET /api/mitm/status, /api/mitm/portal, /api/ca-certificate)
Projects:    OK   (GET /api/projects)
Sessions:    OK   (GET /api/sessions)
Reports:     OK   (POST /api/reports/generate)
```

### Admin Mode

Il backend rileva se è eseguito con privilegi admin:
- **Con admin:** ARP spoofing + netsh/iptables redirect funzionano
- **Senza admin:** Il proxy trasparente è attivo ma senza ARP spoofing (i pacchetti non vengono reindirizzati automaticamente)

L'Electron desktop può essere lanciato "as administrator" per abilitare tutte le funzionalità.

### Proxy Mode

- **Transparent** (default): Il proxy ascolta in trasparenza. Il traffico deve essere reindirizzato via ARP spoofing o firewall rules.
- **Regular**: Il proxy funge da forward proxy classico. Il client va configurato manualmente con proxy `PC_IP:8080`.
