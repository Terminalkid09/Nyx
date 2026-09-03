const { app, BrowserWindow, dialog, ipcMain, session, screen } = require('electron');
const { autoUpdater } = require('electron-updater');
const path = require('path');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');

const PID_FILE = path.join(os.tmpdir(), 'nyx-backend.pid');
const COLLAB_PID_FILE = path.join(os.tmpdir(), 'nyx-collaborator.pid');
const WINDOW_STATE_FILE = path.join(app.getPath('userData'), 'window-state.json');

autoUpdater.autoDownload = false;
autoUpdater.autoInstallOnAppQuit = true;

let backendProcess = null;
let mainWindow = null;
let loadingWindow = null;

process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err);
});
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled rejection:', reason);
});

// ── Single instance ────────────────────────────────────────────────────────
// Multiple Nyx windows spawn multiple backends that fight over ports
// 8000/8080/8082/8085: the second backend fails to bind its proxy, and the
// WinDivert API gets split across processes, which blackholes MITM targets.
// Enforce exactly one running instance; further launches focus the window.
const gotSingleInstanceLock = app.requestSingleInstanceLock()
if (!gotSingleInstanceLock) {
  app.quit()
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore()
      mainWindow.focus()
    }
  })
}

function getBackendDir() {
  if (app.isPackaged) {
    return path.join(process.resourcesPath, 'backend');
  }
  return path.join(__dirname, '..', 'backend');
}

function getFrontendDir() {
  if (app.isPackaged) {
    return path.join(process.resourcesPath, 'frontend');
  }
  return path.join(__dirname, '..', 'frontend', 'dist');
}

function getBackendExec() {
  const dir = getBackendDir();
  if (app.isPackaged) {
    const ext = process.platform === 'win32' ? '.exe' : '';
    return path.join(dir, 'nyx-backend' + ext);
  }
  return 'python';
}

function getBackendArgs() {
  if (app.isPackaged) {
    return [];
  }
  return ['-m', 'uvicorn', 'main:app', '--host', '127.0.0.1', '--port', '8000'];
}

function killProcessTree(pid) {
  if (process.platform === 'win32') {
    try {
      require('child_process').execSync(`taskkill /PID ${pid} /T /F`, { stdio: 'ignore', timeout: 3000 });
    } catch {}
  } else {
    try {
      process.kill(-pid, 'SIGKILL');
    } catch {
      try { process.kill(pid, 'SIGKILL'); } catch {}
    }
  }
}

function killOrphanBackends() {
  // Kill only the PIDs that a previous Nyx session wrote to disk. We no
  // longer kill *any* process holding ports 8000/8080/8082 — that destroyed
  // unrelated dev servers / services the user might be running on those ports.
  [PID_FILE, COLLAB_PID_FILE].forEach((f) => {
    try {
      const oldPid = parseInt(fs.readFileSync(f, 'utf8').trim(), 10);
      if (!isNaN(oldPid)) {
        killProcessTree(oldPid);
        try { fs.unlinkSync(f); } catch {}
      }
    } catch {}
  });
  // Packaged builds: also kill any stray Nyx backend processes left over from
  // previous multi-instance sessions (the PID-file race let several backends
  // start at once). nyx-backend.exe / nyx-collaborator.exe are exclusively
  // Nyx's own bundled binaries — never user processes — so killing them by
  // image name is safe. In dev mode the backend runs as `python`, which we
  // must NOT touch.
  if (app.isPackaged && process.platform === 'win32') {
    try {
      require('child_process').execSync(
        'taskkill /IM nyx-backend.exe /F /T 2>nul & taskkill /IM nyx-collaborator.exe /F /T 2>nul',
        { stdio: 'ignore', timeout: 5000 }
      );
    } catch {}
  }
}

let backendLogStream = null;

function startBackend() {
  const backendDir = getBackendDir();
  const execPath = getBackendExec();
  const execArgs = getBackendArgs();
  const frontendDist = getFrontendDir();
  const logPath = path.join(os.tmpdir(), 'nyx-backend.log');
  const nyxHome = path.join(app.getPath('userData'), 'data');
  try { fs.mkdirSync(nyxHome, { recursive: true }); } catch {}

  const env = {
    ...process.env,
    DATABASE_URL: process.env.DATABASE_URL || `sqlite+aiosqlite:///${path.join(nyxHome, 'nyx.db').replace(/\\/g, '/')}`,
    SECRET_KEY: process.env.SECRET_KEY || require('crypto').randomBytes(32).toString('hex'),
    NYX_HOME: nyxHome,
  };
  if (app.isPackaged && fs.existsSync(frontendDist)) {
    env.NYX_FRONTEND_DIST = frontendDist;
  }

  backendProcess = spawn(execPath, execArgs, {
    cwd: backendDir,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  try { backendLogStream = fs.createWriteStream(logPath, { flags: 'w' }); } catch {}
  const log = (d) => {
    process.stdout.write(`[backend] ${d}`);
    if (backendLogStream) backendLogStream.write(`${d}`);
  };
  const logErr = (d) => {
    process.stderr.write(`[backend] ${d}`);
    if (backendLogStream) backendLogStream.write(`${d}`);
  };
  let lastStderr = '';
  backendProcess.stdout.on('data', log);
  backendProcess.stderr.on('data', (d) => { lastStderr = d.toString(); logErr(d); });
  backendProcess.on('error', (err) => {
    console.error('Backend spawn error:', err);
  });
  backendProcess.on('exit', (code, signal) => {
    console.log(`Backend exited code=${code} signal=${signal}`);
    if (backendLogStream) { try { backendLogStream.end(); } catch {} backendLogStream = null; }
    if (code !== 0 && code !== null && !backendProcess.killed) {
      const detail = lastStderr.trim().slice(-200);
      dialog.showErrorBox(
        'Backend Error',
        `Nyx backend stopped unexpectedly (code ${code}).\n\nLog: ${logPath}\n\nLast error:\n${detail || '(no stderr output)'}`
      ).then(() => app.quit());
    }
  });
  backendProcess.on('close', () => {
    backendProcess = null;
  });

  try { fs.writeFileSync(PID_FILE, String(backendProcess.pid), 'utf8'); } catch {}
}

function stopBackend() {
  if (!backendProcess) {
    try { fs.unlinkSync(PID_FILE); } catch {}
    return;
  }
  const pid = backendProcess.pid;
  backendProcess.killed = true;

  // 1) Graceful first: ask the backend to flush its network state (IP
  //    forwarding, WinDivert, firewall rules, system proxy) and exit. A bare
  //    taskkill /F would skip FastAPI's teardown and leave the OS dirty.
  try {
    require('child_process').execSync(
      'curl -s -m 2 -X POST http://127.0.0.1:8000/api/shutdown',
      { stdio: 'ignore', timeout: 2500 }
    );
  } catch {}
  // 2) Give it up to ~4s to exit on its own.
  const waitCmd = process.platform === 'win32' ? 'timeout /t 1 /nobreak >nul' : 'sleep 1';
  for (let i = 0; i < 4; i++) {
    let exited = false;
    try { process.kill(pid, 0); } catch { exited = true; }
    if (exited) break;
    try { require('child_process').execSync(waitCmd, { stdio: 'ignore', timeout: 1500 }); } catch {}
  }
  // 3) Fallback: force-kill (also covers backends that never got the request).
  killProcessTree(pid);
  backendProcess = null;
  try { fs.unlinkSync(PID_FILE); } catch {}
}

let collaboratorProcess = null;

function getCollaboratorExec() {
  const dir = getBackendDir();
  if (app.isPackaged) {
    const ext = process.platform === 'win32' ? '.exe' : '';
    return path.join(dir, 'nyx-collaborator' + ext);
  }
  return process.platform === 'win32' ? path.join(__dirname, '..', 'dist', 'nyx-collaborator.exe') : path.join(__dirname, '..', 'dist', 'nyx-collaborator');
}

function startCollaborator() {
  const execPath = getCollaboratorExec();
  if (!fs.existsSync(execPath)) {
    console.log('[collaborator] Executable not found at:', execPath);
    return;
  }

  const env = {
    ...process.env,
    COLLAB_DOMAIN: 'localhost',
    COLLAB_SECRET: require('crypto').randomBytes(16).toString('hex'),
    COLLAB_HTTP_PORT: '9999',
    COLLAB_DNS_PORT: '53',
    COLLAB_API_PORT: '9090',
    COLLAB_WEBHOOK_URL: 'http://localhost:8000/api/collaborator/interactions',
  };

  collaboratorProcess = spawn(execPath, [], {
    cwd: path.dirname(execPath),
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  collaboratorProcess.stdout.on('data', (d) => process.stdout.write(`[collaborator] ${d}`));
  collaboratorProcess.stderr.on('data', (d) => process.stderr.write(`[collaborator] ${d}`));
  collaboratorProcess.on('error', (err) => console.error('Collaborator spawn error:', err));
  collaboratorProcess.on('exit', (code, signal) => console.log(`Collaborator exited code=${code} signal=${signal}`));
  collaboratorProcess.on('close', () => { collaboratorProcess = null; });

  try { fs.writeFileSync(COLLAB_PID_FILE, String(collaboratorProcess.pid), 'utf8'); } catch {}
}

function stopCollaborator() {
  if (!collaboratorProcess) return;
  try {
    const pid = collaboratorProcess.pid;
    collaboratorProcess.killed = true;
    killProcessTree(pid);
  } catch {}
  collaboratorProcess = null;
  try { fs.unlinkSync(COLLAB_PID_FILE); } catch {}
}

function pollHealth(retries = 90) {
  return new Promise((resolve, reject) => {
    const attempt = (n) => {
      if (n <= 0) return reject(new Error('Backend did not start in time'));
      const req = http.get('http://127.0.0.1:8000/health', (res) => {
        if (res.statusCode === 200) return resolve();
        setTimeout(() => attempt(n - 1), 1000);
      });
      req.on('error', () => setTimeout(() => attempt(n - 1), 1000));
      req.setTimeout(2000, () => { req.destroy(); setTimeout(() => attempt(n - 1), 1000); });
    };
    attempt(retries);
  });
}

// Remember the main window position/size between launches so the app does
// not force its own geometry every startup.
function loadWindowState() {
  try {
    const saved = JSON.parse(fs.readFileSync(WINDOW_STATE_FILE, 'utf8'));
    if (!saved || typeof saved.width !== 'number' || typeof saved.height !== 'number') return {};
    const visible = screen.getAllDisplays().some((d) => {
      const a = d.workArea;
      const x = saved.x ?? a.x;
      const y = saved.y ?? a.y;
      const intersects =
        x < a.x + a.width && x + saved.width > a.x &&
        y < a.y + a.height && y + saved.height > a.y;
      return intersects || (saved.x === undefined && saved.y === undefined);
    });
    if (!visible) return {};
    return { width: saved.width, height: saved.height, x: saved.x, y: saved.y };
  } catch {
    return {};
  }
}

function saveWindowState(win) {
  const bounds = win.getBounds();
  const data = { width: bounds.width, height: bounds.height, x: bounds.x, y: bounds.y };
  try {
    fs.writeFileSync(WINDOW_STATE_FILE, JSON.stringify(data), 'utf8');
  } catch {}
}

function trackWindowState(win) {
  if (!win) return;
  let timer = null;
  const persist = () => {
    if (win.isDestroyed()) return;
    saveWindowState(win);
  };
  const debounced = () => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(persist, 400);
  };
  win.on('resize', debounced);
  win.on('move', debounced);
  win.on('close', () => {
    if (timer) clearTimeout(timer);
    persist();
  });
}

function showLoading() {
  loadingWindow = new BrowserWindow({
    width: 420, height: 320, frame: true, transparent: false,
    alwaysOnTop: false, resizable: true, backgroundColor: '#030712',
    title: 'Starting Nyx...',
    center: true,
  });
  loadingWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(
    `<!DOCTYPE html><html><body style="background:#030712;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;color:#f59e0b;font-family:monospace;font-size:18px;flex-direction:column;gap:16px;cursor:default;-webkit-app-region:drag">
    <div style="font-size:36px;font-weight:bold;letter-spacing:4px;-webkit-app-region:no-drag">NYX</div>
    <div style="font-size:13px;color:#9ca3af" id="status">Starting backend...</div>
    <div style="width:160px;height:2px;background:#1f2937;border-radius:2px;overflow:hidden">
      <div style="width:30%;height:100%;background:#f59e0b;border-radius:2px;animation:load 1.5s ease-in-out infinite"></div>
    </div>
    <div style="font-size:11px;color:#6b7280;margin-top:8px" id="substatus">v1.0.0</div>
    <style>@keyframes load { 50% { width:80%; } }</style></body></html>`
  )}`);
  loadingWindow.on('closed', () => { loadingWindow = null; });
}

function createMainWindow() {
  const state = loadWindowState();
  mainWindow = new BrowserWindow({
    width: state.width || 1280,
    height: state.height || 800,
    x: state.x,
    y: state.y,
    title: 'Nyx \u2014 Security Testing Suite',
    autoHideMenuBar: true,
    backgroundColor: '#030712',
    icon: path.join(__dirname, 'icon.png'),
    show: false,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  trackWindowState(mainWindow);

  mainWindow.loadURL('http://127.0.0.1:8000');

  mainWindow.once('ready-to-show', () => {
    if (loadingWindow) { loadingWindow.close(); loadingWindow = null; }
    mainWindow.show();
  });

  mainWindow.webContents.on('crashed', () => {
    dialog.showErrorBox('Renderer Crashed', 'Nyx UI has crashed. The application will restart.').then(() => {
      app.relaunch();
      app.exit(0);
    });
  });

  mainWindow.on('closed', () => { mainWindow = null; });

  autoUpdater.on('update-available', (info) => {
    dialog.showMessageBox(mainWindow, {
      type: 'info', title: 'Update Available',
      message: `Nyx ${info.version} is available. Download now?`,
      buttons: ['Download', 'Later'],
    }).then((r) => { if (r.response === 0) autoUpdater.downloadUpdate(); });
  });

  autoUpdater.on('update-downloaded', () => {
    dialog.showMessageBox(mainWindow, {
      type: 'info', title: 'Update Ready',
      message: 'Update downloaded. Nyx will restart to apply it.',
      buttons: ['Restart Now', 'Later'],
    }).then((r) => { if (r.response === 0) autoUpdater.quitAndInstall(); });
  });

  mainWindow.webContents.on('did-finish-load', () => {
    setTimeout(() => autoUpdater.checkForUpdates().catch(() => {}), 3000);
  });
}

// Only accept TLS certificates cryptographically verified against the local
// Nyx/mitmproxy CA. Anything else falls through to Chromium's default
// verification, so the browser does NOT globally trust arbitrary certs.
// (Previously this matched the issuer *name*, which any attacker can forge
// by naming their own CA "mitmproxy"/"nyx".)
function isNyxMitmCert(req) {
  try {
    const { X509Certificate } = require('crypto');
    const caPath = path.join(os.homedir(), '.mitmproxy', 'mitmproxy-ca-cert.pem');
    const caPem = fs.readFileSync(caPath, 'utf8');
    const ca = new X509Certificate(caPem);
    const leaf = new X509Certificate(req.certificate.data);
    return leaf.issuer === ca.subject && leaf.verify(ca.publicKey);
  } catch {
    return false;
  }
}

async function launchBrowser() {
  const PARTITION = 'persist:nyx-browser';
  const ses = session.fromPartition(PARTITION);

  ses.setCertificateVerifyProc((req, callback) => {
    if (isNyxMitmCert(req)) {
      callback(0);
    } else {
      callback(-3); // fall back to default verification
    }
  });

  // Check if proxy capture is active
  let useProxy = false;
  let tlsMitm = true; // TLS MITM forced (CA trusted) — decrypt HTTPS
  try {
    const resp = await new Promise((resolve, reject) => {
      const req = http.get('http://127.0.0.1:8000/api/proxy/capture', { timeout: 3000 }, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => {
          try { resolve(JSON.parse(data)); } catch { reject(new Error('Bad JSON')); }
        });
      });
      req.on('error', reject);
      req.setTimeout(3000, () => { req.destroy(); reject(new Error('Timeout')); });
    });
    useProxy = resp.capture_active === true;
    tlsMitm = resp.tls_mitm !== false;
  } catch (err) {
    console.error('Failed to check proxy capture status:', err);
  }

  if (useProxy) {
    try {
      // When TLS MITM is active (CA trusted) route both http+https through the
      // proxy so HTTPS is decrypted. When the CA is NOT in the trust store we
      // must NOT force TLS MITM: route only http through the proxy and let
      // https go direct — otherwise every HTTPS page throws a cert alert.
      const rules = tlsMitm
        ? 'http=127.0.0.1:8080;https=127.0.0.1:8080'
        : 'http=127.0.0.1:8080';
      await ses.setProxy({
        proxyRules: rules,
        proxyBypassRules: '<local>',
      });
    } catch (err) {
      console.error('Failed to set proxy:', err);
    }
  } else {
    try {
      await ses.setProxy({ proxyRules: 'direct://' });
    } catch (err) {
      console.error('Failed to set direct proxy:', err);
    }
  }

  const browserWin = new BrowserWindow({
    width: 1280, height: 800,
    title: 'Nyx Browser',
    autoHideMenuBar: true,
    backgroundColor: '#030712',
    icon: path.join(__dirname, 'icon.png'),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webviewTag: true,
    },
  });

  const browserPage = path.join(__dirname, 'browser.html');
  browserWin.loadFile(browserPage);
}

function toggleProxyCapture(active) {
  const postData = JSON.stringify({ active });
  const req = http.request('http://127.0.0.1:8000/api/proxy/capture', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(postData) },
    timeout: 3000,
  });
  req.write(postData);
  req.end();
}

function downloadCA() {
  http.get('http://127.0.0.1:8000/api/ca-certificate', (res) => {
    if (res.statusCode !== 200) return;
    const filePath = path.join(app.getPath('downloads'), 'mitmproxy-ca-cert.pem');
    const file = fs.createWriteStream(filePath);
    res.pipe(file);
  });
}

app.whenReady().then(async () => {
  killOrphanBackends();
  showLoading();
  startBackend();
  startCollaborator();

  try {
    await pollHealth();
  } catch {
    if (loadingWindow) { loadingWindow.close(); loadingWindow = null; }
    dialog.showErrorBox(
      'Nyx Startup Failed',
      'Could not start Nyx backend.\n\n' +
      (app.isPackaged
        ? 'Try reinstalling the application or running as administrator.\nIf the problem persists, check the logs.'
        : 'Check your Python installation and dependencies.\nRun: cd backend && python -m uvicorn main:app')
    );
    app.quit();
    return;
  }

  createMainWindow();

ipcMain.on('launch-browser', launchBrowser);
ipcMain.on('download-ca', downloadCA);
ipcMain.on('toggle-proxy-capture', (_event, active) => toggleProxyCapture(active));

// The backend persists its API key to nyx.secret under NYX_HOME on first
// boot. Expose it to the renderer so API calls can carry X-API-Key (needed
// as soon as the API is ever bound beyond localhost).
ipcMain.handle('get-api-key', () => {
  try {
    const secretPath = path.join(app.getPath('userData'), 'data', 'nyx.secret');
    if (fs.existsSync(secretPath)) {
      const data = JSON.parse(fs.readFileSync(secretPath, 'utf8'));
      if (typeof data.api_key === 'string' && data.api_key.length >= 16) {
        return data.api_key;
      }
    }
  } catch {}
  return null;
});

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createMainWindow();
  });
});

app.on('before-quit', () => {
  stopBackend();
  stopCollaborator();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
