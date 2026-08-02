const { app, BrowserWindow, dialog, ipcMain, session } = require('electron');
const { autoUpdater } = require('electron-updater');
const path = require('path');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');

const PID_FILE = path.join(os.tmpdir(), 'nyx-backend.pid');
const COLLAB_PID_FILE = path.join(os.tmpdir(), 'nyx-collaborator.pid');

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

function getPidsOnPorts(ports) {
  const { execSync } = require('child_process');
  const platform = process.platform;
  const pids = new Set();
  try {
    if (platform === 'win32') {
      const out = execSync(`netstat -ano | findstr "${ports.map(p => `:${p}`).join(' ')}"`, { timeout: 3000, encoding: 'utf8' });
      out.split('\n').forEach(line => {
        const m = line.match(/(\d+)\s*$/);
        if (m) pids.add(parseInt(m[1], 10));
      });
    } else if (platform === 'darwin') {
      const out = execSync(`lsof -i :${ports.join(' -i :')} -P -t 2>/dev/null`, { timeout: 3000, encoding: 'utf8' });
      out.trim().split('\n').forEach(pid => { if (pid) pids.add(parseInt(pid, 10)); });
    } else {
      // Linux
      let out = '';
      try { out = execSync(`ss -tlnp ${ports.map(p => `sport = :${p}`).join(' or ')} 2>/dev/null`, { timeout: 3000, encoding: 'utf8' }); } catch {}
      if (!out) {
        try { out = execSync(`netstat -tlnp 2>/dev/null`, { timeout: 3000, encoding: 'utf8' }); } catch {}
      }
      out.split('\n').forEach(line => {
        const m = line.match(/pid=(\d+)/);
        if (m) pids.add(parseInt(m[1], 10));
      });
    }
  } catch {}
  return [...pids];
}

function killOrphanBackends() {
  // Kill by PID file
  [PID_FILE, COLLAB_PID_FILE].forEach((f) => {
    try {
      const oldPid = parseInt(fs.readFileSync(f, 'utf8').trim(), 10);
      if (!isNaN(oldPid)) {
        killProcessTree(oldPid);
        try { fs.unlinkSync(f); } catch {}
      }
    } catch {}
  });
  // Kill any process holding Nyx ports (8000, 8080, 8082)
  getPidsOnPorts([8000, 8080, 8082]).forEach(pid => {
    try { killProcessTree(pid); } catch {}
  });
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
  if (!backendProcess) return;
  try {
    const pid = backendProcess.pid;
    backendProcess.killed = true;
    killProcessTree(pid);
  } catch (e) {
    console.error('Failed to stop backend:', e);
  }
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
    COLLAB_SECRET: 'nyx-secret',
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
  mainWindow = new BrowserWindow({
    width: 1280, height: 800,
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

// Only accept TLS certificates issued by the local Nyx/mitmproxy CA (the
// proxy's MITM cert). Anything else falls through to Chromium's default
// verification, so the browser does NOT globally trust arbitrary certs.
function isNyxMitmCert(req) {
  const issuer = (req.certificate && req.certificate.issuerName ? req.certificate.issuerName : '').toLowerCase();
  return issuer.includes('mitmproxy') || issuer.includes('nyx');
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
  } catch (err) {
    console.error('Failed to check proxy capture status:', err);
  }

  if (useProxy) {
    try {
      await ses.setProxy({
        proxyRules: 'http=127.0.0.1:8080;https=127.0.0.1:8080',
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
