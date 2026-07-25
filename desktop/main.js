const { app, BrowserWindow, dialog, ipcMain } = require('electron');
const { autoUpdater } = require('electron-updater');
const path = require('path');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');

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

function killOrphanBackends() {
  if (process.platform === 'win32') {
    try {
      require('child_process').execSync('taskkill /IM nyx-backend.exe /F', { stdio: 'ignore', timeout: 3000 });
    } catch {}
    try {
      require('child_process').execSync('taskkill /IM nyx-collaborator.exe /F', { stdio: 'ignore', timeout: 3000 });
    } catch {}
  }
}

function startBackend() {
  const backendDir = getBackendDir();
  const execPath = getBackendExec();
  const execArgs = getBackendArgs();
  const frontendDist = getFrontendDir();

  const env = {
    ...process.env,
    DATABASE_URL: process.env.DATABASE_URL || 'sqlite+aiosqlite:///nyx.db',
    SECRET_KEY: process.env.SECRET_KEY || require('crypto').randomBytes(32).toString('hex'),
  };
  if (app.isPackaged && fs.existsSync(frontendDist)) {
    env.NYX_FRONTEND_DIST = frontendDist;
  }

  backendProcess = spawn(execPath, execArgs, {
    cwd: backendDir,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  backendProcess.stdout.on('data', (d) => process.stdout.write(`[backend] ${d}`));
  backendProcess.stderr.on('data', (d) => process.stderr.write(`[backend] ${d}`));
  backendProcess.on('error', (err) => {
    console.error('Backend spawn error:', err);
  });
  backendProcess.on('exit', (code, signal) => {
    console.log(`Backend exited code=${code} signal=${signal}`);
    if (code !== 0 && code !== null && !backendProcess.killed) {
      dialog.showErrorBox(
        'Backend Error',
        `Nyx backend stopped unexpectedly (code ${code}).\n\nThe application will close. Please restart Nyx.`
      ).then(() => app.quit());
    }
  });
  backendProcess.on('close', () => {
    backendProcess = null;
  });
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
    COLLAB_API_PORT: '9090'
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
}

function stopCollaborator() {
  if (!collaboratorProcess) return;
  try {
    const pid = collaboratorProcess.pid;
    collaboratorProcess.killed = true;
    killProcessTree(pid);
  } catch {}
  collaboratorProcess = null;
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

async function launchBrowser() {
  const browserWin = new BrowserWindow({
    width: 1280, height: 800,
    title: 'Nyx Browser',
    autoHideMenuBar: true,
    backgroundColor: '#030712',
    icon: path.join(__dirname, 'icon.png'),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: false,
    },
  });

  browserWin.webContents.session.setCertificateVerifyProc((req, callback) => {
    callback(0);
  });

  try {
    await browserWin.webContents.session.setProxy({
      proxyRules: 'http=127.0.0.1:8080;https=127.0.0.1:8080',
      proxyBypassRules: '<local>',
    });
  } catch (err) {
    console.error('Failed to set proxy:', err);
  }

  browserWin.loadURL('http://example.com');
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