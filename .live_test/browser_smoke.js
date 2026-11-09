// Headless smoke test for the integrated browsing window.
//
// Loads desktop/browser.html with the real preload, stubs the two IPC calls
// the page makes, and asserts the toolbar reflects the proxy state and that
// the address bar resolves hosts (including LAN targets) instead of searching.
//
// Run: npx electron .live_test/browser_smoke.js
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');

const DESKTOP = path.join(__dirname, '..', 'desktop');
const results = [];

function check(name, actual, expected) {
  const ok = actual === expected;
  results.push({ name, ok, actual, expected });
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name} — ${JSON.stringify(actual)}`);
}

ipcMain.handle('browser-proxy-state', () => ({ capture: true, tlsMitm: false }));
ipcMain.handle('get-api-key', () => null);

app.whenReady().then(async () => {
  const win = new BrowserWindow({
    show: false,
    webPreferences: {
      preload: path.join(DESKTOP, 'browser-preload.js'),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      webviewTag: true,
    },
  });

  const pageErrors = [];
  win.webContents.on('console-message', (_e, level, message) => {
    if (level >= 2) pageErrors.push(message);
  });

  await win.loadFile(path.join(DESKTOP, 'browser.html'));
  await new Promise((resolve) => setTimeout(resolve, 1200));

  const badge = await win.webContents.executeJavaScript(
    "document.getElementById('capture-badge').textContent"
  );
  check('badge reflects capture+TLS-off', badge, '⬤ PROXIED (HTTP only)');

  const dot = await win.webContents.executeJavaScript(
    "document.getElementById('proxy-dot').style.background"
  );
  check('proxy dot is lit', dot.includes('168, 85, 247'), true);

  const hosts = await win.webContents.executeJavaScript(
    "['example.com','192.168.1.1:8080/admin','localhost:3000','admin'].map(h => HOST_LIKE.test(h))"
  );
  check('host-like detection', JSON.stringify(hosts), JSON.stringify([true, true, true, false]));

  // Re-render with capture off: the badge must stop claiming it is proxied.
  await win.webContents.executeJavaScript("applyProxyState({ capture: false, tlsMitm: true })");
  const off = await win.webContents.executeJavaScript(
    "document.getElementById('capture-badge').textContent"
  );
  check('badge shows not captured', off, '○ NOT CAPTURED');

  const webviewCount = await win.webContents.executeJavaScript(
    "document.querySelectorAll('webview').length"
  );
  check('single webview', webviewCount, 1);

  const popups = await win.webContents.executeJavaScript(
    "document.getElementById('page').hasAttribute('allowpopups')"
  );
  check('popups disabled on webview', popups, false);

  check('no console errors', pageErrors.length, 0);
  if (pageErrors.length) console.log('errors:', pageErrors);

  const failed = results.filter((r) => !r.ok).length;
  console.log(`\n${results.length - failed}/${results.length} checks passed`);
  app.exit(failed === 0 ? 0 : 1);
});
