// Preload for the integrated browsing window.
//
// browser.html is a local page with contextIsolation + sandbox, so it has no
// direct access to the main process. It needs exactly one fact — whether
// traffic is currently captured through the Nyx proxy — because the toolbar
// used to show a hard-coded "PROXIED" badge even when the proxy was off.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('nyxBrowser', {
  getProxyState: () => ipcRenderer.invoke('browser-proxy-state'),
  onProxyState: (callback) => {
    ipcRenderer.on('browser-proxy-state', (_event, state) => callback(state));
  },
});
