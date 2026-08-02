const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('nyxDesktop', {
  launchBrowser: () => ipcRenderer.send('launch-browser'),
  downloadCA: () => ipcRenderer.send('download-ca'),
  setProxyCapture: (active) => ipcRenderer.send('toggle-proxy-capture', active),
  getApiKey: () => ipcRenderer.invoke('get-api-key'),
});

contextBridge.exposeInMainWorld('__NYX_API_KEY__', null);
