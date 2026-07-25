const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('nyxDesktop', {
  launchBrowser: () => ipcRenderer.send('launch-browser'),
  downloadCA: () => ipcRenderer.send('download-ca'),
});
