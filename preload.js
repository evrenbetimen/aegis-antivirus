const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  // Tarama
  scanStart: (payload) => ipcRenderer.invoke('scan:start', payload),
  scanStop: () => ipcRenderer.invoke('scan:stop'),
  scanHistory: () => ipcRenderer.invoke('scan:history'),
  scanHistoryClear: () => ipcRenderer.invoke('scan:history:clear'),
  scanHistoryExport: (format) => ipcRenderer.invoke('scan:history:export', format),
  scanCustomPaths: () => ipcRenderer.invoke('scan:customPaths'),
  createEicar: () => ipcRenderer.invoke('scan:createEicar'),
  onScanProgress: (cb) => ipcRenderer.on('scan:progress', (_e, p) => cb(p)),
  onScanDone: (cb) => ipcRenderer.on('scan:done', (_e, r) => cb(r)),
  onScanError: (cb) => ipcRenderer.on('scan:error', (_e, m) => cb(m)),

  // Karantina
  quarantineList: () => ipcRenderer.invoke('quarantine:list'),
  quarantineRestore: (id) => ipcRenderer.invoke('quarantine:restore', id),
  quarantineDelete: (id) => ipcRenderer.invoke('quarantine:delete', id),
  quarantineIntegrity: () => ipcRenderer.invoke('quarantine:integrity'),

  // Firewall
  firewallRules: () => ipcRenderer.invoke('firewall:rules:get'),
  firewallSetRules: (rules) => ipcRenderer.invoke('firewall:rules:set', rules),
  firewallConnections: () => ipcRenderer.invoke('firewall:connections'),
  firewallResolve: () => ipcRenderer.invoke('firewall:resolve'),

  // İmza DB
  dbUpdate: () => ipcRenderer.invoke('db:update'),
  dbVerify: () => ipcRenderer.invoke('db:verify'),
  dbInfo: () => ipcRenderer.invoke('db:info'),

  // Ayarlar / durum
  getSettings: () => ipcRenderer.invoke('settings:get'),
  setSettings: (patch) => ipcRenderer.invoke('settings:set', patch),
  getStats: () => ipcRenderer.invoke('stats:get'),
  getEvents: () => ipcRenderer.invoke('events:get'),
  getRuntime: () => ipcRenderer.invoke('runtime:get'),
  fdaStatus: () => ipcRenderer.invoke('perm:fda'),
  appVersion: () => ipcRenderer.invoke('update:status'),
  updateCheck: () => ipcRenderer.invoke('update:check'),
  updateInstall: () => ipcRenderer.invoke('update:install'),
  onUpdateStatus: (cb) => ipcRenderer.on('update:status', (_e, s) => cb(s)),
  openPath: (p) => ipcRenderer.invoke('shell:openPath', p),
  openExternal: (url) => ipcRenderer.invoke('shell:openExternal', url),

  // Ana süreçten gelen olaylar
  onEvent: (cb) => ipcRenderer.on('event:new', (_e, ev) => cb(ev))
});
