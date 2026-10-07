const fs = require('fs');
const path = require('path');
const { app } = require('electron');

const FILE = path.join(app.getPath('userData'), 'aegis-store.json');

const DEFAULTS = {
  settingsVersion: 2,
  settings: {
    autoQuarantine: true,
    heuristics: true,
    notifications: true,
    scanArchives: true, // arşiv içi tarama
    firewallEnabled: true,
    realtimeEnabled: false, // native daemon gerektirir
    exclusions: [],
    // Yeni nesil özellikler
    language: 'tr', // 'tr' | 'en'
    scheduledScan: false,
    scanIntervalHours: 24,
    honeypotEnabled: true, // fidye yem dosyaları
    dbAutoUpdate: false,
    dbUrl: '' // imza DB güncelleme adresi
  },
  stats: {
    filesScanned: 0,
    threatsFound: 0,
    scans: 0,
    lastScan: null,
    bytesScanned: 0
  },
  events: [],
  scanHistory: [],
  rules: [
    { id: 'r1', type: 'block', proto: 'tcp', host: 'doubleclick.net', port: null, note: 'Reklam ağı (örnek engel)' },
    { id: 'r2', type: 'block', proto: 'tcp', host: 'google-analytics.com', port: 443, note: 'Telemetri istatistikleri (örnek)' },
    { id: 'r3', type: 'allow', proto: 'tcp', host: 'api.aegis.local', port: 443, note: 'Aegis güncelleme sunucusu (yerel)' }
  ]
};

let cache = null;

const CURRENT_VERSION = 2;
const OLD_DEMO_HOSTS = ['malware.example.com', 'telemetry.bad-ads.net', 'api.aegis.local'];

function load() {
  if (cache) return cache;
  let raw = null;
  try {
    raw = JSON.parse(fs.readFileSync(FILE, 'utf8'));
  } catch {
    raw = null;
  }
  cache = Object.assign({}, DEFAULTS, raw || {});
  cache.settings = Object.assign({}, DEFAULTS.settings, (raw && raw.settings) || {});

  const ver = raw ? raw.settingsVersion || 0 : CURRENT_VERSION;
  if (raw && ver < 1) {
    if (raw.settings && 'scanArchives' in raw.settings) {
      cache.settings.scanArchives = true; // arşiv taraması artık açık
    }
  }
  if (raw && ver < 2 && Array.isArray(cache.rules)) {
    // Kullanıcı dokunmadıysa eski demo kuralları gerçek çözülenlerle yenile
    const untouched =
      cache.rules.length === 3 && cache.rules.every((r, i) => r.id === `r${i + 1}` && OLD_DEMO_HOSTS.includes(r.host));
    if (untouched) cache.rules = JSON.parse(JSON.stringify(DEFAULTS.rules));
  }
  if (!raw || ver < CURRENT_VERSION) {
    cache.settingsVersion = CURRENT_VERSION;
    save();
  }
  return cache;
}

function save() {
  try {
    fs.mkdirSync(path.dirname(FILE), { recursive: true });
    fs.writeFileSync(FILE, JSON.stringify(cache, null, 2));
  } catch (err) {
    console.error('store save failed:', err);
  }
}

module.exports = {
  getSettings: () => load().settings,
  updateSettings(patch) {
    Object.assign(load().settings, patch);
    save();
    return load().settings;
  },
  getStats: () => load().stats,
  recordScan(report, meta) {
    const s = load().stats;
    s.filesScanned += report.filesScanned;
    s.bytesScanned += report.bytesScanned;
    s.threatsFound += report.threats.length;
    s.scans += 1;
    s.lastScan = Date.now();

    // Tarama geçmişi (UI + JSON/CSV dışa aktarma)
    const h = load().scanHistory || (load().scanHistory = []);
    h.unshift({
      id: Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8),
      at: s.lastScan,
      mode: (meta && meta.mode) || report.mode || 'quick',
      duration: report.duration || 0,
      filesScanned: report.filesScanned,
      bytesScanned: report.bytesScanned,
      threatCount: report.threats.length,
      deniedCount: report.deniedCount || 0,
      stopped: !!report.stopped,
      signatureVersion: report.signatureVersion || null,
      threats: report.threats.slice(0, 200).map((t) => ({
        path: t.path,
        threat: t.threat,
        quarantined: !!t.quarantined
      }))
    });
    if (h.length > 100) h.length = 100;
    save();
  },
  getScanHistory: () => load().scanHistory || [],
  clearScanHistory() {
    load().scanHistory = [];
    save();
    return { ok: true };
  },
  getEvents: () => load().events.slice(0, 50),
  addEvent(ev) {
    const e = Object.assign({ ts: Date.now() }, ev);
    load().events.unshift(e);
    if (load().events.length > 200) load().events.length = 200;
    save();
  },
  getRules: () => load().rules,
  setRules(rules) {
    load().rules = rules;
    save();
    return load().rules;
  }
};
