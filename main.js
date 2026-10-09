const { app, BrowserWindow, ipcMain, dialog, Notification, shell, safeStorage } = require('electron');
const path = require('path');
const os = require('os');
const fs = require('fs');

const store = require('./src/store');
const scanner = require('./src/scanner');
const quarantine = require('./src/quarantine');
const firewall = require('./src/firewall');
const signatures = require('./src/signatures');
const dbupdate = require('./src/dbupdate');
const permissions = require('./src/permissions');
const { createUpdater } = require('./src/updater');
const { NativeBridge, writePolicy } = require('./src/native-bridge');
const { Honeypot } = require('./src/honeypot');
const { Scheduler } = require('./src/scheduler');

// Paketle gelen imzalar app.asar içinde (salt okunur); tarama ve güncellemeler
// kullanıcı dizinindeki kopyayı kullanır (bkz. dbupdate.prepareSignaturesDir).
const BUNDLED_SIGNATURES_DIR = path.join(__dirname, 'signatures');
const SIGNATURES_DIR = path.join(app.getPath('userData'), 'signatures');
// Yayıncı açık anahtarı YALNIZCA paketten okunur — güncellemeyle değiştirilemez
const DB_PUBLIC_KEY = dbupdate.loadPublicKey(BUNDLED_SIGNATURES_DIR);
const CACHE_FILE = path.join(app.getPath('userData'), 'hash-cache.json');

let win = null;
let honeypot = null;
let scheduler = null;

function send(channel, payload) {
  if (win && !win.isDestroyed()) win.webContents.send(channel, payload);
}

const updater = createUpdater({ app, getSettings: () => store.getSettings(), send: (s) => send('update:status', s) });

function notify(title, body) {
  const settings = store.getSettings();
  if (settings.notifications && Notification.isSupported()) {
    new Notification({ title, body }).show();
  }
}

function createWindow() {
  win = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 980,
    minHeight: 640,
    titleBarStyle: 'hiddenInset',
    trafficLightPosition: { x: 18, y: 18 },
    backgroundColor: '#070b14',
    icon: path.join(__dirname, 'build', 'icon.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  // Tarayıcı önbelleğini temizle (geliştirme sırasında eski renderer kodu
  // önbellekten yüklenip kafa karıştırabilir)
  const loadTarget = () => {
    const pageArg = process.argv.find((a) => a.startsWith('--page='));
    win.loadFile(path.join(__dirname, 'renderer', 'index.html'), pageArg ? { hash: pageArg.slice(7) } : {});
  };
  win.webContents.session.clearCache().then(loadTarget, loadTarget);

  // Hata ayıklama: renderer konsol çıktısını terminale yazdır
  win.webContents.on('console-message', (...args) => {
    const [, a, b, c, d] = args;
    let level, message, line, sourceId;
    if (a && typeof a === 'object') {
      level = a.level ?? a.messageLevel;
      message = a.message;
      line = a.lineNumber ?? a.line;
      sourceId = a.sourceId;
    } else {
      level = a; message = b; line = c; sourceId = d;
    }
    if (level === 0 || level === 'verbose') return;
    console.log(`[renderer] ${message} (${sourceId}:${line})`);
  });
  win.webContents.on('did-finish-load', () => {
    console.log('[main] loaded URL:', win.webContents.getURL());
  });

  // Test bayrağı: --capture=/yol.png → sayfayı görsel olarak kaydet ve çık
  const captureArg = process.argv.find((a) => a.startsWith('--capture='));
  if (captureArg) {
    win.webContents.on('did-finish-load', () => {
      setTimeout(async () => {
        try {
          const info = await win.webContents.executeJavaScript(
            `JSON.stringify({ hash: location.hash, title: (document.querySelector('#page-title')||{}).textContent, active: (document.querySelector('.page.active')||{}).id, aegis: window.__aegis })`
          );
          console.log('[main] page info:', info);
          const img = await win.webContents.capturePage();
          fs.writeFileSync(captureArg.slice(10), img.toPNG());
          console.log('[main] capture saved:', captureArg.slice(10));
        } catch (err) {
          console.error('[main] capture failed:', err);
        }
        app.quit();
      }, 5500);
    });
  }
}

/* ---------------- Korumalı servisler: honeypot + zamanlayıcı ---------------- */

function addEvent(ev) {
  const saved = store.addEvent(ev);
  send('event:new', Object.assign({ ts: Date.now() }, ev));
  return saved;
}

/* ---------------- Native sistem genişletmeleri (native-daemon/) ---------------- */

let nativeBridge = null;
const flowSeen = new Map(); // host → son kayıt zamanı (olay seli önleme)

function onNativeEvent(ev) {
  if (ev.source === 'shield' && ev.verdict === 'deny') {
    const name = ev.threat || ev.reason || 'blocked';
    addEvent({
      type: 'threat',
      i18n: { key: 'event.shieldBlocked', vars: { name } },
      title: 'Kalkan engelledi: ' + name,
      detail: ev.path
    });
    notify('Aegis kalkanı bir uygulamayı engelledi', `${name}\n${ev.path}`);
  } else if (ev.source === 'firewall') {
    const key = ev.host || ev.rule;
    const now = Date.now();
    if (now - (flowSeen.get(key) || 0) < 60 * 1000) return;
    flowSeen.set(key, now);
    if (flowSeen.size > 500) flowSeen.clear();
    addEvent({
      type: 'info',
      i18n: { key: 'event.flowBlocked', vars: { host: ev.host || '?' } },
      title: 'Bağlantı engellendi: ' + (ev.host || '?'),
      detail: ev.rule ? `kural ${ev.rule}` : ''
    });
  }
}

function applyShieldPolicy(settings) {
  try {
    writePolicy(app.getPath('userData'), settings);
  } catch (err) {
    console.warn('[native] kalkan politikası yazılamadı:', err && err.message);
  }
}

function startNativeBridge() {
  if (process.platform !== 'darwin') return;
  const socketPath = path.join(app.getPath('userData'), 'aegis.sock');
  if (Buffer.byteLength(socketPath) > 103) {
    console.warn('[native] socket yolu çok uzun, köprü başlatılmadı:', socketPath);
    return;
  }
  nativeBridge = new NativeBridge({ socketPath, onEvent: onNativeEvent });
  nativeBridge.start().catch((err) => {
    console.warn('[native] köprü başlatılamadı:', err && err.message);
    nativeBridge = null;
  });
}

function applyHoneypot(settings) {
  const want = !!settings.honeypotEnabled;
  if (want && (!honeypot || !honeypot.running)) {
    if (honeypot) honeypot.stop();
    honeypot = new Honeypot({
      onEvent: (ev) => {
        addEvent({
          type: 'ransomware',
          i18n: { key: 'event.ransomware', vars: { kind: ev.kind } },
          title: 'Fidye şüphesi: ' + ev.kind,
          detail: `${ev.detail} — ${ev.path}`
        });
        notify('Aegis: Fidye aktivitesi', ev.detail);
      }
    });
    honeypot.start();
  } else if (!want && honeypot && honeypot.running) {
    honeypot.stop();
  }
}

function applyScheduler(settings) {
  const want = !!settings.scheduledScan;
  if (want) {
    if (!scheduler) {
      scheduler = new Scheduler({
        intervalHours: settings.scanIntervalHours || 24,
        onTick: () => {
          if (scanner.isScanning()) return;
          startScan({ paths: [], scheduled: true });
        }
      });
    }
    scheduler.setIntervalHours(settings.scanIntervalHours || 24);
    if (!scheduler.enabled) scheduler.start();
  } else if (scheduler && scheduler.enabled) {
    scheduler.stop();
  }
}

/* ---------------- Tarama ---------------- */

function startScan(payload) {
  if (scanner.isScanning()) return { ok: false, reason: 'busy' };

  const settings = store.getSettings();
  let paths = payload && payload.paths;
  const mode = payload && payload.scheduled ? 'scheduled' : paths && paths.length ? 'custom' : 'quick';
  if (!paths || paths.length === 0) {
    const home = os.homedir();
    paths = [
      path.join(home, 'Downloads'),
      path.join(home, 'Desktop'),
      path.join(home, 'Documents'),
      '/Applications'
    ];
  }

  scanner
    .run(
      {
        paths,
        heuristics: settings.heuristics,
        autoQuarantine: settings.autoQuarantine,
        scanArchives: settings.scanArchives,
        exclusions: settings.exclusions || [],
        signaturesDir: SIGNATURES_DIR,
        cacheFile: CACHE_FILE
      },
      (p) => send('scan:progress', p)
    )
    .then((report) => {
      store.recordScan(report, { mode });
      for (const th of report.threats) {
        addEvent({
          type: 'threat',
          i18n: { key: 'event.threat', vars: { name: th.threat } },
          title: 'Tehdit: ' + th.threat,
          detail: th.path
        });
      }
      addEvent({
        type: 'scan',
        i18n: {
          key: 'event.scanDone',
          vars: { files: report.filesScanned, threats: report.threats.length }
        },
        title: 'Tarama tamamlandı',
        detail: `${report.filesScanned} dosya tarandı, ${report.threats.length} tehdit`
      });
      if (report.deniedCount > 0) {
        addEvent({
          type: 'warning',
          i18n: { key: 'event.permissionDenied', vars: { n: report.deniedCount } },
          title: 'Erişim izni yok',
          detail: (report.deniedDirs || []).slice(0, 2).join(', ')
        });
      }
      send('scan:done', report);
      if (report.threats.length > 0) {
        notify('Aegis: Tehdit bulundu', `${report.threats.length} tehdit işlendi`);
      }
    })
    .catch((err) => {
      send('scan:error', String(err && err.message ? err.message : err));
    });

  return { ok: true };
}

/* ---------------- IPC: Tarama ---------------- */

ipcMain.handle('scan:start', (_e, payload) => startScan(payload));
ipcMain.handle('scan:stop', () => {
  scanner.stop();
  return { ok: true };
});
ipcMain.handle('scan:customPaths', async () => {
  const res = await dialog.showOpenDialog(win, {
    properties: ['openDirectory', 'multiSelections', 'createDirectory']
  });
  return res.canceled ? [] : res.filePaths;
});
ipcMain.handle('scan:createEicar', () => scanner.createEicarTestFile());

/* ---------------- IPC: Tarama geçmişi ---------------- */

// CSV hücresi: tırnak kaçışı + formül enjeksiyonu koruması. Dosya adları
// saldırgan kontrolünde olabilir ("=HYPERLINK(...).exe"); = + - @ ile
// başlayan hücreler elektronik tabloda formül olarak çalışmasın diye ' alır.
function csvCell(v) {
  let s = v == null ? '' : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return /[",\n\r;]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

function eventsToCSV(items) {
  const rows = [['tarih', 'tur', 'baslik', 'ayrinti'].join(',')];
  for (const e of items) {
    rows.push([new Date(e.ts || 0).toISOString(), e.type, e.title, e.detail].map(csvCell).join(','));
  }
  return rows.join('\n') + '\n';
}

async function saveExport(fmt, content, title, baseName) {
  const res = await dialog.showSaveDialog(win, {
    title,
    defaultPath: path.join(app.getPath('documents'), `${baseName}.${fmt}`),
    filters: [{ name: fmt.toUpperCase(), extensions: [fmt] }]
  });
  if (res.canceled || !res.filePath) return { ok: false, canceled: true };
  try {
    fs.writeFileSync(res.filePath, content);
    return { ok: true, path: res.filePath };
  } catch (err) {
    return { ok: false, error: String(err.message || err) };
  }
}

function historyToCSV(items) {
  const esc = csvCell;
  const rows = [
    ['tarih', 'mod', 'sure_ms', 'dosya', 'bayt', 'tehdit', 'izin_hatasi', 'kesildi', 'imza_surumu', 'tehditler'].join(',')
  ];
  for (const h of items) {
    rows.push(
      [
        new Date(h.at).toISOString(),
        h.mode,
        h.duration,
        h.filesScanned,
        h.bytesScanned,
        h.threatCount,
        h.deniedCount,
        h.stopped ? 1 : 0,
        h.signatureVersion || '',
        (h.threats || []).map((t) => `${t.threat} @ ${t.path}`).join(' | ')
      ]
        .map(esc)
        .join(',')
    );
  }
  return rows.join('\n');
}

ipcMain.handle('scan:history', () => store.getScanHistory());
ipcMain.handle('scan:history:clear', () => store.clearScanHistory());
ipcMain.handle('scan:history:export', async (_e, format) => {
  const fmt = format === 'csv' ? 'csv' : 'json';
  const items = store.getScanHistory();
  const content =
    fmt === 'csv'
      ? historyToCSV(items)
      : JSON.stringify(
          { app: 'Aegis Security Suite', exportedAt: new Date().toISOString(), count: items.length, scans: items },
          null,
          2
        );
  return saveExport(
    fmt,
    content,
    fmt === 'csv' ? 'Tarama geçmişini CSV kaydet' : 'Tarama geçmişini JSON kaydet',
    'aegis-tarama-gecmisi'
  );
});

ipcMain.handle('events:export', async (_e, format) => {
  const fmt = format === 'csv' ? 'csv' : 'json';
  const items = store.getEvents();
  const content =
    fmt === 'csv'
      ? eventsToCSV(items)
      : JSON.stringify({ app: 'Aegis Security Suite', exportedAt: new Date().toISOString(), count: items.length, events: items }, null, 2);
  return saveExport(
    fmt,
    content,
    fmt === 'csv' ? 'Etkinlik kaydını CSV kaydet' : 'Etkinlik kaydını JSON kaydet',
    'aegis-etkinlik-kaydi'
  );
});

/* ---------------- IPC: Karantina ---------------- */

ipcMain.handle('quarantine:list', () => quarantine.list());
ipcMain.handle('quarantine:restore', async (_e, id) => {
  const r = await quarantine.restore(id);
  if (r && r.ok) {
    addEvent({ type: 'info', i18n: { key: 'event.quarantineRestored' }, title: 'Karantinadan geri yüklendi', detail: r.path });
  }
  return r;
});
ipcMain.handle('quarantine:delete', (_e, id) => quarantine.remove(id));
ipcMain.handle('quarantine:integrity', () => quarantine.verifyAll());

/* ---------------- IPC: Firewall ---------------- */

ipcMain.handle('firewall:rules:get', () => firewall.getRules());
ipcMain.handle('firewall:rules:set', (_e, rules) => firewall.setRules(rules));
ipcMain.handle('firewall:connections', () => firewall.getConnections());
ipcMain.handle('firewall:resolve', async () => {
  try {
    return await firewall.resolveRules(firewall.getRules());
  } catch {
    return {};
  }
});

/* ---------------- IPC: İmza DB ---------------- */

ipcMain.handle('db:info', async () => {
  try {
    const db = signatures.load(SIGNATURES_DIR);
    return { version: db.version, count: db.sha256.size + db.rules.length, skipped: (db.skipped || []).length };
  } catch (err) {
    return { reason: String(err.message || err) };
  }
});

async function runDbUpdate() {
  const settings = store.getSettings();
  if (!settings.dbUrl) return { ok: false, reason: 'Güncelleme adresi ayarlanmamış (Ayarlar → İmza veritabanı)' };
  const res = await dbupdate.update({ url: settings.dbUrl, dir: SIGNATURES_DIR, publicKey: DB_PUBLIC_KEY });
  if (res.ok && res.changed) {
    addEvent({
      type: 'info',
      i18n: { key: 'event.dbUpdated', vars: { version: res.version } },
      title: 'İmza DB güncellendi',
      detail: `${res.count} imza`
    });
  }
  return res;
}

ipcMain.handle('db:update', () => runDbUpdate());

// Otomatik imza güncellemesi: açılıştan kısa süre sonra, sonra her 6 saatte bir
const DB_AUTO_UPDATE_MS = 6 * 60 * 60 * 1000;
let dbUpdateTimer = null;
function scheduleDbAutoUpdate() {
  const tick = async () => {
    const settings = store.getSettings();
    if (!settings.dbAutoUpdate || !settings.dbUrl) return;
    try {
      const res = await runDbUpdate();
      if (!res.ok) console.warn('[signatures] otomatik güncelleme başarısız:', res.reason);
    } catch (err) {
      console.warn('[signatures] otomatik güncelleme hatası:', err);
    }
  };
  setTimeout(tick, 20 * 1000).unref();
  dbUpdateTimer = setInterval(tick, DB_AUTO_UPDATE_MS);
  dbUpdateTimer.unref();
}

ipcMain.handle('db:verify', () => dbupdate.verifyLocal(SIGNATURES_DIR, DB_PUBLIC_KEY, BUNDLED_SIGNATURES_DIR));

/* ---------------- IPC: Ayarlar / durum / kabuk ---------------- */

ipcMain.handle('settings:get', () => store.getSettings());
ipcMain.handle('settings:set', (_e, patch) => {
  const s = store.updateSettings(patch);
  applyHoneypot(s);
  applyScheduler(s);
  applyShieldPolicy(s);
  return s;
});
ipcMain.handle('stats:get', () => store.getStats());
ipcMain.handle('events:get', () => store.getEvents());
ipcMain.handle('runtime:get', () => ({
  honeypot: honeypot ? honeypot.status() : { running: false },
  scheduler: scheduler ? scheduler.status() : { enabled: false },
  native: nativeBridge ? nativeBridge.status() : { listening: false, connected: false },
  scanning: scanner.isScanning()
}));

ipcMain.handle('update:status', () => updater.status());
ipcMain.handle('update:check', () => updater.check());
ipcMain.handle('update:install', () => updater.install());
ipcMain.handle('perm:fda', () => permissions.fullDiskAccessStatus());

ipcMain.handle('shell:openPath', (_e, p) => shell.showItemInFolder(p));
ipcMain.handle('shell:openExternal', (_e, url) => {
  const allowed = /^(x-apple\.systempreferences:|https?:\/\/)/i.test(String(url || ''));
  if (!allowed) return { ok: false };
  shell.openExternal(String(url));
  return { ok: true };
});

/* ---------------- Uygulama yaşam döngüsü ---------------- */

app.whenReady().then(() => {
  try {
    dbupdate.prepareSignaturesDir(BUNDLED_SIGNATURES_DIR, SIGNATURES_DIR);
  } catch (err) {
    console.error('[signatures] kullanıcı imza dizini hazırlanamadı:', err);
  }
  // Karantina anahtarı → Keychain (safeStorage); kullanılamazsa dosya anahtarı
  quarantine.initSecureKey(safeStorage);
  // Eski restore() sürümünden kalan orfan .qtn artıklarını temizle
  try {
    const orphans = quarantine.cleanupOrphans();
    if (orphans > 0) console.log(`[quarantine] ${orphans} orfan karantina artığı temizlendi`);
  } catch {}
  createWindow();
  scheduleDbAutoUpdate();
  updater.schedule();
  const settings = store.getSettings();
  applyShieldPolicy(settings);
  startNativeBridge();
  applyHoneypot(settings);
  applyScheduler(settings);
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (honeypot) honeypot.stop();
  if (scheduler) scheduler.stop();
  if (process.platform !== 'darwin') app.quit();
});

app.on('will-quit', () => {
  if (nativeBridge) nativeBridge.stop();
  if (honeypot) honeypot.stop();
  if (scheduler) scheduler.stop();
});
