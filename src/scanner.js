const fs = require('fs');
const path = require('path');
const os = require('os');
const { Worker } = require('worker_threads');
const { app } = require('electron');

const signatures = require('./signatures');
const { HashCache } = require('./cache');
const { scanFileCore, EICAR } = require('./filescan');

// Arşiv modülü (varsa) — yoksa arşiv taraması devre dışı kalır
let archive = null;
try {
  archive = require('./archive');
} catch {
  archive = null;
}

const QUARANTINE_DIR = path.join(app.getPath('userData'), 'quarantine');

// Ek yerel imzalar (test/aktarma için) — db yüklenince birleştirilir
// (EICAR dizgisi ve hashFile src/filescan.js'e taşındı — worker ile ortak)
const SIGNATURES = new Map([
  ['275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'EICAR-Test-File'],
  ['ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'Demo.Fake-Threat']
]);

function ensureDir() {
  fs.mkdirSync(QUARANTINE_DIR, { recursive: true });
}

function listFiles(dir, exclusions, out, depth, ctx) {
  if (depth > 24) return;
  const denied = (code) => {
    if (ctx && (code === 'EPERM' || code === 'EACCES')) ctx.denied.push(dir);
  };
  // Dosya yolu verilmişse (ör. EICAR test) doğrudan ekle
  let st;
  try {
    st = fs.statSync(dir);
  } catch (err) {
    denied(err && err.code);
    return; // yok / izin yok
  }
  if (st.isFile()) {
    out.push(dir);
    return;
  }
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    denied(err && err.code);
    return; // izin yok (Tam Disk Erişimi) vs.
  }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (isExcluded(full, exclusions)) continue;
    if (e.isDirectory()) {
      if (e.name === 'quarantine' || e.name === 'node_modules' || e.name.startsWith('.')) continue;
      listFiles(full, exclusions, out, depth + 1, ctx);
    } else if (e.isFile()) {
      out.push(full);
    }
  }
}

/** Dışlama yolun kendisi ya da üst dizini mi? ("/a/proje" → "/a/proje2" dışlanmaz) */
function isExcluded(full, exclusions) {
  return exclusions.some((x) => {
    const base = String(x || '').replace(/[\\/]+$/, '');
    if (!base) return false;
    return full === base || full.startsWith(base + path.sep);
  });
}

function heuristicCheck(file, size) {
  const base = path.basename(file).toLowerCase();
  // Çift uzantı: fatura.pdf.exe tarzı
  if (/\.(pdf|doc|docx|jpg|png|txt|xls|xlsx)\.(exe|scr|bat|cmd|js|vbs|app|dmg)$/.test(base)) {
    return { threat: 'Suspicious.DoubleExtension', detail: 'Şüpheli çift dosya uzantısı' };
  }
  // İndirilenler klasöründe Windows çalıştırılabiliri
  if (/\.(exe|scr)$/.test(base) && file.includes('/Downloads/')) {
    return { threat: 'Suspicious.WindowsBinary', detail: 'İndirilenler klasöründe Windows çalıştırılabilir dosyası' };
  }
  // Otomatik başlatma girişi (kalıcılık)
  if (file.includes('/Library/LaunchAgents/') || file.includes('/Library/LaunchDaemons/')) {
    if (size > 0 && size < 5 * 1024 * 1024) {
      return { threat: 'Suspicious.Persistence', detail: 'LaunchAgent/LaunchDaemon içinde şüpheli dosya' };
    }
  }
  return null;
}

async function moveToQuarantine(file, meta) {
  // Şifreli karantina modülüne devret
  const quarantine = require('./quarantine');
  return quarantine.store(file, meta);
}

/* ------------------------- Paralel tarama havuzu -------------------------- */

// Bu dosya sayısında worker havuzu kurulmaz (küçük taramalarda spawn maliyeti
// kazançtan büyük olur) — doğrudan ana iş parçacığında taranır.
const INLINE_THRESHOLD = 8;
const MAX_WORKERS = Math.max(1, Math.min(6, (os.cpus() || []).length - 1));

/**
 * Basit FIFO worker havuzu.
 * - Her worker kendi imza DB'sini init mesajıyla yükler ("ready" der).
 * - Boşta olana iş verilir; backpressure doğrudan havuz boyutuyla sınırlıdır.
 * - Worker ölürse görev reddedilir → çağıran taraf ana iş parçacığında yedekler.
 */
class WorkerPool {
  constructor(size, initMsg) {
    this.size = size;
    this.slots = [];
    this.queue = [];
    this.seq = 0;
    this.destroyed = false;
    for (let i = 0; i < size; i++) this._spawn(initMsg);
  }

  _spawn(initMsg) {
    const slot = { w: null, ready: false, pending: null, dead: false, timer: null };
    this.slots.push(slot);
    try {
      slot.w = new Worker(path.join(__dirname, 'scan-worker.js'));
    } catch {
      slot.dead = true;
      return;
    }
    slot.timer = setTimeout(() => this._kill(slot, new Error('worker hazır olma zaman aşımı')), 15000);
    if (slot.timer.unref) slot.timer.unref();

    slot.w.on('message', (msg) => {
      if (!msg) return;
      if (msg.type === 'ready') {
        slot.ready = true;
        if (slot.timer) clearTimeout(slot.timer);
        this._pump();
      } else if (msg.type === 'result' && slot.pending) {
        const p = slot.pending;
        slot.pending = null;
        p.resolve(msg);
        this._pump();
      }
    });
    slot.w.on('error', (err) => this._kill(slot, err));
    slot.w.on('exit', (code) => {
      if (this.destroyed || slot.dead) return;
      if (code !== 0) this._kill(slot, new Error('worker beklenmedik çıkış: ' + code));
    });
    try {
      slot.w.postMessage(initMsg);
    } catch (err) {
      this._kill(slot, err);
    }
  }

  _kill(slot, err) {
    if (slot.dead) return;
    slot.dead = true;
    if (slot.timer) clearTimeout(slot.timer);
    if (slot.pending) {
      const p = slot.pending;
      slot.pending = null;
      p.reject(err);
    }
    try {
      if (slot.w) slot.w.terminate();
    } catch {}
    // Tüm workerlar kapandıysa bekleyen işleri de reddet (sonsuz bekleme yok)
    if (this.slots.every((s) => s.dead)) {
      for (const item of this.queue.splice(0)) item.reject(err);
    }
  }

  exec(payload) {
    if (this.destroyed) return Promise.reject(new Error('havuz kapandı'));
    if (this.slots.every((s) => s.dead)) return Promise.reject(new Error('tüm workerlar kapandı'));
    return new Promise((resolve, reject) => {
      this.queue.push({ payload, resolve, reject });
      this._pump();
    });
  }

  _pump() {
    while (this.queue.length) {
      const slot = this.slots.find((s) => !s.dead && !s.pending && s.ready);
      if (!slot) return;
      const item = this.queue.shift();
      slot.pending = item;
      try {
        slot.w.postMessage({
          type: 'scan',
          id: ++this.seq,
          file: item.payload.file,
          size: item.payload.size,
          hash: item.payload.hash
        });
      } catch (err) {
        slot.pending = null;
        item.reject(err);
      }
    }
  }

  destroy() {
    this.destroyed = true;
    for (const item of this.queue.splice(0)) item.reject(new Error('havuz kapandı'));
    for (const slot of this.slots) {
      if (slot.timer) clearTimeout(slot.timer);
      if (slot.pending) {
        const p = slot.pending;
        slot.pending = null;
        p.reject(new Error('havuz kapandı'));
      }
      try {
        if (slot.w) slot.w.terminate();
      } catch {}
    }
  }
}

let stopFlag = false;
let scanning = false;
let activePool = null;

function destroyPool() {
  if (activePool) {
    try {
      activePool.destroy();
    } catch {}
    activePool = null;
  }
}

function isScanning() {
  return scanning;
}

/** EICAR test dosyası (çalışma anında kurulur) */
function createEicarTestFile() {
  const dir = path.join(app.getPath('temp'), 'aegis-eicar-test');
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, 'eicar-test.com');
  fs.writeFileSync(file, EICAR);
  return file;
}

function stop() {
  stopFlag = true;
}

async function run(opts, onProgress) {
  if (scanning) throw new Error('Tarama zaten çalışıyor');
  scanning = true;
  stopFlag = false;
  try {
    return await runScan(opts, onProgress);
  } finally {
    destroyPool();
    scanning = false;
  }
}

async function runScan(opts, onProgress) {
  const files = [];
  const exclusions = (opts.exclusions || []).slice();
  const ctx = { denied: [] }; // EPERM/EACCES ile erişilemeyen dizinler
  for (const p of opts.paths) listFiles(p, exclusions, files, 0, ctx);

  // 1) İmza veritabanı
  let db = { version: '0', sha256: new Map(), rules: [], skipped: [] };
  try {
    db = signatures.load(opts.signaturesDir);
  } catch (err) {
    console.error('imza DB yüklenemedi:', err);
  }
  for (const [hash, name] of SIGNATURES) db.sha256.set(hash, name);

  // 2) Hash önbelleği
  let cache = null;
  if (opts.cacheFile) {
    try {
      cache = new HashCache(opts.cacheFile);
      if (cache.flushOnExit) cache.flushOnExit();
    } catch {
      cache = null;
    }
  }

  const report = {
    filesScanned: 0,
    bytesScanned: 0,
    archiveEntries: 0,
    threats: [],
    startedAt: Date.now(),
    stopped: false,
    signatureVersion: db.version
  };
  const startTime = Date.now();
  let lastEmit = 0;

  const emit = (file) => {
    const now = Date.now();
    if (now - lastEmit > 100) {
      lastEmit = now;
      onProgress({
        file,
        filesScanned: report.filesScanned,
        bytesScanned: report.bytesScanned,
        archiveEntries: report.archiveEntries,
        total: files.length,
        elapsed: now - startTime,
        currentThreat: report.threats.length
      });
    }
  };

  const checkHeuristic = async (file, size, pathForReport) => {
    if (!opts.heuristics) return null;
    const heur = heuristicCheck(file, size);
    if (!heur) return null;
    return handleThreat(pathForReport, Object.assign({ kind: 'heuristic' }, heur), opts);
  };

  // --- Worker havuzu (büyük taramalarda paralel hash + imza taraması) ---
  // opts.maxWorkers === 0 → havuz kurulmaz (inline/yedek yol, ölçüm ve test için)
  if (files.length > INLINE_THRESHOLD && opts.maxWorkers !== 0) {
    try {
      activePool = new WorkerPool(MAX_WORKERS, {
        type: 'init',
        signaturesDir: opts.signaturesDir,
        localSignatures: Array.from(SIGNATURES)
      });
    } catch {
      activePool = null;
    }
  }

  /** Çekirdek tarama: havuz varsa worker'a, yoksa/worker hatasında ana iş parçacığına. */
  const dispatch = async (file, size, hash) => {
    if (!activePool) return scanFileCore(file, size, hash, db);
    try {
      const r = await activePool.exec({ file, size, hash });
      return { hash: r.hash || null, threat: r.threat || null, error: r.error || null };
    } catch {
      return scanFileCore(file, size, hash, db); // yedek yol
    }
  };

  const scanOne = async (file) => {
    if (stopFlag) return;

    let stat;
    try {
      stat = fs.statSync(file);
    } catch {
      return;
    }
    if (!stat.isFile() || stat.size > 1024 * 1024 * 1024) return;

    report.filesScanned++;
    report.bytesScanned += stat.size;
    emit(file);

    // --- Hash (önbellek ana iş parçacığında; worker yalnızca ipucu alır) ---
    const cacheKey = cache ? HashCache.keyFor(stat) : null;
    const cachedHash = cacheKey ? cache.get(cacheKey) || null : null;

    const res = await dispatch(file, stat.size, cachedHash);
    if (res.error && !res.hash && !cachedHash) return; // okunamadı → eskisi gibi atla
    const hash = res.hash || cachedHash;
    if (hash && cacheKey && !cachedHash) cache.set(cacheKey, hash);

    // --- 1-3) İmza / YARA / EICAR (worker içinde) ---
    if (res.threat) {
      report.threats.push(await handleThreat(file, Object.assign({ hash }, res.threat), opts));
      return;
    }

    // --- 4) Arşiv taraması (ana iş parçacığında, sistem araçlarıyla akış halinde) ---
    if (opts.scanArchives && archive && archive.isArchive(file)) {
      const found = await scanArchiveFile(file, db, opts, report, emit);
      if (found) {
        report.threats.push(found);
        return;
      }
    }

    // --- 5) Sezgisel tarama (varsayılan olarak karantinaya ALINMAZ) ---
    if (opts.heuristics) {
      const heur = await checkHeuristic(file, stat.size, file);
      if (heur) report.threats.push(heur);
    }
  };

  // Paralel koşucular: her biri sıradaki dosyayı alır (doğal backpressure:
  // aynı anda en fazla worker kadar dosya işlenir).
  let nextIndex = 0;
  const runner = async () => {
    while (!stopFlag) {
      const i = nextIndex++;
      if (i >= files.length) break;
      await scanOne(files[i]);
    }
  };
  const concurrency = activePool ? activePool.size : 1;
  try {
    await Promise.all(Array.from({ length: concurrency }, runner));
  } catch (err) {
    destroyPool();
    throw err;
  }
  destroyPool();

  if (cache) {
    try {
      cache.flush();
    } catch {}
  }

  // İzin verilmeyen dizinler (EPERM/EACCES) → UI'da Tam Disk Erişimi uyarısı
  const deniedSet = Array.from(new Set(ctx.denied));
  report.deniedCount = deniedSet.length;
  report.deniedDirs = deniedSet.slice(0, 50);

  report.stopped = stopFlag && nextIndex < files.length;
  report.duration = Date.now() - startTime;
  return report;
}

/** Belirli bir bayt üst sınırına kadar akış okur (fazlası atlanır). */
function readStreamCapped(stream, cap) {
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0;
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      resolve(Buffer.concat(chunks));
    };
    stream.on('data', (c) => {
      if (done) return;
      chunks.push(c);
      size += c.length;
      if (size >= cap) {
        try {
          stream.destroy();
        } catch {}
        finish();
      }
    });
    stream.on('end', finish);
    stream.on('close', finish);
    stream.on('error', finish);
  });
}

// İç içe arşiv sınırları: derinlik ve tüm katmanlar boyunca ortak bütçe
const NESTED_MAX_DEPTH = 3;
const NESTED_MAX_BYTES = 30 * 1024 * 1024; // tek iç arşiv
const ARCHIVE_TOTAL_ENTRIES = 300;
const ARCHIVE_TOTAL_BYTES = 200 * 1024 * 1024;

/**
 * Arşiv içindeki girdileri imza/YARA/EICAR ile tarar; iç içe arşivlere
 * (zip içinde zip, tar.gz içinde zip…) NESTED_MAX_DEPTH katmana kadar iner.
 * İç arşivler 0700 geçici klasörde, girdi adından bağımsız bir adla açılır
 * ve hemen silinir. Girdi/bayt bütçesi tüm katmanlar boyunca ortaktır, böylece
 * "arşiv bombası" katman ekleyerek sınırları aşamaz.
 */
async function scanArchiveFile(file, db, opts, report, emit) {
  if (!archive || !archive.scanEntries) return null;
  const ctx = { entriesLeft: ARCHIVE_TOTAL_ENTRIES, bytesLeft: ARCHIVE_TOTAL_BYTES, tmpDir: null };
  let hit = null;
  try {
    hit = await scanArchiveLayer(file, file, 0, db, report, emit, ctx);
  } finally {
    if (ctx.tmpDir) {
      try {
        fs.rmSync(ctx.tmpDir, { recursive: true, force: true });
      } catch {}
    }
  }
  if (!hit || stopFlag) return null;
  return await handleThreat(
    `${file}!${hit.entry}`,
    { kind: 'signature', threat: hit.name, detail: `Arşiv içi eşleşme (${hit.kind})`, hash: null, inArchive: true },
    opts
  );
}

function checkBufferHit(buf, db) {
  const b = signatures.checkBuffer(buf, db);
  if (b) return { name: b.name, kind: b.kind };
  if (buf.length <= 2048 && buf.toString('utf8').includes(EICAR)) return { name: 'EICAR-Test-File', kind: 'eicar' };
  return null;
}

async function scanArchiveLayer(diskPath, label, depth, db, report, emit, ctx) {
  if (ctx.entriesLeft <= 0 || ctx.bytesLeft <= 0) return null;
  let hit = null;
  const pending = [];
  const nested = [];

  const checkEntry = (entry, getStream) => {
    const p = (async () => {
      if (hit || stopFlag || !entry || entry.isDir || entry.encrypted) return 0; // akış hiç açılmaz
      const ext = depth + 1 < NESTED_MAX_DEPTH && archive.archiveExt ? archive.archiveExt(entry.name) : null;
      const cap = ext ? Math.min(NESTED_MAX_BYTES, ctx.bytesLeft) : 4 * 1024 * 1024;
      const buf = await readStreamCapped(getStream(), cap);
      report.archiveEntries++;
      report.bytesScanned += buf.length;
      if (emit) emit(`${label}!${entry.name}`);
      const h = checkBufferHit(buf, db);
      if (h) {
        hit = Object.assign(h, { entry: entry.name });
        return buf.length;
      }
      // Kesilmemiş iç arşivleri sonraki katman için sakla (sırayla taranır)
      if (ext && buf.length > 0 && buf.length < cap) nested.push({ name: entry.name, ext, buf });
      return buf.length;
    })();
    pending.push(p);
    return p;
  };

  let res = null;
  try {
    res = await archive.scanEntries(diskPath, checkEntry, {
      maxEntries: Math.max(1, ctx.entriesLeft),
      maxTotalBytes: Math.max(1, ctx.bytesLeft)
    });
  } catch {
    return null;
  }
  try {
    await Promise.allSettled(pending);
  } catch {}
  if (res) {
    ctx.entriesLeft -= (res.scanned || 0) + (res.skipped || 0);
    ctx.bytesLeft -= res.totalBytes || 0;
  }
  if (hit) return hit;

  for (const inner of nested) {
    if (stopFlag || ctx.entriesLeft <= 0 || ctx.bytesLeft <= 0) break;
    if (!ctx.tmpDir) ctx.tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-nested-'));
    const tmp = path.join(ctx.tmpDir, `n${depth}-${nested.indexOf(inner)}${inner.ext}`);
    try {
      fs.writeFileSync(tmp, inner.buf, { mode: 0o600 });
      inner.buf = null;
      const innerHit = await scanArchiveLayer(tmp, `${label}!${inner.name}`, depth + 1, db, report, emit, ctx);
      if (innerHit) return Object.assign(innerHit, { entry: `${inner.name}!${innerHit.entry}` });
    } catch {
      // bozuk iç arşiv: atla
    } finally {
      try {
        fs.unlinkSync(tmp);
      } catch {}
    }
  }
  return null;
}

async function handleThreat(file, meta, opts) {
  const entry = {
    path: file,
    threat: meta.threat,
    detail: meta.detail,
    hash: meta.hash || null,
    kind: meta.kind || 'signature',
    quarantined: false
  };
  // Politika: yalnızca kesin imza/EICAR tespitleri otomatik karantinaya alınır.
  // Sezgisel bulgular yalnızca işaretlenir (kullanıcı onayı gerekir).
  const auto = opts.autoQuarantine && meta.kind !== 'heuristic';
  // Arşiv içi bulgu ("arsiv.zip!girdi") diskte ayrı dosya değildir; yolunda
  // "!" geçen gerçek dosyalar (ör. "indir!.exe") yine karantinaya alınır.
  if (auto && !meta.inArchive) {
    const rec = await moveToQuarantine(file, meta);
    entry.quarantined = !rec.error;
    entry.quarantineId = rec.id;
    entry.error = rec.error;
  }
  return entry;
}

module.exports = { run, stop, isScanning, createEicarTestFile, QUARANTINE_DIR, SIGNATURES };
