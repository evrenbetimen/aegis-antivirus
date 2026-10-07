//
// Arşiv tarama modülü — zip / tar / tar.gz / tgz / gz / bz2
//
// Tasarım:
//   - Hiçbir yere DOSYA ÇIKARMAZ: içerik sistem araçlarıyla akıtılır
//     (unzip -p, tar -xOf, gzip -dc) → zip-slip / path traversal imkânsız.
//   - Sınır kontrolü: maxEntries, maxEntryBytes, maxTotalBytes, spawn timeout.
//   - Bozuk/desteklenmeyen arşivler hata fırlatmaz; atlanır.
//
const path = require('path');
const { spawn, execFile, execFileSync } = require('child_process');
const { PassThrough } = require('stream');

const ZIP_EXTS = ['.zip'];
const TAR_EXTS = ['.tar', '.tgz', '.tar.gz', '.tbz2', '.tar.bz2'];
const GZ_EXTS = ['.gz'];
const BZ2_EXTS = ['.bz2'];

const DEFAULTS = {
  maxEntries: 300,
  maxEntryBytes: 30 * 1024 * 1024,
  maxTotalBytes: 200 * 1024 * 1024,
  timeoutMs: 15000
};

function lower(p) {
  return String(p || '').toLowerCase();
}

function kindOf(filePath) {
  const p = lower(filePath);
  if (ZIP_EXTS.some((e) => p.endsWith(e))) return 'zip';
  if (TAR_EXTS.some((e) => p.endsWith(e))) return 'tar';
  if (p.endsWith('.gz')) return 'gz';
  if (p.endsWith('.bz2')) return 'bz2';
  return null;
}

function isArchive(filePath) {
  return kindOf(filePath) !== null;
}

function baseArchiveName(filePath) {
  const p = lower(filePath);
  if (p.endsWith('.tar.gz')) return path.basename(filePath).slice(0, -7);
  if (p.endsWith('.tar.bz2')) return path.basename(filePath).slice(0, -8);
  if (p.endsWith('.tgz')) return path.basename(filePath).slice(0, -4);
  // Sadece sıkıştırma uzantısı kalkar (belge.txt.gz → belge.txt)
  if (p.endsWith('.gz')) return path.basename(filePath).slice(0, -3);
  if (p.endsWith('.bz2')) return path.basename(filePath).slice(0, -4);
  if (p.endsWith('.zip') || p.endsWith('.tar')) {
    return path.basename(filePath).replace(/\.[^.]+$/, '');
  }
  return path.basename(filePath);
}

function isArchiveEntryName(name) {
  return isArchive(name);
}

/** Güvenli dizin/yol filtresi (zip-slip). */
function unsafeName(name) {
  if (!name) return true;
  const n = String(name);
  if (n.startsWith('/') || n.startsWith('\\')) return true;
  if (/^[a-zA-Z]:[\\/]/.test(n)) return true; // Windows sürücü
  return n.split(/[\\/]/).some((seg) => seg === '..');
}

function run(cmd, args, { timeoutMs = 15000, maxBuffer = 8 * 1024 * 1024 } = {}) {
  return new Promise((resolve) => {
    execFile(
      cmd,
      args,
      { timeout: timeoutMs, maxBuffer, killSignal: 'SIGKILL', encoding: 'utf8' },
      (err, stdout, stderr) => resolve({ ok: !err, stdout: stdout || '', stderr: stderr || '' })
    );
  });
}

/* ------------------------------- Listeleme ------------------------------- */

function parseUnzipList(out) {
  const items = [];
  let inList = false;
  for (const line of String(out).split('\n')) {
    if (/^-{4,}/.test(line)) {
      inList = !inList;
      continue;
    }
    if (!inList) continue;
    // "  Length      Date    Time    Name" başlığı ve son özet satırları elenir
    const m = line.match(/^\s*(\d+)\s+(\d{2}-\d{2}-\d{4}|\d{4}-\d{2}-\d{2})\s+\d{1,2}:\d{2}\s+(.+)$/);
    if (m) {
      items.push({ size: Number(m[1]), name: m[3].replace(/\s+$/, '') });
    }
  }
  return items;
}

async function listEntries(filePath, opts = {}) {
  const maxEntries = opts.maxEntries || DEFAULTS.maxEntries;
  const kind = kindOf(filePath);
  if (!kind) return [];

  try {
    if (kind === 'zip') {
      const r = await run('unzip', ['-l', filePath]);
      if (!r.ok && !r.stdout) return [];
      const parsed = parseUnzipList(r.stdout);
      const out = [];
      for (const it of parsed) {
        if (unsafeName(it.name)) continue; // zip-slip girdileri listelenmez
        out.push({
          name: it.name,
          size: it.size,
          isDir: /\/$/.test(it.name),
          isArchive: isArchiveEntryName(it.name),
          encrypted: false
        });
        if (out.length >= maxEntries) break;
      }
      return out;
    }

    if (kind === 'tar') {
      const r = await run('tar', ['-tf', filePath]);
      if (!r.ok && !r.stdout) return [];
      const out = [];
      for (const raw of r.stdout.split('\n')) {
        const name = raw.replace(/\s+$/, '');
        if (!name || unsafeName(name)) continue;
        out.push({
          name,
          size: 0, // tar -tf boyut vermez; okuma sırasında üst sınır uygulanır
          isDir: /\/$/.test(name),
          isArchive: isArchiveEntryName(name),
          encrypted: false
        });
        if (out.length >= maxEntries) break;
      }
      return out;
    }

    // gz / bz2: tek girdi
    return [
      {
        name: baseArchiveName(filePath),
        size: 0,
        isDir: false,
        isArchive: false,
        encrypted: false
      }
    ];
  } catch {
    return [];
  }
}

/* --------------------------- İçerik akışı açma --------------------------- */

// unzip ve bsdtar (macOS tar) girdi adını kalıp (glob) olarak yorumlar:
// "[x].exe" gibi bir ad kendisiyle eşleşmez ve içerik hiç okunmaz. Kalıp
// karakterleri ters bölüyle kaçırılır. GNU tar adı birebir alır (kaçırma yok).
function escapeGlob(name) {
  return String(name).replace(/[\\*?[\]]/g, '\\$&');
}

let tarIsBsd = null;
function isBsdTar() {
  if (tarIsBsd === null) {
    try {
      tarIsBsd = /bsdtar/i.test(execFileSync('tar', ['--version'], { encoding: 'utf8', timeout: 5000 }));
    } catch {
      tarIsBsd = true; // macOS varsayılanı
    }
  }
  return tarIsBsd;
}

/** Girdi adını araç argümanına çevirir ("-x" gibi adlar seçenek sanılmasın). */
function zipMemberArg(name) {
  const n = escapeGlob(name);
  return n.startsWith('-') ? '\\' + n : n;
}

function tarMemberArg(name) {
  return isBsdTar() ? escapeGlob(name) : String(name);
}

function openEntryStream(filePath, entryName) {
  const kind = kindOf(filePath);
  let cmd = null;
  let args = null;

  if (kind === 'zip') {
    cmd = 'unzip';
    args = ['-p', filePath, zipMemberArg(entryName)];
  } else if (kind === 'tar') {
    cmd = 'tar';
    args = ['-xOf', filePath, '--', tarMemberArg(entryName)];
  } else if (kind === 'gz') {
    cmd = 'gzip';
    args = ['-dc', filePath];
  } else if (kind === 'bz2') {
    cmd = 'bzip2';
    args = ['-dc', filePath];
  }

  const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  const out = new PassThrough();

  let stderr = '';
  child.stderr.on('data', (c) => {
    if (stderr.length < 64 * 1024) stderr += String(c);
  });

  child.stdout.pipe(out);

  const timer = setTimeout(() => {
    try {
      child.kill('SIGKILL');
    } catch {}
  }, DEFAULTS.timeoutMs);
  child.on('close', () => clearTimeout(timer));

  child.on('error', (err) => {
    try {
      out.destroy(err);
    } catch {}
  });

  // Erken kapanırsa (tüketici destroy ettiyse) alt süreci öldür
  const origDestroy = out.destroy.bind(out);
  out.destroy = (...a) => {
    clearTimeout(timer);
    try {
      child.kill('SIGKILL');
    } catch {}
    return origDestroy(...a);
  };

  out.child = child;
  out.stderrRef = () => stderr;
  return out;
}

/* ------------------------------ Tarama akışı ----------------------------- */

/**
 * Arşivdeki her girdi için onEntry(entry, getStream) çağırır.
 * getStream()'ü çağırmak zorunda değil (atlanan girdilerde çağırmaz).
 *
 * @returns {{scanned:number, skipped:number, totalBytes:number, truncated:boolean}}
 */
async function scanEntries(filePath, onEntry, opts = {}) {
  const maxEntries = opts.maxEntries || DEFAULTS.maxEntries;
  const maxEntryBytes = opts.maxEntryBytes || DEFAULTS.maxEntryBytes;
  const maxTotalBytes = opts.maxTotalBytes || DEFAULTS.maxTotalBytes;

  const res = { scanned: 0, skipped: 0, totalBytes: 0, truncated: false };
  if (!isArchive(filePath) || typeof onEntry !== 'function') return res;

  let entries = [];
  try {
    // +1 girdi: sınırda kalınırsa "daha fazlası var" tespit edilebilsin
    entries = await listEntries(filePath, { maxEntries: maxEntries + 1 });
  } catch {
    return res;
  }
  if (!entries.length) return res;

  let budget = 0;
  for (const entry of entries) {
    if (res.scanned + res.skipped >= maxEntries) {
      res.truncated = true;
      break;
    }
    if (budget >= maxTotalBytes) {
      res.truncated = true;
      break;
    }
    if (entry.isDir || unsafeName(entry.name)) {
      res.skipped++;
      continue;
    }
    if (entry.size && entry.size > maxEntryBytes) {
      res.skipped++;
      continue;
    }

    let stream = null;
    const getStream = () => {
      if (!stream) stream = openEntryStream(filePath, entry.name);
      return stream;
    };

    try {
      await onEntry(entry, getStream);
      res.scanned++;
      const sz = entry.size || 0;
      budget += sz;
      res.totalBytes += sz;
    } catch {
      res.skipped++;
    }
  }

  return res;
}

module.exports = { isArchive, listEntries, scanEntries, unsafeName, DEFAULTS };
