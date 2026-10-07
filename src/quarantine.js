//
// Karantina — AES-256-GCM şifreli izolasyon
//
// Tasarım:
//   - Dosya, karantina dizinine AES-256-GCM ile şifrelenerek kopyalanır:
//     <id>.qtn = [12B IV][ciphertext][16B auth tag]
//   - Anahtar: Electron main'de safeStorage (macOS Keychain) ile şifrelenip
//     quarantine/.key.enc içinde tutulur (bkz. main.js initQuarantineKey).
//     Keychain kullanılamazsa yalın quarantine/.key (0600) dosyasına düşülür.
//   - Meta veri <id>.json: orijinal yol, tehdit adı, şifresiz SHA-256
//     ve HMAC-SHA256 imzası → kayıt değiştirilirse `intact:false` görünür.
//   - Geri yüklemede önce HMAC, sonra dosyanın SHA-256'sı doğrulanır.
//   - Eski (şifresiz) kayıtlar da okunabilir/geri yüklenebilir.
//
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { PassThrough } = require('stream');
const { app } = require('electron');

const QUARANTINE_DIR = path.join(app.getPath('userData'), 'quarantine');
const KEY_FILE = path.join(QUARANTINE_DIR, '.key');
const ENC_KEY_FILE = path.join(QUARANTINE_DIR, '.key.enc');

let keyCache = null;

function ensureDir() {
  fs.mkdirSync(QUARANTINE_DIR, { recursive: true });
}

/**
 * Anahtarı dışarıdan enjekte et (ör. Electron safeStorage → macOS Keychain).
 * Enjekte edilirse dosya tabanlı .key kullanılmaz.
 */
function setKey(key) {
  if (Buffer.isBuffer(key) && key.length === 32) {
    keyCache = key;
  }
}

/**
 * Keychain tabanlı anahtarı başlat (Electron main + e2e aynı fonksiyonu çağırır).
 *   - .key.enc varsa çözülür (Keychain'den) → kullanılır.
 *   - yoksa düz .key varsa (göç) o değer şifrelenip .key.enc yazılır, DÜZ kopya silinir.
 *   - hiçbiri yoksa yeni anahtar üretilir (yalnızca .key.enc yazılır, düz kopya YOK).
 *   - safeStorage kullanılamazsa dosya tabanlı .key'ye düşülür (eskisi gibi).
 * @returns {'keychain'|'file'}
 */
function initSecureKey(safeStorage) {
  const useFileFallback = () => {
    keyCache = null; // getKey() dosya yolundan okusun
    return 'file';
  };
  try {
    if (!safeStorage || typeof safeStorage.isEncryptionAvailable !== 'function' || !safeStorage.isEncryptionAvailable()) {
      return useFileFallback();
    }

    ensureDir();
    let hex = null;
    if (fs.existsSync(ENC_KEY_FILE)) {
      try {
        hex = safeStorage.decryptString(fs.readFileSync(ENC_KEY_FILE)).trim();
      } catch {
        hex = null;
      }
    }
    if (!/^[0-9a-f]{64}$/.test(hex)) {
      let fresh = null;
      try {
        const t = fs.readFileSync(KEY_FILE, 'utf8').trim();
        if (/^[0-9a-f]{64}$/.test(t)) fresh = t;
      } catch {}
      if (!fresh) fresh = crypto.randomBytes(32).toString('hex');
      fs.writeFileSync(ENC_KEY_FILE, safeStorage.encryptString(fresh), { mode: 0o600 });
      try {
        fs.chmodSync(ENC_KEY_FILE, 0o600);
      } catch {}
      hex = fresh;
      try {
        if (fs.existsSync(KEY_FILE)) fs.unlinkSync(KEY_FILE); // düz kopya artık gereksiz
      } catch {}
    }
    // Göç tamamlandıysa artakalan bayat düz kopya da temizlensin
    try {
      if (fs.existsSync(KEY_FILE)) fs.unlinkSync(KEY_FILE);
    } catch {}
    keyCache = Buffer.from(hex, 'hex');
    return 'keychain';
  } catch (err) {
    console.error('Keychain anahtarı başlatılamadı (dosya anahtarı kullanılacak):', err);
    return useFileFallback();
  }
}

function getKey() {
  if (keyCache) return keyCache;
  // Şifreli anahtar var ama initSecureKey hiç çağrılmadıysa sessizce YENİ anahtar
  // üretme (HMAC kayıtları kalıcı bozulur) — açıkça hata ver.
  if (fs.existsSync(ENC_KEY_FILE)) {
    throw new Error('Karantina anahtarı yüklenmedi — initSecureKey() çağrılmalı (Keychain)');
  }
  ensureDir();
  try {
    const hex = fs.readFileSync(KEY_FILE, 'utf8').trim();
    if (/^[0-9a-f]{64}$/.test(hex)) {
      keyCache = Buffer.from(hex, 'hex');
      return keyCache;
    }
  } catch {}
  keyCache = crypto.randomBytes(32);
  fs.writeFileSync(KEY_FILE, keyCache.toString('hex'), { mode: 0o600 });
  try {
    fs.chmodSync(KEY_FILE, 0o600);
  } catch {}
  return keyCache;
}

function metaPath(id) {
  return path.join(QUARANTINE_DIR, id + '.json');
}

function qtnPath(id) {
  return path.join(QUARANTINE_DIR, id + '.qtn');
}

function signMeta(meta) {
  const key = getKey();
  const copy = Object.assign({}, meta);
  delete copy.hmac;
  return crypto.createHmac('sha256', key).update(JSON.stringify(copy)).digest('hex');
}

function sha256File(file) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash('sha256');
    const s = fs.createReadStream(file);
    s.on('error', reject);
    s.on('data', (c) => h.update(c));
    s.on('end', () => resolve(h.digest('hex')));
  });
}

/** Dosyayı AES-256-GCM ile akış halinde şifreler. */
function encryptFile(srcPath, destPath, key, iv) {
  return new Promise((resolve, reject) => {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const out = fs.createWriteStream(destPath);
    const inp = fs.createReadStream(srcPath);
    let failed = false;
    const fail = (err) => {
      if (failed) return;
      failed = true;
      try {
        out.destroy();
        fs.unlinkSync(destPath);
      } catch {}
      reject(err);
    };
    inp.on('error', fail);
    out.on('error', fail);
    out.write(iv);
    inp.pipe(cipher);
    cipher.on('error', fail);
    cipher.pipe(out);
    out.on('finish', () => {
      fs.appendFile(destPath, cipher.getAuthTag(), (err) => (err ? fail(err) : resolve()));
    });
  });
}

/** Şifreli dosyayı çözer ve SHA-256 doğrulaması üretir. */
async function decryptFile(srcPath, destPath, key) {
  const stat = await fs.promises.stat(srcPath);
  const total = stat.size;
  if (total < 12 + 16) throw new Error('Karantina dosyası bozuk (çok kısa)');

  const iv = Buffer.alloc(12);
  const tag = Buffer.alloc(16);
  const fh = await fs.promises.open(srcPath, 'r');
  try {
    await fh.read(iv, 0, 12, 0);
    await fh.read(tag, 0, 16, total - 16);
  } finally {
    await fh.close();
  }

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);

  return new Promise((resolve, reject) => {
    // Özet ÇÖZÜLMÜŞ içerikten alınmalı (GCM'de ciphertext ≠ plaintext).
    // Not: crypto.Hash bir transform olarak veriyi İLETMEZ (digest basar),
    // bu yüzden PassThrough ile akıştan "ayıklanır".
    const hash = crypto.createHash('sha256');
    const out = fs.createWriteStream(destPath);
    const inp = fs.createReadStream(srcPath, { start: 12, end: total - 17 });
    const tap = new PassThrough();
    let failed = false;
    const fail = (err) => {
      if (failed) return;
      failed = true;
      try {
        out.destroy();
        fs.unlinkSync(destPath);
      } catch {}
      reject(err);
    };
    inp.on('error', fail);
    out.on('error', fail);
    decipher.on('error', () => fail(new Error('Şifre çözme başarısız — dosya bozulmuş olabilir')));
    // akış: dosya → decipher → (hash tap) → dosya
    inp.pipe(decipher).pipe(tap);
    tap.on('data', (c) => hash.update(c));
    tap.pipe(out);
    out.on('finish', () => resolve(hash.digest('hex')));
  });
}

/**
 * Dosyayı karantinaya alır. Kaynak dosya silinir (taşınır).
 * @returns kayıt objesi (hata dahil)
 */
async function store(file, meta) {
  ensureDir();
  const id = Date.now().toString(36) + '-' + crypto.randomBytes(4).toString('hex');
  const record = {
    id,
    originalPath: file,
    quarantinedAt: Date.now(),
    threat: meta.threat,
    detail: meta.detail || '',
    hash: meta.hash || null,
    encrypted: true
  };

  try {
    const plainSha = await sha256File(file);
    record.sha256 = plainSha;
    const key = getKey();
    const iv = crypto.randomBytes(12);
    await encryptFile(file, qtnPath(id), key, iv);
    // Şifreli kopya doğrulanınca kaynağı sil
    await fs.promises.unlink(file);
    record.file = qtnPath(id);
    record.hmac = signMeta(record);
    fs.writeFileSync(metaPath(id), JSON.stringify(record, null, 2), { mode: 0o600 });
    return record;
  } catch (err) {
    record.error = String(err.message || err);
    record.encrypted = false;
    record.file = null;
    return record;
  }
}

function readMeta(id) {
  try {
    return JSON.parse(fs.readFileSync(metaPath(id), 'utf8'));
  } catch {
    return null;
  }
}

function verifyMeta(meta) {
  if (!meta || typeof meta.hmac !== 'string') return { valid: false, legacy: true };
  let expect;
  try {
    expect = signMeta(meta);
  } catch {
    return { valid: false, legacy: false, error: 'anahtar-yuklenmedi' }; // initSecureKey çağrılmamış
  }
  const a = Buffer.from(expect, 'utf8');
  const b = Buffer.from(meta.hmac, 'utf8');
  const ok = a.length === b.length && crypto.timingSafeEqual(a, b);
  return { valid: ok, legacy: false };
}

function list() {
  let files = [];
  try {
    files = fs.readdirSync(QUARANTINE_DIR);
  } catch {
    return [];
  }
  const items = [];
  for (const f of files) {
    if (!f.endsWith('.json')) continue;
    try {
      const meta = JSON.parse(fs.readFileSync(path.join(QUARANTINE_DIR, f), 'utf8'));
      const v = verifyMeta(meta);
      meta.intact = v.valid || v.legacy ? (v.legacy ? 'legacy' : true) : false;
      items.push(meta);
    } catch {}
  }
  return items.sort((a, b) => b.quarantinedAt - a.quarantinedAt);
}

async function restore(id) {
  const meta = readMeta(id);
  if (!meta) return { ok: false, error: 'Kayıt bulunamadı' };

  const v = verifyMeta(meta);
  if (!v.valid && !v.legacy) {
    return { ok: false, error: 'Bütünlük doğrulanamadı — kayıt değiştirilmiş' };
  }

  try {
    const dest = meta.originalPath;
    await fs.promises.mkdir(path.dirname(dest), { recursive: true });

    if (meta.encrypted && meta.file) {
      const tmp = dest + '.aegis-restore-tmp';
      const plainSha = await decryptFile(meta.file, tmp, getKey());
      if (meta.sha256 && plainSha !== meta.sha256) {
        fs.unlinkSync(tmp);
        return { ok: false, error: 'Dosya özeti uyuşmuyor — karantina dosyası bozulmuş' };
      }
      await fs.promises.rename(tmp, dest);
      // Şifreli kopya artık gereksiz — silinmezse orfan .qtn artığı kalır
      try {
        if (meta.file) fs.unlinkSync(meta.file);
      } catch {}
    } else if (meta.file && fs.existsSync(meta.file)) {
      // Eski sürüm: düz dosya
      await fs.promises.copyFile(meta.file, dest);
      fs.unlinkSync(meta.file);
    } else {
      return { ok: false, error: 'Dosya yok' };
    }

    try {
      fs.unlinkSync(metaPath(id));
    } catch {}
    return { ok: true, path: dest };
  } catch (err) {
    return { ok: false, error: String(err.message || err) };
  }
}

function remove(id) {
  const meta = readMeta(id);
  try {
    if (meta && meta.file && fs.existsSync(meta.file)) fs.unlinkSync(meta.file);
    fs.unlinkSync(metaPath(id));
    return { ok: true };
  } catch (err) {
    return { ok: false, error: String(err.message || err) };
  }
}

/**
 * Tüm karantina kayıtlarının bütünlüğünü denetler (HMAC + şifreli dosya varlığı).
 * Anti-tamper kontrolü: UI'da "Karantina bütünlüğü" olarak gösterilir.
 */
function verifyAll() {
  const items = list();
  const report = { total: items.length, intact: 0, legacy: 0, tampered: 0, missing: [] };
  for (const it of items) {
    if (it.intact === false) {
      report.tampered++;
      report.missing.push({ id: it.id, reason: 'hmac' });
      continue;
    }
    if (it.intact === 'legacy') report.legacy++;
    else report.intact++;
    if (it.encrypted && (!it.file || !fs.existsSync(it.file))) {
      report.tampered++;
      report.missing.push({ id: it.id, reason: 'file-missing' });
    }
  }
  return report;
}

/**
 * .json metası OLMAYAN .qtn artıklarını siler.
 * Eski restore() sürümü şifreli kopyayı silmediği için birikmiş artıklar
 * (geri alınamaz, listelenemez) temizlenir. Başlangıçta bir kez çağrılır.
 * @returns kaç dosyanın silindiği
 */
function cleanupOrphans() {
  let names = [];
  try {
    names = fs.readdirSync(QUARANTINE_DIR);
  } catch {
    return 0;
  }
  let removed = 0;
  for (const f of names) {
    if (!f.endsWith('.qtn')) continue;
    const id = f.slice(0, -4);
    if (!fs.existsSync(metaPath(id))) {
      try {
        fs.unlinkSync(path.join(QUARANTINE_DIR, f));
        removed++;
      } catch {}
    }
  }
  return removed;
}

module.exports = { store, list, restore, remove, verifyAll, setKey, initSecureKey, cleanupOrphans, QUARANTINE_DIR };
