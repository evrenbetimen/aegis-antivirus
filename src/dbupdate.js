//
// İmza veritabanı güncelleme — bütünlük doğrulamalı
//
// Akış:
//   1. url'den db.json indir (https zorunlu; localhost/dosya yolu test için)
//   2. Aynı kaynaktan db.json.sha256 yan dosyasını al (üretimde imzalı
//      yayın için Ed25519 anahtarı eklenebilir — bkz. README)
//   3. sha256(db.json) === yan dosya kontrolü; uyuşmazsa REDDET
//   4. JSON şema kontrolü (version + sha256 eşlemesi)
//   5. Atomik yaz (tmp → rename), eski sürümü .bak olarak sakla
//
// Yayıncı imzası (Ed25519): db.json.sig = base64(Ed25519(db.json baytları)).
// Uzak (https) kaynaktan güncelleme YALNIZCA uygulamaya gömülü açık anahtarla
// doğrulanan imzayla kabul edilir: aynı sunucudan gelen .sha256 tek başına
// yalnızca bozulmayı yakalar, sunucuyu ele geçiren saldırganı durdurmaz.
// Anahtar üretimi/imzalama: scripts/db-keygen.js, scripts/sign-db.js
//
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');

const DB_FILE = 'db.json';
const SIDECAR = 'db.json.sha256';
const SIG_FILE = 'db.json.sig';
const RULES_FILE = 'rules.yar';
const PUBLIC_KEY_FILE = 'db-public.pem';
const MAX_REDIRECTS = 5;

function isLocalUrl(url) {
  return /^file:\/\//.test(url) || /^http:\/\/(localhost|127\.0\.0\.1)([:/]|$)/.test(url);
}

/** Ed25519 imzasını doğrular; anahtar/imza bozuksa false döner (fırlatmaz). */
function verifySignature(payload, sigText, publicKey) {
  try {
    const sig = Buffer.from(String(sigText).trim(), 'base64');
    if (sig.length !== 64) return false;
    const key = typeof publicKey === 'string' ? crypto.createPublicKey(publicKey) : publicKey;
    return crypto.verify(null, payload, key, sig);
  } catch {
    return false;
  }
}

/** Uygulamaya gömülü yayıncı açık anahtarını okur (yoksa null). */
function loadPublicKey(dir) {
  try {
    return fs.readFileSync(path.join(dir, PUBLIC_KEY_FILE), 'utf8');
  } catch {
    return null;
  }
}

function fetchBuffer(url, timeoutMs = 15000, redirectsLeft = MAX_REDIRECTS) {
  return new Promise((resolve, reject) => {
    // Test/kurumsal ağa için dosya yolu ve http:// (yalnızca localhost) kabul
    if (url.startsWith('file://')) {
      return fs.readFile(url.slice(7), (err, buf) => (err ? reject(err) : resolve(buf)));
    }
    if (!/^https:\/\//.test(url) && !/^http:\/\/(localhost|127\.0\.0\.1)/.test(url)) {
      return reject(new Error('Güvenlik: yalnızca https:// veya localhost indirmelerine izin verilir'));
    }
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { timeout: timeoutMs }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        if (redirectsLeft <= 0) return reject(new Error('Çok fazla yönlendirme'));
        return fetchBuffer(new URL(res.headers.location, url).toString(), timeoutMs, redirectsLeft - 1).then(
          resolve,
          reject
        );
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`Sunucu ${res.statusCode} döndü`));
      }
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > 20 * 1024 * 1024) {
          req.destroy(new Error('İmza DB çok büyük (>20MB)'));
          return;
        }
        chunks.push(c);
      });
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('Zaman aşımı')));
    req.on('error', reject);
  });
}

function parseSidecar(text) {
  // "e81b75...  db.json" veya sadece hex
  const m = String(text).trim().match(/^([0-9a-fA-F]{64})/);
  return m ? m[1].toLowerCase() : null;
}

function validateDb(obj) {
  if (!obj || typeof obj !== 'object') return 'Şema geçersiz (obje değil)';
  if (typeof obj.version !== 'string' || !obj.version) return 'version alanı yok';
  if (!obj.sha256 || typeof obj.sha256 !== 'object' || Array.isArray(obj.sha256)) {
    return 'sha256 eşlemesi yok';
  }
  if (obj.yara !== undefined && typeof obj.yara !== 'string') return 'yara alanı metin olmalı';
  for (const [k, v] of Object.entries(obj.sha256)) {
    if (!/^[0-9a-f]{64}$/i.test(k)) return `Geçersiz hash anahtarı: ${k}`;
    if (typeof v !== 'string') return `Geçersiz imza değeri: ${k}`;
  }
  return null;
}

function readCurrent(dir) {
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, DB_FILE), 'utf8'));
  } catch {
    return null;
  }
}

/**
 * @param {{url:string, dir:string, timeoutMs?:number, publicKey?:string|null}} opts
 *   publicKey: yayıncı Ed25519 açık anahtarı (PEM). Uzak kaynakta zorunlu.
 * @returns {Promise<{ok:boolean, version?:string, previous?:string, changed?:boolean, count?:number, reason?:string}>}
 */
async function update({ url, dir, timeoutMs = 15000, publicKey = null }) {
  if (!url) return { ok: false, reason: 'url yok' };
  if (!dir) return { ok: false, reason: 'dizin yok' };
  if (!publicKey && !isLocalUrl(url)) {
    return { ok: false, reason: 'Yayıncı açık anahtarı yok — imzasız uzak güncelleme reddedildi' };
  }

  let payload;
  try {
    payload = await fetchBuffer(url, timeoutMs);
  } catch (err) {
    return { ok: false, reason: 'indirme başarısız: ' + (err.message || err) };
  }

  const actual = crypto.createHash('sha256').update(payload).digest('hex');

  // Yan dosya (bütünlük)
  let sidecar;
  try {
    sidecar = parseSidecar((await fetchBuffer(url + '.sha256', timeoutMs)).toString('utf8'));
  } catch {
    sidecar = null;
  }
  if (!sidecar) return { ok: false, reason: 'sha256 yan dosyası alınamadı — güncelleme reddedildi' };
  if (sidecar !== actual) {
    return { ok: false, reason: 'SHA-256 uyuşmazlığı — güncelleme reddedildi (müdahale olabilir)' };
  }

  // Yayıncı imzası (anahtar varsa her kaynakta zorunlu)
  let sigText = null;
  if (publicKey) {
    try {
      sigText = (await fetchBuffer(url + '.sig', timeoutMs)).toString('utf8');
    } catch {
      return { ok: false, reason: 'İmza dosyası (.sig) alınamadı — güncelleme reddedildi' };
    }
    if (!verifySignature(payload, sigText, publicKey)) {
      return { ok: false, reason: 'Yayıncı imzası geçersiz — güncelleme reddedildi' };
    }
  }

  let parsed;
  try {
    parsed = JSON.parse(payload.toString('utf8'));
  } catch {
    return { ok: false, reason: 'JSON çözümlenemedi' };
  }
  const schemaErr = validateDb(parsed);
  if (schemaErr) return { ok: false, reason: 'Şema hatası: ' + schemaErr };

  const current = readCurrent(dir);
  const previous = current ? current.version : null;
  const changed = !current || JSON.stringify(current) !== JSON.stringify(parsed);

  if (changed) {
    try {
      fs.mkdirSync(dir, { recursive: true });
      const target = path.join(dir, DB_FILE);
      if (current) {
        try {
          fs.copyFileSync(target, target + '.bak');
        } catch {}
      }
      // İndirilen baytlar AYNEN yazılır: yeniden biçimlemek imzayı geçersiz kılar
      const tmp = target + '.tmp';
      fs.writeFileSync(tmp, payload);
      fs.renameSync(tmp, target);
      fs.writeFileSync(path.join(dir, SIDECAR), actual + '  ' + DB_FILE);
      if (sigText) fs.writeFileSync(path.join(dir, SIG_FILE), sigText.trim() + '\n');
      else fs.rmSync(path.join(dir, SIG_FILE), { force: true });
    } catch (err) {
      return { ok: false, reason: 'Yazma hatası: ' + (err.message || err) };
    }
  }

  return {
    ok: true,
    version: parsed.version,
    previous,
    changed,
    count: Object.keys(parsed.sha256).length
  };
}

/** Yerel db.json'ı yan dosyayla (ve anahtar verilmişse yayıncı imzasıyla) doğrular. */
function verifyLocal(dir, publicKey = null, bundledDir = null) {
  try {
    const buf = fs.readFileSync(path.join(dir, DB_FILE));
    const side = parseSidecar(fs.readFileSync(path.join(dir, SIDECAR), 'utf8'));
    if (!side) return { ok: false, reason: 'yan dosya yok' };
    const actual = crypto.createHash('sha256').update(buf).digest('hex');
    if (side !== actual) return { ok: false, reason: 'özeti uyuşmuyor' };
    if (publicKey) {
      let sig = null;
      try {
        sig = fs.readFileSync(path.join(dir, SIG_FILE), 'utf8');
      } catch {}
      if (sig) {
        if (!verifySignature(buf, sig, publicKey)) return { ok: false, reason: 'yayıncı imzası geçersiz' };
        return { ok: true, reason: 'ok', signed: true };
      }
      // İmzasız kopya yalnızca uygulamayla gelen DB'nin aynısıysa kabul edilir
      let bundled = null;
      try {
        if (bundledDir) bundled = fs.readFileSync(path.join(bundledDir, DB_FILE));
      } catch {}
      if (bundled && bundled.equals(buf)) return { ok: true, reason: 'ok', signed: false };
      return { ok: false, reason: 'yayıncı imzası yok' };
    }
    return { ok: true, reason: 'ok' };
  } catch (err) {
    return { ok: false, reason: String(err.message || err) };
  }
}

function compareVersions(a, b) {
  const pa = String(a || '0').split(/[.\-]/).map((x) => parseInt(x, 10) || 0);
  const pb = String(b || '0').split(/[.\-]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}

function readVersion(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8')).version || '0';
  } catch {
    return null;
  }
}

/**
 * Paketlenmiş uygulamada imza dizini app.asar içindedir (salt okunur).
 * Güncellemeler yazılabilir kullanıcı dizinine gider; bu fonksiyon o dizini
 * paketle gelen imzalarla hazırlar:
 *   - rules.yar her zaman paketteki sürümle eşitlenir (güncelleme yalnız db.json'ı değiştirir)
 *   - db.json yoksa ya da paketteki sürüm daha yeniyse (uygulama güncellemesi) kopyalanır
 * @returns userDir
 */
function prepareSignaturesDir(bundledDir, userDir) {
  fs.mkdirSync(userDir, { recursive: true });
  const copyIfExists = (name) => {
    const src = path.join(bundledDir, name);
    const dst = path.join(userDir, name);
    if (fs.existsSync(src)) fs.writeFileSync(dst, fs.readFileSync(src));
    else fs.rmSync(dst, { force: true });
  };
  try {
    copyIfExists(RULES_FILE);
  } catch {}
  const bundledVer = readVersion(path.join(bundledDir, DB_FILE));
  const userVer = readVersion(path.join(userDir, DB_FILE));
  if (bundledVer !== null && (userVer === null || compareVersions(bundledVer, userVer) > 0)) {
    try {
      copyIfExists(DB_FILE);
      copyIfExists(SIG_FILE);
      const db = fs.readFileSync(path.join(userDir, DB_FILE));
      const sha = crypto.createHash('sha256').update(db).digest('hex');
      fs.writeFileSync(path.join(userDir, SIDECAR), sha + '  ' + DB_FILE);
    } catch {}
  }
  return userDir;
}

module.exports = {
  update,
  verifyLocal,
  validateDb,
  verifySignature,
  loadPublicKey,
  prepareSignaturesDir,
  compareVersions,
  DB_FILE,
  SIDECAR,
  SIG_FILE,
  PUBLIC_KEY_FILE,
  MAX_REDIRECTS
};
