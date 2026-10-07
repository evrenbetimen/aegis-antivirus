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
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');

const DB_FILE = 'db.json';
const SIDECAR = 'db.json.sha256';

function fetchBuffer(url, timeoutMs = 15000) {
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
        return fetchBuffer(new URL(res.headers.location, url).toString(), timeoutMs).then(resolve, reject);
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
 * @param {{url:string, dir:string, timeoutMs?:number}} opts
 * @returns {Promise<{ok:boolean, version?:string, previous?:string, changed?:boolean, count?:number, reason?:string}>}
 */
async function update({ url, dir, timeoutMs = 15000 }) {
  if (!url) return { ok: false, reason: 'url yok' };
  if (!dir) return { ok: false, reason: 'dizin yok' };

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
      const tmp = target + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(parsed, null, 2));
      fs.renameSync(tmp, target);
      fs.writeFileSync(path.join(dir, SIDECAR), actual + '  ' + DB_FILE);
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

/** Bulundukça yerel db.json'ın yan dosyayla tutarlılığını doğrular. */
function verifyLocal(dir) {
  try {
    const buf = fs.readFileSync(path.join(dir, DB_FILE));
    const side = parseSidecar(fs.readFileSync(path.join(dir, SIDECAR), 'utf8'));
    if (!side) return { ok: false, reason: 'yan dosya yok' };
    const actual = crypto.createHash('sha256').update(buf).digest('hex');
    return { ok: side === actual, reason: side === actual ? 'ok' : 'özeti uyuşmuyor' };
  } catch (err) {
    return { ok: false, reason: String(err.message || err) };
  }
}

module.exports = { update, verifyLocal, validateDb, DB_FILE, SIDECAR };
