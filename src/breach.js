'use strict';

/**
 * Parola sızıntı denetimi (Norton/McAfee "Dark Web Monitoring" benzeri).
 *
 * Have I Been Pwned "Pwned Passwords" k-anonimlik API'si kullanılır: parolanın
 * SHA-1 özetinin yalnızca ilk 5 karakteri gönderilir, sunucu o önekle başlayan
 * tüm özet son eklerini döner ve eşleşme yerelde aranır. Parolanın kendisi ya
 * da tam özeti cihazdan hiç çıkmaz; hiçbir yere kaydedilmez.
 * https://haveibeenpwned.com/API/v3#PwnedPasswords
 */

const crypto = require('crypto');
const https = require('https');

const API = 'https://api.pwnedpasswords.com/range/';
const MAX_BODY = 2 * 1024 * 1024;

function sha1Upper(text) {
  return crypto.createHash('sha1').update(String(text), 'utf8').digest('hex').toUpperCase();
}

/** "SUFFIX:COUNT" satırlarında son eki arar (dolgu satırları sayı 0'dır). */
function countInRange(body, suffix) {
  for (const line of String(body).split(/\r?\n/)) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    if (line.slice(0, idx).trim().toUpperCase() === suffix) {
      const n = parseInt(line.slice(idx + 1), 10);
      return Number.isFinite(n) ? n : 0;
    }
  }
  return 0;
}

function httpGet(url, timeout = 10000) {
  return new Promise((resolve, reject) => {
    const req = https.get(
      url,
      { headers: { 'Add-Padding': 'true', 'User-Agent': 'Aegis-Security-Suite' }, timeout },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          reject(new Error(`HTTP ${res.statusCode}`));
          return;
        }
        let size = 0;
        const chunks = [];
        res.on('data', (c) => {
          size += c.length;
          if (size > MAX_BODY) {
            req.destroy(new Error('response too large'));
            return;
          }
          chunks.push(c);
        });
        res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        res.on('error', reject);
      }
    );
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
  });
}

/**
 * @param {string} password
 * @param {{get?: (url:string) => Promise<string>}} [opts] test için HTTP enjeksiyonu
 * @returns {Promise<{ok:true, count:number} | {ok:false, error:string}>}
 */
async function checkPassword(password, opts = {}) {
  if (typeof password !== 'string' || password.length === 0 || password.length > 1024) {
    return { ok: false, error: 'invalid' };
  }
  const hash = sha1Upper(password);
  const get = opts.get || httpGet;
  try {
    const body = await get(API + hash.slice(0, 5));
    return { ok: true, count: countInRange(body, hash.slice(5)) };
  } catch (err) {
    return { ok: false, error: String((err && err.message) || err) };
  }
}

module.exports = { checkPassword, countInRange, sha1Upper, API };
