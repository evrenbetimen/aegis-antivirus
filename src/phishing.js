//
// Kimlik avı (phishing) koruması — bağlantı denetimi ve alan adı listesi
//
// Liste biçimi (imzalı db.json → "domains"):
//   { "phishing": "<kayıtlar>", "malware": "<kayıtlar>" }
//   Her kayıt, küçük harfli ASCII (punycode) alan adının SHA-256 özetinin
//   base64url ilk 11 karakteridir; kayıtlar sıralı ve ayraçsız art arda
//   yazılır. 390 bin alan adı ~4 MB tutar (düz metin 11 MB) ve bellekte ek
//   yapı kurmadan ikili arama ile sorgulanır.
//
// Liste eşleşmesi "tehlikeli" sayılır. Sezgiler (IP adresi, punycode,
// kullanıcı bilgisi, marka taklidi…) yalnızca "şüpheli" uyarısı üretir ve
// dosya taramasında kullanılmaz (yanlış pozitif riski).
//
const crypto = require('crypto');
const { domainToUnicode } = require('url');

const REC = 11;
const REC_RE = /^[A-Za-z0-9_-]*$/;

function hashDomain(domain) {
  return crypto.createHash('sha256').update(String(domain)).digest('base64url').slice(0, REC);
}

/** Liste dizgisini doğrular; geçersizse boş döner (bozuk DB taramayı bozmasın). */
function validList(s) {
  return typeof s === 'string' && s.length % REC === 0 && REC_RE.test(s) ? s : '';
}

/** Sıralı kayıt listesini derler (build-db ve testler için). */
function buildList(domains) {
  const set = new Set();
  for (const d of domains) {
    const n = normalizeHost(d);
    if (n) set.add(hashDomain(n));
  }
  return Array.from(set).sort().join('');
}

function listHas(list, rec) {
  let lo = 0;
  let hi = list.length / REC - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const cur = list.substr(mid * REC, REC);
    if (cur === rec) return true;
    if (cur < rec) lo = mid + 1;
    else hi = mid - 1;
  }
  return false;
}

function listSize(list) {
  return list ? list.length / REC : 0;
}

/** Alan adını karşılaştırılabilir biçime getirir (küçük harf, punycode, sonda nokta yok). */
function normalizeHost(host) {
  let h = String(host || '').trim().toLowerCase();
  if (!h) return '';
  h = h.replace(/\.+$/, '');
  if (/[^\x21-\x7e]/.test(h)) {
    try {
      h = new URL('http://' + h).hostname;
    } catch {
      return '';
    }
  }
  if (!/^[a-z0-9._-]+$/.test(h) || h.length > 253 || !h.includes('.')) return '';
  return h;
}

/** Listeyi alan adı ve üst alan adlarıyla sorgular (giris.kotu.xyz → kotu.xyz). */
function lookupHost(host, domains) {
  const h = normalizeHost(host);
  if (!h || !domains) return null;
  const labels = h.split('.');
  for (let i = 0; i <= labels.length - 2; i++) {
    const cand = labels.slice(i).join('.');
    const rec = hashDomain(cand);
    for (const kind of ['phishing', 'malware']) {
      if (domains[kind] && listHas(domains[kind], rec)) return { kind, domain: cand };
    }
  }
  return null;
}

/* -------------------------------- sezgiler -------------------------------- */

// İkinci düzey ülke alan adları: "kayıtlı alan adı" son üç etiket sayılır
const SECOND_LEVEL = new Set([
  'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr', 'k12.tr', 'bel.tr', 'gen.tr', 'web.tr',
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.br', 'net.br', 'gov.br', 'com.au', 'net.au',
  'co.jp', 'ne.jp', 'or.jp', 'com.cn', 'net.cn', 'com.mx', 'co.in', 'co.kr', 'com.ar',
  'co.za', 'com.pl', 'com.ru', 'co.nz', 'com.es', 'com.sg', 'com.hk', 'com.tw'
]);

function registrable(host) {
  const labels = host.split('.');
  const two = labels.slice(-2).join('.');
  return SECOND_LEVEL.has(two) && labels.length >= 3 ? labels.slice(-3).join('.') : two;
}

// Sık taklit edilen markalar ve resmî alan adları
const BRANDS = {
  paypal: ['paypal.com', 'paypal.me'],
  apple: ['apple.com', 'icloud.com', 'apple.news', 'apps.apple.com'],
  icloud: ['icloud.com', 'apple.com'],
  google: ['google.com', 'google.com.tr', 'googleapis.com', 'gstatic.com', 'youtube.com', 'goo.gl', 'g.co'],
  gmail: ['google.com', 'gmail.com'],
  microsoft: ['microsoft.com', 'live.com', 'office.com', 'microsoftonline.com', 'outlook.com', 'azure.com', 'sharepoint.com'],
  office365: ['office.com', 'microsoft.com', 'microsoftonline.com'],
  outlook: ['outlook.com', 'live.com', 'office.com', 'microsoft.com'],
  amazon: ['amazon.com', 'amazon.com.tr', 'amazon.de', 'amazon.co.uk', 'amazon.co.jp', 'amazon.fr', 'amazon.es', 'amazon.it', 'amazonaws.com'],
  netflix: ['netflix.com'],
  facebook: ['facebook.com', 'fb.com', 'fb.me', 'meta.com'],
  instagram: ['instagram.com'],
  whatsapp: ['whatsapp.com', 'whatsapp.net', 'wa.me'],
  telegram: ['telegram.org', 't.me'],
  binance: ['binance.com', 'binance.tr'],
  coinbase: ['coinbase.com'],
  metamask: ['metamask.io'],
  steam: ['steampowered.com', 'steamcommunity.com'],
  dhl: ['dhl.com', 'dhl.com.tr', 'dhl.de'],
  fedex: ['fedex.com'],
  garanti: ['garantibbva.com.tr', 'garanti.com.tr'],
  akbank: ['akbank.com'],
  ziraat: ['ziraatbank.com.tr', 'ziraat.com.tr'],
  isbank: ['isbank.com.tr'],
  yapikredi: ['yapikredi.com.tr'],
  edevlet: ['turkiye.gov.tr'],
  turkiye: ['turkiye.gov.tr'],
  hepsiburada: ['hepsiburada.com'],
  trendyol: ['trendyol.com'],
  sahibinden: ['sahibinden.com'],
  ptt: ['ptt.gov.tr', 'pttavm.com']
};

// Hedefi gizleyen kısaltıcılar
const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'rebrand.ly', 'ow.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 'buff.ly']);

function deconfuse(s) {
  return s.replace(/0/g, 'o').replace(/[1!|]/g, 'l').replace(/3/g, 'e').replace(/4/g, 'a').replace(/5/g, 's').replace(/rn/g, 'm').replace(/vv/g, 'w');
}

function editDistance(a, b, max) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      rowMin = Math.min(rowMin, cur[j]);
    }
    if (rowMin > max) return max + 1;
    prev = cur;
  }
  return prev[b.length];
}

function isOfficial(host, domains) {
  return domains.some((d) => host === d || host.endsWith('.' + d));
}

/** Marka taklidi: marka adı resmî olmayan alan adında ya da benzer yazımla. */
function brandImpersonation(host) {
  const reg = registrable(host);
  const regLabel = reg.split('.')[0];
  const tokens = host.split(/[.-]/).filter(Boolean);
  for (const [brand, official] of Object.entries(BRANDS)) {
    if (isOfficial(host, official)) return null; // resmî alan adı
  }
  for (const [brand, official] of Object.entries(BRANDS)) {
    if (tokens.includes(brand) || tokens.some((t) => t.length > brand.length + 2 && t.includes(brand) && brand.length >= 5)) {
      return { brand, official: official[0], how: 'name' };
    }
    if (brand.length >= 5) {
      const d = deconfuse(regLabel);
      if (d !== regLabel && d === brand) return { brand, official: official[0], how: 'lookalike' };
      if (regLabel !== brand && editDistance(regLabel, brand, 1) === 1) return { brand, official: official[0], how: 'lookalike' };
    }
  }
  return null;
}

/**
 * Bağlantıyı denetler.
 * @returns {{ ok, verdict: 'safe'|'suspicious'|'dangerous'|'invalid', url, host, display,
 *             reasons: Array<{code, level: 'danger'|'warn'|'info', vars?}> }}
 */
function checkUrl(input, domains) {
  let raw = String(input || '').trim();
  if (!raw) return { ok: false, verdict: 'invalid', reasons: [{ code: 'invalid', level: 'warn' }] };
  if (!/^[a-z][a-z0-9+.-]*:/i.test(raw)) raw = 'http://' + raw;
  let u;
  try {
    u = new URL(raw);
  } catch {
    return { ok: false, verdict: 'invalid', reasons: [{ code: 'invalid', level: 'warn' }] };
  }
  const reasons = [];
  const scheme = u.protocol.replace(':', '');
  if (scheme === 'javascript' || scheme === 'data' || scheme === 'vbscript') {
    return { ok: true, verdict: 'dangerous', url: u.href.slice(0, 200), host: '', display: '', reasons: [{ code: 'scheme', level: 'danger', vars: { scheme } }] };
  }
  if (scheme !== 'http' && scheme !== 'https') {
    return { ok: false, verdict: 'invalid', reasons: [{ code: 'invalid', level: 'warn' }] };
  }
  const host = u.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '');
  const display = domainToUnicode(host) || host;

  const hit = lookupHost(host, domains);
  if (hit) reasons.push({ code: hit.kind === 'malware' ? 'listMalware' : 'listPhishing', level: 'danger', vars: { domain: hit.domain } });

  if (u.username || u.password) reasons.push({ code: 'userinfo', level: 'warn', vars: { host: display } });
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':')) reasons.push({ code: 'ipHost', level: 'warn' });
  else {
    if (host.split('.').some((l) => l.startsWith('xn--'))) reasons.push({ code: 'punycode', level: 'warn', vars: { display, host } });
    const imp = brandImpersonation(host);
    if (imp) reasons.push({ code: imp.how === 'name' ? 'brandName' : 'lookalike', level: 'warn', vars: { brand: imp.brand, official: imp.official } });
    if (host.split('.').length > 5) reasons.push({ code: 'deepSubdomain', level: 'warn' });
    if (SHORTENERS.has(host)) reasons.push({ code: 'shortener', level: 'info' });
  }
  if (scheme === 'http') reasons.push({ code: 'http', level: 'info' });

  const verdict = reasons.some((r) => r.level === 'danger')
    ? 'dangerous'
    : reasons.some((r) => r.level === 'warn')
      ? 'suspicious'
      : 'safe';
  return { ok: true, verdict, url: u.href.slice(0, 500), host, display, reasons };
}

/* ------------------------- dosyalardaki bağlantılar ------------------------- */

// Bağlantı taşıyan dosya türleri: kısayollar, web sayfaları, e-postalar
const LINK_FILE_RE = /\.(webloc|inetloc|url|html?|shtml|xhtml|svg|eml|emlx|mht|mhtml)$/i;

function isLinkFile(name) {
  return LINK_FILE_RE.test(String(name || ''));
}

/** Metindeki http(s) bağlantılarının alan adlarını çıkarır (en fazla limit). */
function extractHosts(text, limit = 500) {
  const hosts = new Set();
  // quoted-printable satır sonları (=\r\n) bağlantıları bölmesin
  const s = String(text).replace(/=\r?\n/g, '').replace(/=3D/gi, '=');
  const re = /\bhttps?:\/\/(?:[^\s/@"'<>]*@)?([^\s/:?#"'<>()\\[\]]+)/gi;
  let m;
  while ((m = re.exec(s)) && hosts.size < limit) {
    const h = normalizeHost(m[1]);
    if (h) hosts.add(h);
  }
  return Array.from(hosts);
}

/** Metindeki ilk listelenmiş alan adı (yoksa null). */
function findListedHost(text, domains) {
  if (!domains || (!domains.phishing && !domains.malware)) return null;
  for (const h of extractHosts(text)) {
    const hit = lookupHost(h, domains);
    if (hit) return Object.assign({ host: h }, hit);
  }
  return null;
}

module.exports = {
  REC,
  hashDomain,
  buildList,
  validList,
  listHas,
  listSize,
  normalizeHost,
  lookupHost,
  checkUrl,
  isLinkFile,
  extractHosts,
  findListedHost,
  registrable,
  brandImpersonation
};
