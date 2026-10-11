//
// Gerçek imza veritabanı üretici — GitHub Actions'ta (signatures.yml) çalışır.
//
//   node scripts/build-db.js --out dist-db \
//     [--previous <db.json yolu|url>] \
//     [--mb-csv <MalwareBazaar CSV yolu|url>] \
//     [--yara-dir <dizin> [--yara-match <düzenli ifade>]]... [--max-hashes 100000]
//     [--rule-sources signatures/rule-sources.json --rule-cache <dizin>]
//     [--phishing-list <dosya|url>] [--urlhaus-hosts <dosya|url>]
//     [--popular-domains <dosya|url> [--popular-top 100000]]
//
// - SHA-256: MalwareBazaar "recent" CSV dışa aktarımı (abuse.ch, CC0).
//   Önceki yayınla birleştirilir; en yeni --max-hashes kayıt tutulur (kayan pencere).
// - YARA: verilen dizinlerdeki .yar/.yara dosyaları kural kural ayrılır
//   (--yara-match, kendinden önceki dizinde yalnız göreli yolu eşleşen dosyaları
//   alır; ör. yanlış pozitif riski yüksek "genel/araç" kurallarını dışarıda
//   bırakmak için); yalnız
//   Aegis motorunun TAM desteklediği ve en az bir dizgiye dayanan kurallar alınır
//   (desteklenmeyen kural asla yanlış değerlendirilmez, ayrıca boyut da küçülür).
// - Alan adları: kimlik avı listesi (Phishing.Database, MIT) ve URLhaus host
//   listesi (abuse.ch, CC0), src/phishing.js'in özet biçiminde. Popüler alan
//   adları (--popular-domains, ör. Cisco Umbrella top-1m) ve paylaşımlı
//   barındırma kökleri listeden çıkarılır: bu listeler ele geçirilmiş meşru
//   siteleri de içerir ve tüm bir platformu engellemek yanlış pozitiftir.
//   Kaynak alınamazsa önceki yayının listesi korunur.
// - Çıktı: <out>/db.json (yara metni db.json içine gömülür → tek imzalı dosya).
//   İmzalamak için: node scripts/sign-db.js <out>/db.json <özel-anahtar>
//
const fs = require('fs');
const path = require('path');
const https = require('https');
const signatures = require('../src/signatures');
const phishing = require('../src/phishing');
const { validateDb } = require('../src/dbupdate');

const EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
const MAX_DB_BYTES = 36 * 1024 * 1024; // uygulama 40MB üstünü reddeder
// 40MB sınırından önceki sürümler 20MB üstünü reddeder; yayın onlar
// güncellenene kadar bu sınırın altında tutulur (en eski hash'ler düşer)
const LEGACY_CLIENT_BYTES = 19 * 1024 * 1024;

function parseArgs(argv) {
  const out = { yaraDirs: [], maxHashes: 100000 }; // ~100 bayt/kayıt → ~10MB
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const v = argv[i + 1];
    if (a === '--out') (out.out = v), i++;
    else if (a === '--previous') (out.previous = v), i++;
    else if (a === '--mb-csv') (out.mbCsv = v), i++;
    else if (a === '--yara-dir') out.yaraDirs.push({ dir: v, match: null }), i++;
    else if (a === '--yara-match') {
      if (!out.yaraDirs.length) throw new Error('--yara-match bir --yara-dir sonrasında gelmeli');
      out.yaraDirs[out.yaraDirs.length - 1].match = new RegExp(v);
      i++;
    }
    else if (a === '--rule-sources') (out.ruleSources = v), i++;
    else if (a === '--rule-cache') (out.ruleCache = v), i++;
    else if (a === '--max-hashes') (out.maxHashes = Number(v)), i++;
    else if (a === '--phishing-list') (out.phishingList = v), i++;
    else if (a === '--urlhaus-hosts') (out.urlhausHosts = v), i++;
    else if (a === '--popular-domains') (out.popularDomains = v), i++;
    else if (a === '--popular-top') (out.popularTop = Number(v)), i++;
    else if (a === '--version') (out.version = v), i++;
    else throw new Error('Bilinmeyen argüman: ' + a);
  }
  if (!out.out) throw new Error('--out gerekli');
  if (out.ruleSources && !out.ruleCache) throw new Error('--rule-sources için --rule-cache gerekli');
  return out;
}

function fetchText(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers, timeout: 60000 }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return fetchText(new URL(res.headers.location, url).toString(), headers).then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`${url} → HTTP ${res.statusCode}`));
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('zaman aşımı: ' + url)));
    req.on('error', reject);
  });
}

async function readSource(src, headers) {
  if (/^https:\/\//.test(src)) return fetchText(src, headers);
  return fs.readFileSync(src, 'utf8');
}

/** CSV satırı: tırnaklı alanlar, ayraç "," (ardından boşluk olabilir). */
function parseCsvLine(line) {
  const out = [];
  let i = 0;
  while (i < line.length) {
    while (line[i] === ' ') i++;
    if (line[i] === '"') {
      let v = '';
      i++;
      while (i < line.length) {
        if (line[i] === '"' && line[i + 1] === '"') {
          v += '"';
          i += 2;
        } else if (line[i] === '"') {
          i++;
          break;
        } else v += line[i++];
      }
      out.push(v);
      while (i < line.length && line[i] !== ',') i++;
    } else {
      const j = line.indexOf(',', i);
      out.push((j === -1 ? line.slice(i) : line.slice(i, j)).trim());
      i = j === -1 ? line.length : j;
    }
    if (line[i] === ',') {
      i++;
      if (i === line.length) out.push('');
    }
  }
  return out;
}

function threatName(sig, type) {
  const clean = (s) => String(s || '').replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '');
  const s = clean(sig);
  const name = s && s.toLowerCase() !== 'n-a' ? s : 'Generic' + (clean(type) ? '.' + clean(type) : '');
  return ('MalwareBazaar.' + name).slice(0, 80);
}

/** MalwareBazaar CSV → [[sha256, ad], ...] (en eski önce). */
function parseMalwareBazaarCsv(text) {
  let header = null;
  const rows = [];
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith('#')) {
      if (/sha256_hash/.test(line)) header = parseCsvLine(line.replace(/^#\s*/, ''));
      continue;
    }
    const cols = parseCsvLine(line);
    const h = header || ['first_seen_utc', 'sha256_hash'];
    const get = (k) => cols[h.indexOf(k)];
    const sha = String(get('sha256_hash') || '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(sha)) continue;
    rows.push({ seen: get('first_seen_utc') || '', sha, name: threatName(get('signature'), get('file_type_guess')) });
  }
  rows.sort((a, b) => (a.seen < b.seen ? -1 : a.seen > b.seen ? 1 : 0));
  return rows.map((r) => [r.sha, r.name]);
}

/** Kayan pencere: önceki + yeni (yeni olan sona taşınır), en yeni max kayıt. */
function mergeHashes(previous, fresh, max) {
  const map = new Map(Object.entries(previous || {}));
  for (const [sha, name] of fresh) {
    map.delete(sha);
    map.set(sha, name);
  }
  map.delete(EICAR_SHA256);
  const entries = Array.from(map.entries());
  const kept = entries.slice(Math.max(0, entries.length - Math.max(0, max - 1)));
  return Object.fromEntries([[EICAR_SHA256, 'EICAR-Test-File'], ...kept]);
}

const RULE_START = /^[ \t]*(?:(?:private|global)[ \t]+)*rule[ \t]+([A-Za-z_][A-Za-z0-9_]*)/gm;

function conditionUsesStrings(node) {
  if (!node || typeof node !== 'object') return false;
  if (['string', 'at', 'count', 'quant'].includes(node.type)) return true;
  return ['left', 'right', 'operand'].some((k) => conditionUsesStrings(node[k]));
}

/** Dosyayı kural bloklarına ayırır; motorun tam desteklediklerini döndürür. */
function extractSupportedRules(text, seenNames) {
  const starts = [];
  let m;
  RULE_START.lastIndex = 0;
  while ((m = RULE_START.exec(text))) starts.push(m.index);
  const kept = [];
  let skipped = 0;
  for (let i = 0; i < starts.length; i++) {
    const block = text.slice(starts[i], i + 1 < starts.length ? starts[i + 1] : text.length).trim();
    if (/^\s*(private|global)\b/.test(block)) {
      skipped++; // private/global kurallar başka kurallara bağlıdır
      continue;
    }
    const parsed = signatures.parseYara(block);
    const rule = parsed.length === 1 && parsed.skipped.length === 0 ? parsed[0] : null;
    if (!rule || rule.strings.length === 0 || !conditionUsesStrings(rule.condition) || seenNames.has(rule.name)) {
      skipped++;
      continue;
    }
    seenNames.add(rule.name);
    kept.push(block);
  }
  return { kept, skipped };
}

function collectYara(dirs) {
  const seen = new Set();
  const blocks = [];
  let skipped = 0;
  const notices = [];
  for (const entry of dirs) {
    const { dir, match } = typeof entry === 'string' ? { dir: entry, match: null } : entry;
    const files = [];
    const walk = (d) => {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        const p = path.join(d, e.name);
        if (e.isDirectory()) walk(p);
        else if (/\.(yar|yara)$/i.test(e.name) && (!match || match.test(path.relative(dir, p).split(path.sep).join('/')))) files.push(p);
      }
    };
    walk(dir);
    files.sort();
    let ruleCount = 0;
    for (const f of files) {
      const r = extractSupportedRules(fs.readFileSync(f, 'utf8'), seen);
      blocks.push(...r.kept);
      ruleCount += r.kept.length;
      skipped += r.skipped;
    }
    // Lisans bildirimi (ör. MIT) DB ile birlikte dağıtılır
    for (const d of [dir, path.dirname(dir)]) {
      const lic = ['LICENSE', 'LICENSE.md', 'LICENSE.txt'].map((n) => path.join(d, n)).find((p) => fs.existsSync(p));
      if (lic) {
        const meta = (typeof entry === 'object' && entry.source) || { name: path.basename(path.resolve(d)) };
        notices.push(Object.assign({}, meta, { source: meta.name, rules: ruleCount, license: fs.readFileSync(lic, 'utf8').trim() }));
        break;
      }
    }
  }
  return { text: blocks.join('\n\n') + (blocks.length ? '\n' : ''), count: blocks.length, skipped, notices };
}

/**
 * rule-sources.json'daki depoları (sığ) klonlar; her biri için yara dizini,
 * dosya süzgeci ve kaynak bilgisi (commit dahil) döndürür.
 */
function fetchRuleSources(file, cacheDir) {
  const { execFileSync } = require('child_process');
  const cfg = JSON.parse(fs.readFileSync(file, 'utf8'));
  fs.mkdirSync(cacheDir, { recursive: true });
  return cfg.sources.map((src) => {
    const dest = path.join(cacheDir, src.repo.replace(/^.*\/([^/]+?)(\.git)?$/, '$1'));
    if (!fs.existsSync(path.join(dest, '.git'))) {
      execFileSync('git', ['clone', '--quiet', '--depth', '1', src.repo, dest], { stdio: 'inherit' });
    }
    const commit = execFileSync('git', ['-C', dest, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
    return {
      dir: path.join(dest, src.path),
      match: src.match ? new RegExp(src.match) : null,
      source: { name: src.name, url: src.repo.replace(/\.git$/, ''), commit, spdx: src.license }
    };
  });
}

// Paylaşımlı barındırma/platform kökleri: alt alan adları listelenebilir,
// kökün kendisi asla (sites.google.com tüm Google Sites demektir)
const PLATFORM_ROOTS = new Set([
  'sites.google.com', 'docs.google.com', 'drive.google.com', 'forms.gle', 'storage.googleapis.com',
  'firebasestorage.googleapis.com', 'googleapis.com', 'appspot.com', 'web.app', 'firebaseapp.com',
  'blogspot.com', 'github.io', 'githubusercontent.com', 'gitlab.io', 'vercel.app', 'netlify.app',
  'pages.dev', 'workers.dev', 'r2.dev', 'herokuapp.com', 'glitch.me', 'replit.app', 'repl.co',
  'azurewebsites.net', 'blob.core.windows.net', 'web.core.windows.net', 'amazonaws.com',
  's3.amazonaws.com', 'cloudfront.net', 'ipfs.io', 'dweb.link', 'sharepoint.com', 'onedrive.live.com',
  '1drv.ms', 'dropbox.com', 'dropboxusercontent.com', 'notion.site', 'webflow.io', 'framer.app',
  'framer.website', 'wixsite.com', 'weebly.com', 'weeblysite.com', 'square.site', 'godaddysites.com',
  'mybluehost.me', '000webhostapp.com', 'duckdns.org', 'ngrok.io', 'ngrok-free.app', 'linktr.ee',
  'canva.site', 'my.canva.site', 'translate.goog', 'bit.ly', 'tinyurl.com', 't.co', 'l.instagram.com',
  'l.facebook.com', 'lm.facebook.com', 'cdn.ampproject.org', 'gravatar.com', 'telegra.ph'
]);

/** Satır başına alan adı (veya URL) listesi; "#" yorum, hosts biçimi de olur. */
function parseDomainList(text) {
  const out = [];
  for (const raw of String(text).split(/\r?\n/)) {
    let line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;
    const parts = line.split(/[\s,]+/);
    // hosts biçimi ("0.0.0.0 alan.adi") ve Umbrella CSV ("1,alan.adi")
    line = parts.length > 1 && /^(\d+|0\.0\.0\.0|127\.0\.0\.1)$/.test(parts[0]) ? parts[1] : parts[0];
    if (/^[a-z]+:\/\//i.test(line)) {
      try {
        line = new URL(line).hostname;
      } catch {
        continue;
      }
    }
    const h = phishing.normalizeHost(line);
    if (h && h !== 'localhost' && !/^\d+(\.\d+){3}$/.test(h)) out.push(h);
  }
  return out;
}

async function domainList(src, label, popular, previousList) {
  if (!src) return null;
  try {
    const all = parseDomainList(await readSource(src));
    // Üst alan adı da eşleştiği için popüler bir sitenin üst alan adı
    // (ör. s3.us-west-2.amazonaws.com) listede kalırsa o sitenin tamamı düşer
    const kept = all.filter(
      (d) => !PLATFORM_ROOTS.has(d) && !popular.has(d) && !popular.has(d.replace(/^www\./, '')) && !popular.parents.has(d)
    );
    if (!kept.length) throw new Error('liste boş');
    const list = phishing.buildList(kept);
    return { list, count: phishing.listSize(list), dropped: all.length - kept.length };
  } catch (err) {
    console.warn(`::warning::${label} alınamadı, önceki liste korunuyor:`, err.message);
    const list = phishing.validList(previousList || '');
    return list ? { list, count: phishing.listSize(list), dropped: 0, stale: true } : null;
  }
}

function defaultVersion(now = new Date()) {
  const p = (n) => String(n).padStart(2, '0');
  return `${now.getUTCFullYear()}.${now.getUTCMonth() + 1}.${now.getUTCDate()}.${p(now.getUTCHours())}${p(now.getUTCMinutes())}`;
}

async function build(opts) {
  let previous = {};
  let previousDomains = {};
  if (opts.previous) {
    try {
      const prev = JSON.parse(await readSource(opts.previous));
      previous = prev.sha256 || {};
      previousDomains = prev.domains || {};
    } catch (err) {
      console.warn('Önceki DB okunamadı, sıfırdan başlanıyor:', err.message);
    }
  }
  let fresh = [];
  if (opts.mbCsv) {
    const headers = process.env.MALWAREBAZAAR_AUTH_KEY ? { 'Auth-Key': process.env.MALWAREBAZAAR_AUTH_KEY } : {};
    try {
      fresh = parseMalwareBazaarCsv(await readSource(opts.mbCsv, headers));
    } catch (err) {
      // Besleme geçici olarak erişilemezse önceki hash'ler + güncel kurallar yine yayınlanır
      console.warn('::warning::MalwareBazaar alınamadı, yalnız önceki hash listesi kullanılıyor:', err.message);
    }
  }
  const sha256 = mergeHashes(previous, fresh, opts.maxHashes);
  const yaraDirs = [...(opts.yaraDirs || [])];
  if (opts.ruleSources) yaraDirs.push(...fetchRuleSources(opts.ruleSources, opts.ruleCache));
  const yara = collectYara(yaraDirs);

  let popular = new Set();
  popular.parents = new Set();
  if (opts.popularDomains) {
    try {
      popular = new Set(parseDomainList(await readSource(opts.popularDomains)).slice(0, opts.popularTop || 100000));
    } catch (err) {
      console.warn('::warning::Popüler alan adı listesi alınamadı:', err.message);
    }
    popular.parents = new Set();
    for (const d of popular) {
      const labels = d.split('.');
      for (let i = 1; i < labels.length - 1; i++) popular.parents.add(labels.slice(i).join('.'));
    }
  }
  const phish = await domainList(opts.phishingList, 'Kimlik avı listesi', popular, previousDomains.phishing);
  const malware = await domainList(opts.urlhausHosts, 'URLhaus', popular, previousDomains.malware);

  const db = {
    version: opts.version || defaultVersion(),
    updated: Date.now(),
    sha256,
    yara: yara.text,
    sources: [
      ...(opts.mbCsv ? [{ name: 'MalwareBazaar (abuse.ch)', url: 'https://bazaar.abuse.ch', license: 'CC0', newHashes: fresh.length }] : []),
      ...yara.notices.map((n) => {
        const out = { name: n.source, license: n.license, rules: n.rules };
        if (n.url) Object.assign(out, { url: n.url, commit: n.commit, spdx: n.spdx });
        return out;
      }),
      ...(phish ? [{ name: 'Phishing.Database', url: 'https://github.com/mitchellkrogza/Phishing.Database', license: 'MIT', domains: phish.count }] : []),
      ...(malware ? [{ name: 'URLhaus (abuse.ch)', url: 'https://urlhaus.abuse.ch', license: 'CC0', domains: malware.count }] : [])
    ]
  };
  if (phish || malware) db.domains = { phishing: phish ? phish.list : '', malware: malware ? malware.list : '' };
  const err = validateDb(db);
  if (err) throw new Error('Şema hatası: ' + err);
  let json = JSON.stringify(db);
  let trimmedHashes = 0;
  const limit = opts.legacyLimit || LEGACY_CLIENT_BYTES;
  if (Buffer.byteLength(json) > limit) {
    const keys = Object.keys(db.sha256).filter((k) => k !== EICAR_SHA256); // eski → yeni
    const perHash = keys.length ? (Buffer.byteLength(JSON.stringify(db.sha256)) / (keys.length + 1)) : 1;
    while (Buffer.byteLength(json) > limit && keys.length) {
      const drop = Math.max(1, Math.ceil((Buffer.byteLength(json) - limit) / perHash));
      for (const k of keys.splice(0, drop)) delete db.sha256[k];
      trimmedHashes += drop;
      json = JSON.stringify(db);
    }
    if (trimmedHashes) console.warn(`::warning::Eski istemci sınırı için en eski ${trimmedHashes} hash çıkarıldı`);
  }
  if (Buffer.byteLength(json) > MAX_DB_BYTES) throw new Error(`DB çok büyük (${Buffer.byteLength(json)} bayt)`);

  // Son güvenlik: üretilen DB, uygulamanın yükleyicisiyle hatasız yüklenmeli
  fs.mkdirSync(opts.out, { recursive: true });
  fs.writeFileSync(path.join(opts.out, 'db.json'), json);
  const loaded = signatures.load(opts.out);
  if (loaded.skipped.length) throw new Error('Üretilen DB temiz yüklenmedi: ' + JSON.stringify(loaded.skipped.slice(0, 3)));

  return {
    version: db.version,
    hashes: Object.keys(db.sha256).length,
    trimmedHashes,
    fresh: fresh.length,
    rules: yara.count,
    skippedRules: yara.skipped,
    phishingDomains: phish ? phish.count : 0,
    malwareDomains: malware ? malware.count : 0,
    droppedDomains: (phish ? phish.dropped : 0) + (malware ? malware.dropped : 0),
    bytes: Buffer.byteLength(json)
  };
}

module.exports = { parseCsvLine, parseMalwareBazaarCsv, mergeHashes, extractSupportedRules, threatName, parseDomainList, build };

if (require.main === module) {
  build(parseArgs(process.argv.slice(2)))
    .then((r) => console.log(JSON.stringify(r)))
    .catch((err) => {
      console.error(err.message || err);
      process.exit(1);
    });
}
