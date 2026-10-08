//
// Gerçek imza veritabanı üretici — GitHub Actions'ta (signatures.yml) çalışır.
//
//   node scripts/build-db.js --out dist-db \
//     [--previous <db.json yolu|url>] \
//     [--mb-csv <MalwareBazaar CSV yolu|url>] \
//     [--yara-dir <dizin>]... [--max-hashes 100000]
//
// - SHA-256: MalwareBazaar "recent" CSV dışa aktarımı (abuse.ch, CC0).
//   Önceki yayınla birleştirilir; en yeni --max-hashes kayıt tutulur (kayan pencere).
// - YARA: verilen dizinlerdeki .yar/.yara dosyaları kural kural ayrılır; yalnız
//   Aegis motorunun TAM desteklediği ve en az bir dizgiye dayanan kurallar alınır
//   (desteklenmeyen kural asla yanlış değerlendirilmez, ayrıca boyut da küçülür).
// - Çıktı: <out>/db.json (yara metni db.json içine gömülür → tek imzalı dosya).
//   İmzalamak için: node scripts/sign-db.js <out>/db.json <özel-anahtar>
//
const fs = require('fs');
const path = require('path');
const https = require('https');
const signatures = require('../src/signatures');
const { validateDb } = require('../src/dbupdate');

const EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
const MAX_DB_BYTES = 18 * 1024 * 1024; // uygulama 20MB üstünü reddeder

function parseArgs(argv) {
  const out = { yaraDirs: [], maxHashes: 100000 }; // ~100 bayt/kayıt → ~10MB
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const v = argv[i + 1];
    if (a === '--out') (out.out = v), i++;
    else if (a === '--previous') (out.previous = v), i++;
    else if (a === '--mb-csv') (out.mbCsv = v), i++;
    else if (a === '--yara-dir') out.yaraDirs.push(v), i++;
    else if (a === '--max-hashes') (out.maxHashes = Number(v)), i++;
    else if (a === '--version') (out.version = v), i++;
    else throw new Error('Bilinmeyen argüman: ' + a);
  }
  if (!out.out) throw new Error('--out gerekli');
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
  for (const dir of dirs) {
    const files = [];
    const walk = (d) => {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        const p = path.join(d, e.name);
        if (e.isDirectory()) walk(p);
        else if (/\.(yar|yara)$/i.test(e.name)) files.push(p);
      }
    };
    walk(dir);
    files.sort();
    for (const f of files) {
      const r = extractSupportedRules(fs.readFileSync(f, 'utf8'), seen);
      blocks.push(...r.kept);
      skipped += r.skipped;
    }
    // Lisans bildirimi (ör. MIT) DB ile birlikte dağıtılır
    for (const d of [dir, path.dirname(dir)]) {
      const lic = ['LICENSE', 'LICENSE.md', 'LICENSE.txt'].map((n) => path.join(d, n)).find((p) => fs.existsSync(p));
      if (lic) {
        notices.push({ source: path.basename(path.resolve(d)), license: fs.readFileSync(lic, 'utf8').trim() });
        break;
      }
    }
  }
  return { text: blocks.join('\n\n') + (blocks.length ? '\n' : ''), count: blocks.length, skipped, notices };
}

function defaultVersion(now = new Date()) {
  const p = (n) => String(n).padStart(2, '0');
  return `${now.getUTCFullYear()}.${now.getUTCMonth() + 1}.${now.getUTCDate()}.${p(now.getUTCHours())}${p(now.getUTCMinutes())}`;
}

async function build(opts) {
  let previous = {};
  if (opts.previous) {
    try {
      previous = JSON.parse(await readSource(opts.previous)).sha256 || {};
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
  const yara = collectYara(opts.yaraDirs);

  const db = {
    version: opts.version || defaultVersion(),
    updated: Date.now(),
    sha256,
    yara: yara.text,
    sources: [
      { name: 'MalwareBazaar (abuse.ch)', url: 'https://bazaar.abuse.ch', license: 'CC0', newHashes: fresh.length },
      ...yara.notices.map((n) => ({ name: n.source, license: n.license }))
    ]
  };
  const err = validateDb(db);
  if (err) throw new Error('Şema hatası: ' + err);
  const json = JSON.stringify(db);
  if (Buffer.byteLength(json) > MAX_DB_BYTES) throw new Error(`DB çok büyük (${Buffer.byteLength(json)} bayt)`);

  // Son güvenlik: üretilen DB, uygulamanın yükleyicisiyle hatasız yüklenmeli
  fs.mkdirSync(opts.out, { recursive: true });
  fs.writeFileSync(path.join(opts.out, 'db.json'), json);
  const loaded = signatures.load(opts.out);
  if (loaded.skipped.length) throw new Error('Üretilen DB temiz yüklenmedi: ' + JSON.stringify(loaded.skipped.slice(0, 3)));

  return { version: db.version, hashes: Object.keys(sha256).length, fresh: fresh.length, rules: yara.count, skippedRules: yara.skipped, bytes: Buffer.byteLength(json) };
}

module.exports = { parseCsvLine, parseMalwareBazaarCsv, mergeHashes, extractSupportedRules, threatName, build };

if (require.main === module) {
  build(parseArgs(process.argv.slice(2)))
    .then((r) => console.log(JSON.stringify(r)))
    .catch((err) => {
      console.error(err.message || err);
      process.exit(1);
    });
}
