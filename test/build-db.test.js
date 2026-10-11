// İmza DB üretim hattı testleri — node --test test/build-db.test.js
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const build = require('../scripts/build-db');
const signatures = require('../src/signatures');

const EICAR = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
const h = (n) => n.toString(16).padStart(64, '0');

test('CSV: tırnaklı alanlar, içte virgül ve boşluklu ayraç', () => {
  assert.deepEqual(build.parseCsvLine('"a", "b, c", "d""e", f,'), ['a', 'b, c', 'd"e', 'f', '']);
});

test('MalwareBazaar CSV: geçersiz hash atlanır, ad üretilir, eski → yeni sıralanır', () => {
  const csv = [
    '# "first_seen_utc","sha256_hash","md5_hash","file_type_guess","signature"',
    `"2026-10-08 00:02:00", "${h(2).toUpperCase()}", "m", "exe", "Agent Tesla"`,
    `"2026-10-08 00:01:00", "${h(1)}", "m", "sh", "n/a"`,
    '"2026-10-08 00:03:00", "zzz", "m", "exe", "Bad"'
  ].join('\n');
  assert.deepEqual(build.parseMalwareBazaarCsv(csv), [
    [h(1), 'MalwareBazaar.Generic.sh'],
    [h(2), 'MalwareBazaar.Agent-Tesla']
  ]);
});

test('kayan pencere: en yeni N kayıt tutulur, EICAR her zaman ilk sırada', () => {
  const prev = { [h(1)]: 'a', [h(2)]: 'b', [h(3)]: 'c' };
  const out = build.mergeHashes(prev, [[h(4), 'd'], [h(1), 'a2']], 4);
  assert.deepEqual(Object.keys(out), [EICAR, h(3), h(4), h(1)]);
  assert.equal(out[h(1)], 'a2');
});

test('YARA ayıklama: yalnız tam desteklenen ve dizgi kullanan kurallar alınır', () => {
  const text = `
import "pe"
rule Good_Rule : tag {
  strings: $a = { 4D 5A [2] 90 } $b = "evil" wide
  condition: uint16(0) == 0x5A4D and ($a or $b)
}
rule Uses_Pe { strings: $a = "x" condition: pe.is_dll() and $a }
rule No_Strings { condition: uint16(0) == 0x5A4D }
private rule Helper { strings: $a = "h" condition: $a }
rule Good_Rule { strings: $a = "dup" condition: $a }
`;
  const r = build.extractSupportedRules(text, new Set());
  assert.equal(r.kept.length, 1);
  assert.match(r.kept[0], /^rule Good_Rule/);
  assert.equal(r.skipped, 4);
});

test('uçtan uca: CSV + YARA dizini → uygulamanın temiz yüklediği db.json', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-build-'));
  const yaraDir = path.join(dir, 'rules');
  fs.mkdirSync(yaraDir);
  fs.writeFileSync(path.join(dir, 'LICENSE'), 'MIT License (test)');
  fs.writeFileSync(
    path.join(yaraDir, 'a.yara'),
    'rule Feed_Marker { strings: $m = "aegis-feed-marker" condition: $m }\nrule Bad { condition: pe.x }'
  );
  const csv = path.join(dir, 'mb.csv');
  fs.writeFileSync(csv, `# "first_seen_utc","sha256_hash","signature"\n"2026-10-08 00:00:00", "${h(9)}", "Emotet"\n`);
  const prev = path.join(dir, 'prev.json');
  fs.writeFileSync(prev, JSON.stringify({ version: '1', sha256: { [h(8)]: 'Old' } }));

  const out = path.join(dir, 'out');
  const res = await build.build({ out, previous: prev, mbCsv: csv, yaraDirs: [yaraDir], maxHashes: 100, version: '2099.1.1' });
  assert.deepEqual([res.hashes, res.fresh, res.rules, res.skippedRules], [3, 1, 1, 1]);

  const db = signatures.load(out);
  assert.deepEqual(db.skipped, []);
  assert.equal(db.version, '2099.1.1');
  assert.equal(db.sha256.get(h(9)), 'MalwareBazaar.Emotet');
  assert.equal(db.sha256.get(h(8)), 'Old');
  assert.deepEqual(signatures.checkBuffer(Buffer.from('x aegis-feed-marker y'), db), { name: 'Feed_Marker', kind: 'yara' });
  const json = JSON.parse(fs.readFileSync(path.join(out, 'db.json'), 'utf8'));
  assert.ok(json.sources.some((s) => /MIT License/.test(s.license)), 'lisans bildirimi eksik');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('--yara-match: yalnız göreli yolu eşleşen kural dosyaları alınır', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-build-'));
  const rules = path.join(dir, 'rules');
  fs.mkdirSync(path.join(rules, 'crimeware'), { recursive: true });
  fs.mkdirSync(path.join(rules, 'generic'), { recursive: true });
  fs.writeFileSync(path.join(rules, 'crimeware', 'a.yar'), 'rule Keep_Me { strings: $ = "keep-me-marker" condition: any of them }');
  fs.writeFileSync(path.join(rules, 'generic', 'b.yar'), 'rule Drop_Me { strings: $a = "drop-me-marker" condition: $a }');
  const out = path.join(dir, 'out');
  const res = await build.build({ out, yaraDirs: [{ dir: rules, match: /^crimeware\// }], maxHashes: 10, version: '2099.1.2' });
  assert.equal(res.rules, 1);
  const db = signatures.load(out);
  assert.deepEqual(db.rules.map((r) => r.name), ['Keep_Me']);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('alan adı listeleri: popüler ve platform kökleri çıkarılır, kaynak yoksa önceki korunur', async () => {
  const phishing = require('../src/phishing');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-build-'));
  fs.writeFileSync(
    path.join(dir, 'phish.txt'),
    ['# yorum', 'kotu-giris.xyz', 'WWW.Banka-Dogrula.com.', 'sites.google.com', 'gravatar.com',
      's3.us-west-2.amazonaws.com', 'https://evil.example.net/login', 'kotu-giris.xyz'].join('\n')
  );
  fs.writeFileSync(path.join(dir, 'hosts.txt'), '# URLhaus\n127.0.0.1\tmalware-cdn.top\n127.0.0.1\t1.2.3.4\n');
  fs.writeFileSync(path.join(dir, 'top.csv'), '1,google.com\n2,gravatar.com\n3,bucket.s3.us-west-2.amazonaws.com\n');
  const out = path.join(dir, 'out');
  const r = await build.build({
    out, yaraDirs: [], maxHashes: 10, version: '1',
    phishingList: path.join(dir, 'phish.txt'), urlhausHosts: path.join(dir, 'hosts.txt'),
    popularDomains: path.join(dir, 'top.csv')
  });
  assert.equal(r.phishingDomains, 3);
  assert.equal(r.malwareDomains, 1);
  const db = signatures.load(out);
  assert.deepEqual(phishing.lookupHost('giris.kotu-giris.xyz', db.domains), { kind: 'phishing', domain: 'kotu-giris.xyz' });
  assert.ok(phishing.lookupHost('www.banka-dogrula.com', db.domains));
  assert.ok(phishing.lookupHost('evil.example.net', db.domains));
  assert.deepEqual(phishing.lookupHost('malware-cdn.top', db.domains), { kind: 'malware', domain: 'malware-cdn.top' });
  for (const ok of ['sites.google.com', 'gravatar.com', 'bucket.s3.us-west-2.amazonaws.com', 'example.net']) {
    assert.equal(phishing.lookupHost(ok, db.domains), null, ok);
  }
  const json = JSON.parse(fs.readFileSync(path.join(out, 'db.json'), 'utf8'));
  assert.deepEqual(json.sources.map((s) => s.license), ['MIT', 'CC0']);
  assert.ok(!fs.readFileSync(path.join(out, 'db.json'), 'utf8').includes('kotu-giris'), 'liste düz metin taşımamalı');

  // Kaynak erişilemezse önceki yayının listesi korunur
  const out2 = path.join(dir, 'out2');
  const r2 = await build.build({
    out: out2, yaraDirs: [], maxHashes: 10, version: '2',
    previous: path.join(out, 'db.json'), phishingList: path.join(dir, 'yok.txt')
  });
  assert.equal(r2.phishingDomains, 3);
  assert.ok(phishing.lookupHost('kotu-giris.xyz', signatures.load(out2).domains));
});

test('eski istemci sınırı: DB sığana kadar en eski hash\'ler çıkarılır, EICAR kalır', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-build-'));
  const prev = path.join(dir, 'prev.json');
  const sha = {};
  for (let i = 1; i <= 500; i++) sha[h(i)] = 'Eski.' + i;
  fs.writeFileSync(prev, JSON.stringify({ version: '0', sha256: sha }));
  const out = path.join(dir, 'out');
  const r = await build.build({ out, yaraDirs: [], maxHashes: 1000, version: '1', previous: prev, legacyLimit: 20000 });
  const json = fs.readFileSync(path.join(out, 'db.json'));
  assert.ok(json.length <= 20000, `${json.length} bayt`);
  assert.ok(r.trimmedHashes > 0);
  const db = JSON.parse(json);
  assert.ok(db.sha256[EICAR]);
  assert.ok(db.sha256[h(500)], 'en yeni hash kalmalı');
  assert.ok(!db.sha256[h(1)], 'en eski hash çıkmalı');
});
