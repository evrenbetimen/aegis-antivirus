const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const { HashCache } = require('../src/cache.js');

const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);

function tmpDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-cache-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test('set/get/miss ve temel islemler', (t) => {
  const dir = tmpDir(t);
  const cache = new HashCache(path.join(dir, 'cache.json'));

  assert.strictEqual(cache.size(), 0);
  assert.strictEqual(cache.get('yok'), undefined);
  assert.strictEqual(cache.has('yok'), false);

  assert.strictEqual(cache.set('k1', HASH_A), true);
  assert.strictEqual(cache.get('k1'), HASH_A);
  assert.strictEqual(cache.has('k1'), true);
  assert.strictEqual(cache.size(), 1);

  // guncelleme ayni anahtari tazeler, sayiyi artirmaz
  assert.strictEqual(cache.set('k1', HASH_B), true);
  assert.strictEqual(cache.get('k1'), HASH_B);
  assert.strictEqual(cache.size(), 1);
});

test('gecersiz hash degerleri reddedilir', (t) => {
  const dir = tmpDir(t);
  const cache = new HashCache(path.join(dir, 'cache.json'));

  const bad = [
    'zz'.repeat(32), // hex degil
    'a'.repeat(63), // kisa
    'a'.repeat(65), // uzun
    'not-a-hash',
    '',
    null,
    undefined,
    123,
    { toString: () => 'a'.repeat(64) }
  ];
  for (const value of bad) {
    assert.strictEqual(cache.set('g' + String(value).slice(0, 4), value), false, String(value));
  }
  assert.strictEqual(cache.size(), 0);
  assert.strictEqual(cache.stats().writes, 0);

  // buyuk harfli 64 hex normalize edilerek kabul edilir
  assert.strictEqual(cache.set('upper', 'A'.repeat(64)), true);
  assert.strictEqual(cache.get('upper'), 'a'.repeat(64));
});

test('keyFor farkli statlar icin farkli, ayni stat icin ayni', () => {
  const base = { dev: 1, ino: 42, size: 1024, mtimeMs: 1700000000000 };
  assert.strictEqual(HashCache.keyFor(base), HashCache.keyFor({ ...base }));
  assert.notStrictEqual(HashCache.keyFor(base), HashCache.keyFor({ ...base, dev: 2 }));
  assert.notStrictEqual(HashCache.keyFor(base), HashCache.keyFor({ ...base, ino: 43 }));
  assert.notStrictEqual(HashCache.keyFor(base), HashCache.keyFor({ ...base, size: 1025 }));
  assert.notStrictEqual(HashCache.keyFor(base), HashCache.keyFor({ ...base, mtimeMs: 1700000000001 }));

  // gercek stat nesnesiyle (fs.statSync)
  const file = path.join(os.tmpdir(), 'aegis-keyfor-' + process.pid);
  fs.writeFileSync(file, 'x');
  const stat = fs.statSync(file);
  const key = HashCache.keyFor(stat);
  assert.match(key, /^\d+:\d+:\d+:[\d.]+$/);
  assert.strictEqual(key, HashCache.keyFor(fs.statSync(file)));
  fs.rmSync(file, { force: true });
});

test('flush sonrasi dosyadan yeniden yukleme (kalicilik)', (t) => {
  const dir = tmpDir(t);
  const file = path.join(dir, 'cache.json');

  const first = new HashCache(file);
  first.set('1:2:3:4', HASH_A);
  first.set('5:6:7:8', HASH_B);
  assert.strictEqual(first.flush(), true);

  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.strictEqual(raw.version, 1);
  assert.deepStrictEqual(raw.entries, { '1:2:3:4': HASH_A, '5:6:7:8': HASH_B });

  const second = new HashCache(file);
  assert.strictEqual(second.size(), 2);
  assert.strictEqual(second.get('1:2:3:4'), HASH_A);
  assert.strictEqual(second.get('5:6:7:8'), HASH_B);
  assert.strictEqual(second.get('9:9:9:9'), undefined);
  // yeni ornek temiz istatistiklerle baslar
  assert.deepStrictEqual(second.stats(), { hits: 2, misses: 1, writes: 0, evictions: 0 });
});

test('yok dosya / bozuk JSON / yanlis surum sessizce bos baslar', (t) => {
  const dir = tmpDir(t);

  const missing = new HashCache(path.join(dir, 'yok.json'));
  assert.strictEqual(missing.size(), 0);
  assert.strictEqual(missing.get('k'), undefined);

  const corruptFile = path.join(dir, 'bozuk.json');
  fs.writeFileSync(corruptFile, '{"version":1,"entries":{"1:2:3:4":"');
  const corrupt = new HashCache(corruptFile);
  assert.strictEqual(corrupt.size(), 0);
  assert.strictEqual(corrupt.get('1:2:3:4'), undefined);

  const wrongVersion = path.join(dir, 'surum.json');
  fs.writeFileSync(wrongVersion, JSON.stringify({ version: 99, entries: { a: HASH_A } }));
  assert.strictEqual(new HashCache(wrongVersion).size(), 0);

  const badValues = path.join(dir, 'gecersiz.json');
  fs.writeFileSync(
    badValues,
    JSON.stringify({ version: 1, entries: { ok: HASH_A, kisa: 'abc', sayi: 5, yok: null } })
  );
  const filtered = new HashCache(badValues);
  assert.strictEqual(filtered.size(), 1);
  assert.strictEqual(filtered.get('ok'), HASH_A);
  assert.strictEqual(filtered.get('kisa'), undefined);
});

test('maxEntries asiliminda ilk girdiler eviction', (t) => {
  const dir = tmpDir(t);
  const file = path.join(dir, 'cache.json');
  const cache = new HashCache(file, { maxEntries: 3 });

  for (let i = 0; i < 5; i++) cache.set(`k${i}`, HASH_A);

  assert.strictEqual(cache.size(), 3);
  assert.strictEqual(cache.get('k0'), undefined);
  assert.strictEqual(cache.get('k1'), undefined);
  assert.strictEqual(cache.get('k2'), HASH_A);
  assert.strictEqual(cache.get('k3'), HASH_A);
  assert.strictEqual(cache.get('k4'), HASH_A);
  assert.strictEqual(cache.stats().evictions, 2);

  // kalicilikte de limit korunur
  cache.flush();
  const reloaded = new HashCache(file, { maxEntries: 3 });
  assert.strictEqual(reloaded.size(), 3);
  assert.strictEqual(reloaded.get('k0'), undefined);

  // guncellenen girdi sona alinir, erken eviction yemez
  const lru = new HashCache(path.join(dir, 'lru.json'), { maxEntries: 2 });
  lru.set('a', HASH_A);
  lru.set('b', HASH_B);
  lru.set('a', HASH_B); // 'a' tazelenir
  lru.set('c', HASH_A); // 'b' atilmali
  assert.strictEqual(lru.get('b'), undefined);
  assert.strictEqual(lru.get('a'), HASH_B);
  assert.strictEqual(lru.get('c'), HASH_A);
});

test('flush atomiktir: .tmp kalmaz, hedef guncel', (t) => {
  const dir = tmpDir(t);
  const file = path.join(dir, 'cache.json');
  const cache = new HashCache(file);

  cache.set('k', HASH_A);
  assert.strictEqual(cache.flush(), true);

  const left = fs.readdirSync(dir);
  assert.deepStrictEqual(left, ['cache.json'], `tmp dosyasi kaldi: ${left.join(', ')}`);
  assert.strictEqual(fs.existsSync(file + '.tmp'), false);
  assert.strictEqual(JSON.parse(fs.readFileSync(file, 'utf8')).entries.k, HASH_A);

  // uzerine yazmada da tmp temizlenir
  cache.set('k', HASH_B);
  cache.flush();
  assert.deepStrictEqual(fs.readdirSync(dir), ['cache.json']);
  assert.strictEqual(JSON.parse(fs.readFileSync(file, 'utf8')).entries.k, HASH_B);

  // kirli yazma yok: set dosyaya dokunmaz
  const other = path.join(dir, 'diger.json');
  const c2 = new HashCache(other);
  c2.set('x', HASH_A);
  assert.strictEqual(fs.existsSync(other), false);
  assert.strictEqual(fs.existsSync(other + '.tmp'), false);
});

test('1000 yazımda bir otomatik flush', (t) => {
  const dir = tmpDir(t);
  const file = path.join(dir, 'auto.json');
  const cache = new HashCache(file);

  for (let i = 0; i < 999; i++) cache.set(`k${i}`, HASH_A);
  assert.strictEqual(fs.existsSync(file), false, '1000 oncesinde yazmamali');

  cache.set('k999', HASH_A); // 1000. yazim -> otomatik flush
  assert.strictEqual(fs.existsSync(file), true);
  assert.strictEqual(fs.readdirSync(dir).length, 1, 'tmp kalmamali');
  assert.strictEqual(new HashCache(file).size(), 1000);
});

test('istatistikler: hits, misses, writes, evictions', (t) => {
  const dir = tmpDir(t);
  const cache = new HashCache(path.join(dir, 'stats.json'), { maxEntries: 2 });

  assert.deepStrictEqual(cache.stats(), { hits: 0, misses: 0, writes: 0, evictions: 0 });

  cache.set('a', HASH_A);
  cache.set('b', HASH_B);
  cache.set('g', 'bozuk'); // yazilmadi
  cache.get('a'); // hit
  cache.get('a'); // hit
  cache.get('yok'); // miss
  cache.set('c', HASH_A); // 'a' eviction

  assert.deepStrictEqual(cache.stats(), { hits: 2, misses: 1, writes: 3, evictions: 1 });

  // donen nesne kopyadir, disaridan bozulamaz
  const s = cache.stats();
  s.hits = 999;
  assert.strictEqual(cache.stats().hits, 2);
});

test('flushOnExit process cikisinda yazar (istege bagli)', (t) => {
  const dir = tmpDir(t);
  const file = path.join(dir, 'exit.json');
  const script = path.join(dir, 'child.js');

  fs.writeFileSync(
    script,
    `
    const { HashCache } = require(${JSON.stringify(path.join(__dirname, '..', 'src', 'cache.js'))});
    const c = new HashCache(${JSON.stringify(file)});
    c.set('exit-key', ${JSON.stringify(HASH_A)});
    c.flushOnExit();
    process.exit(0); // acik cikis: 'exit' olayi tetiklenir
    `
  );

  execFileSync(process.execPath, [script], { stdio: 'pipe' });

  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.strictEqual(raw.version, 1);
  assert.strictEqual(raw.entries['exit-key'], HASH_A);
  assert.strictEqual(fs.existsSync(file + '.tmp'), false);
});

test('dispose cikis dinleyicisini kaldirir (dinleyici sizintisi yok)', () => {
  const before = process.listenerCount('exit');
  const cache = new HashCache(path.join(os.tmpdir(), 'aegis-dispose-' + process.pid + '.json'));
  cache.flushOnExit();
  cache.flushOnExit(); // iki kez cagirilmamali
  assert.strictEqual(process.listenerCount('exit'), before + 1);
  cache.dispose();
  assert.strictEqual(process.listenerCount('exit'), before);
});
