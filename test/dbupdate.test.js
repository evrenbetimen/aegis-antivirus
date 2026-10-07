// İmza DB güncelleme testleri — node --test test/dbupdate.test.js (electron gerekmez)
const { test } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const dbupdate = require('../src/dbupdate');

function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-upd-'));
}

function makeKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { pub: publicKey.export({ type: 'spki', format: 'pem' }), priv: privateKey };
}

/** Kaynak dizinde db.json + .sha256 (+ isteğe bağlı .sig) yayını hazırlar. */
function publish(dir, version, privKey) {
  const key = crypto.createHash('sha256').update(version).digest('hex');
  const payload = Buffer.from(JSON.stringify({ version, updated: 0, sha256: { [key]: 'Test.Update' } }));
  const file = path.join(dir, 'db.json');
  fs.writeFileSync(file, payload);
  fs.writeFileSync(file + '.sha256', crypto.createHash('sha256').update(payload).digest('hex') + '  db.json');
  if (privKey) fs.writeFileSync(file + '.sig', crypto.sign(null, payload, privKey).toString('base64'));
  return file;
}

test('imzalı güncelleme kabul edilir, bayt bayt yazılır ve yerelde doğrulanır', async () => {
  const src = tmpdir();
  const dst = tmpdir();
  const { pub, priv } = makeKeys();
  const file = publish(src, '2099.1.1', priv);
  const res = await dbupdate.update({ url: 'file://' + file, dir: dst, publicKey: pub });
  assert.ok(res.ok && res.changed, JSON.stringify(res));
  assert.deepEqual(fs.readFileSync(path.join(dst, 'db.json')), fs.readFileSync(file));
  assert.deepEqual(dbupdate.verifyLocal(dst, pub), { ok: true, reason: 'ok', signed: true });
});

test('imzası bozuk ya da başka anahtarla imzalı güncelleme reddedilir', async () => {
  const src = tmpdir();
  const dst = tmpdir();
  const { pub } = makeKeys();
  const other = makeKeys();
  const file = publish(src, '2099.1.1', other.priv);
  const res = await dbupdate.update({ url: 'file://' + file, dir: dst, publicKey: pub });
  assert.equal(res.ok, false);
  assert.match(res.reason, /imza/i);
  assert.ok(!fs.existsSync(path.join(dst, 'db.json')), 'reddedilen DB yazıldı');

  fs.rmSync(file + '.sig');
  const res2 = await dbupdate.update({ url: 'file://' + file, dir: dst, publicKey: pub });
  assert.equal(res2.ok, false);
  assert.match(res2.reason, /\.sig/);
});

test('uzak kaynak açık anahtar olmadan reddedilir (ağa çıkmadan)', async () => {
  const res = await dbupdate.update({ url: 'https://example.invalid/db.json', dir: tmpdir() });
  assert.equal(res.ok, false);
  assert.match(res.reason, /açık anahtar/);
});

test('yerelde değiştirilen db.json imza denetiminde yakalanır', async () => {
  const src = tmpdir();
  const dst = tmpdir();
  const { pub, priv } = makeKeys();
  const file = publish(src, '2099.1.1', priv);
  await dbupdate.update({ url: 'file://' + file, dir: dst, publicKey: pub });
  // Saldırgan hem db.json'ı hem .sha256'yı değiştirir; imza yine de tutmaz
  const evil = publish(tmpdir(), '2099.9.9', null);
  fs.copyFileSync(evil, path.join(dst, 'db.json'));
  fs.copyFileSync(evil + '.sha256', path.join(dst, 'db.json.sha256'));
  const v = dbupdate.verifyLocal(dst, pub);
  assert.equal(v.ok, false, JSON.stringify(v));
  // .sig silinse de imzasız kopya kabul edilmez (paketteki DB'nin aynısı değil)
  fs.rmSync(path.join(dst, 'db.json.sig'));
  assert.equal(dbupdate.verifyLocal(dst, pub, src).ok, false);
  // Paketteki DB'nin birebir kopyası imzasız da geçerlidir
  fs.copyFileSync(file, path.join(dst, 'db.json'));
  fs.copyFileSync(file + '.sha256', path.join(dst, 'db.json.sha256'));
  assert.equal(dbupdate.verifyLocal(dst, pub, src).ok, true);
});

test('yönlendirme döngüsü sınırlanır', async () => {
  let hits = 0;
  const server = http.createServer((req, res) => {
    hits++;
    res.writeHead(302, { Location: '/db.json' });
    res.end();
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}/db.json`;
  try {
    const res = await dbupdate.update({ url, dir: tmpdir(), timeoutMs: 3000 });
    assert.equal(res.ok, false);
    assert.match(res.reason, /yönlendirme/);
    assert.ok(hits <= dbupdate.MAX_REDIRECTS + 1, `istek sayısı: ${hits}`);
  } finally {
    server.close();
  }
});

test('imza dizini hazırlığı: ilk kurulum, kullanıcı güncellemesi korunur, yeni paket sürümü kazanır', () => {
  const bundled = tmpdir();
  const user = path.join(tmpdir(), 'signatures');
  publish(bundled, '2026.10.1', null);
  fs.writeFileSync(path.join(bundled, 'rules.yar'), 'rule A { strings: $a = "x" condition: $a }');

  dbupdate.prepareSignaturesDir(bundled, user);
  assert.equal(JSON.parse(fs.readFileSync(path.join(user, 'db.json'))).version, '2026.10.1');
  assert.ok(fs.existsSync(path.join(user, 'rules.yar')));
  assert.equal(dbupdate.verifyLocal(user).ok, true);

  // Kullanıcı daha yeni sürüme güncelledi → paket eski, dokunulmaz
  publish(user, '2026.11.0', null);
  dbupdate.prepareSignaturesDir(bundled, user);
  assert.equal(JSON.parse(fs.readFileSync(path.join(user, 'db.json'))).version, '2026.11.0');

  // Uygulama güncellemesi daha yeni DB getirdi → kullanıcı kopyası yenilenir
  publish(bundled, '2027.1.0', null);
  dbupdate.prepareSignaturesDir(bundled, user);
  assert.equal(JSON.parse(fs.readFileSync(path.join(user, 'db.json'))).version, '2027.1.0');
});

test('sürüm karşılaştırma sayısal yapılır', () => {
  assert.equal(dbupdate.compareVersions('2026.10.1', '2026.9.9'), 1);
  assert.equal(dbupdate.compareVersions('2026.1', '2026.1.0'), 0);
  assert.equal(dbupdate.compareVersions('1', '2'), -1);
});
