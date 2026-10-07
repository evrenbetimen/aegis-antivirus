// Arşiv modülü testleri — node --test test/archive.test.js (electron gerekmez)
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const archive = require('../src/archive');

const MARKER = 'AEGIS-TEST-MARKER-V1'; // EICAR KULLANMA (harici AV siler)

function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-arch-'));
}

/** Elle ustar arşivi üretir (zip-slip girdisi için). */
function makeTar(entries, dest) {
  const chunks = [];
  for (const e of entries) {
    const data = Buffer.from(e.data, 'utf8');
    const header = Buffer.alloc(512, 0);
    header.write(e.name, 0, 100, 'utf8');
    header.write('0000644\0', 100, 8);
    header.write('0000000\0', 108, 8);
    header.write('0000000\0', 116, 8);
    header.write(data.length.toString(8).padStart(11, '0') + '\0', 124, 12);
    header.write('00000000000\0', 136, 12);
    header.write('        ', 148, 8); // sağlama alanı boşlukla doldurulur
    header.write('0', 156, 1);
    header.write('ustar\0', 257, 6);
    header.write('00', 263, 2);
    let sum = 0;
    for (const b of header) sum += b;
    header.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8);
    chunks.push(header, data);
    const pad = (512 - (data.length % 512)) % 512;
    if (pad) chunks.push(Buffer.alloc(pad, 0));
  }
  chunks.push(Buffer.alloc(1024, 0)); // bitiş
  fs.writeFileSync(dest, Buffer.concat(chunks));
}

function readEntry(getStream, cap = 4 * 1024 * 1024) {
  return new Promise((resolve) => {
    const s = getStream();
    const chunks = [];
    let size = 0;
    const done = () => resolve(Buffer.concat(chunks));
    s.on('data', (c) => {
      size += c.length;
      if (size <= cap) chunks.push(c);
      if (size >= cap) {
        try {
          s.destroy();
        } catch {}
        done();
      }
    });
    s.on('end', done);
    s.on('close', done);
    s.on('error', done);
  });
}

test('zip: listeleme ve içerik taraması', async () => {
  const d = tmpdir();
  fs.writeFileSync(path.join(d, 'ic.txt'), 'içerik ' + MARKER);
  fs.writeFileSync(path.join(d, 'normal.txt'), 'zararsız');
  const zip = path.join(d, 'a.zip');
  execFileSync('zip', ['-q', '-j', zip, path.join(d, 'ic.txt'), path.join(d, 'normal.txt')]);

  assert.ok(archive.isArchive(zip));
  const entries = await archive.listEntries(zip);
  assert.equal(entries.length, 2, JSON.stringify(entries));
  assert.ok(entries.some((e) => e.name === 'ic.txt' && e.size > 0));
  assert.ok(entries.some((e) => e.name === 'normal.txt'));

  let found = null;
  const res = await archive.scanEntries(zip, async (entry, getStream) => {
    const buf = await readEntry(getStream);
    if (buf.toString('utf8').includes(MARKER)) found = entry.name;
  });
  assert.equal(found, 'ic.txt', 'marker içeren girdi okunamadı');
  assert.equal(res.scanned, 2, JSON.stringify(res));
  assert.ok(res.totalBytes > 0);
  fs.rmSync(d, { recursive: true, force: true });
});

test('tar: zip-slip girdisi listelenmez', async () => {
  const d = tmpdir();
  const tar = path.join(d, 'evil.tar');
  makeTar(
    [
      { name: 'guvenli.txt', data: 'ok ' + MARKER },
      { name: '../asiri-tirnali.txt', data: 'saldiri' }
    ],
    tar
  );

  const entries = await archive.listEntries(tar);
  assert.ok(entries.some((e) => e.name === 'guvenli.txt'), 'güvenli girdi yok');
  assert.ok(
    !entries.some((e) => e.name.includes('..')),
    '../ girdisi filtrelenmedi'
  );
  fs.rmSync(d, { recursive: true, force: true });
});

test('tar.gz: içerik okunur', async () => {
  const d = tmpdir();
  fs.writeFileSync(path.join(d, 'x.txt'), 'tgz icerik ' + MARKER);
  const tgz = path.join(d, 'a.tgz');
  execFileSync('tar', ['-czf', tgz, '-C', d, 'x.txt']);

  const entries = await archive.listEntries(tgz);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].name, 'x.txt');

  let content = '';
  await archive.scanEntries(tgz, async (entry, getStream) => {
    content = (await readEntry(getStream)).toString('utf8');
  });
  assert.ok(content.includes(MARKER), JSON.stringify(content));
  fs.rmSync(d, { recursive: true, force: true });
});

test('gz: tek dosya akışı', async () => {
  const d = tmpdir();
  fs.writeFileSync(path.join(d, 'belge.txt'), 'gz icerik ' + MARKER);
  execFileSync('gzip', ['-f', path.join(d, 'belge.txt')]);

  const gz = path.join(d, 'belge.txt.gz');
  const entries = await archive.listEntries(gz);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].name, 'belge.txt');

  let content = '';
  await archive.scanEntries(gz, async (entry, getStream) => {
    content = (await readEntry(getStream)).toString('utf8');
  });
  assert.ok(content.includes(MARKER));
  fs.rmSync(d, { recursive: true, force: true });
});

test('maxEntries sınırı: truncation', async () => {
  const d = tmpdir();
  const files = [];
  for (let i = 0; i < 4; i++) {
    const f = path.join(d, `f${i}.txt`);
    fs.writeFileSync(f, 'veri ' + i);
    files.push(f);
  }
  const zip = path.join(d, 'cok.zip');
  execFileSync('zip', ['-q', '-j', zip, ...files]);

  let calls = 0;
  const res = await archive.scanEntries(
    zip,
    () => {
      calls++;
    },
    { maxEntries: 1 }
  );
  assert.equal(calls, 1, 'sınır aşıldı');
  assert.ok(res.truncated, 'truncated işareti yok');
  fs.rmSync(d, { recursive: true, force: true });
});

test('şifreli zip: asılı kalmaz ve içerik sızmaz', async () => {
  const d = tmpdir();
  const inner = path.join(d, 'gizli.txt');
  fs.writeFileSync(inner, 'hem ' + MARKER);
  const zip = path.join(d, 'sifreli.zip');
  execFileSync('zip', ['-q', '-j', '-P', 's3cret', zip, inner]);

  let leaked = false;
  const started = Date.now();
  await archive.scanEntries(zip, async (entry, getStream) => {
    const buf = await readEntry(getStream, 256 * 1024);
    if (buf.toString('utf8').includes(MARKER)) leaked = true;
  });
  const elapsed = Date.now() - started;

  assert.ok(!leaked, 'şifreli içerik okundu!');
  assert.ok(elapsed < 12000, `çok uzun sürdü: ${elapsed}ms`);
  fs.rmSync(d, { recursive: true, force: true });
});

test('bozuk arşiv hata fırlatmaz', async () => {
  const d = tmpdir();
  const bad = path.join(d, 'bozuk.zip');
  fs.writeFileSync(bad, 'bu bir zip degil');
  const entries = await archive.listEntries(bad);
  assert.deepEqual(entries, []);
  const res = await archive.scanEntries(bad, () => {});
  assert.equal(res.scanned, 0);
  assert.equal(archive.isArchive('dosya.txt'), false);
  fs.rmSync(d, { recursive: true, force: true });
});

test('özel girdi adları ("-x", "[x]", "*") atlanmadan okunur', async () => {
  const d = tmpdir();
  const names = ['-gizli.txt', '[x].exe', 'a*b.txt'];
  for (const n of names) fs.writeFileSync(path.join(d, n), 'icerik ' + MARKER);
  fs.writeFileSync(path.join(d, 'aXb.txt'), 'zararsiz');
  const zip = path.join(d, 'ozel.zip');
  execFileSync('zip', ['-q', zip, '--', ...names, 'aXb.txt'], { cwd: d });
  const tar = path.join(d, 'ozel.tar');
  execFileSync('tar', ['-cf', tar, '--', ...names], { cwd: d });

  for (const arc of [zip, tar]) {
    const hits = {};
    const res = await archive.scanEntries(arc, async (entry, getStream) => {
      hits[entry.name] = (await readEntry(getStream)).toString('utf8');
    });
    for (const n of names) {
      assert.equal(hits[n], 'icerik ' + MARKER, `${path.basename(arc)}: ${n} okunamadı`);
    }
    assert.equal(res.skipped, 0, JSON.stringify(res));
    // "a*b.txt" kalıp olarak yorumlanıp "aXb.txt" ile birleşmemeli
    if (arc === zip) assert.equal(hits['aXb.txt'], 'zararsiz');
  }
  fs.rmSync(d, { recursive: true, force: true });
});

test('tar: boyutu bilinmeyen girdilerde toplam bayt bütçesi okunan baytla uygulanır', async () => {
  const d = tmpdir();
  const names = [];
  for (let i = 0; i < 5; i++) {
    const n = `b${i}.bin`;
    fs.writeFileSync(path.join(d, n), Buffer.alloc(64 * 1024, 65 + i));
    names.push(n);
  }
  const tar = path.join(d, 'butce.tar');
  execFileSync('tar', ['-cf', tar, ...names], { cwd: d });

  let calls = 0;
  const res = await archive.scanEntries(
    tar,
    async (entry, getStream) => {
      calls++;
      return (await readEntry(getStream)).length;
    },
    { maxTotalBytes: 100 * 1024 }
  );
  assert.equal(calls, 2, `bütçe aşıldı: ${calls} girdi okundu`);
  assert.ok(res.truncated, JSON.stringify(res));
  assert.equal(res.totalBytes, 128 * 1024);
  fs.rmSync(d, { recursive: true, force: true });
});
