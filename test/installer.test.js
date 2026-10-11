// macOS yükleyici (.pkg / .dmg) taraması — node --test test/installer.test.js
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { execFileSync } = require('child_process');
const installer = require('../src/installer');
const archive = require('../src/archive');

const MARKER = 'AEGIS-TEST-MARKER-V1'; // EICAR KULLANMA (harici AV siler)
const onMac = process.platform === 'darwin';

function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-inst-'));
}

const { cpioOdc, cpioNewc, makeXar } = require('./pkg-fixtures');

function readAll(getStream) {
  return new Promise((resolve) => {
    const s = getStream();
    const chunks = [];
    s.on('data', (c) => chunks.push(c));
    s.on('end', () => resolve(Buffer.concat(chunks)));
    s.on('error', () => resolve(Buffer.concat(chunks)));
  });
}

async function collect(file, opts) {
  const seen = [];
  const res = await archive.scanEntries(
    file,
    async (entry, getStream) => {
      const buf = await readAll(getStream);
      seen.push({ name: entry.name, text: buf.toString('utf8') });
      return buf.length;
    },
    opts
  );
  return { seen, res };
}

/* --------------------------------- .pkg --------------------------------- */

test('pkg: betikler, yük ve Distribution taranır; betikler yükten önce gelir', async () => {
  const d = tmpdir();
  const pkg = path.join(d, 'kur.pkg');
  fs.writeFileSync(
    pkg,
    makeXar([
      { path: 'Distribution', data: Buffer.from('<installer-gui-script>&amp;</installer-gui-script>'), zlib: true },
      {
        path: 'app.pkg/Payload',
        data: zlib.gzipSync(
          cpioNewc([
            { name: '.', data: '', mode: 0o40755 },
            { name: './Applications/A.app/Contents/MacOS/A', data: 'ikili ' + MARKER },
            { name: './Applications/A.app/link', data: 'A', mode: 0o120755 }
          ])
        )
      },
      { path: 'app.pkg/PackageInfo', data: Buffer.from('<pkg-info/>') },
      { path: 'app.pkg/Bom', data: Buffer.from('BOMStore') },
      {
        path: 'app.pkg/Scripts',
        data: zlib.gzipSync(cpioOdc([{ name: './postinstall', data: '#!/bin/sh\ncurl x | sh # ' + MARKER }]))
      }
    ])
  );
  assert.ok(archive.isArchive(pkg));
  const { seen, res } = await collect(pkg);
  const names = seen.map((s) => s.name);
  assert.deepEqual(names, [
    'Distribution',
    'app.pkg/PackageInfo',
    'app.pkg/Scripts/postinstall',
    'app.pkg/Payload/Applications/A.app/Contents/MacOS/A'
  ]);
  assert.match(seen[0].text, /installer-gui-script/);
  assert.match(seen[2].text, new RegExp(MARKER));
  assert.equal(seen[3].text, 'ikili ' + MARKER);
  assert.equal(res.scanned, 4);
  assert.equal(res.truncated, false);
});

test('pkg: girdi sınırı aşılınca kesilir', async () => {
  const d = tmpdir();
  const pkg = path.join(d, 'cok.pkg');
  const many = Array.from({ length: 20 }, (_, i) => ({ name: `./f${i}`, data: 'x' + i }));
  fs.writeFileSync(pkg, makeXar([{ path: 'Payload', data: zlib.gzipSync(cpioOdc(many)) }]));
  const { seen, res } = await collect(pkg, { maxEntries: 5 });
  assert.equal(seen.length, 5);
  assert.equal(res.truncated, true);
});

test('pkg: bozuk dosya ve xar olmayan içerik hata fırlatmaz', async () => {
  const d = tmpdir();
  const bad = path.join(d, 'bozuk.pkg');
  fs.writeFileSync(bad, 'xar!' + 'Z'.repeat(40));
  assert.deepEqual((await collect(bad)).seen, []);
  const notXar = path.join(d, 'metin.pkg');
  fs.writeFileSync(notXar, 'merhaba');
  assert.deepEqual((await collect(notXar)).seen, []);
  // Kesik cpio: eldeki kısım taranır, sonra durur
  const cut = path.join(d, 'kesik.pkg');
  const cp = cpioOdc([{ name: './a', data: 'tamam' }, { name: './b', data: 'y'.repeat(1000) }]);
  fs.writeFileSync(cut, makeXar([{ path: 'Scripts', data: zlib.gzipSync(cp.subarray(0, cp.length - 900)) }]));
  const r = await collect(cut);
  assert.deepEqual(r.seen.map((s) => s.name), ['Scripts/a', 'Scripts/b']);
  assert.equal(r.seen[0].text, 'tamam');
  assert.ok(r.seen[1].text.length < 1000);
});

test('pkg: pbzx yükü macOS dışında desteklenmiyor olarak sayılır', { skip: onMac && 'macOS pkgutil kullanır' }, async () => {
  const d = tmpdir();
  const pkg = path.join(d, 'apple.pkg');
  fs.writeFileSync(pkg, makeXar([{ path: 'Payload', data: Buffer.from('pbzx\0\0\0\0\0\x10\0\0') }]));
  const { seen, res } = await collect(pkg);
  assert.deepEqual(seen, []);
  assert.equal(res.unsupported, 1);
});

test('xar içindekiler tablosu: iç içe dizinler ve XML varlıkları', () => {
  const files = installer.parseToc(
    '<xar><toc><file id="1"><name>a &amp; b</name><type>directory</type>' +
      '<file id="2"><name>c&#x2F;d</name><type>file</type><data><offset>5</offset><length>3</length>' +
      '<size>9</size><encoding style="application/x-gzip"/></data></file></file></toc></xar>'
  );
  assert.equal(files.length, 2);
  assert.equal(files[1].path, 'a & b/c/d');
  assert.deepEqual(files[1].data, { offset: 5, length: 3, size: 9, encoding: 'application/x-gzip' });
});

test('dmg: macOS dışında desteklenmiyor olarak sayılır', { skip: onMac && 'macOS' }, async () => {
  const d = tmpdir();
  const dmg = path.join(d, 'x.dmg');
  fs.writeFileSync(dmg, 'koly');
  const { seen, res } = await collect(dmg);
  assert.deepEqual(seen, []);
  assert.equal(res.unsupported, 1);
});

/* ------------------------ gerçek macOS araçlarıyla ------------------------ */

test('macOS: pkgbuild ile üretilen gerçek .pkg taranır', { skip: !onMac && 'yalnızca macOS' }, async () => {
  const d = tmpdir();
  const root = path.join(d, 'root/Applications/Demo.app/Contents/MacOS');
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, 'Demo'), 'ikili ' + MARKER);
  const scripts = path.join(d, 'scripts');
  fs.mkdirSync(scripts);
  fs.writeFileSync(path.join(scripts, 'postinstall'), '#!/bin/sh\necho ' + MARKER + '\n', { mode: 0o755 });
  const pkg = path.join(d, 'demo.pkg');
  execFileSync('pkgbuild', [
    '--quiet', '--root', path.join(d, 'root'), '--scripts', scripts,
    '--identifier', 'com.aegis.test', '--version', '1', pkg
  ]);
  const { seen } = await collect(pkg);
  const names = seen.map((s) => s.name);
  console.log('# pkg girdileri:', JSON.stringify(names));
  const post = seen.find((s) => s.name.endsWith('Scripts/postinstall'));
  const bin = seen.find((s) => s.name.endsWith('Demo.app/Contents/MacOS/Demo'));
  assert.ok(post && post.text.includes(MARKER), 'postinstall taranmadı');
  assert.ok(bin && bin.text.includes(MARKER), 'yükteki ikili taranmadı');
});

test('macOS: hdiutil ile üretilen gerçek .dmg bağlanır, taranır ve ayrılır', { skip: !onMac && 'yalnızca macOS' }, async () => {
  const d = tmpdir();
  const src = path.join(d, 'src/Demo.app/Contents/MacOS');
  fs.mkdirSync(src, { recursive: true });
  fs.writeFileSync(path.join(src, 'Demo'), 'ikili ' + MARKER);
  fs.symlinkSync('/etc/passwd', path.join(d, 'src/link')); // izlenmemeli
  const dmg = path.join(d, 'demo.dmg');
  execFileSync('hdiutil', ['create', '-quiet', '-srcfolder', path.join(d, 'src'), '-format', 'UDZO', '-volname', 'AegisTest', dmg]);
  const { seen, res } = await collect(dmg);
  console.log('# dmg girdileri:', JSON.stringify(seen.map((s) => s.name)), JSON.stringify(res));
  const bin = seen.find((s) => s.name.endsWith('Demo.app/Contents/MacOS/Demo'));
  assert.ok(bin && bin.text.includes(MARKER), 'dmg içindeki ikili taranmadı');
  assert.ok(!seen.some((s) => s.name === 'link'), 'sembolik bağ izlendi');
  const info = execFileSync('hdiutil', ['info'], { encoding: 'utf8' });
  assert.ok(!info.includes(dmg), 'görüntü ayrılmadı');
});
