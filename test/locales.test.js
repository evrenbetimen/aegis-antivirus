// Arayüz dilleri: her sözlük İngilizce referansla aynı anahtarlara ve yer
// tutuculara sahip olmalı; HTML ve app.js'te kullanılan her anahtar tanımlı olmalı.
// node --test test/locales.test.js
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const DIR = path.join(__dirname, '..', 'renderer');
const CODES = ['en', 'tr', 'de', 'fr', 'es', 'it', 'pt', 'nl', 'pl', 'ru', 'ja', 'zh'];
for (const c of CODES) require(path.join(DIR, 'locales', c + '.js'));
const L = globalThis.AEGIS_LOCALES;
const I18N = require(path.join(DIR, 'i18n.js'));
const { LANGUAGES } = require('../src/validate');

const placeholders = (s) => (s.match(/\{\w+\}/g) || []).sort().join(',');

test('her dil yüklendi ve ayarlar listesiyle eşleşiyor', () => {
  assert.deepEqual(Object.keys(L).sort(), [...CODES].sort());
  assert.deepEqual(I18N.LANGUAGES.map((l) => l.code).sort(), [...CODES].sort());
  assert.deepEqual(LANGUAGES.filter((l) => l !== 'system').sort(), [...CODES].sort());
  const html = fs.readFileSync(path.join(DIR, 'index.html'), 'utf8');
  for (const c of CODES) assert.ok(html.includes(`src="locales/${c}.js"`), `index.html ${c}.js yüklemiyor`);
});

for (const code of CODES.filter((c) => c !== 'en')) {
  test(`${code}: anahtarlar ve yer tutucular İngilizceyle aynı`, () => {
    const en = L.en;
    const loc = L[code];
    assert.deepEqual(Object.keys(loc).sort(), Object.keys(en).sort());
    for (const k of Object.keys(en)) {
      assert.equal(typeof loc[k], 'string', k);
      assert.ok(loc[k].trim().length > 0, `${code}.${k} boş`);
      assert.equal(placeholders(loc[k]), placeholders(en[k]), `${code}.${k} yer tutucuları farklı`);
    }
  });
}

test("HTML ve app.js'teki anahtarların hepsi tanımlı", () => {
  const html = fs.readFileSync(path.join(DIR, 'index.html'), 'utf8');
  const app = fs.readFileSync(path.join(DIR, 'app.js'), 'utf8');
  const keys = new Set();
  for (const m of html.matchAll(/data-i18n(?:-placeholder|-title)?="([^"]+)"/g)) keys.add(m[1]);
  for (const m of app.matchAll(/\b(?:t|d|setText\([^,]+,)\s*\(?'([a-z][\w]*(?:\.[\w]+)+)'/g)) keys.add(m[1]);
  // Dinamik olarak birleştirilen anahtarlar
  for (const s of ['pass', 'warn', 'fail', 'unknown', 'na']) keys.add('audit.status.' + s);
  for (const id of ['filevault', 'gatekeeper', 'sip', 'firewall', 'updates', 'wifi', 'screenlock']) {
    keys.add('audit.item.' + id);
    keys.add('audit.item.' + id + '.pass');
    keys.add('audit.item.' + id + '.sub');
  }
  for (const r of ['missingProgram', 'noProgram', 'tempLocation', 'hiddenPath', 'scriptInterpreter', 'unreadable']) keys.add('startup.risk.' + r);
  for (const s of ['user', 'agent', 'daemon']) keys.add('startup.scope.' + s);
  for (const s of ['weak', 'fair', 'good', 'strong', 'excellent']) keys.add('id.strength.' + s);
  for (const s of ['system', 'light', 'dark']) keys.add('theme.toggle.' + s);
  for (const p of ['dashboard', 'scan', 'quarantine', 'firewall', 'audit', 'startup', 'identity', 'activity', 'settings']) {
    keys.add('page.' + p);
    keys.add('pagesub.' + p);
  }
  for (const s of ['idle', 'checking', 'none', 'downloading', 'ready', 'error', 'unsupported']) keys.add('upd.' + s);
  for (const s of ['granted', 'denied', 'unknown']) keys.add('fda.' + s);
  for (const lvl of ['warn', 'bad']) ['hero.title.', 'hero.sub.', 'top.status.', 'sidebar.status.'].forEach((p) => keys.add(p + lvl));
  for (const m of app.matchAll(/key: '(issue\.\w+)'/g)) {
    keys.add(m[1]);
    keys.add(m[1] + '.sub');
  }
  const main = fs.readFileSync(path.join(__dirname, '..', 'main.js'), 'utf8');
  for (const m of main.matchAll(/key: '([\w.]+)'/g)) keys.add(m[1]);
  const missing = [...keys].filter((k) => !(k in L.en));
  assert.deepEqual(missing, []);
});

test('çeviri: yedek zinciri, sistem dili ve yer tutucular', () => {
  I18N.setLanguage('de');
  assert.equal(I18N.getLanguage(), 'de');
  assert.equal(I18N.t('nav.settings'), L.de['nav.settings']);
  assert.equal(I18N.t('olmayan.anahtar'), 'olmayan.anahtar');
  assert.equal(I18N.t('center.count', { n: 3 }), L.de['center.count'].replace('{n}', '3'));
  assert.equal(I18N.t('center.count', {}), L.de['center.count'], 'eksik değişken yer tutucuyu bozmamalı');
  assert.equal(I18N.resolve('ja'), 'ja');
  assert.equal(I18N.resolve('klingon'), I18N.resolve('system'));
  I18N.setLanguage('tr');
});
