// IPC girdi doğrulaması — node --test test/validate.test.js (electron gerekmez)
const { test } = require('node:test');
const assert = require('node:assert');
const { sanitizeSettingsPatch, sanitizeRules } = require('../src/validate');

test('ayar yaması: bilinmeyen anahtar ve yanlış tip atılır', () => {
  const out = sanitizeSettingsPatch({
    autoQuarantine: 'evet',
    heuristics: false,
    __proto__x: 1,
    language: 'de',
    exclusions: 'yol',
    dbUrl: ' https://x/db.json '
  });
  assert.deepEqual(out, { heuristics: false, dbUrl: 'https://x/db.json' });
  assert.deepEqual(sanitizeSettingsPatch(null), {});
  assert.deepEqual(sanitizeSettingsPatch([1]), {});
});

test('ayar yaması: tarama aralığı 1-168 saate sıkıştırılır', () => {
  assert.equal(sanitizeSettingsPatch({ scanIntervalHours: 0 }).scanIntervalHours, 1);
  assert.equal(sanitizeSettingsPatch({ scanIntervalHours: 1e9 }).scanIntervalHours, 168);
  assert.equal(sanitizeSettingsPatch({ scanIntervalHours: '12' }).scanIntervalHours, 12);
  assert.equal('scanIntervalHours' in sanitizeSettingsPatch({ scanIntervalHours: 'x' }), false);
});

test('ayar yaması: dışlamalar mutlak yol dizisi olmalı', () => {
  const out = sanitizeSettingsPatch({ exclusions: ['/a', 'goreli', 5, '/a', '/b\0c', '/c'] });
  assert.deepEqual(out.exclusions, ['/a', '/c']);
});

test('firewall kuralları: geçersizler atılır, alanlar normalize edilir', () => {
  const out = sanitizeRules([
    { id: 'r1', type: 'block', host: 'example.com', port: 443, note: 'ok' },
    { id: 'r2', type: 'drop', host: 'x.com' },
    { id: 'r3', type: 'allow', host: 'a.com', port: 70000 },
    { id: 'r4', type: 'block', host: '<img src=x onerror=alert(1)>' },
    { id: '"><script>', type: 'allow', host: null, port: '' },
    null
  ]);
  assert.equal(out.length, 2, JSON.stringify(out));
  assert.deepEqual(out[0], { id: 'r1', type: 'block', proto: 'tcp', host: 'example.com', port: 443, note: 'ok' });
  assert.match(out[1].id, /^[A-Za-z0-9_-]+$/);
  assert.equal(out[1].port, null);
  assert.equal(sanitizeRules('degil'), null);
});
