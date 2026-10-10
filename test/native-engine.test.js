// C++ motoru ↔ JS referans motoru karşılaştırma testleri
// node --test test/native-engine.test.js
//
// Aynı kural metni iki derleyiciden de geçirilir; rastgele üretilmiş binlerce
// kural × tampon üzerinde iki eşleştiricinin aynı kararı verdiği doğrulanır.
// AEGIS_ENGINE=native ile çalıştırıldığında (CI) C++ motoru zorunludur.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const native = require('../src/native-engine');
const signatures = require('../src/signatures');

const skip = native.available ? false : 'C++ motoru derlenmemiş (npm run build:native)';

/* ---------------- deterministik rastgelelik ---------------- */

function rng(seed) {
  let x = seed >>> 0 || 1;
  return () => {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    return x / 0x100000000;
  };
}

/* ---------------- rastgele kural üretici ---------------- */

const ALPHABET = ['ab', 'AB', 'aB', 'x', 'MZ', 'tok', 'Tok', 'é', 'ü', '1', '_', ' '];

function gen(seed) {
  const r = rng(seed);
  const pick = (arr) => arr[Math.floor(r() * arr.length)];
  const int = (lo, hi) => lo + Math.floor(r() * (hi - lo + 1));
  const hexByte = () => pick(['41', '42', '61', '62', '4D', '5A', '00', 'FF', '20']);

  function hexAtom(depth) {
    const k = r();
    if (k < 0.45) return hexByte();
    if (k < 0.55) return '??';
    if (k < 0.62) return pick(['4?', '6?', '?1', '?2']);
    if (k < 0.68) return '~' + hexByte();
    if (k < 0.8) {
      const lo = int(0, 3);
      return pick([`[${lo}]`, `[${lo}-${lo + int(0, 3)}]`, `[${lo}-]`, '[-]']);
    }
    if (depth < 2) {
      const n = int(2, 3);
      const alts = [];
      for (let i = 0; i < n; i += 1) alts.push(hexSeq(depth + 1, int(1, 3)));
      return `( ${alts.join(' | ')} )`;
    }
    return hexByte();
  }
  function hexSeq(depth, n) {
    const out = [hexByte()];
    for (let i = 1; i < n; i += 1) out.push(hexAtom(depth));
    return out.join(' ');
  }

  const strings = [];
  const count = int(1, 4);
  for (let i = 0; i < count; i += 1) {
    const id = pick(['a', 'b', 'ab', 'x']) + i;
    if (r() < 0.55) {
      let text = '';
      const len = int(1, 3);
      for (let j = 0; j < len; j += 1) text += pick(ALPHABET);
      const mods = [];
      if (r() < 0.35) mods.push('nocase');
      if (r() < 0.2) mods.push('wide');
      if (r() < 0.15) mods.push('ascii');
      if (r() < 0.25) mods.push('fullword');
      if (r() < 0.05) mods.push('xor(1-2)');
      strings.push({ id, decl: `$${id} = "${text}" ${mods.join(' ')}` });
    } else {
      strings.push({ id, decl: `$${id} = { ${hexSeq(0, int(1, 5))} }` });
    }
  }

  function num(depth) {
    const k = r();
    if (depth > 2 || k < 0.25) return String(pick([0, 1, 2, 3, 4, 7, 16, 65, 0x5a4d, -1]));
    if (k < 0.35) return 'filesize';
    if (k < 0.5) return '#' + pick(strings).id;
    if (k < 0.62) return `${pick(['uint8', 'uint16', 'uint32', 'int8', 'int16be', 'uint32be'])}(${num(depth + 1)})`;
    if (k < 0.7) return pick(['-', '~']) + num(depth + 1);
    if (k < 0.72) return pick(['1KB', '0x10', '2MB']);
    return `(${num(depth + 1)} ${pick(['+', '-', '*', '\\', '%', '&', '|', '^', '<<', '>>'])} ${num(depth + 1)})`;
  }
  function cond(depth) {
    const k = r();
    if (depth > 2 || k < 0.25) return '$' + pick(strings).id;
    if (k < 0.33) return `$${pick(strings).id} at ${num(depth + 1)}`;
    if (k < 0.48) return `${num(depth + 1)} ${pick(['==', '!=', '<', '<=', '>', '>='])} ${num(depth + 1)}`;
    if (k < 0.58) {
      const q = pick(['any', 'all', 'none', '1', '2', '0']);
      const set = r() < 0.5 ? 'them' : `(${strings.map((s) => '$' + s.id).slice(0, int(1, strings.length)).join(', ')})`;
      return `${q} of ${set}`;
    }
    if (k < 0.62) return `any of ($${strings[0].id[0]}*)`;
    if (k < 0.7) return 'not ' + cond(depth + 1);
    if (k < 0.74) return pick(['true', 'false']);
    if (k < 0.77) return num(depth + 1); // sayı da bir koşul olabilir
    return `(${cond(depth + 1)} ${pick(['and', 'or'])} ${cond(depth + 1)})`;
  }

  return `rule R${seed} { strings: ${strings.map((s) => s.decl).join(' ')} condition: ${cond(0)} }`;
}

function genBuffer(seed) {
  const r = rng(seed * 7919 + 13);
  const parts = [];
  const n = 1 + Math.floor(r() * 12);
  for (let i = 0; i < n; i += 1) {
    const k = r();
    if (k < 0.5) parts.push(Buffer.from(ALPHABET[Math.floor(r() * ALPHABET.length)], k < 0.42 ? 'utf8' : 'utf16le'));
    else if (k < 0.8) parts.push(Buffer.from([[0x41, 0x42, 0x61, 0x62, 0x4d, 0x5a, 0x00, 0xff, 0x20][Math.floor(r() * 9)]]));
    else parts.push(crypto.randomBytes(Math.floor(r() * 4)));
  }
  return Buffer.concat(parts);
}

/* ---------------- testler ---------------- */

test('motor seçimi: CI native modunda C++ motoru yüklü', { skip: process.env.AEGIS_ENGINE !== 'native' }, () => {
  const info = signatures.engineInfo();
  assert.equal(info.engine, 'native');
  assert.equal(info.language, 'C++');
  assert.match(info.version, /^\d+\.\d+\.\d+$/);
});

test('SHA-256: C++ uygulaması Node crypto ile aynı', { skip }, async () => {
  const b = native.binding;
  for (const len of [0, 1, 55, 56, 63, 64, 65, 1000, 1024 * 1024 + 7]) {
    const buf = crypto.randomBytes(len);
    assert.equal(b.sha256(buf), crypto.createHash('sha256').update(buf).digest('hex'), `uzunluk ${len}`);
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-native-'));
  const file = path.join(dir, 'f.bin');
  const data = crypto.randomBytes(3 * 1024 * 1024 + 11);
  fs.writeFileSync(file, data);
  const want = crypto.createHash('sha256').update(data).digest('hex');
  assert.equal(b.sha256FileSync(file), want);
  assert.equal(await b.sha256File(file), want);
  await assert.rejects(b.sha256File(path.join(dir, 'yok')), (err) => err.code === 'ENOENT');
  assert.throws(() => b.sha256FileSync(path.join(dir, 'yok')), (err) => err.code === 'ENOENT');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('derleyici: paket kuralları iki motorda aynı', { skip }, () => {
  const text = fs.readFileSync(path.join(__dirname, '..', 'signatures', 'rules.yar'), 'utf8');
  const js = signatures.parseYara(text);
  const set = new native.binding.RuleSet(text);
  assert.deepEqual(set.names(), js.map((r) => r.name));
  assert.deepEqual(set.skipped().map((s) => s.rule), js.skipped.map((s) => s.rule));
});

test('derleyici: desteklenmeyen ve bozuk kurallar iki motorda da atlanır', { skip }, () => {
  const text = `
import "pe"
rule Ok1 { strings: $a = "x" condition: $a }
rule Mod { condition: pe.is_pe }
rule Rx { strings: $r = /abc/ condition: $r }
rule ForLoop { strings: $a = "a" condition: for any i in (1..2) : ( $a ) }
rule NoCond { strings: $a = "a" }
rule Empty { strings: $a = "" condition: $a }
rule Undecl { strings: $a = "a" condition: $b }
rule Dup { strings: $a = "a" $a = "b" condition: $a }
rule BadHex { strings: $a = { 4G } condition: $a }
rule BadJump { strings: $a = { 41 [4-2] 42 } condition: $a }
rule Tilde { strings: $a = { ~?1 } condition: $a }
rule Ok2 : tag1 tag2 { meta: author = "x" strings: $a = { 41 ( 42 | 43 ) } condition: #a == 1 }
rule Unterminated { strings: $a = "a" condition: $a
rule Ok3 { condition: filesize > 0 }
`;
  const js = signatures.parseYara(text);
  const set = new native.binding.RuleSet(text);
  assert.deepEqual(set.names(), js.map((r) => r.name));
  assert.deepEqual(set.names(), ['Ok1', 'Ok2', 'Ok3']);
  assert.deepEqual(set.skipped().map((s) => s.rule), js.skipped.map((s) => s.rule));
});

test('fark testi: 4000 rastgele kural × 12 tampon, iki motor aynı kararı verir', { skip }, () => {
  let compared = 0;
  let matched = 0;
  const seeds = Number(process.env.AEGIS_FUZZ_SEEDS) || 4000;
  for (let seed = 1; seed <= seeds; seed += 1) {
    const text = gen(seed);
    const rules = signatures.parseYara(text);
    const set = new native.binding.RuleSet(text);
    assert.deepEqual(set.names(), rules.map((r) => r.name), `derleme farkı: ${text}`);
    if (rules.length === 0) continue;
    for (let b = 0; b < 12; b += 1) {
      const buf = genBuffer(seed * 100 + b);
      if (buf.length === 0) continue;
      const head = b % 3 === 0 ? Math.floor(buf.length / 2) : buf.length;
      const opts = { filesize: buf.length + (b % 4 === 0 ? 5000 : 0), headLength: head };
      const want = signatures.matchRulesJs(buf, rules, opts);
      const got = set.match(buf, opts.filesize, opts.headLength);
      assert.equal(got >= 0, want !== null, `eşleşme farkı\nkural: ${text}\ntampon: ${buf.toString('hex')}\nopts: ${JSON.stringify(opts)}`);
      compared += 1;
      if (want) matched += 1;
    }
  }
  // Üretici anlamlı olmalı: kararların hem eşleşen hem eşleşmeyen tarafı dolu
  assert.ok(compared > 20000, `yalnız ${compared} karşılaştırma`);
  assert.ok(matched > compared * 0.1 && matched < compared * 0.9, `eşleşme oranı dengesiz: ${matched}/${compared}`);
});

test('checkBuffer/checkFile C++ motorundan geçer ve aynı sonucu verir', { skip }, () => {
  const text = fs.readFileSync(path.join(__dirname, '..', 'signatures', 'rules.yar'), 'utf8');
  const rules = signatures.parseYara(text);
  const db = { sha256: new Map(), rules };
  const before = signatures.engineInfo().stats.nativeMatches;
  const hit = signatures.checkBuffer(Buffer.from('..AEGIS-TEST-MARKER-V1..'), db);
  assert.deepEqual(hit, signatures.matchRulesJs(Buffer.from('..AEGIS-TEST-MARKER-V1..'), rules));
  assert.ok(signatures.engineInfo().stats.nativeMatches > before, 'eşleştirme C++ motorundan geçmedi');

  // Elle kurulmuş (kaynaksız) kural listesi JS motoruna düşer, sonuç bozulmaz
  const handmade = rules.map((r) => Object.assign({}, r));
  assert.deepEqual(signatures.checkBuffer(Buffer.from('AEGIS-TEST-MARKER-V1'), { sha256: new Map(), rules: handmade }), hit);
});

test('büyük dosya penceresi: baş + kuyruk, ofset denetimleri yalnız başta', { skip }, () => {
  const text = 'rule Tail { strings: $t = "tail-marker-xyz" condition: $t } rule AtHead { strings: $m = "MZ" condition: $m at 0 and uint16(0) == 0x5A4D }';
  const rules = signatures.parseYara(text);
  const set = new native.binding.RuleSet(text);
  const buf = Buffer.concat([Buffer.from('MZ'), Buffer.alloc(100), Buffer.from('tail-marker-xyz')]);
  for (const head of [0, 1, 2, 50, buf.length]) {
    const want = signatures.matchRulesJs(buf, rules, { filesize: 10 * 1024 * 1024, headLength: head });
    const got = set.match(buf, 10 * 1024 * 1024, head);
    assert.equal(got >= 0 ? rules[got].name : null, want ? want.name : null, `headLength=${head}`);
  }
});

test('fark testi: rastgele belirteç çorbası iki derleyicide aynı ayrışır', { skip }, () => {
  const FRAGS = [
    'rule', 'R', 'Q', ':', 'tag', '{', '}', 'strings', 'condition', 'meta', '=', '$a', '$b', '$', '#a', '*',
    '"txt"', '"un', '{ 41 42 }', '{ 4? [1-2] ( 43 | 44 ) }', '{ 4G }', 'nocase', 'wide', 'xor', '(', ')', ',',
    'and', 'or', 'not', 'any', 'all', 'none', 'of', 'them', 'at', 'in', 'filesize', 'uint16', '0x5A4D', '12',
    '3KB', '==', '!=', '<', '>', '<=', '<<', '>>', '+', '-', '\\', '%', '&', '|', '^', '~', 'true', 'false',
    '// yorum\n', '/* blok */', '\n', 'ü', 'pe.is_pe', 'import "pe"', '/re/', '"\\""'
  ];
  for (let seed = 1; seed <= 3000; seed += 1) {
    const r = rng(seed * 31 + 7);
    const parts = [];
    const n = 5 + Math.floor(r() * 60);
    for (let i = 0; i < n; i += 1) parts.push(FRAGS[Math.floor(r() * FRAGS.length)]);
    const text = parts.join(r() < 0.5 ? ' ' : '');
    const js = signatures.parseYara(text);
    const set = new native.binding.RuleSet(text);
    assert.deepEqual(set.names(), js.map((x) => x.name), `ayrıştırma farkı: ${JSON.stringify(text)}`);
    assert.deepEqual(set.skipped().map((s) => s.rule), js.skipped.map((s) => s.rule), `atlama farkı: ${JSON.stringify(text)}`);
  }
});
