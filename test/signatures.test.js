'use strict';

// Signature engine tests — plain Node, no Electron required:
//   node --test test/signatures.test.js
//
// NOTE: the real EICAR test string is intentionally absent from every source
// file in this repo (anti-virus products delete files that embed it).
// Tests use the fake marker AEGIS-TEST-MARKER-V1 instead.

const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const signatures = require('../src/signatures');

const REPO_SIG_DIR = path.join(__dirname, '..', 'signatures');
const MARKER = 'AEGIS-TEST-MARKER-V1';

const MB = 1024 * 1024;
const tmpDirs = [];

after(() => {
  for (const dir of tmpDirs) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // best effort cleanup
    }
  }
});

function tmpDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-sig-'));
  tmpDirs.push(dir);
  return dir;
}

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function writeDb(dir, sha256Map, version) {
  const db = { version: version || 'test.1', updated: 0, sha256: sha256Map || {} };
  fs.writeFileSync(path.join(dir, 'db.json'), JSON.stringify(db));
}

// Builds a throwaway signatures directory and loads it.
function yaraDb(rulesText, sha256Map) {
  const dir = tmpDir();
  fs.writeFileSync(path.join(dir, 'rules.yar'), rulesText);
  writeDb(dir, sha256Map);
  return signatures.load(dir);
}

function ruleNames(db) {
  return db.rules.map((r) => r.name);
}

/* ------------------------------------------------------------------ *
 * load()
 * ------------------------------------------------------------------ */

test('load: ships the sample signature database', () => {
  const db = signatures.load(REPO_SIG_DIR);

  assert.equal(db.version, '2026.10.1');
  assert.ok(db.sha256 instanceof Map);
  assert.ok(db.sha256.size >= 2, 'db.json must contain at least 2 sample hashes');
  assert.ok(db.rules.length >= 4, 'rules.yar must contain sample rules');
  assert.deepEqual(ruleNames(db).slice(0, 1), ['Ad_Ortasi']);
  assert.ok(db.source.dbFile && fs.existsSync(db.source.dbFile));
  assert.ok(db.source.rulesFile && fs.existsSync(db.source.rulesFile));
  assert.equal(
    db.skipped.filter((s) => s.file === 'rules.yar').length,
    0,
    'shipped rules.yar must parse cleanly'
  );
});

test('load: defaults to the repository signatures directory', () => {
  const db = signatures.load();
  assert.equal(db.version, '2026.10.1');
  assert.ok(db.rules.length >= 4);
});

test('load: missing files are tolerated', () => {
  const db = signatures.load(tmpDir());
  assert.equal(db.version, '0');
  assert.equal(db.sha256.size, 0);
  assert.deepEqual(ruleNames(db), []);
  assert.equal(db.source.dbFile, null);
  assert.equal(db.source.rulesFile, null);
  assert.deepEqual(db.skipped, []);
});

test('load: malformed db.json is tolerated and recorded', () => {
  const dir = tmpDir();
  fs.writeFileSync(path.join(dir, 'db.json'), '{ this is not json');
  fs.writeFileSync(path.join(dir, 'rules.yar'), 'rule R { strings: $a = "x" condition: $a }');
  const db = signatures.load(dir);

  assert.equal(db.sha256.size, 0);
  assert.deepEqual(ruleNames(db), ['R']);
  assert.equal(db.skipped.length, 1);
  assert.equal(db.skipped[0].file, 'db.json');
});

/* ------------------------------------------------------------------ *
 * SHA-256 matching
 * ------------------------------------------------------------------ */

test('sha256: buffer and file matches', async () => {
  const payload = Buffer.from('AEGIS-DEMO-PAYLOAD-V1\n');
  const dir = tmpDir();
  writeDb(dir, { [sha256(payload)]: 'Test.Payload' });
  fs.writeFileSync(
    path.join(dir, 'rules.yar'),
    'rule Never_Hits { strings: $a = "no-such-token" condition: $a }'
  );
  const db = signatures.load(dir);

  assert.deepEqual(signatures.checkBuffer(payload, db), { name: 'Test.Payload', kind: 'sha256' });
  assert.equal(signatures.checkBuffer(Buffer.from('clean content'), db), null);

  const file = path.join(dir, 'payload.bin');
  fs.writeFileSync(file, payload);
  const hit = signatures.checkFile(file, db);
  assert.deepEqual(hit, { name: 'Test.Payload', kind: 'sha256' });
  // The synchronous result may simply be used, or awaited — both work.
  assert.deepEqual(await signatures.checkFile(file, db), hit);
});

test('sha256: addLocalSignature registers test signatures', () => {
  const db = { version: '0', sha256: new Map(), rules: [] };
  const payload = Buffer.from('local-only-payload');

  signatures.addLocalSignature(db, sha256(payload).toUpperCase(), 'Local.Test');
  assert.deepEqual(signatures.checkBuffer(payload, db), { name: 'Local.Test', kind: 'sha256' });
  assert.equal(signatures.checkBuffer(Buffer.from('unrelated'), db), null);
  assert.equal(db.sha256.size, 1);
});

test('sha256: takes precedence over a yara match', () => {
  const content = Buffer.from(`clean prefix ${MARKER}`);
  const db = yaraDb(`rule Pre {\n strings:\n  $m = "${MARKER}"\n condition:\n  $m\n}`, {
    [sha256(content)]: 'Pre.Sha'
  });
  const file = path.join(tmpDir(), 'both.bin');
  fs.writeFileSync(file, content);

  assert.deepEqual(signatures.checkFile(file, db), { name: 'Pre.Sha', kind: 'sha256' });
  assert.deepEqual(signatures.checkBuffer(content, db), { name: 'Pre.Sha', kind: 'sha256' });
});

test('checkFile: missing file or directory returns null', () => {
  const db = yaraDb('rule R { strings: $a = "abc" condition: $a }');
  assert.equal(signatures.checkFile(path.join(tmpDir(), 'nope.bin'), db), null);
  assert.equal(signatures.checkFile(tmpDir(), db), null);
  assert.equal(signatures.checkBuffer(Buffer.alloc(0), db), null);
});

/* ------------------------------------------------------------------ *
 * YARA: strings
 * ------------------------------------------------------------------ */

test('yara: text string, case sensitive', () => {
  const db = yaraDb('rule T { strings: $a = "zararli-ornek-metni" condition: $a }');
  assert.deepEqual(
    signatures.checkBuffer(Buffer.from('header zararli-ornek-metni footer'), db),
    { name: 'T', kind: 'yara' }
  );
  assert.equal(signatures.checkBuffer(Buffer.from('ZARARLI-ORNEK-METNI'), db), null);
});

test('yara: nocase matches any casing', () => {
  const db = yaraDb(`rule N { strings: $a = "${MARKER}" nocase condition: $a }`);
  assert.deepEqual(signatures.checkBuffer(Buffer.from(`xx ${MARKER} yy`), db), {
    name: 'N',
    kind: 'yara'
  });
  assert.deepEqual(
    signatures.checkBuffer(Buffer.from(`xx ${MARKER.toLowerCase()} yy`), db),
    { name: 'N', kind: 'yara' }
  );
  assert.equal(signatures.checkBuffer(Buffer.from('nothing here'), db), null);
});

test('yara: hex string with wildcards', () => {
  const db = yaraDb('rule H { strings: $b = { 41 45 47 49 53 ?? 2D } condition: $b }');

  const hit = Buffer.from([0x41, 0x45, 0x47, 0x49, 0x53, 0x99, 0x2d]);
  const nearMiss = Buffer.from([0x41, 0x45, 0x47, 0x49, 0x53, 0x99, 0x2e]);
  assert.deepEqual(signatures.checkBuffer(hit, db), { name: 'H', kind: 'yara' });
  assert.equal(signatures.checkBuffer(nearMiss, db), null);
});

test('yara: nibble wildcards and exact hex', () => {
  const db = yaraDb(
    'rule Nib { strings: $n = { 4D 5A 9? 00 } $e = { 7F 45 4C 46 } condition: $n or $e }'
  );
  assert.deepEqual(signatures.checkBuffer(Buffer.from([0x4d, 0x5a, 0x90, 0x00]), db), {
    name: 'Nib',
    kind: 'yara'
  });
  assert.deepEqual(signatures.checkBuffer(Buffer.from([0x4d, 0x5a, 0x9f, 0x00]), db), {
    name: 'Nib',
    kind: 'yara'
  });
  assert.equal(signatures.checkBuffer(Buffer.from([0x4d, 0x5a, 0x80, 0x00]), db), null);
  assert.deepEqual(signatures.checkBuffer(Buffer.from([0x7f, 0x45, 0x4c, 0x46]), db), {
    name: 'Nib',
    kind: 'yara'
  });
});

/* ------------------------------------------------------------------ *
 * YARA: conditions
 * ------------------------------------------------------------------ */

test('yara: condition any of them / all of them', () => {
  const db = yaraDb(`
rule Any_Thing { strings: $a = "any-aa" $b = "any-bb" condition: any of them }
rule All_Things { strings: $c = "all-cc" $d = "all-dd" condition: all of them }
`);

  assert.deepEqual(signatures.checkBuffer(Buffer.from('has any-aa inside'), db), {
    name: 'Any_Thing',
    kind: 'yara'
  });
  assert.equal(signatures.checkBuffer(Buffer.from('has all-cc only'), db), null);
  assert.deepEqual(signatures.checkBuffer(Buffer.from('all-cc and all-dd'), db), {
    name: 'All_Things',
    kind: 'yara'
  });
});

test('yara: condition $a and $b', () => {
  const db = yaraDb('rule Both { strings: $a = "and-alpha" $b = "and-beta" condition: $a and $b }');

  assert.deepEqual(signatures.checkBuffer(Buffer.from('and-alpha and-beta'), db), {
    name: 'Both',
    kind: 'yara'
  });
  assert.equal(signatures.checkBuffer(Buffer.from('and-alpha only'), db), null);
  assert.equal(signatures.checkBuffer(Buffer.from('and-beta only'), db), null);
});

test('yara: condition $a or $b, not $c, parentheses', () => {
  const db = yaraDb(`
rule Mix {
  strings:
    $a = "mix-alpha"
    $b = "mix-beta"
    $clean = "mix-clean"
  condition:
    ($a or $b) and not $clean
}
`);

  assert.deepEqual(signatures.checkBuffer(Buffer.from('mix-alpha'), db), {
    name: 'Mix',
    kind: 'yara'
  });
  assert.deepEqual(signatures.checkBuffer(Buffer.from('mix-beta'), db), {
    name: 'Mix',
    kind: 'yara'
  });
  assert.equal(signatures.checkBuffer(Buffer.from('mix-alpha mix-clean'), db), null);
  assert.equal(signatures.checkBuffer(Buffer.from('mix-clean'), db), null);
  assert.equal(signatures.checkBuffer(Buffer.from('nothing'), db), null);
});

test('yara: condition #a == N counts occurrences', () => {
  const db = yaraDb('rule Twice { strings: $a = "count-token" condition: #a == 2 }');

  assert.deepEqual(
    signatures.checkBuffer(Buffer.from('count-token x count-token'), db),
    { name: 'Twice', kind: 'yara' }
  );
  assert.equal(signatures.checkBuffer(Buffer.from('count-token'), db), null);
  assert.equal(
    signatures.checkBuffer(Buffer.from('count-token count-token count-token'), db),
    null
  );
});

test('yara: unsupported modifiers and keywords are tolerated', () => {
  const db = yaraDb(`
import "pe"
include "other.yar"

rule Tolerant {
  meta:
    author = "aegis"
    date = 2026-10-01
  strings:
    $a = "wide-ascii-xor-demo" wide ascii fullword nocase
    $b = { AA BB CC DD } xor(1-255)
  condition:
    any of them
}
`);

  assert.deepEqual(ruleNames(db), ['Tolerant']);
  assert.deepEqual(signatures.checkBuffer(Buffer.from('WIDE-ASCII-XOR-DEMO'), db), {
    name: 'Tolerant',
    kind: 'yara'
  });
  assert.deepEqual(
    signatures.checkBuffer(Buffer.from([0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0x02], 'binary'), db),
    { name: 'Tolerant', kind: 'yara' }
  );
  assert.equal(signatures.checkBuffer(Buffer.from('plain text'), db), null);
});

/* ------------------------------------------------------------------ *
 * Broken rules / parser tolerance
 * ------------------------------------------------------------------ */

test('parseYara: broken rules are skipped, never thrown', () => {
  const text = `
rule Good_One { strings: $a = "good-one-token" condition: $a }
rule Broken_NoClose { strings: $a = "oops"
rule Broken_Condition { strings: $a = "x" condition: filesize > 10 }
rule Broken_Undeclared { strings: $a = "x" condition: $a and $b }
rule Broken_NoCondition { strings: $a = "x" }
rule Broken_Hex { strings: $h = { 41 4 } condition: $h }
garbage garbage {{{ "unterminated string
rule Good_Two { strings: $t = { DE AD BE EF } condition: $t }
`;

  const rules = signatures.parseYara(text); // must not throw
  assert.deepEqual(ruleNames({ rules }), ['Good_One', 'Good_Two']);
  assert.ok(rules.skipped.length >= 5, 'broken rules must be recorded');
  for (const entry of rules.skipped) {
    assert.ok(entry.error && entry.error.length > 0);
  }
  assert.deepEqual(ruleNames({ rules: signatures.parseYara('total garbage {') }), []);
  assert.deepEqual(ruleNames({ rules: signatures.parseYara('') }), []);
  assert.deepEqual(ruleNames({ rules: signatures.parseYara(null) }), []);

  // The surviving rules still work.
  assert.deepEqual(signatures.checkBuffer(Buffer.from('good-one-token'), { rules }), {
    name: 'Good_One',
    kind: 'yara'
  });
  assert.deepEqual(signatures.checkBuffer(Buffer.from([0xde, 0xad, 0xbe, 0xef]), { rules }), {
    name: 'Good_Two',
    kind: 'yara'
  });
});

test('load: broken rules.yar is tolerated and recorded', () => {
  const dir = tmpDir();
  writeDb(dir, {});
  fs.writeFileSync(
    path.join(dir, 'rules.yar'),
    'rule Ok { strings: $a = "ok-token" condition: $a }\nrule Bad { condition: wat is this }'
  );
  const db = signatures.load(dir);

  assert.deepEqual(ruleNames(db), ['Ok']);
  assert.equal(db.skipped.length, 1);
  assert.equal(db.skipped[0].file, 'rules.yar');
  assert.equal(db.skipped[0].rule, 'Bad');
});

/* ------------------------------------------------------------------ *
 * Large files: windowing + full-file hashing
 * ------------------------------------------------------------------ */

test('large file: string scan covers head and tail only', () => {
  const db = yaraDb(`rule Mark { strings: $m = "${MARKER}" condition: $m }`);
  const dir = tmpDir();
  const size = 3 * MB;

  const head = Buffer.alloc(size, 0x41);
  head.write(MARKER, 1000, 'utf8');
  const headFile = path.join(dir, 'head.bin');
  fs.writeFileSync(headFile, head);

  const tail = Buffer.alloc(size, 0x41);
  tail.write(MARKER, size - 50, 'utf8');
  const tailFile = path.join(dir, 'tail.bin');
  fs.writeFileSync(tailFile, tail);

  const middle = Buffer.alloc(size, 0x41);
  middle.write(MARKER, 2 * MB + 1000, 'utf8');
  const middleFile = path.join(dir, 'middle.bin');
  fs.writeFileSync(middleFile, middle);

  assert.deepEqual(signatures.checkFile(headFile, db), { name: 'Mark', kind: 'yara' });
  assert.deepEqual(signatures.checkFile(tailFile, db), { name: 'Mark', kind: 'yara' });
  // 2MB + 1000 lies outside both scan windows -> no match (windowing proof).
  assert.equal(signatures.checkFile(middleFile, db), null);
});

test('large file: sha256 still covers the whole file', () => {
  const dir = tmpDir();
  const content = Buffer.alloc(3 * MB, 0x42);
  content.write(MARKER, 2 * MB + 1000, 'utf8'); // outside every string window
  const db = yaraDb(
    `rule Mark { strings: $m = "${MARKER}" condition: $m }`,
    { [sha256(content)]: 'Big.Whole-File' }
  );

  const file = path.join(dir, 'big.bin');
  fs.writeFileSync(file, content);
  assert.deepEqual(signatures.checkFile(file, db), { name: 'Big.Whole-File', kind: 'sha256' });
});

test('oversized file (>1GB): hashing is skipped, string scan still runs', () => {
  const SIZE = 1024 * MB + 4096; // just above the 1GB hash limit
  const markerBuf = Buffer.from(MARKER, 'utf8');
  const offset = SIZE - 100; // inside the 256KB tail window

  // Expected SHA-256 of the sparse (zero-filled + marker) file, computed
  // without touching the disk.
  const zeros = Buffer.alloc(8 * MB);
  const hash = crypto.createHash('sha256');
  let pos = 0;
  while (pos + zeros.length <= offset) {
    hash.update(zeros);
    pos += zeros.length;
  }
  hash.update(zeros.subarray(0, offset - pos));
  const region = Buffer.alloc(SIZE - offset);
  markerBuf.copy(region, 0);
  hash.update(region);
  const expectedHash = hash.digest('hex');

  const dir = tmpDir();
  const db = yaraDb(
    `rule Mark { strings: $m = "${MARKER}" condition: $m }`,
    { [expectedHash]: 'Huge.Should-Not-Hash' }
  );

  // Sparse file: instant to create, reads as zeros.
  const file = path.join(dir, 'huge.bin');
  const fd = fs.openSync(file, 'w');
  try {
    fs.ftruncateSync(fd, SIZE);
    fs.writeSync(fd, markerBuf, 0, markerBuf.length, offset);
  } finally {
    fs.closeSync(fd);
  }
  assert.equal(fs.statSync(file).size, SIZE);

  // If the engine hashed the file it would report the sha256 hit instead,
  // so this assertion proves both: hash skipped AND tail window scanned.
  assert.deepEqual(signatures.checkFile(file, db), { name: 'Mark', kind: 'yara' });
});

/* ------------------------------------------------------------------ *
 * The shipped sample rules actually work end to end
 * ------------------------------------------------------------------ */

test('sample database detects demo payloads', () => {
  const db = signatures.load(REPO_SIG_DIR);

  // sha256 entry from db.json
  const payload = Buffer.from('AEGIS-DEMO-PAYLOAD-V1\n');
  assert.deepEqual(signatures.checkBuffer(payload, db), {
    name: 'Demo.Known-Payload',
    kind: 'sha256'
  });

  // text string rule (Ad_Ortasi)
  assert.deepEqual(signatures.checkBuffer(Buffer.from('xx zararli-ornek-metni yy'), db), {
    name: 'Ad_Ortasi',
    kind: 'yara'
  });

  // hex string rule (Ad_Ortasi $b) with the wildcard byte varied
  const hexHit = Buffer.from([0x41, 0x45, 0x47, 0x49, 0x53, 0x00, 0x2d]);
  assert.deepEqual(signatures.checkBuffer(hexHit, db), { name: 'Ad_Ortasi', kind: 'yara' });

  // dedicated test-marker rule
  assert.deepEqual(signatures.checkBuffer(Buffer.from(`x ${MARKER} y`), db), {
    name: 'Demo_Test_Marker',
    kind: 'yara'
  });

  // clean content matches nothing
  assert.equal(signatures.checkBuffer(Buffer.from('totally clean file'), db), null);
});
