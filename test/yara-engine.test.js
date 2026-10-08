// Genişletilmiş YARA motoru testleri — node --test test/yara-engine.test.js
// (gerçek kural setlerinde — ör. ReversingLabs — kullanılan yapılar)
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const signatures = require('../src/signatures');

function db(text) {
  const rules = signatures.parseYara(text);
  assert.deepEqual(rules.skipped, [], 'beklenmeyen atlanan kural: ' + JSON.stringify(rules.skipped));
  return { sha256: new Map(), rules };
}
const hit = (d, buf) => (signatures.checkBuffer(Buffer.from(buf), d) || {}).name || null;

// Minimal PE: "MZ", e_lfanew @0x3C → "PE\0\0"
function fakePe(extra = Buffer.alloc(0)) {
  const b = Buffer.alloc(0x100 + extra.length);
  b.write('MZ', 0, 'latin1');
  b.writeUInt32LE(0x80, 0x3c);
  b.write('PE\0\0', 0x80, 'latin1');
  extra.copy(b, 0x100);
  return b;
}

test('hex: atlamalar, alternatifler, yarım bayt ve ~ desenleri', () => {
  const d = db(`rule H { strings: $a = { 41 [2-4] 42 ( 43 | 44 45 ) 4? ~00 } condition: $a }`);
  assert.equal(hit(d, Buffer.from([0x41, 1, 2, 0x42, 0x43, 0x4f, 0x01])), 'H');
  assert.equal(hit(d, Buffer.from([0x41, 1, 2, 3, 4, 0x42, 0x44, 0x45, 0x40, 0x07])), 'H');
  assert.equal(hit(d, Buffer.from([0x41, 1, 0x42, 0x43, 0x4f, 0x01])), null, 'atlama 2 bayttan kısa');
  assert.equal(hit(d, Buffer.from([0x41, 1, 2, 0x42, 0x43, 0x4f, 0x00])), null, '~00 eşleşmemeli');
  assert.equal(hit(d, Buffer.from([0x41, 1, 2, 0x42, 0x43, 0x5f, 0x01])), null, '4? yalnız 0x40-0x4F');
});

test('hex: [n] sabit ve [n-] / [-] sınırsız atlama', () => {
  const d = db(`rule J { strings: $a = { AA [3] BB [2-] CC [-] DD } condition: $a }`);
  assert.equal(hit(d, Buffer.from([0xaa, 0, 0, 0, 0xbb, 1, 2, 3, 0xcc, 0xdd])), 'J');
  assert.equal(hit(d, Buffer.from([0xaa, 0, 0, 0xbb, 1, 2, 0xcc, 0xdd])), null);
});

test('uint16/uint32 ve PE başlık denetimi (iç içe ifade)', () => {
  const d = db(`
rule Pe_Marker {
  strings: $m = "demo-pe-payload"
  condition: uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and $m
}`);
  assert.equal(hit(d, fakePe(Buffer.from('demo-pe-payload'))), 'Pe_Marker');
  assert.equal(hit(d, Buffer.from('xx demo-pe-payload')), null, 'MZ yoksa eşleşmemeli');
  const broken = fakePe(Buffer.from('demo-pe-payload'));
  broken.writeUInt32LE(0x10000, 0x3c); // tampon dışına işaret eder → undefined → false
  assert.equal(hit(d, broken), null);
});

test('filesize, KB/MB ekleri ve aritmetik', () => {
  const d = db(`rule F { strings: $a = "tok" condition: $a and filesize < 1KB and #a * 2 + 1 == 5 }`);
  assert.equal(hit(d, 'tok tok'), 'F');
  assert.equal(hit(d, 'tok tok tok'), null);
  assert.equal(hit(d, 'tok tok' + ' '.repeat(1024)), null);
  const big = db(`rule M { condition: filesize >= 2MB and false or 0x10 & 0x30 == 0x10 }`);
  assert.equal(hit(big, 'x'), 'M');
});

test('N of (set*), none of, any of them', () => {
  const d = db(`
rule Q {
  strings:
    $api_1 = "CreateRemoteThread"
    $api_2 = "VirtualAllocEx"
    $api_3 = "WriteProcessMemory"
    $clean = "trusted-build"
  condition: 2 of ($api_*) and none of ($clean)
}`);
  assert.equal(hit(d, 'VirtualAllocEx .. WriteProcessMemory'), 'Q');
  assert.equal(hit(d, 'VirtualAllocEx only'), null);
  assert.equal(hit(d, 'VirtualAllocEx WriteProcessMemory trusted-build'), null);
});

test('$a at N', () => {
  const d = db(`rule A { strings: $h = { 7F 45 4C 46 } condition: $h at 0 }`);
  assert.equal(hit(d, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 1])), 'A');
  assert.equal(hit(d, Buffer.from([0, 0x7f, 0x45, 0x4c, 0x46])), null);
});

test('wide, ascii wide ve fullword', () => {
  const d = db(`
rule W { strings: $a = "ransom" wide condition: $a }
rule AW { strings: $a = "decryptor" ascii wide nocase condition: $a }
rule FW { strings: $a = "evil" fullword condition: $a }`);
  assert.equal(hit(d, Buffer.from('ransom', 'utf16le')), 'W');
  assert.equal(hit(d, 'ransom'), null, 'yalnız wide → ascii aranmaz');
  assert.equal(hit(d, Buffer.from('DECRYPTOR', 'utf16le')), 'AW');
  assert.equal(hit(d, 'Decryptor'), 'AW');
  assert.equal(hit(d, 'an evil.exe'), 'FW');
  assert.equal(hit(d, 'devilish'), null, 'fullword kelime içinde eşleşmemeli');
});

test('desteklenmeyen yapılar kuralı atlatır (yanlış değerlendirme yok)', () => {
  const rules = signatures.parseYara(`
import "pe"
rule Mod { condition: pe.number_of_sections > 2 }
rule Loop { strings: $a = "x" condition: for any i in (1..#a): (@a[i] < 10) }
rule Re { strings: $r = /abc[0-9]+/ condition: $r }
rule In { strings: $a = "x" condition: $a in (0..100) }
rule Ref { strings: $a = "x" condition: Other_Rule and $a }
rule Ok { strings: $a = "ok-token" condition: $a }`);
  assert.deepEqual(rules.map((r) => r.name), ['Ok']);
  assert.equal(rules.skipped.length, 5);
});

test('büyük dosya: ofset denetimleri yalnız gerçek ofsetteki baş kısımda', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-yara-'));
  const file = path.join(dir, 'big.bin');
  const buf = Buffer.alloc(3 * 1024 * 1024);
  buf.write('MZ', 0, 'latin1');
  fs.writeFileSync(file, buf);
  const d = db(`
rule Head { condition: uint16(0) == 0x5A4D and filesize > 2MB }
rule Tail { condition: uint8(2200000) == 0 }`);
  assert.equal((signatures.checkFile(file, d) || {}).name, 'Head');
  const tailOnly = { sha256: new Map(), rules: d.rules.filter((r) => r.name === 'Tail') };
  assert.equal(signatures.checkFile(file, tailOnly), null, 'baş penceresi dışındaki ofset okunmamalı');
  fs.rmSync(dir, { recursive: true, force: true });
});
