// Tarama hızı karşılaştırması: inline (tek çekirdek) vs worker havuzu
// Çalıştırma: env -u NODE_OPTIONS ./node_modules/.bin/electron test/bench-scan.js
const { app } = require('electron');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const scanner = require('../src/scanner');

const SIGNATURES_DIR = path.join(__dirname, '..', 'signatures');

app.whenReady().then(async () => {
  const dir = fs.mkdtempSync(path.join(app.getPath('temp'), 'aegis-bench-'));
  const N = 800;
  const SIZE = 128 * 1024;
  const chunk = crypto.randomBytes(SIZE);
  const t0 = Date.now();
  for (let i = 0; i < N; i++) {
    // benzersiz içerik → hash önbelleği işe yaramaz
    fs.writeFileSync(path.join(dir, `f-${i}.bin`), crypto.createHash('sha256').update(String(i)).digest() + chunk.toString('base64').slice(0, SIZE));
  }
  console.log(`hazırlık: ${N} dosya × ${SIZE / 1024}KB — ${Date.now() - t0}ms`);

  const opts = { paths: [dir], heuristics: true, autoQuarantine: false, scanArchives: false, signaturesDir: SIGNATURES_DIR };

  const a = Date.now();
  const r1 = await scanner.run(Object.assign({}, opts, { maxWorkers: 0 }), () => {});
  const inlineMs = Date.now() - a;

  const b = Date.now();
  const r2 = await scanner.run(opts, () => {});
  const poolMs = Date.now() - b;

  console.log(`inline (tek çekirdek): ${inlineMs}ms — ${r1.filesScanned} dosya, ${r1.bytesScanned} B`);
  console.log(`havuz (worker):       ${poolMs}ms — ${r2.filesScanned} dosya, ${r2.bytesScanned} B`);
  console.log(`hızlanma: ${(inlineMs / poolMs).toFixed(2)}×`);

  fs.rmSync(dir, { recursive: true, force: true });
  app.exit(0);
});
