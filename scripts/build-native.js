#!/usr/bin/env node
// C++ tarama motorunu (native-engine/) Node-API eklentisi olarak derler.
//
//   npm run build:native            derleme hatası → çıkış kodu 1
//   postinstall (npm install/ci)    derleyici yoksa uyarır, kurulumu bozmaz;
//                                   uygulama JS referans motoruyla çalışır
//
// N-API ABI kararlı olduğundan aynı .node dosyası Node ve Electron'da yüklenir.
// macOS'ta binding.gyp arm64 + x86_64 evrensel ikili üretir.
'use strict';

const { spawnSync } = require('child_process');
const path = require('path');

const strict = process.argv.includes('--strict') || process.env.AEGIS_REQUIRE_NATIVE === '1';
const root = path.join(__dirname, '..');
const gyp = require.resolve('node-gyp/bin/node-gyp.js', { paths: [root] });

const res = spawnSync(process.execPath, [gyp, 'rebuild', '--directory', path.join(root, 'native-engine')], {
  stdio: 'inherit',
  cwd: root
});

if (res.status !== 0) {
  const msg = 'C++ tarama motoru derlenemedi (C++17 derleyici ve Python 3 gerekir).';
  if (strict) {
    console.error(`[aegis] ${msg}`);
    process.exit(res.status || 1);
  }
  console.warn(`[aegis] UYARI: ${msg} Uygulama JS referans motoruyla çalışacak.`);
  process.exit(0);
}
console.log('[aegis] C++ tarama motoru hazır: native-engine/build/Release/aegis_engine.node');
