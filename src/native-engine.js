'use strict';

/**
 * C++ tarama motoru yükleyicisi (native-engine/ → aegis_engine.node).
 *
 * Motor seçimi AEGIS_ENGINE ortam değişkeniyle yapılır:
 *   auto   (varsayılan) C++ motoru yüklenebiliyorsa onu, yoksa JS motorunu kullan
 *   native C++ motoru zorunlu; yüklenemezse modül yüklenirken hata fırlat (CI)
 *   js     her zaman JS referans motorunu kullan
 *
 * Paketlenmiş uygulamada .node dosyası app.asar dışına açılır
 * (package.json → build.asarUnpack), bu yüzden yol app.asar.unpacked'e çevrilir.
 */

const path = require('path');

const MODE = String(process.env.AEGIS_ENGINE || 'auto').toLowerCase();
const BINARY = path.join(__dirname, '..', 'native-engine', 'build', 'Release', 'aegis_engine.node');

let binding = null;
let loadError = null;

if (MODE !== 'js') {
  const target = BINARY.replace(/app\.asar([\\/])/, 'app.asar.unpacked$1');
  try {
    binding = require(target);
  } catch (err) {
    loadError = err;
  }
  if (!binding && MODE === 'native') {
    throw new Error(`AEGIS_ENGINE=native ama C++ motoru yüklenemedi (${target}): ${loadError && loadError.message}`);
  }
}

module.exports = {
  binding,
  available: Boolean(binding),
  // Dosya özeti C++'ta yalnızca donanım hızlandırmalıysa (macOS CommonCrypto)
  // hesaplanır; taşınabilir uygulama Node'un OpenSSL'inden yavaştır.
  nativeHashing: Boolean(binding && binding.sha256Accelerated),
  mode: MODE,
  version: binding ? binding.version() : null,
  loadError: loadError ? String(loadError.message || loadError) : null
};
