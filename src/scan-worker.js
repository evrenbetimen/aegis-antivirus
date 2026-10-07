//
// Tarama worker'ı (worker_threads).
//
// Ana iş parçacığından mesaj alır:
//   { type:'init', signaturesDir, localSignatures: [[hash,name],...] }
//   { type:'scan', id, file, size, hash }
// Yanıtlar:
//   { type:'ready' }
//   { type:'result', id, file, hash, threat, error? }
//
// Her worker imza DB'yi kendisi yükler (one-shot init); yerel/test
// imzaları init mesajıyla aktarılır (ana süreçteki SIGNATURES Map'i).
//
const { parentPort } = require('worker_threads');
const signatures = require('./signatures');
const { scanFileCore } = require('./filescan');

let db = { version: '0', sha256: new Map(), rules: [], skipped: [] };

if (parentPort) {
  parentPort.on('message', (msg) => {
    if (!msg || !msg.type) return;

    if (msg.type === 'init') {
      try {
        db = signatures.load(msg.signaturesDir);
      } catch {
        db = { version: '0', sha256: new Map(), rules: [], skipped: [] };
      }
      if (!db.sha256 || typeof db.sha256.set !== 'function') db.sha256 = new Map();
      if (Array.isArray(msg.localSignatures)) {
        for (const pair of msg.localSignatures) {
          if (Array.isArray(pair) && pair.length === 2) db.sha256.set(pair[0], pair[1]);
        }
      }
      parentPort.postMessage({ type: 'ready' });
      return;
    }

    if (msg.type === 'scan') {
      scanFileCore(msg.file, msg.size, msg.hash || null, db)
        .then((r) => {
          parentPort.postMessage({
            type: 'result',
            id: msg.id,
            file: msg.file,
            hash: r.hash || null,
            threat: r.threat || null,
            error: r.error || null
          });
        })
        .catch((err) => {
          parentPort.postMessage({
            type: 'result',
            id: msg.id,
            file: msg.file,
            hash: null,
            threat: null,
            error: String((err && err.message) || err)
          });
        });
    }
  });
}
