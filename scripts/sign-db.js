//
// İmza DB yayını için db.json'ı imzalar.
//   node scripts/sign-db.js <db.json> [özel-anahtar-yolu]
//
// Yan dosyalar üretir: db.json.sha256 ve db.json.sig (base64 Ed25519).
// Üçünü de aynı adrese yükleyin; uygulama .sig'i gömülü açık anahtarla doğrular.
//
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { validateDb } = require('../src/dbupdate');

const dbPath = process.argv[2];
if (!dbPath) {
  console.error('Kullanım: node scripts/sign-db.js <db.json> [özel-anahtar-yolu]');
  process.exit(1);
}
const keyPath = path.resolve(process.argv[3] || path.join(os.homedir(), '.aegis', 'db-signing-key.pem'));

const payload = fs.readFileSync(dbPath);
const schemaErr = validateDb(JSON.parse(payload.toString('utf8')));
if (schemaErr) {
  console.error('Şema hatası: ' + schemaErr);
  process.exit(1);
}

const key = crypto.createPrivateKey(fs.readFileSync(keyPath, 'utf8'));
const sig = crypto.sign(null, payload, key).toString('base64');
const sha = crypto.createHash('sha256').update(payload).digest('hex');
fs.writeFileSync(dbPath + '.sig', sig + '\n');
fs.writeFileSync(dbPath + '.sha256', sha + '  ' + path.basename(dbPath));
console.log(`İmzalandı: ${dbPath}.sig, ${dbPath}.sha256`);
