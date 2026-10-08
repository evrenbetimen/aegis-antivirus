//
// İmza DB yayıncı anahtarı üretir (Ed25519) — bir kez çalıştırılır.
//   node scripts/db-keygen.js [özel-anahtar-yolu]
//
// - Açık anahtar → signatures/db-public.pem (uygulamaya gömülür, depoya eklenir)
// - Özel anahtar → varsayılan ~/.aegis/db-signing-key.pem (0600). DEPOYA EKLEMEYİN.
//
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const privPath = path.resolve(process.argv[2] || path.join(os.homedir(), '.aegis', 'db-signing-key.pem'));
const pubPath = path.join(__dirname, '..', 'signatures', 'db-public.pem');

if (fs.existsSync(privPath)) {
  console.error(`Özel anahtar zaten var: ${privPath} (üzerine yazılmadı)`);
  process.exit(1);
}

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
fs.mkdirSync(path.dirname(privPath), { recursive: true });
fs.writeFileSync(privPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
fs.writeFileSync(pubPath, publicKey.export({ type: 'spki', format: 'pem' }));
console.log(`Özel anahtar: ${privPath}`);
console.log(`Açık anahtar: ${pubPath}`);
