//
// Dosya çekirdek taraması — ana iş parçacığı VE worker için ortak modül.
//
// Sıra (tarihsel davranışla aynı):
//   1) SHA-256 hesapla (ipucu önbellekten gelebilir)
//   2) SHA-256 imza DB eşleşmesi
//   3) YARA/string kural eşleşmesi
//   4) EICAR test dizgisi (yalnız <= 2KB dosyalar)
//
const fs = require('fs');
const crypto = require('crypto');
const signatures = require('./signatures');

/**
 * DİKKAT: EICAR test dizgisi bu dosyada HAM metin olarak BULUNMAZ.
 * Aksi halde antivirüs yazılımları (ör. Avast) bu kaynak dosyasını
 * kendisi imzalanmış tehdit sanıp SİLER. Bu yüzden dize çalışma
 * anında karakter kodlarından birleştirilir.
 */
const EICAR = String.fromCharCode(
  88, 53, 79, 33, 80, 37, 64, 65, 80, 91, 52, 92, 80, 90, 88, 53, 52, 40, 80,
  94, 41, 55, 67, 67, 41, 55, 125, 36, 69, 73, 67, 65, 82, 45, 83, 84, 65, 78,
  68, 65, 82, 68, 45, 65, 78, 84, 73, 86, 73, 82, 85, 83, 45, 84, 69, 83, 84,
  45, 70, 73, 76, 69, 33, 36, 72, 43, 72, 42
);

function hashFile(file) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash('sha256');
    const s = fs.createReadStream(file);
    s.on('error', reject);
    s.on('data', (chunk) => h.update(chunk));
    s.on('end', () => resolve(h.digest('hex')));
  });
}

/**
 * Tek dosyanın çekirdek taraması.
 * @param file   dosya yolu
 * @param size   dosya boyutu (stat'tan)
 * @param hintHash önbellekten gelen hash (yoksa hesaplanır)
 * @param db     signatures.load() çıktısı (sha256 Map + rules)
 * @returns {Promise<{hash: string|null, threat: {threat:string,kind:string,detail:string}|null, error?: string}>}
 */
async function scanFileCore(file, size, hintHash, db) {
  let hash = hintHash || null;
  if (!hash) {
    try {
      hash = await hashFile(file);
    } catch (err) {
      return { hash: null, threat: null, error: String((err && err.code) || (err && err.message) || err) };
    }
  }

  // 1) SHA-256 imza
  const shaName = hash && db.sha256.get(hash);
  if (shaName) {
    return { hash, threat: { threat: shaName, kind: 'signature', detail: 'İmza eşleşmesi (SHA-256)' } };
  }

  // 2) YARA/string kuralları (hash gerektirmez)
  const yaraHit = signatures.checkStrings(file, db);
  if (yaraHit) {
    return {
      hash,
      threat: { threat: yaraHit.name, kind: 'signature', detail: `Kural eşleşmesi (${yaraHit.kind})` }
    };
  }

  // 3) EICAR test dizgisi
  if (size <= 2048) {
    let content = '';
    try {
      content = fs.readFileSync(file, 'utf8');
    } catch {}
    if (content.includes(EICAR)) {
      return { hash, threat: { threat: 'EICAR-Test-File', kind: 'signature', detail: 'EICAR antivirüs test dosyası' } };
    }
  }

  return { hash, threat: null };
}

module.exports = { scanFileCore, hashFile, EICAR };
