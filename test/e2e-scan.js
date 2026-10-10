// Uçtan uca test: tarama motoru + karantina + firewall + yeni modüller
// Çalıştırma: env -u NODE_OPTIONS ./node_modules/.bin/electron test/e2e-scan.js
//
// Not: Sisteminizde Avast gibi bir antivirüs varsa EICAR test dosyasını
// bizden önce yakalayıp silebilir — bu durumda EICAR kontrolü "atlandı"
// olarak işaretlenir (bu, harici AV'nin doğru çalıştığı anlamına gelir).
const { app, safeStorage } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const scanner = require('../src/scanner');
const quarantine = require('../src/quarantine');
const firewall = require('../src/firewall');
const signatures = require('../src/signatures');
const { HashCache } = require('../src/cache');
const { Honeypot } = require('../src/honeypot');
const { Scheduler } = require('../src/scheduler');
const dbupdate = require('../src/dbupdate');

const SIGNATURES_DIR = path.join(__dirname, '..', 'signatures');
let archive = null;
try {
  archive = require('../src/archive');
} catch {
  archive = null;
}

const results = [];
function check(name, ok, extra) {
  results.push({ name, ok });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra ? ' — ' + extra : ''}`);
}
function skip(name, extra) {
  console.log(`SKIP  ${name} — ${extra}`);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

app.whenReady().then(async () => {
  // Karantina anahtarı → Keychain (safeStorage) — gerçek göç yolu
  const keyMode = quarantine.initSecureKey(safeStorage);
  if (safeStorage.isEncryptionAvailable()) {
    check("Karantina anahtarı Keychain'e taşındı", keyMode === 'keychain', `mod=${keyMode}`);
  } else {
    // Linux CI / anahtar zinciri olmayan ortam: dosya anahtarına düşmek beklenen davranış
    check('Keychain yok → dosya anahtarına düşüldü', keyMode === 'file', `mod=${keyMode}`);
  }

  const tmp = fs.mkdtempSync(path.join(app.getPath('temp'), 'aegis-e2e-'));

  // ---------- Yeni modüllerin bağımsız doğrulaması ----------

  // 0) Tarama motoru (CI'da Electron içinde C++ eklentisi zorunlu)
  const engine = signatures.engineInfo();
  if (process.env.AEGIS_ENGINE === 'native') {
    check('C++ tarama motoru Electron içinde yüklendi', engine.engine === 'native', `${engine.language} ${engine.version}`);
  } else {
    console.log(`INFO  tarama motoru: ${engine.language} ${engine.version || ''}`);
  }

  // A) İmza veritabanı
  let db = null;
  try {
    db = signatures.load(SIGNATURES_DIR);
    check('İmza DB yüklendi', db.sha256.size > 0, `${db.sha256.size} hash, ${db.rules.length} YARA kuralı, v${db.version}`);
  } catch (err) {
    check('İmza DB yüklendi', false, String(err.message || err));
  }

  // B) Hash önbelleği (kalıcılık)
  const cacheFile = path.join(tmp, 'hash-cache.json');
  try {
    const c1 = new HashCache(cacheFile);
    const st = fs.statSync(__filename);
    const key = HashCache.keyFor(st);
    const h = crypto.createHash('sha256').update(fs.readFileSync(__filename)).digest('hex');
    c1.set(key, h);
    c1.flush();
    const c2 = new HashCache(cacheFile);
    check('Hash önbelleği kalıcı', c2.get(key) === h, key);
  } catch (err) {
    check('Hash önbelleği kalıcı', false, String(err.message || err));
  }

  // C) Zamanlayıcı
  try {
    let ticks = 0;
    const sch = new Scheduler({ intervalHours: 1, onTick: () => ticks++ });
    sch.start();
    sch.runNow();
    sch.stop();
    check('Zamanlayıcı tetiklendi', ticks === 1 && sch.status().runs === 1, `${ticks} tik`);
  } catch (err) {
    check('Zamanlayıcı tetiklendi', false, String(err.message || err));
  }

  // D) Fidye izleyici (yalnızca test dizini — gerçek klasörlere dokunulmaz)
  try {
    const hpDir = fs.mkdtempSync(path.join(app.getPath('temp'), 'aegis-hp-'));
    const events = [];
    const hp = new Honeypot({ dirs: [hpDir], onEvent: (e) => events.push(e) });
    hp.start();
    const bait = path.join(hpDir, require('../src/honeypot').BAIT_NAME);
    check('Yem dosyası oluşturuldu', fs.existsSync(bait));
    await sleep(250); // fs.watch kurulsun
    fs.appendFileSync(bait, '\nFIDYE-TETIK-TESTI');
    await sleep(700); // olay işlensin
    hp.cleanup();
    check(
      'Yem dosyası değişikliği alarmı',
      events.some((e) => e.kind === 'decoy-modified'),
      events.map((e) => e.kind).join(', ') || 'olay yok'
    );
    fs.rmSync(hpDir, { recursive: true, force: true });
  } catch (err) {
    check('Yem dosyası değişikliği alarmı', false, String(err.message || err));
  }

  // E) İmza DB güncelleme (bütünlük denetimli, yerel kaynaktan)
  try {
    const updDir = fs.mkdtempSync(path.join(app.getPath('temp'), 'aegis-upd-'));
    const srcDir = path.join(updDir, 'src');
    fs.mkdirSync(srcDir, { recursive: true });
    const srcFile = path.join(srcDir, 'db.json');
    // geçerli şema üret (64 hex anahtar)
    const goodKey = crypto.createHash('sha256').update('x').digest('hex');
    const goodPayload = JSON.stringify({ version: '2099.1.1', updated: 0, sha256: { [goodKey]: 'Test.Update' } });
    fs.writeFileSync(srcFile, goodPayload);
    fs.writeFileSync(srcFile + '.sha256', crypto.createHash('sha256').update(goodPayload).digest('hex') + '  db.json');
    const res = await dbupdate.update({ url: 'file://' + srcFile, dir: updDir, timeoutMs: 5000 });
    check('İmza DB güncelleme (doğrulamalı)', res.ok && res.changed, res.ok ? `v${res.version}` : res.reason);

    // Bozulmuş yan dosya REDDEDİLMELİ
    fs.writeFileSync(srcFile + '.sha256', 'f'.repeat(64) + '  db.json');
    const res2 = await dbupdate.update({ url: 'file://' + srcFile, dir: updDir, timeoutMs: 5000 });
    check('Bozuk özetli güncelleme reddedildi', !res2.ok, res2.reason);
    fs.rmSync(updDir, { recursive: true, force: true });
  } catch (err) {
    check('İmza DB güncelleme (doğrulamalı)', false, String(err.message || err));
  }

  // ---------- Tarama motoru uçtan uca ----------

  // 1) EICAR test dosyası (hızlıca tara — AV yarışabilir)
  const eicarFile = scanner.createEicarTestFile();
  const eicarAlive = fs.existsSync(eicarFile);

  // 2) Şüpheli çift uzantılı dosya (sezgisel kural)
  fs.writeFileSync(path.join(tmp, 'fatura-odeme.pdf.exe'), 'MZ fake binary');

  // 3) İmza yolu için kayıt: hash'ini imza DB'ye ekliyoruz
  const sigFile = path.join(tmp, 'imza-dosyasi.bin');
  fs.writeFileSync(sigFile, 'imza test icerigi');
  const sigHash = crypto.createHash('sha256').update(fs.readFileSync(sigFile)).digest('hex');
  scanner.SIGNATURES.set(sigHash, 'Test.Signature-Match');

  // 4) Temiz dosya
  fs.writeFileSync(path.join(tmp, 'temiz-not.txt'), 'bu dosya güvenlidir');

  // 5) YARA kuralı eşleşmesi (rules.yar içindeki marker)
  const yaraFile = path.join(tmp, 'yara-test.txt');
  fs.writeFileSync(yaraFile, 'bilgi belgesi AEGIS-TEST-MARKER-V1 sonu');

  const report = await scanner.run(
    {
      paths: [tmp, path.dirname(eicarFile)],
      heuristics: true,
      autoQuarantine: true,
      scanArchives: true,
      signaturesDir: SIGNATURES_DIR,
      cacheFile
    },
    () => {}
  );

  check('Tarama çalıştı', report.filesScanned >= 4, `${report.filesScanned} dosya tarandı`);
  check(
    'SHA-256 imza eşleşmesi tespit edildi',
    report.threats.some((t) => t.threat === 'Test.Signature-Match'),
    report.threats.map((t) => t.threat).join(', ') || 'tehdit yok'
  );
  check(
    'YARA kuralı eşleşmesi tespit edildi',
    report.threats.some((t) => t.kind === 'signature' && /Marker|Test|Rule/i.test(t.threat)),
    report.threats.map((t) => t.threat).join(', ')
  );
  check(
    'Sezgisel kural (çift uzantı) tespit edildi',
    report.threats.some((t) => t.threat === 'Suspicious.DoubleExtension')
  );
  if (eicarAlive) {
    const found = report.threats.some((t) => t.threat === 'EICAR-Test-File');
    if (found) check('EICAR tespit edildi', true);
    else if (!fs.existsSync(eicarFile)) skip('EICAR', 'sistem AV dosyayı bizden önce yakaladı');
    else check('EICAR tespit edildi', false, 'dosya var ama bulunamadı');
  } else {
    skip('EICAR', 'harici AV dosyayı oluştuktan hemen önce sildi');
  }
  check('Temiz dosya işaretlenmedi', !report.threats.some((t) => t.path.endsWith('temiz-not.txt')));

  // Politika: kesin imza/EICAR karantinaya alınır, sezgisel bulgu yalnız işaretlenir
  const sigThreats = report.threats.filter((t) => t.kind !== 'heuristic' && !String(t.path).includes('!'));
  const heurThreats = report.threats.filter((t) => t.kind === 'heuristic');
  check(
    'Kesin tehditler karantinada',
    sigThreats.length > 0 && sigThreats.every((t) => t.quarantined),
    `${sigThreats.length} kesin tehdit`
  );
  check(
    'Sezgisel bulgular karantinaya alınmadı (yalnız işaretli)',
    heurThreats.every((t) => !t.quarantined),
    `${heurThreats.length} sezgisel bulgu`
  );

  // Arşiv entegrasyonu (modül varsa)
  if (archive) {
    const zipMarker = path.join(tmp, 'arsiv-icinde.zip');
    try {
      const inner = path.join(tmp, 'inner-marker.txt');
      // Uzun tekrarlı dolgu → zip DEFLATE ile sıkıştırır; marker zip gövdesinde
      // literal olarak BULUNMAZ, yalnız çözülmüş içerikte görünür.
      fs.writeFileSync(inner, 'x'.repeat(4000) + ' AEGIS-TEST-MARKER-V1 ' + 'y'.repeat(4000));
      require('child_process').execFileSync('zip', ['-q', '-j', '-9', zipMarker, inner]);
      fs.unlinkSync(inner);
      const raw = fs.readFileSync(zipMarker);
      const markerLiteralInZip = raw.includes(Buffer.from('AEGIS-TEST-MARKER-V1'));
      const r2 = await scanner.run(
        { paths: [zipMarker], heuristics: false, autoQuarantine: true, scanArchives: true, signaturesDir: SIGNATURES_DIR },
        () => {}
      );
      check(
        'Arşiv içi tarama (sıkıştırılmış içerik)',
        !markerLiteralInZip && r2.archiveEntries > 0 && r2.threats.length > 0,
        `literal=${markerLiteralInZip} girdi=${r2.archiveEntries} tehdit=${r2.threats.map((t) => t.threat).join(',')}`
      );
      for (const t of r2.threats) if (t.quarantineId) quarantine.remove(t.quarantineId);
    } catch (err) {
      check('Arşiv içi tarama (sıkıştırılmış içerik)', false, String(err.message || err));
    }

    // İç içe arşiv: tar.gz → zip → zip → marker (üç katman)
    try {
      const cp = require('child_process');
      const nestDir = fs.mkdtempSync(path.join(tmp, 'nest-'));
      const leaf = path.join(nestDir, 'leaf.txt');
      fs.writeFileSync(leaf, 'x'.repeat(4000) + ' AEGIS-TEST-MARKER-V1 ' + 'y'.repeat(4000));
      cp.execFileSync('zip', ['-q', '-j', '-9', path.join(nestDir, 'l2.zip'), leaf]);
      fs.unlinkSync(leaf);
      cp.execFileSync('zip', ['-q', '-j', '-0', path.join(nestDir, 'l1.zip'), path.join(nestDir, 'l2.zip')]);
      fs.unlinkSync(path.join(nestDir, 'l2.zip'));
      const outer = path.join(tmp, 'ic-ice.tar.gz');
      cp.execFileSync('tar', ['-czf', outer, '-C', nestDir, 'l1.zip']);
      fs.rmSync(nestDir, { recursive: true, force: true });
      const r3 = await scanner.run(
        { paths: [outer], heuristics: false, autoQuarantine: true, scanArchives: true, signaturesDir: SIGNATURES_DIR },
        () => {}
      );
      const t3 = r3.threats[0];
      check(
        'İç içe arşiv taraması (tar.gz → zip → zip)',
        r3.threats.length === 1 && /l1\.zip!l2\.zip!leaf\.txt$/.test(t3.path) && !t3.quarantined,
        `tehdit=${r3.threats.map((t) => t.path).join(',')}`
      );
      check(
        'İç içe arşiv geçici dosyaları temizlendi',
        !fs.readdirSync(require('os').tmpdir()).some((n) => n.startsWith('aegis-nested-')),
        ''
      );
    } catch (err) {
      check('İç içe arşiv taraması (tar.gz → zip → zip)', false, String(err.message || err));
    }
  } else {
    skip('Arşiv içi tarama (sıkıştırılmış içerik)', 'archive modülü henüz yok');
  }

  // İzin verilmeyen dizin raporu (TCC izni emülasyonu)
  // root chmod 000 dizini yine okuyabildiği için emülasyon root'ta anlamsız
  if (process.getuid && process.getuid() === 0) {
    skip('İzin verilmeyen dizin raporlandı', 'root olarak çalışıyor (chmod 000 etkisiz)');
  } else try {
    const locked = path.join(tmp, 'kilitli');
    fs.mkdirSync(locked, { recursive: true });
    fs.writeFileSync(path.join(locked, 'gizli.txt'), 'gizli');
    fs.chmodSync(locked, 0o000);
    let rLocked;
    try {
      rLocked = await scanner.run(
        { paths: [locked], heuristics: false, autoQuarantine: false, signaturesDir: SIGNATURES_DIR },
        () => {}
      );
    } finally {
      try {
        fs.chmodSync(locked, 0o755);
      } catch {}
    }
    check(
      'İzin verilmeyen dizin raporlandı',
      rLocked.deniedCount >= 1,
      `denied=${rLocked.deniedCount} dosya=${rLocked.filesScanned} dirs=${(rLocked.deniedDirs || []).join(',')}`
    );
  } catch (err) {
    check('İzin verilmeyen dizin raporlandı', false, String(err.message || err));
  }

  // Dışlama listesi (exclusions)
  try {
    const exDir = path.join(tmp, 'dislama');
    fs.mkdirSync(exDir, { recursive: true });
    const exFile = path.join(exDir, 'imza-dosyasi.bin');
    fs.writeFileSync(exFile, 'dislanmis icerik icerik');
    const exHash = crypto.createHash('sha256').update(fs.readFileSync(exFile)).digest('hex');
    scanner.SIGNATURES.set(exHash, 'Test.Excluded-Match');

    const rEx = await scanner.run(
      { paths: [tmp], exclusions: [exDir], heuristics: false, autoQuarantine: false, signaturesDir: SIGNATURES_DIR },
      () => {}
    );
    check(
      'Dışlama uygulandı',
      !rEx.threats.some((t) => t.path === exFile),
      rEx.threats.map((t) => t.path.split('/').pop()).join(',')
    );

    const rEx2 = await scanner.run(
      { paths: [exDir], heuristics: false, autoQuarantine: false, signaturesDir: SIGNATURES_DIR },
      () => {}
    );
    check(
      'Dışlama olmadan aynı dosya bulunur',
      rEx2.threats.some((t) => t.path === exFile),
      rEx2.threats.map((t) => t.threat).join(',') || 'tehdit yok'
    );
    fs.rmSync(exDir, { recursive: true, force: true });
  } catch (err) {
    check('Dışlama uygulandı', false, String(err.message || err));
  }

  // Dışlama yalnızca dizinin kendisini kapsar ("dislama" → "dislama2" taranır)
  try {
    const exDir = path.join(tmp, 'dislama-kok');
    const sibDir = path.join(tmp, 'dislama-kok2');
    fs.mkdirSync(exDir, { recursive: true });
    fs.mkdirSync(sibDir, { recursive: true });
    const sibFile = path.join(sibDir, 'kardes.bin');
    fs.writeFileSync(sibFile, 'kardes dizin icerigi');
    const sibHash = crypto.createHash('sha256').update(fs.readFileSync(sibFile)).digest('hex');
    scanner.SIGNATURES.set(sibHash, 'Test.Sibling-Match');
    const rSib = await scanner.run(
      { paths: [tmp], exclusions: [exDir], heuristics: false, autoQuarantine: false, signaturesDir: SIGNATURES_DIR, maxWorkers: 0 },
      () => {}
    );
    check(
      'Dışlama kardeş dizini kapsamadı',
      rSib.threats.some((t) => t.path === sibFile),
      rSib.threats.map((t) => t.path.split('/').pop()).join(',') || 'tehdit yok'
    );
    fs.rmSync(exDir, { recursive: true, force: true });
    fs.rmSync(sibDir, { recursive: true, force: true });
  } catch (err) {
    check('Dışlama kardeş dizini kapsamadı', false, String(err.message || err));
  }

  // Yolunda "!" geçen gerçek dosya da karantinaya alınır (arşiv girdisi sanılmaz)
  try {
    const bangDir = path.join(tmp, 'unlem');
    fs.mkdirSync(bangDir, { recursive: true });
    const bangFile = path.join(bangDir, 'indir!.bin');
    fs.writeFileSync(bangFile, 'unlemli dosya icerigi');
    const bangHash = crypto.createHash('sha256').update(fs.readFileSync(bangFile)).digest('hex');
    scanner.SIGNATURES.set(bangHash, 'Test.Bang-Match');
    const rBang = await scanner.run(
      { paths: [bangDir], heuristics: false, autoQuarantine: true, signaturesDir: SIGNATURES_DIR },
      () => {}
    );
    const th = rBang.threats.find((t) => t.path === bangFile);
    check('"!" içeren yol karantinaya alındı', !!(th && th.quarantined) && !fs.existsSync(bangFile), th ? `q=${th.quarantined}` : 'tehdit yok');
    if (th && th.quarantineId) quarantine.remove(th.quarantineId);
    fs.rmSync(bangDir, { recursive: true, force: true });
  } catch (err) {
    check('"!" içeren yol karantinaya alındı', false, String(err.message || err));
  }

  // Paralel tarama (worker havuzu) — 8'den fazla dosya havuzu zorlar
  try {
    const pdir = path.join(tmp, 'paralel');
    fs.mkdirSync(pdir, { recursive: true });
    let target = null;
    for (let i = 0; i < 12; i++) {
      const fp = path.join(pdir, `dosya-${i}.dat`);
      fs.writeFileSync(fp, `paralel icerik ${i}`);
      if (i === 7) target = fp;
    }
    const pHash = crypto.createHash('sha256').update(fs.readFileSync(target)).digest('hex');
    scanner.SIGNATURES.set(pHash, 'Test.Parallel-Match'); // worker init mesajıyla aktarılmalı
    const rP = await scanner.run(
      { paths: [pdir], heuristics: false, autoQuarantine: false, signaturesDir: SIGNATURES_DIR },
      () => {}
    );
    scanner.SIGNATURES.delete(pHash);
    check(
      'Paralel tarama (worker havuzu) sonuç verdi',
      rP.filesScanned === 12 && rP.threats.some((t) => t.path === target && t.threat === 'Test.Parallel-Match'),
      `dosya=${rP.filesScanned} tehdit=${rP.threats.map((t) => t.threat).join(',') || 'yok'}`
    );
    fs.rmSync(pdir, { recursive: true, force: true });
  } catch (err) {
    check('Paralel tarama (worker havuzu) sonuç verdi', false, String(err.message || err));
  }

  // Önbellek ikinci taramada kullanıldı mı (cache dosyası oluştu + hit)
  try {
    const c = new HashCache(cacheFile);
    const stats = c.stats();
    check('Tarama önbelleği kullanıldı', c.size() > 0, `girdi=${c.size()}`);
  } catch (err) {
    check('Tarama önbelleği kullanıldı', false, String(err.message || err));
  }

  // ---------- Karantina: şifreleme + bütünlük ----------
  const q = quarantine.list();
  check('Karantina listesi dolu', q.length >= 2, `${q.length} öğe`);
  check(
    'Karantina kayıtları şifreli + imzalı',
    q.every((it) => it.encrypted === true && typeof it.hmac === 'string' && it.intact !== false),
    q.map((it) => `enc=${it.encrypted} intact=${it.intact}`).join(' | ')
  );

  const rep = quarantine.verifyAll();
  check('Karantina bütünlük denetimi temiz', rep.tampered === 0, JSON.stringify(rep));

  // Şifreli dosya geri açılınca özgün içerik gelmeli
  const withId = q.find((it) => it.originalPath && it.originalPath.includes('imza-dosyasi'));
  const target = withId || q[0];
  const r = await quarantine.restore(target.id);
  check('Karantina geri yükleme (şifre çözme)', r.ok === true, r.ok ? target.originalPath : r.error);
  if (r.ok && target.file) {
    check(
      'Geri yüklemeden sonra şifreli kopya silindi',
      !fs.existsSync(target.file),
      target.file ? target.file.split('/').pop() : ''
    );
  }
  if (r.ok && target.originalPath.includes('imza-dosyasi')) {
    const restored = fs.readFileSync(target.originalPath, 'utf8');
    check('Geri yüklenen içerik doğru', restored === 'imza test icerigi', JSON.stringify(restored.slice(0, 40)));
    fs.unlinkSync(target.originalPath);
  }

  // ---------- Tarama geçmişi ----------
  try {
    const store = require('../src/store');
    const before = store.getScanHistory().length;
    const fakeReport = {
      filesScanned: 10,
      bytesScanned: 12345,
      threats: [{ path: '/tmp/x.bin', threat: 'Test.History', quarantined: false }],
      duration: 42,
      deniedCount: 0,
      stopped: false,
      signatureVersion: 'v-test'
    };
    store.recordScan(fakeReport, { mode: 'custom' });
    const h = store.getScanHistory();
    check(
      'Tarama geçmişi kaydedildi',
      h.length === before + 1 && h[0].mode === 'custom' && h[0].threatCount === 1 && h[0].threats.length === 1,
      `n=${h.length} mode=${h[0] && h[0].mode}`
    );
    store.clearScanHistory();
    check('Tarama geçmişi temizlendi', store.getScanHistory().length === 0, `${store.getScanHistory().length} kayıt`);
  } catch (err) {
    check('Tarama geçmişi kaydedildi', false, String(err.message || err));
  }

  // ---------- Firewall ----------
  const rules = firewall.getRules();
  check('Firewall kuralları yüklü', Array.isArray(rules) && rules.length >= 3, `${rules.length} kural`);

  const conns = await firewall.getConnections();
  check(
    'Bağlantı listesi alındı',
    Array.isArray(conns.connections),
    `${conns.connections.length} bağlantı, ${conns.connections.filter((c) => c.verdict === 'blocked').length} kural eşleşmesi`
  );

  if (conns.connections.length > 0) {
    const target2 = conns.connections[0];
    const rules2 = firewall.getRules();
    rules2.push({ id: 'test-block', type: 'block', host: target2.remote, port: null, note: 'e2e test' });
    firewall.setRules(rules2);
    const conns2 = await firewall.getConnections();
    const marked = conns2.connections.find((c) => c.remote === target2.remote && c.port === target2.port);
    check(
      'Engel kuralı işaretleme',
      marked && marked.verdict === 'blocked',
      marked ? `${marked.remote}:${marked.port} → ${marked.verdict}` : 'bağlantı bulunamadı'
    );
    firewall.setRules(rules2.filter((r2) => r2.id !== 'test-block'));
  } else {
    skip('Engel kuralı işaretleme', 'test için canlı bağlantı yok');
  }

  // DNS çözümleme + alan adı kuralının IP üzerinden eşleşmesi
  try {
    const res = await firewall.resolveHost('localhost');
    const loopback = (res.ips || []).map((x) => String(x).toLowerCase());
    check(
      'DNS çözümleme (localhost → loopback)',
      loopback.includes('127.0.0.1') || loopback.includes('::1'),
      JSON.stringify(res)
    );

    const before = firewall.getRules();
    firewall.setRules(
      before.concat([{ id: 'test-domain', type: 'block', host: 'localhost', port: 443, note: 'e2e' }])
    );
    const resolutions = { localhost: { ips: loopback, error: null } };

    const hit = firewall.matchRules({ remote: '127.0.0.1', port: 443, process: 'testproc' }, resolutions);
    check(
      'Alan adı kuralı IP üzerinden eşleşti',
      !!hit && hit.id === 'test-domain',
      hit ? `${hit.host}:${hit.port}` : 'eşleşme yok'
    );

    const miss = firewall.matchRules({ remote: '10.9.8.7', port: 9999, process: 'testproc' }, resolutions);
    check('Alakasız IP/port eşleşmedi', !miss, miss ? `${miss.host}:${miss.port}` : 'ok');

    firewall.setRules(before);
  } catch (err) {
    check('DNS çözümleme + alan adı eşleşmesi', false, String(err.message || err));
  }

  // ---------- Orfan .qtn temizliği ----------
  try {
    const orphan = path.join(quarantine.QUARANTINE_DIR, `orfan-test-${Date.now()}.qtn`);
    fs.writeFileSync(orphan, 'artik');
    const n = quarantine.cleanupOrphans();
    check('Orfan karantina artığı temizlendi', n >= 1 && !fs.existsSync(orphan), `silinen=${n}`);
  } catch (err) {
    check('Orfan karantina artığı temizlendi', false, String(err.message || err));
  }

  // ---------- Karantina kimliği doğrulaması (dizin dışına erişim yok) ----------
  try {
    const victim = path.join(tmp, 'kurban.txt');
    fs.writeFileSync(victim, 'silinmemeli');
    const fakeMeta = path.join(tmp, 'sahte.json');
    fs.writeFileSync(fakeMeta, JSON.stringify({ id: 'x', file: victim, originalPath: victim }));
    const rel = path.relative(quarantine.QUARANTINE_DIR, fakeMeta).replace(/\.json$/, '');
    const rDel = quarantine.remove(rel);
    const rRes = await quarantine.restore(rel);
    check(
      'Geçersiz karantina kimliği reddedildi',
      !rDel.ok && !rRes.ok && fs.existsSync(victim) && fs.existsSync(fakeMeta),
      `${rDel.error} | ${rRes.error}`
    );
  } catch (err) {
    check('Geçersiz karantina kimliği reddedildi', false, String(err.message || err));
  }

  // ---------- Keychain enjeksiyonu (safeStorage yolu emülasyonu) ----------
  try {
    const keyFile = path.join(quarantine.QUARANTINE_DIR, '.key');
    const encFile = path.join(quarantine.QUARANTINE_DIR, '.key.enc');
    let origHex = null;
    if (fs.existsSync(keyFile)) origHex = fs.readFileSync(keyFile, 'utf8').trim();
    else if (fs.existsSync(encFile)) origHex = safeStorage.decryptString(fs.readFileSync(encFile)).trim();

    if (!origHex || !/^[0-9a-f]{64}$/.test(origHex)) {
      skip('Enjekte anahtarla karantina (Keychain yolu)', 'orijinal anahtar çözülemedi');
    } else {
      quarantine.setKey(crypto.randomBytes(32)); // dışarıdan anahtar (Keychain gibi)
      const kf = path.join(tmp, 'enjekte-anahtar.bin');
      fs.writeFileSync(kf, 'enjekte anahtar icerik');
      const rec = await quarantine.store(kf, { threat: 'Test.Injected-Key', detail: 'e2e' });
      const mine = quarantine.list().find((i) => i.id === rec.id);
      const okInject = rec.encrypted === true && !rec.error && mine && mine.intact === true;
      // orijinal anahtara dön (eski kayıtların imzası bozulmasın) + test kaydını sil
      quarantine.setKey(Buffer.from(origHex, 'hex'));
      quarantine.remove(rec.id);
      check('Enjekte anahtarla karantina (Keychain yolu)', okInject, rec.error || `intact=${mine && mine.intact}`);
    }
  } catch (err) {
    check('Enjekte anahtarla karantina (Keychain yolu)', false, String(err.message || err));
  }

  // Temizlik
  fs.rmSync(tmp, { recursive: true, force: true });
  for (const t of report.threats) if (t.quarantineId) quarantine.remove(t.quarantineId);

  const failed = results.filter((x) => !x.ok).length;
  console.log(`\nSonuç: ${results.length - failed}/${results.length} başarılı`);
  app.exit(failed === 0 ? 0 : 1);
}).catch((err) => {
  console.error('TEST HATASI:', err);
  app.exit(2);
});
