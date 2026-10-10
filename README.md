# Aegis Security Suite

macOS için Electron tabanlı, profesyonel arayüzlü güvenlik paketi.
**Tarama + şifreli karantina + firewall + fidye izleyici** Evre 1'de çalışır;
**gerçek zamanlı kalkan + gerçek paket engelleme** native daemon (Evre 2) ile
tamamlanır.

## Çalıştırma

```bash
cd antivirus
npm install
npm start        # uygulamayı açar
npm test         # uçtan uca test (tarama + karantina + firewall + yeni modüller)
```

Modül testleri (electron gerektirmez):

```bash
node --test test/signatures.test.js   # imza DB + YARA motoru
node --test test/yara-engine.test.js  # genişletilmiş YARA yapıları
node --test test/build-db.test.js     # imza DB üretim hattı
node --test test/archive.test.js      # arşiv tarama (zip/tar/gz)
node --test test/cache.test.js        # hash önbelleği
node --test test/dbupdate.test.js     # imza DB güncelleme (Ed25519, yönlendirme, dizin)
node --test test/validate.test.js     # IPC girdi doğrulaması (ayarlar, firewall kuralları)
```

Yararlı bayraklar:

```bash
npm start -- --page=firewall      # belirli bir sayfayla aç
npm start -- --page=scan --capture=/tmp/ekran.png   # sayfayı görsel olarak kaydet ve çık
```

### Bu makinede bilinen tuzaklar (çözüldü)

1. **`NODE_OPTIONS=--openssl-legacy-provider`** `~/.zshrc` içinde tanımlı;
   Electron bunu reddeder. `start` betiği bu değişkeni `env -u` ile kaldırır.
2. **Avast kaynak dosyaları silebilir**: EICAR test imzası içeren dosyaları
   (eski `src/scanner.js` dahil) yanlış pozitif olarak karantinaya aldı.
   Bu yüzden EICAR dizgisi kodda ham metin olarak tutulmuyor, çalışma anında
   karakter kodlarından birleştiriliyor. Proje klasörüne Avast dışlama
   eklemeniz önerilir (Ayarlar → Genel → Hariç tutulanlar).
3. **Electron v31.7.7 bu makinede çalışamaz** (Apple notarization'ı iptal
   etti → SIGKILL). Sürüm ^44.5.1'de kaldı.

## Özellikler

### Çalışır durumda (Evre 1)

- **Tarama motoru**
  - SHA-256 imza veritabanı (`signatures/db.json`) + **YARA motoru**
    (`signatures/rules.yar` + yayındaki gömülü kurallar): metin dizgiler
    (`nocase/ascii/wide/fullword`), hex (`??`, `A?`, `~XX`, `[n-m]` atlama,
    `( AA | BB )`), `uint16(0) == 0x5A4D`, `filesize`, `$a at N`, aritmetik,
    `N of ($x*)`. Desteklenmeyen yapı (pe/elf modülleri, regex, `for`, `in`)
    içeren kural **atlanır**, asla yanlış değerlendirilmez
  - **Gerçek imza beslemesi**: saatlik GitHub Actions (`signatures.yml`) —
    MalwareBazaar (abuse.ch, CC0) son örnek hash'leri (kayan pencere, 100k) +
    ReversingLabs YARA kuralları (MIT; motorun desteklediği ~290 kural) →
    imzalı `db.json` → `signatures` sürümü. Uygulama varsayılan olarak bunu
    6 saatte bir indirir (Ayarlar → Otomatik güncelle)
  - EICAR test dosyası (kodda ham metin yok — AV yarışı için)
  - Sezgisel kurallar: çift uzantı, indirilen Windows binary'leri,
    LaunchAgent kalıcılığı
  - **Arşiv taraması** (zip/tar/tar.gz/gz/bz2) — dosya çıkarmadan, akışla;
    zip-slip imkânsız, girdi/bayt/süre sınırları, şifreli girdiler atlanır
  - **Hash önbelleği** (inode+mtime+size → SHA-256): ikinci tarama ~10x hızlı
  - **Paralel tarama** — 8'den fazla dosyada worker thread havuzu (CPU
    çekirdeği kadar paralel hash + imza taraması); 800×128KB ölçümünde
    tek çekirdeğe göre ~15x hızlanma (`test/bench-scan.js` ile ölçüldü)
  - Politika: kesin imza/EICAR tespitleri otomatik karantinaya alınır,
    **sezgisel bulgular yalnız işaretlenir** (kullanıcı onayı gerekir)
- **Karantina — AES-256-GCM şifreli**
  - Dosya `[IV][ciphertext][auth tag]` olarak şifrelenir; anahtar **macOS
    Keychain'de** tutulur (`safeStorage` → `quarantine/.key.enc`); Keychain
    kullanılamıyorsa `0600` dosyaya düşülür
  - Meta veri HMAC-SHA256 ile imzalanır → `Ayarlar → Karantina bütünlüğü`
    denetimi kayıt değişimini yakalar
  - Geri yüklemede önce HMAC, sonra dosyanın SHA-256'sı doğrulanır
- **Firewall**: kural motoru (alan adı/IP/port/uygulama), canlı bağlantı
  izleme (`lsof` alan kipi) ve kural eşleşmelerini işaretleme
- **Fidye izleyici**: Belgeler/Masaüstü'ne yem dosyaları (honeypot) +
  `fs.watch` ile anlık alarm + 5 sn içinde toplu değişiklik patlaması tespiti
- **Zamanlanmış tarama**: uygulama açıkken saatlik/günlük periyodik tarama
- **İmza DB güncelleme**: `db.json` + `.sha256` + **Ed25519 yayıncı imzası**
  (`db.json.sig`). Uzak (https) güncelleme yalnızca uygulamaya gömülü
  `signatures/db-public.pem` ile doğrulanan imzayla kabul edilir; anahtar
  yoksa uzak güncelleme **reddedilir**. Güncellemeler salt okunur paket
  yerine kullanıcı dizinine (`userData/signatures`) yazılır; uygulama
  güncellemesi daha yeni bir DB getirirse kullanıcı kopyası yenilenir.

  Yayıncı kurulumu (bir kez):

  ```bash
  node scripts/db-keygen.js            # özel anahtar ~/.aegis/db-signing-key.pem, açık anahtar signatures/db-public.pem
  node scripts/sign-db.js yol/db.json  # db.json.sig + db.json.sha256 üretir; üçünü aynı adrese yükleyin
  ```

  Özel anahtarı depoya eklemeyin; `db-public.pem`'i ekleyip uygulamayı yeniden paketleyin.
- **Çoklu dil**: TR/EN (Ayarlar → Dil), tüm statik ve dinamik metinler
- **Tarama geçmişi + rapor dışa aktarma**: son 100 tarama (mod, süre, tehdit
  listesi, izin hataları) ve tek tıkla **JSON/CSV** kaydetme
  (Tarama → Tarama geçmişi)
- **Dashboard**: güvenlik puanı, istatistikler, etkinlik akışı (i18n)
- **Premium UI**: koyu tema, cam efektli kartlar, macOS gizli başlık çubuğu,
  üretilmiş uygulama ikonu (`build/icon.icns`, `npm run icon` ile yeniden üretilir)

### Evre 2 (native-daemon/) — kod yazıldı, Apple yetkisi bekliyor

- **Gerçek zamanlı kalkan**: Endpoint Security Framework ile dosya
  açma/çalıştırma olaylarını izleme ve engelleme → `native-daemon/AegisShield.swift`
- **Gerçek firewall**: NEFilterDataProvider ile paket/atış engelleme →
  `native-daemon/AegisFirewall.swift`

## Mimari

Norton ve McAfee'de olduğu gibi katmanlar farklı dillerde yazılmıştır:
arayüz JavaScript (Electron), tarama motoru **C++17**, macOS sistem
genişletmeleri **Swift**.

```
┌───────────────────────────────┐
│ Electron UI (renderer/)       │  ← JavaScript: dashboard, tarama, firewall, i18n
├───────────────────────────────┤
│ Electron main (main.js, src/) │  ← JavaScript: tarama orkestrasyonu, şifreli
│                               │     karantina, kural motoru, yem dosyaları
├───────────────────────────────┤
│ Tarama motoru (native-engine/)│  ← C++17: YARA derleyici/eşleştirici, SHA-256,
│   aegis_engine.node, aegis-scan│     komut satırı tarayıcısı (Node-API)
├───────────────────────────────┤
│ Native daemon (native-daemon/ │  ← Endpoint Security + Network Extension
│   Swift, Evre 2)              │     (Apple yetkisi gerektirir)
└───────────────────────────────┘
```

| Modül | Dosya |
|---|---|
| Tarama motoru | `src/scanner.js` |
| Dosya çekirdek tarama + worker | `src/filescan.js`, `src/scan-worker.js` |
| **C++ tarama motoru** (YARA + SHA-256 + CLI) | `native-engine/` ([ayrıntı](native-engine/README.md)) |
| İmza DB + YARA referans motoru (JS yedek) | `src/signatures.js`, `src/native-engine.js`, `signatures/` |
| Arşiv tarama | `src/archive.js` |
| Hash önbelleği | `src/cache.js` |
| Şifreli karantina | `src/quarantine.js` |
| Firewall kural motoru | `src/firewall.js` |
| Fidye izleyici | `src/honeypot.js` |
| Zamanlayıcı | `src/scheduler.js` |
| İmza DB güncelleme | `src/dbupdate.js` |
| Ayar/istatistik deposu | `src/store.js` |
| Tam Disk Erişimi denetimi | `src/permissions.js` |
| Uygulama güncellemesi | `src/updater.js` |
| Native genişletme köprüsü | `src/native-bridge.js` |

## Test

- `npm test` → 35 uçtan uca kontrol (tarama, imza, YARA, arşiv, önbellek,
  paralel worker havuzu, şifreli karantina geri yükleme, bütünlük, Keychain
  anahtarı, güncelleme doğrulama, firewall DNS eşleşmesi, tarama geçmişi)
- `npm run test:unit` → birim testler (imza/YARA, önbellek, arşiv) + C++ ↔ JS
  motor fark testi (`AEGIS_ENGINE=native|js` ile iki motorda da çalışır)
- `npm run test:native` → C++ motoru birim testleri (CMake/ctest)
- `test/bench-scan.js` → paralel tarama hız karşılaştırması
- Tarama sayfasındaki **"EICAR test dosyası oluştur"** düğmesi: tarama bunu
  `EICAR-Test-File` olarak bulup karantinaya almalıdır. (Bu makinede Avast
  dosyayı bazen bizden önce yakalar → test `SKIP` olur; bu normaldir.)

## Eksikler / yol haritası (dürüst durum)

### 🔴 Apple onayı gerektirir (Evre 2 — kod hazır, yetki bekliyor)

1. **Gerçek zamanlı kalkan** — `native-daemon/AegisShield.swift` tam kod ve
   her PR'da macOS CI'da derleniyor; Electron köprüsü (`src/native-bridge.js`:
   socket sunucusu, politika dosyası, olay akışı, dashboard durumu) hazır.
   Eksik olan yalnızca `com.apple.developer.endpoint-security.client` yetkisi
   (Apple Developer portal başvurusu) ve sistem genişletmesinin Xcode
   hedefi olarak paketlenmesi
2. **Gerçek paket engelleme** — `AegisFirewall.swift` (NEFilterDataProvider);
   `com.apple.developer.networkextension.network-filter` yetkisi ister
3. **Süreç/kendi kendini koruma (anti-tamper)** — `pkill` engelleme ve dosya
   bütünlüğü koruması da native yetki (SIP/ES) ister

### 🟡 Dağıtım öncesi (sertifika / kullanıcı izni)

4. **Kod imzası + notarization** — `.github/workflows/release.yml` hazır:
   `v*` etiketi push edilince macOS'ta derler, Developer ID ile imzalar,
   notarize eder ve GitHub Release'e yükler. Gerekli secret'lar: `CSC_LINK`
   (.p12, base64), `CSC_KEY_PASSWORD`, `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`,
   `APPLE_TEAM_ID`. Kısıtlı ES/NE yetkileri uygulama entitlements'ından
   çıkarıldı (profilsiz imzalanmış uygulama açılışta öldürülür); bunlar
   yalnızca `native-daemon/` sistem genişletmelerine ait
5. ✅ **Tam Disk Erişimi (TCC)** — ilk açılışta izin yoksa rehber penceresi
   çıkar; Sistem Ayarları'ndan dönünce durum otomatik yenilenir, Ayarlar'da
   güncel durum görünür (`src/permissions.js`)
6. **Gerçek imza istihbaratı** — saatlik besleme hazır (`signatures.yml`);
   çalışması için depo sırrı `DB_SIGNING_KEY` (özel anahtar) gerekir. Depo
   gizliyse yayın herkese açık ayrı depoya yapılmalı (`vars.SIGNATURES_REPO`
   + `SIGNATURES_TOKEN`). Authenticode sertifika kuralları (pe modülü) henüz yok
7. ✅ **Otomatik uygulama güncellemesi** — `electron-updater` (`src/updater.js`):
   imzalı macOS sürümünde 30 sn sonra ve 6 saatte bir denetler, arka planda
   indirir, çıkışta kurar (Ayarlar → Uygulama güncellemeleri). Güncellemeler
   `release.yml`'ın yüklediği `latest-mac.yml` + `.zip`'ten gelir; depo
   gizliyse sürümler `vars.RELEASES_REPO` + `RELEASES_TOKEN` ile herkese açık
   ayrı bir depoya yayınlanmalı
8. **Uygulama kapanınca da çalışan zamanlanmış tarama** — launchd plist
   iskeleti (README: `native-daemon/` içinde)

### 🟢 İyileştirme fırsatları (yerel yapılabilir)

9. ✅ **İç içe arşiv taraması** — zip/tar/gz içindeki arşivlere 3 katmana
   kadar iner; girdi (300) ve bayt (200 MB) bütçesi tüm katmanlarda ortak,
   iç arşivler 0700 geçici klasörde açılıp hemen silinir
10. **Alan adı bazlı phishing engelleme** — Evre 1'de domain kuralları DNS ile
    çözülüp IP üzerinden eşleşir; bağlantı öncesi hostname engeli NEFilter ister
11. **.dmg/.pkg kurulum paketi taraması** — hdiutil ile bağlama desteği yok
12. **Tarama önbelleği için değişen dosya imzası (ssdeep benzeri)** — parçalı
    hash ile hızlı yaklaşık eşleşme
13. **Uygulama/HTML ikinci dil testi + çevirinin tam senkronu** — TR/EN
    eklendi; üçüncü dil için sözlük genişletilmeli
14. ✅ **Etkinlik kaydı dışa aktarma** (JSON/CSV) — Etkinlik sayfasından;
    CSV hücreleri formül enjeksiyonuna karşı korunur (tarama geçmişi dahil)

> Tamamlananlar: karantina anahtarı Keychain'e taşındı, paralel (worker)
> tarama eklendi, tarama geçmişi + JSON/CSV dışa aktarma eklendi.

## Dikkat

- Bu proje **eğitim/geliştirme** amaçlıdır. Gerçek dağıtım için kod imzası,
  notarization ve Apple yetkileri (endpoint-security, network-filter) gerekir.
- Kullanıcı bilgilendirmesi ve gizlilik politikası olmadan dosya taraması
  yapmak macOS TCC kurallarına takılır (Tam Disk Erişimi izni gerekir).
- Fidye izleyici kapalıysa yem dosyaları temizlenir; açıkken
  `Aegis-Korumali-Dosya.txt` adlı dosyalar Belgeler/Masaüstü'ne yerleştirilir.
