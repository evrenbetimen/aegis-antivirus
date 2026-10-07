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
node --test test/signatures.test.js   # imza DB + mini YARA motoru
node --test test/archive.test.js      # arşiv tarama (zip/tar/gz)
node --test test/cache.test.js        # hash önbelleği
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
  - SHA-256 imza veritabanı (`signatures/db.json`) + **mini YARA motoru**
    (`signatures/rules.yar`): metin/hex dizgiler, `nocase`, `any/all of them`,
    `and/or/not`, `#a == N` — parse hatalarında kural atlanır, asla çökmez
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
- **İmza DB güncelleme**: `db.json` + `.sha256` yan dosyası doğrulaması;
  özet uyuşmazlığında güncelleme **reddedilir** (yalnızca https/localhost)
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

```
┌───────────────────────────────┐
│ Electron UI (renderer/)       │  ← dashboard, tarama, firewall, i18n
├───────────────────────────────┤
│ Electron main (main.js, src/) │  ← tarama motoru, şifreli karantina,
│                               │     kural motoru, yem dosyaları, zamanlayıcı
├───────────────────────────────┤
│ Native daemon (native-daemon/ │  ← Endpoint Security + Network Extension
│   Swift, Evre 2)              │     (Apple yetkisi gerektirir)
└───────────────────────────────┘
```

| Modül | Dosya |
|---|---|
| Tarama motoru | `src/scanner.js` |
| Dosya çekirdek tarama + worker | `src/filescan.js`, `src/scan-worker.js` |
| İmza DB + mini YARA | `src/signatures.js`, `signatures/` |
| Arşiv tarama | `src/archive.js` |
| Hash önbelleği | `src/cache.js` |
| Şifreli karantina | `src/quarantine.js` |
| Firewall kural motoru | `src/firewall.js` |
| Fidye izleyici | `src/honeypot.js` |
| Zamanlayıcı | `src/scheduler.js` |
| İmza DB güncelleme | `src/dbupdate.js` |
| Ayar/istatistik deposu | `src/store.js` |

## Test

- `npm test` → 35 uçtan uca kontrol (tarama, imza, YARA, arşiv, önbellek,
  paralel worker havuzu, şifreli karantina geri yükleme, bütünlük, Keychain
  anahtarı, güncelleme doğrulama, firewall DNS eşleşmesi, tarama geçmişi)
- `npm run test:unit` → 41 birim test (imza/YARA, önbellek, arşiv)
- `test/bench-scan.js` → paralel tarama hız karşılaştırması
- Tarama sayfasındaki **"EICAR test dosyası oluştur"** düğmesi: tarama bunu
  `EICAR-Test-File` olarak bulup karantinaya almalıdır. (Bu makinede Avast
  dosyayı bazen bizden önce yakalar → test `SKIP` olur; bu normaldir.)

## Eksikler / yol haritası (dürüst durum)

### 🔴 Apple onayı gerektirir (Evre 2 — kod hazır, yetki bekliyor)

1. **Gerçek zamanlı kalkan** — `native-daemon/AegisShield.swift` tam kod;
   `com.apple.developer.endpoint-security.client` yetkisi Apple Developer
   portal başvurusu ister
2. **Gerçek paket engelleme** — `AegisFirewall.swift` (NEFilterDataProvider);
   `com.apple.developer.networkextension.network-filter` yetkisi ister
3. **Süreç/kendi kendini koruma (anti-tamper)** — `pkill` engelleme ve dosya
   bütünlüğü koruması da native yetki (SIP/ES) ister

### 🟡 Dağıtım öncesi (sertifika / kullanıcı izni)

4. **Kod imzası + notarization** — `electron-builder` + `build/entitlements.mac.plist`
   hazır; **Developer ID sertifikası** şart (yoksa macOS "hasarlı" uyarısı)
5. **Tam Disk Erişimi (TCC)** — UI'da rehber butonu var; ilk kurulumda akış
   olarak istenmeli (Ayarlar → Gizlilik ve Güvenlik)
6. **Gerçek imza istihbaratı** — şu an demo hash + örnek YARA kuralları;
   gerçek tehdit beslemesi (ör. açık imza kaynakları) + Ed25519 ile imzalı
   yayın gerekiyor (yan dosya özeti yalnızca bozulmayı değil, saldırıyı da
   engellemek için asimetrik imza ister)
7. **Otomatik uygulama güncellemesi** — `electron-updater` entegrasyonu
8. **Uygulama kapanınca da çalışan zamanlanmış tarama** — launchd plist
   iskeleti (README: `native-daemon/` içinde)

### 🟢 İyileştirme fırsatları (yerel yapılabilir)

9. **Arşiv taraması derinliği** — içindeki iç içe arşivler şimdilik taramaz
   (tek katman); recursive tarama + toplam bütçe eklenebilir
10. **Alan adı bazlı phishing engelleme** — Evre 1'de domain kuralları DNS ile
    çözülüp IP üzerinden eşleşir; bağlantı öncesi hostname engeli NEFilter ister
11. **.dmg/.pkg kurulum paketi taraması** — hdiutil ile bağlama desteği yok
12. **Tarama önbelleği için değişen dosya imzası (ssdeep benzeri)** — parçalı
    hash ile hızlı yaklaşık eşleşme
13. **Uygulama/HTML ikinci dil testi + çevirinin tam senkronu** — TR/EN
    eklendi; üçüncü dil için sözlük genişletilmeli
14. **Etkinlik/olay akışı dışa aktarma** (JSON/CSV) — tarama geçmişi
    dışa aktarılabilir; etkinlik akışı henüz dışa aktarılamıyor

> Tamamlananlar: karantina anahtarı Keychain'e taşındı, paralel (worker)
> tarama eklendi, tarama geçmişi + JSON/CSV dışa aktarma eklendi.

## Dikkat

- Bu proje **eğitim/geliştirme** amaçlıdır. Gerçek dağıtım için kod imzası,
  notarization ve Apple yetkileri (endpoint-security, network-filter) gerekir.
- Kullanıcı bilgilendirmesi ve gizlilik politikası olmadan dosya taraması
  yapmak macOS TCC kurallarına takılır (Tam Disk Erişimi izni gerekir).
- Fidye izleyici kapalıysa yem dosyaları temizlenir; açıkken
  `Aegis-Korumali-Dosya.txt` adlı dosyalar Belgeler/Masaüstü'ne yerleştirilir.
