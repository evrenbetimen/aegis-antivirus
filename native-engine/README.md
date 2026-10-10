# Aegis C++ tarama motoru

Norton ve McAfee gibi ticari antivirüslerde olduğu gibi Aegis'in tarama
çekirdeği de C++ ile yazılmıştır. Arayüz Electron'da (JavaScript), macOS
sistem genişletmeleri Swift'te (`native-daemon/`), tarama motoru C++17'dedir.

| Bileşen | Dil | Görev |
|---|---|---|
| `src/core/` | C++17 | YARA derleyici + eşleştirici, SHA-256, JSON okuyucu, dosya tarayıcı |
| `src/node/addon.cc` | C++ / Node-API | Electron'un yüklediği `aegis_engine.node` eklentisi |
| `src/cli/main.cc` | C++17 | `aegis-scan` komut satırı tarayıcısı |
| `tests/engine_tests.cc` | C++17 | Bağımlılıksız birim testleri (ctest) |
| `../src/signatures.js` | JavaScript | Referans uygulama ve yedek motor |

## Derleme

```bash
npm run build:native   # Electron eklentisi (node-gyp); macOS'ta arm64 + x86_64 evrensel
npm run build:cli      # aegis-scan + engine_tests (CMake)
npm run test:native    # C++ birim testleri
```

`npm install` sırasında eklenti otomatik derlenir. Derleyici yoksa kurulum
bozulmaz; uygulama JS referans motoruyla çalışır ve Ayarlar → Hakkında'da
hangi motorun kullanıldığı görünür.

Motor seçimi `AEGIS_ENGINE` ortam değişkeniyle zorlanabilir:
`native` (C++ zorunlu, yüklenemezse hata), `js` (her zaman JS), `auto` (varsayılan).

## Komut satırı tarayıcısı

```bash
aegis-scan --db ~/Library/Application\ Support/aegis-antivirus/signatures ~/Downloads
aegis-scan --json --db signatures dosya.zip klasor/
```

Çıkış kodları clamscan ile uyumludur: `0` temiz, `1` tehdit bulundu, `2` hata.
Sembolik bağlantılar izlenmez; erişilemeyen dizinler atlanır.

## Doğruluk güvencesi

C++ motoru JS referans motoruyla **birebir aynı** kararı verecek şekilde
yazılmıştır ve bu her CI çalışmasında ölçülür:

- `test/native-engine.test.js` rastgele üretilmiş 4000 kuralı (metin
  değiştiricileri, joker/atlama/alternatifli hex desenleri, aritmetik,
  bit işlemleri, sayaçlar, `at`, niceleyiciler) 12'şer tamponda iki motora
  verir ve kararları karşılaştırır; ayrıca rastgele belirteç çorbasıyla iki
  ayrıştırıcının aynı kuralları kabul/ret ettiğini doğrular. Yerelde
  `AEGIS_FUZZ_SEEDS=300000` ile 3,6 milyon karşılaştırma temiz geçti.
- Tüm mevcut birim testleri hem `AEGIS_ENGINE=native` hem `AEGIS_ENGINE=js`
  ile çalışır; Electron uçtan uca testi C++ motoruyla koşar.
- C++ birim testleri AddressSanitizer + UBSan ile Linux ve macOS'ta koşar.

## Performans

300 kural, 2 MB tampon (Linux, tek çekirdek): JS 585 ms → C++ 209 ms (2,8×).
SHA-256 macOS'ta CommonCrypto (donanım hızlandırmalı) ile C++'ta hesaplanır;
diğer sistemlerde taşınabilir uygulama OpenSSL'den yavaş olduğundan özetleme
Node'un OpenSSL'ine bırakılır.

## Güvenlik notları

- Ayrıştırıcı istisna fırlatmaz: bozuk ya da desteklenmeyen kural atlanır,
  taramayı asla durdurmaz.
- Eklenti bağlam farkındalıklıdır (`NAPI_MODULE_INIT`); tarama worker
  iş parçacıklarında da yüklenir ve paylaşılan durum tutmaz.
- `aegis-scan` imza dizinini olduğu gibi okur; yayıncı imzası doğrulaması
  uygulamanın güncelleme hattında (`src/dbupdate.js`) yapılır.
