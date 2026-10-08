# Aegis Native Daemon — macOS sistem genişletmeleri (Swift)

Electron tarafı yalnızca **arayüz, tarama ve kural yönetimi** yapar. Sistem
genelinde dosya/bağlantı izleme ve engelleme, macOS'un yalnızca imzalı
**sistem genişletmelerine** açık tuttuğu iki API ile buradaki Swift
dosyalarında yapılır:

| Modül | Dosya | Görev | Gereken yetki |
|---|---|---|---|
| **Gerçek zamanlı kalkan** | `AegisShield.swift` | Endpoint Security ile exec/open/mutation olayları, imza denetimi, SHA-256, engelleme | `com.apple.developer.endpoint-security.client` |
| **Gerçek firewall** | `AegisFirewall.swift` | `NEFilterDataProvider` ile yeni akışları kural listesine göre allow/drop | `com.apple.developer.networking.networkextension` (content filter) |

| Destek dosyası | Görev |
|---|---|
| `Info.plist` | İki hedef için ortak bilgi sözlüğü şablonu (ayrıştırma talimatları §4.2'de) |
| `entitlements.plist` | İki hedef için yetki (entitlement) anahtarları |
| `README.md` | Bu belge (Türkçe) |

Kod yorumları **İngilizce**'dir; yalnızca kullanıcıya dönük bu belge
Türkçedir. Her `.swift` dosyası tek başına derlenebilecek şekilde
kendi `@main` giriş noktasına sahiptir (`AegisShieldMain`,
`AegisFirewallMain`).

---

## 1. Neden native?

macOS, güvenlik yazılımlarının sistem genelinde izleme yapması için üç şeyi
zorunlu tutar:

1. **Endpoint Security** — eski `kext` yerine modern, imzalı, kullanıcı
   alanında çalışan API. Node.js/Electron bunlara abone olamaz.
2. **Sistem genişletmesi** — yüklenmesi ve çalıştırılması kullanıcının
   Sistem Ayarları'ndan onayını gerektirir; SIP kapatılamaz.
3. **Apple onayı** — aşağıdaki yetkiler sıradan bir Developer ID ile
   verilmez; Apple'a başvuru (entitlement talebi) gerekir.

Aynı sınırlar firewall için de geçerlidir: `NEFilterDataProvider`
yalnızca bir sistem genişletmesi içinde çalışır.

---

## 2. Olay ve IPC şeması (UNIX domain socket)

Genişletmeler ile Electron ana süreç arasındaki tek kanal **satır sonu JSON**
durumundaki bir UNIX domain socket'idir:

```
varsayılan yol : /Library/Application Support/Aegis/aegis.sock
override       : AEGIS_IPC_SOCKET=/yeni/yol
```

Kurallar:

* Bağlantı kurulduğunda **her olay = bir satır = bir JSON nesnesi**, satır
  sonu `0x0A`.
* Yön **tek yönlüdür**: genişletme → Electron. Geriye yanıt yok; politika ve
  kural değişiklikleri dosyalar üzerinden yapılır (§3).
* Socket'e bağlanılamıyorsa olay **sessizce atılır** (UI'ı bloke etmek yok),
  istemci **5 saniyede bir** yeniden bağlanmayı dener, tek yazma işlemi en
  fazla **200 ms** sürer (`SO_SNDTIMEO`, `SO_NOSIGPIPE`).
* Tüm nesnelerde ortak alanlar: `v` (şema sürümü, `1`), `ts` (ISO-8601),
  `source` (`shield` | `firewall`), `event`.

### 2.1 `event: "exec"` (kalkan)

```json
{"v":1,"ts":"2026-10-02T04:21:07Z","source":"shield","event":"exec",
 "verdict":"deny","reason":"signature-hit","threat":"EICAR-Test-File",
 "pid":4821,"ppid":4810,"uid":501,
 "path":"/Users/ali/Downloads/evil.bin",
 "args":["/Users/ali/Downloads/evil.bin","--silent"],
 "cwd":"/Users/ali/Downloads",
 "signingID":"com.example.evil","teamID":"ABCD123456",
 "platformBinary":false,
 "sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
```

| Alan | Anlamı |
|---|---|
| `verdict` | `allow` / `deny` — verilen cevap |
| `reason` | `platform-binary`, `allow-path`, `deny-path`, `signature-hit`, `unsigned-binary`, `protected-path-write`, `protected-path-mutation`, `shield-disabled` |
| `threat` | Yalnızca imza veritabanında eşleşen dosyalarda (§3.2) |
| `sha256` | Yalnızca `hashing` politikası açıksa ve dosya boyutu sınırın altındaysa |
| `args` | En fazla 32 argv girdisi, mesaj tamponundan kopyalanmış |

### 2.2 `event: "flow-block"` (firewall)

```json
{"v":1,"ts":"2026-10-02T04:21:09Z","source":"firewall","event":"flow-block",
 "verdict":"deny","host":"doubleclick.net","port":443,"proto":"tcp",
 "endpointResolved":true,"rule":"r1","direction":1,"sourcePid":5120}
```

| Alan | Anlamı |
|---|---|
| `host` / `port` | Uzak uç nokta; çözülememişse `host:""`, `port:0` |
| `endpointResolved` | `false` ise host/port kuralı eşleşememiştir (yalnız `proto` kuralları geçerli) |
| `rule` | Eşleşen kuralın `id` değeri |
| `direction` | `NEFilterDirection` hammad değeri (1 = outbound) |
| `sourcePid` | Uygulamanın audit token'ından okunan PID (best effort) |
| `url` | Yalnızca akışta URL varsa |

> Kalkan ayrıca yalnızca **bildirim** amaçlı `NOTIFY_EXEC` mesajlarını da
> `verdict:"allow"`, `reason` alanı olmadan yayınlar (izleme modu).

### 2.3 Electron tarafı (`src/native-bridge.js`)

Electron ana süreci macOS'ta açılışta socket sunucusunu başlatır:

* Socket **`~/Library/Application Support/aegis-antivirus/aegis.sock`**
  (Electron `userData`), izin `0600`. Electron oturum açan kullanıcıda
  çalıştığı için kök sahipli `/Library/Application Support/Aegis/`
  klasörüne yazamaz. Genişletmeler kanonik socket yoksa
  `/Users/*/Library/Application Support/*/aegis.sock` adaylarını dener
  (`socketCandidates()`); root olduklarından `0600` socket'e bağlanabilirler,
  başka kullanıcılar bağlanamaz.
* Her satır şemaya göre doğrulanır (`v:1`, bilinen `source`/`event`), en
  fazla 64 KB satır, en fazla 4 eşzamanlı bağlantı. Bozuk satırlar sayılıp
  atılır.
* `exec` + `verdict:"deny"` → etkinlik akışında "Kalkan engelledi" kaydı +
  bildirim. `flow-block` → host başına dakikada en fazla bir kayıt.
  Olaylar yalnızca bilgi amaçlıdır, karantina gibi bir eylemi tetiklemez.
* Ayarlar'daki **Gerçek zamanlı kalkan** anahtarı
  `userData/shield-policy.json` içindeki `enabled` alanına yazılır;
  genişletme bu dosyayı 2 saniyede bir okur. İmza veritabanı da zaten
  `userData/signatures/db.json`'dadır, böylece imzalı saatlik güncellemeler
  kalkana da ulaşır.
* Dashboard'daki kalkan durumu, bağlı bir genişletme varsa veya son 10
  dakikada olay geldiyse **Aktif** olur.

---

## 3. Yapılandırma dosyaları

Tüm yolların environment override'ı vardır; genişletme kurulduğunda sabit
yolları kullanır (override'lar elle çalıştırmada/gelecekteki launchd
yapılandırmasında geçerlidir).

| Ne | Varsayılan yol | Override |
|---|---|---|
| IPC socket | `/Library/Application Support/Aegis/aegis.sock`, yoksa `~/Library/Application Support/*/aegis.sock` | `AEGIS_IPC_SOCKET` |
| Kalkan politikası | `/Library/Application Support/Aegis/shield-policy.json` | `AEGIS_POLICY` |
| İmza veritabanı | `/Library/Application Support/Aegis/signatures/db.json` | `AEGIS_SIGNATURE_DB` |
| Firewall kuralları | `/Library/Application Support/Aegis/firewall-rules.json` | `AEGIS_RULES_FILE` |
| Firewall kurulumu | (otomatik) | `AEGIS_SKIP_FILTER_SETUP=1` → `NEFilterManager` ayarını atla |

Klasör yokluğunda kalkan ve firewall, `/Users/*` altındaki
`Library/Application Support/*` dizinlerinde de arama yapar; firewall
özellikle Electron'un gerçekte yazdığı `aegis-store.json` dosyasını bu
şekilde bulur (§3.3).

### 3.1 `shield-policy.json`

Dosya **2 saniyede bir** yeniden okunur; eksik alanlar varsayılana döner,
dosyanın hiç olmaması korumayı kapatmaz.

```json
{
  "enabled": true,
  "denyUnsigned": false,
  "hashing": true,
  "maxHashBytes": 16777216,
  "denyPaths": ["/private/tmp/", "/var/tmp/"],
  "allowPaths": [],
  "protectedPaths": ["/Library/Preferences/", "/System/Library/"]
}
```

| Alan | Varsayılan | Anlamı |
|---|---|---|
| `enabled` | `true` | `false` → engelleme yok, telemetri devam eder |
| `denyUnsigned` | `false` | `true` → tam imza denetimi geçemeyen binary'yi reddet |
| `hashing` | `true` | exec hedefinin SHA-256'sını hesapla + imza DB'sine bak |
| `maxHashBytes` | 16 MB | Bu boyuttan büyük dosyalar hash'lenmez (ES deadline koruması) |
| `denyPaths` | `/private/tmp/`, `/var/tmp/` | Bu öneklerdeki exec hedefleri reddedilir |
| `allowPaths` | `[]` | Hızlı geçiş: hiç denetlenmez |
| `protectedPaths` | tercihler/system klasörleri | Root olmayan süreçlerin yazamayacağı dizinler (create/unlink/rename/truncate/open-W) |

### 3.2 `signatures/db.json`

Birebir Electron'un `src/signatures.js` / `src/dbupdate.js` kullandığı
biçim:

```json
{
  "version": "2026.10.1",
  "updated": 0,
  "sha256": {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File"
  }
}
```

* Anahtarlar **küçük harf hex SHA-256**, değer tehdit adı.
* `version` string veya number olabilir; dosya **5 saniyede bir** yeniden
  okunur, böylece Electron imza DB güncellediğinde genişletme fark eder.
* **Eksik iş:** paket içindeki `signatures/db.json` Electron kaynak
  dizinindedir, genişletmenin okuduğu yolda değildir. Electron'un bu dosyayı
  `/Library/Application Support/Aegis/signatures/` altına kopyalaması (veya
  `AEGIS_SIGNATURE_DB` vermesi) gerekir — aksi halde hash'ler ama hiçbir
  zaman "tehdit" eşleşmez.

### 3.3 Firewall kural listesi

İki biçim de kabul edilir (dosya **2 saniyede bir** yeniden okunur):

1. Dizi: `[{"id":"r1", ...}, ...]` → `/Library/Application Support/Aegis/firewall-rules.json`
2. Belge: `{"rules":[...]}` → `aegis-store.json` (`src/store.js`'in yazdığı
   dosya, `~/Library/Application Support/<uygulama>/` altında otomatik taranır)

```json
[
  {"id":"r1","type":"block","proto":"tcp","host":"doubleclick.net","port":null,"note":"Reklam ağı"},
  {"id":"r3","type":"allow","proto":"tcp","host":"api.aegis.local","port":443,"note":"Güncelleme"}
]
```

Eşleme semantiği `src/firewall.js` ile aynıdır:

* **Öncelik:** eşleşen bir `allow` kuralı varsa akış **izin görür**; aksi
  halde eşleşen ilk `block` kuralı engeller; **varsayılan = izin**.
* `proto`: `tcp`, `udp`, `tcp,udp`, `*` / `any` (boş = hepsi).
* `host`: tam eşleşme, son ek (`.suffix`), alt alan adı (`*.example.com`) veya
  alt dize eşleşmesi — hepsi `src/firewall.js`'deki gibi.
* `port`: `null` / `0` / eksik = "herhangi bir port"; `flowPort` bilinmiyor
  (0) ise port kuralı **eşleşmez** (onaylanamayan şey engellenmez).
* `type` alanı yoksa `block` sayılır, `id` yoksa üretilir.

---

## 4. Xcode hedeflerinin kurulumu (Xcode 27 ile doğrulandı)

Bu makinede hazır sistem genişletmesi **şablonları** vardır; şablon yolunu
doğrulamak için:

```
/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/
  Library/Xcode/Templates/Project Templates/macOS/System Extension/
    Endpoint Security Extension.xctemplate
    Network Extension.xctemplate
    System Extension Base.xctemplate
```

### 4.1 Hedefleri oluştur

1. `File → New → Project → macOS` ve şablon listesinde **System Extension**
   (Endpoint Security Extension / Network Extension öğeleri).
2. **AegisShield** hedefi: *Endpoint Security Extension*, dil **Swift**.
   Şablon `libEndpointSecurity.tbd`'yi ve
   `com.apple.developer.endpoint-security.client` yetkili dosyasını kendisi
   ekler; ayrıca `main.swift` üretir.
3. **AegisFirewall** hedefi: *Network Extension*, **Provider Type: Filter
   Data** (`com.apple.networkextension.filter-data`), dil **Swift**.
   Şablon `FilterDataProvider.swift` + `main.swift` üretir.
4. **`main.swift` dosyalarını silin.** Bizim dosyalarımız `@main` ile kendi
   giriş noktasına sahiptir; hedefte `main.swift` varsa derleme şunu verir:
   `'main' attribute cannot be used in a module that contains top-level code`.
   (Alternatif: `@main`'i silip `main.swift` içinden `AegisShieldMain.main()`
   / `AegisFirewallMain.main()` çağırın.)
5. Şablonun ürettiği `AegisShield.swift` / `FilterDataProvider.swift` /
   `AppDelegate` benzeri örnek dosyaları hedeften çıkarıp yerine
   `native-daemon/AegisShield.swift` (resp. `AegisFirewall.swift`) dosyalarını
   ekleyin: **hedef başına tek Swift dosyası**.

### 4.2 Build Settings (hedef başına)

| Ayar | AegisShield | AegisFirewall |
|---|---|---|
| `PRODUCT_BUNDLE_IDENTIFIER` | `com.aegis.antivirus.shield` | `com.aegis.antivirus.firewall` |
| `INFOPLIST_FILE` | `native-daemon/AegisShield-Info.plist` | `native-daemon/AegisFirewall-Info.plist` |
| `CODE_SIGN_ENTITLEMENTS` | `native-daemon/AegisShield.entitlements` | `native-daemon/AegisFirewall.entitlements` |
| `MACOSX_DEPLOYMENT_TARGET` | `13.0` | `13.0` (uygulama 15.0 ise `15.0`) |
| `ENABLE_APP_SANDBOX` | `NO` | `NO` |
| `SWIFT_VERSION` | `5.0` (veya `6.0`) | `5.0` (veya `6.0`) |
| `CODE_SIGN_STYLE` / Team | Automatic + kendi Team ID'niz | aynı |
| Framework'ler | `EndpointSecurity` (şablon ekler), `Security`, `CryptoKit` | `NetworkExtension`, `Network` |

**Info.plist ayrıştırma:** `native-daemon/Info.plist` tek dosyalık bir
**şablon**tur, iki hedefin ikisine birden verilemez. Şablonun içindeki
yorumlara uyarak ayırın:

* `AegisShield-Info.plist` = ortak anahtarlar + `NSExtension`
  (`NSExtensionPointIdentifier = com.apple.system-extension.endpoint-security`)
  → `NetworkExtension` sözlüğünü **silin**.
* `AegisFirewall-Info.plist` = ortak anahtarlar + `NetworkExtension` →
  `NEProviderClasses > com.apple.networkextension.filter-data = AegisFirewall`.
  Değer, `AegisFirewall.swift` içindeki `@objc(AegisFirewall)` adına birebir
  eşleşmelidir (Swift modül adına güvenmeyin). `NSExtension` bloğu bu hedefte
  gerekmez.
* `CFBundlePackageType = SYSX` olmalıdır (gerçek sistem genişletmelerinde
  doğrulandı). `NSSystemExtensionUsageDescription` **ana uygulamada** da
  bulunmalıdır.

**Entitlements:** `native-daemon/entitlements.plist` iki hedef için de
tek dosya olarak bırakılabilir (kullanılmayan anahtarlar codesign tarafından
sessizce yok sayılır) ya da hedeflere bölünebilir:

* `AegisShield.entitlements` → `com.apple.developer.endpoint-security.client`
* `AegisFirewall.entitlements` → `com.apple.developer.networking.networkextension`
  = `["content-filter-provider-systemextension", "content-filter-provider"]`
  (+ isteğe bağlı `com.apple.developer.networkextension.network-filter`,
  bkz. dosya içi yorum).

Ana Electron hedefinde (`build/entitlements.mac.plist`) bu anahtarların
**ana uygulama için de** bulunması gerekir: sistem genişletmesi, yetkileri
**kendi içinde** taşır, ancak imzalayıcı ve takım kimliği uygulamayla aynı
olmalıdır.

---

## 5. Apple Developer portalı ve imzalama

1. Apple Developer Account → **Certificates, Identifiers & Profiles →
   Identifiers** → uygulamanızın App ID'si (`com.aegis.antivirus`).
2. **Capabilities** sekmesinde anahtarları açın:
   * *Endpoint Security Client* (`com.apple.developer.endpoint-security.client`)
     — **Apple onayı gerektirir**; listede görünmüyorsa sistem genişletmesi
     entitlement talebini Apple'a gönderin ve onayı bekleyin.
   * *Network Extensions* (`com.apple.developer.networking.networkextension`)
     için `content-filter-provider(-systemextension)` değeri.
3. Genişletme bundle ID'leri App ID'nin **altında** olmalıdır
   (`com.aegis.antivirus.shield`, `com.aegis.antivirus.firewall`).
4. **Provisioning profile:** kısıtlı (restricted) entitlement'lar, Mac App
   Store dışında (**Developer ID**) dağıtımda da **provisioning profile**
   ister. Xcode ile takımınızı seçtiğinde profili otomatik indirir; indirilen
   profil hem ana uygulamaya hem `.systemextension`'a gömülür.
5. Ana uygulama `package.json` içinde `hardenedRuntime: true` ile
   `electron-builder --mac` ile imzalanır/notarize edilir. `native-daemon`
   çıktıları **imzalı** olmalıdır; ad-hoc imzalı (`-`) genişletme
   `es_new_client` → `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED` verir.

---

## 6. Derleme, yerleştirme, kurulum

### 6.1 Derleme

```sh
xcodebuild -project Aegis.xcodeproj -scheme AegisShield \
  -configuration Release -derivedDataPath build build
xcodebuild -project Aegis.xcodeproj -scheme AegisFirewall \
  -configuration Release -derivedDataPath build build
# çıktılar:
#   build/Build/Products/Release/AegisShield.systemextension
#   build/Build/Products/Release/AegisFirewall.systemextension
```

### 6.2 Ana uygulamaya yerleştirme

Sistem genişletmeleri **yalnızca** şu yoldan yüklenir:

```
Aegis.app/Contents/Library/SystemExtensions/<ad>.systemextension
```

`electron-builder` için `build.mac.extraFiles` ile `Contents/` altına
kopyalanabilir:

```json
"extraFiles": [
  { "from": "native-daemon/build/Release/AegisShield.systemextension",
    "to": "Library/SystemExtensions/AegisShield.systemextension" },
  { "from": "native-daemon/build/Release/AegisFirewall.systemextension",
    "to": "Library/SystemExtensions/AegisFirewall.systemextension" }
]
```

### 6.3 Kurulum / etkinleştirme

* **Yöntem 1 (üretim):** ana uygulama `OSSystemExtensionRequest.activationRequest`
  çağırır; kullanıcı Sistem Ayarları'nda onaylar.
  **Eksik iş:** `main.js`'te bu çağrı henüz yok.
* **Yöntem 2 (geliştirme, Xcode):** genişletme hedefini Xcode'dan
  **Run** ettiğinizde Xcode genişletmeyi kendisi kurar ve etkinleştirir
  (içeren uygulamayı da kurar).
* `systemextensionsctl` **`install` / `activate` komutu YOKTUR**. Kullanılabilen
  fiiller yalnızca şunlardır:

```sh
systemextensionsctl developer on|off   # geliştirme modu (yalnız test makinesi!)
systemextensionsctl list [category]    # kurulu/etkin genişletmeler
systemextensionsctl reset              # tüm sistem genişletmesi durumunu sıfırla
systemextensionsctl uninstall <teamID> <bundleID>
systemextensionsctl gc                # yetim genişletmeleri topla
```

`list` çıktısındaki aktivasyon yolu:
`System Settings → General → Login Items & Extensions → Network Extensions`
(performans ve güvenlik filtreleri ayrıca **System Settings → Network**
altında açılıp kapatılabilir).

### 6.4 TCC / Full Disk Access

Kalkan, `es_new_client` sırasında `ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED`
alırsa **Full Disk Access** izni yoktur:

1. System Settings → Privacy & Security → Full Disk Access → `+`
2. İçeren uygulamayı (`Aegis.app`) **ve** genişletme binary'sini ekleyin
   (`Aegis.app/Contents/Library/SystemExtensions/AegisShield.systemextension`
   — Finder'da `Sağ tık → pkg içeriğini göster` ile gezinebilirsiniz).
3. Değişikliğin geçerli olması için genişletmeyi yeniden başlatın.

Kalkan ayrıca **root** olarak çalışmalıdır; yetki/TCC hatalarını
başlangıçta loglayıp `exit(EXIT_FAILURE)` ile çıkar (sessizce "açık"
gezmek istenmez).

---

## 7. Derleme kontrolü (bu makinede geçerli çıktı)

Dosyalar tek başına `-typecheck` ile doğrulanır:

```sh
cd native-daemon

# Kalkan
xcrun swiftc -typecheck -parse-as-library \
  -framework EndpointSecurity -framework Security -framework CryptoKit \
  AegisShield.swift

# Firewall
xcrun swiftc -typecheck -parse-as-library \
  -framework NetworkExtension -framework Network \
  AegisFirewall.swift
```

Ek olarak şunlar da **hata/uyarı vermez**:

```sh
xcrun swiftc -typecheck -parse-as-library -target arm64-apple-macos13.0 ... AegisShield.swift
xcrun swiftc -typecheck -parse-as-library -target arm64-apple-macos15.0 ... AegisShield.swift
xcrun swiftc -typecheck -parse-as-library -swift-version 6              ... AegisShield.swift
xcrun swiftc -typecheck -parse-as-library -warnings-as-errors           ... AegisShield.swift
# (aynı dördü AegisFirewall.swift için de)
```

Doğrulama ortamı ve sonuç:

```
Apple Swift version 6.4 (swiftlang-6.4.0.34.1 clang-2100.3.34.1)
Target: arm64-apple-macosx27.2.0   |  macOS 27.2  |  Xcode 27.0 (27A266a)

8 derleme = 8 × rc=0, çıktı yok (0 hata, 0 uyarı)
```

> Not: `-parse-as-library` **zorunludur**; `@main` içeren bir dosya
> `main.swift`'siz hedefte bu olmadan derlenmez.

### 7.1 Log'ları izleme

```sh
log stream --predicate 'subsystem == "com.aegis.antivirus.shield"' --info
log stream --predicate 'subsystem == "com.aegis.antivirus.firewall"' --info
```

Loglar `os.log` (`Logger`) üzerindendir; engelleme olayları Türkçe metinle
`ENGELLENDİ (...)` olarak düşer.

---

## 8. Electron tarafında eksik olan işler (dürüst liste)

Tamamlananlar (`src/native-bridge.js`, §2.3): socket sunucusu, olayların
etkinlik akışına ve bildirimlere iletilmesi, `realtimeEnabled` →
`shield-policy.json`, imza DB'sinin genişletmenin bulduğu yerde
(`userData/signatures/db.json`) tutulması, dashboard durumu.

Kalanlar:

1. **Kural dışa aktarımı yok** — `src/firewall.js` kuralları yalnızca
   `aegis-store.json` içinde tutuyor; firewall bunu `~/Library/Application
   Support/*/aegis-store.json` taramasıyla buluyor, bu yüzden çalışır;
   üretilmiş `firewall-rules.json` yok.
2. **Aktivasyon çağrısı yok** — `OSSystemExtensionRequest` kullanılmıyor,
   genişletme ancak Xcode'dan Run edilerek kuruluyor (§6.3). Bunun için
   uygulamanın içine gömülü bir Xcode sistem genişletmesi hedefi ve Apple
   yetkisi gerekir.

---

## 9. Dürüst sınırlar

* **SIP kapatılamaz, root zorunlu.** ES istemcisi root + Full Disk Access
  ister; firewall genişletmesi sistem tarafından root çalıştırılır.
* **İmzalama ve notarization zorunlu.** `hardenedRuntime: true` ile imzalanmış
  ad-hoc veya imzasız genişletme yetki hatası verir. Apple onayı alınmamış
  entitlement ile `codesign` imzalar, sistem **yüklemeyi reddeder**.
* **ES deadline.** AUTH mesajına süre içinde cevap verilmezse sistem istemciyi
  öldürür (varsayılan `ES_DEADLINE_MISS_MODE_KILL`; macOS 27+'ta kod
  `FAIL_CLOSED` seçiyor). Bu yüzden hash `maxHashBytes` ile sınırlıdır ve 20
  ms'yi geçen değerlendirmeler loglanır.
* **Firewall fail-open'dır.** Endpoint çözülemediyse (`endpointResolved:false`)
  host/port kuralları eşleşmez, yalnız `proto` kuralları uygulanır; durum bir
  kez loglanır. Hiçbir akış sessizce karartılmaz.
* **Alan adı kuralları IP akışlarında eşleşmez.** `NEFilterDataProvider`
  çoğunlukla IP/uç nokta verir; DNS çözümleme (firewall.js'in yaptığı gibi)
  genişletmede **yoktur**. Alan adı kuralı istiyorsanız Electron tarafında
  çözümlenip IP kuralı olarak yazın ya da kuralı IP ile verin.
* **Yalnızca yeni akışlar.** Filtre, açık olan mevcut bağlantıları geriye
  dönük kesmez; `NEFilterManager` ayarı kullanıcı onayı ister.
* **Kanal yönü.** Genişletme → Electron tek yönlüdür; politika/kural değişikliği
  dosyalar üzerinden yapılır (2–5 sn gecikmeli).
* **Bu depoda Xcode projesi yok.** `native-daemon/` içinde yalnız kaynak ve
  şablonlar vardır; `.xcodeproj` sizin tarafınızda oluşturulur (§4).
* **Çalışma biçimi:** genişletmeler `dispatchMain()` ile sonsuz döngüde kalır,
  `SIGINT`/`SIGTERM`/`SIGHUP` yakalanarak kalkan düzgün durdurulur
  (`es_delete_client` çağrılır).
