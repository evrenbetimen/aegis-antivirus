// Dosya tarayıcı: imza veritabanını yükler ve tek bir dosyayı tarar.
// src/signatures.js load()/checkFile() ve src/filescan.js ile aynı sıra:
//   1) SHA-256 imza eşleşmesi (dosya ≤ 1 GB ise)
//   2) YARA kuralları (ilk 2 MB + büyük dosyalarda son 256 KB)
//   3) EICAR test dizgisi (≤ 2 KB dosyalar)
#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "yara.h"

namespace aegis {

constexpr size_t kStringScanLimit = 2 * 1024 * 1024;
constexpr size_t kTailScanSize = 256 * 1024;
constexpr unsigned long long kMaxHashSize = 1024ULL * 1024 * 1024;

struct Database {
  std::string version = "0";
  std::unordered_map<std::string, std::string> sha256;  // küçük harf özet → tehdit adı
  std::vector<yara::Rule> rules;
  std::vector<std::string> skipped;  // "dosya: kural: hata"
};

// signaturesDir/db.json + signaturesDir/rules.yar. Eksik dosyalar sorun değil;
// okunamayan/bozuk dosyalar skipped listesine yazılır.
Database LoadDatabase(const std::string& dir);

// Kural metnini veritabanına ekler (dosya adı yalnızca hata iletileri için).
void AddRules(Database* db, const std::string& text, const std::string& label);

struct ScanResult {
  bool ok = true;        // dosya okunabildi mi
  std::string error;     // ok == false ise
  std::string sha256;    // hesaplandıysa
  bool infected = false;
  std::string threat;    // tehdit adı
  std::string kind;      // "sha256" | "yara" | "eicar"
  unsigned long long size = 0;
};

ScanResult ScanFile(const Database& db, const std::string& path);

}  // namespace aegis
