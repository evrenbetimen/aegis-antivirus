// SHA-256 (FIPS 180-4) — bağımsız, akış tabanlı uygulama.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#if defined(__APPLE__)
#include <CommonCrypto/CommonDigest.h>
#define AEGIS_SHA256_COMMONCRYPTO 1
#endif

namespace aegis {

// macOS'ta CommonCrypto (Apple Silicon/Intel donanım hızlandırmalı),
// diğer sistemlerde taşınabilir FIPS 180-4 uygulaması kullanılır.
constexpr bool kSha256Accelerated =
#if defined(AEGIS_SHA256_COMMONCRYPTO)
    true;
#else
    false;
#endif

class Sha256 {
 public:
  Sha256();
  void Update(const uint8_t* data, size_t len);
  // 32 baytlık özeti yazar; nesne bundan sonra yeniden kullanılmamalı.
  void Final(uint8_t out[32]);
  std::string HexDigest();

 private:
  void Transform(const uint8_t block[64]);

#if defined(AEGIS_SHA256_COMMONCRYPTO)
  CC_SHA256_CTX cc_;
#endif
  uint32_t state_[8];
  uint64_t bit_len_;
  uint8_t buffer_[64];
  size_t buffer_len_;
};

std::string Sha256Hex(const uint8_t* data, size_t len);

// Dosyayı 1 MB parçalarla okuyup özetler. Hata olursa false döner ve
// err'e errno değerini yazar.
bool Sha256File(const char* path, std::string* hex, int* err);

}  // namespace aegis
