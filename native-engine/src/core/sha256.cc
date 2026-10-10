#include "sha256.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <vector>

namespace aegis {
namespace {

constexpr uint32_t kK[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline uint32_t Rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

constexpr size_t kChunk = 1024 * 1024;

}  // namespace

Sha256::Sha256() : bit_len_(0), buffer_len_(0) {
#if defined(AEGIS_SHA256_COMMONCRYPTO)
  CC_SHA256_Init(&cc_);
#endif
  static const uint32_t kInit[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  std::memcpy(state_, kInit, sizeof(state_));
}

void Sha256::Transform(const uint8_t block[64]) {
  uint32_t w[64];
  for (int i = 0; i < 16; ++i) {
    w[i] = (uint32_t(block[i * 4]) << 24) | (uint32_t(block[i * 4 + 1]) << 16) |
           (uint32_t(block[i * 4 + 2]) << 8) | uint32_t(block[i * 4 + 3]);
  }
  for (int i = 16; i < 64; ++i) {
    uint32_t s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
  uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
  for (int i = 0; i < 64; ++i) {
    uint32_t S1 = Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25);
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t t1 = h + S1 + ch + kK[i] + w[i];
    uint32_t S0 = Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = S0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::Update(const uint8_t* data, size_t len) {
#if defined(AEGIS_SHA256_COMMONCRYPTO)
  while (len > 0) {
    const CC_LONG take = len > 0x40000000 ? 0x40000000 : static_cast<CC_LONG>(len);
    CC_SHA256_Update(&cc_, data, take);
    data += take;
    len -= take;
  }
  return;
#endif
  bit_len_ += uint64_t(len) * 8;
  if (buffer_len_ > 0) {
    size_t take = 64 - buffer_len_;
    if (take > len) take = len;
    std::memcpy(buffer_ + buffer_len_, data, take);
    buffer_len_ += take;
    data += take;
    len -= take;
    if (buffer_len_ == 64) {
      Transform(buffer_);
      buffer_len_ = 0;
    }
  }
  while (len >= 64) {
    Transform(data);
    data += 64;
    len -= 64;
  }
  if (len > 0) {
    std::memcpy(buffer_, data, len);
    buffer_len_ = len;
  }
}

void Sha256::Final(uint8_t out[32]) {
#if defined(AEGIS_SHA256_COMMONCRYPTO)
  CC_SHA256_Final(out, &cc_);
  return;
#endif
  uint64_t bits = bit_len_;
  uint8_t pad[72] = {0x80};
  size_t pad_len = (buffer_len_ < 56) ? (56 - buffer_len_) : (120 - buffer_len_);
  uint8_t len_be[8];
  for (int i = 0; i < 8; ++i) len_be[i] = uint8_t(bits >> (56 - 8 * i));
  Update(pad, pad_len);
  Update(len_be, 8);
  for (int i = 0; i < 8; ++i) {
    out[i * 4] = uint8_t(state_[i] >> 24);
    out[i * 4 + 1] = uint8_t(state_[i] >> 16);
    out[i * 4 + 2] = uint8_t(state_[i] >> 8);
    out[i * 4 + 3] = uint8_t(state_[i]);
  }
}

std::string Sha256::HexDigest() {
  static const char kHex[] = "0123456789abcdef";
  uint8_t digest[32];
  Final(digest);
  std::string hex(64, '0');
  for (int i = 0; i < 32; ++i) {
    hex[i * 2] = kHex[digest[i] >> 4];
    hex[i * 2 + 1] = kHex[digest[i] & 0x0f];
  }
  return hex;
}

std::string Sha256Hex(const uint8_t* data, size_t len) {
  Sha256 h;
  h.Update(data, len);
  return h.HexDigest();
}

bool Sha256File(const char* path, std::string* hex, int* err) {
  FILE* f = std::fopen(path, "rb");
  if (!f) {
    *err = errno;
    return false;
  }
  std::vector<uint8_t> buf(kChunk);
  Sha256 h;
  for (;;) {
    size_t n = std::fread(buf.data(), 1, buf.size(), f);
    if (n > 0) h.Update(buf.data(), n);
    if (n < buf.size()) {
      if (std::ferror(f)) {
        *err = errno ? errno : EIO;
        std::fclose(f);
        return false;
      }
      break;
    }
  }
  std::fclose(f);
  *hex = h.HexDigest();
  return true;
}

}  // namespace aegis
