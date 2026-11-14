/**
 * @file scp_crypto.hpp
 * @brief The chip model's own crypto: AES, AES-CMAC, SHA-256 and P-256, written independently of
 * the library's reference crypto (hardware-lessons rule on independent models, RD-07).
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Deliberately different from `inc/se05x_crypto.hpp`: the AES S-box is built at run time from
 * logarithm tables and indexed directly; the CMAC pads into a copy of the last block; SHA-256 keeps
 * a rolling 16-word schedule; P-256 multiplies limbs schoolbook and reduces with the NIST fast
 * reduction of FIPS 186 (D.2.3), and adds points in Jacobian coordinates with explicit doubling
 * and infinity cases. Nothing here is constant time: it is a test oracle, never product code. Both
 * implementations are pinned to the same public known-answer vectors in test_scp_crypto.cpp.
 */
#ifndef SE05X_TESTS_MODEL_SCP_CRYPTO_HPP
#define SE05X_TESTS_MODEL_SCP_CRYPTO_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace se05x::testmodel::mc {

using Bytes = std::span<const uint8_t>;

// ---------------------------------------------------------------------------------------------
// AES (FIPS 197) from log/antilog tables.
// ---------------------------------------------------------------------------------------------
class Aes {
public:
  Aes() {
    buildTables();
  }
  bool SetKey(Bytes key) {
    const std::size_t nk = key.size() / 4U;
    if ((key.size() != 16U) && (key.size() != 24U) && (key.size() != 32U)) {
      return false;
    }
    nr_ = nk + 6U;
    static_cast<void>(std::memcpy(w_.data(), key.data(), key.size()));
    uint8_t rc = 1U;
    for (std::size_t i = nk; i < (4U * (nr_ + 1U)); ++i) {
      uint8_t t[4];
      static_cast<void>(std::memcpy(t, &w_[4U * (i - 1U)], 4U));
      if ((i % nk) == 0U) {
        const uint8_t a = t[0];
        t[0] = static_cast<uint8_t>(sbox_[t[1]] ^ rc);
        t[1] = sbox_[t[2]];
        t[2] = sbox_[t[3]];
        t[3] = sbox_[a];
        rc = mul(rc, 2U);
      } else if ((nk == 8U) && ((i % nk) == 4U)) {
        for (uint8_t& v : t) {
          v = sbox_[v];
        }
      } else {
        // no substitution for this word
      }
      for (std::size_t j = 0U; j < 4U; ++j) {
        w_[(4U * i) + j] = static_cast<uint8_t>(unsigned{w_[(4U * (i - nk)) + j]} ^ unsigned{t[j]});
      }
    }
    return true;
  }
  void Encrypt(uint8_t* b) const {
    uint8_t s[16];
    static_cast<void>(std::memcpy(s, b, 16U));
    xorKey(s, 0U);
    for (std::size_t r = 1U; r <= nr_; ++r) {
      for (uint8_t& v : s) {
        v = sbox_[v];
      }
      uint8_t t[16];
      for (std::size_t c = 0U; c < 4U; ++c) {
        for (std::size_t row = 0U; row < 4U; ++row) {
          t[(4U * c) + row] = s[(4U * ((c + row) % 4U)) + row];
        }
      }
      if (r != nr_) {
        for (std::size_t c = 0U; c < 4U; ++c) {
          const uint8_t* a = &t[4U * c];
          s[(4U * c) + 0U] = xor4(mul(a[0], 2U), mul(a[1], 3U), a[2], a[3]);
          s[(4U * c) + 1U] = xor4(a[0], mul(a[1], 2U), mul(a[2], 3U), a[3]);
          s[(4U * c) + 2U] = xor4(a[0], a[1], mul(a[2], 2U), mul(a[3], 3U));
          s[(4U * c) + 3U] = xor4(mul(a[0], 3U), a[1], a[2], mul(a[3], 2U));
        }
      } else {
        static_cast<void>(std::memcpy(s, t, 16U));
      }
      xorKey(s, r);
    }
    static_cast<void>(std::memcpy(b, s, 16U));
  }
  void Decrypt(uint8_t* b) const {
    uint8_t s[16];
    static_cast<void>(std::memcpy(s, b, 16U));
    xorKey(s, nr_);
    for (std::size_t r = nr_; r >= 1U; --r) {
      uint8_t t[16];
      for (std::size_t c = 0U; c < 4U; ++c) {
        for (std::size_t row = 0U; row < 4U; ++row) {
          t[(4U * ((c + row) % 4U)) + row] = s[(4U * c) + row];
        }
      }
      for (std::size_t i = 0U; i < 16U; ++i) {
        s[i] = inv_[t[i]];
      }
      xorKey(s, r - 1U);
      if (r != 1U) {
        for (std::size_t c = 0U; c < 4U; ++c) {
          uint8_t a[4];
          static_cast<void>(std::memcpy(a, &s[4U * c], 4U));
          for (std::size_t row = 0U; row < 4U; ++row) {
            s[(4U * c) + row] = xor4(mul(a[row], 14U), mul(a[(row + 1U) % 4U], 11U),
                                     mul(a[(row + 2U) % 4U], 13U), mul(a[(row + 3U) % 4U], 9U));
          }
        }
      }
    }
    static_cast<void>(std::memcpy(b, s, 16U));
  }

private:
  static uint8_t xor4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return static_cast<uint8_t>(unsigned{a} ^ unsigned{b} ^ unsigned{c} ^ unsigned{d});
  }
  [[nodiscard]] uint8_t mul(uint8_t a, uint8_t b) const {
    if ((a == 0U) || (b == 0U)) {
      return 0U;
    }
    return exp_[(static_cast<unsigned>(log_[a]) + static_cast<unsigned>(log_[b])) % 255U];
  }
  void buildTables() {
    uint8_t x = 1U;
    for (unsigned i = 0U; i < 255U; ++i) {
      exp_[i] = x;
      log_[x] = static_cast<uint8_t>(i);
      // multiply by the generator 3: x * 2 xor x
      const auto x2 = static_cast<uint8_t>((unsigned{x} << 1U) ^
                                           (((unsigned{x} & 0x80U) != 0U) ? 0x1BU : 0x00U));
      x = static_cast<uint8_t>(unsigned{x2} ^ unsigned{x});
    }
    for (unsigned i = 0U; i < 256U; ++i) {
      const uint8_t inv = (i == 0U) ? 0U : exp_[(255U - log_[i]) % 255U];
      uint8_t s = inv;
      uint8_t r = inv;
      for (int k = 0; k < 4; ++k) {
        r = static_cast<uint8_t>((unsigned{r} << 1U) | (unsigned{r} >> 7U));
        s = static_cast<uint8_t>(s ^ r);
      }
      sbox_[i] = static_cast<uint8_t>(s ^ 0x63U);
    }
    for (unsigned i = 0U; i < 256U; ++i) {
      inv_[sbox_[i]] = static_cast<uint8_t>(i);
    }
  }
  void xorKey(uint8_t* s, std::size_t round) const {
    for (std::size_t i = 0U; i < 16U; ++i) {
      s[i] = static_cast<uint8_t>(unsigned{s[i]} ^ unsigned{w_[(16U * round) + i]});
    }
  }
  std::array<uint8_t, 256> sbox_{};
  std::array<uint8_t, 256> inv_{};
  std::array<uint8_t, 256> exp_{};
  std::array<uint8_t, 256> log_{};
  std::array<uint8_t, 240> w_{};
  std::size_t nr_{0};
};

/// AES-CBC with an IV; `iv` is updated.
inline bool CbcEncrypt(Bytes key, uint8_t* iv, uint8_t* data, std::size_t n) {
  Aes aes;
  if ((!aes.SetKey(key)) || ((n % 16U) != 0U)) {
    return false;
  }
  for (std::size_t off = 0U; off < n; off += 16U) {
    for (std::size_t i = 0U; i < 16U; ++i) {
      data[off + i] = static_cast<uint8_t>(data[off + i] ^ iv[i]);
    }
    aes.Encrypt(&data[off]);
    static_cast<void>(std::memcpy(iv, &data[off], 16U));
  }
  return true;
}

inline bool CbcDecrypt(Bytes key, uint8_t* iv, uint8_t* data, std::size_t n) {
  Aes aes;
  if ((!aes.SetKey(key)) || ((n % 16U) != 0U)) {
    return false;
  }
  for (std::size_t off = 0U; off < n; off += 16U) {
    uint8_t c[16];
    static_cast<void>(std::memcpy(c, &data[off], 16U));
    aes.Decrypt(&data[off]);
    for (std::size_t i = 0U; i < 16U; ++i) {
      data[off + i] = static_cast<uint8_t>(data[off + i] ^ iv[i]);
    }
    static_cast<void>(std::memcpy(iv, c, 16U));
  }
  return true;
}

/// One block AES encryption.
inline void EncryptBlock(Bytes key, uint8_t* block) {
  Aes aes;
  static_cast<void>(aes.SetKey(key));
  aes.Encrypt(block);
}

/// AES-CMAC (RFC 4493 section 2.4, written from the algorithm box).
inline void Cmac(Bytes key, Bytes msg, uint8_t* out16) {
  Aes aes;
  static_cast<void>(aes.SetKey(key));
  uint8_t l[16] = {};
  aes.Encrypt(l);
  auto shift = [](const uint8_t* in, uint8_t* o) {
    const bool msb = (in[0] & 0x80U) != 0U;
    for (int i = 0; i < 15; ++i) {
      o[i] = static_cast<uint8_t>((unsigned{in[i]} << 1U) | (unsigned{in[i + 1]} >> 7U));
    }
    o[15] = static_cast<uint8_t>(in[15] << 1U);
    if (msb) {
      o[15] = static_cast<uint8_t>(o[15] ^ 0x87U);
    }
  };
  uint8_t k1[16];
  uint8_t k2[16];
  shift(l, k1);
  shift(k1, k2);
  std::size_t n = (msg.size() + 15U) / 16U;
  bool full = true;
  if (n == 0U) {
    n = 1U;
    full = false;
  } else {
    full = (msg.size() % 16U) == 0U;
  }
  uint8_t last[16] = {};
  const std::size_t tail = msg.size() - (16U * (n - 1U));
  static_cast<void>(std::memcpy(last, msg.data() + (16U * (n - 1U)), tail));
  if (full) {
    for (int i = 0; i < 16; ++i) {
      last[i] = static_cast<uint8_t>(last[i] ^ k1[i]);
    }
  } else {
    last[tail] = 0x80U;
    for (int i = 0; i < 16; ++i) {
      last[i] = static_cast<uint8_t>(last[i] ^ k2[i]);
    }
  }
  uint8_t x[16] = {};
  for (std::size_t b = 0U; (b + 1U) < n; ++b) {
    for (int i = 0; i < 16; ++i) {
      x[i] = static_cast<uint8_t>(unsigned{x[i]} ^
                                  unsigned{msg[(16U * b) + static_cast<std::size_t>(i)]});
    }
    aes.Encrypt(x);
  }
  for (int i = 0; i < 16; ++i) {
    x[i] = static_cast<uint8_t>(x[i] ^ last[i]);
  }
  aes.Encrypt(x);
  static_cast<void>(std::memcpy(out16, x, 16U));
}

// ---------------------------------------------------------------------------------------------
// SHA-256 (FIPS 180-4), rolling schedule.
// ---------------------------------------------------------------------------------------------
inline void Sha256(Bytes msg, uint8_t* out32) {
  static const uint32_t kRound[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
      0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
      0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
      0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
      0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
      0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
      0xc67178f2};
  uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  auto rotr = [](uint32_t x, unsigned n) { return (x >> n) | (x << (32U - n)); };
  const std::size_t total = ((msg.size() + 9U + 63U) / 64U) * 64U;
  for (std::size_t off = 0U; off < total; off += 64U) {
    uint8_t blk[64];
    for (std::size_t i = 0U; i < 64U; ++i) {
      const std::size_t p = off + i;
      uint8_t v = 0U;
      if (p < msg.size()) {
        v = msg[p];
      } else if (p == msg.size()) {
        v = 0x80U;
      } else if (p >= (total - 8U)) {
        const uint64_t bits = static_cast<uint64_t>(msg.size()) * 8U;
        v = static_cast<uint8_t>(bits >> (8U * (total - 1U - p)));
      } else {
        v = 0U;
      }
      blk[i] = v;
    }
    uint32_t w[16];
    for (int i = 0; i < 16; ++i) {
      const std::size_t o = 4U * static_cast<std::size_t>(i);
      w[i] = (uint32_t{blk[o]} << 24U) | (uint32_t{blk[o + 1U]} << 16U) |
             (uint32_t{blk[o + 2U]} << 8U) | uint32_t{blk[o + 3U]};
    }
    uint32_t a = h[0];
    uint32_t b = h[1];
    uint32_t c = h[2];
    uint32_t d = h[3];
    uint32_t e = h[4];
    uint32_t f = h[5];
    uint32_t g = h[6];
    uint32_t hh = h[7];
    for (int t = 0; t < 64; ++t) {
      uint32_t wt = 0;
      if (t < 16) {
        wt = w[t];
      } else {
        const uint32_t w15 = w[static_cast<unsigned>(t - 15) & 15U];
        const uint32_t w2 = w[static_cast<unsigned>(t - 2) & 15U];
        const uint32_t s0 = rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >> 3);
        const uint32_t s1 = rotr(w2, 17) ^ rotr(w2, 19) ^ (w2 >> 10);
        wt = w[static_cast<unsigned>(t) & 15U] + s0 + w[static_cast<unsigned>(t - 7) & 15U] + s1;
        w[static_cast<unsigned>(t) & 15U] = wt;
      }
      const uint32_t t1 =
          hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + kRound[t] + wt;
      const uint32_t t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
      hh = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
  }
  for (int i = 0; i < 8; ++i) {
    const std::size_t o = 4U * static_cast<std::size_t>(i);
    out32[o] = static_cast<uint8_t>(h[i] >> 24U);
    out32[o + 1U] = static_cast<uint8_t>(h[i] >> 16U);
    out32[o + 2U] = static_cast<uint8_t>(h[i] >> 8U);
    out32[o + 3U] = static_cast<uint8_t>(h[i]);
  }
}

// ---------------------------------------------------------------------------------------------
// P-256 (FIPS 186): NIST fast reduction and Jacobian points.
// ---------------------------------------------------------------------------------------------
struct U256 {
  uint32_t w[8] = {}; // little endian words
};

inline int Cmp(const U256& a, const U256& b) {
  for (int i = 7; i >= 0; --i) {
    if (a.w[i] != b.w[i]) {
      return (a.w[i] > b.w[i]) ? 1 : -1;
    }
  }
  return 0;
}
inline uint32_t AddRaw(U256& r, const U256& a, const U256& b) {
  uint64_t c = 0;
  for (int i = 0; i < 8; ++i) {
    c += uint64_t{a.w[i]} + b.w[i];
    r.w[i] = static_cast<uint32_t>(c);
    c >>= 32;
  }
  return static_cast<uint32_t>(c);
}
inline uint32_t SubRaw(U256& r, const U256& a, const U256& b) {
  int64_t c = 0;
  for (int i = 0; i < 8; ++i) {
    c += int64_t{a.w[i]} - int64_t{b.w[i]};
    r.w[i] = static_cast<uint32_t>(c);
    c = (c < 0) ? -1 : 0; // the borrow
  }
  return (c != 0) ? 1U : 0U;
}
inline U256 FromBe(const uint8_t* b) {
  U256 r;
  for (int i = 0; i < 8; ++i) {
    const uint8_t* p = b + (4 * (7 - static_cast<std::ptrdiff_t>(i)));
    r.w[i] = (uint32_t{p[0]} << 24) | (uint32_t{p[1]} << 16) | (uint32_t{p[2]} << 8) | p[3];
  }
  return r;
}
inline void ToBe(const U256& a, uint8_t* b) {
  for (int i = 0; i < 8; ++i) {
    uint8_t* p = b + (4 * (7 - static_cast<std::ptrdiff_t>(i)));
    p[0] = static_cast<uint8_t>(a.w[i] >> 24);
    p[1] = static_cast<uint8_t>(a.w[i] >> 16);
    p[2] = static_cast<uint8_t>(a.w[i] >> 8);
    p[3] = static_cast<uint8_t>(a.w[i]);
  }
}
inline bool IsZero(const U256& a) {
  uint32_t acc = 0U;
  for (const uint32_t v : a.w) {
    acc |= v;
  }
  return acc == 0U;
}

inline const U256& PrimeP() {
  static const U256 kPrimeP{{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0, 1, 0xFFFFFFFF}};
  return kPrimeP;
}
inline const U256& OrderN() {
  static const U256 kOrderN{
      {0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0xFFFFFFFF}};
  return kOrderN;
}

inline U256 AddP(const U256& a, const U256& b) {
  U256 r;
  const uint32_t c = AddRaw(r, a, b);
  if ((c != 0U) || (Cmp(r, PrimeP()) >= 0)) {
    static_cast<void>(SubRaw(r, r, PrimeP()));
  }
  return r;
}
inline U256 SubP(const U256& a, const U256& b) {
  U256 r;
  if (SubRaw(r, a, b) != 0U) {
    static_cast<void>(AddRaw(r, r, PrimeP()));
  }
  return r;
}

/// a * b mod p: schoolbook product, then FIPS 186 D.2.3 fast reduction.
inline U256 MulP(const U256& a, const U256& b) {
  uint64_t c[16] = {};
  for (int i = 0; i < 8; ++i) {
    uint64_t carry = 0;
    for (int j = 0; j < 8; ++j) {
      const uint64_t t = c[i + j] + (uint64_t{a.w[i]} * b.w[j]) + carry;
      c[i + j] = t & 0xFFFFFFFFULL;
      carry = t >> 32;
    }
    c[i + 8] += carry;
  }
  // r = s1 + 2 s2 + 2 s3 + s4 + s5 - d1 - d2 - d3 - d4, words listed from the least significant.
  const int64_t cw[16] = {int64_t(c[0]),  int64_t(c[1]),  int64_t(c[2]),  int64_t(c[3]),
                          int64_t(c[4]),  int64_t(c[5]),  int64_t(c[6]),  int64_t(c[7]),
                          int64_t(c[8]),  int64_t(c[9]),  int64_t(c[10]), int64_t(c[11]),
                          int64_t(c[12]), int64_t(c[13]), int64_t(c[14]), int64_t(c[15])};
  int64_t r[8];
  r[0] = cw[0] + cw[8] + cw[9] - cw[11] - cw[12] - cw[13] - cw[14];
  r[1] = cw[1] + cw[9] + cw[10] - cw[12] - cw[13] - cw[14] - cw[15];
  r[2] = cw[2] + cw[10] + cw[11] - cw[13] - cw[14] - cw[15];
  r[3] = cw[3] + 2 * cw[11] + 2 * cw[12] + cw[13] - cw[15] - cw[8] - cw[9];
  r[4] = cw[4] + 2 * cw[12] + 2 * cw[13] + cw[14] - cw[9] - cw[10];
  r[5] = cw[5] + 2 * cw[13] + 2 * cw[14] + cw[15] - cw[10] - cw[11];
  r[6] = cw[6] + 3 * cw[14] + 2 * cw[15] + cw[13] - cw[8] - cw[9];
  r[7] = cw[7] + 3 * cw[15] + cw[8] - cw[10] - cw[11] - cw[12] - cw[13];
  // Propagate carries into a signed top word.
  int64_t carry = 0;
  U256 out;
  for (int i = 0; i < 8; ++i) {
    const int64_t v = r[i] + carry;
    out.w[i] = static_cast<uint32_t>(static_cast<uint64_t>(v) & 0xFFFFFFFFU);
    carry = (v - int64_t(out.w[i])) / int64_t{0x100000000};
  }
  // out + carry * 2^256; 2^256 = 2^224 - 2^192 - 2^96 + 1 (mod p).
  while (carry != 0) {
    U256 t{};
    const int64_t k = carry;
    int64_t add[8] = {k, 0, 0, -k, 0, 0, -k, k};
    int64_t cc = 0;
    for (int i = 0; i < 8; ++i) {
      const int64_t v = int64_t(out.w[i]) + add[i] + cc;
      t.w[i] = static_cast<uint32_t>(static_cast<uint64_t>(v) & 0xFFFFFFFFU);
      cc = (v - int64_t(t.w[i])) / int64_t{0x100000000};
    }
    out = t;
    carry = cc;
  }
  while (Cmp(out, PrimeP()) >= 0) {
    static_cast<void>(SubRaw(out, out, PrimeP()));
  }
  return out;
}

/// a * b mod m by double-and-add (generic, slow; used for the few scalar operations mod n).
inline U256 MulMod(const U256& a, const U256& b, const U256& m) {
  U256 r{};
  for (unsigned i = 256U; i > 0U; --i) {
    const unsigned bit = i - 1U;
    U256 d;
    uint32_t c = AddRaw(d, r, r);
    if ((c != 0U) || (Cmp(d, m) >= 0)) {
      static_cast<void>(SubRaw(d, d, m));
    }
    r = d;
    if (((b.w[bit / 32U] >> (bit % 32U)) & 1U) != 0U) {
      U256 s;
      c = AddRaw(s, r, a);
      if ((c != 0U) || (Cmp(s, m) >= 0)) {
        static_cast<void>(SubRaw(s, s, m));
      }
      r = s;
    }
  }
  return r;
}

template <typename Mul>
U256 PowMod(const U256& a, const U256& e, Mul mul) {
  U256 r{};
  r.w[0] = 1U;
  for (unsigned i = 256U; i > 0U; --i) {
    const unsigned bit = i - 1U;
    r = mul(r, r);
    if (((e.w[bit / 32U] >> (bit % 32U)) & 1U) != 0U) {
      r = mul(r, a);
    }
  }
  return r;
}

inline U256 InvP(const U256& a) {
  U256 e = PrimeP();
  e.w[0] -= 2U;
  return PowMod(a, e, [](const U256& x, const U256& y) { return MulP(x, y); });
}
inline U256 InvN(const U256& a) {
  U256 e = OrderN();
  e.w[0] -= 2U;
  return PowMod(a, e, [](const U256& x, const U256& y) { return MulMod(x, y, OrderN()); });
}

struct Jac {
  U256 x, y, z; // z == 0: infinity
};

inline Jac Double(const Jac& p) {
  if (IsZero(p.z) || IsZero(p.y)) {
    return Jac{{}, {}, {}};
  }
  // dbl-2001-b (a = -3)
  const U256 delta = MulP(p.z, p.z);
  const U256 gamma = MulP(p.y, p.y);
  const U256 beta = MulP(p.x, gamma);
  const U256 t = MulP(SubP(p.x, delta), AddP(p.x, delta));
  const U256 alpha = AddP(AddP(t, t), t);
  const U256 beta4 = AddP(AddP(beta, beta), AddP(beta, beta));
  const U256 beta8 = AddP(beta4, beta4);
  Jac r;
  r.x = SubP(MulP(alpha, alpha), beta8);
  r.z = SubP(SubP(MulP(AddP(p.y, p.z), AddP(p.y, p.z)), gamma), delta);
  const U256 g2 = MulP(gamma, gamma);
  const U256 g8 = AddP(AddP(AddP(g2, g2), AddP(g2, g2)), AddP(AddP(g2, g2), AddP(g2, g2)));
  r.y = SubP(MulP(alpha, SubP(beta4, r.x)), g8);
  return r;
}

inline Jac AddJ(const Jac& p, const Jac& q) {
  if (IsZero(p.z)) {
    return q;
  }
  if (IsZero(q.z)) {
    return p;
  }
  const U256 z1z1 = MulP(p.z, p.z);
  const U256 z2z2 = MulP(q.z, q.z);
  const U256 u1 = MulP(p.x, z2z2);
  const U256 u2 = MulP(q.x, z1z1);
  const U256 s1 = MulP(MulP(p.y, q.z), z2z2);
  const U256 s2 = MulP(MulP(q.y, p.z), z1z1);
  if (Cmp(u1, u2) == 0) {
    if (Cmp(s1, s2) == 0) {
      return Double(p);
    }
    return Jac{{}, {}, {}};
  }
  const U256 h = SubP(u2, u1);
  const U256 r = SubP(s2, s1);
  const U256 h2 = MulP(h, h);
  const U256 h3 = MulP(h2, h);
  const U256 u1h2 = MulP(u1, h2);
  Jac o;
  o.x = SubP(SubP(MulP(r, r), h3), AddP(u1h2, u1h2));
  o.y = SubP(MulP(r, SubP(u1h2, o.x)), MulP(s1, h3));
  o.z = MulP(MulP(p.z, q.z), h);
  return o;
}

inline Jac MulJ(const U256& k, const Jac& p) {
  Jac r{{}, {}, {}};
  for (unsigned i = 256U; i > 0U; --i) {
    const unsigned bit = i - 1U;
    r = Double(r);
    if (((k.w[bit / 32U] >> (bit % 32U)) & 1U) != 0U) {
      r = AddJ(r, p);
    }
  }
  return r;
}

inline bool Affine(const Jac& p, U256& x, U256& y) {
  if (IsZero(p.z)) {
    return false;
  }
  const U256 zi = InvP(p.z);
  const U256 zi2 = MulP(zi, zi);
  x = MulP(p.x, zi2);
  y = MulP(p.y, MulP(zi2, zi));
  return true;
}

inline Jac Base() {
  static const uint8_t kGx[32] = {0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6,
                                  0xE5, 0x63, 0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB,
                                  0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96};
  static const uint8_t kGy[32] = {0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB,
                                  0x4A, 0x7C, 0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31,
                                  0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5};
  Jac g;
  g.x = FromBe(kGx);
  g.y = FromBe(kGy);
  g.z.w[0] = 1U;
  return g;
}

/// pub = 04 || x || y of d * G.
inline bool PublicKey(const uint8_t* d, uint8_t* pub65) {
  U256 x;
  U256 y;
  if (!Affine(MulJ(FromBe(d), Base()), x, y)) {
    return false;
  }
  pub65[0] = 0x04U;
  ToBe(x, pub65 + 1);
  ToBe(y, pub65 + 33);
  return true;
}

/// x(d * Q).
inline bool Ecdh(const uint8_t* d, const uint8_t* pub65, uint8_t* out32) {
  if (pub65[0] != 0x04U) {
    return false;
  }
  Jac q;
  q.x = FromBe(pub65 + 1);
  q.y = FromBe(pub65 + 33);
  q.z.w[0] = 1U;
  U256 x;
  U256 y;
  if (!Affine(MulJ(FromBe(d), q), x, y)) {
    return false;
  }
  ToBe(x, out32);
  return true;
}

/// ECDSA verification of r || s over a 32-byte digest.
inline bool Verify(const uint8_t* pub65, const uint8_t* digest, const uint8_t* r32,
                   const uint8_t* s32) {
  const U256 r = FromBe(r32);
  const U256 s = FromBe(s32);
  if (IsZero(r) || IsZero(s) || (Cmp(r, OrderN()) >= 0) || (Cmp(s, OrderN()) >= 0)) {
    return false;
  }
  U256 e = FromBe(digest);
  if (Cmp(e, OrderN()) >= 0) {
    static_cast<void>(SubRaw(e, e, OrderN()));
  }
  const U256 w = InvN(s);
  const U256 u1 = MulMod(e, w, OrderN());
  const U256 u2 = MulMod(r, w, OrderN());
  Jac q;
  q.x = FromBe(pub65 + 1);
  q.y = FromBe(pub65 + 33);
  q.z.w[0] = 1U;
  U256 x;
  U256 y;
  if (!Affine(AddJ(MulJ(u1, Base()), MulJ(u2, q)), x, y)) {
    return false;
  }
  if (Cmp(x, OrderN()) >= 0) {
    static_cast<void>(SubRaw(x, x, OrderN()));
  }
  return Cmp(x, r) == 0;
}

/// Parse a DER ECDSA signature (SEQUENCE of two INTEGERs) into r and s, 32 bytes each.
inline bool ParseDer(Bytes der, uint8_t* r32, uint8_t* s32) {
  if ((der.size() < 8U) || (der[0] != 0x30U) || (der[1] != (der.size() - 2U))) {
    return false;
  }
  std::size_t at = 2U;
  uint8_t* outs[2] = {r32, s32};
  for (uint8_t* o : outs) {
    if (((at + 2U) > der.size()) || (der[at] != 0x02U)) {
      return false;
    }
    std::size_t len = der[at + 1U];
    at += 2U;
    if ((len == 0U) || ((at + len) > der.size())) {
      return false;
    }
    const uint8_t* v = &der[at];
    at += len;
    while ((len > 32U) && (*v == 0U)) {
      ++v;
      --len;
    }
    if (len > 32U) {
      return false;
    }
    static_cast<void>(std::memset(o, 0, 32U));
    static_cast<void>(std::memcpy(o + (32U - len), v, len));
  }
  return at == der.size();
}

} // namespace se05x::testmodel::mc

#endif // SE05X_TESTS_MODEL_SCP_CRYPTO_HPP
