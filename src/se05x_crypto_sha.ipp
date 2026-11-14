/**
 * @file se05x_crypto_sha.ipp
 * @brief SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 (FIPS 180-4) and HMAC-SHA-256 (FIPS 198-1)
 * of the reference crypto port, included by `se05x_crypto.hpp`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Written from FIPS 180-4 sections 4.1, 4.2, 5.1, 5.3 and 6. The constants of section 4.2 are the
 * fractional parts of cube and square roots of primes; they are typed in and pinned by the
 * known-answer tests of `tests/test_scp_crypto.cpp` (FIPS 180-4 examples). Every hash object wipes
 * its state and buffer when it is destroyed (S-01): the ECKey master key and RFC 6979 hash
 * secrets through it.
 */
#ifndef SE05X_CRYPTO_SHA_IPP
#define SE05X_CRYPTO_SHA_IPP

namespace se05x::refcrypto {

namespace sha_detail {

constexpr uint32_t Rotr32(uint32_t x, uint32_t n) noexcept {
  return (x >> n) | (x << (32U - n));
}
constexpr uint32_t Rotl32(uint32_t x, uint32_t n) noexcept {
  return (x << n) | (x >> (32U - n));
}
constexpr uint64_t Rotr64(uint64_t x, uint32_t n) noexcept {
  return (x >> n) | (x << (64U - n));
}
/// The big-endian word at `b[at]` to `b[at + 3]` (indices, no pointer arithmetic: Rule 8.7.1).
constexpr uint32_t Load32(ByteSpan b, std::size_t at) noexcept {
  return (static_cast<uint32_t>(b[at]) << 24U) | (static_cast<uint32_t>(b[at + 1U]) << 16U) |
         (static_cast<uint32_t>(b[at + 2U]) << 8U) | static_cast<uint32_t>(b[at + 3U]);
}
/// The big-endian double word at `b[at]` to `b[at + 7]`.
constexpr uint64_t Load64(ByteSpan b, std::size_t at) noexcept {
  return (static_cast<uint64_t>(Load32(b, at)) << 32U) | static_cast<uint64_t>(Load32(b, at + 4U));
}
/// Write `v` big-endian to `b[at]` to `b[at + 3]`.
constexpr void Store32(uint32_t v, MutableByteSpan b, std::size_t at) noexcept {
  b[at] = static_cast<uint8_t>(v >> 24U);
  b[at + 1U] = static_cast<uint8_t>((v >> 16U) & 0xFFU);
  b[at + 2U] = static_cast<uint8_t>((v >> 8U) & 0xFFU);
  b[at + 3U] = static_cast<uint8_t>(v & 0xFFU);
}
/// Write `v` big-endian to `b[at]` to `b[at + 7]`.
constexpr void Store64(uint64_t v, MutableByteSpan b, std::size_t at) noexcept {
  Store32(static_cast<uint32_t>(v >> 32U), b, at);
  Store32(static_cast<uint32_t>(v & 0xFFFFFFFFU), b, at + 4U);
}

/// FIPS 180-4 4.2.2.
inline constexpr std::array<uint32_t, 64> kK256{
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
    0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
    0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
    0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
    0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
    0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
    0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
    0xc67178f2U};

/// FIPS 180-4 4.2.3.
inline constexpr std::array<uint64_t, 80> kK512{
    0x428a2f98d728ae22U, 0x7137449123ef65cdU, 0xb5c0fbcfec4d3b2fU, 0xe9b5dba58189dbbcU,
    0x3956c25bf348b538U, 0x59f111f1b605d019U, 0x923f82a4af194f9bU, 0xab1c5ed5da6d8118U,
    0xd807aa98a3030242U, 0x12835b0145706fbeU, 0x243185be4ee4b28cU, 0x550c7dc3d5ffb4e2U,
    0x72be5d74f27b896fU, 0x80deb1fe3b1696b1U, 0x9bdc06a725c71235U, 0xc19bf174cf692694U,
    0xe49b69c19ef14ad2U, 0xefbe4786384f25e3U, 0x0fc19dc68b8cd5b5U, 0x240ca1cc77ac9c65U,
    0x2de92c6f592b0275U, 0x4a7484aa6ea6e483U, 0x5cb0a9dcbd41fbd4U, 0x76f988da831153b5U,
    0x983e5152ee66dfabU, 0xa831c66d2db43210U, 0xb00327c898fb213fU, 0xbf597fc7beef0ee4U,
    0xc6e00bf33da88fc2U, 0xd5a79147930aa725U, 0x06ca6351e003826fU, 0x142929670a0e6e70U,
    0x27b70a8546d22ffcU, 0x2e1b21385c26c926U, 0x4d2c6dfc5ac42aedU, 0x53380d139d95b3dfU,
    0x650a73548baf63deU, 0x766a0abb3c77b2a8U, 0x81c2c92e47edaee6U, 0x92722c851482353bU,
    0xa2bfe8a14cf10364U, 0xa81a664bbc423001U, 0xc24b8b70d0f89791U, 0xc76c51a30654be30U,
    0xd192e819d6ef5218U, 0xd69906245565a910U, 0xf40e35855771202aU, 0x106aa07032bbd1b8U,
    0x19a4c116b8d2d0c8U, 0x1e376c085141ab53U, 0x2748774cdf8eeb99U, 0x34b0bcb5e19b48a8U,
    0x391c0cb3c5c95a63U, 0x4ed8aa4ae3418acbU, 0x5b9cca4f7763e373U, 0x682e6ff3d6b2b8a3U,
    0x748f82ee5defb2fcU, 0x78a5636f43172f60U, 0x84c87814a1f0ab72U, 0x8cc702081a6439ecU,
    0x90befffa23631e28U, 0xa4506cebde82bde9U, 0xbef9a3f7b2c67915U, 0xc67178f2e372532bU,
    0xca273eceea26619cU, 0xd186b8c721c0c207U, 0xeada7dd6cde0eb1eU, 0xf57d4f7fee6ed178U,
    0x06f067aa72176fbaU, 0x0a637dc5a2c898a6U, 0x113f9804bef90daeU, 0x1b710b35131c471bU,
    0x28db77f523047d84U, 0x32caab7b40c72493U, 0x3c9ebe0a15c9bebcU, 0x431d67c49c100d4cU,
    0x4cc5d4becb3e42b6U, 0x597f299cfc657e2aU, 0x5fcb6fab3ad6faecU, 0x6c44198c4a475817U};

} // namespace sha_detail

inline void Sha256::Reset(bool sha224) noexcept {
  is224_ = sha224;
  if (sha224) {
    h_ = {0xc1059ed8U, 0x367cd507U, 0x3070dd17U, 0xf70e5939U,
          0xffc00b31U, 0x68581511U, 0x64f98fa7U, 0xbefa4fa4U};
  } else {
    h_ = {0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
          0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};
  }
  Zeroize(MutableByteSpan{buffer_});
  used_ = 0U;
  total_ = 0U;
}

inline Sha256::~Sha256() noexcept {
  Zeroize(MutableByteSpan{buffer_});
  ZeroizeWords(h_);
  used_ = 0U;
  total_ = 0U;
}

inline void Sha256::compress() noexcept {
  using namespace sha_detail;
  std::array<uint32_t, 64> w{};
  for (std::size_t t = 0U; t < 16U; ++t) {
    w[t] = Load32(ByteSpan{buffer_}, 4U * t);
  }
  for (std::size_t t = 16U; t < 64U; ++t) {
    const uint32_t s0 = Rotr32(w[t - 15U], 7U) ^ Rotr32(w[t - 15U], 18U) ^ (w[t - 15U] >> 3U);
    const uint32_t s1 = Rotr32(w[t - 2U], 17U) ^ Rotr32(w[t - 2U], 19U) ^ (w[t - 2U] >> 10U);
    w[t] = w[t - 16U] + s0 + w[t - 7U] + s1;
  }
  std::array<uint32_t, 8> v = h_;
  for (std::size_t t = 0U; t < 64U; ++t) {
    const uint32_t s1 = Rotr32(v[4], 6U) ^ Rotr32(v[4], 11U) ^ Rotr32(v[4], 25U);
    const uint32_t ch = (v[4] & v[5]) ^ ((~v[4]) & v[6]);
    const uint32_t t1 = v[7] + s1 + ch + kK256[t] + w[t];
    const uint32_t s0 = Rotr32(v[0], 2U) ^ Rotr32(v[0], 13U) ^ Rotr32(v[0], 22U);
    const uint32_t maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
    const uint32_t t2 = s0 + maj;
    v = {t1 + t2, v[0], v[1], v[2], v[3] + t1, v[4], v[5], v[6]};
  }
  for (std::size_t i = 0U; i < 8U; ++i) {
    h_[i] += v[i];
  }
  ZeroizeWords(w);
}

inline void Sha256::Update(ByteSpan data) noexcept {
  for (const uint8_t byte : data) {
    buffer_[used_] = byte;
    ++used_;
    if (used_ == buffer_.size()) {
      compress();
      used_ = 0U;
    }
  }
  total_ += static_cast<uint64_t>(data.size());
}

inline std::size_t Sha256::Final(MutableByteSpan digest) noexcept {
  const std::size_t length = is224_ ? 28U : 32U;
  if (digest.size() < length) {
    return 0U;
  }
  const uint64_t bits = total_ * 8U;
  const std::array<uint8_t, 1> pad{0x80U};
  Update(ByteSpan{pad});
  const std::array<uint8_t, 1> zero{0x00U};
  while (used_ != 56U) {
    Update(ByteSpan{zero});
  }
  std::array<uint8_t, 8> len{};
  sha_detail::Store64(bits, MutableByteSpan{len}, 0U);
  Update(ByteSpan{len});
  std::array<uint8_t, 32> out{};
  for (std::size_t i = 0U; i < 8U; ++i) {
    sha_detail::Store32(h_[i], MutableByteSpan{out}, 4U * i);
  }
  for (std::size_t i = 0U; i < length; ++i) {
    digest[i] = out[i];
  }
  Zeroize(MutableByteSpan{out});
  Reset(is224_);
  return length;
}

inline void Sha512::Reset(bool sha384) noexcept {
  is384_ = sha384;
  if (sha384) {
    h_ = {0xcbbb9d5dc1059ed8U, 0x629a292a367cd507U, 0x9159015a3070dd17U, 0x152fecd8f70e5939U,
          0x67332667ffc00b31U, 0x8eb44a8768581511U, 0xdb0c2e0d64f98fa7U, 0x47b5481dbefa4fa4U};
  } else {
    h_ = {0x6a09e667f3bcc908U, 0xbb67ae8584caa73bU, 0x3c6ef372fe94f82bU, 0xa54ff53a5f1d36f1U,
          0x510e527fade682d1U, 0x9b05688c2b3e6c1fU, 0x1f83d9abfb41bd6bU, 0x5be0cd19137e2179U};
  }
  Zeroize(MutableByteSpan{buffer_});
  used_ = 0U;
  total_ = 0U;
}

inline Sha512::~Sha512() noexcept {
  Zeroize(MutableByteSpan{buffer_});
  ZeroizeWords(h_);
  used_ = 0U;
  total_ = 0U;
}

inline void Sha512::compress() noexcept {
  using namespace sha_detail;
  std::array<uint64_t, 80> w{};
  for (std::size_t t = 0U; t < 16U; ++t) {
    w[t] = Load64(ByteSpan{buffer_}, 8U * t);
  }
  for (std::size_t t = 16U; t < 80U; ++t) {
    const uint64_t s0 = Rotr64(w[t - 15U], 1U) ^ Rotr64(w[t - 15U], 8U) ^ (w[t - 15U] >> 7U);
    const uint64_t s1 = Rotr64(w[t - 2U], 19U) ^ Rotr64(w[t - 2U], 61U) ^ (w[t - 2U] >> 6U);
    w[t] = w[t - 16U] + s0 + w[t - 7U] + s1;
  }
  std::array<uint64_t, 8> v = h_;
  for (std::size_t t = 0U; t < 80U; ++t) {
    const uint64_t s1 = Rotr64(v[4], 14U) ^ Rotr64(v[4], 18U) ^ Rotr64(v[4], 41U);
    const uint64_t ch = (v[4] & v[5]) ^ ((~v[4]) & v[6]);
    const uint64_t t1 = v[7] + s1 + ch + kK512[t] + w[t];
    const uint64_t s0 = Rotr64(v[0], 28U) ^ Rotr64(v[0], 34U) ^ Rotr64(v[0], 39U);
    const uint64_t maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
    const uint64_t t2 = s0 + maj;
    v = {t1 + t2, v[0], v[1], v[2], v[3] + t1, v[4], v[5], v[6]};
  }
  for (std::size_t i = 0U; i < 8U; ++i) {
    h_[i] += v[i];
  }
  ZeroizeWords(w);
}

inline void Sha512::Update(ByteSpan data) noexcept {
  for (const uint8_t byte : data) {
    buffer_[used_] = byte;
    ++used_;
    if (used_ == buffer_.size()) {
      compress();
      used_ = 0U;
    }
  }
  total_ += static_cast<uint64_t>(data.size());
}

inline std::size_t Sha512::Final(MutableByteSpan digest) noexcept {
  const std::size_t length = is384_ ? 48U : 64U;
  if (digest.size() < length) {
    return 0U;
  }
  const uint64_t bits = total_ * 8U;
  const std::array<uint8_t, 1> pad{0x80U};
  Update(ByteSpan{pad});
  const std::array<uint8_t, 1> zero{0x00U};
  while (used_ != 112U) {
    Update(ByteSpan{zero});
  }
  std::array<uint8_t, 16> len{}; // the high 64 bits of the 128-bit length are zero
  sha_detail::Store64(bits, MutableByteSpan{len}, 8U);
  Update(ByteSpan{len});
  std::array<uint8_t, 64> out{};
  for (std::size_t i = 0U; i < 8U; ++i) {
    sha_detail::Store64(h_[i], MutableByteSpan{out}, 8U * i);
  }
  for (std::size_t i = 0U; i < length; ++i) {
    digest[i] = out[i];
  }
  Zeroize(MutableByteSpan{out});
  Reset(is384_);
  return length;
}

inline void Sha1::Reset() noexcept {
  h_ = {0x67452301U, 0xEFCDAB89U, 0x98BADCFEU, 0x10325476U, 0xC3D2E1F0U};
  Zeroize(MutableByteSpan{buffer_});
  used_ = 0U;
  total_ = 0U;
}

inline Sha1::~Sha1() noexcept {
  Zeroize(MutableByteSpan{buffer_});
  ZeroizeWords(h_);
}

inline void Sha1::compress() noexcept {
  using namespace sha_detail;
  std::array<uint32_t, 80> w{};
  for (std::size_t t = 0U; t < 16U; ++t) {
    w[t] = Load32(ByteSpan{buffer_}, 4U * t);
  }
  for (std::size_t t = 16U; t < 80U; ++t) {
    w[t] = Rotl32(w[t - 3U] ^ w[t - 8U] ^ w[t - 14U] ^ w[t - 16U], 1U);
  }
  std::array<uint32_t, 5> v = h_;
  for (std::size_t t = 0U; t < 80U; ++t) {
    uint32_t f = 0U;
    uint32_t k = 0U;
    if (t < 20U) {
      f = (v[1] & v[2]) | ((~v[1]) & v[3]);
      k = 0x5A827999U;
    } else if (t < 40U) {
      f = v[1] ^ v[2] ^ v[3];
      k = 0x6ED9EBA1U;
    } else if (t < 60U) {
      f = (v[1] & v[2]) | (v[1] & v[3]) | (v[2] & v[3]);
      k = 0x8F1BBCDCU;
    } else {
      f = v[1] ^ v[2] ^ v[3];
      k = 0xCA62C1D6U;
    }
    const uint32_t temp = Rotl32(v[0], 5U) + f + v[4] + k + w[t];
    v = {temp, v[0], Rotl32(v[1], 30U), v[2], v[3]};
  }
  for (std::size_t i = 0U; i < 5U; ++i) {
    h_[i] += v[i];
  }
}

inline void Sha1::Update(ByteSpan data) noexcept {
  for (const uint8_t byte : data) {
    buffer_[used_] = byte;
    ++used_;
    if (used_ == buffer_.size()) {
      compress();
      used_ = 0U;
    }
  }
  total_ += static_cast<uint64_t>(data.size());
}

inline std::size_t Sha1::Final(MutableByteSpan digest) noexcept {
  if (digest.size() < 20U) {
    return 0U;
  }
  const uint64_t bits = total_ * 8U;
  const std::array<uint8_t, 1> pad{0x80U};
  Update(ByteSpan{pad});
  const std::array<uint8_t, 1> zero{0x00U};
  while (used_ != 56U) {
    Update(ByteSpan{zero});
  }
  std::array<uint8_t, 8> len{};
  sha_detail::Store64(bits, MutableByteSpan{len}, 0U);
  Update(ByteSpan{len});
  for (std::size_t i = 0U; i < 5U; ++i) {
    sha_detail::Store32(h_[i], digest, 4U * i);
  }
  Reset();
  return 20U;
}

inline HmacSha256::HmacSha256(ByteSpan key) noexcept {
  std::array<uint8_t, 64> block{};
  if (key.size() > block.size()) {
    Sha256 h;
    h.Update(key);
    static_cast<void>(h.Final(MutableByteSpan{block}));
  } else {
    for (std::size_t i = 0U; i < key.size(); ++i) {
      block[i] = key[i];
    }
  }
  for (std::size_t i = 0U; i < block.size(); ++i) {
    pad_[i] = static_cast<uint8_t>(static_cast<uint32_t>(block[i]) ^ 0x5CU);
    block[i] = static_cast<uint8_t>(static_cast<uint32_t>(block[i]) ^ 0x36U);
  }
  inner_.Update(ByteSpan{block});
  Zeroize(MutableByteSpan{block});
}

inline HmacSha256::~HmacSha256() noexcept {
  Zeroize(MutableByteSpan{pad_});
}

inline void HmacSha256::Update(ByteSpan data) noexcept {
  inner_.Update(data);
}

inline void HmacSha256::Final(std::span<uint8_t, 32> mac) noexcept {
  std::array<uint8_t, 32> inner{};
  static_cast<void>(inner_.Final(MutableByteSpan{inner}));
  Sha256 outer;
  outer.Update(ByteSpan{pad_});
  outer.Update(ByteSpan{inner});
  static_cast<void>(outer.Final(MutableByteSpan{mac}));
  Zeroize(MutableByteSpan{inner});
}

} // namespace se05x::refcrypto

#endif // SE05X_CRYPTO_SHA_IPP
