/**
 * @file se05x_crypto_aes.ipp
 * @brief AES (FIPS 197), AES-CBC (SP 800-38A) and AES-CMAC (SP 800-38B, RFC 4493) of the reference
 * crypto port, included by `se05x_crypto.hpp`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Written from FIPS 197 sections 5.1 to 5.3. The S-box is computed at compile time from its
 * definition (multiplicative inverse in GF(2^8), then the affine map of section 5.1.1), not typed
 * in. Every S-box access during a cipher operation scans the whole table and selects the entry with
 * a mask, so the memory access pattern does not depend on the key or the data; `MixColumns` uses
 * branch-free doubling. This is the bring-up code of S-15: not hardened against power or fault
 * attacks. The key schedule is wiped when it goes out of scope (S-01).
 */
#ifndef SE05X_CRYPTO_AES_IPP
#define SE05X_CRYPTO_AES_IPP

namespace se05x::refcrypto {

namespace aes_detail {

/// Widen a byte for bit operations (hicpp-signed-bitwise: never on a promoted `int`).
constexpr uint32_t W(uint8_t v) noexcept {
  return static_cast<uint32_t>(v);
}
/// Narrow to a byte.
constexpr uint8_t B(uint32_t v) noexcept {
  return static_cast<uint8_t>(v & 0xFFU);
}

/// Multiply by x in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1 without a branch (FIPS 197 4.2.1).
constexpr uint8_t XTime(uint8_t v) noexcept {
  const uint32_t high = (W(v) >> 7U) & 1U;
  return B((W(v) << 1U) ^ (0x1BU & (0U - high)));
}

/// Multiply two field elements; `b` is a public constant here, the loop is fixed-length.
constexpr uint8_t GfMul(uint8_t a, uint8_t b) noexcept {
  uint32_t result = 0U;
  uint8_t x = a;
  for (uint32_t bit = 0U; bit < 8U; ++bit) {
    const uint32_t take = (W(b) >> bit) & 1U;
    result ^= W(x) & (0U - take);
    x = XTime(x);
  }
  return B(result);
}

/// The multiplicative inverse, x^254 (0 maps to 0), FIPS 197 5.1.1.
constexpr uint8_t GfInverse(uint8_t x) noexcept {
  uint8_t result = 1U;
  uint8_t power = x;
  uint32_t exponent = 254U;
  for (uint32_t i = 0U; i < 8U; ++i) {
    if (((exponent >> i) & 1U) != 0U) {
      result = GfMul(result, power);
    }
    power = GfMul(power, power);
  }
  return result;
}

/// Rotate a byte left.
constexpr uint32_t Rotl8(uint32_t v, uint32_t n) noexcept {
  return ((v << n) | (v >> (8U - n))) & 0xFFU;
}

/// The S-box of FIPS 197 5.1.1, computed from its definition.
constexpr std::array<uint8_t, 256> MakeSbox() noexcept {
  std::array<uint8_t, 256> box{};
  for (uint32_t i = 0U; i < 256U; ++i) {
    const uint32_t inv = W(GfInverse(B(i)));
    const uint32_t s =
        inv ^ Rotl8(inv, 1U) ^ Rotl8(inv, 2U) ^ Rotl8(inv, 3U) ^ Rotl8(inv, 4U) ^ 0x63U;
    box[i] = B(s);
  }
  return box;
}

/// The inverse S-box of FIPS 197 5.3.2.
constexpr std::array<uint8_t, 256> MakeInvSbox(const std::array<uint8_t, 256>& box) noexcept {
  std::array<uint8_t, 256> inv{};
  for (uint32_t i = 0U; i < 256U; ++i) {
    inv[box[i]] = B(i);
  }
  return inv;
}

/// The S-box.
inline constexpr std::array<uint8_t, 256> kSbox = MakeSbox();
/// The inverse S-box.
inline constexpr std::array<uint8_t, 256> kInvSbox = MakeInvSbox(kSbox);

static_assert((kSbox[0x00] == 0x63U) && (kSbox[0x53] == 0xEDU), "FIPS 197 Figure 7");
static_assert(kInvSbox[0x63] == 0x00U, "FIPS 197 Figure 14");

/// Look a byte up without a data-dependent memory access: every entry is read and masked.
constexpr uint8_t Lookup(const std::array<uint8_t, 256>& table, uint8_t index) noexcept {
  uint32_t result = 0U;
  for (uint32_t i = 0U; i < 256U; ++i) {
    const uint32_t diff = i ^ W(index);
    const uint32_t equal = ((diff - 1U) >> 8U) & 1U; // 1 only when diff is 0
    result |= W(table[i]) & (0U - equal);
  }
  return B(result);
}

/// One state of 16 bytes, column-major as in FIPS 197 3.4.
using State = std::array<uint8_t, kAesBlock>;

constexpr void AddRoundKey(State& s, const std::array<uint8_t, kAesScheduleBytes>& rk,
                           std::size_t round) noexcept {
  for (std::size_t i = 0U; i < kAesBlock; ++i) {
    s[i] = B(W(s[i]) ^ W(rk[(round * kAesBlock) + i]));
  }
}

constexpr void SubBytes(State& s, const std::array<uint8_t, 256>& table) noexcept {
  for (std::size_t i = 0U; i < s.size(); ++i) {
    s[i] = Lookup(table, s[i]);
  }
}

/// ShiftRows (FIPS 197 5.1.2) or its inverse (5.3.1): row r moves by r columns.
constexpr void ShiftRows(State& s, bool inverse) noexcept {
  const State in = s;
  for (std::size_t r = 1U; r < 4U; ++r) {
    for (std::size_t c = 0U; c < 4U; ++c) {
      const std::size_t from = inverse ? (((c + 4U) - r) % 4U) : ((c + r) % 4U);
      s[r + (4U * c)] = in[r + (4U * from)];
    }
  }
}

/// MixColumns (FIPS 197 5.1.3).
constexpr void MixColumns(State& s) noexcept {
  for (std::size_t c = 0U; c < 4U; ++c) {
    const uint8_t a0 = s[4U * c];
    const uint8_t a1 = s[(4U * c) + 1U];
    const uint8_t a2 = s[(4U * c) + 2U];
    const uint8_t a3 = s[(4U * c) + 3U];
    const uint32_t all = W(a0) ^ W(a1) ^ W(a2) ^ W(a3);
    s[4U * c] = B(W(a0) ^ all ^ W(XTime(B(W(a0) ^ W(a1)))));
    s[(4U * c) + 1U] = B(W(a1) ^ all ^ W(XTime(B(W(a1) ^ W(a2)))));
    s[(4U * c) + 2U] = B(W(a2) ^ all ^ W(XTime(B(W(a2) ^ W(a3)))));
    s[(4U * c) + 3U] = B(W(a3) ^ all ^ W(XTime(B(W(a3) ^ W(a0)))));
  }
}

/// InvMixColumns (FIPS 197 5.3.3).
constexpr void InvMixColumns(State& s) noexcept {
  for (std::size_t c = 0U; c < 4U; ++c) {
    const std::array<uint8_t, 4> a{s[4U * c], s[(4U * c) + 1U], s[(4U * c) + 2U], s[(4U * c) + 3U]};
    for (std::size_t r = 0U; r < 4U; ++r) {
      const uint32_t v = W(GfMul(a[r], 0x0EU)) ^ W(GfMul(a[(r + 1U) % 4U], 0x0BU)) ^
                         W(GfMul(a[(r + 2U) % 4U], 0x0DU)) ^ W(GfMul(a[(r + 3U) % 4U], 0x09U));
      s[r + (4U * c)] = B(v);
    }
  }
}

} // namespace aes_detail

inline AesSchedule::~AesSchedule() noexcept {
  Zeroize(MutableByteSpan{round_keys_});
  rounds_ = 0U;
}

inline bool AesSchedule::Expand(ByteSpan key) noexcept {
  using aes_detail::B;
  using aes_detail::W;
  Zeroize(MutableByteSpan{round_keys_});
  rounds_ = 0U;
  const std::size_t nk = key.size() / 4U;
  if (((key.size() != 16U) && (key.size() != 24U) && (key.size() != 32U))) {
    return false;
  }
  const std::size_t nr = nk + 6U;
  const std::size_t total_words = 4U * (nr + 1U);
  for (std::size_t i = 0U; i < key.size(); ++i) {
    round_keys_[i] = key[i];
  }
  uint32_t rcon = 1U;
  for (std::size_t i = nk; i < total_words; ++i) {
    std::array<uint8_t, 4> t{round_keys_[(4U * i) - 4U], round_keys_[(4U * i) - 3U],
                             round_keys_[(4U * i) - 2U], round_keys_[(4U * i) - 1U]};
    if ((i % nk) == 0U) {
      const uint8_t first = t[0];
      t[0] = B(W(aes_detail::Lookup(aes_detail::kSbox, t[1])) ^ rcon);
      t[1] = aes_detail::Lookup(aes_detail::kSbox, t[2]);
      t[2] = aes_detail::Lookup(aes_detail::kSbox, t[3]);
      t[3] = aes_detail::Lookup(aes_detail::kSbox, first);
      rcon = W(aes_detail::XTime(B(rcon)));
    } else if ((nk > 6U) && ((i % nk) == 4U)) {
      for (uint8_t& v : t) {
        v = aes_detail::Lookup(aes_detail::kSbox, v);
      }
    } else {
      // No transformation for this word (FIPS 197 5.2).
    }
    for (std::size_t j = 0U; j < 4U; ++j) {
      round_keys_[(4U * i) + j] = B(W(round_keys_[(4U * (i - nk)) + j]) ^ W(t[j]));
    }
    Zeroize(MutableByteSpan{t});
  }
  rounds_ = static_cast<uint8_t>(nr);
  return true;
}

inline void AesSchedule::Encrypt(std::span<uint8_t, kAesBlock> block) const noexcept {
  aes_detail::State s{};
  for (std::size_t i = 0U; i < kAesBlock; ++i) {
    s[i] = block[i];
  }
  aes_detail::AddRoundKey(s, round_keys_, 0U);
  for (std::size_t round = 1U; round <= rounds_; ++round) {
    aes_detail::SubBytes(s, aes_detail::kSbox);
    aes_detail::ShiftRows(s, false);
    if (round != rounds_) {
      aes_detail::MixColumns(s);
    }
    aes_detail::AddRoundKey(s, round_keys_, round);
  }
  for (std::size_t i = 0U; i < kAesBlock; ++i) {
    block[i] = s[i];
  }
  Zeroize(MutableByteSpan{s});
}

inline void AesSchedule::Decrypt(std::span<uint8_t, kAesBlock> block) const noexcept {
  aes_detail::State s{};
  for (std::size_t i = 0U; i < kAesBlock; ++i) {
    s[i] = block[i];
  }
  aes_detail::AddRoundKey(s, round_keys_, rounds_);
  for (std::size_t round = rounds_; round > 0U; --round) {
    aes_detail::ShiftRows(s, true);
    aes_detail::SubBytes(s, aes_detail::kInvSbox);
    aes_detail::AddRoundKey(s, round_keys_, round - 1U);
    if (round != 1U) {
      aes_detail::InvMixColumns(s);
    }
  }
  for (std::size_t i = 0U; i < kAesBlock; ++i) {
    block[i] = s[i];
  }
  Zeroize(MutableByteSpan{s});
}

inline bool AesCbcCrypt(const AesSchedule& schedule, bool encrypt, std::span<uint8_t, kAesBlock> iv,
                        MutableByteSpan data) noexcept {
  using aes_detail::B;
  using aes_detail::W;
  if ((!schedule.IsValid()) || ((data.size() % kAesBlock) != 0U)) {
    return false;
  }
  for (std::size_t off = 0U; off < data.size(); off += kAesBlock) {
    const std::span<uint8_t, kAesBlock> block{data.subspan(off, kAesBlock).data(), kAesBlock};
    if (encrypt) {
      for (std::size_t i = 0U; i < kAesBlock; ++i) {
        block[i] = B(W(block[i]) ^ W(iv[i]));
      }
      schedule.Encrypt(block);
      for (std::size_t i = 0U; i < kAesBlock; ++i) {
        iv[i] = block[i];
      }
    } else {
      std::array<uint8_t, kAesBlock> saved{};
      for (std::size_t i = 0U; i < kAesBlock; ++i) {
        saved[i] = block[i];
      }
      schedule.Decrypt(block);
      for (std::size_t i = 0U; i < kAesBlock; ++i) {
        block[i] = B(W(block[i]) ^ W(iv[i]));
        iv[i] = saved[i];
      }
    }
  }
  return true;
}

namespace aes_detail {
/// Doubling in GF(2^128) for the CMAC subkeys (SP 800-38B 6.1), branch-free.
inline void CmacDouble(std::array<uint8_t, kAesBlock>& v) noexcept {
  const uint32_t msb = (W(v[0]) >> 7U) & 1U;
  for (std::size_t i = 0U; i < (kAesBlock - 1U); ++i) {
    v[i] = B((W(v[i]) << 1U) | (W(v[i + 1U]) >> 7U));
  }
  v[kAesBlock - 1U] = B((W(v[kAesBlock - 1U]) << 1U) ^ (0x87U & (0U - msb)));
}
} // namespace aes_detail

inline bool AesCmacCompute(const AesSchedule& schedule, ByteSpan message,
                           std::span<uint8_t, kAesBlock> mac) noexcept {
  using aes_detail::B;
  using aes_detail::W;
  if (!schedule.IsValid()) {
    return false;
  }
  std::array<uint8_t, kAesBlock> k1{};
  schedule.Encrypt(std::span<uint8_t, kAesBlock>{k1});
  aes_detail::CmacDouble(k1);
  std::array<uint8_t, kAesBlock> k2 = k1;
  aes_detail::CmacDouble(k2);
  const std::size_t blocks =
      message.empty() ? 1U : (((message.size() + kAesBlock) - 1U) / kAesBlock);
  const bool complete = (!message.empty()) && ((message.size() % kAesBlock) == 0U);
  std::array<uint8_t, kAesBlock> x{};
  for (std::size_t b = 0U; b < blocks; ++b) {
    const std::size_t off = b * kAesBlock;
    const bool last = (b + 1U) == blocks;
    for (std::size_t i = 0U; i < kAesBlock; ++i) {
      uint32_t m = 0U;
      if ((off + i) < message.size()) {
        m = W(message[off + i]);
      } else if ((off + i) == message.size()) {
        m = 0x80U; // padding 10* (SP 800-38B 6.2 step 3)
      } else {
        m = 0U;
      }
      if (last) {
        m ^= complete ? W(k1[i]) : W(k2[i]);
      }
      x[i] = B(W(x[i]) ^ m);
    }
    schedule.Encrypt(std::span<uint8_t, kAesBlock>{x});
  }
  for (std::size_t i = 0U; i < kAesBlock; ++i) {
    mac[i] = x[i];
  }
  Zeroize(MutableByteSpan{k1});
  Zeroize(MutableByteSpan{k2});
  Zeroize(MutableByteSpan{x});
  return true;
}

} // namespace se05x::refcrypto

#endif // SE05X_CRYPTO_AES_IPP
