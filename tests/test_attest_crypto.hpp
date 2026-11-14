/**
 * @file test_attest_crypto.hpp
 * @brief A crypto port for the attestation tests: SHA-224/256/384/512 (FIPS 180-4, written for
 * the tests) and an ECDSA P-256 check that compares the key, the 32-byte input and the raw
 * signature with the expectation of a vector.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * The vectors (tests/vectors/attest_vectors.hpp) were signed by openssl over messages built by a
 * script, independently of the verifier, and checked there with a real ECDSA verification. So a
 * verifier that builds another message, hashes it differently or reads the DER signature wrongly
 * gets `Mismatch` from this port, exactly as a real verification would refuse it. Every other
 * hook fails: the verifier needs none.
 */
#ifndef SE05X_TEST_ATTEST_CRYPTO_HPP
#define SE05X_TEST_ATTEST_CRYPTO_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "se05x_ports.hpp"

namespace attesttest {

using se05x::ByteSpan;
using se05x::CryptoStatus;
using se05x::HashAlg;
using se05x::KeyKind;
using se05x::KeyRef;
using se05x::MutableByteSpan;

/// SHA-256 and SHA-224 (FIPS 180-4 6.2, 6.3).
inline void Sha256(ByteSpan msg, MutableByteSpan out, bool is224) {
  static constexpr std::array<uint32_t, 64> kRound{
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
  std::array<uint32_t, 8> h =
      is224 ? std::array<uint32_t, 8>{0xc1059ed8U, 0x367cd507U, 0x3070dd17U, 0xf70e5939U,
                                      0xffc00b31U, 0x68581511U, 0x64f98fa7U, 0xbefa4fa4U}
            : std::array<uint32_t, 8>{0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
                                      0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};
  const auto rotr = [](uint32_t x, uint32_t n) { return (x >> n) | (x << (32U - n)); };
  const std::size_t total = ((msg.size() + 9U + 63U) / 64U) * 64U;
  for (std::size_t block = 0U; block < total; block += 64U) {
    std::array<uint32_t, 64> w{};
    for (std::size_t i = 0U; i < 64U; ++i) {
      const std::size_t pos = block + i;
      uint8_t byte = 0U;
      if (pos < msg.size()) {
        byte = msg[pos];
      } else if (pos == msg.size()) {
        byte = 0x80U;
      } else if (pos >= (total - 8U)) {
        const uint64_t bits = static_cast<uint64_t>(msg.size()) * 8U;
        byte = static_cast<uint8_t>(bits >> (8U * (total - 1U - pos)));
      } else {
        // a zero padding byte
      }
      w[i / 4U] |= static_cast<uint32_t>(byte) << (24U - (8U * (i % 4U)));
    }
    for (std::size_t i = 16U; i < 64U; ++i) {
      const uint32_t s0 = rotr(w[i - 15U], 7U) ^ rotr(w[i - 15U], 18U) ^ (w[i - 15U] >> 3U);
      const uint32_t s1 = rotr(w[i - 2U], 17U) ^ rotr(w[i - 2U], 19U) ^ (w[i - 2U] >> 10U);
      w[i] = w[i - 16U] + s0 + w[i - 7U] + s1;
    }
    std::array<uint32_t, 8> v = h;
    for (std::size_t i = 0U; i < 64U; ++i) {
      const uint32_t t1 = v[7] + (rotr(v[4], 6U) ^ rotr(v[4], 11U) ^ rotr(v[4], 25U)) +
                          ((v[4] & v[5]) ^ (~v[4] & v[6])) + kRound[i] + w[i];
      const uint32_t t2 = (rotr(v[0], 2U) ^ rotr(v[0], 13U) ^ rotr(v[0], 22U)) +
                          ((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]));
      v = {t1 + t2, v[0], v[1], v[2], v[3] + t1, v[4], v[5], v[6]};
    }
    for (std::size_t i = 0U; i < 8U; ++i) {
      h[i] += v[i];
    }
  }
  const std::size_t n = is224 ? 28U : 32U;
  for (std::size_t i = 0U; i < n; ++i) {
    out[i] = static_cast<uint8_t>(h[i / 4U] >> (24U - (8U * (i % 4U))));
  }
}

/// SHA-512 and SHA-384 (FIPS 180-4 6.4, 6.5).
inline void Sha512(ByteSpan msg, MutableByteSpan out, bool is384) {
  static constexpr std::array<uint64_t, 80> kRound{
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
  std::array<uint64_t, 8> h =
      is384 ? std::array<uint64_t, 8>{0xcbbb9d5dc1059ed8U, 0x629a292a367cd507U, 0x9159015a3070dd17U,
                                      0x152fecd8f70e5939U, 0x67332667ffc00b31U, 0x8eb44a8768581511U,
                                      0xdb0c2e0d64f98fa7U, 0x47b5481dbefa4fa4U}
            : std::array<uint64_t, 8>{0x6a09e667f3bcc908U, 0xbb67ae8584caa73bU, 0x3c6ef372fe94f82bU,
                                      0xa54ff53a5f1d36f1U, 0x510e527fade682d1U, 0x9b05688c2b3e6c1fU,
                                      0x1f83d9abfb41bd6bU, 0x5be0cd19137e2179U};
  const auto rotr = [](uint64_t x, uint64_t n) { return (x >> n) | (x << (64U - n)); };
  const std::size_t total = ((msg.size() + 17U + 127U) / 128U) * 128U;
  for (std::size_t block = 0U; block < total; block += 128U) {
    std::array<uint64_t, 80> w{};
    for (std::size_t i = 0U; i < 128U; ++i) {
      const std::size_t pos = block + i;
      uint8_t byte = 0U;
      if (pos < msg.size()) {
        byte = msg[pos];
      } else if (pos == msg.size()) {
        byte = 0x80U;
      } else if (pos >= (total - 8U)) {
        const uint64_t bits = static_cast<uint64_t>(msg.size()) * 8U;
        byte = static_cast<uint8_t>(bits >> (8U * (total - 1U - pos)));
      } else {
        // a zero padding byte
      }
      w[i / 8U] |= static_cast<uint64_t>(byte) << (56U - (8U * (i % 8U)));
    }
    for (std::size_t i = 16U; i < 80U; ++i) {
      const uint64_t s0 = rotr(w[i - 15U], 1U) ^ rotr(w[i - 15U], 8U) ^ (w[i - 15U] >> 7U);
      const uint64_t s1 = rotr(w[i - 2U], 19U) ^ rotr(w[i - 2U], 61U) ^ (w[i - 2U] >> 6U);
      w[i] = w[i - 16U] + s0 + w[i - 7U] + s1;
    }
    std::array<uint64_t, 8> v = h;
    for (std::size_t i = 0U; i < 80U; ++i) {
      const uint64_t t1 = v[7] + (rotr(v[4], 14U) ^ rotr(v[4], 18U) ^ rotr(v[4], 41U)) +
                          ((v[4] & v[5]) ^ (~v[4] & v[6])) + kRound[i] + w[i];
      const uint64_t t2 = (rotr(v[0], 28U) ^ rotr(v[0], 34U) ^ rotr(v[0], 39U)) +
                          ((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]));
      v = {t1 + t2, v[0], v[1], v[2], v[3] + t1, v[4], v[5], v[6]};
    }
    for (std::size_t i = 0U; i < 8U; ++i) {
      h[i] += v[i];
    }
  }
  const std::size_t n = is384 ? 48U : 64U;
  for (std::size_t i = 0U; i < n; ++i) {
    out[i] = static_cast<uint8_t>(h[i / 8U] >> (56U - (8U * (i % 8U))));
  }
}

/** @brief The crypto port of the attestation tests. */
class VectorCrypto : public se05x::CryptoInterface<VectorCrypto> {
public:
  std::array<uint8_t, 65> want_key{};           ///< The key the verification expects.
  std::array<uint8_t, 32> want_input{};         ///< The 32-byte ECDSA input it expects.
  std::array<uint8_t, 64> want_sig{};           ///< The raw signature it expects.
  CryptoStatus verify_status{CryptoStatus::Ok}; ///< What a matching verification returns.
  bool fail_hash{false};                        ///< Make every hash fail.
  int hashes{0};                                ///< Hashes computed.
  HashAlg last_hash{HashAlg::Sha256};           ///< The algorithm of the last hash.

  CryptoStatus ImportKey(KeyKind kind, ByteSpan key, KeyRef& ref) noexcept {
    static_cast<void>(kind);
    static_cast<void>(key);
    static_cast<void>(ref);
    return CryptoStatus::Failed;
  }
  CryptoStatus ReleaseKey(KeyRef ref) noexcept {
    static_cast<void>(ref);
    return CryptoStatus::Failed;
  }
  CryptoStatus AesCmac(KeyRef key, ByteSpan msg, std::span<uint8_t, 16> mac) noexcept {
    static_cast<void>(key);
    static_cast<void>(msg);
    static_cast<void>(mac);
    return CryptoStatus::Failed;
  }
  CryptoStatus AesCbc(KeyRef key, bool encrypt, std::span<uint8_t, 16> iv,
                      MutableByteSpan data) noexcept {
    static_cast<void>(key);
    static_cast<void>(encrypt);
    static_cast<void>(iv);
    static_cast<void>(data);
    return CryptoStatus::Failed;
  }
  CryptoStatus GenerateP256(KeyRef& key, std::span<uint8_t, 65> pub) noexcept {
    static_cast<void>(key);
    static_cast<void>(pub);
    return CryptoStatus::Failed;
  }
  CryptoStatus EcdhP256(KeyRef key, std::span<const uint8_t, 65> peer,
                        std::span<uint8_t, 32> secret) noexcept {
    static_cast<void>(key);
    static_cast<void>(peer);
    static_cast<void>(secret);
    return CryptoStatus::Failed;
  }
  CryptoStatus EcdsaP256Sign(KeyRef key, std::span<const uint8_t, 32> digest,
                             std::span<uint8_t, 64> signature) noexcept {
    static_cast<void>(key);
    static_cast<void>(digest);
    static_cast<void>(signature);
    return CryptoStatus::Failed;
  }
  CryptoStatus EcdsaP256Verify(std::span<const uint8_t, 65> pub,
                               std::span<const uint8_t, 32> digest,
                               std::span<const uint8_t, 64> signature) noexcept {
    bool same = true;
    for (std::size_t i = 0U; i < 65U; ++i) {
      same = same && (pub[i] == want_key[i]);
    }
    for (std::size_t i = 0U; i < 32U; ++i) {
      same = same && (digest[i] == want_input[i]);
    }
    for (std::size_t i = 0U; i < 64U; ++i) {
      same = same && (signature[i] == want_sig[i]);
    }
    return same ? verify_status : CryptoStatus::Mismatch;
  }
  CryptoStatus Hash(HashAlg alg, ByteSpan message, MutableByteSpan digest) noexcept {
    ++hashes;
    last_hash = alg;
    if (fail_hash) {
      return CryptoStatus::Failed;
    }
    switch (alg) {
    case HashAlg::Sha224:
    case HashAlg::Sha256:
      if (digest.size() < ((alg == HashAlg::Sha224) ? 28U : 32U)) {
        return CryptoStatus::Failed;
      }
      Sha256(message, digest, alg == HashAlg::Sha224);
      return CryptoStatus::Ok;
    case HashAlg::Sha384:
    case HashAlg::Sha512:
      if (digest.size() < ((alg == HashAlg::Sha384) ? 48U : 64U)) {
        return CryptoStatus::Failed;
      }
      Sha512(message, digest, alg == HashAlg::Sha384);
      return CryptoStatus::Ok;
    case HashAlg::Sha1:
    default:
      break;
    }
    return CryptoStatus::Failed;
  }
  CryptoStatus Random(MutableByteSpan out) noexcept {
    static_cast<void>(out);
    return CryptoStatus::Failed;
  }
};

} // namespace attesttest

#endif // SE05X_TEST_ATTEST_CRYPTO_HPP
