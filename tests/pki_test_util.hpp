/**
 * @file pki_test_util.hpp
 * @brief Helpers of the PKI tests: a byte buffer to mutate vectors in, a known-answer verifier for
 * P-384, and a test-only certificate issuer over the reference crypto.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * The issuer exists only to make variants the OpenSSL vectors do not cover (a v1 certificate, a
 * certificate for a key the chip model generated at run time). Its key is a made-up test scalar.
 */
#ifndef SE05X_TESTS_PKI_TEST_UTIL_HPP
#define SE05X_TESTS_PKI_TEST_UTIL_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

#include "se05x_crypto.hpp"
#include "se05x_pki_csr.hpp"
#include "se05x_pki_der.hpp"
#include "se05x_pki_types.hpp"
#include "se05x_pki_verify.hpp"
#include "se05x_pki_x509.hpp"

namespace se05x::pkitest {

using namespace se05x::pki; // NOLINT(google-build-using-namespace): test helpers only

/** @brief A copy of a vector that a test can edit. */
template <std::size_t N>
struct Copy {
  std::array<uint8_t, N + 8U> bytes{};
  std::size_t size{N};

  explicit Copy(const std::array<uint8_t, N>& v) noexcept {
    static_cast<void>(std::copy(v.begin(), v.end(), bytes.begin()));
  }
  [[nodiscard]] ByteSpan View() const noexcept {
    return ByteSpan{bytes}.first(size);
  }
  /** @return The offset of the first occurrence of `pattern` at or after `from`, or N. */
  [[nodiscard]] std::size_t Find(ByteSpan pattern, std::size_t from = 0U) const noexcept {
    for (std::size_t i = from; (i + pattern.size()) <= size; ++i) {
      if (std::equal(pattern.begin(), pattern.end(),
                     bytes.begin() + static_cast<std::ptrdiff_t>(i))) {
        return i;
      }
    }
    return N;
  }
};

/** @brief Deterministic test entropy. */
inline bool TestEntropy(MutableByteSpan out) noexcept {
  for (std::size_t i = 0U; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>(((i * 37U) + 11U) & 0xFFU);
  }
  return true;
}

/** @brief A verifier that accepts exactly one (type, key, digest, signature): a known answer. */
struct KnownAnswerVerifier {
  KeyType type{KeyType::EcP384};
  ByteSpan key;
  ByteSpan digest;
  ByteSpan raw;
  uint32_t calls{0};

  [[nodiscard]] bool Supports(KeyType t) const noexcept {
    return t != KeyType::Ed25519;
  }
  CryptoStatus VerifySignature(KeyType t, ByteSpan k, ByteSpan d, ByteSpan r) noexcept {
    ++calls;
    const bool same = (t == type) && der::SameBytes(k, key) && der::SameBytes(d, digest) &&
                      der::SameBytes(r, raw);
    return same ? CryptoStatus::Ok : CryptoStatus::Mismatch;
  }
};

/** @brief A verifier that always answers the same. */
struct FixedVerifier {
  CryptoStatus answer{CryptoStatus::Ok};
  bool supports{true};
  [[nodiscard]] bool Supports(KeyType t) const noexcept {
    return supports && (t != KeyType::Ed25519);
  }
  [[nodiscard]] CryptoStatus VerifySignature(KeyType t, ByteSpan k, ByteSpan d,
                                             ByteSpan r) const noexcept {
    static_cast<void>(t);
    static_cast<void>(k);
    static_cast<void>(d);
    static_cast<void>(r);
    return answer;
  }
};

/** @brief The RFC 6979 A.2.5 P-256 test key (a published test vector, not a key of anything). */
inline constexpr std::array<uint8_t, 32> kRfc6979Key{
    0xC9U, 0xAFU, 0xA9U, 0xD8U, 0x45U, 0xBAU, 0x75U, 0x16U, 0x6BU, 0x5CU, 0x21U,
    0x57U, 0x67U, 0xB1U, 0xD6U, 0x93U, 0x4EU, 0x50U, 0xC3U, 0xDBU, 0x36U, 0xE8U,
    0x9BU, 0x12U, 0x7BU, 0x8AU, 0x62U, 0x2BU, 0x12U, 0x0FU, 0x67U, 0x21U};
/// A made-up scalar for the test issuer.
inline constexpr std::array<uint8_t, 32> kTestCaKey{
    0x3AU, 0x5CU, 0x7EU, 0x91U, 0x12U, 0x34U, 0x56U, 0x78U, 0x9AU, 0xBCU, 0xDEU,
    0xF0U, 0x0FU, 0x1EU, 0x2DU, 0x3CU, 0x4BU, 0x5AU, 0x69U, 0x78U, 0x87U, 0x96U,
    0xA5U, 0xB4U, 0xC3U, 0xD2U, 0xE1U, 0xF0U, 0x01U, 0x23U, 0x45U, 0x67U};

/** @brief What the test issuer puts in a certificate. */
struct CertSpec {
  ByteSpan issuer;  ///< Encoded issuer Name.
  ByteSpan subject; ///< Encoded subject Name.
  PublicKey key{};  ///< Subject key.
  Time not_before{2025U, 1U, 1U, 0U, 0U, 0U};
  Time not_after{2045U, 1U, 1U, 0U, 0U, 0U};
  bool ca{false};
  uint8_t path_length{kNoPathLength};
  uint16_t key_usage{key_usage::kDigitalSignature};
  bool v1{false};
  uint32_t serial{1U};
};

/** @brief Write a UTCTime. */
inline void WriteUtc(der::Writer& w, const Time& t) noexcept {
  const std::array<uint32_t, 6> f{t.year % 100U, t.month, t.day, t.hour, t.minute, t.second};
  std::array<uint8_t, 13> s{};
  for (std::size_t i = 0U; i < f.size(); ++i) {
    s[2U * i] = static_cast<uint8_t>(0x30U + (f[i] / 10U));
    s[(2U * i) + 1U] = static_cast<uint8_t>(0x30U + (f[i] % 10U));
  }
  s[12] = 0x5AU;
  w.Primitive(der::kUtcTime, ByteSpan{s});
}

/** @brief Write the extensions of a test certificate. */
inline void WriteTestExtensions(der::Writer& w, const CertSpec& spec) noexcept {
  w.Begin(der::ContextConstructed(3U));
  w.Begin(der::kSequence);
  w.Begin(der::kSequence);
  w.Oid(ByteSpan{oid::kBasicConstraints});
  w.Boolean(true);
  w.Begin(der::kOctetString);
  w.Begin(der::kSequence);
  if (spec.ca) {
    w.Boolean(true);
    if (spec.path_length != kNoPathLength) {
      w.Small(spec.path_length);
    }
  }
  w.End();
  w.End();
  w.End();
  if (spec.key_usage != 0U) {
    w.Begin(der::kSequence);
    w.Oid(ByteSpan{oid::kKeyUsage});
    w.Boolean(true);
    w.Begin(der::kOctetString);
    w.NamedBits(spec.key_usage);
    w.End();
    w.End();
  }
  w.End();
  w.End();
}

/**
 * @brief Import a P-256 test scalar into the reference crypto and compute its public point.
 * @return true when both worked.
 */
inline bool LoadTestKey(ReferenceCrypto& crypto, const std::array<uint8_t, 32>& scalar, KeyRef& key,
                        std::array<uint8_t, 65>& pub) noexcept {
  return (crypto.ImportKey(KeyKind::P256Private, ByteSpan{scalar}, key) == CryptoStatus::Ok) &&
         refcrypto::P256PublicKey(std::span<const uint8_t, 32>{scalar},
                                  std::span<uint8_t, 65>{pub});
}

/** @brief A test-only issuer: ecdsa-with-SHA256 with a made-up P-256 key. */
class TestIssuer {
public:
  TestIssuer() noexcept
      : crypto_(&TestEntropy), ok_(LoadTestKey(crypto_, kTestCaKey, key_, pub_)) {}
  [[nodiscard]] bool Ok() const noexcept {
    return ok_;
  }
  [[nodiscard]] PublicKey Key() const noexcept {
    return PublicKey{KeyType::EcP256, ByteSpan{pub_}};
  }
  ReferenceCrypto& Crypto() noexcept {
    return crypto_;
  }
  /** @return The DER length of the issued certificate, 0 on failure. */
  std::size_t Issue(const CertSpec& spec, MutableByteSpan out) noexcept {
    der::Writer w(out);
    w.Begin(der::kSequence);
    w.Begin(der::kSequence);
    if (!spec.v1) {
      w.Begin(der::ContextConstructed(0U));
      w.Small(2U);
      w.End();
    }
    w.Small(spec.serial);
    pki::detail::WriteSignatureAlgorithm(w, SignatureAlgorithm::EcdsaSha256);
    w.Raw(spec.issuer);
    w.Begin(der::kSequence);
    WriteUtc(w, spec.not_before);
    WriteUtc(w, spec.not_after);
    w.End();
    w.Raw(spec.subject);
    pki::detail::WritePublicKeyInfo(w, spec.key);
    if (!spec.v1) {
      WriteTestExtensions(w, spec);
    }
    w.End();
    std::array<uint8_t, kMaxSignatureDer> sig{};
    PortSigner<ReferenceCrypto> signer(crypto_, key_);
    std::array<uint8_t, kMaxDigest> digest{};
    if ((w.Status() != Reason::Ok) ||
        (Digest(crypto_, SignatureAlgorithm::EcdsaSha256, w.LastClosed(), digest) != Reason::Ok)) {
      return 0U;
    }
    const Result<std::size_t> s = signer.Sign(ByteSpan{digest}.first(32U), MutableByteSpan{sig});
    if (!s.ok()) {
      return 0U;
    }
    pki::detail::WriteSignatureAlgorithm(w, SignatureAlgorithm::EcdsaSha256);
    w.BeginBitString();
    w.Raw(ByteSpan{sig}.first(s.value));
    w.End();
    w.End();
    const Result<std::size_t> done = w.Finish();
    return done.ok() ? done.value : 0U;
  }

private:
  ReferenceCrypto crypto_;
  KeyRef key_{};
  std::array<uint8_t, 65> pub_{};
  bool ok_{false};
};

/** @brief Encode a Name into a buffer; returns the view. */
template <std::size_t N>
ByteSpan EncodeName(const Name& name, std::array<uint8_t, N>& buffer) noexcept {
  der::Writer w(MutableByteSpan{buffer});
  name.Encode(w);
  const Result<std::size_t> r = w.Finish();
  return r.ok() ? ByteSpan{buffer}.first(r.value) : ByteSpan{};
}

/** @return 2030-01-01T00:00:00Z: inside every vector's validity but the expired one. */
inline uint64_t Now() noexcept {
  return ToUnixSeconds(Time{2030U, 1U, 1U, 0U, 0U, 0U});
}

} // namespace se05x::pkitest

#endif // SE05X_TESTS_PKI_TEST_UTIL_HPP
