/**
 * @file test_pki_verify.cpp
 * @brief PKI layer: chain verification up to a trust anchor (RFC 5280 6.1 subset) on OpenSSL
 * chains: signatures, names, time, basic constraints, key usage, path length, limits.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <array>
#include <cstddef>
#include <cstdint>

#include "pki_test_util.hpp"
#include "se05x_crypto.hpp"
#include "se05x_pki_verify.hpp"
#include "test_harness.hpp"
#include "vectors/pki_vectors.hpp"

using namespace se05x;
using namespace se05x::pki;
using pkitest::Copy;

namespace {

TrustAnchor AnchorOf(ByteSpan der) {
  const Result<Certificate> c = ParseCertificate(der);
  if (!c.ok()) {
    return TrustAnchor{};
  }
  const Result<TrustAnchor> a = AnchorFromCertificate(c.value);
  return a.ok() ? a.value : TrustAnchor{};
}

struct Fixture {
  ReferenceCrypto crypto{&pkitest::TestEntropy};
  PortVerifier<ReferenceCrypto> verifier{crypto};
  std::array<TrustAnchor, 1> anchors{AnchorOf(ByteSpan{testvec::kRootP256})};
  VerifyOptions options{pkitest::Now(), 0U, false};

  Reason Verify(std::span<const ByteSpan> chain) {
    const Result<VerifiedChain> r =
        VerifyChain(chain, std::span<const TrustAnchor>{anchors}, options, verifier, crypto);
    return r.ok() ? Reason::Ok : ReasonOf(r.detail);
  }
};

uint64_t At(uint16_t year, uint8_t month, uint8_t day, uint8_t s) {
  return ToUnixSeconds(Time{year, month, day, 0U, 0U, s});
}

} // namespace

TEST_CASE("PKI verify: an OpenSSL P-256 chain verifies up to its root") {
  Fixture f;
  const std::array<ByteSpan, 2> chain{ByteSpan{testvec::kLeafP256},
                                      ByteSpan{testvec::kIntermediateP256}};
  const Result<VerifiedChain> r =
      VerifyChain(std::span<const ByteSpan>{chain}, std::span<const TrustAnchor>{f.anchors},
                  f.options, f.verifier, f.crypto);
  REQUIRE(r.ok());
  CHECK_EQ(r.value.length, 2U);
  CHECK_EQ(r.value.anchor_index, 0U);
  const Result<Certificate> leaf = ParseCertificate(ByteSpan{testvec::kLeafP256});
  REQUIRE(leaf.ok());
  CHECK(der::SameBytes(r.value.leaf_key.bytes, leaf.value.public_key.bytes));
  CHECK(der::SameBytes(r.value.leaf_subject, leaf.value.subject));
  f.options.required_key_usage = key_usage::kDigitalSignature;
  CHECK_EQ(f.Verify(chain), Reason::Ok);
}

TEST_CASE("PKI verify: trust anchors come from CA certificates only") {
  const Result<Certificate> leaf = ParseCertificate(ByteSpan{testvec::kLeafP256});
  REQUIRE(leaf.ok());
  CHECK_EQ(ReasonOf(AnchorFromCertificate(leaf.value).detail), Reason::NotCa);
  const Result<Certificate> nokcs = ParseCertificate(ByteSpan{testvec::kNoKeyCertSignP256});
  REQUIRE(nokcs.ok());
  CHECK_EQ(ReasonOf(AnchorFromCertificate(nokcs.value).detail), Reason::KeyCertSignMissing);
  const Result<Certificate> root = ParseCertificate(ByteSpan{testvec::kRootP256});
  REQUIRE(root.ok());
  const Result<TrustAnchor> a = AnchorFromCertificate(root.value);
  REQUIRE(a.ok());
  CHECK(der::SameBytes(a.value.subject, root.value.subject));
  CHECK_EQ(a.value.path_length, kNoPathLength);
}

TEST_CASE("PKI verify: validity includes both ends; outside it is NotYetValid or Expired") {
  Fixture f;
  const std::array<ByteSpan, 2> chain{ByteSpan{testvec::kLeafP256},
                                      ByteSpan{testvec::kIntermediateP256}};
  f.options.now_unix = At(2025U, 6U, 1U, 0U);
  CHECK_EQ(f.Verify(chain), Reason::Ok);
  f.options.now_unix = At(2025U, 6U, 1U, 0U) - 1U;
  CHECK_EQ(f.Verify(chain), Reason::NotYetValid);
  f.options.now_unix = At(2035U, 6U, 1U, 0U);
  CHECK_EQ(f.Verify(chain), Reason::Ok);
  f.options.now_unix = At(2035U, 6U, 1U, 1U);
  CHECK_EQ(f.Verify(chain), Reason::Expired);
  f.options.now_unix = pkitest::Now();
  const std::array<ByteSpan, 2> expired{ByteSpan{testvec::kExpiredP256},
                                        ByteSpan{testvec::kIntermediateP256}};
  CHECK_EQ(f.Verify(expired), Reason::Expired);
  f.options.now_unix = 0U;
  const Result<VerifiedChain> r =
      VerifyChain(std::span<const ByteSpan>{chain}, std::span<const TrustAnchor>{f.anchors},
                  f.options, f.verifier, f.crypto);
  CHECK_EQ(ReasonOf(r.detail), Reason::NoTime);
  CHECK_EQ(r.error, Error::InvalidArgument);
}

TEST_CASE("PKI verify: a changed signature or a changed TBS fails the signature check") {
  Fixture f;
  Copy<testvec::kLeafP256.size()> sig(testvec::kLeafP256);
  sig.bytes[sig.size - 1U] = static_cast<uint8_t>(sig.bytes[sig.size - 1U] ^ 0x01U);
  const std::array<ByteSpan, 2> a{sig.View(), ByteSpan{testvec::kIntermediateP256}};
  CHECK_EQ(f.Verify(a), Reason::SignatureInvalid);
  Copy<testvec::kLeafP256.size()> tbs(testvec::kLeafP256);
  const std::size_t at = tbs.Find(std::array<uint8_t, 5>{0x1FU, 0x2EU, 0x3DU, 0x4CU, 0x5BU});
  REQUIRE(at < tbs.size);
  tbs.bytes[at + 4U] = 0x5CU; // the serial
  const std::array<ByteSpan, 2> b{tbs.View(), ByteSpan{testvec::kIntermediateP256}};
  CHECK_EQ(f.Verify(b), Reason::SignatureInvalid);
  Copy<testvec::kIntermediateP256.size()> mid(testvec::kIntermediateP256);
  mid.bytes[mid.size - 1U] = static_cast<uint8_t>(mid.bytes[mid.size - 1U] ^ 0x01U);
  const std::array<ByteSpan, 2> c{ByteSpan{testvec::kLeafP256}, mid.View()};
  CHECK_EQ(f.Verify(c), Reason::SignatureInvalid);
}

TEST_CASE("PKI verify: names chain byte for byte; no anchor for the top issuer") {
  Fixture f;
  const std::array<ByteSpan, 1> alone{ByteSpan{testvec::kLeafP256}};
  CHECK_EQ(f.Verify(alone), Reason::NoTrustAnchor);
  f.anchors[0] = AnchorOf(ByteSpan{testvec::kIntermediateP256});
  CHECK_EQ(f.Verify(alone), Reason::Ok);
  f.anchors[0].path_length = kNoPathLength; // the intermediate's own pathLen 0 would stop first
  const std::array<ByteSpan, 2> wrong{ByteSpan{testvec::kLeafP256},
                                      ByteSpan{testvec::kSecondIntermediateP256}};
  CHECK_EQ(f.Verify(wrong), Reason::NameMismatch);
}

TEST_CASE("PKI verify: pathLenConstraint and the anchor's path length") {
  Fixture f;
  const std::array<ByteSpan, 3> deep{ByteSpan{testvec::kTooDeepP256},
                                     ByteSpan{testvec::kSecondIntermediateP256},
                                     ByteSpan{testvec::kIntermediateP256}};
  CHECK_EQ(f.Verify(deep), Reason::PathLengthExceeded);
  // Below the intermediate itself (path length 0 allows no further CA) the chain is fine:
  const std::array<ByteSpan, 2> shallow{ByteSpan{testvec::kLeafP256},
                                        ByteSpan{testvec::kIntermediateP256}};
  f.anchors[0].path_length = 0U;
  CHECK_EQ(f.Verify(shallow), Reason::PathLengthExceeded);
  f.anchors[0].path_length = 1U;
  CHECK_EQ(f.Verify(shallow), Reason::Ok);
  // With the intermediate as anchor, the second intermediate (pathLen 1) may issue the leaf.
  f.anchors[0] = AnchorOf(ByteSpan{testvec::kIntermediateP256});
  const std::array<ByteSpan, 2> below{ByteSpan{testvec::kTooDeepP256},
                                      ByteSpan{testvec::kSecondIntermediateP256}};
  CHECK_EQ(f.Verify(below), Reason::PathLengthExceeded); // the anchor's own pathLen 0
  f.anchors[0].path_length = kNoPathLength;
  CHECK_EQ(f.Verify(below), Reason::Ok);
}

TEST_CASE("PKI verify: an issuer must be a CA with keyCertSign") {
  Fixture f;
  const std::array<ByteSpan, 2> notca{ByteSpan{testvec::kUnderNotCaP256},
                                      ByteSpan{testvec::kNotCaP256}};
  CHECK_EQ(f.Verify(notca), Reason::NotCa);
  const std::array<ByteSpan, 2> nokcs{ByteSpan{testvec::kUnderNoKeyCertSignP256},
                                      ByteSpan{testvec::kNoKeyCertSignP256}};
  CHECK_EQ(f.Verify(nokcs), Reason::KeyCertSignMissing);
  const std::array<ByteSpan, 2> bare{ByteSpan{testvec::kLeafP256},
                                     ByteSpan{testvec::kNoExtensionsP256}};
  f.anchors[0] = AnchorOf(ByteSpan{testvec::kIntermediateP256});
  const std::array<ByteSpan, 1> bare_leaf{ByteSpan{testvec::kNoExtensionsP256}};
  CHECK_EQ(f.Verify(bare_leaf), Reason::Ok);
  CHECK_EQ(f.Verify(bare), Reason::NotCa); // no basicConstraints at all
}

TEST_CASE("PKI verify: the end entity: required key usage, CA as leaf") {
  Fixture f;
  const std::array<ByteSpan, 2> chain{ByteSpan{testvec::kLeafP256},
                                      ByteSpan{testvec::kIntermediateP256}};
  f.options.required_key_usage = key_usage::kKeyAgreement;
  CHECK_EQ(f.Verify(chain), Reason::LeafKeyUsageMissing);
  f.options.required_key_usage = key_usage::kDigitalSignature;
  f.anchors[0] = AnchorOf(ByteSpan{testvec::kIntermediateP256});
  const std::array<ByteSpan, 1> bare{ByteSpan{testvec::kNoExtensionsP256}};
  CHECK_EQ(f.Verify(bare), Reason::LeafKeyUsageMissing);
  f.options.required_key_usage = 0U;
  f.anchors[0] = AnchorOf(ByteSpan{testvec::kRootP256});
  const std::array<ByteSpan, 1> ca{ByteSpan{testvec::kIntermediateP256}};
  CHECK_EQ(f.Verify(ca), Reason::LeafIsCa);
  f.options.allow_ca_leaf = true;
  CHECK_EQ(f.Verify(ca), Reason::Ok);
}

TEST_CASE("PKI verify: a certificate the parser refuses stops the chain") {
  Fixture f;
  const std::array<ByteSpan, 2> chain{ByteSpan{testvec::kUnknownCriticalP256},
                                      ByteSpan{testvec::kIntermediateP256}};
  const Result<VerifiedChain> r =
      VerifyChain(std::span<const ByteSpan>{chain}, std::span<const TrustAnchor>{f.anchors},
                  f.options, f.verifier, f.crypto);
  CHECK_EQ(ReasonOf(r.detail), Reason::UnknownCriticalExtension);
  CHECK_EQ(r.error, Error::Unsupported);
  Copy<testvec::kIntermediateP256.size()> top(testvec::kIntermediateP256);
  top.size = top.size - 1U;
  const std::array<ByteSpan, 2> broken{ByteSpan{testvec::kLeafP256}, top.View()};
  CHECK_EQ(f.Verify(broken), Reason::Truncated);
}

TEST_CASE("PKI verify: P-384 through a verifier that supports it (known answer from OpenSSL)") {
  ReferenceCrypto crypto{&pkitest::TestEntropy};
  pkitest::KnownAnswerVerifier kat{};
  kat.type = KeyType::EcP384;
  kat.key = ByteSpan{testvec::kRootP384PublicKey};
  kat.digest = ByteSpan{testvec::kLeafP384TbsSha384};
  kat.raw = ByteSpan{testvec::kLeafP384Signature};
  const std::array<TrustAnchor, 1> anchors{AnchorOf(ByteSpan{testvec::kRootP384})};
  const std::array<ByteSpan, 1> chain{ByteSpan{testvec::kLeafP384}};
  const VerifyOptions options{pkitest::Now(), key_usage::kDigitalSignature, false};
  const Result<VerifiedChain> r =
      VerifyChain(std::span<const ByteSpan>{chain}, std::span<const TrustAnchor>{anchors}, options,
                  kat, crypto);
  REQUIRE(r.ok());
  CHECK_EQ(kat.calls, 1U);
  CHECK_EQ(r.value.leaf_key.type, KeyType::EcP384);
  kat.digest = ByteSpan{testvec::kLeafP384TbsSha384}.first(47U);
  CHECK_EQ(ReasonOf(VerifyChain(std::span<const ByteSpan>{chain},
                                std::span<const TrustAnchor>{anchors}, options, kat, crypto)
                        .detail),
           Reason::SignatureInvalid);
  PortVerifier<ReferenceCrypto> p256{crypto};
  CHECK_EQ(ReasonOf(VerifyChain(std::span<const ByteSpan>{chain},
                                std::span<const TrustAnchor>{anchors}, options, p256, crypto)
                        .detail),
           Reason::CurveNotSupported);
}

TEST_CASE("PKI verify: a key and a hash that do not pair are refused (RFC 5480 4)") {
  ReferenceCrypto crypto{&pkitest::TestEntropy};
  pkitest::FixedVerifier yes{};
  const std::array<TrustAnchor, 1> anchors{AnchorOf(ByteSpan{testvec::kRootP384})};
  const std::array<ByteSpan, 1> chain{ByteSpan{testvec::kMixedP384}};
  const VerifyOptions options{pkitest::Now(), 0U, false};
  CHECK_EQ(ReasonOf(VerifyChain(std::span<const ByteSpan>{chain},
                                std::span<const TrustAnchor>{anchors}, options, yes, crypto)
                        .detail),
           Reason::AlgorithmMismatch);
  const PublicKey ed{KeyType::Ed25519, ByteSpan{testvec::kRootP384PublicKey}.first(32U)};
  CHECK_EQ(VerifySigned(yes, crypto, ed, SignatureAlgorithm::Ed25519, ByteSpan{}, ByteSpan{}),
           Reason::UnsupportedAlgorithm);
}

TEST_CASE("PKI verify: the verifier's answers map to reasons") {
  ReferenceCrypto crypto{&pkitest::TestEntropy};
  const std::array<TrustAnchor, 1> anchors{AnchorOf(ByteSpan{testvec::kRootP256})};
  const std::array<ByteSpan, 2> chain{ByteSpan{testvec::kLeafP256},
                                      ByteSpan{testvec::kIntermediateP256}};
  const VerifyOptions options{pkitest::Now(), 0U, false};
  pkitest::FixedVerifier v{};
  const std::array<CryptoStatus, 4> answers{CryptoStatus::Ok, CryptoStatus::Mismatch,
                                            CryptoStatus::InvalidKey, CryptoStatus::Failed};
  const std::array<Reason, 4> reasons{Reason::Ok, Reason::SignatureInvalid, Reason::BadPublicKey,
                                      Reason::CryptoFailure};
  for (std::size_t i = 0U; i < answers.size(); ++i) {
    v.answer = answers[i];
    const Result<VerifiedChain> r =
        VerifyChain(std::span<const ByteSpan>{chain}, std::span<const TrustAnchor>{anchors},
                    options, v, crypto);
    CHECK_EQ(r.ok() ? Reason::Ok : ReasonOf(r.detail), reasons[i]);
  }
  v.answer = CryptoStatus::Ok;
  std::array<TrustAnchor, 1> short_key = anchors;
  short_key[0].key.bytes = short_key[0].key.bytes.first(64U);
  CHECK_EQ(ReasonOf(VerifyChain(std::span<const ByteSpan>{chain},
                                std::span<const TrustAnchor>{short_key}, options, v, crypto)
                        .detail),
           Reason::BadPublicKey);
  v.supports = false;
  CHECK_EQ(ReasonOf(VerifyChain(std::span<const ByteSpan>{chain},
                                std::span<const TrustAnchor>{anchors}, options, v, crypto)
                        .detail),
           Reason::CurveNotSupported);
}

TEST_CASE("PKI verify: several anchors with one name: the one whose key verifies") {
  Fixture f;
  const std::array<ByteSpan, 2> chain{ByteSpan{testvec::kLeafP256},
                                      ByteSpan{testvec::kIntermediateP256}};
  TrustAnchor wrong = AnchorOf(ByteSpan{testvec::kRootP256});
  const Result<Certificate> other = ParseCertificate(ByteSpan{testvec::kNotCaP256});
  REQUIRE(other.ok());
  wrong.key = other.value.public_key; // same name, another P-256 key
  const std::array<TrustAnchor, 2> anchors{wrong, AnchorOf(ByteSpan{testvec::kRootP256})};
  const Result<VerifiedChain> r =
      VerifyChain(std::span<const ByteSpan>{chain}, std::span<const TrustAnchor>{anchors},
                  f.options, f.verifier, f.crypto);
  REQUIRE(r.ok());
  CHECK_EQ(r.value.anchor_index, 1U);
  const std::array<TrustAnchor, 1> only_wrong{wrong};
  CHECK_EQ(ReasonOf(VerifyChain(std::span<const ByteSpan>{chain},
                                std::span<const TrustAnchor>{only_wrong}, f.options, f.verifier,
                                f.crypto)
                        .detail),
           Reason::SignatureInvalid);
}

TEST_CASE("PKI verify: limits: empty chain, too long, too many anchors, none") {
  Fixture f;
  CHECK_EQ(f.Verify(std::span<const ByteSpan>{}), Reason::EmptyInput);
  std::array<ByteSpan, kMaxChain + 1U> many{};
  many.fill(ByteSpan{testvec::kIntermediateP256});
  CHECK_EQ(f.Verify(many), Reason::ChainTooLong);
  std::array<ByteSpan, kMaxChain> most{};
  most.fill(ByteSpan{testvec::kIntermediateP256});
  CHECK_EQ(f.Verify(most), Reason::NameMismatch); // within the limit: checked, and wrong
  const std::array<ByteSpan, 1> chain{ByteSpan{testvec::kIntermediateP256}};
  std::array<TrustAnchor, kMaxAnchors + 1U> anchors{};
  anchors.fill(f.anchors[0]);
  const VerifyOptions ca_leaf{pkitest::Now(), 0U, true};
  CHECK_EQ(
      ReasonOf(VerifyChain(std::span<const ByteSpan>{chain}, std::span<const TrustAnchor>{anchors},
                           ca_leaf, f.verifier, f.crypto)
                   .detail),
      Reason::TooManyEntries);
  CHECK(VerifyChain(std::span<const ByteSpan>{chain},
                    std::span<const TrustAnchor>{anchors}.first(kMaxAnchors), ca_leaf, f.verifier,
                    f.crypto)
            .ok());
  CHECK_EQ(ReasonOf(VerifyChain(std::span<const ByteSpan>{chain}, std::span<const TrustAnchor>{},
                                ca_leaf, f.verifier, f.crypto)
                        .detail),
           Reason::NoTrustAnchor);
}

TEST_CASE("PKI verify: the digest of a TBSCertificate matches OpenSSL's") {
  ReferenceCrypto crypto{&pkitest::TestEntropy};
  const Result<Certificate> leaf = ParseCertificate(ByteSpan{testvec::kLeafP384});
  REQUIRE(leaf.ok());
  std::array<uint8_t, kMaxDigest> digest{};
  CHECK_EQ(Digest(crypto, SignatureAlgorithm::EcdsaSha384, leaf.value.tbs, digest), Reason::Ok);
  CHECK(der::SameBytes(ByteSpan{digest}, ByteSpan{testvec::kLeafP384TbsSha384}));
  CHECK_EQ(Digest(crypto, SignatureAlgorithm::Ed25519, leaf.value.tbs, digest),
           Reason::UnsupportedAlgorithm);
  std::array<uint8_t, 96> raw{};
  CHECK_EQ(der::ParseEcdsaSignature(leaf.value.signature, 48U, MutableByteSpan{raw}), Reason::Ok);
  CHECK(der::SameBytes(ByteSpan{raw}, ByteSpan{testvec::kLeafP384Signature}));
}
