/**
 * @file test_pki_x509.cpp
 * @brief PKI layer: the X.509 v3 parser on OpenSSL certificates, and every refusal of its profile
 * (RFC 5280 4.1 and 4.2, RFC 5480, RFC 5758).
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <array>
#include <cstddef>
#include <cstdint>

#include "pki_test_util.hpp"
#include "se05x_pki_x509.hpp"
#include "test_harness.hpp"
#include "vectors/pki_vectors.hpp"

using namespace se05x;
using namespace se05x::pki;
using pkitest::Copy;

namespace {

template <std::size_t N>
Reason ParseReason(const Copy<N>& c) {
  const Result<Certificate> r = ParseCertificate(c.View());
  return r.ok() ? Reason::Ok : ReasonOf(r.detail);
}

/// Change the byte `delta` after the first occurrence of `pattern` (from `from`).
template <std::size_t N>
bool Edit(Copy<N>& c, ByteSpan pattern, std::size_t delta, uint8_t value, std::size_t from = 0U) {
  const std::size_t at = c.Find(pattern, from);
  if (at >= N) {
    return false;
  }
  c.bytes[at + delta] = value;
  return true;
}

/// A certificate from the test issuer with the subject "CN=t" and its issuer name.
struct Issued {
  std::array<uint8_t, 600> der{};
  std::size_t size{0};
  [[nodiscard]] ByteSpan View() const {
    return ByteSpan{der}.first(size);
  }
};

constexpr std::array<uint8_t, 13> kNameT{0x30U, 0x0BU, 0x31U, 0x09U, 0x30U, 0x07U, 0x06U,
                                         0x03U, 0x55U, 0x04U, 0x03U, 0x0CU, 0x01U}; // + 't'
constexpr std::array<uint8_t, 14> kNameTFull{0x30U, 0x0CU, 0x31U, 0x0AU, 0x30U, 0x08U, 0x06U,
                                             0x03U, 0x55U, 0x04U, 0x03U, 0x0CU, 0x01U, 0x74U};
constexpr std::array<uint8_t, 2> kEmptyName{0x30U, 0x00U};

Issued Issue(pkitest::CertSpec spec) {
  pkitest::TestIssuer issuer;
  Issued out{};
  if (spec.issuer.empty()) {
    spec.issuer = ByteSpan{kNameTFull};
  }
  if (spec.subject.empty()) {
    spec.subject = ByteSpan{kNameTFull};
  }
  if (spec.key.bytes.empty()) {
    spec.key = issuer.Key();
  }
  out.size = issuer.Ok() ? issuer.Issue(spec, MutableByteSpan{out.der}) : 0U;
  return out;
}

Reason ParseIssued(const Issued& c) {
  const Result<Certificate> r = ParseCertificate(c.View());
  return r.ok() ? Reason::Ok : ReasonOf(r.detail);
}

} // namespace

TEST_CASE("PKI X.509: an OpenSSL end-entity certificate parses with every field") {
  const Result<Certificate> r = ParseCertificate(ByteSpan{testvec::kLeafP256});
  REQUIRE(r.ok());
  const Certificate& c = r.value;
  CHECK_EQ(c.der.size(), testvec::kLeafP256.size());
  CHECK(der::SameBytes(c.serial, std::array<uint8_t, 5>{0x1FU, 0x2EU, 0x3DU, 0x4CU, 0x5BU}));
  CHECK_EQ(c.signature_algorithm, SignatureAlgorithm::EcdsaSha256);
  CHECK_EQ(c.public_key.type, KeyType::EcP256);
  CHECK_EQ(c.public_key.bytes.size(), 65U);
  CHECK_EQ(c.public_key.bytes[0], 0x04U);
  CHECK(c.has_basic_constraints);
  CHECK(!c.is_ca);
  CHECK_EQ(c.path_length, kNoPathLength);
  CHECK(c.has_key_usage);
  CHECK_EQ(c.key_usage, key_usage::kDigitalSignature);
  CHECK(!c.subject_alt_names.empty());
  CHECK(!c.alt_names_critical);
  CHECK(!c.ext_key_usage.empty());
  CHECK_EQ(c.subject_key_id.size(), 20U);
  CHECK(!c.authority_key_id.empty());
  CHECK_EQ(c.not_before.year, 2025U);
  CHECK_EQ(c.not_before.month, 6U);
  CHECK_EQ(c.not_after.year, 2035U);
  CHECK_EQ(c.tbs[0], 0x30U);
  CHECK(c.tbs.data() == (c.der.data() + 4U));
  const Result<Certificate> issuer = ParseCertificate(ByteSpan{testvec::kIntermediateP256});
  REQUIRE(issuer.ok());
  CHECK(der::SameBytes(c.issuer, issuer.value.subject));
}

TEST_CASE("PKI X.509: CA certificates carry cA, the path length and keyCertSign") {
  const Result<Certificate> i = ParseCertificate(ByteSpan{testvec::kIntermediateP256});
  REQUIRE(i.ok());
  CHECK(i.value.is_ca);
  CHECK_EQ(i.value.path_length, 0U);
  CHECK_EQ(i.value.key_usage, static_cast<uint16_t>(key_usage::kKeyCertSign | key_usage::kCrlSign));
  const Result<Certificate> root = ParseCertificate(ByteSpan{testvec::kRootP256});
  REQUIRE(root.ok());
  CHECK(root.value.is_ca);
  CHECK_EQ(root.value.path_length, kNoPathLength);
  CHECK(der::SameBytes(root.value.issuer, root.value.subject));
  const Result<Certificate> second = ParseCertificate(ByteSpan{testvec::kSecondIntermediateP256});
  REQUIRE(second.ok());
  CHECK_EQ(second.value.path_length, 1U);
}

TEST_CASE("PKI X.509: P-384 keys and ecdsa-with-SHA384") {
  const Result<Certificate> root = ParseCertificate(ByteSpan{testvec::kRootP384});
  REQUIRE(root.ok());
  CHECK_EQ(root.value.public_key.type, KeyType::EcP384);
  CHECK_EQ(root.value.public_key.bytes.size(), 97U);
  CHECK_EQ(root.value.signature_algorithm, SignatureAlgorithm::EcdsaSha384);
  CHECK(der::SameBytes(root.value.public_key.bytes, ByteSpan{testvec::kRootP384PublicKey}));
  const Result<Certificate> leaf = ParseCertificate(ByteSpan{testvec::kLeafP384});
  REQUIRE(leaf.ok());
  CHECK_EQ(leaf.value.signature_algorithm, SignatureAlgorithm::EcdsaSha384);
}

TEST_CASE("PKI X.509: GeneralizedTime from 2050, and a certificate without extensions") {
  const Result<Certificate> gt = ParseCertificate(ByteSpan{testvec::kGeneralizedP256});
  REQUIRE(gt.ok());
  CHECK_EQ(gt.value.not_after.year, 2055U);
  const Result<Certificate> bare = ParseCertificate(ByteSpan{testvec::kNoExtensionsP256});
  REQUIRE(bare.ok());
  CHECK(!bare.value.has_basic_constraints);
  CHECK(!bare.value.has_key_usage);
  CHECK(bare.value.subject_alt_names.empty());
  // GeneralizedTime for a year before 2050 is not the RFC 5280 form: "2055" -> "2045"
  Copy<testvec::kGeneralizedP256.size()> c(testvec::kGeneralizedP256);
  REQUIRE(Edit(c, std::array<uint8_t, 4>{0x18U, 0x0FU, 0x32U, 0x30U}, 4U, 0x34U));
  CHECK_EQ(ParseReason(c), Reason::BadTime);
}

TEST_CASE("PKI X.509: an unknown critical extension is refused, never ignored") {
  const Result<Certificate> r = ParseCertificate(ByteSpan{testvec::kUnknownCriticalP256});
  CHECK_EQ(r.error, Error::Unsupported);
  CHECK_EQ(ReasonOf(r.detail), Reason::UnknownCriticalExtension);
  // The same extension made non-critical by dropping the BOOLEAN is not expressible in place; an
  // unknown non-critical extension is ignored: rename subjectAltName to an unknown id.
  Copy<testvec::kLeafP256.size()> c(testvec::kLeafP256);
  REQUIRE(Edit(c, ByteSpan{oid::kSubjectAltName}, 2U, 0x7FU));
  const Result<Certificate> ok = ParseCertificate(c.View());
  REQUIRE(ok.ok());
  CHECK(ok.value.subject_alt_names.empty());
}

TEST_CASE("PKI X.509: the two signature algorithms must be the same (4.1.1.2)") {
  Copy<testvec::kLeafP256.size()> outer(testvec::kLeafP256);
  const std::size_t first = outer.Find(ByteSpan{oid::kEcdsaSha256});
  REQUIRE(Edit(outer, ByteSpan{oid::kEcdsaSha256}, 7U, 0x03U, first + 1U));
  CHECK_EQ(ParseReason(outer), Reason::AlgorithmMismatch);
  Copy<testvec::kLeafP256.size()> inner(testvec::kLeafP256);
  REQUIRE(Edit(inner, ByteSpan{oid::kEcdsaSha256}, 7U, 0x03U));
  CHECK_EQ(ParseReason(inner), Reason::AlgorithmMismatch);
  Copy<testvec::kLeafP256.size()> both(testvec::kLeafP256);
  REQUIRE(Edit(both, ByteSpan{oid::kEcdsaSha256}, 7U, 0x04U));
  REQUIRE(Edit(both, ByteSpan{oid::kEcdsaSha256}, 7U, 0x04U));
  CHECK_EQ(ParseReason(both), Reason::UnsupportedAlgorithm); // ecdsa-with-SHA512
}

TEST_CASE("PKI X.509: v1 and v2 certificates are refused (4.1.2.1)") {
  Copy<testvec::kLeafP256.size()> c(testvec::kLeafP256);
  REQUIRE(Edit(c, std::array<uint8_t, 5>{0xA0U, 0x03U, 0x02U, 0x01U, 0x02U}, 4U, 0x01U));
  CHECK_EQ(ParseReason(c), Reason::UnsupportedVersion);
  pkitest::CertSpec spec{};
  spec.v1 = true;
  const Issued v1 = Issue(spec);
  REQUIRE(v1.size != 0U);
  CHECK_EQ(ParseIssued(v1), Reason::UnsupportedVersion);
  const Issued v3 = Issue(pkitest::CertSpec{});
  CHECK_EQ(ParseIssued(v3), Reason::Ok);
}

TEST_CASE("PKI X.509: trailing and missing bytes are refused") {
  Copy<testvec::kLeafP256.size()> longer(testvec::kLeafP256);
  longer.size = testvec::kLeafP256.size() + 1U;
  CHECK_EQ(ParseReason(longer), Reason::TrailingData);
  Copy<testvec::kLeafP256.size()> shorter(testvec::kLeafP256);
  shorter.size = testvec::kLeafP256.size() - 1U;
  CHECK_EQ(ParseReason(shorter), Reason::Truncated);
  CHECK_EQ(ReasonOf(ParseCertificate(ByteSpan{}).detail), Reason::Truncated);
}

TEST_CASE("PKI X.509: only P-256 and P-384 named curves, uncompressed points") {
  Copy<testvec::kLeafP256.size()> curve(testvec::kLeafP256);
  REQUIRE(Edit(curve, ByteSpan{oid::kP256}, 7U, 0x08U));
  CHECK_EQ(ParseReason(curve), Reason::UnsupportedCurve);
  Copy<testvec::kLeafP256.size()> point(testvec::kLeafP256);
  REQUIRE(Edit(point, std::array<uint8_t, 4>{0x03U, 0x42U, 0x00U, 0x04U}, 3U, 0x02U));
  CHECK_EQ(ParseReason(point), Reason::BadPublicKey);
  Copy<testvec::kLeafP256.size()> alg(testvec::kLeafP256);
  REQUIRE(Edit(alg, ByteSpan{oid::kEcPublicKey}, 6U, 0x02U));
  CHECK_EQ(ParseReason(alg), Reason::UnsupportedAlgorithm);
}

TEST_CASE("PKI X.509: DER rules inside the certificate: BOOLEAN, times, serial") {
  Copy<testvec::kLeafP256.size()> crit(testvec::kLeafP256);
  REQUIRE(Edit(crit, std::array<uint8_t, 3>{0x01U, 0x01U, 0xFFU}, 2U, 0x00U));
  CHECK_EQ(ParseReason(crit), Reason::BadBoolean);
  Copy<testvec::kLeafP256.size()> time(testvec::kLeafP256);
  REQUIRE(Edit(time, std::array<uint8_t, 3>{0x17U, 0x0DU, 0x32U}, 3U, 0x41U));
  CHECK_EQ(ParseReason(time), Reason::BadTime);
  pkitest::CertSpec zero{};
  zero.serial = 0U;
  CHECK_EQ(ParseIssued(Issue(zero)), Reason::BadInteger);
  pkitest::CertSpec backwards{};
  backwards.not_before = Time{2040U, 1U, 1U, 0U, 0U, 0U};
  backwards.not_after = Time{2030U, 1U, 1U, 0U, 0U, 0U};
  CHECK_EQ(ParseIssued(Issue(backwards)), Reason::BadTime);
}

TEST_CASE("PKI X.509: a duplicate extension is refused") {
  // keyUsage renamed to basicConstraints: the second basicConstraints is a duplicate.
  Copy<testvec::kLeafP256.size()> c(testvec::kLeafP256);
  REQUIRE(Edit(c, ByteSpan{oid::kKeyUsage}, 2U, 0x13U));
  CHECK_EQ(ParseReason(c), Reason::DuplicateExtension);
}

TEST_CASE("PKI X.509: names: empty issuer, empty subject without critical SAN, string types") {
  pkitest::CertSpec empty_issuer{};
  empty_issuer.issuer = ByteSpan{kEmptyName};
  CHECK_EQ(ParseIssued(Issue(empty_issuer)), Reason::BadName);
  pkitest::CertSpec empty_subject{};
  empty_subject.subject = ByteSpan{kEmptyName};
  CHECK_EQ(ParseIssued(Issue(empty_subject)), Reason::BadName);
  bool empty = false;
  CHECK_EQ(CheckName(ByteSpan{kEmptyName}, empty), Reason::Ok);
  CHECK(empty);
  CHECK_EQ(CheckName(ByteSpan{kNameTFull}, empty), Reason::Ok);
  CHECK(!empty);
  CHECK_EQ(CheckName(std::array<uint8_t, 4>{0x30U, 0x02U, 0x31U, 0x00U}, empty), Reason::BadName);
  Copy<kNameTFull.size()> bmp(kNameTFull);
  bmp.bytes[11] = 0x1EU; // BMPString
  CHECK_EQ(CheckName(bmp.View(), empty), Reason::BadString);
  Copy<kNameTFull.size()> printable(kNameTFull);
  printable.bytes[11] = der::kPrintableString;
  printable.bytes[13] = 0x40U; // '@'
  CHECK_EQ(CheckName(printable.View(), empty), Reason::BadString);
  CHECK_EQ(CheckName(std::array<uint8_t, 2>{0x31U, 0x00U}, empty), Reason::BadName);
  CHECK_EQ(CheckName(ByteSpan{kNameT}, empty), Reason::Truncated);
}

TEST_CASE("PKI X.509: unique identifiers are refused") {
  // Issue with an issuerUniqueID: write it by hand after the key, as [1] IMPLICIT BIT STRING.
  pkitest::TestIssuer issuer;
  REQUIRE(issuer.Ok());
  std::array<uint8_t, 600> out{};
  der::Writer w(MutableByteSpan{out});
  w.Begin(der::kSequence);
  w.Begin(der::ContextConstructed(0U));
  w.Small(2U);
  w.End();
  w.Small(1U);
  pki::detail::WriteSignatureAlgorithm(w, SignatureAlgorithm::EcdsaSha256);
  w.Raw(ByteSpan{kNameTFull});
  w.Begin(der::kSequence);
  pkitest::WriteUtc(w, Time{2025U, 1U, 1U, 0U, 0U, 0U});
  pkitest::WriteUtc(w, Time{2045U, 1U, 1U, 0U, 0U, 0U});
  w.End();
  w.Raw(ByteSpan{kNameTFull});
  pki::detail::WritePublicKeyInfo(w, issuer.Key());
  w.Primitive(der::ContextPrimitive(1U), std::array<uint8_t, 2>{0x00U, 0x01U});
  w.End();
  const Result<std::size_t> tbs = w.Finish();
  REQUIRE(tbs.ok());
  der::Reader reader(ByteSpan{out}.first(tbs.value));
  der::Reader inner(ByteSpan{});
  REQUIRE(reader.ExpectEnter(der::kSequence, inner) == Reason::Ok);
  Certificate cert{};
  der::Element alg{};
  CHECK_EQ(pki::detail::ParseTbsHead(inner, cert, alg), Reason::Ok);
  CHECK_EQ(pki::detail::ParseTbsTail(inner, cert), Reason::UniqueIdPresent);
}

TEST_CASE("PKI X.509: basicConstraints, keyUsage and GeneralNames values") {
  Certificate c{};
  CHECK_EQ(pki::detail::ParseBasicConstraints(
               std::array<uint8_t, 8>{0x30U, 0x06U, 0x01U, 0x01U, 0xFFU, 0x02U, 0x01U, 0x05U}, c),
           Reason::Ok);
  CHECK(c.is_ca);
  CHECK_EQ(c.path_length, 5U);
  CHECK_EQ(pki::detail::ParseBasicConstraints(
               std::array<uint8_t, 5>{0x30U, 0x03U, 0x02U, 0x01U, 0x00U}, c),
           Reason::BadExtension); // a path length without cA
  CHECK_EQ(pki::detail::ParseBasicConstraints(
               std::array<uint8_t, 5>{0x30U, 0x03U, 0x01U, 0x01U, 0x00U}, c),
           Reason::BadExtension); // cA FALSE written out
  CHECK_EQ(
      pki::detail::ParseBasicConstraints(
          std::array<uint8_t, 9>{0x30U, 0x07U, 0x01U, 0x01U, 0xFFU, 0x02U, 0x02U, 0x00U, 0xFFU}, c),
      Reason::BadExtension); // 255 is out of range
  CHECK_EQ(pki::detail::ParseBasicConstraints(std::array<uint8_t, 2>{0x30U, 0x00U}, c), Reason::Ok);
  CHECK(!c.is_ca);
  bool known = false;
  Certificate k{};
  CHECK_EQ(pki::detail::ApplyExtension(ByteSpan{oid::kKeyUsage}, true,
                                       std::array<uint8_t, 5>{0x03U, 0x03U, 0x06U, 0x00U, 0x40U}, k,
                                       known),
           Reason::BadExtension); // a key usage bit beyond decipherOnly
  CHECK(!k.has_key_usage);
  CHECK_EQ(pki::detail::CheckGeneralNames(
               std::array<uint8_t, 8>{0x30U, 0x06U, 0x87U, 0x04U, 0xC0U, 0x00U, 0x02U, 0x07U}),
           Reason::Ok);
  CHECK_EQ(pki::detail::CheckGeneralNames(
               std::array<uint8_t, 9>{0x30U, 0x07U, 0x87U, 0x05U, 0xC0U, 0x00U, 0x02U, 0x07U, 0U}),
           Reason::BadExtension);
  CHECK_EQ(pki::detail::CheckGeneralNames(std::array<uint8_t, 4>{0x30U, 0x02U, 0x82U, 0x00U}),
           Reason::BadExtension);
  CHECK_EQ(
      pki::detail::CheckGeneralNames(std::array<uint8_t, 5>{0x30U, 0x03U, 0x89U, 0x01U, 0x41U}),
      Reason::BadExtension);
  CHECK_EQ(
      pki::detail::CheckGeneralNames(std::array<uint8_t, 5>{0x30U, 0x03U, 0x82U, 0x01U, 0x80U}),
      Reason::BadExtension);
  CHECK_EQ(pki::detail::CheckGeneralNames(std::array<uint8_t, 2>{0x30U, 0x00U}),
           Reason::BadExtension);
  CHECK_EQ(pki::detail::CheckOidList(std::array<uint8_t, 2>{0x30U, 0x00U}), Reason::BadExtension);
}

TEST_CASE("PKI X.509: signature algorithm identifiers carry no parameters") {
  const std::array<uint8_t, 14> with_null{0x30U, 0x0CU, 0x06U, 0x08U, 0x2AU, 0x86U, 0x48U,
                                          0xCEU, 0x3DU, 0x04U, 0x03U, 0x02U, 0x05U, 0x00U};
  der::Reader r(ByteSpan{with_null});
  der::Element e{};
  REQUIRE(r.Next(e) == Reason::Ok);
  SignatureAlgorithm a = SignatureAlgorithm::Ed25519;
  CHECK_EQ(ParseSignatureAlgorithm(e, a), Reason::UnsupportedAlgorithm);
  const std::array<uint8_t, 7> ed{0x30U, 0x05U, 0x06U, 0x03U, 0x2BU, 0x65U, 0x70U};
  der::Reader r2(ByteSpan{ed});
  REQUIRE(r2.Next(e) == Reason::Ok);
  CHECK_EQ(ParseSignatureAlgorithm(e, a), Reason::Ok);
  CHECK_EQ(a, SignatureAlgorithm::Ed25519);
  std::array<uint8_t, 64> sig{};
  CHECK_EQ(CheckSignatureValue(SignatureAlgorithm::Ed25519, ByteSpan{sig}), Reason::Ok);
  CHECK_EQ(CheckSignatureValue(SignatureAlgorithm::Ed25519, ByteSpan{sig}.first(63U)),
           Reason::BadSignatureValue);
  CHECK_EQ(CheckSignatureValue(SignatureAlgorithm::EcdsaSha256, ByteSpan{sig}),
           Reason::BadSignatureValue);
}
