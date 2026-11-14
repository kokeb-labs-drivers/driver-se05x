/**
 * @file test_pki_csr.cpp
 * @brief PKI layer: subject and alternative-name builders, PKCS#10 requests (RFC 2986) compared
 * with OpenSSL's, signer adapters and `VerifyCsr()`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

#include "pki_test_util.hpp"
#include "se05x_crypto.hpp"
#include "se05x_pki_csr.hpp"
#include "test_harness.hpp"
#include "vectors/pki_vectors.hpp"

using namespace se05x;
using namespace se05x::pki;
using pkitest::Copy;

namespace {

// "Test Vectors", "device-0001", "device-0001.example"
constexpr std::array<uint8_t, 12> kOrg{0x54U, 0x65U, 0x73U, 0x74U, 0x20U, 0x56U,
                                       0x65U, 0x63U, 0x74U, 0x6FU, 0x72U, 0x73U};
constexpr std::array<uint8_t, 11> kCn{0x64U, 0x65U, 0x76U, 0x69U, 0x63U, 0x65U,
                                      0x2DU, 0x30U, 0x30U, 0x30U, 0x31U};
constexpr std::array<uint8_t, 19> kDns{0x64U, 0x65U, 0x76U, 0x69U, 0x63U, 0x65U, 0x2DU,
                                       0x30U, 0x30U, 0x30U, 0x31U, 0x2EU, 0x65U, 0x78U,
                                       0x61U, 0x6DU, 0x70U, 0x6CU, 0x65U};

/// The OpenSSL request's CertificationRequestInfo: offset 4, 3 + 208 bytes.
ByteSpan OpenSslInfo() {
  return ByteSpan{testvec::kCsrP256}.subspan(4U, 211U);
}

/// A signer that returns fixed bytes and records its input.
struct ScriptedSigner {
  SignatureAlgorithm algorithm{SignatureAlgorithm::EcdsaSha256};
  ByteSpan output;
  std::array<uint8_t, 512> seen{};
  std::size_t seen_length{0};
  std::size_t length_override{0};
  Error error{Error::Ok};

  [[nodiscard]] SignatureAlgorithm Algorithm() const noexcept {
    return algorithm;
  }
  Result<std::size_t> Sign(ByteSpan input, MutableByteSpan signature) noexcept {
    seen_length = std::min(input.size(), seen.size());
    static_cast<void>(std::copy(
        input.begin(), input.begin() + static_cast<std::ptrdiff_t>(seen_length), seen.begin()));
    if (error != Error::Ok) {
      return Result<std::size_t>::Failure(error, Detail{0x6985U, 0x01U, Layer::Device, 0U, 0xFFU});
    }
    const std::size_t n = std::min(output.size(), signature.size());
    static_cast<void>(std::copy(output.begin(), output.begin() + static_cast<std::ptrdiff_t>(n),
                                signature.begin()));
    return Result<std::size_t>::Success((length_override != 0U) ? length_override : n);
  }
};

struct Rfc6979 {
  ReferenceCrypto crypto{&pkitest::TestEntropy};
  KeyRef key{};
  std::array<uint8_t, 65> pub{};
  bool ok{pkitest::LoadTestKey(crypto, pkitest::kRfc6979Key, key, pub)};
};

Name TestName() {
  Name n{};
  static_cast<void>(
      n.Add(Attribute::Organization, ByteSpan{kOrg}).Add(Attribute::CommonName, ByteSpan{kCn}));
  return n;
}

Reason ReasonOfResult(const Result<std::size_t>& r) {
  return r.ok() ? Reason::Ok : ReasonOf(r.detail);
}

} // namespace

TEST_CASE("PKI CSR: the subject name is what OpenSSL writes") {
  const Name n = TestName();
  CHECK_EQ(n.Status(), Reason::Ok);
  CHECK_EQ(n.Count(), 2U);
  std::array<uint8_t, 128> buf{};
  const ByteSpan encoded = pkitest::EncodeName(n, buf);
  CHECK(der::SameBytes(encoded, ByteSpan{testvec::kCsrP256}.subspan(10U, 47U)));
}

TEST_CASE("PKI CSR: the name builder refuses bad values and latches the first error") {
  std::array<uint8_t, 129> long_value{};
  long_value.fill(0x61U);
  Name a{};
  static_cast<void>(a.Add(Attribute::CommonName, ByteSpan{long_value}.first(64U)));
  CHECK_EQ(a.Status(), Reason::Ok);
  static_cast<void>(a.Add(Attribute::CommonName, ByteSpan{long_value}.first(65U)));
  CHECK_EQ(a.Status(), Reason::InvalidInput);
  CHECK_EQ(a.Count(), 1U);
  Name b{};
  static_cast<void>(b.Add(Attribute::Locality, ByteSpan{long_value}.first(128U)));
  CHECK_EQ(b.Status(), Reason::Ok);
  static_cast<void>(b.Add(Attribute::Locality, ByteSpan{long_value}));
  CHECK_EQ(b.Status(), Reason::InvalidInput);
  const std::array<std::array<uint8_t, 2>, 3> countries{
      {{0x43U, 0x48U}, {0x63U, 0x68U}, {0x43U, 0x31U}}};
  const std::array<Reason, 3> expected{Reason::Ok, Reason::InvalidInput, Reason::InvalidInput};
  for (std::size_t i = 0U; i < countries.size(); ++i) {
    Name c{};
    static_cast<void>(c.Add(Attribute::Country, ByteSpan{countries[i]}));
    CHECK_EQ(c.Status(), expected[i]);
  }
  Name d{};
  static_cast<void>(d.Add(Attribute::Country, std::array<uint8_t, 3>{0x43U, 0x48U, 0x45U}));
  CHECK_EQ(d.Status(), Reason::InvalidInput);
  Name e{};
  static_cast<void>(e.Add(Attribute::SerialNumber, std::array<uint8_t, 2>{0x41U, 0x40U}));
  CHECK_EQ(e.Status(), Reason::InvalidInput);
  Name f{};
  static_cast<void>(f.Add(Attribute::CommonName, std::array<uint8_t, 1>{0xC3U}));
  CHECK_EQ(f.Status(), Reason::InvalidInput);
  Name g{};
  static_cast<void>(g.Add(Attribute::CommonName, ByteSpan{}));
  CHECK_EQ(g.Status(), Reason::InvalidInput);
  Name h{};
  // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange): a value that is no enumerator
  static_cast<void>(h.Add(static_cast<Attribute>(9U), ByteSpan{kCn}));
  CHECK_EQ(h.Status(), Reason::InvalidInput);
}

TEST_CASE("PKI CSR: at most kMaxNameAttributes; AddHex writes upper-case hex") {
  Name n{};
  for (std::size_t i = 0U; i < kMaxNameAttributes; ++i) {
    static_cast<void>(n.Add(Attribute::OrganizationalUnit, ByteSpan{kCn}));
  }
  CHECK_EQ(n.Status(), Reason::Ok);
  static_cast<void>(n.Add(Attribute::OrganizationalUnit, ByteSpan{kCn}));
  CHECK_EQ(n.Status(), Reason::TooManyEntries);
  CHECK_EQ(n.Count(), kMaxNameAttributes);
  Name hex{};
  static_cast<void>(
      hex.AddHex(Attribute::SerialNumber, std::array<uint8_t, 3>{0x0AU, 0xBCU, 0x9FU}));
  REQUIRE(hex.Status() == Reason::Ok);
  std::array<uint8_t, 64> buf{};
  const ByteSpan encoded = pkitest::EncodeName(hex, buf);
  // 30 11 31 0F 30 0D 06 03 55 04 05 13 06 "0ABC9F"
  const std::array<uint8_t, 19> expected{0x30U, 0x11U, 0x31U, 0x0FU, 0x30U, 0x0DU, 0x06U,
                                         0x03U, 0x55U, 0x04U, 0x05U, 0x13U, 0x06U, 0x30U,
                                         0x41U, 0x42U, 0x43U, 0x39U, 0x46U};
  CHECK(der::SameBytes(encoded, ByteSpan{expected}));
  std::array<uint8_t, kMaxHexInput + 1U> big{};
  Name too{};
  static_cast<void>(too.AddHex(Attribute::CommonName, ByteSpan{big}));
  CHECK_EQ(too.Status(), Reason::InvalidInput);
  Name empty{};
  static_cast<void>(empty.AddHex(Attribute::CommonName, ByteSpan{}));
  CHECK_EQ(empty.Status(), Reason::InvalidInput);
  Name most{};
  static_cast<void>(most.AddHex(Attribute::CommonName, ByteSpan{big}.first(kMaxHexInput)));
  CHECK_EQ(most.Status(), Reason::Ok);
}

TEST_CASE("PKI CSR: alternative names: types, limits, encoding") {
  const std::array<uint8_t, 4> ip{192U, 0U, 2U, 7U};
  AltNames a{};
  static_cast<void>(a.Add(AltNameType::Dns, ByteSpan{kDns})
                        .Add(AltNameType::Ip, ByteSpan{ip})
                        .Add(AltNameType::Uri, ByteSpan{kDns})
                        .Add(AltNameType::Email, ByteSpan{kDns}));
  CHECK_EQ(a.Status(), Reason::Ok);
  std::array<uint8_t, 128> buf{};
  der::Writer w(MutableByteSpan{buf});
  a.Encode(w);
  const Result<std::size_t> r = w.Finish();
  REQUIRE(r.ok());
  CHECK_EQ(pki::detail::CheckGeneralNames(ByteSpan{buf}.first(r.value)), Reason::Ok);
  CHECK_EQ(buf[2], 0x82U);
  CHECK_EQ(buf[2U + 2U + kDns.size()], 0x87U);
  AltNames bad_ip{};
  static_cast<void>(bad_ip.Add(AltNameType::Ip, std::array<uint8_t, 5>{}));
  CHECK_EQ(bad_ip.Status(), Reason::InvalidInput);
  AltNames bad_text{};
  static_cast<void>(bad_text.Add(AltNameType::Dns, std::array<uint8_t, 1>{0x80U}));
  CHECK_EQ(bad_text.Status(), Reason::InvalidInput);
  AltNames empty{};
  static_cast<void>(empty.Add(AltNameType::Dns, ByteSpan{}));
  CHECK_EQ(empty.Status(), Reason::InvalidInput);
  AltNames many{};
  for (std::size_t i = 0U; i <= kMaxAltNames; ++i) {
    static_cast<void>(many.Add(AltNameType::Dns, ByteSpan{kDns}));
  }
  CHECK_EQ(many.Status(), Reason::TooManyEntries);
  CHECK_EQ(many.Count(), kMaxAltNames);
  AltNames none{};
  der::Writer w2(MutableByteSpan{buf});
  none.Encode(w2);
  CHECK_EQ(w2.Status(), Reason::EmptyInput);
  AltNames odd{};
  // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange): a value that is no enumerator
  static_cast<void>(odd.Add(static_cast<AltNameType>(7U), ByteSpan{kDns}));
  CHECK_EQ(odd.Status(), Reason::InvalidInput);
}

TEST_CASE("PKI CSR: a P-256 request through a port key matches OpenSSL's and verifies") {
  Rfc6979 k;
  REQUIRE(k.ok);
  const Name subject = TestName();
  AltNames alt{};
  static_cast<void>(alt.Add(AltNameType::Dns, ByteSpan{kDns}));
  const CsrRequest request{&subject, PublicKey{KeyType::EcP256, ByteSpan{k.pub}}, &alt,
                           key_usage::kDigitalSignature};
  PortSigner<ReferenceCrypto> signer(k.crypto, k.key);
  std::array<uint8_t, 400> csr{};
  const Result<std::size_t> r = BuildCsr(request, signer, k.crypto, MutableByteSpan{csr});
  REQUIRE(r.ok());
  // Same info as OpenSSL, byte for byte (the ECDSA signatures differ: nonces).
  der::Reader outer(ByteSpan{csr}.first(r.value));
  der::Reader top(ByteSpan{});
  der::Element info{};
  REQUIRE(outer.ExpectEnter(der::kSequence, top) == Reason::Ok);
  REQUIRE(top.Expect(der::kSequence, info) == Reason::Ok);
  CHECK(der::SameBytes(info.encoded, OpenSslInfo()));
  PortVerifier<ReferenceCrypto> verifier(k.crypto);
  const Result<CsrInfo> v = VerifyCsr(ByteSpan{csr}.first(r.value), verifier, k.crypto);
  REQUIRE(v.ok());
  CHECK(der::SameBytes(v.value.key.bytes, ByteSpan{k.pub}));
  CHECK_EQ(v.value.signature_algorithm, SignatureAlgorithm::EcdsaSha256);
  // RFC 6979 makes the reference signer deterministic: the same request twice is the same bytes.
  std::array<uint8_t, 400> again{};
  const Result<std::size_t> r2 = BuildCsr(request, signer, k.crypto, MutableByteSpan{again});
  REQUIRE(r2.ok());
  CHECK(der::SameBytes(ByteSpan{csr}.first(r.value), ByteSpan{again}.first(r2.value)));
}

TEST_CASE("PKI CSR: OpenSSL's request verifies; changes to it do not") {
  ReferenceCrypto crypto{&pkitest::TestEntropy};
  PortVerifier<ReferenceCrypto> verifier(crypto);
  const Result<CsrInfo> ok = VerifyCsr(ByteSpan{testvec::kCsrP256}, verifier, crypto);
  REQUIRE(ok.ok());
  CHECK_EQ(ok.value.key.type, KeyType::EcP256);
  CHECK(!ok.value.attributes.empty());
  Copy<testvec::kCsrP256.size()> sig(testvec::kCsrP256);
  sig.bytes[sig.size - 1U] = static_cast<uint8_t>(sig.bytes[sig.size - 1U] ^ 0x01U);
  CHECK_EQ(ReasonOf(VerifyCsr(sig.View(), verifier, crypto).detail), Reason::SignatureInvalid);
  Copy<testvec::kCsrP256.size()> version(testvec::kCsrP256);
  version.bytes[9] = 0x01U; // INTEGER 0 -> 1
  CHECK_EQ(ReasonOf(VerifyCsr(version.View(), verifier, crypto).detail),
           Reason::UnsupportedVersion);
  Copy<testvec::kCsrP256.size()> longer(testvec::kCsrP256);
  longer.size = longer.size + 1U;
  CHECK_EQ(ReasonOf(VerifyCsr(longer.View(), verifier, crypto).detail), Reason::TrailingData);
  Copy<testvec::kCsrP256.size()> cn(testvec::kCsrP256);
  cn.bytes[46] = 0x2AU; // a byte of the subject: the signature no longer matches
  CHECK_EQ(ReasonOf(VerifyCsr(cn.View(), verifier, crypto).detail), Reason::SignatureInvalid);
  CHECK_EQ(ReasonOf(VerifyCsr(ByteSpan{testvec::kCsrEd25519}, verifier, crypto).detail),
           Reason::UnsupportedAlgorithm);
}

TEST_CASE("PKI CSR: an Ed25519 request is OpenSSL's byte for byte (RFC 8032 is deterministic)") {
  // RFC 8032 7.1 TEST 1 public key.
  const std::array<uint8_t, 32> pub{0xD7U, 0x5AU, 0x98U, 0x01U, 0x82U, 0xB1U, 0x0AU, 0xB7U,
                                    0xD5U, 0x4BU, 0xFEU, 0xD3U, 0xC9U, 0x64U, 0x07U, 0x3AU,
                                    0x0EU, 0xE1U, 0x72U, 0xF3U, 0xDAU, 0xA6U, 0x23U, 0x25U,
                                    0xAFU, 0x02U, 0x1AU, 0x68U, 0xF7U, 0x07U, 0x51U, 0x1AU};
  ScriptedSigner signer{};
  signer.algorithm = SignatureAlgorithm::Ed25519;
  signer.output = ByteSpan{testvec::kCsrEd25519}.last(64U);
  const Name subject = TestName();
  AltNames alt{};
  static_cast<void>(alt.Add(AltNameType::Dns, ByteSpan{kDns}));
  const CsrRequest request{&subject, PublicKey{KeyType::Ed25519, ByteSpan{pub}}, &alt,
                           key_usage::kDigitalSignature};
  ReferenceCrypto crypto{&pkitest::TestEntropy};
  std::array<uint8_t, 400> csr{};
  const Result<std::size_t> r = BuildCsr(request, signer, crypto, MutableByteSpan{csr});
  REQUIRE(r.ok());
  CHECK(der::SameBytes(ByteSpan{csr}.first(r.value), ByteSpan{testvec::kCsrEd25519}));
  // The signer got the message itself (the info), not a digest.
  CHECK(der::SameBytes(ByteSpan{signer.seen}.first(signer.seen_length),
                       ByteSpan{testvec::kCsrEd25519}.subspan(3U, 164U)));
}

TEST_CASE("PKI CSR: a P-384 request hashes with SHA-384 and pairs only with a P-384 key") {
  std::array<uint8_t, 97> pub{};
  pub[0] = 0x04U;
  // r = s = 48 bytes of 0x11
  std::array<uint8_t, 102> der_sig{0x30U, 0x64U, 0x02U, 0x30U};
  std::fill(der_sig.begin() + 4, der_sig.begin() + 52, uint8_t{0x11U});
  der_sig[52] = 0x02U;
  der_sig[53] = 0x30U;
  std::fill(der_sig.begin() + 54, der_sig.end(), uint8_t{0x11U});
  ScriptedSigner signer{};
  signer.algorithm = SignatureAlgorithm::EcdsaSha384;
  signer.output = ByteSpan{der_sig};
  const Name subject = TestName();
  const CsrRequest request{&subject, PublicKey{KeyType::EcP384, ByteSpan{pub}}, nullptr, 0U};
  ReferenceCrypto crypto{&pkitest::TestEntropy};
  std::array<uint8_t, 400> csr{};
  const Result<std::size_t> r = BuildCsr(request, signer, crypto, MutableByteSpan{csr});
  REQUIRE(r.ok());
  CHECK_EQ(signer.seen_length, 48U);
  const CsrRequest p256{&subject, PublicKey{KeyType::EcP256, ByteSpan{pub}.first(65U)}, nullptr,
                        0U};
  CHECK_EQ(ReasonOfResult(BuildCsr(p256, signer, crypto, MutableByteSpan{csr})),
           Reason::AlgorithmMismatch);
}

TEST_CASE("PKI CSR: no attributes is A0 00; an empty subject needs a critical SAN") {
  Rfc6979 k;
  REQUIRE(k.ok);
  PortSigner<ReferenceCrypto> signer(k.crypto, k.key);
  PortVerifier<ReferenceCrypto> verifier(k.crypto);
  const Name subject = TestName();
  const CsrRequest plain{&subject, PublicKey{KeyType::EcP256, ByteSpan{k.pub}}, nullptr, 0U};
  std::array<uint8_t, 400> csr{};
  const Result<std::size_t> r = BuildCsr(plain, signer, k.crypto, MutableByteSpan{csr});
  REQUIRE(r.ok());
  const Result<CsrInfo> v = VerifyCsr(ByteSpan{csr}.first(r.value), verifier, k.crypto);
  REQUIRE(v.ok());
  CHECK(v.value.attributes.empty());
  const Name empty{};
  const CsrRequest nothing{&empty, PublicKey{KeyType::EcP256, ByteSpan{k.pub}}, nullptr, 0U};
  CHECK_EQ(ReasonOfResult(BuildCsr(nothing, signer, k.crypto, MutableByteSpan{csr})),
           Reason::EmptyInput);
  AltNames alt{};
  static_cast<void>(alt.Add(AltNameType::Dns, ByteSpan{kDns}));
  const CsrRequest san_only{&empty, PublicKey{KeyType::EcP256, ByteSpan{k.pub}}, &alt, 0U};
  const Result<std::size_t> s = BuildCsr(san_only, signer, k.crypto, MutableByteSpan{csr});
  REQUIRE(s.ok());
  const Result<CsrInfo> sv = VerifyCsr(ByteSpan{csr}.first(s.value), verifier, k.crypto);
  REQUIRE(sv.ok());
  // ... 06 03 55 1D 11 01 01 FF: the SAN is marked critical
  Copy<400> c(csr);
  const std::size_t at = c.Find(ByteSpan{oid::kSubjectAltName});
  REQUIRE(at < 400U);
  CHECK_EQ(c.bytes[at + 3U], 0x01U);
  CHECK_EQ(c.bytes[at + 5U], 0xFFU);
}

TEST_CASE("PKI CSR: the self check catches a public key that is not the signer's") {
  Rfc6979 k;
  REQUIRE(k.ok);
  PortSigner<ReferenceCrypto> signer(k.crypto, k.key);
  PortVerifier<ReferenceCrypto> verifier(k.crypto);
  const Name subject = TestName();
  const Result<Certificate> other = ParseCertificate(ByteSpan{testvec::kLeafP256});
  REQUIRE(other.ok());
  const CsrRequest request{&subject, other.value.public_key, nullptr, 0U};
  std::array<uint8_t, 400> csr{};
  const Result<std::size_t> r = BuildCsr(request, signer, k.crypto, MutableByteSpan{csr});
  REQUIRE(r.ok());
  CHECK_EQ(ReasonOf(VerifyCsr(ByteSpan{csr}.first(r.value), verifier, k.crypto).detail),
           Reason::SignatureInvalid);
}

TEST_CASE("PKI CSR: request checks before anything is written") {
  Rfc6979 k;
  REQUIRE(k.ok);
  PortSigner<ReferenceCrypto> signer(k.crypto, k.key);
  const Name subject = TestName();
  std::array<uint8_t, 400> csr{};
  const CsrRequest no_subject{nullptr, PublicKey{KeyType::EcP256, ByteSpan{k.pub}}, nullptr, 0U};
  CHECK_EQ(ReasonOfResult(BuildCsr(no_subject, signer, k.crypto, MutableByteSpan{csr})),
           Reason::InvalidInput);
  const CsrRequest short_key{&subject, PublicKey{KeyType::EcP256, ByteSpan{k.pub}.first(64U)},
                             nullptr, 0U};
  CHECK_EQ(ReasonOfResult(BuildCsr(short_key, signer, k.crypto, MutableByteSpan{csr})),
           Reason::BadPublicKey);
  std::array<uint8_t, 65> compressed = k.pub;
  compressed[0] = 0x02U;
  const CsrRequest comp{&subject, PublicKey{KeyType::EcP256, ByteSpan{compressed}}, nullptr, 0U};
  CHECK_EQ(ReasonOfResult(BuildCsr(comp, signer, k.crypto, MutableByteSpan{csr})),
           Reason::BadPublicKey);
  const CsrRequest usage{&subject, PublicKey{KeyType::EcP256, ByteSpan{k.pub}}, nullptr, 0x0200U};
  CHECK_EQ(ReasonOfResult(BuildCsr(usage, signer, k.crypto, MutableByteSpan{csr})),
           Reason::InvalidInput);
  Name broken{};
  static_cast<void>(broken.Add(Attribute::Country, ByteSpan{kCn}));
  const CsrRequest bad_name{&broken, PublicKey{KeyType::EcP256, ByteSpan{k.pub}}, nullptr, 0U};
  CHECK_EQ(ReasonOfResult(BuildCsr(bad_name, signer, k.crypto, MutableByteSpan{csr})),
           Reason::InvalidInput);
  AltNames bad_alt{};
  static_cast<void>(bad_alt.Add(AltNameType::Ip, ByteSpan{kCn}));
  const CsrRequest alt{&subject, PublicKey{KeyType::EcP256, ByteSpan{k.pub}}, &bad_alt, 0U};
  CHECK_EQ(ReasonOfResult(BuildCsr(alt, signer, k.crypto, MutableByteSpan{csr})),
           Reason::InvalidInput);
  // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange): a value that is no enumerator
  const CsrRequest odd{&subject, PublicKey{static_cast<KeyType>(5U), ByteSpan{k.pub}}, nullptr, 0U};
  CHECK_EQ(ReasonOfResult(BuildCsr(odd, signer, k.crypto, MutableByteSpan{csr})),
           Reason::InvalidInput);
}

TEST_CASE("PKI CSR: a small buffer and a failed signer leave nothing behind") {
  Rfc6979 k;
  REQUIRE(k.ok);
  PortSigner<ReferenceCrypto> signer(k.crypto, k.key);
  const Name subject = TestName();
  const CsrRequest request{&subject, PublicKey{KeyType::EcP256, ByteSpan{k.pub}}, nullptr, 0U};
  std::array<uint8_t, 200> small{};
  const Result<std::size_t> r = BuildCsr(request, signer, k.crypto, MutableByteSpan{small});
  CHECK_EQ(ReasonOfResult(r), Reason::BufferTooSmall);
  CHECK(std::all_of(small.begin(), small.end(), [](uint8_t b) { return b == 0U; }));
  ScriptedSigner failing{};
  failing.error = Error::Timeout;
  std::array<uint8_t, 400> csr{};
  const Result<std::size_t> f = BuildCsr(request, failing, k.crypto, MutableByteSpan{csr});
  CHECK_EQ(f.error, Error::Timeout);
  CHECK_EQ(f.detail.layer, Layer::Device);
  CHECK_EQ(f.detail.sw, 0x6985U);
  CHECK(std::all_of(csr.begin(), csr.end(), [](uint8_t b) { return b == 0U; }));
  const std::array<uint8_t, 4> not_a_signature{0x30U, 0x02U, 0x05U, 0x00U};
  ScriptedSigner garbage{};
  garbage.output = ByteSpan{not_a_signature};
  CHECK_EQ(ReasonOfResult(BuildCsr(request, garbage, k.crypto, MutableByteSpan{csr})),
           Reason::SignerOutputInvalid);
  ScriptedSigner liar{};
  liar.output = ByteSpan{testvec::kCsrP256}.last(72U);
  liar.length_override = kMaxSignatureDer + 1U;
  CHECK_EQ(ReasonOfResult(BuildCsr(request, liar, k.crypto, MutableByteSpan{csr})),
           Reason::SignerOutputInvalid);
}

TEST_CASE("PKI CSR: raw r || s to ECDSA-Sig-Value and back; the port signer's checks") {
  std::array<uint8_t, 64> raw{};
  raw[31] = 0x80U; // r = 0x80: needs a pad byte
  raw[63] = 0x01U;
  std::array<uint8_t, 80> der_sig{};
  const Result<std::size_t> e = EncodeEcdsaSignature(ByteSpan{raw}, MutableByteSpan{der_sig});
  REQUIRE(e.ok());
  CHECK_EQ(e.value, 9U);
  std::array<uint8_t, 64> back{};
  CHECK_EQ(der::ParseEcdsaSignature(ByteSpan{der_sig}.first(e.value), 32U, MutableByteSpan{back}),
           Reason::Ok);
  CHECK(der::SameBytes(ByteSpan{back}, ByteSpan{raw}));
  CHECK_EQ(ReasonOfResult(EncodeEcdsaSignature(ByteSpan{raw}.first(63U), MutableByteSpan{der_sig})),
           Reason::InvalidInput);
  CHECK_EQ(ReasonOfResult(EncodeEcdsaSignature(ByteSpan{}, MutableByteSpan{der_sig})),
           Reason::InvalidInput);
  Rfc6979 k;
  REQUIRE(k.ok);
  PortSigner<ReferenceCrypto> signer(k.crypto, k.key);
  CHECK_EQ(signer.Algorithm(), SignatureAlgorithm::EcdsaSha256);
  CHECK_EQ(ReasonOfResult(signer.Sign(ByteSpan{raw}.first(31U), MutableByteSpan{der_sig})),
           Reason::InvalidInput);
  PortSigner<ReferenceCrypto> no_key(k.crypto, KeyRef{});
  CHECK_EQ(ReasonOfResult(no_key.Sign(ByteSpan{raw}.first(32U), MutableByteSpan{der_sig})),
           Reason::SignerFailed);
}
