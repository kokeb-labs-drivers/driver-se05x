/**
 * @file test_pki_device.cpp
 * @brief PKI layer on the chip model: the provisioning recipe (key generated in the chip, CSR
 * signed by the chip, certificate issued, stored read-only, read back, chain verified), the
 * storage rules and the signer adapter.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <array>
#include <cstddef>
#include <cstdint>

#include "model/chip_bench.hpp"
#include "pki_test_util.hpp"
#include "se05x_pki.hpp"
#include "test_harness.hpp"
#include "vectors/pki_vectors.hpp"

using namespace se05x;
using namespace se05x::pki;
using testmodel::ChipBench;

namespace {

constexpr ObjectId kKey{0x00002001U};
constexpr ObjectId kCert{0x00002002U};
constexpr ObjectId kAnchor{0x00002003U};
constexpr ObjectId kOther{0x00002004U};
constexpr AuthObject kAdmin{ObjectId{testmodel::kAesCredential}};
// "device-0001"
constexpr std::array<uint8_t, 11> kCn{0x64U, 0x65U, 0x76U, 0x69U, 0x63U, 0x65U,
                                      0x2DU, 0x30U, 0x30U, 0x30U, 0x31U};
// "Test CA"
constexpr std::array<uint8_t, 7> kCaName{0x54U, 0x65U, 0x73U, 0x74U, 0x20U, 0x43U, 0x41U};

/// A CA and an end-entity certificate from the test issuer, the second for `key`.
struct Issued {
  pkitest::TestIssuer issuer;
  std::array<uint8_t, 160> ca_name{};
  std::array<uint8_t, 160> leaf_name{};
  std::array<uint8_t, 600> ca{};
  std::array<uint8_t, 600> leaf{};
  std::size_t ca_size{0};
  std::size_t leaf_size{0};

  explicit Issued(const PublicKey& key) {
    Name ca_subject{};
    static_cast<void>(ca_subject.Add(Attribute::CommonName, ByteSpan{kCaName}));
    Name leaf_subject{};
    static_cast<void>(leaf_subject.Add(Attribute::CommonName, ByteSpan{kCn}));
    pkitest::CertSpec ca_spec{};
    ca_spec.issuer = pkitest::EncodeName(ca_subject, ca_name);
    ca_spec.subject = ca_spec.issuer;
    ca_spec.key = issuer.Key();
    ca_spec.ca = true;
    ca_spec.key_usage = key_usage::kKeyCertSign;
    ca_size = issuer.Issue(ca_spec, MutableByteSpan{ca});
    pkitest::CertSpec leaf_spec{};
    leaf_spec.issuer = ca_spec.issuer;
    leaf_spec.subject = pkitest::EncodeName(leaf_subject, leaf_name);
    leaf_spec.key = key;
    leaf_spec.serial = 2U;
    leaf_size = issuer.Issue(leaf_spec, MutableByteSpan{leaf});
  }
  [[nodiscard]] ByteSpan Ca() const {
    return ByteSpan{ca}.first(ca_size);
  }
  [[nodiscard]] ByteSpan Leaf() const {
    return ByteSpan{leaf}.first(leaf_size);
  }
};

Policy DefaultPolicy() {
  return CertificatePolicy<AppletGeneration::V7>(kAdmin).value;
}

} // namespace

TEST_CASE("PKI recipe: key in the chip, CSR signed by the chip, certificate stored and verified") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  // 1. Generate the key pair inside the chip; read its public key.
  REQUIRE(
      b.device.GenerateEcKey(kKey, testmodel::SignPolicy<AppletGeneration::V7>(), EcCurve::NistP256)
          .ok());
  std::array<uint8_t, 65> pub{};
  const Result<PublicKey> key =
      ReadPublicKey(b.device, kKey, KeyType::EcP256, MutableByteSpan{pub});
  REQUIRE(key.ok());
  // 2. Build the request; the chip signs the digest.
  Name subject{};
  static_cast<void>(subject.Add(Attribute::CommonName, ByteSpan{kCn}));
  const CsrRequest request{&subject, key.value, nullptr, key_usage::kDigitalSignature};
  DeviceSigner<testmodel::BenchPorts> signer(b.device, kKey, KeyType::EcP256);
  std::array<uint8_t, 400> csr{};
  const Result<std::size_t> built = BuildCsr(request, signer, b.crypto, MutableByteSpan{csr});
  REQUIRE(built.ok());
  PortVerifier<ReferenceCrypto> verifier(b.crypto);
  REQUIRE(VerifyCsr(ByteSpan{csr}.first(built.value), verifier, b.crypto).ok());
  // 3. The CA issues the certificate (here: the test issuer); store it and the anchor read-only.
  const Issued issued(key.value);
  REQUIRE(issued.leaf_size != 0U);
  std::array<uint8_t, 600> scratch{};
  REQUIRE(
      StoreCertificate(b.device, kAnchor, issued.Ca(), DefaultPolicy(), MutableByteSpan{scratch})
          .ok());
  REQUIRE(
      StoreCertificate(b.device, kCert, issued.Leaf(), DefaultPolicy(), MutableByteSpan{scratch})
          .ok());
  // 4. Later: read both back and verify the chain with the chip's time source of choice.
  std::array<uint8_t, 600> anchor_buf{};
  const Result<TrustAnchor> anchor =
      LoadTrustAnchor(b.device, kAnchor, MutableByteSpan{anchor_buf});
  REQUIRE(anchor.ok());
  std::array<uint8_t, 600> cert_buf{};
  const Result<Certificate> cert = ReadCertificate(b.device, kCert, MutableByteSpan{cert_buf});
  REQUIRE(cert.ok());
  CHECK(der::SameBytes(cert.value.der, issued.Leaf()));
  const std::array<ByteSpan, 1> chain{cert.value.der};
  const std::array<TrustAnchor, 1> anchors{anchor.value};
  const VerifyOptions options{pkitest::Now(), key_usage::kDigitalSignature, false};
  const Result<VerifiedChain> v =
      VerifyChain(std::span<const ByteSpan>{chain}, std::span<const TrustAnchor>{anchors}, options,
                  verifier, b.crypto);
  REQUIRE(v.ok());
  CHECK(der::SameBytes(v.value.leaf_key.bytes, ByteSpan{pub}));
}

TEST_CASE("PKI store: a certificate nobody may delete is the irreversible operation") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  const Result<Policy> forever =
      PolicyBuilder<AppletGeneration::V7, ObjectClass::BinaryFile, Profile::Strict>{}
          .ForAllOthers()
          .Allow<Rule::Read>()
          .Build();
  REQUIRE(forever.ok());
  std::array<uint8_t, 1024> scratch{};
  const uint32_t before = b.chip.commands;
  const Result<void> r = StoreCertificate(b.device, kCert, ByteSpan{testvec::kLeafP256},
                                          forever.value, MutableByteSpan{scratch});
  CHECK_EQ(r.error, Error::IrreversibleNotConfirmed);
  CHECK(!b.chip.Has(kCert.value));
  CHECK(b.chip.commands <= (before + 1U)); // at most the existence check; never the write
}

TEST_CASE("PKI store: an existing object is never overwritten") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  std::array<uint8_t, 600> scratch{};
  REQUIRE(StoreCertificate(b.device, kCert, ByteSpan{testvec::kLeafP256}, DefaultPolicy(),
                           MutableByteSpan{scratch})
              .ok());
  const uint32_t before = b.device.ApduCount();
  const Result<void> again = StoreCertificate(b.device, kCert, ByteSpan{testvec::kRootP256},
                                              DefaultPolicy(), MutableByteSpan{scratch});
  CHECK_EQ(again.error, Error::ObjectExists);
  CHECK_EQ(b.device.ApduCount(), before + 1U); // only the existence check
  std::array<uint8_t, 600> buf{};
  const Result<Certificate> kept = ReadCertificate(b.device, kCert, MutableByteSpan{buf});
  REQUIRE(kept.ok());
  CHECK(der::SameBytes(kept.value.der, ByteSpan{testvec::kLeafP256}));
}

TEST_CASE("PKI store: a policy that lets anyone change the certificate is refused, nothing sent") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  std::array<uint8_t, 600> scratch{};
  const Result<Policy> writable =
      PolicyBuilder<AppletGeneration::V7, ObjectClass::BinaryFile, Profile::Open>{}
          .ForAllOthers()
          .Allow<Rule::Read>()
          .Allow<Rule::Write>()
          .WithReason(OpenReason::PublicDataObject)
          .Build();
  REQUIRE(writable.ok());
  const Result<Policy> deletable =
      PolicyBuilder<AppletGeneration::V7, ObjectClass::BinaryFile, Profile::Strict>{}
          .ForAllOthers()
          .Allow<Rule::Read>()
          .Allow<Rule::Delete>()
          .Build();
  REQUIRE(deletable.ok());
  const Result<Policy> admin_writes =
      PolicyBuilder<AppletGeneration::V7, ObjectClass::BinaryFile, Profile::Strict>{}
          .ForAllOthers()
          .Allow<Rule::Read>()
          .For(kAdmin)
          .Allow<Rule::Write>()
          .Build();
  REQUIRE(admin_writes.ok());
  const uint32_t before = b.device.ApduCount();
  for (const Policy* p : {&writable.value, &deletable.value, &admin_writes.value}) {
    const Result<void> r = StoreCertificate(b.device, kCert, ByteSpan{testvec::kLeafP256}, *p,
                                            MutableByteSpan{scratch});
    CHECK_EQ(ReasonOf(r.detail), Reason::PolicyAllowsWrite);
  }
  CHECK_EQ(b.device.ApduCount(), before);
  const Result<Policy> rotation = CertificatePolicy<AppletGeneration::V7>(kAdmin);
  REQUIRE(rotation.ok());
  CHECK(StoreCertificate(b.device, kCert, ByteSpan{testvec::kLeafP256}, rotation.value,
                         MutableByteSpan{scratch})
            .ok());
}

TEST_CASE("PKI store: input refusals send nothing: not a certificate, too large, small scratch") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  std::array<uint8_t, 2000> scratch{};
  const uint32_t before = b.device.ApduCount();
  const std::array<uint8_t, 4> junk{0x30U, 0x02U, 0x05U, 0x00U};
  CHECK_EQ(
      StoreCertificate(b.device, kCert, ByteSpan{junk}, DefaultPolicy(), MutableByteSpan{scratch})
          .error,
      Error::InvalidArgument);
  CHECK_EQ(ReasonOf(StoreCertificate(b.device, kCert, ByteSpan{testvec::kLeafP256}, DefaultPolicy(),
                                     MutableByteSpan{scratch}.first(100U))
                        .detail),
           Reason::BufferTooSmall);
  CHECK_EQ(ReasonOf(StoreCertificate(b.device, kCert, ByteSpan{testvec::kLeafP256}, Policy{},
                                     MutableByteSpan{scratch})
                        .detail),
           Reason::InvalidInput);
  // A certificate with a long subject: valid, and larger than one WriteBinary carries.
  std::array<uint8_t, 128> long_value{};
  long_value.fill(0x61U);
  Name big{};
  for (std::size_t i = 0U; i < kMaxNameAttributes; ++i) {
    static_cast<void>(big.Add(Attribute::Locality, ByteSpan{long_value}));
  }
  std::array<uint8_t, 1200> name_buf{};
  pkitest::TestIssuer issuer;
  pkitest::CertSpec spec{};
  spec.issuer = pkitest::EncodeName(big, name_buf);
  spec.subject = spec.issuer;
  spec.key = issuer.Key();
  std::array<uint8_t, 2600> large{};
  const std::size_t n = issuer.Issue(spec, MutableByteSpan{large});
  REQUIRE(n > MaxStoredCertificate(DefaultPolicy()));
  REQUIRE(ParseCertificate(ByteSpan{large}.first(n)).ok());
  const Result<void> r = StoreCertificate(b.device, kCert, ByteSpan{large}.first(n),
                                          DefaultPolicy(), MutableByteSpan{scratch});
  CHECK_EQ(ReasonOf(r.detail), Reason::ObjectTooLarge);
  CHECK_EQ(r.error, Error::BufferTooSmall);
  CHECK_EQ(b.device.ApduCount(), before);
}

TEST_CASE("PKI store: MaxStoredCertificate fills the 1024-byte command body exactly") {
  for (const Policy& p : {DefaultPolicy(), CertificatePolicy<AppletGeneration::V7>(kAdmin).value}) {
    const std::size_t max = MaxStoredCertificate(p);
    std::array<uint8_t, kMaxApduPayload> data{};
    std::array<uint8_t, kMaxPlainCommandApdu> out{};
    WriteBinaryArgs args{};
    args.id = kCert;
    args.policy = &p;
    args.data = ByteSpan{data}.first(max);
    args.file_length = static_cast<uint16_t>(max);
    const Result<std::size_t> r = Codec<Command::WriteBinary>::Encode(args, MutableByteSpan{out});
    REQUIRE(r.ok());
    CHECK_EQ(r.value, 4U + 3U + kMaxApduPayload); // header, extended Lc, body; no Le
  }
  CHECK_EQ(MaxStoredCertificate(DefaultPolicy()), 990U);
  CHECK_EQ(CertificatePolicy<AppletGeneration::V7>(AuthObject{}).error, Error::InvalidArgument);
}

TEST_CASE("PKI store: CheckReadOnlyPolicy reads every entry") {
  const Policy p = DefaultPolicy();
  CHECK_EQ(CheckReadOnlyPolicy(p.Bytes()), Reason::Ok);
  CHECK_EQ(CheckReadOnlyPolicy(ByteSpan{}), Reason::InvalidInput);
  CHECK_EQ(CheckReadOnlyPolicy(std::array<uint8_t, 3>{0x08U, 0x00U, 0x00U}), Reason::InvalidInput);
  const Result<Policy> two =
      PolicyBuilder<AppletGeneration::V7, ObjectClass::BinaryFile, Profile::Strict>{}
          .For(kAdmin)
          .Allow<Rule::Read>()
          .ForAllOthers()
          .Allow<Rule::Read>()
          .Allow<Rule::Delete>()
          .Build();
  REQUIRE(two.ok());
  CHECK_EQ(CheckReadOnlyPolicy(two.value.Bytes()), Reason::PolicyAllowsWrite); // the second entry
}

TEST_CASE("PKI read: a stored object that is not one certificate, a missing object") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  const Result<Policy> open =
      PolicyBuilder<AppletGeneration::V7, ObjectClass::BinaryFile, Profile::Open>{}
          .ForAllOthers()
          .Allow<Rule::Read>()
          .Allow<Rule::Write>()
          .WithReason(OpenReason::PublicDataObject)
          .Build();
  REQUIRE(open.ok());
  const std::array<uint8_t, 6> two{0x30U, 0x00U, 0x30U, 0x00U, 0x05U, 0x00U};
  REQUIRE(b.device.WriteBinary(kOther, open.value, 0U, ByteSpan{two}, 6U).ok());
  std::array<uint8_t, 64> buf{};
  CHECK_EQ(ReasonOf(ReadCertificate(b.device, kOther, MutableByteSpan{buf}).detail),
           Reason::NotACertificate);
  const Result<Certificate> missing = ReadCertificate(b.device, kCert, MutableByteSpan{buf});
  CHECK_EQ(missing.error, Error::ObjectNotFound);
  CHECK_EQ(LoadTrustAnchor(b.device, kCert, MutableByteSpan{buf}).error, Error::ObjectNotFound);
  std::array<uint8_t, 600> scratch{};
  REQUIRE(StoreCertificate(b.device, kCert, ByteSpan{testvec::kLeafP256}, DefaultPolicy(),
                           MutableByteSpan{scratch})
              .ok());
  std::array<uint8_t, 600> anchor_buf{};
  CHECK_EQ(ReasonOf(LoadTrustAnchor(b.device, kCert, MutableByteSpan{anchor_buf}).detail),
           Reason::NotCa);
}

TEST_CASE("PKI device: ReadPublicKey checks the type and the buffer") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  REQUIRE(
      b.device.GenerateEcKey(kKey, testmodel::SignPolicy<AppletGeneration::V7>(), EcCurve::NistP256)
          .ok());
  std::array<uint8_t, 97> buf{};
  CHECK_EQ(ReasonOf(ReadPublicKey(b.device, kKey, KeyType::EcP384, MutableByteSpan{buf}).detail),
           Reason::BadPublicKey);
  CHECK_EQ(
      ReasonOf(
          ReadPublicKey(b.device, kKey, KeyType::EcP256, MutableByteSpan{buf}.first(64U)).detail),
      Reason::BufferTooSmall);
  CHECK_EQ(
      ReasonOf(
          // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange): a value that is no
          // enumerator
          ReadPublicKey(b.device, kKey, static_cast<KeyType>(9U), MutableByteSpan{buf}).detail),
      Reason::InvalidInput);
  CHECK_EQ(ReadPublicKey(b.device, kOther, KeyType::EcP256, MutableByteSpan{buf}).error,
           Error::ObjectNotFound);
}

TEST_CASE("PKI device: the signer refuses a digest of the wrong length before sending") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  REQUIRE(
      b.device.GenerateEcKey(kKey, testmodel::SignPolicy<AppletGeneration::V7>(), EcCurve::NistP256)
          .ok());
  DeviceSigner<testmodel::BenchPorts> p256(b.device, kKey, KeyType::EcP256);
  DeviceSigner<testmodel::BenchPorts> p384(b.device, kKey, KeyType::EcP384);
  CHECK_EQ(p256.Algorithm(), SignatureAlgorithm::EcdsaSha256);
  CHECK_EQ(p384.Algorithm(), SignatureAlgorithm::EcdsaSha384);
  std::array<uint8_t, 48> digest{};
  std::array<uint8_t, kMaxSignatureDer> sig{};
  const uint32_t before = b.device.ApduCount();
  CHECK_EQ(ReasonOf(p256.Sign(ByteSpan{digest}, MutableByteSpan{sig}).detail),
           Reason::InvalidInput);
  CHECK_EQ(ReasonOf(p384.Sign(ByteSpan{digest}.first(32U), MutableByteSpan{sig}).detail),
           Reason::InvalidInput);
  CHECK_EQ(b.device.ApduCount(), before);
  const Result<std::size_t> ok = p256.Sign(ByteSpan{digest}.first(32U), MutableByteSpan{sig});
  REQUIRE(ok.ok());
  CHECK_EQ(CheckSignatureValue(SignatureAlgorithm::EcdsaSha256, ByteSpan{sig}.first(ok.value)),
           Reason::Ok);
}

TEST_CASE("PKI device: an Ed25519 signer sends EdDSASign; SE052F refuses it before sending") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  REQUIRE(
      b.device.GenerateEcKey(kKey, testmodel::SignPolicy<AppletGeneration::V7>(), EcCurve::NistP256)
          .ok());
  DeviceSigner<testmodel::BenchPorts> ed(b.device, kKey, KeyType::Ed25519);
  CHECK_EQ(ed.Algorithm(), SignatureAlgorithm::Ed25519);
  std::array<uint8_t, 100> message{};
  std::array<uint8_t, kMaxSignatureDer> sig{};
  const uint32_t before = b.device.ApduCount();
  const Result<std::size_t> r = ed.Sign(ByteSpan{message}, MutableByteSpan{sig});
  REQUIRE(r.ok());
  CHECK_EQ(r.value, 64U); // the model's EdDSA answer is 64 fixed bytes
  CHECK_EQ(b.device.ApduCount(), before + 1U);
  ChipBench se052(testmodel::kSe052);
  REQUIRE(se052.device.Open().ok());
  DeviceSigner<testmodel::BenchPorts> refused(se052.device, kKey, KeyType::Ed25519);
  const uint32_t sent = se052.device.ApduCount();
  CHECK_EQ(refused.Sign(ByteSpan{message}, MutableByteSpan{sig}).error, Error::Unsupported);
  CHECK_EQ(se052.device.ApduCount(), sent);
}

TEST_CASE("PKI store: the read-back comparison: other bytes, fewer bytes, a failed read") {
  const std::array<uint8_t, 4> written{1U, 2U, 3U, 4U};
  const std::array<uint8_t, 4> same{1U, 2U, 3U, 4U};
  const std::array<uint8_t, 4> other{1U, 2U, 3U, 5U};
  CHECK(pki::detail::CheckReadBack(Result<std::size_t>::Success(4U), ByteSpan{same},
                                   ByteSpan{written})
            .ok());
  CHECK_EQ(ReasonOf(pki::detail::CheckReadBack(Result<std::size_t>::Success(4U), ByteSpan{other},
                                               ByteSpan{written})
                        .detail),
           Reason::ReadBackMismatch);
  CHECK_EQ(ReasonOf(pki::detail::CheckReadBack(Result<std::size_t>::Success(3U), ByteSpan{same},
                                               ByteSpan{written})
                        .detail),
           Reason::ReadBackMismatch);
  CHECK_EQ(ReasonOf(pki::detail::CheckReadBack(Result<std::size_t>::Success(4U),
                                               ByteSpan{same}.first(3U), ByteSpan{written})
                        .detail),
           Reason::ReadBackMismatch);
  CHECK_EQ(pki::detail::CheckReadBack(Result<std::size_t>::Failure(Error::Timeout), ByteSpan{same},
                                      ByteSpan{written})
               .error,
           Error::Timeout);
}

TEST_CASE("PKI device: a public key that is not an uncompressed point is refused") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  const Result<Policy> open =
      PolicyBuilder<AppletGeneration::V7, ObjectClass::BinaryFile, Profile::Open>{}
          .ForAllOthers()
          .Allow<Rule::Read>()
          .Allow<Rule::Delete>()
          .WithReason(OpenReason::PublicDataObject)
          .Build();
  REQUIRE(open.ok());
  std::array<uint8_t, 65> compressed{};
  compressed[0] = 0x02U;
  REQUIRE(b.device.WriteBinary(kOther, open.value, 0U, ByteSpan{compressed}, 65U).ok());
  std::array<uint8_t, 65> out{};
  CHECK_EQ(ReasonOf(ReadPublicKey(b.device, kOther, KeyType::EcP256, MutableByteSpan{out}).detail),
           Reason::BadPublicKey);
}

TEST_CASE("PKI device: a P-384 signer sends ECDSASign with SHA-384 and a 48-byte digest") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  DeviceSigner<testmodel::BenchPorts> p384(b.device, kKey, KeyType::EcP384);
  std::array<uint8_t, 48> digest{};
  std::array<uint8_t, kMaxSignatureDer> sig{};
  const uint32_t before = b.device.ApduCount();
  // The model has no P-384 key: the chip answers with an error, but the command went out.
  CHECK(!p384.Sign(ByteSpan{digest}, MutableByteSpan{sig}).ok());
  CHECK_EQ(b.device.ApduCount(), before + 1U);
}
