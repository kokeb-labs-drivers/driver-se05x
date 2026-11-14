/**
 * @file test_docs_jobs.cpp
 * @brief Every job path of the getting-started page and every recipe of the HRoT cookbook, as the
 * pages show them (`tests/docs/jobs.hpp`), run against the chip model: the documentation shows
 * code that compiles and does what the page says.
 */
#include <array>
#include <cstddef>
#include <cstdint>

#include "docs/jobs.hpp"
#include "hrot_bench.hpp"
#include "model/scp_crypto.hpp"
#include "test_harness.hpp"

using namespace se05x;
using testmodel::HrotBench;
using testmodel::kDigestAbc;

namespace {

const hrot::Digest kDigest{kDigestAbc};

/// A made-up host key (not a chip key).
constexpr std::array<uint8_t, 32> kHostPrivate{
    0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x0F, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x08, 0x19, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x01, 0x12};

/// RFC 3394 2.2.1 wrap with the model's AES (test side only).
std::array<uint8_t, 24> Wrap(const std::array<uint8_t, 16>& kek,
                             const std::array<uint8_t, 16>& key) {
  std::array<uint8_t, 8> a{0xA6U, 0xA6U, 0xA6U, 0xA6U, 0xA6U, 0xA6U, 0xA6U, 0xA6U};
  std::array<std::array<uint8_t, 8>, 2> r{};
  for (std::size_t i = 0U; i < 8U; ++i) {
    r[0][i] = key[i];
    r[1][i] = key[8U + i];
  }
  for (uint32_t j = 0U; j < 6U; ++j) {
    for (std::size_t i = 0U; i < 2U; ++i) {
      std::array<uint8_t, 16> b{};
      for (std::size_t q = 0U; q < 8U; ++q) {
        b[q] = a[q];
        b[8U + q] = r[i][q];
      }
      testmodel::mc::EncryptBlock(testmodel::mc::Bytes(kek.data(), 16U), b.data());
      const uint32_t t = (2U * j) + static_cast<uint32_t>(i) + 1U;
      for (std::size_t q = 0U; q < 8U; ++q) {
        a[q] = b[q];
        r[i][q] = b[8U + q];
      }
      a[7] = static_cast<uint8_t>(a[7] ^ static_cast<uint8_t>(t));
    }
  }
  std::array<uint8_t, 24> out{};
  for (std::size_t q = 0U; q < 8U; ++q) {
    out[q] = a[q];
    out[8U + q] = r[0][q];
    out[16U + q] = r[1][q];
  }
  return out;
}

/// The bench's platform key handles, as a board's crypto port would hold them.
struct Handles {
  KeyRef enc{};
  KeyRef mac{};
};
Handles PlatformHandles(testmodel::ChipBench& b) {
  Handles h{};
  static_cast<void>(b.crypto.ImportKey(KeyKind::Aes128, ByteSpan{testmodel::kPlatformEnc}, h.enc));
  static_cast<void>(b.crypto.ImportKey(KeyKind::Aes128, ByteSpan{testmodel::kPlatformMac}, h.mac));
  return h;
}

/// Open the bench through the page's own `OpenSecure`.
bool Open(HrotBench& t) {
  const Handles h = PlatformHandles(t.bench);
  return jobs::OpenSecure(t.bench.device, h.enc, h.mac) == Error::Ok;
}

} // namespace

TEST_CASE("Docs: open with platform SCP03, then provision and attest the device key") {
  HrotBench t;
  REQUIRE(Open(t));
  CHECK(t.bench.device.SecureMessagingActive());
  hrot::EcPublicKey pub{};
  REQUIRE(jobs::ProvisionDeviceKey(t.facade, pub) == Error::Ok);
  CHECK_EQ(pub.point[0], 0x04U);
  CHECK(jobs::ProvisionDeviceKey(t.facade, pub) == Error::ObjectExists);
  hrot::EcPublicKey vendor{};
  vendor.point = t.bench.chip.AttestPublic();
  hrot::EcPublicKey attested{};
  REQUIRE(jobs::AttestDeviceKey(t.facade, vendor, attested) == Error::Ok);
  CHECK(attested.point == pub.point);
  hrot::EcPublicKey wrong{};
  REQUIRE(testmodel::mc::PublicKey(kHostPrivate.data(), wrong.point.data()));
  CHECK(jobs::AttestDeviceKey(t.facade, wrong, attested) == Error::AttestationInvalid);
}

TEST_CASE("Docs: sign and verify, a TLS signature, a firmware root") {
  HrotBench t;
  REQUIRE(Open(t));
  hrot::EcPublicKey pub{};
  REQUIRE(jobs::ProvisionDeviceKey(t.facade, pub) == Error::Ok);
  hrot::Signature sig{};
  REQUIRE(jobs::SignAndVerify(t.facade, kDigest, sig) == Error::Ok);
  CHECK(sig.length > 8U);
  REQUIRE(jobs::StoreFirmwareRoot(t.facade, pub) == Error::Ok);
  CHECK(jobs::CheckFirmware(t.facade, kDigest, sig.View()) == Error::Ok);
  sig.bytes[sig.length - 2U] = static_cast<uint8_t>(sig.bytes[sig.length - 2U] ^ 0x10U);
  CHECK(jobs::CheckFirmware(t.facade, kDigest, sig.View()) == Error::AttestationInvalid);
  CHECK_EQ(jobs::FindTlsKey(t.facade).error, Error::ObjectNotFound);
  REQUIRE(t.facade.Provision<hrot::KeyUse::TlsClient>(hrot::Slot::At<3>()).ok());
  const auto tls = jobs::FindTlsKey(t.facade);
  REQUIRE(tls.ok());
  const uint32_t before = t.Commands();
  CHECK(jobs::TlsSignCallback(t.facade, tls.value, kDigest, sig) == Error::Ok);
  CHECK_EQ(t.Commands(), before + 1U); // one APDU per handshake
}

TEST_CASE("Docs: ECDH provisions the agreement key once and agrees with the host") {
  // SE050E with EXTCFG_CRYPTO_EC_FORBID_ECDH clear (bit 0x02 of each extended feature byte off).
  constexpr testmodel::ChipProfile kEcdh{"se050e_ecdh", 7U,   2U,    0U,    0x3FFFU, 0x010BU,
                                         0xA921U,       true, 0xFDU, false, true};
  HrotBench t(kEcdh);
  REQUIRE(Open(t));
  hrot::EcPublicKey peer{};
  REQUIRE(testmodel::mc::PublicKey(kHostPrivate.data(), peer.point.data()));
  SecretBuffer<32> shared;
  REQUIRE(jobs::AgreeWithPeer(t.facade, peer, shared) == Error::Ok);
  CHECK(t.bench.chip.Has(hrot::Slot::At<1>().Object().value));
  const auto key = t.facade.Find<hrot::KeyUse::Agree>(hrot::Slot::At<1>());
  REQUIRE(key.ok());
  const auto chip_pub = t.facade.GetPublicKey(key.value);
  REQUIRE(chip_pub.ok());
  std::array<uint8_t, 32> expected{};
  REQUIRE(testmodel::mc::Ecdh(kHostPrivate.data(), chip_pub.value.point.data(), expected.data()));
  CHECK(ct::Equal(shared.Span(), ByteSpan{expected}));
  const uint32_t before = t.Commands();
  REQUIRE(jobs::AgreeWithPeer(t.facade, peer, shared) == Error::Ok); // found, not provisioned again
  CHECK_EQ(t.Commands(), before + 4U); // existence, attributes, type (adoption check), ECDH
  CHECK(ct::Equal(shared.Span(), ByteSpan{expected}));
}

TEST_CASE("Docs: a wrapped AES key is imported under a key-encryption key") {
  HrotBench t;
  REQUIRE(Open(t));
  const std::array<uint8_t, 16> kek{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
  const std::array<uint8_t, 16> key{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
  // RFC 3394 4.1: the 128-bit key data wrapped with a 128-bit KEK.
  const std::array<uint8_t, 24> wrapped = Wrap(kek, key);
  const std::array<uint8_t, 8> rfc_head{0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47};
  CHECK(ct::Equal(ByteSpan{wrapped}.first(8U), ByteSpan{rfc_head}));
  const auto kek_policy = PolicyBuilder<AppletGeneration::V7, ObjectClass::AesKey, Profile::Open>{}
                              .ForAllOthers()
                              .Allow<Rule::Wrap>()
                              .WithReason(OpenReason::Laboratory)
                              .Build();
  REQUIRE(kek_policy.ok());
  WriteSymmKeyArgs plain{};
  plain.id = ObjectId{0x00006001U};
  plain.policy = &kek_policy.value;
  plain.key = ByteSpan{kek};
  REQUIRE(t.bench.device.Execute<Command::WriteSymmKey>(plain).ok());
  REQUIRE(jobs::ImportWrappedAesKey(t.bench.device, ObjectId{0x00006001U}, ObjectId{0x00006002U},
                                    ByteSpan{wrapped}) == Error::Ok);
  CHECK(t.bench.chip.AesKeyIs(0x00006002U, ByteSpan{key}));
  std::array<uint8_t, 24> tampered = wrapped;
  tampered[5] = static_cast<uint8_t>(tampered[5] ^ 0x01U);
  CHECK(jobs::ImportWrappedAesKey(t.bench.device, ObjectId{0x00006001U}, ObjectId{0x00006003U},
                                  ByteSpan{tampered}) != Error::Ok);
  CHECK(!t.bench.chip.Has(0x00006003U));
}

TEST_CASE("Docs: an AESKey session opens with the credential's key handle") {
  HrotBench t(testmodel::kSe050E, false);
  REQUIRE(t.Open());
  const AesKeySessionParams p = t.bench.AesParams();
  REQUIRE(jobs::OpenAesKeySession(t.bench.device, p.credential, p.keys.enc) == Error::Ok);
  CHECK_EQ(t.bench.device.Session(), SessionKind::AesKey);
  CHECK(t.bench.device.SecureMessagingActive());
}

TEST_CASE("Docs: sealed configuration and the device certificate") {
  HrotBench t;
  REQUIRE(Open(t));
  const std::array<uint8_t, 6> cfg{0xC0U, 0xFFU, 0xEEU, 0x00U, 0x01U, 0x02U};
  REQUIRE(jobs::SealConfig(t.facade, ByteSpan{cfg}) == Error::Ok);
  std::array<uint8_t, 32> back{};
  const auto n = jobs::UnsealConfig(t.facade, MutableByteSpan{back});
  REQUIRE(n.ok());
  CHECK_EQ(n.value, cfg.size());
  CHECK(ct::Equal(ByteSpan{back}.first(n.value), ByteSpan{cfg}));
  std::array<uint8_t, 400> der{};
  der[0] = 0x30U;
  der[1] = 0x82U;
  std::array<uint8_t, 512> out{};
  REQUIRE(jobs::KeepCertificate(t.facade, ByteSpan{der}, MutableByteSpan{out}) == Error::Ok);
  CHECK_EQ(out[1], 0x82U);
  CHECK(jobs::KeepCertificate(t.facade, ByteSpan{der}, MutableByteSpan{out}) ==
        Error::ObjectExists);
}

TEST_CASE("Docs: the anti-rollback floor refuses an older image") {
  HrotBench t;
  REQUIRE(Open(t));
  REQUIRE(t.facade.CreateCounter(hrot::CounterSlot::At<0>(), 3U).ok());
  CHECK(jobs::BootCheck(t.facade, 3U) == Error::Ok);
  CHECK(jobs::BootCheck(t.facade, 4U) == Error::Ok);
  CHECK(jobs::BootCheck(t.facade, 2U) == Error::PolicyDenied); // a rollback
  REQUIRE(jobs::CommitImage(t.facade, 4U) == Error::Ok);
  CHECK(jobs::BootCheck(t.facade, 4U) == Error::Ok);
  CHECK(jobs::BootCheck(t.facade, 3U) == Error::PolicyDenied); // 3 ran before, 4 is the floor now
  CHECK(jobs::CommitImage(t.facade, 2U) != Error::Ok);         // the floor never goes down
}

TEST_CASE("Docs: the factory record, a nonce and the APDU budget") {
  HrotBench t(testmodel::kSe052);
  REQUIRE(Open(t));
  hrot::Identity id{};
  hrot::EcPublicKey pub{};
  REQUIRE(jobs::FactoryRecord(t.facade, id, pub) == Error::Ok);
  CHECK_EQ(id.unique_id[0], 0xC0U);
  CHECK_EQ(id.oef_id, 0xB501U);
  std::array<uint8_t, 16> nonce{};
  REQUIRE(jobs::Nonce(t.facade, nonce) == Error::Ok);
  const uint32_t sent = t.bench.device.ApduCount();
  CHECK_EQ(jobs::ApdusLeft(t.facade, 1000U), kThroughputLimitApdus - 1000U);
  CHECK_EQ(t.bench.device.ApduCount(), sent); // reading the budget sends nothing
  CHECK_EQ(jobs::ApdusLeft(t.facade, kThroughputLimitApdus + 5U), 0U);
  HrotBench e;
  REQUIRE(Open(e));
  CHECK_EQ(jobs::ApdusLeft(e.facade, 1000U), kThroughputLimitApdus); // the limit does not apply
}

TEST_CASE("Docs: the Wi-Fi passphrase is stored once and read back into a SecretBuffer") {
  HrotBench t;
  REQUIRE(Open(t));
  const std::array<uint8_t, 12> pass{'c', 'o', 'r', 'r', 'e', 'c', 't', '-', 'h', 'o', 'r', 's'};
  REQUIRE(jobs::SaveWifiPassphrase(t.facade, ByteSpan{pass}) == Error::Ok);
  CHECK(jobs::SaveWifiPassphrase(t.facade, ByteSpan{pass}) == Error::ObjectExists);
  SecretBuffer<64> back;
  REQUIRE(jobs::LoadWifiPassphrase(t.facade, back) == Error::Ok);
  CHECK(ct::Equal(back.Span(), ByteSpan{pass}));
  HrotBench plain(testmodel::kSe050E, false); // no secure messaging: refused, nothing read
  REQUIRE(plain.Open());
  SecretBuffer<64> none;
  CHECK(jobs::LoadWifiPassphrase(plain.facade, none) == Error::PolicyDenied);
  CHECK(none.Span().empty());
}
