/**
 * @file test_hrot_keys.cpp
 * @brief The facade: admission (closed device, no secure messaging, a UserID session alone),
 * slots, provisioning, sign and verify, trust anchors, ECDH, identity and attestation, against the
 * chip model behind platform SCP03.
 */
#include <array>
#include <cstddef>
#include <cstdint>

#include "hrot_bench.hpp"
#include "model/scp_crypto.hpp"
#include "test_harness.hpp"

using namespace se05x;
using testmodel::HrotBench;
using testmodel::kDigestAbc;

namespace {

constexpr hrot::Slot kSlot0 = hrot::Slot::At<0>();
constexpr hrot::Slot kSlot1 = hrot::Slot::At<1>();
const hrot::Digest kDigest{kDigestAbc};

// Slots: compile-time and run-time checks, one id range per kind.
static_assert(hrot::Slot::At<15>().Index() == 15U);
static_assert(!hrot::Slot::Make(16U).ok() && hrot::Slot::Make(15U).ok());
static_assert(hrot::Slot::At<3>().Object().value == 0x5E050103U);
static_assert(hrot::DataSlot::At<3>().Object().value == 0x5E050203U);
static_assert(hrot::CounterSlot::At<3>().Object().value == 0x5E050303U);
static_assert(hrot::CertSlot::At<3>().Object().value == 0x5E050403U);
static_assert(MakeUserObject(hrot::CertSlot::At<15>().Object().value).ok());
static_assert(!hrot::SignKey{}.IsValid() && (hrot::AgreeKey::Use() == hrot::KeyUse::Agree));
// A trusted key needs an id and an uncompressed point.
static_assert(!hrot::TrustAttestationKey(ObjectId{0U}, hrot::EcPublicKey{}).ok());
static_assert(!hrot::TrustAttestationKey(ObjectId{0xF0000012U}, hrot::EcPublicKey{}).ok());
static_assert(
    hrot::TrustAttestationKey(ObjectId{0xF0000012U}, hrot::EcPublicKey{.point = {0x04U}}).ok());

/// A host key pair for ECDH (made up).
constexpr std::array<uint8_t, 32> kPeerPrivate{
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x08, 0x19, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x01,
    0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x09, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x02};

constexpr const testmodel::ChipProfile& kEcdhAllowed = testmodel::kSe050EEcdh;

} // namespace

TEST_CASE("Facade: a closed device refuses every call and sends nothing") {
  HrotBench t;
  CHECK_EQ(t.facade.Identify().error, Error::NotInitialized);
  CHECK_EQ(t.facade.Provision<hrot::KeyUse::Sign>(kSlot0).error, Error::NotInitialized);
  CHECK_EQ(t.facade.Provision<hrot::KeyUse::Sign>(kSlot0).detail.layer, Layer::Hrot);
  std::array<uint8_t, 4> out{};
  CHECK_EQ(t.facade.Random(MutableByteSpan{out}).error, Error::NotInitialized);
  CHECK_EQ(t.facade.CounterValue(hrot::CounterSlot::At<0>()).error, Error::NotInitialized);
  const std::array<hrot::SlotPlan, 1> plan{hrot::SlotPlan{kSlot0, hrot::KeyUse::Sign}};
  CHECK_EQ(t.facade.CheckPlan(plan).error, Error::NotInitialized);
  CHECK_EQ(t.bench.device.ApduCount(), 0U);
}

TEST_CASE("Facade: without secure messaging keys and counters are refused, nothing is sent") {
  HrotBench t(testmodel::kSe050E, false);
  REQUIRE(t.Open());
  CHECK(!t.bench.device.SecureMessagingActive());
  const uint32_t before = t.Commands();
  const auto key = t.facade.Provision<hrot::KeyUse::Sign>(kSlot0);
  CHECK_EQ(key.error, Error::PolicyDenied);
  CHECK_EQ(key.detail.layer, Layer::Hrot);
  CHECK_EQ(t.facade.Find<hrot::KeyUse::Sign>(kSlot0).error, Error::PolicyDenied);
  CHECK_EQ(t.facade.CreateCounter(hrot::CounterSlot::At<0>(), 0U).error, Error::PolicyDenied);
  const std::array<uint8_t, 4> data{1U, 2U, 3U, 4U};
  CHECK_EQ(t.facade.Store(hrot::DataSlot::At<0>(), ByteSpan{data}, hrot::Protection::Secret).error,
           Error::PolicyDenied);
  CHECK_EQ(t.Commands(), before);
  CHECK(!t.bench.chip.Has(kSlot0.Object().value));
  // Public data, certificates, the identity and random numbers need no secure messaging.
  CHECK(t.facade.Store(hrot::DataSlot::At<1>(), ByteSpan{data}, hrot::Protection::Public).ok());
  CHECK(t.facade.Identify().ok());
  std::array<uint8_t, 8> rnd{};
  CHECK(t.facade.Random(MutableByteSpan{rnd}).ok());
}

TEST_CASE("Facade: a UserID session alone is no secure messaging (S-14)") {
  HrotBench t(testmodel::kSe050E, false);
  REQUIRE(t.Open());
  REQUIRE(t.bench.device.BeginUserIdSession(testmodel::ChipBench::UserParams()).ok());
  CHECK(!t.bench.device.SecureMessagingActive());
  CHECK_EQ(t.facade.Provision<hrot::KeyUse::TlsClient>(kSlot0).error, Error::PolicyDenied);
  CHECK(!t.bench.chip.Has(kSlot0.Object().value));
}

TEST_CASE("Facade: an AESKey session is secure messaging enough") {
  HrotBench t(testmodel::kSe050E, false);
  REQUIRE(t.Open());
  REQUIRE(t.bench.device.BeginAesKeySession(t.bench.AesParams()).ok());
  const auto key = t.facade.Provision<hrot::KeyUse::Sign>(kSlot0);
  REQUIRE(key.ok());
  CHECK(t.facade.Sign(key.value, kDigest).ok());
}

TEST_CASE("Facade: Provision generates in the chip, never twice in one slot") {
  HrotBench t;
  REQUIRE(t.Open());
  const auto key = t.facade.Provision<hrot::KeyUse::Sign>(kSlot0);
  REQUIRE(key.ok());
  CHECK(key.value.IsValid());
  CHECK_EQ(key.value.Id().value, kSlot0.Object().value);
  CHECK(t.bench.chip.Has(kSlot0.Object().value));
  const uint32_t before = t.Commands();
  const auto again = t.facade.Provision<hrot::KeyUse::Agree>(kSlot0);
  CHECK_EQ(again.error, Error::ObjectExists);
  CHECK(!again.value.IsValid());
  CHECK_EQ(t.Commands(), before + 1U); // the existence check only: no WriteECKey
  const auto found = t.facade.Find<hrot::KeyUse::Sign>(kSlot0);
  REQUIRE(found.ok());
  CHECK(found.value.GetSlot() == kSlot0);
  CHECK_EQ(t.facade.Find<hrot::KeyUse::Sign>(kSlot1).error, Error::ObjectNotFound);
}

TEST_CASE("Facade: the public key is the chip's point, and a forged handle is refused") {
  HrotBench t;
  REQUIRE(t.Open());
  const auto key = t.facade.Provision<hrot::KeyUse::Sign>(kSlot0);
  REQUIRE(key.ok());
  const auto pub = t.facade.GetPublicKey(key.value);
  REQUIRE(pub.ok());
  CHECK_EQ(pub.value.point[0], 0x04U);
  const uint32_t before = t.Commands();
  CHECK_EQ(t.facade.GetPublicKey(hrot::SignKey{}).error, Error::InvalidArgument);
  CHECK_EQ(t.facade.Sign(hrot::SignKey{}, kDigest).error, Error::InvalidArgument);
  CHECK_EQ(t.facade.TlsSign(hrot::TlsKey{}, kDigest).error, Error::InvalidArgument);
  CHECK_EQ(t.Commands(), before);
}

TEST_CASE("Facade: a signature verifies with the host and on the chip; a bad one fails closed") {
  HrotBench t;
  REQUIRE(t.Open());
  const auto key = t.facade.Provision<hrot::KeyUse::Sign>(kSlot0);
  REQUIRE(key.ok());
  const auto sig = t.facade.Sign(key.value, kDigest);
  REQUIRE(sig.ok());
  CHECK(sig.value.length >= 8U);
  CHECK_EQ(sig.value.bytes[0], 0x30U);
  const auto pub = t.facade.GetPublicKey(key.value);
  REQUIRE(pub.ok());
  uint8_t rs[64];
  REQUIRE(testmodel::mc::ParseDer(sig.value.View(), rs, rs + 32));
  CHECK(testmodel::mc::Verify(pub.value.point.data(), kDigestAbc.data(), rs, rs + 32));
  CHECK(t.facade.VerifySignature(key.value, kDigest, sig.value.View()).ok());
  hrot::Signature bad = sig.value;
  bad.bytes[bad.length - 1U] = static_cast<uint8_t>(bad.bytes[bad.length - 1U] ^ 0x01U);
  const auto refused = t.facade.VerifySignature(key.value, kDigest, bad.View());
  CHECK_EQ(refused.error, Error::AttestationInvalid);
  CHECK_EQ(refused.detail.layer, Layer::Hrot);
  CHECK_EQ(t.facade.VerifySignature(key.value, kDigest, ByteSpan{}).error, Error::InvalidArgument);
}

TEST_CASE("Facade: a TLS key signs the handshake digest") {
  HrotBench t;
  REQUIRE(t.Open());
  const auto key = t.facade.Provision<hrot::KeyUse::TlsClient>(kSlot1);
  REQUIRE(key.ok());
  const auto sig = t.facade.TlsSign(key.value, kDigest);
  REQUIRE(sig.ok());
  CHECK(t.facade.VerifySignature(key.value, kDigest, sig.value.View()).ok());
}

TEST_CASE("Facade: a trust anchor stored as a public key verifies, and is never overwritten") {
  HrotBench t;
  REQUIRE(t.Open());
  const auto signer = t.facade.Provision<hrot::KeyUse::Sign>(kSlot0);
  REQUIRE(signer.ok());
  const auto pub = t.facade.GetPublicKey(signer.value);
  REQUIRE(pub.ok());
  const auto anchor = t.facade.ImportPublicKey(kSlot1, pub.value);
  REQUIRE(anchor.ok());
  const auto sig = t.facade.Sign(signer.value, kDigest);
  REQUIRE(sig.ok());
  CHECK(t.facade.VerifySignature(anchor.value, kDigest, sig.value.View()).ok());
  CHECK_EQ(t.facade.ImportPublicKey(kSlot1, pub.value).error, Error::ObjectExists);
  const uint32_t before = t.Commands();
  CHECK_EQ(t.facade.ImportPublicKey(hrot::Slot::At<2>(), hrot::EcPublicKey{}).error,
           Error::InvalidArgument);
  CHECK_EQ(t.Commands(), before);
}

TEST_CASE("Facade: ECDH gives the host's shared secret; a bad peer wipes the output") {
  HrotBench t(kEcdhAllowed);
  REQUIRE(t.Open());
  const auto key = t.facade.Provision<hrot::KeyUse::Agree>(kSlot0);
  REQUIRE(key.ok());
  const auto chip_pub = t.facade.GetPublicKey(key.value);
  REQUIRE(chip_pub.ok());
  hrot::EcPublicKey peer{};
  REQUIRE(testmodel::mc::PublicKey(kPeerPrivate.data(), peer.point.data()));
  SecretBuffer<32> shared;
  REQUIRE(t.facade.Agree(key.value, peer, shared).ok());
  std::array<uint8_t, 32> expected{};
  REQUIRE(testmodel::mc::Ecdh(kPeerPrivate.data(), chip_pub.value.point.data(), expected.data()));
  CHECK(ct::Equal(shared.Span(), ByteSpan{expected}));
  CHECK_EQ(t.facade.Agree(key.value, hrot::EcPublicKey{}, shared).error, Error::InvalidArgument);
  CHECK(shared.Span().empty());
  CHECK_EQ(t.facade.Agree(hrot::AgreeKey{}, peer, shared).error, Error::InvalidArgument);
  HrotBench forbidden; // every extended feature bit set: ECDH forbidden by the chip's configuration
  REQUIRE(forbidden.Open());
  const auto k2 = forbidden.facade.Provision<hrot::KeyUse::Agree>(kSlot0);
  REQUIRE(k2.ok());
  CHECK_EQ(forbidden.facade.Agree(k2.value, peer, shared).error, Error::Unsupported);
  CHECK(shared.Span().empty());
}

TEST_CASE("Facade: Identify reads the unique id and the derived identity") {
  HrotBench t;
  REQUIRE(t.Open());
  const auto id = t.facade.Identify();
  REQUIRE(id.ok());
  CHECK_EQ(id.value.unique_id[0], 0xC0U);
  CHECK_EQ(id.value.unique_id[17], 0xD1U);
  CHECK_EQ(id.value.applet.major, 7U);
  CHECK_EQ(id.value.oef_id, 0xA921U);
  CHECK(id.value.family == t.bench.device.GetCapabilities().family);
}

TEST_CASE("Facade: Attest returns a verified public key with a fresh, ordered timestamp") {
  HrotBench t;
  REQUIRE(t.Open());
  const auto key = t.facade.Provision<hrot::KeyUse::Sign>(kSlot0);
  REQUIRE(key.ok());
  const auto pub = t.facade.GetPublicKey(key.value);
  REQUIRE(pub.ok());
  const auto first = t.facade.Attest(t.VendorKey(), kSlot0);
  REQUIRE(first.ok());
  REQUIRE(first.value.IsValid());
  const hrot::AttestedValue& v = first.value.Get();
  CHECK_EQ(v.data.length, 65U);
  CHECK(ct::Equal(v.data.View(), pub.value.View()));
  CHECK_EQ(v.unique_id[0], 0xC0U);
  const auto second = t.facade.Attest(t.VendorKey(), kSlot0);
  REQUIRE(second.ok());
  CHECK(attest::TimestampNotBefore(second.value.Get().timestamp, v.timestamp));
  CHECK(second.value.Get().timestamp != v.timestamp);
}

TEST_CASE("Facade: the attestation is checked over the TLVs as the chip returned them (A21)") {
  HrotBench t;
  REQUIRE(t.Open());
  REQUIRE(t.facade.Provision<hrot::KeyUse::Sign>(kSlot0).ok());
  t.bench.chip.knobs.attested_short_tlv = true; // one-byte lengths, not 82 xx xx
  const auto r = t.facade.Attest(t.VendorKey(), kSlot0);
  REQUIRE(r.ok());
  CHECK(r.value.IsValid());
  CHECK_EQ(r.value.Get().data.length, 65U);
}

TEST_CASE("Facade: a replayed attested answer is refused (host nonce, strict timestamp order)") {
  HrotBench t;
  REQUIRE(t.Open());
  REQUIRE(t.facade.Provision<hrot::KeyUse::Sign>(kSlot0).ok());
  REQUIRE(t.facade.Attest(t.VendorKey(), kSlot0).ok());
  t.bench.chip.knobs.replay_attested = true;
  const uint32_t before = t.Commands();
  const auto replayed = t.facade.Attest(t.VendorKey(), kSlot0);
  CHECK_EQ(replayed.error, Error::AttestationInvalid);
  CHECK(!replayed.value.IsValid());
  CHECK_EQ(t.Commands(), before + 1U); // no GetRandom: the nonce comes from the crypto port
}

TEST_CASE("Facade: Attest refuses a wrong trusted key and another chip's identity") {
  HrotBench t;
  REQUIRE(t.Open());
  REQUIRE(t.facade.Provision<hrot::KeyUse::Sign>(kSlot0).ok());
  hrot::EcPublicKey other{};
  REQUIRE(testmodel::mc::PublicKey(kPeerPrivate.data(), other.point.data()));
  const auto wrong = t.facade.Attest(
      hrot::TrustAttestationKey(ObjectId{testmodel::ChipModel::kAttestKey}, other).value, kSlot0);
  CHECK_EQ(wrong.error, Error::AttestationInvalid);
  CHECK(!wrong.value.IsValid());
  CHECK_EQ(t.facade.Attest(hrot::AttestationKey{}, kSlot0).error, Error::InvalidArgument);

  HrotBench c;
  REQUIRE(c.Open());
  REQUIRE(c.facade.Provision<hrot::KeyUse::Sign>(kSlot0).ok());
  c.bench.chip.knobs.unique_id_flip = 0x01U; // the plain id read differs from the signed one
  const auto counterfeit = c.facade.Attest(c.VendorKey(), kSlot0);
  CHECK_EQ(counterfeit.error, Error::Counterfeit);
  CHECK(!counterfeit.value.IsValid());
}

TEST_CASE("Facade: an attestation key provisioned by the facade attests data") {
  HrotBench t;
  REQUIRE(t.Open());
  const auto ak = t.facade.Provision<hrot::KeyUse::Attest>(kSlot1);
  REQUIRE(ak.ok());
  const auto ak_pub = t.facade.GetPublicKey(ak.value);
  REQUIRE(ak_pub.ok());
  const std::array<uint8_t, 5> config{0x10U, 0x20U, 0x30U, 0x40U, 0x50U};
  REQUIRE(t.facade.Store(hrot::DataSlot::At<2>(), ByteSpan{config}, hrot::Protection::Secret).ok());
  t.bench.chip.MarkAttestation(ak.value.Id().value);
  const auto trusted = hrot::TrustAttestationKey(ak.value.Id(), ak_pub.value);
  REQUIRE(trusted.ok());
  const auto read = t.facade.Attest(trusted.value, hrot::DataSlot::At<2>());
  REQUIRE(read.ok());
  CHECK(ct::Equal(read.value.Get().data.View(), ByteSpan{config}));
  CHECK_EQ(read.value.Get().object_size, 5U);
}

TEST_CASE("Facade: CheckPlan refuses an empty plan and a slot twice, sends nothing") {
  HrotBench t;
  REQUIRE(t.Open());
  const uint32_t before = t.Commands();
  const std::array<hrot::SlotPlan, 3> plan{
      hrot::SlotPlan{kSlot0, hrot::KeyUse::Sign}, hrot::SlotPlan{kSlot1, hrot::KeyUse::Attest},
      hrot::SlotPlan{hrot::Slot::At<2>(), hrot::KeyUse::Verify}};
  CHECK(t.facade.CheckPlan(plan).ok());
  const std::array<hrot::SlotPlan, 2> twice{hrot::SlotPlan{kSlot1, hrot::KeyUse::Sign},
                                            hrot::SlotPlan{kSlot1, hrot::KeyUse::Agree}};
  CHECK_EQ(t.facade.CheckPlan(twice).error, Error::InvalidArgument);
  CHECK_EQ(t.facade.CheckPlan(std::span<const hrot::SlotPlan>{}).error, Error::InvalidArgument);
  CHECK_EQ(t.Commands(), before);
}

/** @brief Valid keys of every use, made on an applet 7.x chip, and a signature by the sign key. */
struct V7Keys {
  hrot::SignKey sign;
  hrot::TlsKey tls;
  hrot::AttestKey attest;
  hrot::AgreeKey agree;
  hrot::VerifyKey verify;
  hrot::EcPublicKey pub{};
  hrot::AttestationKey trusted;
  hrot::Signature sig{};
};

/** @brief Make the keys on an SE050E into `k`; `k.sig` stays empty on a failure. */
void MakeV7Keys(V7Keys& k) {
  HrotBench t;
  REQUIRE(t.Open());
  const auto sign = t.facade.Provision<hrot::KeyUse::Sign>(kSlot0);
  const auto tls = t.facade.Provision<hrot::KeyUse::TlsClient>(kSlot1);
  const auto attest = t.facade.Provision<hrot::KeyUse::Attest>(hrot::Slot::At<2>());
  const auto agree = t.facade.Provision<hrot::KeyUse::Agree>(hrot::Slot::At<3>());
  REQUIRE((sign.ok() && tls.ok() && attest.ok() && agree.ok()));
  const auto pub = t.facade.GetPublicKey(sign.value);
  REQUIRE(pub.ok());
  const auto verify = t.facade.ImportPublicKey(hrot::Slot::At<4>(), pub.value);
  const auto sig = t.facade.Sign(sign.value, kDigest);
  const auto attest_pub = t.facade.GetPublicKey(attest.value);
  REQUIRE(attest_pub.ok());
  const auto trusted = hrot::TrustAttestationKey(attest.value.Id(), attest_pub.value);
  REQUIRE((verify.ok() && sig.ok() && trusted.ok()));
  k.sign = sign.value;
  k.tls = tls.value;
  k.attest = attest.value;
  k.agree = agree.value;
  k.verify = verify.value;
  k.pub = pub.value;
  k.trusted = trusted.value;
  k.sig = sig.value;
}

/** @brief Every facade call on `t` (opened, not applet 7.x) returns `Unsupported` and sends
 * nothing. */
void CheckEveryCallUnsupported(HrotBench& t, const V7Keys& k) {
  constexpr Error kNo = Error::Unsupported;
  const uint32_t before = t.Commands();
  const std::array<hrot::SlotPlan, 1> plan{hrot::SlotPlan{kSlot1, hrot::KeyUse::Agree}};
  CHECK_EQ(t.facade.CheckPlan(plan).error, kNo);
  CHECK_EQ(t.facade.Identify().error, kNo);
  CHECK_EQ(t.facade.Provision<hrot::KeyUse::Sign>(kSlot0).error, kNo);
  CHECK_EQ(t.facade.Find<hrot::KeyUse::Sign>(kSlot0).error, kNo);
  CHECK_EQ(t.facade.GetPublicKey(k.sign).error, kNo);
  CHECK_EQ(t.facade.ImportPublicKey(hrot::Slot::At<5>(), k.pub).error, kNo);
  CHECK_EQ(t.facade.Sign(k.sign, kDigest).error, kNo);
  CHECK_EQ(t.facade.TlsSign(k.tls, kDigest).error, kNo);
  CHECK_EQ(t.facade.VerifySignature(k.verify, kDigest, k.sig.View()).error, kNo);
  hrot::EcPublicKey peer{};
  REQUIRE(testmodel::mc::PublicKey(kPeerPrivate.data(), peer.point.data()));
  SecretBuffer<32> shared;
  CHECK_EQ(t.facade.Agree(k.agree, peer, shared).error, kNo);
  CHECK(shared.Span().empty());
  CHECK_EQ(t.facade.Attest(k.trusted, hrot::DataSlot::At<0>()).error, kNo);
  CHECK_EQ(t.facade.Attest(k.trusted, kSlot0).error, kNo);
  const std::array<uint8_t, 4> data{1U, 2U, 3U, 4U};
  std::array<uint8_t, 8> out{};
  CHECK_EQ(t.facade.Store(hrot::DataSlot::At<0>(), ByteSpan{data}, hrot::Protection::Secret).error,
           kNo);
  CHECK_EQ(
      t.facade.Load(hrot::DataSlot::At<0>(), MutableByteSpan{out}, hrot::Protection::Secret).error,
      kNo);
  CHECK_EQ(t.facade.Erase(hrot::DataSlot::At<0>()).error, kNo);
  CHECK_EQ(t.facade.StoreCertificate(hrot::CertSlot::At<0>(), ByteSpan{data}).error, kNo);
  CHECK_EQ(t.facade.LoadCertificate(hrot::CertSlot::At<0>(), MutableByteSpan{out}).error, kNo);
  CHECK_EQ(t.facade.EraseCertificate(hrot::CertSlot::At<0>()).error, kNo);
  CHECK_EQ(t.facade.CreateCounter(hrot::CounterSlot::At<0>(), 1U).error, kNo);
  CHECK_EQ(t.facade.CounterValue(hrot::CounterSlot::At<0>()).error, kNo);
  CHECK_EQ(t.facade.CounterIncrement(hrot::CounterSlot::At<0>()).error, kNo);
  CHECK_EQ(t.facade.RaiseCounterTo(hrot::CounterSlot::At<0>(), 2U).error, kNo);
  CHECK_EQ(t.facade.CheckFloor(hrot::CounterSlot::At<0>(), 1U).error, kNo);
  CHECK_EQ(t.facade.Random(MutableByteSpan{out}).error, kNo);
  CHECK_EQ(t.Commands(), before);
  // The device layer still works there: only the facade needs 7.x.
  CHECK(t.bench.device.GetRandom(MutableByteSpan{out}).ok());
}

TEST_CASE("Facade: applet 3.x and 6.x are refused before anything is sent") {
  V7Keys keys{};
  MakeV7Keys(keys);
  REQUIRE(keys.sig.length != 0U);
  HrotBench v3(testmodel::kSe050); // SE050 A to D, F
  REQUIRE(v3.Open());
  CHECK_EQ(v3.bench.device.GetCapabilities().generation, AppletGeneration::V3);
  CheckEveryCallUnsupported(v3, keys);
  HrotBench v6(testmodel::kSe051V6); // SE051 on early boards
  REQUIRE(v6.Open());
  CHECK_EQ(v6.bench.device.GetCapabilities().generation, AppletGeneration::V6);
  CheckEveryCallUnsupported(v6, keys);
}

TEST_CASE("Facade: on applet 3.x the argument checks run before Unsupported") {
  V7Keys keys{};
  MakeV7Keys(keys);
  REQUIRE(keys.sig.length != 0U);
  HrotBench t(testmodel::kSe050);
  REQUIRE(t.Open());
  const uint32_t before = t.Commands();
  CHECK_EQ(t.facade.Store(hrot::DataSlot::At<0>(), ByteSpan{}, hrot::Protection::Secret).error,
           Error::InvalidArgument);
  hrot::EcPublicKey off_curve{};
  REQUIRE(testmodel::mc::PublicKey(kPeerPrivate.data(), off_curve.point.data()));
  off_curve.point[64] =
      static_cast<uint8_t>(off_curve.point[64] ^ 0x01U); // y changed: off the curve
  SecretBuffer<32> shared;
  const auto agreed = t.facade.Agree(keys.agree, off_curve, shared);
  CHECK_EQ(agreed.error, Error::InvalidArgument);
  CHECK_EQ(agreed.detail.layer, Layer::Hrot);
  CHECK(shared.Span().empty());
  CHECK_EQ(t.facade.Random(MutableByteSpan{}).error, Error::InvalidArgument);
  // A default key handle is invalid: refused as an argument, not as Unsupported.
  const hrot::SignKey no_sign{};
  const hrot::AttestationKey no_attest{};
  const auto signature = t.facade.Sign(no_sign, kDigest);
  CHECK_EQ(signature.error, Error::InvalidArgument);
  CHECK_EQ(signature.detail.layer, Layer::Hrot);
  CHECK_EQ(t.facade.GetPublicKey(no_sign).error, Error::InvalidArgument);
  CHECK_EQ(t.facade.Attest(no_attest, kSlot0).error, Error::InvalidArgument);
  CHECK_EQ(t.Commands(), before);
}
