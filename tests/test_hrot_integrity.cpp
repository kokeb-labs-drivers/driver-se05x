/**
 * @file test_hrot_integrity.cpp
 * @brief The facade's safety regressions: the anti-rollback floor cannot be deleted, re-created
 * lower or left torn, the budget survives a reopen, the admission tiers
 *, the policies name the session in use (A20), a failed store leaves nothing behind and the
 * identity cache is per open. Each case runs against the chip model.
 */
#include <array>
#include <cstddef>
#include <cstdint>

#include "hrot_bench.hpp"
#include "test_harness.hpp"

using namespace se05x;
using testmodel::HrotBench;

namespace {

const hrot::Digest kDigest{testmodel::kDigestAbc};

// The policy header word of the first entry of a built policy (length, auth id, header).
uint32_t FirstHeader(const Policy& p) noexcept {
  const ByteSpan b = p.Bytes();
  uint32_t header = 0U;
  for (std::size_t i = 0U; (i < 4U) && ((5U + i) < b.size()); ++i) {
    header = (header << 8U) | b[5U + i];
  }
  return header;
}

// A ChipBench with platform SCP03 at `level`, opened.
bool OpenAt(testmodel::ChipBench& b, scp03::SecurityLevel level) noexcept {
  scp03::ChannelParams p{};
  const bool keys = (b.crypto.ImportKey(KeyKind::Aes128, ByteSpan{testmodel::kPlatformEnc},
                                        p.keys.enc) == CryptoStatus::Ok) &&
                    (b.crypto.ImportKey(KeyKind::Aes128, ByteSpan{testmodel::kPlatformMac},
                                        p.keys.mac) == CryptoStatus::Ok);
  p.level = level;
  return keys && b.device.SetPlatformKeys(p).ok() && b.device.Open().ok();
}

// `WithoutStoreMarker` on a value of `length` bytes that states `object_size`; every byte of the
// buffer is the marker value, so only the length check can refuse. Returns the result, and
// whether a refused value was left unchanged.
struct MarkerResult {
  bool kept;
  bool untouched;
};
constexpr MarkerResult StripMarker(uint32_t object_size, std::size_t length) noexcept {
  hrot::AttestedValue v{};
  v.data.bytes.fill(0xA5U);
  v.data.length = length;
  v.object_size = object_size;
  const bool kept = hrot::detail::WithoutStoreMarker(v);
  return MarkerResult{.kept = kept,
                      .untouched = (v.data.length == length) && (v.object_size == object_size)};
}
// A signed size above the 256-byte buffer is refused without reading past it: in a constant
// expression a read past the array does not compile.
static_assert(!StripMarker(600U, 200U).kept && StripMarker(600U, 200U).untouched);
static_assert(hrot::kMaxAttestedBytes == 256U);

} // namespace

TEST_CASE("Integrity: a counter policy grants no delete, a key policy no write or delete") {
  const auto counter =
      hrot::detail::DataPolicyOf<AppletGeneration::V7, ObjectClass::Counter>(true, false, 0U);
  REQUIRE(counter.ok());
  CHECK((FirstHeader(counter.value) & policy::HeaderBit(Rule::Delete)) == 0U);
  CHECK((FirstHeader(counter.value) & policy::HeaderBit(Rule::Write)) != 0U); // increments
  const auto data =
      hrot::detail::DataPolicyOf<AppletGeneration::V7, ObjectClass::BinaryFile>(true, true, 0U);
  REQUIRE(data.ok());
  CHECK((FirstHeader(data.value) & policy::HeaderBit(Rule::Delete)) != 0U); // Erase works
  const auto key = hrot::detail::KeyPolicyOf<AppletGeneration::V7, hrot::KeyUse::Sign>(0U);
  REQUIRE(key.ok());
  CHECK((FirstHeader(key.value) &
         (policy::HeaderBit(Rule::Delete) | policy::HeaderBit(Rule::Write))) == 0U);
}

TEST_CASE("Integrity: the floor cannot be lowered by delete and re-create") {
  HrotBench t;
  REQUIRE(t.Open());
  constexpr hrot::CounterSlot kFloor = hrot::CounterSlot::At<3>();
  REQUIRE(t.facade.CreateCounter(kFloor, 5U).ok());
  CHECK_EQ(t.facade.CheckFloor(kFloor, 4U).error, Error::PolicyDenied);
  const auto del = t.bench.device.DeleteObject(kFloor.Object());
  CHECK(!del.ok()); // the chip refuses: the policy grants no delete
  CHECK(t.bench.chip.Has(kFloor.Object().value));
  CHECK_EQ(t.facade.CreateCounter(kFloor, 0U).error, Error::ObjectExists);
  CHECK_EQ(t.facade.CheckFloor(kFloor, 4U).error, Error::PolicyDenied); // rollback still refused
  CHECK(t.facade.CheckFloor(kFloor, 5U).ok());
}

TEST_CASE("Integrity: a counter is created at its value in one APDU") {
  HrotBench t;
  REQUIRE(t.Open());
  constexpr hrot::CounterSlot kFloor = hrot::CounterSlot::At<4>();
  const uint32_t before = t.Commands();
  REQUIRE(t.facade.CreateCounter(kFloor, 5U).ok());
  CHECK_EQ(t.Commands(), before + 2U); // the existence check and one WriteCounter with TAG_3
  CHECK_EQ(t.bench.chip.CounterValue(kFloor.Object().value), 5U);
  CHECK(t.facade.CheckFloor(kFloor, 5U).ok());
  CHECK_EQ(t.facade.CheckFloor(kFloor, 4U).error, Error::PolicyDenied);
}

TEST_CASE("Integrity: a torn create (counter at 0) is raised by the retry") {
  HrotBench t;
  REQUIRE(t.Open());
  constexpr hrot::CounterSlot kFloor = hrot::CounterSlot::At<4>();
  const auto pol =
      hrot::detail::DataPolicyOf<AppletGeneration::V7, ObjectClass::Counter>(true, false, 0U);
  REQUIRE(pol.ok());
  WriteCounterArgs create{}; // a create without its value, as an older two-APDU create left it
  create.id = kFloor.Object();
  create.policy = &pol.value;
  create.counter_bytes = hrot::kCounterBytes;
  REQUIRE(t.bench.device.Execute<Command::WriteCounter>(create).ok());
  CHECK_EQ(t.facade.CreateCounter(kFloor, 5U).error, Error::ObjectExists); // the retry
  CHECK_EQ(t.bench.chip.CounterValue(kFloor.Object().value), 5U);
  CHECK_EQ(t.facade.CheckFloor(kFloor, 1U).error, Error::PolicyDenied); // the floor is 5, not 0
  // An existing counter above the asked value is left alone.
  CHECK_EQ(t.facade.CreateCounter(kFloor, 2U).error, Error::ObjectExists);
  CHECK_EQ(t.bench.chip.CounterValue(kFloor.Object().value), 5U);
}

TEST_CASE("Integrity: the budget keeps the APDUs sent before a reopen") {
  HrotBench t(testmodel::kSe052, true);
  REQUIRE(t.Open());
  CHECK_EQ(t.bench.device.OpenCount(), 1U);
  std::array<uint8_t, 16> out{};
  for (int i = 0; i < 10; ++i) {
    REQUIRE(t.facade.Random(MutableByteSpan{out}).ok());
  }
  const uint32_t used_before = t.facade.Budget().Used();
  CHECK(used_before >= 10U);
  REQUIRE(t.bench.device.Close().ok());
  REQUIRE(t.Open());
  CHECK_EQ(t.bench.device.OpenCount(), 2U);
  CHECK(t.facade.Budget().Used() > used_before); // never counts down; the reopen adds APDUs
  t.facade.SetWindowCount(1000U);
  const uint32_t window = t.facade.Budget().Used();
  REQUIRE(t.bench.device.Close().ok());
  REQUIRE(t.Open());
  CHECK(t.facade.Budget().Used() > window); // the window count survives a reopen as well
}

TEST_CASE("Integrity: platform SCP03 at C-MAC only answers nothing the facade trusts") {
  testmodel::ChipBench b(testmodel::kSe050E, testmodel::T1Knobs{}, testmodel::ScpRequired());
  REQUIRE(OpenAt(b, scp03::SecurityLevel::CMac));
  CHECK(!b.device.AnswersAuthenticated());
  hrot::Device<testmodel::BenchPorts> f(b.device);
  const uint32_t before = b.chip.commands;
  CHECK_EQ(f.CreateCounter(hrot::CounterSlot::At<0>(), 3U).error, Error::PolicyDenied);
  CHECK_EQ(f.CheckFloor(hrot::CounterSlot::At<0>(), 3U).error, Error::PolicyDenied);
  CHECK_EQ(f.Provision<hrot::KeyUse::Sign>(hrot::Slot::At<0>()).error, Error::PolicyDenied);
  const std::array<uint8_t, 4> secret{1U, 2U, 3U, 4U};
  CHECK_EQ(f.Store(hrot::DataSlot::At<0>(), ByteSpan{secret}, hrot::Protection::Secret).error,
           Error::PolicyDenied);
  CHECK_EQ(b.chip.commands, before); // nothing sent
}

TEST_CASE("Integrity: C-MAC and R-MAC admits keys and counters, not secrets") {
  testmodel::ChipBench b(testmodel::kSe050EEcdh, testmodel::T1Knobs{}, testmodel::ScpRequired());
  REQUIRE(OpenAt(b, scp03::SecurityLevel::CMacRMac));
  CHECK(b.device.AnswersAuthenticated());
  CHECK(!b.device.TrafficConfidential());
  hrot::Device<testmodel::BenchPorts> f(b.device);
  REQUIRE(f.CreateCounter(hrot::CounterSlot::At<0>(), 3U).ok());
  CHECK(f.CheckFloor(hrot::CounterSlot::At<0>(), 3U).ok());
  const auto key = f.Provision<hrot::KeyUse::Sign>(hrot::Slot::At<0>());
  REQUIRE(key.ok());
  CHECK(f.Sign(key.value, kDigest).ok());
  const uint32_t before = b.chip.commands;
  const std::array<uint8_t, 4> secret{1U, 2U, 3U, 4U};
  CHECK_EQ(f.Store(hrot::DataSlot::At<0>(), ByteSpan{secret}, hrot::Protection::Secret).error,
           Error::PolicyDenied);
  std::array<uint8_t, 4> out{};
  CHECK_EQ(f.Load(hrot::DataSlot::At<0>(), MutableByteSpan{out}, hrot::Protection::Secret).error,
           Error::PolicyDenied);
  const auto agree = f.Provision<hrot::KeyUse::Agree>(hrot::Slot::At<1>());
  CHECK_EQ(agree.error, Error::Ok); // provisioning sends no secret
  hrot::EcPublicKey peer{};
  peer.point = b.chip.AttestPublic();
  SecretBuffer<32> shared;
  CHECK_EQ(f.Agree(agree.value, peer, shared).error, Error::PolicyDenied);
  CHECK_EQ(b.chip.commands, before + 2U); // the agree key's existence check and generation
  // Public data needs no secure messaging at all.
  CHECK(f.Store(hrot::DataSlot::At<1>(), ByteSpan{secret}, hrot::Protection::Public).ok());
}

TEST_CASE("Integrity: full platform SCP03 admits secrets") {
  testmodel::ChipBench b(testmodel::kSe050E, testmodel::T1Knobs{}, testmodel::ScpRequired());
  REQUIRE(OpenAt(b, scp03::SecurityLevel::Full));
  CHECK(b.device.TrafficConfidential());
  hrot::Device<testmodel::BenchPorts> f(b.device);
  const std::array<uint8_t, 4> secret{1U, 2U, 3U, 4U};
  REQUIRE(f.Store(hrot::DataSlot::At<0>(), ByteSpan{secret}, hrot::Protection::Secret).ok());
  std::array<uint8_t, 4> out{};
  const auto n = f.Load(hrot::DataSlot::At<0>(), MutableByteSpan{out}, hrot::Protection::Secret);
  REQUIRE(n.ok());
  CHECK_EQ(n.value, secret.size());
}

TEST_CASE("Integrity: a facade policy names the AESKey session it is created in (A20)") {
  HrotBench t(testmodel::kSe050E, false);
  REQUIRE(t.Open());
  REQUIRE(t.bench.device.BeginAesKeySession(t.bench.AesParams()).ok());
  constexpr hrot::Slot kSlot = hrot::Slot::At<0>();
  constexpr hrot::CounterSlot kCounter = hrot::CounterSlot::At<0>();
  REQUIRE(t.facade.Provision<hrot::KeyUse::Sign>(kSlot).ok());
  REQUIRE(t.facade.CreateCounter(kCounter, 1U).ok());
  CHECK(t.bench.chip.PolicyNames(kSlot.Object().value, testmodel::kAesCredential));
  CHECK(t.bench.chip.PolicyNames(kSlot.Object().value, 0U));
  CHECK(t.bench.chip.PolicyNames(kCounter.Object().value, testmodel::kAesCredential));

  HrotBench d; // the default session (platform SCP03): id 0 only
  REQUIRE(d.Open());
  REQUIRE(d.facade.Provision<hrot::KeyUse::Sign>(kSlot).ok());
  CHECK(d.bench.chip.PolicyNames(kSlot.Object().value, 0U));
  CHECK(!d.bench.chip.PolicyNames(kSlot.Object().value, testmodel::kAesCredential));
}

TEST_CASE("Integrity: a store that fails after the create leaves no partial object") {
  for (uint32_t skip = 0U; skip < 6U; ++skip) {
    HrotBench t;
    REQUIRE(t.Open());
    std::array<uint8_t, (2U * hrot::kChunkBytes) + 10U> data{};
    data.fill(0x5AU);
    t.bench.chip.knobs.inject_sw = 0x6A80U;
    t.bench.chip.knobs.inject_count = 1U;
    t.bench.chip.knobs.inject_skip = skip;
    const auto r =
        t.facade.Store(hrot::DataSlot::At<0>(), ByteSpan{data}, hrot::Protection::Secret);
    if (!r.ok()) {
      CHECK(!t.bench.chip.Has(hrot::DataSlot::At<0>().Object().value));
    }
  }
}

TEST_CASE("Integrity: the identity read for Attest is per open, not kept across a reopen") {
  HrotBench t;
  REQUIRE(t.Open());
  constexpr hrot::Slot kSlot = hrot::Slot::At<0>();
  REQUIRE(t.facade.Provision<hrot::KeyUse::Sign>(kSlot).ok());
  REQUIRE(t.facade.Attest(t.VendorKey(), kSlot).ok());
  const uint32_t before = t.Commands();
  REQUIRE(t.facade.Attest(t.VendorKey(), kSlot).ok());
  CHECK_EQ(t.Commands(), before + 1U); // the id is known in this open
  REQUIRE(t.bench.device.Close().ok());
  t.bench.chip.knobs.unique_id_flip = 0x01U; // another chip answers after the reopen
  REQUIRE(t.Open());
  CHECK_EQ(t.facade.Attest(t.VendorKey(), kSlot).error, Error::Counterfeit);
}

TEST_CASE("Integrity: an attested answer older than the last accepted is refused across a reopen") {
  HrotBench t;
  REQUIRE(t.Open());
  constexpr hrot::Slot kSlot = hrot::Slot::At<0>();
  REQUIRE(t.facade.Provision<hrot::KeyUse::Sign>(kSlot).ok());
  REQUIRE(t.facade.Attest(t.VendorKey(), kSlot).ok());
  REQUIRE(t.facade.Attest(t.VendorKey(), kSlot).ok());
  REQUIRE(t.bench.device.Close().ok());
  REQUIRE(t.Open());
  t.bench.chip.knobs.rewind_timestamp = true; // a signed answer, fresh nonce, older timestamp
  CHECK_EQ(t.facade.Attest(t.VendorKey(), kSlot).error, Error::AttestationInvalid);
}

TEST_CASE(
    "Integrity: a store whose first chunk created the object and then failed leaves nothing") {
  HrotBench t;
  REQUIRE(t.Open());
  const std::array<uint8_t, 4> data{1U, 2U, 3U, 4U};
  t.bench.chip.knobs.sw_after = 0x6A80U;
  t.bench.chip.knobs.sw_after_skip = 1U; // the existence check answers; the create fails after it
  CHECK(!t.facade.Store(hrot::DataSlot::At<1>(), ByteSpan{data}, hrot::Protection::Secret).ok());
  CHECK(!t.bench.chip.Has(hrot::DataSlot::At<1>().Object().value));
}

TEST_CASE("Integrity: Find and CreateCounter adopt only what the facade could have made") {
  HrotBench t;
  REQUIRE(t.Open());
  constexpr hrot::Slot kSlot = hrot::Slot::At<2>();
  REQUIRE(t.facade.Provision<hrot::KeyUse::Sign>(kSlot).ok());
  CHECK(t.facade.Find<hrot::KeyUse::Sign>(kSlot).ok());
  // A key imported from outside, or one whose policy allows delete, is not adopted.
  const Policy open_policy =
      PolicyBuilder<AppletGeneration::V7, ObjectClass::EcKeyPair, Profile::Open>{}
          .ForAllOthers()
          .Allow<Rule::Sign>()
          .Allow<Rule::Delete>()
          .WithReason(OpenReason::Laboratory)
          .Build()
          .value;
  constexpr hrot::Slot kForeign = hrot::Slot::At<3>();
  REQUIRE(t.bench.device.GenerateEcKey(kForeign.Object(), open_policy, EcCurve::NistP256).ok());
  CHECK_EQ(t.facade.Find<hrot::KeyUse::Sign>(kForeign).error, Error::PolicyDenied);
  // A public key is not a signing key, and a key pair is not a trust anchor.
  CHECK_EQ(t.facade.Find<hrot::KeyUse::Verify>(kSlot).error, Error::PolicyDenied);
  // A counter slot holding a binary file, or a deletable counter, is refused, not raised.
  constexpr hrot::CounterSlot kCounter = hrot::CounterSlot::At<5>();
  const auto data_policy =
      hrot::detail::DataPolicyOf<AppletGeneration::V7, ObjectClass::BinaryFile>(true, true, 0U);
  REQUIRE(data_policy.ok());
  REQUIRE(t.bench.device
              .WriteBinary(kCounter.Object(), data_policy.value, 0U,
                           ByteSpan{std::array<uint8_t, 4>{0U, 0U, 0U, 1U}}, 4U)
              .ok());
  CHECK_EQ(t.facade.CreateCounter(kCounter, 9U).error, Error::PolicyDenied);
  constexpr hrot::CounterSlot kLoose = hrot::CounterSlot::At<6>();
  const auto loose =
      hrot::detail::DataPolicyOf<AppletGeneration::V7, ObjectClass::Counter>(true, true, 0U);
  REQUIRE(loose.ok());
  WriteCounterArgs c{};
  c.id = kLoose.Object();
  c.policy = &loose.value;
  c.counter_bytes = hrot::kCounterBytes;
  REQUIRE(t.bench.device.Execute<Command::WriteCounter>(c).ok());
  CHECK_EQ(t.facade.CreateCounter(kLoose, 9U).error, Error::PolicyDenied);
  CHECK_EQ(t.bench.chip.CounterValue(kLoose.Object().value), 0U); // not raised
}

TEST_CASE(
    "Integrity: the adoption check compares class, origin, policy and lifetime each on its own") {
  HrotBench t;
  REQUIRE(t.Open());
  // The facade's own key policy on a key pair imported from outside: only the origin differs.
  const auto key_policy = hrot::detail::KeyPolicyOf<AppletGeneration::V7, hrot::KeyUse::Sign>(0U);
  REQUIRE(key_policy.ok());
  const std::array<uint8_t, 32> priv{0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x08U};
  WriteEcKeyArgs w{};
  constexpr hrot::Slot kImported = hrot::Slot::At<4>();
  w.id = kImported.Object();
  w.policy = &key_policy.value;
  w.private_key = ByteSpan{priv};
  REQUIRE(t.bench.device.Execute<Command::WriteEcKey>(w).ok());
  CHECK_EQ(t.facade.Find<hrot::KeyUse::Sign>(kImported).error, Error::PolicyDenied);
  // A binary file with the facade's exact counter policy in a counter slot: only the class differs.
  constexpr hrot::CounterSlot kFile = hrot::CounterSlot::At<7>();
  const auto kept =
      hrot::detail::DataPolicyOf<AppletGeneration::V7, ObjectClass::Counter>(true, false, 0U);
  REQUIRE(kept.ok());
  REQUIRE(t.bench.device
              .WriteBinary(kFile.Object(), kept.value, 0U,
                           ByteSpan{std::array<uint8_t, 4>{0U, 0U, 0U, 1U}}, 4U)
              .ok());
  CHECK_EQ(t.facade.CreateCounter(kFile, 9U).error, Error::PolicyDenied);
  // A key pair generated in the chip whose policy grants signing to anybody without secure
  // messaging (and nothing else): no write or delete grant, yet not the facade's policy.
  const Policy sign_only =
      PolicyBuilder<AppletGeneration::V7, ObjectClass::EcKeyPair, Profile::Open>{}
          .ForAllOthers()
          .Allow<Rule::Sign>()
          .WithReason(OpenReason::Laboratory)
          .Build()
          .value;
  constexpr hrot::Slot kLoose = hrot::Slot::At<5>();
  REQUIRE(t.bench.device.GenerateEcKey(kLoose.Object(), sign_only, EcCurve::NistP256).ok());
  CHECK_EQ(t.facade.Find<hrot::KeyUse::Sign>(kLoose).error, Error::PolicyDenied);
  // The facade's own key policy plus a write grant: only the policy differs from what Provision
  // makes.
  const Policy with_write =
      PolicyBuilder<AppletGeneration::V7, ObjectClass::EcKeyPair, Profile::Open>{}
          .ForAllOthers()
          .Allow<Rule::Read>()
          .Allow<Rule::Sign>()
          .Allow<Rule::Write>()
          .RequireSecureMessaging()
          .WithReason(OpenReason::Laboratory)
          .Build()
          .value;
  constexpr hrot::Slot kWritable = hrot::Slot::At<6>();
  REQUIRE(t.bench.device.GenerateEcKey(kWritable.Object(), with_write, EcCurve::NistP256).ok());
  CHECK_EQ(t.facade.Find<hrot::KeyUse::Sign>(kWritable).error, Error::PolicyDenied);
  // A counter with the facade's exact policy that is transient: its value would be lost at the next
  // applet select (AN12543 3.2.1.7), so the floor would read 0. Only the lifetime differs.
  constexpr hrot::CounterSlot kTransient = hrot::CounterSlot::At<8>();
  WriteCounterArgs c{};
  c.id = kTransient.Object();
  c.policy = &kept.value;
  c.counter_bytes = hrot::kCounterBytes;
  c.value = 7U;
  c.set_value = true;
  REQUIRE(t.bench.device.Execute<Command::WriteCounter>(c).ok());
  t.bench.chip.MakeTransient(kTransient.Object().value);
  CHECK_EQ(t.facade.CreateCounter(kTransient, 9U).error, Error::PolicyDenied);
  CHECK_EQ(t.bench.chip.CounterValue(kTransient.Object().value), 7U); // refused, not raised
  // The same counter, persistent, is adopted (and raised): the four checks are the only difference.
  constexpr hrot::CounterSlot kGood = hrot::CounterSlot::At<9>();
  c.id = kGood.Object();
  REQUIRE(t.bench.device.Execute<Command::WriteCounter>(c).ok());
  CHECK_EQ(t.facade.CreateCounter(kGood, 9U).error, Error::ObjectExists);
  CHECK_EQ(t.bench.chip.CounterValue(kGood.Object().value), 9U);
}

TEST_CASE("Integrity: a store cut short before its completion marker is never read back as data") {
  HrotBench t;
  REQUIRE(t.Open());
  constexpr hrot::DataSlot kTorn = hrot::DataSlot::At<3>();
  const auto policy =
      hrot::detail::DataPolicyOf<AppletGeneration::V7, ObjectClass::BinaryFile>(true, true, 0U);
  REQUIRE(policy.ok());
  // What a power loss after the first of two chunks leaves: the object created at its full
  // length (data plus marker), the first chunk written, the rest zero.
  std::array<uint8_t, hrot::kChunkBytes> first{};
  first.fill(0x3CU);
  REQUIRE(t.bench.device
              .WriteBinary(kTorn.Object(), policy.value, 0U, ByteSpan{first},
                           static_cast<uint16_t>(hrot::kChunkBytes + 40U + 1U))
              .ok());
  std::array<uint8_t, hrot::kChunkBytes + 40U> out{};
  CHECK_EQ(t.facade.Load(kTorn, MutableByteSpan{out}, hrot::Protection::Secret).error,
           Error::FrameError);
  // A complete store of the same size reads back.
  REQUIRE(t.facade.Erase(kTorn).ok());
  std::array<uint8_t, hrot::kChunkBytes + 40U> data{};
  data.fill(0x3CU);
  REQUIRE(t.facade.Store(kTorn, ByteSpan{data}, hrot::Protection::Secret).ok());
  const auto n = t.facade.Load(kTorn, MutableByteSpan{out}, hrot::Protection::Secret);
  REQUIRE(n.ok());
  CHECK_EQ(n.value, data.size());
}

TEST_CASE("Integrity: Load and Attest refuse an object without its completion marker") {
  HrotBench t;
  REQUIRE(t.Open());
  const auto policy =
      hrot::detail::DataPolicyOf<AppletGeneration::V7, ObjectClass::BinaryFile>(true, true, 0U);
  REQUIRE(policy.ok());
  // One byte that happens to be the marker value: no room for data, refused.
  constexpr hrot::DataSlot kOne = hrot::DataSlot::At<4>();
  const std::array<uint8_t, 1> marker_only{0xA5U};
  REQUIRE(
      t.bench.device.WriteBinary(kOne.Object(), policy.value, 0U, ByteSpan{marker_only}, 1U).ok());
  std::array<uint8_t, 8> out{};
  CHECK_EQ(t.facade.Load(kOne, MutableByteSpan{out}, hrot::Protection::Secret).error,
           Error::FrameError);
  // Five bytes and a last byte that is not the marker: the shape of a store cut short.
  constexpr hrot::DataSlot kTorn = hrot::DataSlot::At<5>();
  const std::array<uint8_t, 6> torn{0x10U, 0x20U, 0x30U, 0x40U, 0x50U, 0x00U};
  REQUIRE(t.bench.device.WriteBinary(kTorn.Object(), policy.value, 0U, ByteSpan{torn}, 6U).ok());
  const auto ak = t.facade.Provision<hrot::KeyUse::Attest>(hrot::Slot::At<1>());
  REQUIRE(ak.ok());
  const auto ak_pub = t.facade.GetPublicKey(ak.value);
  REQUIRE(ak_pub.ok());
  t.bench.chip.MarkAttestation(ak.value.Id().value);
  const auto trusted = hrot::TrustAttestationKey(ak.value.Id(), ak_pub.value);
  REQUIRE(trusted.ok());
  CHECK_EQ(t.facade.Attest(trusted.value, kTorn).error, Error::FrameError);
  CHECK_EQ(t.facade.Load(kTorn, MutableByteSpan{out}, hrot::Protection::Secret).error,
           Error::FrameError);
}

TEST_CASE("Integrity: a signed size that differs from the attested value is refused") {
  HrotBench t;
  REQUIRE(t.Open());
  const auto ak = t.facade.Provision<hrot::KeyUse::Attest>(hrot::Slot::At<1>());
  REQUIRE(ak.ok());
  const auto ak_pub = t.facade.GetPublicKey(ak.value);
  REQUIRE(ak_pub.ok());
  t.bench.chip.MarkAttestation(ak.value.Id().value);
  const auto trusted = hrot::TrustAttestationKey(ak.value.Id(), ak_pub.value);
  REQUIRE(trusted.ok());
  // Every byte is the marker value, so only the length check tells a partial value from a whole.
  constexpr hrot::DataSlot kSlot = hrot::DataSlot::At<3>();
  const std::array<uint8_t, 3> data{0xA5U, 0xA5U, 0xA5U};
  REQUIRE(t.facade.Store(kSlot, ByteSpan{data}, hrot::Protection::Secret).ok());
  REQUIRE(t.facade.Attest(trusted.value, kSlot).ok());
  // The signed answer is shorter than the object size it states: a partial read.
  t.bench.chip.knobs.attested_size_offset = 1;
  CHECK_EQ(t.facade.Attest(trusted.value, kSlot).error, Error::FrameError);
  // The signed answer is longer than the size it states: its byte at that size is 0xA5 too.
  t.bench.chip.knobs.attested_size_offset = -1;
  CHECK_EQ(t.facade.Attest(trusted.value, kSlot).error, Error::FrameError);
  t.bench.chip.knobs.attested_size_offset = 0;
  const auto whole = t.facade.Attest(trusted.value, kSlot);
  REQUIRE(whole.ok());
  CHECK(ct::Equal(whole.value.Get().data.View(), ByteSpan{data}));
}

TEST_CASE("Integrity: the store marker is removed only from a value read whole") {
  // Read whole: the marker goes, from the value and the size.
  hrot::AttestedValue whole{};
  whole.data.bytes.fill(0xA5U);
  whole.data.length = 4U;
  whole.object_size = 4U;
  REQUIRE(hrot::detail::WithoutStoreMarker(whole));
  CHECK_EQ(whole.data.length, 3U);
  CHECK_EQ(whole.object_size, 3U);
  // A partial read (A36): 3 of 4 signed bytes, though the byte after them is the marker value.
  const MarkerResult partial = StripMarker(4U, 3U);
  CHECK(!partial.kept);
  CHECK(partial.untouched);
  // A read longer than the signed size.
  const MarkerResult longer = StripMarker(4U, 5U);
  CHECK(!longer.kept);
  CHECK(longer.untouched);
  // A signed size above the buffer, with fewer bytes read: refused, nothing read past the buffer.
  const MarkerResult above = StripMarker(600U, 200U);
  CHECK(!above.kept);
  CHECK(above.untouched);
  CHECK(!StripMarker(257U, 256U).kept);
  CHECK(StripMarker(256U, 256U).kept);
  // Too small to hold data and the marker.
  CHECK(!StripMarker(1U, 1U).kept);
  CHECK(!StripMarker(0U, 0U).kept);
  CHECK(StripMarker(2U, 2U).kept);
}

TEST_CASE("Integrity: a value cut short under a valid signature is refused by Attest and Load") {
  HrotBench t;
  REQUIRE(t.Open());
  const auto ak = t.facade.Provision<hrot::KeyUse::Attest>(hrot::Slot::At<1>());
  REQUIRE(ak.ok());
  const auto ak_pub = t.facade.GetPublicKey(ak.value);
  REQUIRE(ak_pub.ok());
  t.bench.chip.MarkAttestation(ak.value.Id().value);
  const auto trusted = hrot::TrustAttestationKey(ak.value.Id(), ak_pub.value);
  REQUIRE(trusted.ok());
  constexpr hrot::DataSlot kSlot = hrot::DataSlot::At<4>();
  const std::array<uint8_t, 3> data{0x11U, 0xA5U, 0x22U};
  REQUIRE(t.facade.Store(kSlot, ByteSpan{data}, hrot::Protection::Secret).ok());
  std::array<uint8_t, 8> out{};
  // The chip returns 3 of the 4 stored bytes, states the size 4 and signs what it returned.
  t.bench.chip.knobs.read_truncate = 1U;
  CHECK_EQ(t.facade.Attest(trusted.value, kSlot).error, Error::FrameError);
  CHECK_EQ(t.facade.Load(kSlot, MutableByteSpan{out}, hrot::Protection::Secret).error,
           Error::FrameError);
  // 2 of 4: the value returned ends in the marker value, and is refused all the same.
  t.bench.chip.knobs.read_truncate = 2U;
  CHECK_EQ(t.facade.Attest(trusted.value, kSlot).error, Error::FrameError);
  CHECK_EQ(t.facade.Load(kSlot, MutableByteSpan{out}, hrot::Protection::Secret).error,
           Error::FrameError);
  CHECK(ct::Equal(ByteSpan{out}, ByteSpan{std::array<uint8_t, 8>{}}));
  t.bench.chip.knobs.read_truncate = 0U;
  const auto read = t.facade.Attest(trusted.value, kSlot);
  REQUIRE(read.ok());
  CHECK(ct::Equal(read.value.Get().data.View(), ByteSpan{data}));
  CHECK_EQ(read.value.Get().object_size, 3U);
  const auto loaded = t.facade.Load(kSlot, MutableByteSpan{out}, hrot::Protection::Secret);
  REQUIRE(loaded.ok());
  CHECK_EQ(loaded.value, 3U);
}

TEST_CASE("Integrity: a failed ReadType or a failed raise ends adoption with the error") {
  HrotBench t;
  REQUIRE(t.Open());
  constexpr hrot::Slot kSlot = hrot::Slot::At<2>();
  REQUIRE(t.facade.Provision<hrot::KeyUse::Sign>(kSlot).ok());
  t.bench.chip.knobs.inject_sw = 0x6A82U;
  t.bench.chip.knobs.inject_count = 1U;
  t.bench.chip.knobs.inject_skip = 2U; // existence, attributes; ReadType fails
  CHECK(!t.facade.Find<hrot::KeyUse::Sign>(kSlot).ok());
  constexpr hrot::CounterSlot kFloor = hrot::CounterSlot::At<3>();
  REQUIRE(t.facade.CreateCounter(kFloor, 1U).ok());
  t.bench.chip.knobs.inject_sw = 0x6A80U;
  t.bench.chip.knobs.inject_count = 1U;
  t.bench.chip.knobs.inject_skip = 4U; // existence, attributes, type, value; the raise fails
  const auto r = t.facade.CreateCounter(kFloor, 9U);
  CHECK(!r.ok());
  CHECK(r.error != Error::ObjectExists); // never reported as a floor that is in place
  CHECK_EQ(t.bench.chip.CounterValue(kFloor.Object().value), 1U);
}

TEST_CASE("Integrity: attested data and certificates are read whole, without their marker") {
  HrotBench t;
  REQUIRE(t.Open());
  const auto ak = t.facade.Provision<hrot::KeyUse::Attest>(hrot::Slot::At<1>());
  REQUIRE(ak.ok());
  const auto ak_pub = t.facade.GetPublicKey(ak.value);
  REQUIRE(ak_pub.ok());
  t.bench.chip.MarkAttestation(ak.value.Id().value);
  const auto trusted = hrot::TrustAttestationKey(ak.value.Id(), ak_pub.value);
  REQUIRE(trusted.ok());
  // A certificate slot: the marker is removed from the value and the size.
  const std::array<uint8_t, 6> der{0x30U, 0x04U, 0x02U, 0x01U, 0x05U, 0x00U};
  REQUIRE(t.facade.StoreCertificate(hrot::CertSlot::At<0>(), ByteSpan{der}).ok());
  const auto cert = t.facade.Attest(trusted.value, hrot::CertSlot::At<0>());
  REQUIRE(cert.ok());
  CHECK(ct::Equal(cert.value.Get().data.View(), ByteSpan{der}));
  CHECK_EQ(cert.value.Get().object_size, der.size());
  // An object of one byte (no room for data and marker) and one too large to be read whole.
  const auto policy =
      hrot::detail::DataPolicyOf<AppletGeneration::V7, ObjectClass::BinaryFile>(true, true, 0U);
  REQUIRE(policy.ok());
  const std::array<uint8_t, 1> one{0xA5U};
  REQUIRE(t.bench.device
              .WriteBinary(hrot::DataSlot::At<6>().Object(), policy.value, 0U, ByteSpan{one}, 1U)
              .ok());
  CHECK_EQ(t.facade.Attest(trusted.value, hrot::DataSlot::At<6>()).error, Error::FrameError);
  // The largest attestable value is kMaxAttestedBytes - 1 (the marker takes the last byte).
  std::array<uint8_t, hrot::kMaxAttestedBytes - 1U> edge{};
  edge.fill(0x22U);
  REQUIRE(t.facade.Store(hrot::DataSlot::At<8>(), ByteSpan{edge}, hrot::Protection::Secret).ok());
  const auto at_edge = t.facade.Attest(trusted.value, hrot::DataSlot::At<8>());
  REQUIRE(at_edge.ok());
  CHECK_EQ(at_edge.value.Get().object_size, edge.size());
  std::array<uint8_t, hrot::kMaxAttestedBytes> over{};
  over.fill(0x33U);
  REQUIRE(t.facade.Store(hrot::DataSlot::At<9>(), ByteSpan{over}, hrot::Protection::Secret).ok());
  CHECK_EQ(t.facade.Attest(trusted.value, hrot::DataSlot::At<9>()).error, Error::BufferTooSmall);
  std::array<uint8_t, hrot::kMaxAttestedBytes + 10U> big{};
  big.fill(0x11U);
  REQUIRE(t.facade.Store(hrot::DataSlot::At<7>(), ByteSpan{big}, hrot::Protection::Secret).ok());
  CHECK_EQ(t.facade.Attest(trusted.value, hrot::DataSlot::At<7>()).error, Error::BufferTooSmall);
}

TEST_CASE("Integrity: the largest object round-trips; a failed or short marker read is refused") {
  HrotBench t;
  REQUIRE(t.Open());
  constexpr hrot::DataSlot kSlot = hrot::DataSlot::At<2>();
  std::array<uint8_t, hrot::kMaxStoredBytes> data{};
  data.fill(0x5AU);
  REQUIRE(t.facade.Store(kSlot, ByteSpan{data}, hrot::Protection::Secret).ok());
  std::array<uint8_t, hrot::kMaxStoredBytes> out{};
  const auto n = t.facade.Load(kSlot, MutableByteSpan{out}, hrot::Protection::Secret);
  REQUIRE(n.ok());
  CHECK_EQ(n.value, hrot::kMaxStoredBytes);
  t.bench.chip.knobs.inject_sw = 0x6A82U;
  t.bench.chip.knobs.inject_count = 1U;
  t.bench.chip.knobs.inject_skip = 1U; // ReadSize answers; the marker read fails with its error
  CHECK_EQ(t.facade.Load(kSlot, MutableByteSpan{out}, hrot::Protection::Secret).error,
           Error::ObjectNotFound);
  t.bench.chip.knobs.tamper = testmodel::Tamper::DropLast;
  t.bench.chip.knobs.tamper_skip = 1U; // the marker read comes back empty
  CHECK_EQ(t.facade.Load(kSlot, MutableByteSpan{out}, hrot::Protection::Secret).error,
           Error::FrameError);
}
