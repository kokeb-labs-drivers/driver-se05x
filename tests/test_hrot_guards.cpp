/**
 * @file test_hrot_guards.cpp
 * @brief The facade's answer guards (RD-25): every length and shape check on an answer from the
 * chip has a case that sends it a wrong answer (one byte short, a wrong first byte, a wider
 * counter) and expects the call to fail closed with its output wiped.
 */
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

#include "hrot_bench.hpp"
#include "test_harness.hpp"

using namespace se05x;
using testmodel::HrotBench;
using testmodel::Tamper;

namespace {

constexpr hrot::Slot kSlot0 = hrot::Slot::At<0>();
constexpr hrot::DataSlot kData = hrot::DataSlot::At<0>();
constexpr hrot::CounterSlot kCounter = hrot::CounterSlot::At<0>();

bool AllZero(ByteSpan b) noexcept {
  return std::ranges::all_of(b, [](uint8_t v) { return v == 0U; });
}

// Counts saturate instead of wrapping (S-17): the device's APDU count and the facade's window.
static_assert(detail::SaturatingAdd(1U, 2U) == 3U);
static_assert(detail::SaturatingAdd(0xFFFFFFFEU, 1U) == 0xFFFFFFFFU);
static_assert(detail::SaturatingAdd(0xFFFFFFFEU, 2U) == 0xFFFFFFFFU);
static_assert(detail::SaturatingAdd(0xFFFFFFFFU, 0xFFFFFFFFU) == 0xFFFFFFFFU);
static_assert(detail::SaturatingAdd(0U, 0xFFFFFFFFU) == 0xFFFFFFFFU);

// The attested-read rewrite keeps a command whose Lc does not fit one byte unchanged.
constexpr std::array<uint8_t, 7U + 256U> kLc256 = [] {
  std::array<uint8_t, 7U + 256U> c{0x80U, 0x02U, 0x00U, 0x00U, 0x00U, 0x01U, 0x00U};
  return c;
}();
constexpr std::array<uint8_t, 7U + 255U> kLc255 = [] {
  std::array<uint8_t, 7U + 255U> c{0x80U, 0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0xFFU};
  return c;
}();
static_assert([] {
  std::array<uint8_t, 300> out{};
  return detail::ShortestLcForm(ByteSpan{kLc256}, MutableByteSpan{out}).size() == kLc256.size();
}());
static_assert([] {
  std::array<uint8_t, 300> out{};
  return detail::ShortestLcForm(ByteSpan{kLc255}, MutableByteSpan{out}).size() == (5U + 255U);
}());

// A ChipBench with platform SCP03 at C-MAC only (answers not authenticated), opened.
bool OpenCMacOnly(testmodel::ChipBench& b) noexcept {
  scp03::ChannelParams p{};
  const bool keys = (b.crypto.ImportKey(KeyKind::Aes128, ByteSpan{testmodel::kPlatformEnc},
                                        p.keys.enc) == CryptoStatus::Ok) &&
                    (b.crypto.ImportKey(KeyKind::Aes128, ByteSpan{testmodel::kPlatformMac},
                                        p.keys.mac) == CryptoStatus::Ok);
  p.level = scp03::SecurityLevel::CMac;
  return keys && b.device.SetPlatformKeys(p).ok() && b.device.Open().ok();
}

} // namespace

TEST_CASE("Guards: Sign and RaiseCounterTo need authenticated answers; nothing is sent") {
  HrotBench full;
  REQUIRE(full.Open());
  const auto key = full.facade.Provision<hrot::KeyUse::Sign>(kSlot0); // a handle names a slot
  REQUIRE(key.ok());
  testmodel::ChipBench b(testmodel::kSe050E, testmodel::T1Knobs{}, testmodel::ScpRequired());
  REQUIRE(OpenCMacOnly(b));
  hrot::Device<testmodel::BenchPorts> f(b.device);
  const uint32_t before = b.chip.commands;
  const hrot::Digest digest{testmodel::kDigestAbc};
  CHECK_EQ(f.Sign(key.value, digest).error, Error::PolicyDenied);
  CHECK_EQ(f.RaiseCounterTo(kCounter, 9U).error, Error::PolicyDenied);
  CHECK_EQ(b.chip.commands, before);
}

TEST_CASE("Guards: a stored size of zero is FrameError, nothing is read") {
  HrotBench t;
  REQUIRE(t.Open());
  const std::array<uint8_t, 4> data{1U, 2U, 3U, 4U};
  REQUIRE(t.facade.Store(kData, ByteSpan{data}, hrot::Protection::Secret).ok());
  t.bench.chip.knobs.zero_read_size = true;
  std::array<uint8_t, 8> out{};
  const uint32_t before = t.Commands();
  CHECK_EQ(t.facade.Load(kData, MutableByteSpan{out}, hrot::Protection::Secret).error,
           Error::FrameError);
  CHECK_EQ(t.Commands(), before + 1U); // the size read only
}

TEST_CASE("Guards: a short Load chunk fails and the output is wiped") {
  for (uint32_t skip = 2U; skip <= 3U; ++skip) { // after ReadSize and the marker: chunk 1, then 2
    HrotBench t;
    REQUIRE(t.Open());
    std::array<uint8_t, hrot::kChunkBytes + 44U> data{};
    data.fill(0x3CU);
    REQUIRE(t.facade.Store(kData, ByteSpan{data}, hrot::Protection::Secret).ok());
    t.bench.chip.knobs.tamper = Tamper::DropLast;
    t.bench.chip.knobs.tamper_skip = skip; // ReadSize, the marker, then the chunks
    std::array<uint8_t, hrot::kChunkBytes + 44U> out{};
    const auto r = t.facade.Load(kData, MutableByteSpan{out}, hrot::Protection::Secret);
    CHECK_EQ(r.error, Error::FrameError);
    CHECK(AllZero(ByteSpan{out})); // the first chunk, read whole, is wiped as well
  }
}

TEST_CASE("Guards: a Load whose second chunk is refused wipes the first") {
  HrotBench t;
  REQUIRE(t.Open());
  std::array<uint8_t, hrot::kChunkBytes + 44U> data{};
  data.fill(0x3CU);
  REQUIRE(t.facade.Store(kData, ByteSpan{data}, hrot::Protection::Secret).ok());
  t.bench.chip.knobs.inject_sw = 0x6A80U;
  t.bench.chip.knobs.inject_count = 1U;
  t.bench.chip.knobs.inject_skip = 3U; // ReadSize, the marker and the first chunk answer normally
  std::array<uint8_t, hrot::kChunkBytes + 44U> out{};
  const auto r = t.facade.Load(kData, MutableByteSpan{out}, hrot::Protection::Secret);
  CHECK(!r.ok());
  CHECK(AllZero(ByteSpan{out}));
}

TEST_CASE("Guards: a stored size of zero or above the limit is refused") {
  HrotBench t;
  REQUIRE(t.Open());
  WriteBinaryArgs big{}; // created through the command layer, past the facade's limit
  const auto pol =
      hrot::detail::DataPolicyOf<AppletGeneration::V7, ObjectClass::BinaryFile>(true, true, 0U);
  REQUIRE(pol.ok());
  big.id = kData.Object();
  big.policy = &pol.value;
  big.file_length = static_cast<uint16_t>(hrot::kMaxStoredBytes + 2U); // data plus marker, plus one
  REQUIRE(t.bench.device.Execute<Command::WriteBinary>(big).ok());
  std::array<uint8_t, hrot::kMaxStoredBytes + 8U> out{};
  const uint32_t before = t.Commands();
  CHECK_EQ(t.facade.Load(kData, MutableByteSpan{out}, hrot::Protection::Secret).error,
           Error::FrameError);
  CHECK_EQ(t.Commands(), before + 1U); // the size read only
}

TEST_CASE("Guards: a short ECDH secret fails and the secret is wiped") {
  HrotBench t(testmodel::kSe050EEcdh);
  REQUIRE(t.Open());
  const auto key = t.facade.Provision<hrot::KeyUse::Agree>(kSlot0);
  REQUIRE(key.ok());
  hrot::EcPublicKey peer{};
  peer.point = t.bench.chip.AttestPublic();
  SecretBuffer<32> shared;
  t.bench.chip.knobs.tamper = Tamper::DropLast;
  CHECK_EQ(t.facade.Agree(key.value, peer, shared).error, Error::FrameError);
  CHECK(shared.Span().empty());
  REQUIRE(t.facade.Agree(key.value, peer, shared).ok());
  CHECK_EQ(shared.Span().size(), 32U);
}

TEST_CASE("Guards: a peer point that is not uncompressed is refused before sending") {
  HrotBench t;
  REQUIRE(t.Open());
  const auto key = t.facade.Provision<hrot::KeyUse::Agree>(kSlot0);
  REQUIRE(key.ok());
  hrot::EcPublicKey peer{};
  peer.point = t.bench.chip.AttestPublic();
  peer.point[0] = 0x03U; // a compressed-point prefix on a full point
  SecretBuffer<32> shared;
  const uint32_t before = t.Commands();
  CHECK_EQ(t.facade.Agree(key.value, peer, shared).error, Error::InvalidArgument);
  CHECK_EQ(t.Commands(), before);
  CHECK(shared.Span().empty());
}

TEST_CASE("Guards: a public key one byte short or with a wrong prefix is FrameError") {
  HrotBench t;
  REQUIRE(t.Open());
  const auto key = t.facade.Provision<hrot::KeyUse::Sign>(kSlot0);
  REQUIRE(key.ok());
  t.bench.chip.knobs.tamper = Tamper::DropLast;
  CHECK_EQ(t.facade.GetPublicKey(key.value).error, Error::FrameError);
  t.bench.chip.knobs.tamper = Tamper::FlipFirst; // 0x04 becomes 0x05
  CHECK_EQ(t.facade.GetPublicKey(key.value).error, Error::FrameError);
  CHECK(t.facade.GetPublicKey(key.value).ok());
}

TEST_CASE("Guards: a unique id one byte short is FrameError, and not cached") {
  HrotBench t;
  REQUIRE(t.Open());
  t.bench.chip.knobs.tamper = Tamper::DropLast;
  CHECK_EQ(t.facade.Identify().error, Error::FrameError);
  const auto id = t.facade.Identify();
  REQUIRE(id.ok());
  CHECK(!AllZero(ByteSpan{id.value.unique_id}));
}

TEST_CASE("Guards: a counter that is not 4 bytes wide is FrameError, never a floor") {
  HrotBench t;
  REQUIRE(t.Open());
  const auto pol =
      hrot::detail::DataPolicyOf<AppletGeneration::V7, ObjectClass::Counter>(true, false, 0U);
  REQUIRE(pol.ok());
  WriteCounterArgs wide{}; // an 8-byte counter at 2^32 + 1: its low word reads as 1
  wide.id = kCounter.Object();
  wide.policy = &pol.value;
  wide.counter_bytes = 8U;
  wide.value = 1U;
  wide.set_value = true;
  REQUIRE(t.bench.device.Execute<Command::WriteCounter>(wide).ok());
  CHECK_EQ(t.facade.CounterValue(kCounter).error, Error::FrameError);
  CHECK_EQ(t.facade.CheckFloor(kCounter, 1U).error, Error::FrameError);
}

TEST_CASE("Guards: the window count saturates where the limit does not apply") {
  HrotBench t; // SE050E: no throughput limit, so calls go on past the ceiling
  REQUIRE(t.Open());
  t.facade.SetWindowCount(0xFFFFFFFEU);
  std::array<uint8_t, 8> rnd{};
  for (int i = 0; i < 4; ++i) {
    REQUIRE(t.facade.Random(MutableByteSpan{rnd}).ok());
  }
  CHECK_EQ(t.facade.Budget().Used(), 0xFFFFFFFFU); // saturated, not wrapped to a small number
}

TEST_CASE("Guards: Find is budgeted as its three APDUs, refused whole when they do not fit") {
  HrotBench t(testmodel::kSe052);
  REQUIRE(t.Open());
  REQUIRE(t.facade.Provision<hrot::KeyUse::Sign>(kSlot0).ok());
  t.facade.SetWindowCount(kThroughputLimitApdus - 2U); // room for two APDUs, not three
  const uint32_t before = t.Commands();
  CHECK_EQ(t.facade.Find<hrot::KeyUse::Sign>(kSlot0).error, Error::ThroughputLimited);
  CHECK_EQ(t.Commands(), before);
  t.facade.SetWindowCount(kThroughputLimitApdus - 3U);
  CHECK(t.facade.Find<hrot::KeyUse::Sign>(kSlot0).ok());
}

TEST_CASE("Guards: a peer or trust anchor that is not on P-256 is refused before sending") {
  HrotBench t(testmodel::kSe050EEcdh);
  REQUIRE(t.Open());
  const auto key = t.facade.Provision<hrot::KeyUse::Agree>(kSlot0);
  REQUIRE(key.ok());
  hrot::EcPublicKey off{};
  off.point = t.bench.chip.AttestPublic();
  off.point[64] = static_cast<uint8_t>(off.point[64] ^ 0x01U); // y changed: no longer on the curve
  SecretBuffer<32> shared;
  const uint32_t before = t.Commands();
  CHECK_EQ(t.facade.Agree(key.value, off, shared).error, Error::InvalidArgument);
  CHECK_EQ(t.facade.ImportPublicKey(hrot::Slot::At<1>(), off).error, Error::InvalidArgument);
  CHECK_EQ(t.Commands(), before);
  CHECK(shared.Span().empty());
}

namespace {

// Run `call` with the window one APDU short of `cost` (refused, nothing sent), then with exactly
// `cost` left (`prepare` sets the chip up and says whether it succeeded): the call runs its path to
// the end, sends `sent` APDUs, and the count never passes the ceiling. The costs are written out
// here, not taken from `hrot::cost`, so a lowered constant is caught.
template <typename Prepare, typename Call>
void AtTheEdge(uint32_t cost, uint32_t sent, Error expected, Prepare prepare, Call call,
               const testmodel::ChipProfile& profile = testmodel::kSe052) {
  {
    HrotBench t(profile);
    REQUIRE(t.Open());
    REQUIRE(prepare(t));
    t.facade.SetWindowCount(kThroughputLimitApdus - cost + 1U);
    const uint32_t before = t.Commands();
    CHECK_EQ(call(t), Error::ThroughputLimited);
    CHECK_EQ(t.Commands(), before);
  }
  HrotBench t(profile);
  REQUIRE(t.Open());
  REQUIRE(prepare(t));
  t.facade.SetWindowCount(kThroughputLimitApdus - cost);
  const uint32_t before = t.Commands();
  CHECK_EQ(call(t), expected);
  CHECK_EQ(t.Commands() - before, sent);
  CHECK(t.facade.Budget().Used() <= kThroughputLimitApdus);
}

} // namespace

TEST_CASE("Guards: every facade path stays within its admitted cost at the budget's edge") {
  const std::array<uint8_t, 4> data{1U, 2U, 3U, 4U}; // one chunk
  const auto none = [](HrotBench&) { return true; };
  // Store, worst path: the marker write fails and the object is deleted (3 + 1 chunk).
  AtTheEdge(
      4U, 4U, Error::PolicyInvalid,
      [](HrotBench& t) {
        t.bench.chip.knobs.sw_after = 0x6A80U;
        t.bench.chip.knobs.sw_after_skip = 2U; // existence, chunk; the marker then fails
        return true;
      },
      [&](HrotBench& t) {
        return t.facade.Store(kData, ByteSpan{data}, hrot::Protection::Secret).error;
      });
  // Load of a stored object, sized on the buffer (2 + 1 chunk).
  AtTheEdge(
      3U, 3U, Error::Ok,
      [&](HrotBench& t) {
        return t.facade.Store(kData, ByteSpan{data}, hrot::Protection::Secret).ok();
      },
      [](HrotBench& t) {
        std::array<uint8_t, 8> out{};
        return t.facade.Load(kData, MutableByteSpan{out}, hrot::Protection::Secret).error;
      });
  // Find of a provisioned key.
  AtTheEdge(
      3U, 3U, Error::Ok,
      [](HrotBench& t) { return t.facade.Provision<hrot::KeyUse::Sign>(kSlot0).ok(); },
      [](HrotBench& t) { return t.facade.Find<hrot::KeyUse::Sign>(kSlot0).error; });
  // CreateCounter on an existing lower counter: adopted and raised (5 APDUs).
  AtTheEdge(
      5U, 5U, Error::ObjectExists,
      [](HrotBench& t) { return t.facade.CreateCounter(kCounter, 1U).ok(); },
      [](HrotBench& t) { return t.facade.CreateCounter(kCounter, 9U).error; });
  AtTheEdge(5U, 2U, Error::Ok, none,
            [](HrotBench& t) { return t.facade.CreateCounter(kCounter, 9U).error; });
  AtTheEdge(
      2U, 2U, Error::Ok, [](HrotBench& t) { return t.facade.CreateCounter(kCounter, 1U).ok(); },
      [](HrotBench& t) { return t.facade.CounterIncrement(kCounter).error; });
  AtTheEdge(
      2U, 2U, Error::Ok,
      [](HrotBench& t) { return t.facade.Provision<hrot::KeyUse::Sign>(kSlot0).ok(); },
      [](HrotBench& t) {
        return t.facade.Attest(t.VendorKey(), kSlot0).error; // the unique id, then the read
      });
}

TEST_CASE("Guards: the key, erase and counter calls are refused one APDU short of their cost") {
  const hrot::Digest digest{testmodel::kDigestAbc};
  const auto none = [](HrotBench&) { return true; };
  hrot::SignKey sign{};
  hrot::AgreeKey agree{};
  hrot::Signature sig{};
  const auto signer = [&](HrotBench& t) {
    const auto k = t.facade.Provision<hrot::KeyUse::Sign>(kSlot0);
    sign = k.value;
    return k.ok();
  };
  const auto peer = [](HrotBench& t) {
    hrot::EcPublicKey p{};
    p.point = t.bench.chip.AttestPublic(); // a point on P-256
    return p;
  };
  const std::array<uint8_t, 4> data{1U, 2U, 3U, 4U};
  AtTheEdge(2U, 2U, Error::Ok, none,
            [](HrotBench& t) { return t.facade.Provision<hrot::KeyUse::Sign>(kSlot0).error; });
  AtTheEdge(1U, 1U, Error::Ok, signer,
            [&](HrotBench& t) { return t.facade.GetPublicKey(sign).error; });
  AtTheEdge(2U, 2U, Error::Ok, none,
            [&](HrotBench& t) { return t.facade.ImportPublicKey(kSlot0, peer(t)).error; });
  AtTheEdge(1U, 1U, Error::Ok, signer,
            [&](HrotBench& t) { return t.facade.Sign(sign, digest).error; });
  AtTheEdge(
      1U, 1U, Error::Ok,
      [&](HrotBench& t) {
        if (!signer(t)) {
          return false;
        }
        const auto s = t.facade.Sign(sign, digest);
        sig = s.value;
        return s.ok();
      },
      [&](HrotBench& t) { return t.facade.VerifySignature(sign, digest, sig.View()).error; });
  AtTheEdge(
      1U, 1U, Error::Ok,
      [&](HrotBench& t) {
        const auto k = t.facade.Provision<hrot::KeyUse::Agree>(kSlot0);
        agree = k.value;
        return k.ok();
      },
      [&](HrotBench& t) {
        SecretBuffer<32> shared;
        return t.facade.Agree(agree, peer(t), shared).error;
      },
      testmodel::kSe052Ecdh);
  AtTheEdge(
      1U, 1U, Error::Ok,
      [&](HrotBench& t) {
        return t.facade.Store(kData, ByteSpan{data}, hrot::Protection::Secret).ok();
      },
      [](HrotBench& t) { return t.facade.Erase(kData).error; });
  const auto counter = [](HrotBench& t) { return t.facade.CreateCounter(kCounter, 1U).ok(); };
  AtTheEdge(1U, 1U, Error::Ok, counter,
            [](HrotBench& t) { return t.facade.CounterValue(kCounter).error; });
  AtTheEdge(1U, 1U, Error::Ok, counter,
            [](HrotBench& t) { return t.facade.RaiseCounterTo(kCounter, 9U).error; });
}

TEST_CASE(
    "Guards: a 0x66A6 answer at the edge passes the ceiling by at most the four recovery APDUs") {
  // The recovery after 0x66A6: the select, ReadState and the platform SCP03 handshake (two).
  constexpr uint32_t kRecovery = 4U;
  {
    // Random admitted with one APDU left; the chip refuses it anyway.
    HrotBench t(testmodel::kSe052);
    REQUIRE(t.Open());
    t.facade.SetWindowCount(kThroughputLimitApdus - 1U);
    t.bench.chip.knobs.inject_sw = 0x66A6U;
    t.bench.chip.knobs.inject_count = 1U;
    std::array<uint8_t, 8> out{};
    CHECK_EQ(t.facade.Random(MutableByteSpan{out}).error, Error::ThroughputLimited);
    CHECK_EQ(t.facade.Budget().Used(), kThroughputLimitApdus + kRecovery);
    CHECK_EQ(t.bench.device.State(), DeviceState::Ready);
    // Past the ceiling now: the next call is refused by the facade, nothing sent.
    const uint32_t before = t.Commands();
    CHECK_EQ(t.facade.Random(MutableByteSpan{out}).error, Error::ThroughputLimited);
    CHECK_EQ(t.Commands(), before);
    CHECK_EQ(t.facade.Budget().Used(), kThroughputLimitApdus + kRecovery);
  }
  // Store admitted at exactly its cost (3 + 1 chunk); the marker write gets 0x66A6. No clean-up
  // delete follows the recovery: the count is the existence check, the chunk, the marker and the
  // recovery, and the unfinished object stays (Load refuses it) until Erase.
  const std::array<uint8_t, 4> data{1U, 2U, 3U, 4U};
  HrotBench t(testmodel::kSe052);
  REQUIRE(t.Open());
  t.facade.SetWindowCount(kThroughputLimitApdus - 4U);
  t.bench.chip.knobs.inject_sw = 0x66A6U;
  t.bench.chip.knobs.inject_count = 1U;
  t.bench.chip.knobs.inject_skip = 2U; // existence, chunk; the marker then fails
  CHECK_EQ(t.facade.Store(kData, ByteSpan{data}, hrot::Protection::Secret).error,
           Error::ThroughputLimited);
  CHECK_EQ(t.facade.Budget().Used(), kThroughputLimitApdus - 1U + kRecovery);
  CHECK(t.facade.Budget().Used() <= (kThroughputLimitApdus + kRecovery));
  const auto left = t.bench.device.ObjectExists(kData.Object());
  REQUIRE(left.ok());
  CHECK(left.value);           // not deleted after 0x66A6
  t.facade.SetWindowCount(0U); // a new window
  std::array<uint8_t, 8> out{};
  CHECK_EQ(t.facade.Load(kData, MutableByteSpan{out}, hrot::Protection::Secret).error,
           Error::FrameError);
  CHECK(t.facade.Erase(kData).ok());
}

namespace {

// Points that pass the curve equation only modulo p: x = p (x = 0 on the curve, y = sqrt(b)), and
// y = p + 1 for a point whose y is 1. Only the range checks (coordinates below p) refuse them.
constexpr std::array<uint8_t, 65> kXIsP{
    0x04U, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x66U, 0x48U, 0x5CU, 0x78U, 0x0EU, 0x2FU,
    0x83U, 0xD7U, 0x24U, 0x33U, 0xBDU, 0x5DU, 0x84U, 0xA0U, 0x6BU, 0xB6U, 0x54U, 0x1CU, 0x2AU,
    0xF3U, 0x1DU, 0xAEU, 0x87U, 0x17U, 0x28U, 0xBFU, 0x85U, 0x6AU, 0x17U, 0x4FU, 0x93U, 0xF4U};
constexpr std::array<uint8_t, 65> kYIsOne{
    0x04U, 0x8DU, 0x01U, 0x77U, 0xEBU, 0xABU, 0x9CU, 0x6EU, 0x9EU, 0x10U, 0xDBU, 0x6DU, 0xD0U,
    0x95U, 0xDBU, 0xACU, 0x0DU, 0x63U, 0x75U, 0xE8U, 0xA9U, 0x7BU, 0x70U, 0xF6U, 0x11U, 0x87U,
    0x5DU, 0x87U, 0x7FU, 0x00U, 0x69U, 0xD2U, 0xC7U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U};
constexpr std::array<uint8_t, 65> kYIsPPlusOne{
    0x04U, 0x8DU, 0x01U, 0x77U, 0xEBU, 0xABU, 0x9CU, 0x6EU, 0x9EU, 0x10U, 0xDBU, 0x6DU, 0xD0U,
    0x95U, 0xDBU, 0xACU, 0x0DU, 0x63U, 0x75U, 0xE8U, 0xA9U, 0x7BU, 0x70U, 0xF6U, 0x11U, 0x87U,
    0x5DU, 0x87U, 0x7FU, 0x00U, 0x69U, 0xD2U, 0xC7U, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U,
    0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U};

} // namespace

TEST_CASE(
    "Guards: a coordinate at or above p is refused although it satisfies the equation mod p") {
  CHECK(refcrypto::P256OnCurve(std::span<const uint8_t, 65>{kYIsOne}));
  CHECK(!refcrypto::P256OnCurve(std::span<const uint8_t, 65>{kYIsPPlusOne}));
  CHECK(!refcrypto::P256OnCurve(std::span<const uint8_t, 65>{kXIsP}));
}
