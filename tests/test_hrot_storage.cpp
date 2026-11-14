/**
 * @file test_hrot_storage.cpp
 * @brief The facade: stored data and certificates (chunked writes and reads), monotonic counters
 * and the anti-rollback floor, random numbers, the APDU budget (S-17) and the transaction scope,
 * against the chip model.
 */
#include <array>
#include <cstddef>
#include <cstdint>

#include "hrot_bench.hpp"
#include "test_harness.hpp"

using namespace se05x;
using testmodel::HrotBench;

namespace {

constexpr hrot::DataSlot kData = hrot::DataSlot::At<0>();
constexpr hrot::CertSlot kCert = hrot::CertSlot::At<0>();
constexpr hrot::CounterSlot kCounter = hrot::CounterSlot::At<0>();

// The budget's ceiling is inclusive: one million APDUs may be sent, not one more (AN14028 2.3.1).
constexpr hrot::ApduBudget AtUsed(uint32_t used) noexcept {
  hrot::ApduBudget b{};
  b.applies = true;
  b.issued_by_device = used;
  return b;
}
static_assert(AtUsed(kThroughputLimitApdus - 1U).Allows(1U));
static_assert(!AtUsed(kThroughputLimitApdus - 1U).Allows(2U));
static_assert(AtUsed(kThroughputLimitApdus).Allows(0U));
static_assert(!AtUsed(kThroughputLimitApdus).Allows(1U));
static_assert(!AtUsed(kThroughputLimitApdus + 1U).Allows(0U));
static_assert(hrot::ApduBudget{}.Allows(0xFFFFFFFFU)); // the limit does not apply

} // namespace

TEST_CASE("Storage: secret data round trip in chunks; an occupied slot is not overwritten") {
  HrotBench t;
  REQUIRE(t.Open());
  std::array<uint8_t, 700> data{};
  for (std::size_t i = 0U; i < data.size(); ++i) {
    data[i] = static_cast<uint8_t>(i * 7U);
  }
  const uint32_t before = t.Commands();
  REQUIRE(t.facade.Store(kData, ByteSpan{data}, hrot::Protection::Secret).ok());
  CHECK_EQ(t.Commands(), before + 5U); // existence, three 256-byte chunks, the completion marker
  std::array<uint8_t, 700> back{};
  const auto n = t.facade.Load(kData, MutableByteSpan{back}, hrot::Protection::Secret);
  REQUIRE(n.ok());
  CHECK_EQ(n.value, 700U);
  CHECK(ct::Equal(ByteSpan{back}, ByteSpan{data}));
  CHECK_EQ(t.facade.Store(kData, ByteSpan{data}.first(10U), hrot::Protection::Secret).error,
           Error::ObjectExists);
  std::array<uint8_t, 699> small{};
  CHECK_EQ(t.facade.Load(kData, MutableByteSpan{small}, hrot::Protection::Secret).error,
           Error::BufferTooSmall);
  REQUIRE(t.facade.Erase(kData).ok());
  CHECK_EQ(t.facade.Load(kData, MutableByteSpan{back}, hrot::Protection::Secret).error,
           Error::ObjectNotFound);
  CHECK(t.facade.Store(kData, ByteSpan{data}.first(10U), hrot::Protection::Secret).ok());
}

TEST_CASE("Storage: exactly one chunk, and the size limits") {
  HrotBench t;
  REQUIRE(t.Open());
  std::array<uint8_t, hrot::kChunkBytes> one{};
  one[hrot::kChunkBytes - 1U] = 0x5AU;
  const uint32_t before = t.Commands();
  REQUIRE(t.facade.Store(kData, ByteSpan{one}, hrot::Protection::Public).ok());
  CHECK_EQ(t.Commands(), before + 3U); // existence, one chunk, the completion marker
  std::array<uint8_t, hrot::kChunkBytes> back{};
  REQUIRE(t.facade.Load(kData, MutableByteSpan{back}, hrot::Protection::Public).ok());
  CHECK_EQ(back[hrot::kChunkBytes - 1U], 0x5AU);
  static std::array<uint8_t, hrot::kMaxStoredBytes + 1U> big{};
  const uint32_t at = t.Commands();
  CHECK_EQ(t.facade.Store(hrot::DataSlot::At<1>(), ByteSpan{big}, hrot::Protection::Public).error,
           Error::InvalidArgument);
  CHECK_EQ(t.facade.Store(hrot::DataSlot::At<1>(), ByteSpan{}, hrot::Protection::Public).error,
           Error::InvalidArgument);
  CHECK_EQ(t.Commands(), at);
  CHECK(t.facade
            .Store(hrot::DataSlot::At<1>(), ByteSpan{big}.first(hrot::kMaxStoredBytes),
                   hrot::Protection::Public)
            .ok());
}

TEST_CASE("Storage: certificates are stored and read as bytes, without secure messaging") {
  HrotBench t(testmodel::kSe050E, false);
  REQUIRE(t.Open());
  std::array<uint8_t, 300> der{};
  der[0] = 0x30U;
  der[299] = 0xEEU;
  REQUIRE(t.facade.StoreCertificate(kCert, ByteSpan{der}).ok());
  std::array<uint8_t, 512> back{};
  const auto n = t.facade.LoadCertificate(kCert, MutableByteSpan{back});
  REQUIRE(n.ok());
  CHECK_EQ(n.value, 300U);
  CHECK_EQ(back[299], 0xEEU);
  CHECK(!t.bench.chip.Has(kData.Object().value)); // another kind, another id
  REQUIRE(t.facade.EraseCertificate(kCert).ok());
  CHECK(!t.bench.chip.Has(kCert.Object().value));
}

TEST_CASE("Counters: create, increment, raise in one APDU, never lower") {
  HrotBench t;
  REQUIRE(t.Open());
  REQUIRE(t.facade.CreateCounter(kCounter, 5U).ok());
  CHECK_EQ(t.facade.CounterValue(kCounter).value, 5U);
  const auto inc = t.facade.CounterIncrement(kCounter);
  REQUIRE(inc.ok());
  CHECK_EQ(inc.value, 6U);
  CHECK_EQ(t.bench.chip.CounterValue(kCounter.Object().value), 6U);
  const uint32_t before = t.Commands();
  REQUIRE(t.facade.RaiseCounterTo(kCounter, 1000U).ok());
  CHECK_EQ(t.Commands(), before + 1U);
  CHECK_EQ(t.facade.CounterValue(kCounter).value, 1000U);
  CHECK(!t.facade.RaiseCounterTo(kCounter, 999U).ok());
  CHECK_EQ(t.facade.CounterValue(kCounter).value, 1000U);
  CHECK_EQ(t.facade.CreateCounter(kCounter, 0U).error, Error::ObjectExists);
  REQUIRE(t.facade.CreateCounter(hrot::CounterSlot::At<1>(), 0U).ok());
  CHECK_EQ(t.facade.CounterValue(hrot::CounterSlot::At<1>()).value, 0U);
}

TEST_CASE("Counters: a version at or above the floor passes, one below it fails closed") {
  HrotBench t;
  REQUIRE(t.Open());
  REQUIRE(t.facade.CreateCounter(kCounter, 7U).ok());
  CHECK(t.facade.CheckFloor(kCounter, 8U).ok());
  CHECK(t.facade.CheckFloor(kCounter, 7U).ok());
  const auto below = t.facade.CheckFloor(kCounter, 6U);
  CHECK_EQ(below.error, Error::PolicyDenied);
  CHECK_EQ(below.detail.layer, Layer::Hrot);
  CHECK_EQ(t.facade.CheckFloor(hrot::CounterSlot::At<9>(), 0U).error, Error::ObjectNotFound);
}

TEST_CASE("Random: chunks of 512 bytes, and the size limits") {
  HrotBench t;
  REQUIRE(t.Open());
  static std::array<uint8_t, 1025> out{};
  const uint32_t before = t.Commands();
  REQUIRE(t.facade.Random(MutableByteSpan{out}.first(1024U)).ok());
  CHECK_EQ(t.Commands(), before + 2U);
  bool nonzero = false;
  for (std::size_t i = 512U; i < 1024U; ++i) {
    nonzero = nonzero || (out[i] != 0U);
  }
  CHECK(nonzero);
  CHECK_EQ(t.facade.Random(MutableByteSpan{out}).error, Error::InvalidArgument);
  CHECK_EQ(t.facade.Random(MutableByteSpan{}).error, Error::InvalidArgument);
  CHECK_EQ(t.Commands(), before + 2U);
}

TEST_CASE("Budget: counts every APDU; the limit applies on the SE052F only") {
  HrotBench a;
  REQUIRE(a.Open());
  CHECK(!a.facade.Budget().applies);
  HrotBench t(testmodel::kSe052);
  REQUIRE(t.Open());
  const hrot::ApduBudget b = t.facade.Budget();
  CHECK(b.applies);
  CHECK_EQ(b.issued_by_device, t.bench.device.ApduCount());
  CHECK(b.issued_by_device > 0U);
  CHECK(!b.persistent_counter_known);
  CHECK_EQ(b.limit, kThroughputLimitApdus);
  CHECK_EQ(b.window_days, kThroughputWindowDays);
}

TEST_CASE("Budget: a call past the window's ceiling is refused before anything is sent") {
  HrotBench t(testmodel::kSe052);
  REQUIRE(t.Open());
  t.facade.SetWindowCount(kThroughputLimitApdus - 1U);
  CHECK(t.facade.Budget().persistent_counter_known);
  CHECK_EQ(t.facade.Budget().Used(), kThroughputLimitApdus - 1U);
  std::array<uint8_t, 8> rnd{};
  REQUIRE(t.facade.Random(MutableByteSpan{rnd}).ok()); // the last APDU of the window
  const uint32_t before = t.Commands();
  const auto refused = t.facade.Random(MutableByteSpan{rnd});
  CHECK_EQ(refused.error, Error::ThroughputLimited);
  CHECK_EQ(refused.detail.layer, Layer::Hrot);
  CHECK_EQ(t.facade.Identify().error, Error::ThroughputLimited);
  CHECK_EQ(t.Commands(), before);
  CHECK_EQ(t.bench.device.State(), DeviceState::Ready); // no reset: nothing reached the chip
}

TEST_CASE("Budget: a multi-APDU call is refused whole, not cut short") {
  HrotBench t(testmodel::kSe052);
  REQUIRE(t.Open());
  t.facade.SetWindowCount(kThroughputLimitApdus - 3U);
  std::array<uint8_t, 600> data{};
  const uint32_t before = t.Commands();
  CHECK_EQ(t.facade.Store(kData, ByteSpan{data}, hrot::Protection::Public).error,
           Error::ThroughputLimited); // 3 + 3 APDUs (600 bytes round up to 3 chunks), 3 left
  CHECK_EQ(t.Commands(), before);
  CHECK(!t.bench.chip.Has(kData.Object().value));
  t.facade.SetWindowCount(kThroughputLimitApdus - 4U);
  CHECK(t.facade.Store(kData, ByteSpan{data}.first(100U), hrot::Protection::Public).ok());
}

TEST_CASE("Budget: the window count saturates instead of wrapping") {
  HrotBench t(testmodel::kSe052);
  REQUIRE(t.Open());
  t.facade.SetWindowCount(0xFFFFFFF0U);
  std::array<uint8_t, 8> rnd{};
  CHECK_EQ(t.facade.Random(MutableByteSpan{rnd}).error, Error::ThroughputLimited);
  t.facade.SetWindowCount(0U);
  CHECK(t.facade.Random(MutableByteSpan{rnd}).ok());
}

TEST_CASE("Transaction: one scope at a time, released on destruction") {
  HrotBench t;
  REQUIRE(t.Open());
  {
    const hrot::Transaction<testmodel::BenchPorts> scope(t.bench.device);
    CHECK_EQ(scope.Status(), Error::Ok);
    const hrot::Transaction<testmodel::BenchPorts> second(t.bench.device);
    CHECK_EQ(second.Status(), Error::Busy);
  }
  const hrot::Transaction<testmodel::BenchPorts> again(t.bench.device);
  CHECK_EQ(again.Status(), Error::Ok);
}
