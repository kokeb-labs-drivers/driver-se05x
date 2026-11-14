/**
 * @file test_t1_codec.cpp
 * @brief CRC16, ATR and CIP parsing, and the golden bytes of the first frame of each flavour.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * Vectors: V7 (GPC_SPE_172 Table 4-2, p. 33), V8 (AN13904 pp. 4-5), the CRC-16/X-25 check value of
 * "123456789" (0x906E), and the NXP-flavour byte order of the pinned middleware oracle (least
 * significant byte first). The CIP is synthetic, laid out per GPC_SPE_172 Tables 4-6 to 4-9.
 */
#include <array>
#include <cstddef>
#include <cstdint>

#include "model/t1_fixture.hpp"
#include "se05x_atr.hpp"
#include "se05x_t1_crc.hpp"
#include "se05x_wire.hpp"
#include "test_harness.hpp"

namespace {

using namespace se05x;
using namespace se05x::testmodel;

constexpr std::array<uint8_t, 35> kAtrV8{
    0x01U, 0xA0U, 0x00U, 0x00U, 0x03U, 0x96U, 0x04U, 0x03U, 0xE8U, 0x00U, 0xFEU, 0x02U,
    0x0BU, 0x03U, 0xE8U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x64U, 0x13U, 0x88U,
    0x0AU, 0x00U, 0x65U, 0x53U, 0x45U, 0x30U, 0x35U, 0x31U, 0x00U, 0x00U, 0x00U};

constexpr std::array<uint8_t, 22> kCip{0x01U, 0x04U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U, 0x08U,
                                       0x00U, 0x19U, 0x01U, 0x90U, 0xFFU, 0x0AU, 0x00U, 0x0AU,
                                       0x04U, 0x01U, 0x2CU, 0x00U, 0xFEU, 0x00U};

// Byte offsets of the fields of the two answers above.
constexpr std::size_t kAtrPver = 0U;
constexpr std::size_t kAtrDllpLen = 6U;
constexpr std::size_t kAtrBwt = 7U;
constexpr std::size_t kAtrIfsc = 9U;
constexpr std::size_t kAtrPlid = 11U;
constexpr std::size_t kAtrPlpLen = 12U;
constexpr std::size_t kAtrConfig = 15U;
constexpr std::size_t kAtrMpot = 16U;
constexpr std::size_t kCipIinLen = 1U;
constexpr std::size_t kCipPlid = 6U;
constexpr std::size_t kCipPwt = 9U;
constexpr std::size_t kCipBwt = 17U;
constexpr std::size_t kCipIfsc = 19U;

template <std::size_t N>
Error AtrWith(std::size_t at, uint8_t value) {
  std::array<uint8_t, N> a{};
  for (std::size_t i = 0U; i < N; ++i) {
    a[i] = kAtrV8[i];
  }
  a[at] = value;
  return t1::ParseAtr(a).error;
}

Error CipWith(std::size_t at, uint8_t value) {
  std::array<uint8_t, kCip.size()> c = kCip;
  c[at] = value;
  return t1::ParseCip(c).error;
}

/** @brief A bus that records the first write and NACKs everything else. */
class RecordingBus : public BusInterface<RecordingBus> {
public:
  bool EnsureInitialized() noexcept {
    return true;
  }
  BusStatus Write(uint8_t addr7, ByteSpan data) noexcept {
    static_cast<void>(addr7);
    if ((len == 0U) && (data.size() <= first.size())) {
      for (std::size_t i = 0U; i < data.size(); ++i) {
        first[i] = data[i];
      }
      len = data.size();
    }
    ++writes;
    return BusStatus::Ok;
  }
  BusRead Read(uint8_t addr7, MutableByteSpan out) noexcept {
    static_cast<void>(addr7);
    static_cast<void>(out);
    return BusRead{BusStatus::Nack, 0U};
  }
  std::array<uint8_t, 16> first{};
  std::size_t len{0};
  uint32_t writes{0};
};

/** @brief Record the first frame a link of this flavour writes. */
void FirstFrame(TransportFlavour flavour, RecordingBus& bus) {
  SimClock clock;
  NoCrypto crypto;
  using P = Ports<RecordingBus, SimClock, NoCrypto>;
  const P ports(bus, clock, crypto);
  Config c = WithFlavour(flavour);
  c.atr_poll_budget_ms = 5U;
  t1::Link<P> link(ports, c);
  CHECK(!link.Open().ok());
}

TEST_CASE("Crc16 is CRC-16/X-25: check value, empty string and the GP example V7") {
  // "123456789"
  constexpr std::array<uint8_t, 9> kCheck{0x31U, 0x32U, 0x33U, 0x34U, 0x35U,
                                          0x36U, 0x37U, 0x38U, 0x39U};
  static_assert(t1::Crc16(kCheck).value == 0x906EU);
  CHECK_EQ(t1::Crc16(kCheck).value, 0x906EU);
  CHECK(t1::Crc16(kCheck).ok());
  CHECK_EQ(t1::Crc16(ByteSpan{}).value, 0x0000U);
  CHECK(t1::Crc16(ByteSpan{}).ok());
  // V7: NAD 21, PCB 40, LEN 000E, a 14-byte SELECT; CRC BDA4 (GPC_SPE_172 Table 4-2).
  constexpr std::array<uint8_t, 18> kV7{0x21U, 0x40U, 0x00U, 0x0EU, 0x00U, 0xA4U,
                                        0x04U, 0x00U, 0x08U, 0xA0U, 0x00U, 0x00U,
                                        0x01U, 0x51U, 0x00U, 0x00U, 0x00U, 0x00U};
  CHECK_EQ(t1::Crc16(kV7).value, wire::kGpExampleCrc);
  CHECK_EQ(t1::Crc16(ByteSpan{kV7}.first(17U)).value == wire::kGpExampleCrc, false);
}

TEST_CASE("The model's table CRC and the driver's bit CRC agree on every prefix") {
  SimClock clock;
  const T1Target chip(clock, nullptr, Knobs());
  std::array<uint8_t, 64> data{};
  for (std::size_t i = 0U; i < data.size(); ++i) {
    data[i] = static_cast<uint8_t>((i * 37U) + 11U);
  }
  bool all = true;
  for (std::size_t n = 0U; n <= data.size(); ++n) {
    const ByteSpan s = ByteSpan{data}.first(n);
    all = all && (chip.Crc(s) == t1::Crc16(s).value);
  }
  CHECK(all);
}

TEST_CASE("The first NXP frame is the soft reset, CRC least significant byte first") {
  RecordingBus bus;
  FirstFrame(TransportFlavour::Um11225, bus);
  // 5A CF 00: CRC 0x7F37, sent 37 7F (UM11225 Table 9 code CF; middleware byte order).
  const std::array<uint8_t, 5> expect{0x5AU, 0xCFU, 0x00U, 0x37U, 0x7FU};
  REQUIRE(bus.len == expect.size());
  bool same = true;
  for (std::size_t i = 0U; i < expect.size(); ++i) {
    same = same && (bus.first[i] == expect[i]);
  }
  CHECK(same);
}

TEST_CASE("The first GP frame is S(SWR) with a two-byte LEN and the CRC MSB first") {
  RecordingBus bus;
  FirstFrame(TransportFlavour::Gp, bus);
  // 21 CF 0000: CRC 0x2F6B, sent 2F 6B (GPC_SPE_172 Tables 4-1 and 4-4).
  const std::array<uint8_t, 6> expect{0x21U, 0xCFU, 0x00U, 0x00U, 0x2FU, 0x6BU};
  REQUIRE(bus.len == expect.size());
  bool same = true;
  for (std::size_t i = 0U; i < expect.size(); ++i) {
    same = same && (bus.first[i] == expect[i]);
  }
  CHECK(same);
}

TEST_CASE("Auto tries the NXP flavour first (an SE051 locks onto the first frame's protocol)") {
  RecordingBus bus;
  FirstFrame(TransportFlavour::Auto, bus);
  CHECK_EQ(bus.first[0], 0x5AU);
  CHECK_EQ(bus.len, 5U);
}

TEST_CASE("ParseAtr refuses a BWT above 10 s; 10 s itself is accepted") {
  auto atr = kAtrV8; // BWT at bytes 7 and 8 (UM11225 Table 11)
  atr[7] = 0x27U;
  atr[8] = 0x10U; // 10000 ms
  CHECK(t1::ParseAtr(atr).ok());
  atr[8] = 0x11U; // 10001 ms
  CHECK_EQ(t1::ParseAtr(atr).error, Error::FrameError);
}

TEST_CASE("ParseAtr reads the SE052F ATR of AN13904 (V8)") {
  const auto r = t1::ParseAtr(kAtrV8);
  REQUIRE(r.ok());
  CHECK_EQ(r.value.flavour, TransportFlavour::Um11225);
  CHECK_EQ(r.value.bwt_ms, 1000U);
  CHECK_EQ(r.value.ifsc, 254U);
  CHECK_EQ(r.value.ifsd, 254U);
  CHECK_EQ(r.value.max_scl_khz, 1000U);
  CHECK_EQ(r.value.min_poll_us, 1000U);
  CHECK_EQ(r.value.guard_us, 100U);
  CHECK_EQ(r.value.wakeup_us, 5000U);
  CHECK(!r.value.high_speed);
  CHECK(!r.value.stretching);
  static_assert(t1::ParseAtr(kAtrV8).ok(), "the parser is constexpr");
}

TEST_CASE("ParseAtr: the configuration bit 4 is high-speed mode, MPOT up to 65 ms") {
  CHECK_EQ(AtrWith<35>(kAtrConfig, 0x08U), Error::Ok);
  std::array<uint8_t, 35> a = kAtrV8;
  a[kAtrConfig] = 0x08U;
  CHECK(t1::ParseAtr(a).value.high_speed);
  a[kAtrConfig] = 0x07U; // b1..b3 RFU
  CHECK(!t1::ParseAtr(a).value.high_speed);
  a[kAtrMpot] = 65U;
  CHECK_EQ(t1::ParseAtr(a).value.min_poll_us, 65000U);
  a[kAtrMpot] = 66U;
  CHECK_EQ(t1::ParseAtr(a).error, Error::FrameError);
}

TEST_CASE("ParseAtr refuses every truncation and a trailing byte") {
  bool all = true;
  for (std::size_t n = 0U; n < kAtrV8.size(); ++n) {
    all = all && (t1::ParseAtr(ByteSpan{kAtrV8}.first(n)).error == Error::FrameError);
  }
  CHECK(all);
  std::array<uint8_t, 36> longer{};
  for (std::size_t i = 0U; i < kAtrV8.size(); ++i) {
    longer[i] = kAtrV8[i];
  }
  CHECK_EQ(t1::ParseAtr(longer).error, Error::FrameError);
  CHECK_EQ(t1::ParseAtr(longer).detail.layer, Layer::T1);
}

TEST_CASE("ParseAtr refuses values the link cannot use") {
  CHECK_EQ(AtrWith<35>(kAtrPver, 0U), Error::FrameError);
  CHECK_EQ(AtrWith<35>(kAtrPver, 2U), Error::Ok); // higher versions are compatible (Table 11)
  CHECK_EQ(AtrWith<35>(kAtrPlid, 1U), Error::FrameError);
  CHECK_EQ(AtrWith<35>(kAtrPlid, 3U), Error::FrameError);
  CHECK_EQ(AtrWith<35>(kAtrBwt + 1U, 0U), Error::Ok); // BWT 0x0300
  std::array<uint8_t, 35> a = kAtrV8;
  a[kAtrBwt] = 0U;
  a[kAtrBwt + 1U] = 0U;
  CHECK_EQ(t1::ParseAtr(a).error, Error::FrameError);
  a = kAtrV8;
  a[kAtrIfsc + 1U] = 0U; // IFSC 0
  CHECK_EQ(t1::ParseAtr(a).error, Error::FrameError);
  a[kAtrIfsc + 1U] = 0xFFU; // IFSC 0xFF: above one LEN byte's 0xFE
  CHECK_EQ(t1::ParseAtr(a).error, Error::FrameError);
  a[kAtrIfsc + 1U] = 0x01U;
  CHECK_EQ(t1::ParseAtr(a).value.ifsc, 1U);
  CHECK_EQ(AtrWith<35>(kAtrDllpLen, 3U), Error::FrameError);
  CHECK_EQ(AtrWith<35>(kAtrPlpLen, 10U), Error::FrameError);
}

TEST_CASE("ParseAtr skips extra DLLP and PLP bytes and reads the historical bytes length") {
  // DLLP of 6 bytes and PLP of 12: the extra bytes are ignored (forward compatibility).
  const std::array<uint8_t, 38> a{
      0x01U, 0xA0U, 0x00U, 0x00U, 0x03U, 0x96U, 0x06U, 0x01U, 0x2CU, 0x00U, 0x40U, 0xAAU, 0xBBU,
      0x02U, 0x0CU, 0x01U, 0x90U, 0x08U, 0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x0AU, 0x00U, 0x20U,
      0xCCU, 0x0AU, 0x00U, 0x65U, 0x53U, 0x45U, 0x30U, 0x35U, 0x31U, 0x00U, 0x00U, 0x00U};
  const auto r = t1::ParseAtr(a);
  REQUIRE(r.ok());
  CHECK_EQ(r.value.bwt_ms, 300U);
  CHECK_EQ(r.value.ifsc, 0x40U);
  CHECK_EQ(r.value.max_scl_khz, 400U);
  CHECK(r.value.high_speed);
  CHECK_EQ(r.value.min_poll_us, 2000U);
  CHECK_EQ(r.value.guard_us, 10U);
  CHECK_EQ(r.value.wakeup_us, 32U);
  std::array<uint8_t, 38> b = a;
  b[27] = 0x0BU; // historical bytes claim one more than there is
  CHECK_EQ(t1::ParseAtr(b).error, Error::FrameError);
  b[27] = 0x09U; // one fewer: a byte left over
  CHECK_EQ(t1::ParseAtr(b).error, Error::FrameError);
}

TEST_CASE("ParseCip reads a CIP laid out per GPC_SPE_172") {
  const auto r = t1::ParseCip(kCip);
  REQUIRE(r.ok());
  CHECK_EQ(r.value.flavour, TransportFlavour::Gp);
  CHECK_EQ(r.value.bwt_ms, 300U);
  CHECK_EQ(r.value.ifsc, 254U);
  CHECK_EQ(r.value.ifsd, 64U); // the GP default the chip keeps (section 4.1)
  CHECK_EQ(r.value.max_scl_khz, 400U);
  CHECK_EQ(r.value.min_poll_us, 1000U); // MPOT 10 x 100 us
  CHECK_EQ(r.value.guard_us, 10U);
  CHECK_EQ(r.value.wakeup_us, 25000U);
  static_assert(t1::ParseCip(kCip).ok(), "the parser is constexpr");
}

TEST_CASE("ParseCip refuses truncations, a trailing byte and bad field values") {
  bool all = true;
  for (std::size_t n = 0U; n < kCip.size(); ++n) {
    all = all && (t1::ParseCip(ByteSpan{kCip}.first(n)).error == Error::FrameError);
  }
  CHECK(all);
  std::array<uint8_t, 23> longer{};
  for (std::size_t i = 0U; i < kCip.size(); ++i) {
    longer[i] = kCip[i];
  }
  CHECK_EQ(t1::ParseCip(longer).error, Error::FrameError);
  CHECK_EQ(CipWith(0U, 0U), Error::FrameError);       // PVER 0
  CHECK_EQ(CipWith(kCipPlid, 1U), Error::FrameError); // SPI
  CHECK_EQ(CipWith(kCipPwt, 66U), Error::FrameError); // PWT above 65 ms
  CHECK_EQ(CipWith(kCipPwt, 65U), Error::Ok);
  CHECK_EQ(CipWith(kCipBwt, 0U), Error::Ok); // BWT 0x002C
  std::array<uint8_t, kCip.size()> c = kCip;
  c[kCipBwt + 1U] = 0U;
  c[kCipBwt] = 0U;
  CHECK_EQ(t1::ParseCip(c).error, Error::FrameError);
  c = kCip;
  c[kCipIfsc] = 0x0FU;
  c[kCipIfsc + 1U] = 0xF9U;
  CHECK_EQ(t1::ParseCip(c).value.ifsc, 0x0FF9U);
  c[kCipIfsc + 1U] = 0xFAU;
  CHECK_EQ(t1::ParseCip(c).error, Error::FrameError);
  c[kCipIfsc] = 0U;
  c[kCipIfsc + 1U] = 0U;
  CHECK_EQ(t1::ParseCip(c).error, Error::FrameError);
}

TEST_CASE("ParseCip: IIN of 3 or 4 bytes, at most 32 historical bytes, at most 64 bytes") {
  // IIN of 3 bytes.
  const std::array<uint8_t, 21> iin3{0x01U, 0x03U, 0x00U, 0x00U, 0x00U, 0x02U, 0x08U,
                                     0x00U, 0x19U, 0x01U, 0x90U, 0xFFU, 0x0AU, 0x00U,
                                     0x0AU, 0x04U, 0x01U, 0x2CU, 0x00U, 0xFEU, 0x00U};
  CHECK(t1::ParseCip(iin3).ok());
  CHECK_EQ(CipWith(kCipIinLen, 2U), Error::FrameError);
  CHECK_EQ(CipWith(kCipIinLen, 5U), Error::FrameError);
  // 32 historical bytes: 54 bytes in all; 33: refused.
  std::array<uint8_t, 64> big{};
  for (std::size_t i = 0U; i < 21U; ++i) {
    big[i] = kCip[i];
  }
  big[21] = 32U;
  CHECK(t1::ParseCip(ByteSpan{big}.first(54U)).ok());
  big[21] = 33U;
  CHECK_EQ(t1::ParseCip(ByteSpan{big}.first(55U)).error, Error::FrameError);
  // A PLP of 41 bytes and 10 historical bytes make a well-formed CIP of 65 bytes: one over the
  // limit; with 9 historical bytes it is 64 and accepted.
  std::array<uint8_t, 65> huge{};
  for (std::size_t i = 0U; i < 16U; ++i) {
    huge[i] = kCip[i];
  }
  huge[7] = 41U;
  huge[49] = 0x04U;
  huge[50] = 0x01U;
  huge[51] = 0x2CU;
  huge[52] = 0x00U;
  huge[53] = 0xFEU;
  huge[54] = 0x0AU;
  CHECK_EQ(t1::ParseCip(huge).error, Error::FrameError);
  huge[54] = 0x09U;
  CHECK(t1::ParseCip(ByteSpan{huge}.first(64U)).ok());
  // A well-formed CIP with a 5-byte IIN: refused (3 or 4 bytes, Table 4-6).
  const std::array<uint8_t, 23> iin5{0x01U, 0x05U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U,
                                     0x08U, 0x00U, 0x19U, 0x01U, 0x90U, 0xFFU, 0x0AU, 0x00U,
                                     0x0AU, 0x04U, 0x01U, 0x2CU, 0x00U, 0xFEU, 0x00U};
  CHECK_EQ(t1::ParseCip(iin5).error, Error::FrameError);
}

} // namespace
