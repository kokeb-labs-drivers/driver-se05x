/**
 * @file test_device_recovery.cpp
 * @brief `Device`: the 0x66A6 ladder (S-17), lost frames with and without a session, `Recover()`,
 * the self test that resets the chip, deep power-down, power cycle, the card manager route, raw
 * access and the transaction mark.
 */
#include <array>
#include <cstddef>
#include <cstdint>

#include "model/chip_bench.hpp"
#include "model/t1_fixture.hpp"
#include "test_harness.hpp"

using namespace se05x;
using testmodel::ChipBench;
using testmodel::ChipPlainBench;

namespace {

constexpr ObjectId kKey{0x00001001U};

testmodel::T1Knobs Throttle(uint32_t after) {
  testmodel::T1Knobs k{};
  k.base.throttle_enabled = true;
  k.base.throttle_after = after;
  return k;
}

Config RequireScp() {
  Config c{};
  c.scp_policy = ScpPolicy::Require;
  return c;
}

Error Random(ChipBench& b) {
  std::array<uint8_t, 8> out{};
  return b.device.GetRandom(MutableByteSpan{out}).error;
}

} // namespace

TEST_CASE("Recovery: SW 0x66A6 resets the chip once, reselects, drops the session, no repeat") {
  ChipBench b(testmodel::kSe052, Throttle(9U));
  REQUIRE(b.device.Open().ok());
  REQUIRE(b.device.BeginUserIdSession(ChipBench::UserParams()).ok());
  const uint32_t resets = b.t1.chip_resets;
  Error e = Error::Ok;
  for (uint32_t i = 0U; (i < 10U) && (e == Error::Ok); ++i) {
    e = Random(b);
  }
  CHECK_EQ(e, Error::ThroughputLimited);
  CHECK_EQ(b.device.GetLastDetail().sw, 0x66A6U);
  CHECK_EQ(b.t1.chip_resets, resets + 1U); // the NXP chip reset S-block, once
  CHECK_EQ(b.t1.throttled, 1U);            // no CloseSession was sent to the throttled chip (APP.2)
  CHECK_EQ(b.device.State(), DeviceState::Ready);
  CHECK_EQ(b.device.Session(), SessionKind::None);
  CHECK_EQ(b.device.Role(), AuthRole::None);
  CHECK(Random(b) == Error::Ok); // the budget starts again after the reset
}

TEST_CASE("Recovery: in the GP flavour the 0x66A6 reset goes through the reset port") {
  testmodel::T1Knobs k = Throttle(8U);
  k.base.gp_flavour = true;
  ChipBench b(testmodel::kSe052, k);
  REQUIRE(b.device.Open().ok());
  Error e = Error::Ok;
  for (uint32_t i = 0U; (i < 10U) && (e == Error::Ok); ++i) {
    e = Random(b);
  }
  CHECK_EQ(e, Error::ThroughputLimited);
  CHECK_EQ(b.t1.chip_resets, 0U);
  CHECK((b.reset.resets + b.reset.cycles) >= 1U);
  CHECK_EQ(b.device.State(), DeviceState::Ready);
}

TEST_CASE("Recovery: 0x66A6 to the select after the reset leaves NeedsReopen, no second reset") {
  ChipBench b(testmodel::kSe052, Throttle(8U));
  REQUIRE(b.device.Open().ok());
  b.t1.Knobs().base.throttle_after = 0U; // even the first command after the reset is refused
  Error e = Error::Ok;
  for (uint32_t i = 0U; (i < 10U) && (e == Error::Ok); ++i) {
    e = Random(b);
  }
  CHECK_EQ(e, Error::ThroughputLimited);
  CHECK_EQ(b.t1.chip_resets, 1U);
  CHECK_EQ(b.device.State(), DeviceState::NeedsReopen);
  const uint32_t writes = b.t1.writes;
  CHECK_EQ(Random(b), Error::NeedsReselect); // nothing sent until Recover()
  CHECK_EQ(b.t1.writes, writes);
}

TEST_CASE("Recovery: under platform SCP03 the 0x66A6 ladder opens platform SCP03 again") {
  ChipBench b(testmodel::kSe052, Throttle(12U), RequireScp());
  REQUIRE(b.GivePlatformKeys());
  REQUIRE(b.device.Open().ok());
  Error e = Error::Ok;
  for (uint32_t i = 0U; (i < 12U) && (e == Error::Ok); ++i) {
    e = Random(b);
  }
  CHECK_EQ(e, Error::ThroughputLimited);
  CHECK(b.scp.platform_open);
  CHECK(b.device.GetCapabilities().platform_scp_active);
  CHECK(Random(b) == Error::Ok);
}

TEST_CASE("Recovery: a lost answer without a session keeps Ready; the link resyncs next time") {
  ChipBench b(testmodel::kSe050E);
  REQUIRE(b.device.Open().ok());
  testmodel::DropFromNow(b.t1, 2U); // the answer and its resend: Timeout
  CHECK_EQ(Random(b), Error::Timeout);
  CHECK_EQ(b.device.State(), DeviceState::Ready);
  CHECK(Random(b) == Error::Ok); // the link resynchronised first
  CHECK(b.device.GetLink().GetCounters().resyncs >= 1U);
}

TEST_CASE("Recovery: a lost answer in a session ends the stack; Recover selects again") {
  ChipBench b(testmodel::kSe050E);
  REQUIRE(b.device.Open().ok());
  REQUIRE(b.device.BeginAesKeySession(b.AesParams()).ok());
  testmodel::DropFromNow(b.t1, 8U);
  CHECK(Random(b) != Error::Ok);
  CHECK_EQ(b.device.State(), DeviceState::NeedsReopen);
  CHECK_EQ(b.device.Session(), SessionKind::None);
  CHECK(!b.device.SecureMessagingActive()); // session keys released (S-07)
  CHECK_EQ(Random(b), Error::NeedsReselect);
  const uint32_t selects = b.chip.selects;
  REQUIRE(b.device.Recover().ok());
  CHECK_EQ(b.chip.selects, selects + 1U);
  CHECK_EQ(b.device.State(), DeviceState::Ready);
  CHECK(Random(b) == Error::Ok);
}

TEST_CASE("Recovery: platform SCP03 lost is never replaced by the plain link") {
  ChipBench b(testmodel::kSe050E, testmodel::T1Knobs{}, RequireScp());
  REQUIRE(b.GivePlatformKeys());
  REQUIRE(b.device.Open().ok());
  testmodel::DropFromNow(b.t1, 8U);
  CHECK(Random(b) != Error::Ok);
  CHECK_EQ(b.device.State(), DeviceState::NeedsReopen);
  REQUIRE(b.device.Recover().ok());
  CHECK(b.scp.platform_open);
  const uint32_t ctr = b.scp.platform_ctr;
  CHECK(Random(b) == Error::Ok);
  CHECK(b.scp.platform_ctr > ctr);
}

TEST_CASE("Recovery: an applet that answers another version after the reset is DeviceIdMismatch") {
  ChipBench b(testmodel::kSe050E);
  REQUIRE(b.device.Open().ok());
  b.chip.knobs.version_patch_after_reset = 3U;
  b.t1.PowerCycleChip(); // another applet build behind the device's back
  const auto r = b.device.Recover();
  CHECK_EQ(r.error, Error::DeviceIdMismatch);
  CHECK_EQ(b.device.State(), DeviceState::NeedsReopen);
  CHECK_EQ(Random(b), Error::NeedsReselect);
  REQUIRE(b.device.Close().ok());
  REQUIRE(b.device.Open().ok()); // a fresh open accepts the new version
  CHECK_EQ(b.device.GetCapabilities().applet.patch, 3U);
}

TEST_CASE("Recovery: a dead link is TransportDead; Recover cannot help, Close and Open can") {
  ChipBench b(testmodel::kSe050E);
  REQUIRE(b.device.Open().ok());
  b.reset.reset_ok = false;
  testmodel::Silence(b.t1);
  CHECK_EQ(Random(b), Error::Timeout); // the first loss: the link resynchronises next time
  CHECK_EQ(b.device.State(), DeviceState::Ready);
  CHECK_EQ(Random(b), Error::TransportDead); // nothing answers: the ladder is exhausted
  CHECK_EQ(b.device.State(), DeviceState::Dead);
  CHECK(!b.device.IsOpen());
  const uint32_t writes = b.t1.writes;
  CHECK_EQ(Random(b), Error::TransportDead);
  CHECK_EQ(b.device.Recover().error, Error::TransportDead);
  CHECK_EQ(b.t1.writes, writes);
  static_cast<void>(b.device.Close()); // the end-of-session S-block is still sent (RD-05)
  CHECK(b.t1.writes > writes);
  CHECK_EQ(b.device.State(), DeviceState::Closed);
}

TEST_CASE("Recovery: a self test that resets the chip is Resynced and the device is Ready") {
  ChipBench b(testmodel::kSe050E);
  REQUIRE(b.device.Open().ok());
  const auto ok = b.device.TriggerSelfTest(0xFE01U, irreversible::ResetExpected{});
  REQUIRE(ok.ok());
  CHECK(ok.value);
  b.chip.knobs.selftest_fails = true;
  const auto failed = b.device.TriggerSelfTest(0xFE01U, irreversible::ResetExpected{});
  REQUIRE(failed.ok());
  CHECK(!failed.value);
  b.chip.knobs.selftest_silent = true;
  const auto silent = b.device.TriggerSelfTest(0xFE01U, irreversible::ResetExpected{});
  CHECK_EQ(silent.error, Error::Resynced);
  CHECK_EQ(b.device.State(), DeviceState::Ready);
  b.chip.knobs.selftest_silent = false;
  CHECK(Random(b) == Error::Ok);
}

TEST_CASE("Recovery: deep power-down drops everything; the next Open wakes the chip") {
  ChipBench b(testmodel::kSe050E);
  b.t1.has_ena = true;
  REQUIRE(b.device.Open().ok());
  REQUIRE(b.device.BeginUserIdSession(ChipBench::UserParams()).ok());
  REQUIRE(b.device.DeepPowerDown().ok());
  CHECK_EQ(b.device.State(), DeviceState::Closed);
  CHECK_EQ(b.device.Session(), SessionKind::None);
  CHECK_EQ(Random(b), Error::NotInitialized);
  REQUIRE(b.device.Open().ok());
  CHECK(Random(b) == Error::Ok);
}

TEST_CASE("Recovery: PowerCycle from Ready and from Closed brings the device up") {
  ChipBench b(testmodel::kSe050E);
  REQUIRE(b.device.Open().ok());
  REQUIRE(b.device.PowerCycle().ok());
  CHECK_EQ(b.device.State(), DeviceState::Ready);
  CHECK(b.reset.cycles >= 1U);
  REQUIRE(b.device.Close().ok());
  REQUIRE(b.device.PowerCycle().ok());
  CHECK(Random(b) == Error::Ok);
  b.reset.reset_ok = false;
  REQUIRE(b.device.Close().ok());
  CHECK_EQ(b.device.PowerCycle().error, Error::Bus);
}

TEST_CASE("Recovery: the card identification goes to the card manager and back to the applet") {
  ChipBench b(testmodel::kSe050E);
  REQUIRE(b.device.Open().ok());
  const uint32_t selects = b.chip.selects;
  const auto id = b.device.Execute<Command::GetCardIdentification>(Empty{});
  REQUIRE(id.ok());
  CHECK_EQ(id.value.oef_id, 0xA921U);
  CHECK_EQ(b.chip.selects, selects + 1U);
  CHECK(Random(b) == Error::Ok);
  REQUIRE(b.device.BeginUserIdSession(ChipBench::UserParams()).ok());
  CHECK_EQ(b.device.Execute<Command::GetCardIdentification>(Empty{}).error, Error::WrongState);
}

TEST_CASE("Recovery: ReadRaw is lab only and never sends a select or an irreversible command") {
  ChipBench closed;
  REQUIRE(closed.device.Open().ok());
  std::array<uint8_t, 64> rsp{};
  const std::array<uint8_t, 9> random{0x80U, 0x04U, 0x00U, 0x49U, 0x04U,
                                      0x41U, 0x02U, 0x00U, 0x08U};
  CHECK_EQ(closed.device.ReadRaw(ByteSpan{random}, MutableByteSpan{rsp}).error, Error::Unsupported);
  Config c{};
  c.allow_lab_override = true;
  ChipBench b(testmodel::kSe050E, testmodel::T1Knobs{}, c);
  REQUIRE(b.device.Open().ok());
  const auto r = b.device.ReadRaw(ByteSpan{random}, MutableByteSpan{rsp});
  REQUIRE(r.ok());
  CHECK_EQ(r.value, 2U + 2U + 8U);
  CHECK_EQ(rsp[r.value - 2U], 0x90U);
  const std::array<uint8_t, 5> delete_all{0x80U, 0x04U, 0x00U, 0x2AU, 0x00U};
  const std::array<uint8_t, 5> select{0x00U, 0xA4U, 0x04U, 0x00U, 0x00U};
  const uint32_t writes = b.t1.writes;
  CHECK_EQ(b.device.ReadRaw(ByteSpan{delete_all}, MutableByteSpan{rsp}).error, Error::Unsupported);
  CHECK_EQ(b.device.ReadRaw(ByteSpan{select}, MutableByteSpan{rsp}).error, Error::Unsupported);
  CHECK_EQ(b.t1.writes, writes);
  const std::array<uint8_t, 7> missing{0x80U, 0x04U, 0x00U, 0x28U, 0x02U, 0x41U, 0x00U};
  const auto sw = b.device.ReadRaw(ByteSpan{missing}, MutableByteSpan{rsp});
  REQUIRE(sw.ok()); // the chip's answer is returned as it is
  CHECK_EQ(sw.value, 2U);
}

TEST_CASE("Recovery: the transaction mark is single and End is never refused") {
  ChipBench b(testmodel::kSe050E);
  REQUIRE(b.device.Open().ok());
  REQUIRE(b.device.BeginTransaction().ok());
  CHECK_EQ(b.device.BeginTransaction().error, Error::Busy);
  CHECK(b.device.EndTransaction().ok());
  CHECK(b.device.EndTransaction().ok());
  CHECK(b.device.BeginTransaction().ok());
}

TEST_CASE("Recovery: the lifecycle state read at Open gates commands while locked") {
  ChipBench b(testmodel::kSe050E);
  b.chip.knobs.persistent_lock = true;
  REQUIRE(b.device.Open().ok());
  CHECK(b.device.GetCapabilities().applet_locked);
  const uint32_t before = b.chip.commands;
  const Policy p = testmodel::SignPolicy<AppletGeneration::V7>();
  CHECK_EQ(b.device.GenerateEcKey(kKey, p, EcCurve::NistP256).error, Error::WrongState);
  CHECK_EQ(b.chip.commands, before);
  CHECK(Random(b) == Error::Ok); // GetRandom is allowed while locked (AN12543 Table 19)
}

TEST_CASE("Recovery: a plain bus without a reset port climbs to the chip reset S-block") {
  testmodel::T1Knobs k = Throttle(8U);
  ChipPlainBench b(testmodel::kSe052, k);
  REQUIRE(b.device.Open().ok());
  Error e = Error::Ok;
  std::array<uint8_t, 8> out{};
  for (uint32_t i = 0U; (i < 10U) && (e == Error::Ok); ++i) {
    e = b.device.GetRandom(MutableByteSpan{out}).error;
  }
  CHECK_EQ(e, Error::ThroughputLimited);
  CHECK_EQ(b.t1.chip_resets, 1U);
  CHECK_EQ(b.device.State(), DeviceState::Ready);
}
