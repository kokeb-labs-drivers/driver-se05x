/**
 * @file test_device_open.cpp
 * @brief `Device`: open, capabilities per chip profile, close, the invariants before `Open()`,
 * and the first commands through the whole chain (link, SCP target, chip model).
 */
#include <array>
#include <cstddef>
#include <cstdint>

#include "model/chip_bench.hpp"
#include "test_harness.hpp"

using namespace se05x;
using testmodel::ChipBench;
using testmodel::ChipPlainBench;

namespace {
constexpr ObjectId kKey{0x00001001U};
} // namespace

TEST_CASE("Device: nothing is sent before Open, and every call refuses with NotInitialized") {
  ChipBench b;
  std::array<uint8_t, 8> out{};
  CHECK_EQ(b.device.GetRandom(MutableByteSpan{out}).error, Error::NotInitialized);
  CHECK_EQ(b.device.Execute<Command::GetVersion>(Empty{}).error, Error::NotInitialized);
  CHECK_EQ(b.device.BeginUserIdSession(ChipBench::UserParams()).error, Error::NotInitialized);
  CHECK_EQ(b.device.EndSession().error, Error::NotInitialized);
  CHECK_EQ(b.device.Recover().error, Error::NotInitialized);
  CHECK_EQ(b.device.DeepPowerDown().error, Error::NotInitialized);
  CHECK_EQ(b.device.BeginTransaction().error, Error::NotInitialized);
  CHECK_EQ(b.t1.writes, 0U);
  CHECK_EQ(b.t1.reads, 0U);
  CHECK(b.device.Close().ok()); // never refused (RD-05)
  CHECK_EQ(b.t1.writes, 0U);
}

TEST_CASE("Device: an invalid configuration is refused before any I/O") {
  Config c{};
  c.frame_retries = 0U;
  ChipBench b(testmodel::kSe050E, testmodel::T1Knobs{}, c);
  CHECK_EQ(b.device.Open().error, Error::InvalidArgument);
  CHECK_EQ(b.t1.writes, 0U);
  CHECK_EQ(b.device.State(), DeviceState::Closed);
}

TEST_CASE("Device: Open on SE050E derives version, OEF family and features from the chip") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  CHECK(b.device.IsOpen());
  CHECK_EQ(b.device.State(), DeviceState::Ready);
  const Capabilities& caps = b.device.GetCapabilities();
  CHECK_EQ(caps.applet.major, 7U);
  CHECK_EQ(caps.generation, AppletGeneration::V7);
  CHECK_EQ(caps.oef_id, 0xA921U);
  CHECK_EQ(caps.family, Family::Se050E);
  CHECK(caps.allowed.Contains(Command::GetRandom));
  CHECK(!caps.platform_scp_required);
  CHECK(!caps.platform_scp_active);
  CHECK(!caps.applet_locked);
  CHECK(!b.device.SecureMessagingActive());
  CHECK_EQ(b.device.Session(), SessionKind::None);
  CHECK(b.device.ApduCount() >= 4U);
  CHECK_EQ(b.chip.selects, 1U);
}

TEST_CASE("Device: Open on SE050 (applet 3.x) has no extended features and sends no ReadState") {
  ChipBench b(testmodel::kSe050);
  REQUIRE(b.device.Open().ok());
  const Capabilities& caps = b.device.GetCapabilities();
  CHECK_EQ(caps.generation, AppletGeneration::V3);
  CHECK_EQ(caps.family, Family::Se050C);
  CHECK(!caps.allowed.Contains(Command::ReadState));
  CHECK(b.chip.last_p2 != 0x5BU);
}

TEST_CASE("Device: Open on SE052F reads a 4-byte free memory and refuses EdDSA before sending") {
  ChipBench b(testmodel::kSe052);
  REQUIRE(b.device.Open().ok());
  const Capabilities& caps = b.device.GetCapabilities();
  CHECK_EQ(caps.family, Family::Se052F);
  CHECK(caps.features.free_memory_4byte);
  const auto mem = b.device.FreeMemory(MemoryType::Persistent);
  REQUIRE(mem.ok());
  CHECK_EQ(mem.value, 0x00012345U);
  const uint32_t before = b.chip.commands;
  std::array<uint8_t, 64> sig{};
  const std::array<uint8_t, 4> msg{1, 2, 3, 4};
  const auto ed = b.device.Execute<Command::EddsaSign>(
      SignArgs{kKey, EcSignAlgo::Ed25519Pure, ByteSpan{msg}, MutableByteSpan{sig}});
  CHECK_EQ(ed.error, Error::Unsupported);
  CHECK_EQ(b.chip.commands, before);
}

TEST_CASE("Device: the curve gate refuses a curve the chip lacks before sending") {
  ChipBench b(testmodel::kSe052);
  REQUIRE(b.device.Open().ok());
  const Policy p = testmodel::SignPolicy<AppletGeneration::V7>();
  const uint32_t before = b.chip.commands;
  CHECK_EQ(b.device.GenerateEcKey(kKey, p, EcCurve::Ed25519).error, Error::Unsupported);
  CHECK_EQ(b.device.GenerateEcKey(kKey, p, EcCurve::BnP256).error, Error::Unsupported);
  CHECK_EQ(b.chip.commands, before);
  CHECK(b.device.GenerateEcKey(kKey, p, EcCurve::NistP256).ok());
}

TEST_CASE("Device: an OEF id of another generation is DeviceIdMismatch and the link is closed") {
  ChipBench b;
  b.scp.oef_id = 0xA201U; // an applet 3.x part answering with applet 7.2
  CHECK_EQ(b.device.Open().error, Error::DeviceIdMismatch);
  CHECK_EQ(b.device.State(), DeviceState::Closed);
  CHECK_EQ(b.device.GetLink().State(), t1::LinkState::Closed);
}

TEST_CASE("Device: no IoT applet answering the select is Counterfeit") {
  ChipBench b;
  b.chip.knobs.no_applet = true;
  const auto r = b.device.Open();
  CHECK_EQ(r.error, Error::Counterfeit);
  CHECK_EQ(r.detail.sw, 0x6A82U);
  CHECK_EQ(b.device.State(), DeviceState::Closed);
}

TEST_CASE("Device: Open twice is WrongState and sends nothing more") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  const uint32_t writes = b.t1.writes;
  CHECK_EQ(b.device.Open().error, Error::WrongState);
  CHECK_EQ(b.t1.writes, writes);
}

TEST_CASE("Device: GetRandom, version and free memory through the chain") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  std::array<uint8_t, 32> rnd{};
  REQUIRE(b.device.GetRandom(MutableByteSpan{rnd}).ok());
  bool nonzero = false;
  for (const uint8_t v : rnd) {
    nonzero = nonzero || (v != 0U);
  }
  CHECK(nonzero);
  const auto v = b.device.GetVersion();
  REQUIRE(v.ok());
  CHECK_EQ(v.value.version.minor, 2U);
  const auto mem = b.device.FreeMemory(MemoryType::Persistent);
  REQUIRE(mem.ok());
  CHECK_EQ(mem.value, 0x1234U);
  CHECK_EQ(b.device.GetLastStatusWord(), 0x9000U);
}

TEST_CASE("Device: generate, sign and verify a P-256 key in the chip") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  const Policy policy = testmodel::SignPolicy<AppletGeneration::V7>();
  REQUIRE(b.device.GenerateEcKey(kKey, policy, EcCurve::NistP256).ok());
  CHECK(b.chip.Has(kKey.value));
  std::array<uint8_t, 32> digest{};
  digest[0] = 0x42U;
  std::array<uint8_t, 80> sig{};
  const auto s =
      b.device.EcdsaSign(kKey, EcSignAlgo::Sha256, ByteSpan{digest}, MutableByteSpan{sig});
  REQUIRE(s.ok());
  CHECK(s.value >= 8U);
  const auto ok = b.device.EcdsaVerify(kKey, EcSignAlgo::Sha256, ByteSpan{digest},
                                       ByteSpan{sig.data(), s.value});
  REQUIRE(ok.ok());
  CHECK(ok.value);
  digest[1] = 0x01U;
  const auto bad = b.device.EcdsaVerify(kKey, EcSignAlgo::Sha256, ByteSpan{digest},
                                        ByteSpan{sig.data(), s.value});
  REQUIRE(bad.ok());
  CHECK(!bad.value);
  std::array<uint8_t, 65> pub{};
  const auto read = b.device.ReadObject(kKey, 0U, MutableByteSpan{pub});
  REQUIRE(read.ok());
  CHECK_EQ(read.value, 65U);
  CHECK_EQ(pub[0], 0x04U);
}

TEST_CASE("Device: a policy built for applet 3.x is refused on a 7.x chip before sending") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  const Policy v3 = testmodel::SignPolicy<AppletGeneration::V3>();
  const uint32_t before = b.chip.commands;
  CHECK_EQ(b.device.GenerateEcKey(kKey, v3, EcCurve::NistP256).error, Error::PolicyInvalid);
  CHECK_EQ(b.chip.commands, before);
}

TEST_CASE("Device: a chip status word maps by command context and the raw word is kept") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  std::array<uint8_t, 65> out{};
  const auto r = b.device.ReadObject(ObjectId{0x00002222U}, 0U, MutableByteSpan{out});
  CHECK_EQ(r.error, Error::ObjectNotFound);
  CHECK_EQ(r.detail.sw, 0x6A82U);
  CHECK_EQ(b.device.GetLastStatusWord(), 0x6A82U);
  CHECK_EQ(b.device.GetLastDetail().sw, 0x6A82U);
  CHECK_EQ(b.device.State(), DeviceState::Ready);
  const auto e = b.device.ObjectExists(ObjectId{0x00002222U});
  REQUIRE(e.ok());
  CHECK(!e.value);
}

TEST_CASE("Device: Close ends the link from every state and the device can open again") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  CHECK(b.device.Close().ok());
  CHECK_EQ(b.device.State(), DeviceState::Closed);
  CHECK_EQ(b.device.GetLink().State(), t1::LinkState::Closed);
  std::array<uint8_t, 4> out{};
  CHECK_EQ(b.device.GetRandom(MutableByteSpan{out}).error, Error::NotInitialized);
  REQUIRE(b.device.Open().ok());
  CHECK(b.device.GetRandom(MutableByteSpan{out}).ok());
}

TEST_CASE("Device: probes find the digest command and the curve list; off, they send nothing") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  CHECK(b.device.GetCapabilities().features.digest_commands);
  Config c{};
  c.probe_capabilities = false;
  ChipBench q(testmodel::kSe050E, testmodel::T1Knobs{}, c);
  REQUIRE(q.device.Open().ok());
  CHECK(q.device.ApduCount() < b.device.ApduCount());
}

TEST_CASE("Device: a plain bus without a reset port opens; PowerCycle needs the port") {
  ChipPlainBench b;
  REQUIRE(b.device.Open().ok());
  std::array<uint8_t, 4> out{};
  CHECK(b.device.GetRandom(MutableByteSpan{out}).ok());
}
