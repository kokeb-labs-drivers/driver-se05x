/**
 * @file device_eckey_on.cpp
 * @brief `Device::BeginEcKeySession` with `SE05X_ENABLE_ECKEY_SESSION=1` (part of
 * `se05x_eckey_on`): the verified ECKA key, the session, the receipt check from `Config`, and the
 * reselect after a failed handshake, against the chip model.
 */
#include <array>
#include <cstddef>
#include <cstdint>

#include "model/chip_bench.hpp"
#include "test_harness.hpp"

using namespace se05x;
using testmodel::ChipBench;

namespace {

constexpr uint32_t kEcCredential = 0x00007003U;
constexpr std::array<uint8_t, 32> kHostPrivate{
    0x31, 0x42, 0x53, 0x64, 0x75, 0x06, 0x17, 0x28, 0x39, 0x4A, 0x5B, 0x6C, 0x7D, 0x0E, 0x1F, 0x20,
    0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x0F, 0x11};

struct EcRig {
  ChipBench b;
  std::array<uint8_t, 65> ecka{};
  eckey::SessionParams params{};

  explicit EcRig(const Config& config = Config{})
      : b(testmodel::kSe050E, testmodel::T1Knobs{}, config) {
    std::array<uint8_t, 65> host_public{};
    static_cast<void>(testmodel::mc::PublicKey(kHostPrivate.data(), host_public.data()));
    b.scp.AddEcKey(kEcCredential, host_public.data());
    static_cast<void>(
        b.crypto.ImportKey(KeyKind::P256Private, ByteSpan{kHostPrivate}, params.host_key));
    params.credential = ObjectId{kEcCredential};
  }
  bool OpenAndVerify() {
    return b.device.Open().ok() &&
           b.device
               .ReadEckaPublicKey(ObjectId{testmodel::ChipModel::kAttestKey},
                                  std::span<const uint8_t, 65>{b.chip.AttestPublic()},
                                  std::span<uint8_t, 65>{ecka})
               .ok();
  }
};

} // namespace

static_assert(eckey::kEcKeySessionEnabled);

TEST_CASE("Device ECKey: a verified ECKA key opens the session; commands run under it") {
  EcRig r;
  REQUIRE(r.OpenAndVerify());
  r.params.se_public_key = ByteSpan{r.ecka};
  const uint32_t device_before = r.b.device.ApduCount();
  const uint32_t chip_before = r.b.t1.apdus;
  REQUIRE(r.b.device.BeginEcKeySession(r.params).ok());
  CHECK_EQ(r.b.device.ApduCount() - device_before, r.b.t1.apdus - chip_before); // S-17
  CHECK(r.b.t1.apdus - chip_before >= 2U);
  CHECK_EQ(r.b.device.Session(), SessionKind::EcKey);
  CHECK(r.b.device.SecureMessagingActive());
  CHECK_EQ(r.b.device.Role(), AuthRole::User);
  std::array<uint8_t, 16> rnd{};
  REQUIRE(r.b.device.GetRandom(MutableByteSpan{rnd}).ok());
  REQUIRE(r.b.device.EndSession().ok());
  CHECK_EQ(r.b.scp.sessions_open, 0U);
}

TEST_CASE("Device ECKey: a wrong receipt fails closed and the applet is selected again") {
  EcRig r;
  REQUIRE(r.OpenAndVerify());
  r.b.scp.knobs.receipt_wrong = true;
  r.params.se_public_key = ByteSpan{r.ecka};
  r.params.verify_receipt = false; // Config::verify_eckey_receipt (default on) still checks it
  const uint32_t selects = r.b.chip.selects;
  CHECK_EQ(r.b.device.BeginEcKeySession(r.params).error, Error::SecureChannelError);
  CHECK(r.b.chip.selects > selects);
  CHECK_EQ(r.b.device.State(), DeviceState::Ready);
  CHECK_EQ(r.b.device.Session(), SessionKind::None);
}

TEST_CASE("Device ECKey: without receipt checks in Config and params, the wrong receipt passes") {
  Config c{};
  c.verify_eckey_receipt = false;
  EcRig r(c);
  REQUIRE(r.OpenAndVerify());
  r.b.scp.knobs.receipt_wrong = true;
  r.params.se_public_key = ByteSpan{r.ecka};
  r.params.verify_receipt = false;
  CHECK(r.b.device.BeginEcKeySession(r.params).ok()); // the knob is the caller's (A15)
}
