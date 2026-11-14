/**
 * @file test_device_sessions.cpp
 * @brief `Device`: platform SCP03 at `Open()`, the UserID and AESKey sessions alone and inside
 * platform SCP03, the attempt limit, the half-open session rule, the verified ECKA key before an
 * ECKey session, and the EdDSA input limits per session (940 and 919 bytes).
 */
#include <array>
#include <cstddef>
#include <cstdint>

#include "model/chip_bench.hpp"
#include "test_harness.hpp"

using namespace se05x;
using testmodel::ChipBench;

namespace {

constexpr ObjectId kKey{0x00001001U};

Config RequireScp() {
  Config c{};
  c.scp_policy = ScpPolicy::Require;
  return c;
}

/// Sign `n` message bytes with EdDSA through the device.
Error EddsaVerifyOf(ChipBench& b, std::size_t n) {
  static std::array<uint8_t, 941> msg{};
  std::array<uint8_t, 64> sig{};
  sig[0] = 0x01U;
  return b.device
      .Execute<Command::EddsaVerify>(
          VerifyArgs{kKey, EcSignAlgo::Ed25519Pure, ByteSpan{msg}.first(n), ByteSpan{sig}})
      .error;
}

void MakeKey(ChipBench& b) {
  const Policy p = testmodel::SignPolicy<AppletGeneration::V7>();
  REQUIRE(b.device.GenerateEcKey(kKey, p, EcCurve::NistP256).ok());
}

} // namespace

TEST_CASE("Sessions: platform SCP03 required without keys is WrongState; with keys it opens") {
  ChipBench none(testmodel::kSe050E, testmodel::T1Knobs{}, RequireScp());
  const auto r = none.device.Open();
  CHECK_EQ(r.error, Error::WrongState);
  CHECK_EQ(none.device.State(), DeviceState::Closed);
  CHECK(!none.scp.platform_open);

  ChipBench b(testmodel::kSe050E, testmodel::T1Knobs{}, RequireScp());
  REQUIRE(b.GivePlatformKeys());
  REQUIRE(b.device.Open().ok());
  CHECK(b.scp.platform_open);
  CHECK(b.device.GetCapabilities().platform_scp_active);
  CHECK(b.device.SecureMessagingActive());
  std::array<uint8_t, 16> rnd{};
  const uint32_t mac_before = b.scp.platform_ctr;
  REQUIRE(b.device.GetRandom(MutableByteSpan{rnd}).ok());
  CHECK(b.scp.platform_ctr > mac_before); // it went under SCP03
}

TEST_CASE("Sessions: the chip requires platform SCP03 and the policy says Off: WrongState") {
  Config c{};
  c.scp_policy = ScpPolicy::Off;
  ChipBench b(testmodel::kSe050E, testmodel::T1Knobs{}, c);
  b.chip.knobs.scp_required = true;
  CHECK_EQ(b.device.Open().error, Error::WrongState);
  ChipBench a; // Auto opens it when the chip asks
  a.chip.knobs.scp_required = true;
  REQUIRE(a.GivePlatformKeys());
  REQUIRE(a.device.Open().ok());
  CHECK(a.device.GetCapabilities().platform_scp_required);
  CHECK(a.device.GetCapabilities().platform_scp_active);
}

TEST_CASE("Sessions: SetPlatformKeys refuses a missing handle and an open device") {
  ChipBench b;
  CHECK_EQ(b.device.SetPlatformKeys(scp03::ChannelParams{}).error, Error::InvalidArgument);
  REQUIRE(b.GivePlatformKeys());
  REQUIRE(b.device.Open().ok());
  CHECK_EQ(b.device.SetPlatformKeys(scp03::ChannelParams{}).error, Error::WrongState);
}

TEST_CASE("Sessions: the configuration's receipt check cannot be turned off by a call (A15)") {
  CHECK(detail::VerifyReceipt(true, false));
  CHECK(detail::VerifyReceipt(false, true));
  CHECK(!detail::VerifyReceipt(false, false));
}

TEST_CASE("Sessions: one session at a time; a second of another kind sends nothing") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  REQUIRE(b.device.BeginUserIdSession(ChipBench::UserParams()).ok());
  const uint32_t writes = b.t1.writes;
  CHECK_EQ(b.device.BeginAesKeySession(b.AesParams()).error, Error::WrongState);
  CHECK_EQ(b.t1.writes, writes);
  CHECK_EQ(b.device.Session(), SessionKind::UserId);
}

TEST_CASE("Sessions: the APDU count grows by what each session open sends (S-17)") {
  for (int kind = 0; kind < 3; ++kind) {
    ChipBench b;
    REQUIRE(b.device.Open().ok());
    const uint32_t device_before = b.device.ApduCount();
    const uint32_t chip_before = b.t1.apdus;
    if (kind == 0) {
      REQUIRE(b.device.BeginUserIdSession(ChipBench::UserParams()).ok()); // 2 APDUs
    } else if (kind == 1) {
      REQUIRE(b.device.BeginAesKeySession(b.AesParams()).ok()); // 3 APDUs
    } else {
      AesKeySessionParams wrong = b.AesParams();
      wrong.credential = ObjectId{0x00007777U}; // no such credential: refused by the chip
      CHECK(!b.device.BeginAesKeySession(wrong).ok());
    }
    CHECK_EQ(b.device.ApduCount() - device_before, b.t1.apdus - chip_before);
  }
}

TEST_CASE("Sessions: a UserID session opens, has no secure messaging and ends cleanly") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  REQUIRE(b.device.BeginUserIdSession(ChipBench::UserParams()).ok());
  CHECK_EQ(b.device.Session(), SessionKind::UserId);
  CHECK_EQ(b.device.State(), DeviceState::InSession);
  CHECK_EQ(b.device.Role(), AuthRole::User);
  CHECK(!b.device.SecureMessagingActive()); // S-14
  std::array<uint8_t, 8> rnd{};
  REQUIRE(b.device.GetRandom(MutableByteSpan{rnd}).ok());
  CHECK_EQ(b.scp.auth_id, 0U); // reset after each forwarded command
  CHECK_EQ(b.device.BeginUserIdSession(ChipBench::UserParams()).error, Error::WrongState);
  REQUIRE(b.device.EndSession().ok());
  CHECK_EQ(b.device.Session(), SessionKind::None);
  CHECK_EQ(b.scp.sessions_open, 0U);
  CHECK(b.device.EndSession().ok()); // no session: nothing is sent (errata APP.2)
}

TEST_CASE("Sessions: a wrong UserID value is AuthFailed, reselected, then locked on the host") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  const std::array<uint8_t, 6> wrong{0x39, 0x39, 0x39, 0x39, 0x39, 0x39};
  const UserIdSessionParams p{ObjectId{testmodel::kUserCredential}, ByteSpan{wrong}};
  const uint32_t selects = b.chip.selects;
  CHECK_EQ(b.device.BeginUserIdSession(p).error, Error::AuthFailed);
  CHECK(b.chip.selects > selects); // the half-open session is ended by a select (S-07)
  CHECK_EQ(b.device.State(), DeviceState::Ready);
  CHECK_EQ(b.scp.sessions_open, 0U);
  CHECK_EQ(b.device.BeginUserIdSession(p).error, Error::AuthFailed);
  CHECK_EQ(b.device.BeginUserIdSession(p).error, Error::AuthFailed);
  const uint32_t writes = b.t1.writes;
  CHECK_EQ(b.device.BeginUserIdSession(p).error, Error::AuthLocked); // Config limit 3 (S-14)
  CHECK_EQ(b.t1.writes, writes);
}

TEST_CASE("Sessions: an AESKey session alone and inside platform SCP03 (two layers)") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  REQUIRE(b.device.BeginAesKeySession(b.AesParams()).ok());
  CHECK_EQ(b.device.Session(), SessionKind::AesKey);
  CHECK(b.device.SecureMessagingActive());
  MakeKey(b);
  REQUIRE(b.device.EndSession().ok());

  ChipBench s(testmodel::kSe050E, testmodel::T1Knobs{}, RequireScp());
  REQUIRE(s.GivePlatformKeys());
  REQUIRE(s.device.Open().ok());
  REQUIRE(s.device.BeginAesKeySession(s.AesParams()).ok());
  const uint32_t ctr = s.scp.platform_ctr;
  MakeKey(s);
  CHECK(s.chip.Has(kKey.value));
  CHECK(s.scp.platform_ctr > ctr); // the session command travelled inside platform SCP03
  CHECK(s.scp.platform_open);
  REQUIRE(s.device.EndSession().ok());
  CHECK(s.scp.platform_open); // platform SCP03 stays underneath
}

TEST_CASE("Sessions: a wrong AESKey is refused, the applet is selected again, nothing half open") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  AesKeySessionParams p{};
  p.credential = ObjectId{testmodel::kAesCredential};
  const std::array<uint8_t, 16> other{};
  REQUIRE(b.crypto.ImportKey(KeyKind::Aes128, ByteSpan{other}, p.keys.enc) == CryptoStatus::Ok);
  const uint32_t selects = b.chip.selects;
  const auto r = b.device.BeginAesKeySession(p);
  CHECK(!r.ok());
  CHECK(b.chip.selects > selects);
  CHECK_EQ(b.scp.sessions_open, 0U);
  CHECK_EQ(b.device.State(), DeviceState::Ready);
  CHECK_EQ(b.device.Session(), SessionKind::None);
}

TEST_CASE("Sessions: EdDSA takes 940 bytes in the default session, the AESKey session and under "
          "platform SCP03, and 919 in a UserID session") {
  ChipBench b(testmodel::kSe050E, testmodel::T1Knobs{}, RequireScp());
  REQUIRE(b.GivePlatformKeys());
  REQUIRE(b.device.Open().ok());
  MakeKey(b);
  CHECK(EddsaVerifyOf(b, 936U) == Error::Ok);
  CHECK(EddsaVerifyOf(b, 937U) == Error::Ok);
  CHECK(EddsaVerifyOf(b, 940U) == Error::Ok);
  CHECK_EQ(EddsaVerifyOf(b, 941U), Error::InvalidArgument);
  REQUIRE(b.device.BeginAesKeySession(b.AesParams()).ok());
  CHECK(EddsaVerifyOf(b, 940U) == Error::Ok); // session inside platform SCP03: 1028 + 2 layers
  CHECK_EQ(b.chip.last_len, 1026U); // the 1028-byte APDU without its Le, as sessions send it
  REQUIRE(b.device.EndSession().ok());
  REQUIRE(b.device.BeginUserIdSession(ChipBench::UserParams()).ok());
  CHECK(EddsaVerifyOf(b, 919U) == Error::Ok);
  const uint32_t before = b.chip.commands;
  CHECK_EQ(EddsaVerifyOf(b, 920U), Error::InvalidArgument); // wire::EddsaInputMax(true)
  CHECK_EQ(b.chip.commands, before);
}

TEST_CASE("Sessions: ECKey needs the ECKA key verified by an attested read in this open") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  eckey::SessionParams p{};
  p.credential = ObjectId{0x00007003U};
  std::array<uint8_t, 65> guess{};
  guess[0] = 0x04U;
  p.se_public_key = ByteSpan{guess};
  const uint32_t writes = b.t1.writes;
  CHECK_EQ(b.device.BeginEcKeySession(p).error, Error::WrongState);
  CHECK_EQ(b.t1.writes, writes);
  std::array<uint8_t, 65> ecka{};
  REQUIRE(b.device
              .ReadEckaPublicKey(ObjectId{testmodel::ChipModel::kAttestKey},
                                 std::span<const uint8_t, 65>{b.chip.AttestPublic()},
                                 std::span<uint8_t, 65>{ecka})
              .ok());
  CHECK(ecka == b.scp.SePublic());
  CHECK_EQ(b.device.BeginEcKeySession(p).error, Error::WrongState); // another key than verified
  p.se_public_key = ByteSpan{ecka};
  const auto r = b.device.BeginEcKeySession(p);
  CHECK_EQ(r.error, eckey::kEcKeySessionEnabled ? Error::InvalidArgument : Error::Unsupported);
  CHECK_EQ(b.device.State(), DeviceState::Ready);
}

TEST_CASE("Sessions: an ECKA key signed by another attestation key is AttestationInvalid") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  std::array<uint8_t, 65> other = b.chip.AttestPublic();
  other = b.scp.SePublic(); // a valid point, not the attestation key
  std::array<uint8_t, 65> ecka{};
  const auto r =
      b.device.ReadEckaPublicKey(ObjectId{testmodel::ChipModel::kAttestKey},
                                 std::span<const uint8_t, 65>{other}, std::span<uint8_t, 65>{ecka});
  CHECK_EQ(r.error, Error::AttestationInvalid);
  eckey::SessionParams p{};
  p.credential = ObjectId{0x00007003U};
  p.se_public_key = ByteSpan{b.scp.SePublic()};
  CHECK_EQ(b.device.BeginEcKeySession(p).error, Error::WrongState);
}

TEST_CASE("Sessions: an attested read draws its nonce from the host and echoes the command") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  std::array<uint8_t, 65> data{};
  std::array<uint8_t, 80> sig{};
  ReadObjectAttestedArgs a{};
  a.id = FromReserved(ReservedId::EcKeySession);
  a.attestation_key = ObjectId{testmodel::ChipModel::kAttestKey};
  a.data_out = MutableByteSpan{data};
  a.signature_out = MutableByteSpan{sig};
  const uint32_t before = b.chip.commands;
  const auto r = b.device.ReadAttested(a);
  REQUIRE(r.ok());
  CHECK_EQ(b.chip.commands, before + 1U); // the read only: the nonce is the host's
  CHECK_EQ(r.value.format, AttestationFormat::V2);
  CHECK(r.value.echoed_command.length > 20U);
  CHECK_EQ(r.value.echoed_command.bytes[1], 0x22U); // INS_READ | INS_ATTEST
  CHECK_EQ(r.value.data_length, 65U);
  const auto again = b.device.ReadAttested(a);
  REQUIRE(again.ok());
  REQUIRE(again.value.echoed_command.length == r.value.echoed_command.length);
  bool differs = false; // a fresh nonce from the crypto port each time (S-09)
  for (std::size_t i = 0U; i < r.value.echoed_command.length; ++i) {
    differs = differs || (again.value.echoed_command.bytes[i] != r.value.echoed_command.bytes[i]);
  }
  CHECK(differs);
}

TEST_CASE("Sessions: a UserID object with an infinite counter is refused before sending (S-14)") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  const Policy p = testmodel::SignPolicy<AppletGeneration::V7>();
  const std::array<uint8_t, 8> value{1, 2, 3, 4, 5, 6, 7, 8};
  WriteUserIdArgs w{};
  w.id = ObjectId{0x00007010U};
  w.policy = &p;
  w.user_secret = ByteSpan{value};
  w.max_attempts = 0U;
  const uint32_t before = b.chip.commands;
  CHECK_EQ(b.device.Execute<Command::WriteUserId>(w).error, Error::PolicyInvalid);
  w.max_attempts = 3U;
  w.user_secret = ByteSpan{value}.first(3U); // applet 7.x: 4 to 16 bytes
  CHECK_EQ(b.device.Execute<Command::WriteUserId>(w).error, Error::InvalidArgument);
  CHECK_EQ(b.chip.commands, before);
}

TEST_CASE("Sessions: a valid UserID object is created only by the irreversible operations") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  const Policy p = testmodel::SignPolicy<AppletGeneration::V7>();
  const std::array<uint8_t, 8> value{1, 2, 3, 4, 5, 6, 7, 8};
  WriteUserIdArgs w{};
  w.id = ObjectId{0x00007010U};
  w.policy = &p;
  w.user_secret = ByteSpan{value};
  w.max_attempts = 3U; // finite: the object locks for good when the attempts run out
  const uint32_t before = b.chip.commands;
  CHECK_EQ(b.device.Execute<Command::WriteUserId>(w).error, Error::IrreversibleNotConfirmed);
  CHECK_EQ(b.chip.commands, before);
  CHECK(!b.chip.Has(w.id.value));
}

TEST_CASE("Sessions: the applet stage never sends in the clear once platform SCP03 is required") {
  ChipBench b;
  t1::Link<testmodel::BenchPorts> link(b.ports, Config{});
  REQUIRE(link.Open().ok());
  detail::LinkStage<testmodel::BenchPorts> wire(link);
  scp03::Channel<testmodel::BenchPorts, detail::LinkStage<testmodel::BenchPorts>> platform(b.ports,
                                                                                           wire);
  detail::AppletStage<testmodel::BenchPorts> stage(wire, platform);
  const std::array<uint8_t, 5> cmd{0x80U, 0x04U, 0x00U, 0x20U, 0x00U};
  std::array<uint8_t, 32> rsp{};
  CHECK(stage.Transceive(ByteSpan{cmd}, MutableByteSpan{rsp}).ok()); // plain bus: the link
  stage.RequirePlatform(true);
  const uint32_t writes = b.t1.writes;
  CHECK_EQ(stage.Transceive(ByteSpan{cmd}, MutableByteSpan{rsp}).error, Error::SecureChannelError);
  stage.Block(true);
  CHECK_EQ(stage.Transceive(ByteSpan{cmd}, MutableByteSpan{rsp}).error, Error::NeedsReselect);
  CHECK_EQ(b.t1.writes, writes);
}
