/**
 * @file test_device_lifecycle.cpp
 * @brief `Device::ExecuteIrreversible` with `SE05X_ENABLE_IRREVERSIBLE=1`: the confirmation, the
 * session role of each lifecycle command, the typed state checks, and the session ending with
 * `DeleteAll`, against the chip model. The cases exist only with the flag: the host build has
 * none, the executable `se05x_device_irreversible_on` (and the mutation runner's flag-on build)
 * runs them.
 */
#include <array>
#include <cstddef>
#include <cstdint>

#include "model/chip_bench.hpp"
#include "test_harness.hpp"

#if defined(SE05X_ENABLE_IRREVERSIBLE) && (SE05X_ENABLE_IRREVERSIBLE != 0)

using namespace se05x;
using testmodel::ChipBench;
using testmodel::ChipModel;

namespace {

constexpr std::array<uint8_t, 8> kRoleValue{0x52, 0x4F, 0x4C, 0x45, 0x30, 0x31, 0x32, 0x33};
constexpr ObjectId kKey{0x00001001U};

/// Register the reserved credential as a UserID object and open a session with it.
bool OpenAs(ChipBench& b, uint32_t reserved) {
  b.scp.AddUserId(reserved, kRoleValue.data(), kRoleValue.size(), 5U);
  return b.device.BeginUserIdSession(UserIdSessionParams{ObjectId{reserved}, ByteSpan{kRoleValue}})
      .ok();
}

template <typename Op>
irreversible::Confirmation<Op> Confirmed() {
  return irreversible::Confirmation<Op>{Op::kPhrase};
}

} // namespace

static_assert(kIrreversibleEnabled);

TEST_CASE("Irreversible: a wrong confirmation and a wrong role send nothing") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  const uint32_t before = b.chip.commands;
  const irreversible::Confirmation<irreversible::DeleteAllObjects> wrong{
      irreversible::SetLockStatePersistent::kPhrase};
  CHECK_EQ(
      (b.device
           .ExecuteIrreversible<Command::DeleteAll, irreversible::DeleteAllObjects>(Empty{}, wrong)
           .error),
      Error::IrreversibleNotConfirmed);
  const auto no_role =
      b.device.ExecuteIrreversible<Command::DeleteAll, irreversible::DeleteAllObjects>(
          Empty{}, Confirmed<irreversible::DeleteAllObjects>());
  CHECK_EQ(no_role.error, Error::ConditionsNotSatisfied); // the default session has no role
  REQUIRE(b.device.BeginUserIdSession(ChipBench::UserParams()).ok());
  const uint32_t in_session = b.chip.commands;
  CHECK_EQ((b.device
                .ExecuteIrreversible<Command::DeleteAll, irreversible::DeleteAllObjects>(
                    Empty{}, Confirmed<irreversible::DeleteAllObjects>())
                .error),
           Error::ConditionsNotSatisfied); // a user session is not RESERVED_ID_FACTORY_RESET
  CHECK_EQ(b.chip.commands, in_session);
  CHECK_EQ(b.chip.delete_all, 0U);
  CHECK(before <= in_session);
}

TEST_CASE("Irreversible: DeleteAll in a factory-reset session deletes and ends the session") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  const Policy p = testmodel::SignPolicy<AppletGeneration::V7>();
  REQUIRE(b.device.GenerateEcKey(kKey, p, EcCurve::NistP256).ok());
  REQUIRE(OpenAs(b, ChipModel::kFactoryReset));
  CHECK_EQ(b.device.Role(), AuthRole::FactoryReset);
  const auto r = b.device.ExecuteIrreversible<Command::DeleteAll, irreversible::DeleteAllObjects>(
      Empty{}, Confirmed<irreversible::DeleteAllObjects>());
  REQUIRE(r.ok());
  CHECK_EQ(b.chip.delete_all, 1U);
  CHECK(!b.chip.Has(kKey.value));
  CHECK(b.chip.Has(ChipModel::kAttestKey)); // provisioned objects stay
  CHECK_EQ(b.device.Session(), SessionKind::None);
  CHECK_EQ(b.device.Role(), AuthRole::None);
  CHECK_EQ(b.device.State(), DeviceState::Ready);
}

TEST_CASE("Irreversible: DeleteAll in an AESKey factory-reset session: the bare 9000 is success") {
  ChipBench b;
  b.scp.AddAesKey(ChipModel::kFactoryReset, testmodel::kAesKey.data()); // any credential type
  REQUIRE(b.device.Open().ok());
  const Policy p = testmodel::SignPolicy<AppletGeneration::V7>();
  REQUIRE(b.device.GenerateEcKey(kKey, p, EcCurve::NistP256).ok());
  AesKeySessionParams params = b.AesParams();
  params.credential = ObjectId{ChipModel::kFactoryReset};
  REQUIRE(b.device.BeginAesKeySession(params).ok());
  CHECK_EQ(b.device.Role(), AuthRole::FactoryReset);
  const auto r = b.device.ExecuteIrreversible<Command::DeleteAll, irreversible::DeleteAllObjects>(
      Empty{}, Confirmed<irreversible::DeleteAllObjects>());
  CHECK(r.ok()); // AN12543 4.20.5 p. 154: the reply is not wrapped
  CHECK_EQ(b.chip.delete_all, 1U);
  CHECK(!b.chip.Has(kKey.value));
  CHECK_EQ(b.device.Session(), SessionKind::None);
  CHECK_EQ(b.device.State(), DeviceState::Ready);
  // The next session runs as usual: the bare-answer allowance was for DeleteAll only.
  REQUIRE(b.device.BeginAesKeySession(b.AesParams()).ok());
  std::array<uint8_t, 8> rnd{};
  CHECK(b.device.GetRandom(MutableByteSpan{rnd}).ok());
}

TEST_CASE("Irreversible: the persistent lock needs the transport role and is not set twice") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  REQUIRE(OpenAs(b, ChipModel::kTransport));
  CHECK_EQ(b.device.Role(), AuthRole::Transport);
  SetLockStateArgs lock{};
  lock.state = LockStateValue::Locked;
  REQUIRE((b.device
               .ExecuteIrreversible<Command::SetLockState, irreversible::SetLockStatePersistent>(
                   lock, Confirmed<irreversible::SetLockStatePersistent>())
               .ok()));
  CHECK(b.chip.knobs.persistent_lock);
  CHECK(b.device.GetCapabilities().applet_locked);
  const uint32_t before = b.chip.commands;
  CHECK_EQ((b.device
                .ExecuteIrreversible<Command::SetLockState, irreversible::SetLockStatePersistent>(
                    lock, Confirmed<irreversible::SetLockStatePersistent>())
                .error),
           Error::WrongState);
  CHECK_EQ(b.chip.commands, before);
}

TEST_CASE("Irreversible: the platform SCP requirement needs its role; then the gate requires it") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  REQUIRE(OpenAs(b, ChipModel::kTransport)); // the wrong reserved role
  SetPlatformScpRequestArgs req{};
  CHECK_EQ(
      (b.device
           .ExecuteIrreversible<Command::SetPlatformScpRequest, irreversible::RequirePlatformScp>(
               req, Confirmed<irreversible::RequirePlatformScp>())
           .error),
      Error::ConditionsNotSatisfied);
  REQUIRE(b.device.EndSession().ok());
  REQUIRE(OpenAs(b, ChipModel::kPlatformScp));
  REQUIRE(
      (b.device
           .ExecuteIrreversible<Command::SetPlatformScpRequest, irreversible::RequirePlatformScp>(
               req, Confirmed<irreversible::RequirePlatformScp>())
           .ok()));
  CHECK(b.chip.knobs.scp_required);
  CHECK(b.device.GetCapabilities().platform_scp_required);
  std::array<uint8_t, 8> out{};
  CHECK_EQ(b.device.GetRandom(MutableByteSpan{out}).error, Error::WrongState); // S-11, S-13
}

TEST_CASE("Irreversible: object creation is disabled only in a RESERVED_ID_RESTRICT session") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  REQUIRE(OpenAs(b, ChipModel::kFactoryReset));
  DisableObjCreationArgs args{};
  CHECK_EQ(
      (b.device
           .ExecuteIrreversible<Command::DisableObjCreation, irreversible::DisableObjectCreation>(
               args, Confirmed<irreversible::DisableObjectCreation>())
           .error),
      Error::ConditionsNotSatisfied);
  REQUIRE(b.device.EndSession().ok());
  REQUIRE(OpenAs(b, ChipModel::kRestrict));
  CHECK_EQ(b.device.Role(), AuthRole::Restrict);
  REQUIRE(
      (b.device
           .ExecuteIrreversible<Command::DisableObjCreation, irreversible::DisableObjectCreation>(
               args, Confirmed<irreversible::DisableObjectCreation>())
           .ok()));
  CHECK(b.chip.restrict_mode != 0U);
}

#endif // SE05X_ENABLE_IRREVERSIBLE
