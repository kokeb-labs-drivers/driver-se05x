/**
 * @file test_irreversible.cpp
 * @brief `irreversible::Operations`: without the build flag nothing exists; with it, plan (no
 * I/O, state, role and argument checks), confirmation and apply for every operation, against the
 * chip model. The flag-on cases build in `se05x_device_irreversible_on` and the mutation runner's
 * flag-on build.
 */
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "docs/lifecycle.hpp"
#include "model/chip_bench.hpp"
#include "test_harness.hpp"

using namespace se05x;
using testmodel::ChipBench;
using testmodel::ChipModel;

namespace {

template <typename O>
concept HasPlans = requires(O& o) {
  o.PlanSetLockStatePersistent();
  o.PlanDeleteAllObjects();
};

} // namespace

#if !(defined(SE05X_ENABLE_IRREVERSIBLE) && (SE05X_ENABLE_IRREVERSIBLE != 0))

static_assert(!HasPlans<irreversible::Operations<testmodel::BenchPorts>>);

TEST_CASE("Irreversible, flag off: no plan exists, the chip is never touched") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  const irreversible::Operations<testmodel::BenchPorts> ops(b.device);
  static_cast<void>(ops);
  CHECK(!kIrreversibleEnabled);
  CHECK_EQ(b.chip.delete_all, 0U);
}

#else

using irreversible::Confirmation;
using irreversible::Operations;

namespace {

static_assert(HasPlans<Operations<testmodel::BenchPorts>>);

constexpr std::array<uint8_t, 8> kRoleValue{0x52, 0x4F, 0x4C, 0x45, 0x30, 0x31, 0x32, 0x33};

/// Register the reserved credential as a UserID object and open a session with it.
bool OpenAs(ChipBench& b, uint32_t reserved) {
  b.scp.AddUserId(reserved, kRoleValue.data(), kRoleValue.size(), 5U);
  return b.device.BeginUserIdSession(UserIdSessionParams{ObjectId{reserved}, ByteSpan{kRoleValue}})
      .ok();
}

template <typename Op>
Confirmation<Op> Confirmed() {
  return Confirmation<Op>{Op::kPhrase};
}

/// A binary-file policy for 7.x that grants only reading.
Policy ReadOnly() {
  return PolicyBuilder<AppletGeneration::V7, ObjectClass::BinaryFile, Profile::Strict>{}
      .ForAllOthers()
      .Allow<Rule::Read>()
      .Build()
      .value;
}

/// A binary-file policy for 7.x that grants reading and deleting.
Policy Deletable() {
  return PolicyBuilder<AppletGeneration::V7, ObjectClass::BinaryFile, Profile::Strict>{}
      .ForAllOthers()
      .Allow<Rule::Read>()
      .Allow<Rule::Delete>()
      .Build()
      .value;
}

/// A UserID policy (7.x): reads nothing, writes nothing.
Policy UserIdPolicy() {
  return PolicyBuilder<AppletGeneration::V7, ObjectClass::UserId, Profile::Strict>{}
      .ForAllOthers()
      .Allow<Rule::ForbidAll>()
      .Build()
      .value;
}

} // namespace

static_assert(!policy::IsImmutable(Policy{}));

TEST_CASE("Irreversible: a plan sends nothing and says what changes") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  REQUIRE(OpenAs(b, ChipModel::kFactoryReset));
  Operations<testmodel::BenchPorts> ops(b.device);
  const uint32_t before = b.chip.commands;
  const auto plan = ops.PlanDeleteAllObjects();
  REQUIRE(plan.ok());
  CHECK(plan.value.IsPrepared());
  CHECK_EQ(plan.value.Target().value, 0U);
  CHECK(std::strlen(plan.value.Effect()) > 10U);
  CHECK_EQ(b.chip.commands, before);
  CHECK_EQ(b.chip.delete_all, 0U);
}

TEST_CASE("Irreversible: Apply refuses an unprepared plan, a wrong phrase and a foreign plan") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  REQUIRE(OpenAs(b, ChipModel::kFactoryReset));
  Operations<testmodel::BenchPorts> ops(b.device);
  const uint32_t before = b.chip.commands;
  CHECK_EQ(ops.Apply(irreversible::Plan<irreversible::DeleteAllObjects>{},
                     Confirmed<irreversible::DeleteAllObjects>())
               .error,
           Error::IrreversibleNotConfirmed);
  const auto plan = ops.PlanDeleteAllObjects();
  REQUIRE(plan.ok());
  const Confirmation<irreversible::DeleteAllObjects> wrong{
      irreversible::SetLockStatePersistent::kPhrase};
  CHECK_EQ(ops.Apply(plan.value, wrong).error, Error::IrreversibleNotConfirmed);
  ChipBench other;
  REQUIRE(other.device.Open().ok());
  REQUIRE(OpenAs(other, ChipModel::kFactoryReset));
  Operations<testmodel::BenchPorts> other_ops(other.device);
  CHECK_EQ(other_ops.Apply(plan.value, Confirmed<irreversible::DeleteAllObjects>()).error,
           Error::IrreversibleNotConfirmed);
  CHECK_EQ(other.chip.delete_all, 0U);
  CHECK_EQ(b.chip.commands, before);
  CHECK_EQ(b.chip.delete_all, 0U);
  REQUIRE(ops.Apply(plan.value, Confirmed<irreversible::DeleteAllObjects>()).ok());
  CHECK_EQ(b.chip.delete_all, 1U);
}

TEST_CASE("Irreversible: a plan needs the role of its command and an open device") {
  ChipBench closed;
  Operations<testmodel::BenchPorts> none(closed.device);
  CHECK_EQ(none.PlanDeleteAllObjects().error, Error::NotInitialized);
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  Operations<testmodel::BenchPorts> ops(b.device);
  CHECK_EQ(ops.PlanDeleteAllObjects().error, Error::ConditionsNotSatisfied);
  CHECK_EQ(ops.PlanSetLockStatePersistent().error, Error::ConditionsNotSatisfied);
  CHECK_EQ(ops.PlanRequirePlatformScp().error, Error::ConditionsNotSatisfied);
  CHECK_EQ(ops.PlanDisableObjectCreation(RestrictMode::RestrictNew).error,
           Error::ConditionsNotSatisfied);
  SetAppletFeaturesArgs features{};
  features.applet_config = 0x0001U;
  CHECK_EQ(ops.PlanChangeAppletFeatures(features).error, Error::ConditionsNotSatisfied);
}

TEST_CASE("Irreversible: the persistent lock is applied once; a second plan is WrongState") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  REQUIRE(OpenAs(b, ChipModel::kTransport));
  Operations<testmodel::BenchPorts> ops(b.device);
  const auto plan = ops.PlanSetLockStatePersistent();
  REQUIRE(plan.ok());
  REQUIRE(ops.Apply(plan.value, Confirmed<irreversible::SetLockStatePersistent>()).ok());
  CHECK(b.chip.knobs.persistent_lock);
  CHECK_EQ(ops.PlanSetLockStatePersistent().error, Error::WrongState);
}

TEST_CASE("Irreversible: platform SCP03 is required after Apply; a second plan is WrongState") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  REQUIRE(OpenAs(b, ChipModel::kPlatformScp));
  Operations<testmodel::BenchPorts> ops(b.device);
  const auto plan = ops.PlanRequirePlatformScp();
  REQUIRE(plan.ok());
  REQUIRE(ops.Apply(plan.value, Confirmed<irreversible::RequirePlatformScp>()).ok());
  CHECK(b.chip.knobs.scp_required);
  CHECK_EQ(ops.PlanRequirePlatformScp().error, Error::WrongState);
}

TEST_CASE("Irreversible: a requirement already set is WrongState even inside platform SCP03") {
  Config c{};
  c.scp_policy = ScpPolicy::Require;
  ChipBench b(testmodel::kSe050E, testmodel::T1Knobs{}, c);
  b.chip.knobs.scp_required = true;
  REQUIRE(b.GivePlatformKeys());
  REQUIRE(b.device.Open().ok());
  REQUIRE(b.device.GetCapabilities().platform_scp_required);
  REQUIRE(OpenAs(b, ChipModel::kPlatformScp)); // the right role, under platform SCP03
  Operations<testmodel::BenchPorts> ops(b.device);
  const uint32_t before = b.chip.commands;
  CHECK_EQ(ops.PlanRequirePlatformScp().error, Error::WrongState);
  CHECK_EQ(b.chip.commands, before);
}

TEST_CASE("Irreversible: object creation is restricted, applet features changed, by role") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  REQUIRE(OpenAs(b, ChipModel::kRestrict));
  Operations<testmodel::BenchPorts> ops(b.device);
  CHECK_EQ(ops.PlanDisableObjectCreation(static_cast<RestrictMode>(7U)).error,
           Error::InvalidArgument);
  const auto plan = ops.PlanDisableObjectCreation(RestrictMode::RestrictAll);
  REQUIRE(plan.ok());
  CHECK(plan.value.Arguments().mode == RestrictMode::RestrictAll);
  REQUIRE(ops.Apply(plan.value, Confirmed<irreversible::DisableObjectCreation>()).ok());
  CHECK(b.chip.restrict_mode != 0U);

  ChipBench f;
  REQUIRE(f.device.Open().ok());
  REQUIRE(OpenAs(f, ChipModel::kFeature));
  Operations<testmodel::BenchPorts> fops(f.device);
  CHECK_EQ(fops.PlanChangeAppletFeatures(SetAppletFeaturesArgs{}).error, Error::InvalidArgument);
  SetAppletFeaturesArgs features{};
  features.applet_config = 0x0001U;
  const auto fplan = fops.PlanChangeAppletFeatures(features);
  REQUIRE(fplan.ok());
  CHECK(fops.Apply(fplan.value, Confirmed<irreversible::ChangeAppletFeatures>()).ok());
  CHECK_EQ(f.chip.last_p2, 0x3FU);
}

TEST_CASE("Irreversible: an immutable object needs a policy without write and delete") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  Operations<testmodel::BenchPorts> ops(b.device);
  const std::array<uint8_t, 4> cfg{0x01U, 0x02U, 0x03U, 0x04U};
  const ObjectId id{0x00004001U};
  CHECK(policy::IsImmutable(ReadOnly()));
  CHECK(!policy::IsImmutable(Deletable()));
  CHECK_EQ(ops.PlanCreateImmutableObject(id, Deletable(), ByteSpan{cfg}).error,
           Error::InvalidArgument);
  CHECK_EQ(ops.PlanCreateImmutableObject(ObjectId{0x7FFF0201U}, ReadOnly(), ByteSpan{cfg}).error,
           Error::InvalidArgument);
  CHECK_EQ(ops.PlanCreateImmutableObject(id, ReadOnly(), ByteSpan{}).error, Error::InvalidArgument);
  static std::array<uint8_t, irreversible::kMaxImmutableBytes + 1U> big{};
  CHECK_EQ(ops.PlanCreateImmutableObject(id, ReadOnly(), ByteSpan{big}).error,
           Error::InvalidArgument);
  const uint32_t before = b.chip.commands;
  const auto plan = ops.PlanCreateImmutableObject(id, ReadOnly(), ByteSpan{cfg});
  REQUIRE(plan.ok());
  CHECK_EQ(plan.value.Target().value, id.value);
  CHECK_EQ(b.chip.commands, before);
  CHECK(!b.chip.Has(id.value));
  const Confirmation<irreversible::CreateImmutableObject> wrong{
      irreversible::CreateFiniteAuthObject::kPhrase};
  CHECK_EQ(ops.Apply(plan.value, wrong).error, Error::IrreversibleNotConfirmed);
  CHECK_EQ(b.chip.commands, before);
  REQUIRE(ops.Apply(plan.value, Confirmed<irreversible::CreateImmutableObject>()).ok());
  CHECK(b.chip.Has(id.value));
  std::array<uint8_t, 4> back{};
  REQUIRE(b.device.ReadObject(id, 0U, MutableByteSpan{back}).ok());
  CHECK_EQ(back[3], 0x04U);
}

TEST_CASE("Irreversible: a finite authentication object, the attempt limit checked first") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  Operations<testmodel::BenchPorts> ops(b.device);
  const std::array<uint8_t, 8> secret{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
  const ObjectId id{0x00004002U};
  CHECK_EQ(ops.PlanCreateFiniteAuthObject(id, UserIdPolicy(), ByteSpan{secret}, 0U).error,
           Error::PolicyInvalid);
  CHECK_EQ(ops.PlanCreateFiniteAuthObject(id, UserIdPolicy(), ByteSpan{secret}.first(2U), 3U).error,
           Error::InvalidArgument);
  CHECK_EQ(ops.PlanCreateFiniteAuthObject(id, Policy{}, ByteSpan{secret}, 3U).error,
           Error::InvalidArgument);
  const auto plan = ops.PlanCreateFiniteAuthObject(id, UserIdPolicy(), ByteSpan{secret}, 3U);
  REQUIRE(plan.ok());
  CHECK_EQ(plan.value.Arguments().max_attempts, 3U);
  REQUIRE(ops.Apply(plan.value, Confirmed<irreversible::CreateFiniteAuthObject>()).ok());
  CHECK(b.chip.Has(id.value));
}

TEST_CASE("Irreversible: what this version cannot do is refused at the plan") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  Operations<testmodel::BenchPorts> ops(b.device);
  const uint32_t before = b.chip.commands;
  CHECK_EQ(ops.PlanReplacePlatformKeys().error, Error::Unsupported);
  CHECK_EQ(ops.PlanChangeI2cAddress().error, Error::Unsupported);
  CHECK_EQ(ops.PlanApplyAppletUpdate().error, Error::Unsupported);
  CHECK_EQ(ops.PlanReplaceEcKeyCredential().error, Error::Unsupported);
  CHECK_EQ(ops.Apply(irreversible::Plan<irreversible::ApplyAppletUpdate>{},
                     Confirmed<irreversible::ApplyAppletUpdate>())
               .error,
           Error::IrreversibleNotConfirmed);
  CHECK_EQ(b.chip.commands, before);
}

TEST_CASE("Irreversible: the lifecycle job of the docs locks only with the typed phrase") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  REQUIRE(OpenAs(b, ChipModel::kTransport));
  static const char* shown = nullptr;
  const auto show = [](const char* effect) { shown = effect; };
  CHECK_EQ(jobs::LockForGood(b.device, irreversible::DeleteAllObjects::kPhrase, show),
           Error::IrreversibleNotConfirmed);
  CHECK(!b.chip.knobs.persistent_lock);
  CHECK(shown != nullptr);
  CHECK_EQ(jobs::LockForGood(b.device, irreversible::SetLockStatePersistent::kPhrase, show),
           Error::Ok);
  CHECK(b.chip.knobs.persistent_lock);
}

#endif // SE05X_ENABLE_IRREVERSIBLE
