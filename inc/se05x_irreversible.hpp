/**
 * @file se05x_irreversible.hpp
 * @brief `Operations<P>`: the plan-and-apply surface of every irreversible operation.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Every member exists only when `kIrreversibleEnabled` is true (`SE05X_ENABLE_IRREVERSIBLE=1`,
 * default off): without it the members are not callable and the build of a caller fails.
 *
 * The flow is plan, confirm, apply:
 *
 * 1. `Plan...()` sends nothing. It checks the device state, the capability gate, the session role
 *    the command needs (`ConditionsNotSatisfied`), the arguments, and that the chip is not already
 *    in the requested state (`WrongState`), and returns a `Plan<Op>` with the target, a one-line
 *    effect for the operator and the arguments.
 * 2. A person reads the plan; the code builds `Confirmation<Op>{Op::kPhrase}`.
 * 3. `Apply(plan, confirmation)` is the only call that sends. It refuses a plan that was not
 *    prepared, a plan prepared for another device, or a confirmation that does not match, with
 *    `IrreversibleNotConfirmed` and nothing sent, then runs `Device::ExecuteIrreversible` (which
 *    checks the state, gate and role again) or the creating command.
 *
 * Operations the driver cannot perform in this version return `Unsupported` from their `Plan...()`
 * call, so no plan for them is ever prepared: `ReplacePlatformKeys` (PUT KEY needs a key-wrapping
 * crypto hook, `docs/secure-channels.md`), `ChangeI2cAddress` (no applet command, ambiguity A7),
 * `ApplyAppletUpdate` (SEMS Lite is out of this version) and `ReplaceEcKeyCredential` (the update
 * of an authentication object's key is not described in the sources read). The two PERSO
 * operations stay on `perso::Perso`. The facade (`hrot`) does not use this header.
 */
#ifndef SE05X_IRREVERSIBLE_HPP
#define SE05X_IRREVERSIBLE_HPP

#include <concepts>
#include <cstddef>
#include <cstdint>

#include "se05x_confirm.hpp"
#include "se05x_device.hpp"
#include "se05x_policy.hpp"
#include "se05x_policy_types.hpp"
#include "se05x_ports.hpp"
#include "se05x_status.hpp"

namespace se05x::irreversible {

/** @brief Largest object `PlanCreateImmutableObject` accepts: it is written in one command. */
inline constexpr std::size_t kMaxImmutableBytes = 512U;

/**
 * @brief The irreversible operations of one device.
 *
 * @tparam P A `Ports<...>` set.
 */
template <typename P>
class Operations {
public:
  /**
   * @brief Bind to a device. No I/O.
   * @param device The device; it must outlive the object.
   */
  explicit Operations(Device<P>& device) noexcept : device_(&device) {}

  /** @name Plans (nothing is sent)
   * @{ */
  /**
   * @brief Lock the applet persistently (`SetLockState`, AN12543 4.6.1): from the next session
   * on only the transport credential is accepted until it unlocks. Needs a Transport session.
   * @return The plan; `NotInitialized`; `NeedsReselect`; `ConditionsNotSatisfied` (not a
   * Transport session); `Unsupported` (gate); `WrongState` (already locked).
   */
  Result<Plan<SetLockStatePersistent>> PlanSetLockStatePersistent() noexcept
    requires(kIrreversibleEnabled);
  /**
   * @brief Require platform SCP03 for every command (`SetPlatformSCPRequest`, AN12543 4.6.4).
   * Needs a PlatformScp session.
   * @return As `PlanSetLockStatePersistent()`; `WrongState` when already required.
   */
  Result<Plan<RequirePlatformScp>> PlanRequirePlatformScp() noexcept
    requires(kIrreversibleEnabled);
  /**
   * @brief Replace the platform key set: not available in this version (PUT KEY needs a crypto
   * hook that wraps one key handle under another).
   * @return `Unsupported` (nothing prepared).
   */
  Result<Plan<ReplacePlatformKeys>> PlanReplacePlatformKeys() noexcept
    requires(kIrreversibleEnabled);
  /**
   * @brief Change the applet features (`SetAppletFeatures`, AN12543 4.6.5). Needs a Feature
   * session (the NXP-owned credential).
   * @param args The AppletConfig bits (and the extended bits on applet 7.x).
   * @return As `PlanSetLockStatePersistent()`; `InvalidArgument` (no feature bit set).
   */
  Result<Plan<ChangeAppletFeatures>> PlanChangeAppletFeatures(
      const SetAppletFeaturesArgs& args) noexcept
    requires(kIrreversibleEnabled);
  /**
   * @brief Delete every object that NXP did not provision (`DeleteAll`, AN12543 4.6.9). Needs a
   * FactoryReset session; the session ends with the answer.
   * @return As `PlanSetLockStatePersistent()`.
   */
  Result<Plan<DeleteAllObjects>> PlanDeleteAllObjects() noexcept
    requires(kIrreversibleEnabled);
  /**
   * @brief Forbid creating objects (`DisableObjCreation`, applet 7.x, AN12543 4.6.3). Needs a
   * Restrict session.
   * @param mode The mode.
   * @return As `PlanSetLockStatePersistent()`; `InvalidArgument` (not a mode).
   */
  Result<Plan<DisableObjectCreation>> PlanDisableObjectCreation(RestrictMode mode) noexcept
    requires(kIrreversibleEnabled);
  /**
   * @brief Create a binary object that can never be changed or deleted: the policy must grant
   * neither `Write` nor `Delete` to any authentication object; the data is written in the
   * creating command.
   * @param id The new object (a user id).
   * @param policy The policy, built for the chip's generation.
   * @param data 1 to `kMaxImmutableBytes` bytes; keep them unchanged until `Apply()`.
   * @return The plan; `InvalidArgument` (reserved id, empty or too much data, a policy that grants
   * write or delete: use `Device::WriteBinary`, it is not irreversible); `PolicyInvalid` (another
   * generation); the state errors.
   */
  Result<Plan<CreateImmutableObject>> PlanCreateImmutableObject(ObjectId id, const Policy& policy,
                                                                ByteSpan data) noexcept
    requires(kIrreversibleEnabled);
  /**
   * @brief Create a UserID authentication object whose attempt counter locks it for good when it
   * runs out (`WriteUserID`, AN12543 p. 84; S-14).
   * @param id The new object (a user id).
   * @param policy Its policy.
   * @param secret The value (secret); keep it unchanged until `Apply()`; never copied.
   * @param max_attempts 1 to 255.
   * @return The plan; `InvalidArgument` (reserved id, a length outside the generation's range);
   * `PolicyInvalid` (no attempt limit, or another generation); the state errors.
   */
  Result<Plan<CreateFiniteAuthObject>> PlanCreateFiniteAuthObject(ObjectId id, const Policy& policy,
                                                                  ByteSpan secret,
                                                                  uint8_t max_attempts) noexcept
    requires(kIrreversibleEnabled);
  /**
   * @brief Change the I2C address: not offered by the applet (A7).
   * @return `Unsupported` (nothing prepared).
   */
  Result<Plan<ChangeI2cAddress>> PlanChangeI2cAddress() noexcept
    requires(kIrreversibleEnabled);
  /**
   * @brief Apply an applet update: SEMS Lite is out of this version.
   * @return `Unsupported` (nothing prepared).
   */
  Result<Plan<ApplyAppletUpdate>> PlanApplyAppletUpdate() noexcept
    requires(kIrreversibleEnabled);
  /**
   * @brief Replace the ECKey authentication credential: not available in this version.
   * @return `Unsupported` (nothing prepared).
   */
  Result<Plan<ReplaceEcKeyCredential>> PlanReplaceEcKeyCredential() noexcept
    requires(kIrreversibleEnabled);
  /** @} */

  /**
   * @brief Apply a prepared plan: the only call that sends.
   *
   * @tparam Op The operation tag.
   * @param plan The plan from the matching `Plan...` call on this device.
   * @param confirmation The confirmation built from `Op::kPhrase`.
   * @return `IrreversibleNotConfirmed` for an unprepared plan, a plan of another device or a wrong
   * phrase (nothing sent); else the result of `Device::ExecuteIrreversible` or of the creating
   * command.
   */
  template <typename Op>
  Result<void> Apply(const Plan<Op>& plan, Confirmation<Op> confirmation) noexcept
    requires(kIrreversibleEnabled);

private:
  template <typename Op>
  Result<Plan<Op>> prepare(Command command, const Policy* policy, ObjectId target,
                           const char* effect, const typename Op::Args& args) const noexcept;
  template <typename Op>
  [[nodiscard]] static Result<Plan<Op>> unsupported() noexcept;
  template <Command C, typename Op>
  Result<void> run(const ArgsOf<C>& args, Confirmation<Op> confirmation) noexcept;

  Device<P>* device_;
};

} // namespace se05x::irreversible

// codeql::misra_deviation_next_line(MD-CPP-009)
#include "../src/se05x_irreversible.ipp" // IWYU pragma: export

#endif // SE05X_IRREVERSIBLE_HPP
