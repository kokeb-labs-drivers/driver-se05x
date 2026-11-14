/**
 * @file se05x_confirm.hpp
 * @brief The confirmation types of the irreversible operations (S-10).
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Frozen contract. Every operation that cannot be undone is a distinct type `Op` here, with a
 * phrase constant `Op::kPhrase`. To run it the caller builds `Confirmation<Op>{Op::kPhrase}` and a
 * `Plan<Op>` (a dry run that describes the effect and sends nothing); the operations themselves
 * exist only when the library is built with `SE05X_ENABLE_IRREVERSIBLE` (`kIrreversibleEnabled`),
 * and never in `hrot`. A confirmation for one operation cannot be used for another: the types
 * differ. Each tag names the arguments its plan carries (`Op::Args`); the plan copies them, except
 * the bytes behind a `ByteSpan` (object data, a secret), which the caller keeps unchanged until
 * `Apply()`: a plan never holds a copy of a secret.
 */
#ifndef SE05X_CONFIRM_HPP
#define SE05X_CONFIRM_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "se05x_commands.hpp"
#include "se05x_detail.hpp"
#include "se05x_device_types.hpp"
#include "se05x_ids.hpp"
#include "se05x_policy_types.hpp"
#include "se05x_types.hpp"

namespace se05x::irreversible {

/**
 * @defgroup se05x_confirm Irreversible operations: confirmation types
 * @brief The operation tags, `Confirmation<Op>` and `Plan<Op>`.
 * @{
 */

/// The phrase of an operation: 8 ASCII bytes the caller passes back (shown in `docs/safety.md`).
using Phrase = std::array<uint8_t, 8>;

/// The arguments of an operation that takes none.
struct NoArgs {};

/// The arguments of `CreateImmutableObject`: a binary file written once, with a policy that grants
/// neither write nor delete.
struct ImmutableObjectArgs {
  ObjectId id{}; ///< The new object (a user id).
  Policy policy; ///< Its policy: no `Write`, no `Delete` for any authentication object.
  ByteSpan data; ///< The content, 1 to `apdu::kBinaryFileMax` bytes; kept by the caller.
};

/// The arguments of `CreateFiniteAuthObject`: a UserID authentication object whose attempt counter
/// locks it for good when it runs out (S-14).
struct FiniteAuthArgs {
  ObjectId id{};           ///< The new authentication object (a user id).
  Policy policy;           ///< Its policy.
  ByteSpan secret;         ///< The UserID value (secret); kept by the caller, never copied.
  uint8_t max_attempts{0}; ///< 1 to 255.
};

/// Lock the applet persistently (`SetLockState`). Phrase "LOCKFRVR".
struct SetLockStatePersistent {
  static constexpr Phrase kPhrase{0x4C, 0x4F, 0x43, 0x4B, 0x46, 0x52, 0x56, 0x52}; ///< "LOCKFRVR".
  static constexpr Command kCommand = Command::SetLockState; ///< The applet command.
  using Args = NoArgs;                                       ///< The plan's arguments.
};
/// Require platform SCP03 for every command (`SetPlatformScpRequest`). Phrase "SCPREQRD".
struct RequirePlatformScp {
  static constexpr Phrase kPhrase{0x53, 0x43, 0x50, 0x52, 0x45, 0x51, 0x52, 0x44}; ///< "SCPREQRD".
  static constexpr Command kCommand = Command::SetPlatformScpRequest; ///< The applet command.
  using Args = NoArgs;                                                ///< The plan's arguments.
};
/// Replace the platform SCP03 key set (GP PUT KEY). Phrase "NEWKEYST".
struct ReplacePlatformKeys {
  static constexpr Phrase kPhrase{0x4E, 0x45, 0x57, 0x4B, 0x45, 0x59, 0x53, 0x54}; ///< "NEWKEYST".
  using Args = NoArgs; ///< The plan's arguments.
};
/// Change the feature set for good (`SetAppletFeatures`). Phrase "FEATURES".
struct ChangeAppletFeatures {
  static constexpr Phrase kPhrase{0x46, 0x45, 0x41, 0x54, 0x55, 0x52, 0x45, 0x53}; ///< "FEATURES".
  static constexpr Command kCommand = Command::SetAppletFeatures; ///< The applet command.
  using Args = SetAppletFeaturesArgs;                             ///< The plan's arguments.
};
/// Delete every user object (`DeleteAll`). Phrase "DELETALL".
struct DeleteAllObjects {
  static constexpr Phrase kPhrase{0x44, 0x45, 0x4C, 0x45, 0x54, 0x41, 0x4C, 0x4C}; ///< "DELETALL".
  static constexpr Command kCommand = Command::DeleteAll; ///< The applet command.
  using Args = NoArgs;                                    ///< The plan's arguments.
};
/// Stop object creation (`DisableObjCreation`). Phrase "NOMOREOB".
struct DisableObjectCreation {
  static constexpr Phrase kPhrase{0x4E, 0x4F, 0x4D, 0x4F, 0x52, 0x45, 0x4F, 0x42}; ///< "NOMOREOB".
  static constexpr Command kCommand = Command::DisableObjCreation; ///< The applet command.
  using Args = DisableObjCreationArgs;                             ///< The plan's arguments.
};
/// Create an object nobody can delete or change (`FORBID_ALL`, or no `ALLOW_DELETE`). Phrase
/// "IMMUTABL".
struct CreateImmutableObject {
  static constexpr Phrase kPhrase{0x49, 0x4D, 0x4D, 0x55, 0x54, 0x41, 0x42, 0x4C}; ///< "IMMUTABL".
  using Args = ImmutableObjectArgs; ///< The plan's arguments.
};
/// Create an authentication object with a finite attempt counter. Phrase "FINITEAT".
struct CreateFiniteAuthObject {
  static constexpr Phrase kPhrase{0x46, 0x49, 0x4E, 0x49, 0x54, 0x45, 0x41, 0x54}; ///< "FINITEAT".
  using Args = FiniteAuthArgs; ///< The plan's arguments.
};
/// Change the I2C address (read-only in v1, ambiguity A7). Phrase "NEWADDR!".
struct ChangeI2cAddress {
  static constexpr Phrase kPhrase{0x4E, 0x45, 0x57, 0x41, 0x44, 0x44, 0x52, 0x21}; ///< "NEWADDR!".
  using Args = NoArgs; ///< The plan's arguments.
};
/// Apply an applet update package (SEMS Lite). Phrase "APPLYUPD".
struct ApplyAppletUpdate {
  static constexpr Phrase kPhrase{0x41, 0x50, 0x50, 0x4C, 0x59, 0x55, 0x50, 0x44}; ///< "APPLYUPD".
  using Args = NoArgs; ///< The plan's arguments.
};
/// Write a PERSO setting: I2C address, protocol, ATR or CIP bytes (`perso::Perso::Write`). Phrase
/// "PERSOWRT".
struct WritePersoSetting {
  static constexpr Phrase kPhrase{0x50, 0x45, 0x52, 0x53, 0x4F, 0x57, 0x52, 0x54}; ///< "PERSOWRT".
  using Args = NoArgs; ///< The plan's arguments.
};
/// Delete an optional PERSO module for good (`perso::Perso::DeleteModule`). Phrase "PERSODEL".
struct DeletePersoModule {
  static constexpr Phrase kPhrase{0x50, 0x45, 0x52, 0x53, 0x4F, 0x44, 0x45, 0x4C}; ///< "PERSODEL".
  using Args = NoArgs; ///< The plan's arguments.
};
/// Replace the ECKey session credential. Phrase "NEWECKEY".
struct ReplaceEcKeyCredential {
  static constexpr Phrase kPhrase{0x4E, 0x45, 0x57, 0x45, 0x43, 0x4B, 0x45, 0x59}; ///< "NEWECKEY".
  using Args = NoArgs; ///< The plan's arguments.
};

/// Number of irreversible operations: the contract test checks the list against this.
inline constexpr std::size_t kOperationCount = 13U;

/**
 * @brief A confirmation for operation `Op`: valid only when built from `Op::kPhrase`.
 *
 * `Confirmation<A>` and `Confirmation<B>` are unrelated types, so a confirmation cannot be reused.
 *
 * @tparam Op One of the operation tags above.
 */
template <typename Op>
class Confirmation {
public:
  /**
   * @brief Build a confirmation from a phrase.
   * @param phrase The phrase the caller passes back.
   */
  explicit constexpr Confirmation(const Phrase& phrase) noexcept
      : confirmed_(phrase == Op::kPhrase) {}

  /** @return true when the phrase matched `Op::kPhrase`. */
  [[nodiscard]] constexpr bool IsConfirmed() const noexcept {
    return confirmed_;
  }

private:
  bool confirmed_;
};

template <typename P>
class Operations;

/**
 * @brief The dry run of operation `Op`: what it would do, built without sending anything.
 *
 * Only `Operations<P>` creates a prepared plan; the default value is not prepared and every
 * operation refuses it with `IrreversibleNotConfirmed`.
 *
 * @tparam Op One of the operation tags above.
 */
template <typename Op>
class Plan {
public:
  /** @brief The unprepared plan. */
  constexpr Plan() noexcept = default;

  /** @return true when `Operations::Plan...` produced this plan. */
  [[nodiscard]] constexpr bool IsPrepared() const noexcept {
    return prepared_;
  }
  /** @return The object the operation acts on, or 0 when it acts on the whole chip. */
  [[nodiscard]] constexpr ObjectId Target() const noexcept {
    return target_;
  }
  /** @return A static one-line description of the effect, for the operator's confirmation prompt.
   */
  [[nodiscard]] constexpr const char* Effect() const noexcept {
    return effect_;
  }
  /** @return The arguments the operation will send. */
  [[nodiscard]] constexpr const typename Op::Args& Arguments() const& noexcept {
    return args_;
  }
  /** @brief Not on a temporary: the reference would dangle. */
  void Arguments() const&& = delete;

private:
  template <typename P>
  friend class Operations;

  constexpr Plan(ObjectId target, const char* effect, const typename Op::Args& args,
                 const void* owner) noexcept
      : prepared_(true), target_(target), effect_(effect), args_(args), owner_(owner) {}

  bool prepared_{false};
  ObjectId target_{};
  const char* effect_{""};
  typename Op::Args args_{};
  const void* owner_{nullptr}; ///< The `Operations` object that prepared it.
};

/**
 * @brief The caller's acknowledgement that a command may reset the chip without answering
 * (`TriggerSelfTest`): not irreversible, so not behind the build flag, but explicit.
 */
struct ResetExpected {
  /** @brief The only value. */
  constexpr ResetExpected() noexcept = default;
};

static_assert(Confirmation<DeleteAllObjects>{DeleteAllObjects::kPhrase}.IsConfirmed());
static_assert(!Confirmation<DeleteAllObjects>{SetLockStatePersistent::kPhrase}.IsConfirmed());
static_assert(!Plan<DeleteAllObjects>{}.IsPrepared());

/** @} */

} // namespace se05x::irreversible

#endif // SE05X_CONFIRM_HPP
