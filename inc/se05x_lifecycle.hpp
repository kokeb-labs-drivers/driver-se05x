/**
 * @file se05x_lifecycle.hpp
 * @brief Lifecycle preconditions as types: which authenticated session role a management command
 * needs, and what its reply does to the channel.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Frozen contract and fully implemented (it is data). A management command that the chip accepts
 * only in a session authenticated by a reserved object is refused by `Device` with
 * `Error::ConditionsNotSatisfied` before anything is sent, unless the session role matches
 * (design S-11). The role comes from the reserved authentication object the session was opened with
 * (`RoleOf(ObjectId)`).
 */
#ifndef SE05X_LIFECYCLE_HPP
#define SE05X_LIFECYCLE_HPP

#include <cstdint>

#include "se05x_commands.hpp"
#include "se05x_detail.hpp"
#include "se05x_ids.hpp"

namespace se05x {

/**
 * @defgroup se05x_lifecycle Lifecycle preconditions
 * @brief `AuthRole`, `RequiredRole`, `RoleOf` and the reply handling.
 * @{
 */

/** @brief What the session now open is authenticated as. */
enum class AuthRole : uint8_t {
  None = 0,        ///< No session, or the default session.
  User = 1,        ///< A session on a user-created authentication object.
  Transport = 2,   ///< `ReservedId::Transport`: `SetLockState`.
  PlatformScp = 3, ///< `ReservedId::PlatformScp`: `SetPlatformScpRequest`.
  Feature = 4,     ///< `ReservedId::Feature`: `SetAppletFeatures` (NXP-owned, AN12543 3.2.4.1.1.4).
  FactoryReset = 5, ///< `ReservedId::FactoryReset`: `DeleteAll`.
  Restrict = 6,     ///< `ReservedId::Restrict`: `DisableObjCreation` (AN12543 4.6.3).
};

namespace detail {
/// Last enumerator of `AuthRole`.
template <>
struct EnumLast<AuthRole> {
  static constexpr AuthRole kValue = AuthRole::Restrict; ///< The last enumerator.
};
} // namespace detail

/**
 * @brief The role a command needs: the reserved credential its session must have been opened with
 * (AN12543 4.6.1 `SetLockState`, 4.6.2 `SetPlatformSCPRequest`, 4.6.3 `DisableObjectCreation`,
 * 4.6.4 `SetAppletFeatures`, 4.6.5 `DeleteAll`).
 * @param command The command.
 * @return `AuthRole::None` when it needs none.
 */
constexpr AuthRole RequiredRole(Command command) noexcept {
  if (command == Command::SetLockState) {
    return AuthRole::Transport;
  }
  if (command == Command::SetPlatformScpRequest) {
    return AuthRole::PlatformScp;
  }
  if (command == Command::SetAppletFeatures) {
    return AuthRole::Feature;
  }
  if (command == Command::DeleteAll) {
    return AuthRole::FactoryReset;
  }
  if (command == Command::DisableObjCreation) {
    return AuthRole::Restrict;
  }
  return AuthRole::None;
}

/**
 * @brief The role a session gets from its authentication object.
 * @param credential The authentication object the session was opened with.
 * @return The role; `User` for an object that is not one of the reserved ones.
 */
constexpr AuthRole RoleOf(ObjectId credential) noexcept {
  if (credential == FromReserved(ReservedId::Transport)) {
    return AuthRole::Transport;
  }
  if (credential == FromReserved(ReservedId::PlatformScp)) {
    return AuthRole::PlatformScp;
  }
  if (credential == FromReserved(ReservedId::Feature)) {
    return AuthRole::Feature;
  }
  if (credential == FromReserved(ReservedId::FactoryReset)) {
    return AuthRole::FactoryReset;
  }
  if (credential == FromReserved(ReservedId::Restrict)) {
    return AuthRole::Restrict;
  }
  return AuthRole::User;
}

/**
 * @brief Whether the reply of a command is not secure-messaging wrapped even inside a secured
 * session.
 *
 * `DeleteAll` answers in the clear: a wrapped-reply check would fail, so the channel is marked
 * closed when the command returns (AN13030 p. 615) and the caller opens a new one.
 *
 * @param command The command.
 * @return true when the session ends with the reply.
 */
constexpr bool ReplyEndsSession(Command command) noexcept {
  return command == Command::DeleteAll;
}

/**
 * @brief Whether the chip may reset itself without sending a response (`TriggerSelfTest` on a
 * failure).
 * @param command The command.
 * @return true when the caller must have acknowledged `irreversible::ResetExpected`.
 */
constexpr bool MayResetWithoutReply(Command command) noexcept {
  return command == Command::TriggerSelfTest;
}

static_assert(RequiredRole(Command::DeleteAll) == AuthRole::FactoryReset);
static_assert(RequiredRole(Command::DisableObjCreation) == AuthRole::Restrict);
static_assert(RoleOf(FromReserved(ReservedId::Restrict)) == AuthRole::Restrict);
static_assert(RequiredRole(Command::GetRandom) == AuthRole::None);
static_assert(RoleOf(FromReserved(ReservedId::Transport)) == AuthRole::Transport);
static_assert(RoleOf(ObjectId{0x1000U}) == AuthRole::User);
static_assert(ReplyEndsSession(Command::DeleteAll) && !ReplyEndsSession(Command::SetLockState));

/** @} */

} // namespace se05x

#endif // SE05X_LIFECYCLE_HPP
