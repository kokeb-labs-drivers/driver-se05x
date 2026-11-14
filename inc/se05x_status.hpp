/**
 * @file se05x_status.hpp
 * @brief The error model of the SE05X driver: `Error`, `Detail`, `Result<T>`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Frozen contract (see `docs/contract.md`): a change here is a breaking change and goes through the
 * contract amendment rule in `docs/builders.md`. Every call of every layer returns an `Error`
 * inside a `Result`. `NotInitialized` wins over `InvalidArgument`; `InvalidArgument` sends nothing;
 * the raw status word of the chip is in `Detail` only. One status word maps to different errors by
 * command context (SW 0x6985 after `CloseSession` without a session is `NeedsReselect`, not
 * `ConditionsNotSatisfied`).
 */
#ifndef SE05X_STATUS_HPP
#define SE05X_STATUS_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "se05x_detail.hpp"

namespace se05x {

/**
 * @defgroup se05x_status Error model
 * @brief Errors, details and results.
 * @{
 */

/**
 * @brief Why a call failed. Values 0 to 9 are the base set every driver of the org shares, 16 and
 * up are specific to this chip family.
 */
enum class [[nodiscard]] Error : uint8_t {
  // Base set (standards/driver.md).
  Ok = 0,              ///< The call succeeded.
  NotInitialized = 1,  ///< `Open()` has not succeeded, or `Close()` ran since.
  InvalidArgument = 2, ///< An argument or `Config` field is out of range; nothing was sent.
  Bus = 3,             ///< The I2C port failed (arbitration lost, hook returned a bus error).
  Timeout = 4,         ///< A bounded wait ended: block waiting time, WTX budget or command timeout.
  DeviceIdMismatch = 5, ///< The chip is not the expected family or applet.
  Crc = 6,              ///< A T=1 frame failed its CRC16 and the retry budget is spent.
  Busy = 7,             ///< A command is in flight; one command at a time (errata I2C.1).
  DeviceFault = 8,      ///< The chip reported an internal error (SW 0x6F00 and friends).
  Unsupported = 9,      ///< The capability gate refuses the command for this chip or configuration.
  // Chip specific.
  BufferTooSmall =
      16, ///< A caller buffer, a frame or a response budget is too small; nothing was lost.
  WrongState = 17,    ///< Locked applet, SCP required, no session, or an object of another class.
  Nack = 18,          ///< The chip did not acknowledge its address (not ready, or absent).
  BusStuck = 19,      ///< SCL or SDA held low; only a power cycle clears errata I2C.1.
  TransportDead = 20, ///< The recovery ladder is exhausted; the link is closed.
  FrameError = 21,    ///< A T=1 frame is malformed (NAD, PCB, length, block sequence).
  Resynced =
      22, ///< The link resynchronised: the command is not repeated, the caller re-authenticates.
  NeedsReselect = 23,  ///< The applet must be selected again before the next command.
  ObjectNotFound = 24, ///< No object with that id (SW 0x6A82).
  ObjectExists = 25,   ///< An object with that id exists.
  PolicyDenied = 26,   ///< The object policy does not allow this operation (SW 0x6986 or 0x6982).
  PolicyInvalid =
      27,          ///< A policy was refused: by the builder or by the chip (SW 0x6A80 on creation).
  AuthFailed = 28, ///< Authentication failed; `attempts_left` is in the details when known.
  AuthLocked =
      29, ///< The authentication object is blocked or the host-side attempt limit is reached.
  ConditionsNotSatisfied = 30, ///< SW 0x6985 with a context that has no better name.
  MemoryFull = 31,             ///< No room for the object (SW 0x6A84, or 0x6985 on applet 3.x).
  SecureChannelError =
      32, ///< A MAC, cryptogram, padding or counter check failed; the channel is closed.
  AttestationInvalid = 33, ///< Attestation freshness, timestamp or signature check failed.
  Counterfeit = 34, ///< The unique id or certificate chain does not match the expected device.
  IrreversibleNotConfirmed = 35, ///< An irreversible operation was called without its confirmation.
  ChipSwUnknown = 36,  ///< A status word this driver has no mapping for (see `Detail::sw`).
  CryptoFailure = 37,  ///< The crypto port failed or refused a key handle.
  NotImplemented = 38, ///< Not part of this version; no call returns it today.
  ThroughputLimited =
      39, ///< SW 0x66A6: the chip refuses every command until it is reset (APDU budget, S-17).
};

namespace detail {
/// Names of the errors, indexed by value; `nullptr` in the gap between the base set and the chip
/// range.
inline constexpr std::array<const char*, 40> kErrorNames{"Ok",
                                                         "NotInitialized",
                                                         "InvalidArgument",
                                                         "Bus",
                                                         "Timeout",
                                                         "DeviceIdMismatch",
                                                         "Crc",
                                                         "Busy",
                                                         "DeviceFault",
                                                         "Unsupported",
                                                         nullptr,
                                                         nullptr,
                                                         nullptr,
                                                         nullptr,
                                                         nullptr,
                                                         nullptr,
                                                         "BufferTooSmall",
                                                         "WrongState",
                                                         "Nack",
                                                         "BusStuck",
                                                         "TransportDead",
                                                         "FrameError",
                                                         "Resynced",
                                                         "NeedsReselect",
                                                         "ObjectNotFound",
                                                         "ObjectExists",
                                                         "PolicyDenied",
                                                         "PolicyInvalid",
                                                         "AuthFailed",
                                                         "AuthLocked",
                                                         "ConditionsNotSatisfied",
                                                         "MemoryFull",
                                                         "SecureChannelError",
                                                         "AttestationInvalid",
                                                         "Counterfeit",
                                                         "IrreversibleNotConfirmed",
                                                         "ChipSwUnknown",
                                                         "CryptoFailure",
                                                         "NotImplemented",
                                                         "ThroughputLimited"};
} // namespace detail

/**
 * @brief The name of an error, for logs.
 * @param error The error.
 * @return A static string such as `"Timeout"`; `"Unknown"` for a value that is not an enumerator.
 */
constexpr const char* ToString(Error error) noexcept {
  const auto index = static_cast<std::size_t>(static_cast<uint8_t>(error));
  if ((index < detail::kErrorNames.size()) && (detail::kErrorNames[index] != nullptr)) {
    return detail::kErrorNames[index];
  }
  return "Unknown";
}

/** @brief The layer that produced an error, for `Detail` and log records. */
enum class Layer : uint8_t {
  None = 0,   ///< No layer (success).
  Port = 1,   ///< A port hook (bus, clock, reset, crypto).
  T1 = 2,     ///< The T=1 link.
  Apdu = 3,   ///< APDU encoding, TLV parsing or status word mapping.
  Scp03 = 4,  ///< Platform SCP03 or an AESKey session.
  EcKey = 5,  ///< An ECKey session.
  Gp = 6,     ///< The GlobalPlatform card manager.
  Device = 7, ///< The command layer (gate, sessions).
  Hrot = 8,   ///< The facade.
  Pki = 9,    ///< The optional PKI layer (`se05x::pki`): `step` holds the `pki::Reason`.
};

namespace detail {
/// Last enumerator of `Layer` (detail::IsEnumerator).
template <>
struct EnumLast<Layer> {
  static constexpr Layer kValue = Layer::Pki; ///< The last enumerator.
};
} // namespace detail

/**
 * @brief Where and why a call failed, beyond the `Error`. Plain data, no secrets: the status word,
 * a command number and counters only.
 */
struct Detail {
  uint16_t sw{0};              ///< Raw ISO 7816 status word of the chip; 0 when there was none.
  uint8_t command{0};          ///< `Command` value of the command in flight; 0xFF when none.
  Layer layer{Layer::None};    ///< The layer that produced the error.
  uint8_t step{0};             ///< Layer-specific step number (frame index, authentication step).
  uint8_t attempts_left{0xFF}; ///< Authentication attempts left when the chip said so, else 0xFF.
};

/**
 * @brief The value of a call, or why there is none.
 *
 * Check `ok()` (or the `bool` conversion) before reading `value`; on failure `value` is `T{}`.
 *
 * @tparam T The value type. `Result<void>` carries only the error and the detail.
 */
template <typename T>
struct [[nodiscard]] Result {
  T value{};              ///< The value; `T{}` when the call failed.
  Error error{Error::Ok}; ///< `Error::Ok` on success.
  Detail detail{};        ///< Details of a failure; default when the call succeeded.

  /** @return true when the call succeeded. */
  [[nodiscard]] constexpr bool ok() const noexcept {
    return error == Error::Ok;
  }
  /** @return true when the call succeeded. */
  constexpr explicit operator bool() const noexcept {
    return ok();
  }

  /**
   * @brief A successful result.
   * @param v The value.
   * @return `{v, Error::Ok, {}}`.
   */
  static constexpr Result Success(T v) noexcept {
    Result r{};
    r.value = v;
    return r;
  }
  /**
   * @brief A failed result.
   * @param e Why it failed; never `Error::Ok`.
   * @param d Details, when known.
   * @return `{T{}, e, d}`.
   */
  static constexpr Result Failure(Error e, Detail d = Detail{}) noexcept {
    Result r{};
    r.error = e;
    r.detail = d;
    return r;
  }
};

/** @brief The result of a call that returns no value. */
template <>
struct [[nodiscard]] Result<void> {
  Error error{Error::Ok}; ///< `Error::Ok` on success.
  Detail detail{};        ///< Details of a failure; default when the call succeeded.

  /** @return true when the call succeeded. */
  [[nodiscard]] constexpr bool ok() const noexcept {
    return error == Error::Ok;
  }
  /** @return true when the call succeeded. */
  constexpr explicit operator bool() const noexcept {
    return ok();
  }

  /** @return A successful result. */
  static constexpr Result Success() noexcept {
    return Result{};
  }
  /**
   * @brief A failed result.
   * @param e Why it failed; never `Error::Ok`.
   * @param d Details, when known.
   * @return `{e, d}`.
   */
  static constexpr Result Failure(Error e, Detail d = Detail{}) noexcept {
    Result r{};
    r.error = e;
    r.detail = d;
    return r;
  }
};

/**
 * @brief A failure with `Error::NotImplemented`, for a layer that is not part of this version.
 *
 * Nothing in this version returns it; it never succeeds and never touches a port.
 *
 * @tparam T The value type of the call being stubbed.
 * @param layer The layer of the stub, for the details.
 * @return `Result<T>::Failure(Error::NotImplemented)`.
 */
template <typename T>
constexpr Result<T> NotImplemented(Layer layer) noexcept {
  return Result<T>::Failure(Error::NotImplemented,
                            Detail{.sw = static_cast<uint16_t>(0U),
                                   .command = static_cast<uint8_t>(0xFFU),
                                   .layer = layer,
                                   .step = static_cast<uint8_t>(0U),
                                   .attempts_left = static_cast<uint8_t>(0xFFU)});
}

/** @} */

} // namespace se05x

#endif // SE05X_STATUS_HPP
