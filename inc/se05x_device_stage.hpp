/**
 * @file se05x_device_stage.hpp
 * @brief The transport stack under `Device`: the link stage, the applet stage that runs over
 * platform SCP03 or the plain link, and the command classification the device uses.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * The stack of a `Device` is fixed at compile time and chosen at run time:
 *
 * ```text
 *  applet session (one at a time)   UserIdSession | Channel(AESKey) | eckey::Session
 *                                              \          |          /
 *  AppletStage                      platform SCP03 Channel when the device opened it, else the link
 *                                              \                     /
 *  LinkStage                        t1::Link with the timeout class of the command in flight
 * ```
 *
 * `AppletStage` is the one place that decides whether an applet command travels under platform
 * SCP03. Once the device has opened platform SCP03 it never falls back to the plain link: while
 * the platform channel is closed (after a failed check, a reset, a lost frame) the stage refuses
 * every command with `SecureChannelError` and sends nothing, until `Device::Recover()` opens the
 * channel again (S-07, S-13: no silent downgrade). `Block()` makes the stage refuse everything
 * with `NeedsReselect` while the device tears its sessions down after a reset: their best-effort
 * CloseSession then sends nothing to a chip that has no session (errata APP.2).
 */
#ifndef SE05X_DEVICE_STAGE_HPP
#define SE05X_DEVICE_STAGE_HPP

#include <concepts>
#include <cstddef>
#include <cstdint>

#include "se05x_commands.hpp"
#include "se05x_policy_types.hpp"
#include "se05x_ports.hpp"
#include "se05x_scp03.hpp"
#include "se05x_status.hpp"
#include "se05x_t1.hpp"
#include "se05x_types.hpp"

namespace se05x::detail {

/**
 * @brief The lowest stage: the T=1 link, with the timeout class of the command in flight
 * (`Config::timeouts`, ambiguity A11).
 * @tparam P A `Ports<...>` set.
 */
template <PortSet P>
class LinkStage {
public:
  /**
   * @brief Bind. No I/O.
   * @param link The link; it must outlive the stage.
   */
  explicit LinkStage(t1::Link<P>& link) noexcept : link_(&link) {}
  /** @brief One per device. */
  LinkStage(const LinkStage&) = delete;
  /** @brief One per device. */
  LinkStage& operator=(const LinkStage&) = delete;
  /** @brief Nothing to release. */
  ~LinkStage() noexcept = default;

  /**
   * @brief Send one command APDU over the link with the class set by `SetClass()`.
   * @param command The command.
   * @param response The response buffer.
   * @return The link's result.
   */
  Result<std::size_t> Transceive(ByteSpan command, MutableByteSpan response) noexcept {
    return link_->Transceive(command, response, class_);
  }
  /** @brief The timeout class of the next commands. @param command_class The class. */
  void SetClass(CommandClass command_class) noexcept {
    class_ = command_class;
  }

private:
  t1::Link<P>* link_;
  CommandClass class_{CommandClass::Fast};
};

/**
 * @brief The stage applet commands and applet sessions run on: platform SCP03 when the device
 * opened it, the link otherwise; never a silent fall-back to the link (see the file comment).
 * @tparam P A `Ports<...>` set.
 */
template <PortSet P>
class AppletStage {
public:
  /// The platform channel type.
  using Platform = scp03::Channel<P, LinkStage<P>>;

  /**
   * @brief Bind. No I/O.
   * @param link The link stage.
   * @param platform The platform SCP03 channel over the same link stage.
   */
  AppletStage(LinkStage<P>& link, Platform& platform) noexcept
      : link_(&link), platform_(&platform) {}
  /** @brief One per device. */
  AppletStage(const AppletStage&) = delete;
  /** @brief One per device. */
  AppletStage& operator=(const AppletStage&) = delete;
  /** @brief Nothing to release. */
  ~AppletStage() noexcept = default;

  /**
   * @brief Send one command APDU.
   * @param command The command.
   * @param response The response buffer.
   * @return The result of the platform channel or of the link; `NeedsReselect` while blocked and
   * `SecureChannelError` while platform SCP03 is required and closed (nothing sent in both).
   */
  Result<std::size_t> Transceive(ByteSpan command, MutableByteSpan response) noexcept {
    if (blocked_) {
      return Result<std::size_t>::Failure(Error::NeedsReselect, kStageDetail);
    }
    if (platform_required_) {
      if (!platform_->IsOpen()) {
        return Result<std::size_t>::Failure(Error::SecureChannelError, kStageDetail);
      }
      count();
      return platform_->Transceive(command, response);
    }
    count();
    return link_->Transceive(command, response);
  }
  /** @return The APDUs handed down so far (saturating). No I/O. */
  [[nodiscard]] uint32_t Sent() const noexcept {
    return sent_;
  }
  /** @brief Require platform SCP03 for every command from now on. @param on Whether. */
  void RequirePlatform(bool on) noexcept {
    platform_required_ = on;
  }
  /** @return Whether platform SCP03 is required. */
  [[nodiscard]] bool PlatformRequired() const noexcept {
    return platform_required_;
  }
  /** @brief Refuse every command with `NeedsReselect`, sending nothing. @param on Whether. */
  void Block(bool on) noexcept {
    blocked_ = on;
  }

private:
  static constexpr Detail kStageDetail{
      .sw = 0U, .command = 0xFFU, .layer = Layer::Device, .step = 0U, .attempts_left = 0xFFU};

  LinkStage<P>* link_;
  Platform* platform_;
  bool platform_required_{false};
  uint32_t sent_{0}; ///< APDUs handed to the link or the platform channel.

  void count() noexcept {
    sent_ = SaturatingAdd(sent_, 1U);
  }
  bool blocked_{false};
};

/**
 * @brief Whether a command belongs to the device itself: the select, the session handshake steps
 * and `TriggerSelfTest` (which may reset the chip without an answer). Sending one through
 * `Execute<C>()` would leave the device's view of the chip wrong, so `Execute` does not compile
 * for them; `Open()`, `Recover()`, the `Begin...Session()` calls and `TriggerSelfTest()` run them.
 * @param command The command.
 * @return true for a command `Execute` refuses at compile time.
 */
constexpr bool IsDeviceOwned(Command command) noexcept {
  return (command == Command::SelectApplet) || (command == Command::CreateSession) ||
         (command == Command::CloseSession) || (command == Command::VerifySessionUserId) ||
         (command == Command::ScpInitializeUpdate) ||
         (command == Command::ScpExternalAuthenticate) ||
         (command == Command::EcKeySessionInternalAuthenticate) ||
         (command == Command::TriggerSelfTest);
}

/**
 * @brief Whether a command goes to the card manager (GP GET DATA): the device selects the card
 * manager, sends it, then selects the IoT applet again.
 * @param command The command.
 * @return true for `GetCardIdentification`, `GetCplc` and `CmInvokeGarbageCollection`.
 */
constexpr bool IsCardManagerCommand(Command command) noexcept {
  return (command == Command::GetCardIdentification) || (command == Command::GetCplc) ||
         (command == Command::CmInvokeGarbageCollection);
}

/**
 * @brief The timeout class of a command (ambiguity A11): key generation, KDFs, attested reads and
 * RSA private-key operations get longer deadlines than the rest.
 * @param command The command.
 * @return The class.
 */
constexpr CommandClass ClassOf(Command command) noexcept {
  if ((command == Command::GenerateRsaKey) || (command == Command::GenerateEcKey)) {
    return CommandClass::KeyGen;
  }
  if ((command == Command::Pbkdf2) || (command == Command::Hkdf) ||
      (command == Command::TlsPerformPrf) || (command == Command::TlsCalculatePreMasterSecret)) {
    return CommandClass::Kdf;
  }
  if ((command == Command::ReadObjectAttested) ||
      (command == Command::ReadObjectAttributesAttested) || (command == Command::ReadRsaAttested) ||
      (command == Command::I2cmExecuteCommandSetAttested) || (command == Command::RsaSign) ||
      (command == Command::RsaDecrypt) || (command == Command::TriggerSelfTest)) {
    return CommandClass::Attest;
  }
  return CommandClass::Fast;
}

/// An argument type that carries a policy (`const Policy* policy`).
template <typename A>
concept HasPolicy = requires(const A& args) {
  { args.policy } -> std::convertible_to<const Policy*>;
};

/**
 * @brief The policy an argument carries, for the generation check of `Device`.
 * @tparam A The argument type.
 * @param args The arguments.
 * @return The policy, or null when the type has none.
 */
template <typename A>
constexpr const Policy* PolicyOf(const A& args) noexcept {
  if constexpr (HasPolicy<A>) {
    return args.policy;
  } else {
    static_cast<void>(args);
    return nullptr;
  }
}

/**
 * @brief Whether an ECKey session checks the chip's receipt (A15): on when the configuration or the
 * call asks for it, so a call cannot turn off a check the configuration wants.
 * @param config_wants `Config::verify_eckey_receipt`.
 * @param call_wants `eckey::SessionParams::verify_receipt`.
 * @return true when the receipt is checked.
 */
constexpr bool VerifyReceipt(bool config_wants, bool call_wants) noexcept {
  return config_wants || call_wants;
}

/**
 * @brief The command in the shortest Lc form, without Le: an extended Lc (`00 hi lo`) of at most
 * 255 bytes becomes one byte. A command that is already short, has no data or does not fit `out`
 * comes back unchanged.
 * @param command A well-formed command APDU.
 * @param out The buffer for the rewritten command.
 * @return The rewritten command (in `out`) or `command`.
 */
constexpr ByteSpan ShortestLcForm(ByteSpan command, MutableByteSpan out) noexcept {
  const std::size_t n = command.size();
  if ((n <= 7U) || (command[4] != 0U)) {
    return command;
  }
  const std::size_t lc = (static_cast<std::size_t>(command[5]) << 8U) | command[6];
  if ((lc == 0U) || (lc > 255U) || ((7U + lc) > n) || ((5U + lc) > out.size())) {
    return command;
  }
  for (std::size_t i = 0U; i < 4U; ++i) {
    out[i] = command[i];
  }
  out[4] = static_cast<uint8_t>(lc);
  for (std::size_t i = 0U; i < lc; ++i) {
    out[5U + i] = command[7U + i];
  }
  return ByteSpan{out.data(), 5U + lc};
}

/**
 * @brief The TLVs of an attested answer before the signature TLV (tag 0x52), as returned: what a
 * format 2 signature covers after the command digest (AN12543 Table 128 p. 91). Lengths in the
 * one-byte, `81 xx` and `82 xx xx` forms are read; a malformed list gives an empty span.
 * @param body The response body, without the status word.
 * @return The bytes up to the signature TLV, or empty when there is none or the list is malformed.
 */
constexpr ByteSpan SignedTlvs(ByteSpan body) noexcept {
  std::size_t at = 0U;
  while ((at + 2U) <= body.size()) {
    if (body[at] == 0x52U) {
      return body.first(at);
    }
    std::size_t length = body[at + 1U];
    std::size_t head = 2U;
    if (length == 0x81U) {
      length = ((at + 3U) <= body.size()) ? body[at + 2U] : body.size();
      head = 3U;
    } else if (length == 0x82U) {
      length = ((at + 4U) <= body.size())
                   ? ((static_cast<std::size_t>(body[at + 2U]) << 8U) | body[at + 3U])
                   : body.size();
      head = 4U;
    } else if (length > 0x80U) {
      return ByteSpan{};
    } else {
      // one-byte length
    }
    if ((at + head + length) > body.size()) {
      return ByteSpan{};
    }
    at += head + length;
  }
  return ByteSpan{};
}

static_assert(IsDeviceOwned(Command::CreateSession) && !IsDeviceOwned(Command::GetRandom));
static_assert(ClassOf(Command::GenerateRsaKey) == CommandClass::KeyGen);
static_assert(ClassOf(Command::GetRandom) == CommandClass::Fast);

} // namespace se05x::detail

#endif // SE05X_DEVICE_STAGE_HPP
