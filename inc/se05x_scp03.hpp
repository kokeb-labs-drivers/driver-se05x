/**
 * @file se05x_scp03.hpp
 * @brief GlobalPlatform SCP03 as a secure `ApduTransport` (platform SCP03 and the applet AESKey
 * session), the applet session framing, and the UserID session.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Sources: GlobalPlatform Card Specification Amendment D (SCP03) as AN12543 and
 * AN12413 apply it (AN12543 3.5, 3.6.3.2, 4.5.3; AN12413 3.4.2), errata JOS.2 (SE050 errata sheet
 * 3.13), and the NXP middleware read as an oracle for the counter behaviour the chip shows. No
 * platform key of any chip is in this repository: keys arrive as `KeyRef` handles (S-16).
 *
 * `Channel` wraps a lower transport (the link): `Open()` runs INITIALIZE UPDATE and EXTERNAL
 * AUTHENTICATE, `Transceive()` wraps the command (C-MAC, C-DECRYPTION), sends it and unwraps the
 * response (R-MAC, R-ENCRYPTION), `Close()` releases every session key. The rules:
 *
 * - Session keys come from the SCP03 KDF (NIST SP 800-108 counter mode with AES-CMAC): S-ENC from
 *   the static ENC key, S-MAC and S-RMAC from the static MAC key, context host challenge || card
 *   challenge. The card cryptogram is checked before anything is sent with the keys.
 * - C-MAC chaining: every C-MAC is CMAC(S-MAC, MCV || header || Lc || data); the full 16-byte
 *   result becomes the next MCV. The first MCV, for EXTERNAL AUTHENTICATE, is 16 zero bytes.
 * - The encryption counter starts at 1 after EXTERNAL AUTHENTICATE, only ever increases (S-16:
 *   never rewound) and the channel closes rather than wrap it. The command ICV is
 *   AES(S-ENC, counter); the response ICV is AES(S-ENC, 0x80 || counter bytes 1..15).
 * - Errata JOS.2: in platform SCP03 the chip advances its counter only for a command with data, and
 *   answers a command without data under the counter of the previous command. With
 *   `ChannelParams::jos2_counter_rule` (default) the channel does the same; without it the counter
 *   advances for every command, as in an applet session.
 * - The R-MAC is checked on every response with SW 9000, short ones included (the middleware
 *   defect fixed in v04.08.02), with `ct::Equal` (S-08). A response with another status word must
 *   be the two status bytes only: SCP03 adds no R-MAC to an error, so its status word is not
 *   authenticated (the caller must not act on it as if it were). Anything else is
 *   `SecureChannelError`.
 * - Any failure after the handshake started, a failed check, or a lower-transport error closes the
 *   channel and releases its keys (S-07); a channel never survives a link reset (S-15).
 *
 * The applet's sessions (AN12543 3.6) are framed by `session::Framer`: CreateSession, then every
 * command inside `ProcessSessionCmd` with the 8-byte session id. An AESKey session is a `Channel`
 * with `ChannelKind::AesKeySession`. `session::UserIdSession` opens a UserID session: it carries
 * no secure messaging (S-14), counts failed attempts on the host, and is marked so that no secure
 * channel can be stacked on it.
 */
#ifndef SE05X_SCP03_HPP
#define SE05X_SCP03_HPP

#include <algorithm>
#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>

#include "se05x_ids.hpp"
#include "se05x_ports.hpp"
#include "se05x_secret.hpp"
#include "se05x_status.hpp"
#include "se05x_types.hpp"

namespace se05x::scp03 {

/**
 * @defgroup se05x_scp03 SCP03
 * @brief The SCP03 secure channel and the applet sessions.
 * @{
 */

/** @brief The security level of the channel (GP Amendment D; AN12543 Table 10). */
enum class SecurityLevel : uint8_t {
  CMac = 0,         ///< Command MAC (0x01).
  CMacCDecrypt = 1, ///< Command MAC and decryption (0x03).
  CMacRMac = 2,     ///< Command MAC, response MAC (0x11).
  Full = 3,         ///< Command MAC and decryption, response MAC and encryption (0x33).
};

/** @brief The AES key length of the key set. */
enum class KeyLength : uint8_t {
  Aes128 = 0, ///< AES-128.
  Aes256 = 1, ///< AES-256 (platform SCP03 only; an AESKey session object is 128 bit).
};

/** @brief Which secure channel `Channel::Open()` sets up. */
enum class ChannelKind : uint8_t {
  Platform = 0,      ///< Platform SCP03 with the card manager (no applet session).
  AesKeySession = 1, ///< An applet AESKey session (AN12543 3.6.3.2): CreateSession, then SCP03.
};

/** @brief The static key set as handles: ENC, MAC and DEK (S-16). */
struct StaticKeys {
  KeyRef enc{}; ///< Static encryption key; for an AESKey session the session's AES key.
  KeyRef mac{}; ///< Static MAC key; for an AESKey session leave it empty (the AES key serves).
  KeyRef dek{}; ///< Static data encryption key (key rotation only; not used by the channel).
};

/** @brief What `Channel::Open()` needs. */
struct ChannelParams {
  StaticKeys keys{};      ///< The static keys.
  uint8_t key_version{0}; ///< The key version number to select, 0 for the chip's default.
  SecurityLevel level{SecurityLevel::Full}; ///< The requested level.
  KeyLength length{KeyLength::Aes128};      ///< The key length.
  bool jos2_counter_rule{true}; ///< Platform SCP03: advance the counter only for commands with
                                ///< data, as the chip does (errata JOS.2).
  ChannelKind kind{ChannelKind::Platform}; ///< Platform SCP03 or an AESKey session.
  ObjectId credential{}; ///< The AESKey authentication object; AESKey sessions only.
};

/**
 * @name Wire constants (GP Amendment D as AN12543 applies it)
 * @{
 */
inline constexpr uint8_t kClaGp = 0x80U;                   ///< CLA of a proprietary command.
inline constexpr uint8_t kClaSecureMessaging = 0x04U;      ///< CLA bit of secure messaging.
inline constexpr uint8_t kInsInitializeUpdate = 0x50U;     ///< INITIALIZE UPDATE.
inline constexpr uint8_t kInsExternalAuthenticate = 0x82U; ///< EXTERNAL AUTHENTICATE.
inline constexpr std::size_t kChallengeBytes = 8U;         ///< Host and card challenge.
inline constexpr std::size_t kCryptogramBytes = 8U;        ///< Host and card cryptogram.
inline constexpr std::size_t kMacBytes = 8U;               ///< C-MAC and R-MAC on the wire.
inline constexpr std::size_t kMcvBytes = 16U;              ///< MAC chaining value.
inline constexpr uint8_t kScp03Id = 0x03U;                 ///< SCP identifier in the key info.
inline constexpr uint8_t kDdCardCryptogram = 0x00U;        ///< KDF constant: card cryptogram.
inline constexpr uint8_t kDdHostCryptogram = 0x01U;        ///< KDF constant: host cryptogram.
inline constexpr uint8_t kDdSEnc = 0x04U;                  ///< KDF constant: S-ENC.
inline constexpr uint8_t kDdSMac = 0x06U;                  ///< KDF constant: S-MAC.
inline constexpr uint8_t kDdSRmac = 0x07U;                 ///< KDF constant: S-RMAC.
inline constexpr uint8_t kDdInitialMcv = 0x08U; ///< KDF constant of the ECKey initial MCV (oracle).
inline constexpr uint8_t kLevelCMac = 0x01U;    ///< Level bit C-MAC.
inline constexpr uint8_t kLevelCDecrypt = 0x02U; ///< Level bit C-DECRYPTION.
inline constexpr uint8_t kLevelRMac = 0x10U;     ///< Level bit R-MAC.
inline constexpr uint8_t kLevelREncrypt = 0x20U; ///< Level bit R-ENCRYPTION.
/** @} */

/**
 * @param level The level.
 * @return Its GP byte (0x01, 0x03, 0x11, 0x33), 0 for a value that is not an enumerator.
 */
constexpr uint8_t LevelByte(SecurityLevel level) noexcept {
  switch (level) {
  case SecurityLevel::CMac:
    return kLevelCMac;
  case SecurityLevel::CMacCDecrypt:
    return static_cast<uint8_t>(uint32_t{kLevelCMac} | uint32_t{kLevelCDecrypt});
  case SecurityLevel::CMacRMac:
    return static_cast<uint8_t>(uint32_t{kLevelCMac} | uint32_t{kLevelRMac});
  case SecurityLevel::Full:
    return static_cast<uint8_t>(uint32_t{kLevelCMac} | uint32_t{kLevelCDecrypt} |
                                uint32_t{kLevelRMac} | uint32_t{kLevelREncrypt});
  default:
    break;
  }
  return 0U;
}

/** @} */

} // namespace se05x::scp03

namespace se05x::detail {
/// Last enumerator of `scp03::SecurityLevel`.
template <>
struct EnumLast<scp03::SecurityLevel> {
  static constexpr scp03::SecurityLevel kValue =
      scp03::SecurityLevel::Full; ///< The last enumerator.
};
/// Last enumerator of `scp03::KeyLength`.
template <>
struct EnumLast<scp03::KeyLength> {
  static constexpr scp03::KeyLength kValue = scp03::KeyLength::Aes256; ///< The last enumerator.
};
/// Last enumerator of `scp03::ChannelKind`.
template <>
struct EnumLast<scp03::ChannelKind> {
  static constexpr scp03::ChannelKind kValue =
      scp03::ChannelKind::AesKeySession; ///< The last enumerator.
};
} // namespace se05x::detail

/** @brief The applet session framing (AN12543 4.5.1, 4.5.2). */
namespace se05x::session {

/// The applet's session id length (AN12543 Table 68).
inline constexpr std::size_t kSessionIdBytes = 8U;
/// An applet session id.
using Id = std::array<uint8_t, kSessionIdBytes>;

/**
 * @name Applet session commands (AN12543 Tables 29, 67 to 84)
 * @{
 */
inline constexpr uint8_t kInsMgmt = 0x04U;         ///< INS_MGMT.
inline constexpr uint8_t kInsProcess = 0x05U;      ///< INS_PROCESS.
inline constexpr uint8_t kP2SessionCreate = 0x1BU; ///< P2_SESSION_CREATE.
inline constexpr uint8_t kP2SessionClose = 0x1CU;  ///< P2_SESSION_CLOSE.
inline constexpr uint8_t kP2SessionUserId = 0x2CU; ///< P2_SESSION_USERID.
inline constexpr uint8_t kTagSessionId = 0x10U;    ///< TAG_SESSION_ID.
inline constexpr uint8_t kTag1 = 0x41U;            ///< TAG_1.
/// Bytes the framing may add in front of a command: header, Lc, the session id and the TLV head.
inline constexpr std::size_t kFrameHeadroom = 32U;
/** @} */

/// A transport that is a UserID session: secure channels refuse to stack on it (S-14).
template <typename T>
concept UserIdTransport = requires { requires T::kUserIdSession; };

/**
 * @brief Run CreateSession for an authentication object (session-less, AN12543 4.5.1.1).
 * @tparam T The lower transport.
 * @param lower The transport.
 * @param credential The authentication object.
 * @param id The session id the chip returns.
 * @return `Ok`, `InvalidArgument` (id 0), `ThroughputLimited`, `ConditionsNotSatisfied` (SW
 * 6985: no such authentication object, or no session left), `FrameError` (malformed answer),
 * `ChipSwUnknown`, or the transport's error.
 */
template <ApduTransport T>
Result<void> CreateSession(T& lower, ObjectId credential, Id& id) noexcept;

/**
 * @brief Frame commands for one applet session: `ProcessSessionCmd` around each command
 * (AN12543 4.5.1.3). The framing is written in front of the command, inside the caller's buffer:
 * the command must start `kFrameHeadroom` bytes into it.
 */
class Framer {
public:
  /** @brief Not attached: commands pass unframed. */
  constexpr Framer() noexcept = default;

  /** @brief Attach to a session. @param id The session id from CreateSession. */
  constexpr void Attach(const Id& id) noexcept {
    id_ = id;
    attached_ = true;
  }
  /** @brief Forget the session (no I/O; the chip ends it at deselect or CloseSession). */
  constexpr void Detach() noexcept {
    id_ = Id{};
    attached_ = false;
  }
  /** @return true while attached. */
  [[nodiscard]] constexpr bool Attached() const noexcept {
    return attached_;
  }
  /**
   * @brief Frame the command at `buffer[kFrameHeadroom, kFrameHeadroom + length)`.
   * @param buffer The buffer; it needs 3 free bytes after the command for Le.
   * @param length The command length.
   * @return The framed command, a view into `buffer`; the command itself when not attached;
   * `BufferTooSmall` when the frame does not fit.
   */
  Result<ByteSpan> Frame(MutableByteSpan buffer, std::size_t length) const noexcept;

private:
  Id id_{};
  bool attached_{false};
};

} // namespace se05x::session

namespace se05x::scp03::detail {

/** @brief The parts of a command APDU (ISO 7816-4 cases 1 to 4, short and extended). */
struct CommandParts {
  std::array<uint8_t, 4> header{}; ///< CLA, INS, P1, P2.
  ByteSpan data;                   ///< The data field, empty for cases 1 and 2.
  bool has_le{false};              ///< Whether the command carries Le.
  bool extended{false};            ///< Whether it used the extended length form.
  uint32_t le{0};                  ///< Le as sent (0 means the maximum).
};

/**
 * @brief Split a command APDU.
 * @param apdu The command.
 * @return The parts, or `InvalidArgument` for a length that matches no case.
 */
constexpr Result<CommandParts> ParseCommand(ByteSpan apdu) noexcept;

/** @brief When the encryption counter advances. */
enum class CounterRule : uint8_t {
  EveryCommand = 0,     ///< After every command (applet sessions; GP Amendment D).
  DataCommandsOnly = 1, ///< Only after a command with data (platform SCP03 on the chip, JOS.2).
};

/**
 * @brief The encryption counter after a command (GP Amendment D 6.2.6): unchanged when the rule
 * does not advance it, else one more. A counter at its maximum is never wrapped back to a value
 * already used with these keys (S-16): the call fails and the owner closes the channel.
 * @param counter The counter now.
 * @param advances Whether the counter rule advances it after this command.
 * @param next The counter for the next command; `counter` when the call fails.
 * @return false when the counter would wrap.
 */
constexpr bool NextCounter(uint32_t counter, bool advances, uint32_t& next) noexcept {
  next = counter;
  if (!advances) {
    return true;
  }
  if (counter == 0xFFFFFFFFU) {
    return false;
  }
  next = counter + 1U;
  return true;
}

/** @brief The three session keys as handles. */
struct SessionKeys {
  KeyRef enc{};  ///< S-ENC.
  KeyRef mac{};  ///< S-MAC.
  KeyRef rmac{}; ///< S-RMAC.
};

/**
 * @brief The SCP03 KDF (SP 800-108 counter mode, CMAC): derivation data is 11 zero bytes, the
 * constant, a zero separator, L in bits (2 bytes), the counter i (1 byte) and the context.
 * @tparam K The crypto port.
 * @param crypto The port.
 * @param key The base key.
 * @param constant The derivation constant.
 * @param context The context, at most 16 bytes.
 * @param out The output; its length in bits is L (8, 16, 24 or 32 bytes).
 * @return `Ok`, `InvalidArgument` or `CryptoFailure`.
 */
template <CryptoPort K>
Error Kdf(K& crypto, KeyRef key, uint8_t constant, ByteSpan context, MutableByteSpan out) noexcept;

/**
 * @brief The secure-messaging engine of SCP03 and of the ECKey session: C-MAC chaining, command
 * encryption, R-MAC check, response decryption and the encryption counter.
 * @tparam K The crypto port.
 */
template <CryptoPort K>
class SecureMessaging {
public:
  /// Headroom `Wrap()` needs in front of the command for the MAC chaining value.
  static constexpr std::size_t kHeadroom = kMcvBytes;

  /** @brief Inactive. */
  SecureMessaging() noexcept = default;
  /** @brief Session state has one home. */
  SecureMessaging(const SecureMessaging&) = delete;
  /** @brief Session state has one home. */
  SecureMessaging& operator=(const SecureMessaging&) = delete;
  /** @brief Wipes the chaining value; the owner releases the keys through `Stop()`. */
  ~SecureMessaging() noexcept;

  /**
   * @brief Start with fresh session keys.
   * @param crypto The port that holds the keys; it must outlive the engine.
   * @param keys The session keys; the engine owns them from now on and releases them at `Stop()`.
   * @param level The GP level byte.
   * @param rule When the counter advances.
   * @param mcv The first MAC chaining value.
   */
  void Start(K& crypto, const SessionKeys& keys, uint8_t level, CounterRule rule,
             const std::array<uint8_t, kMcvBytes>& mcv) noexcept;
  /**
   * @brief After EXTERNAL AUTHENTICATE (which runs with C-MAC only): set the session level and
   * rule, and the counter to 1; the keys and the chaining value stay.
   * @param level The GP level byte.
   * @param rule When the counter advances.
   */
  void Reconfigure(uint8_t level, CounterRule rule) noexcept {
    level_ = level;
    rule_ = rule;
    counter_ = 1U;
    last_had_data_ = false;
  }
  /**
   * @brief Wrap a command into `buffer` at `offset`; `buffer[offset - 16, offset)` is overwritten.
   * @param plain The plain command.
   * @param buffer The buffer.
   * @param offset Where the wrapped command starts, at least `kHeadroom`.
   * @param keep_le Whether the wrapped command keeps Le (false inside an applet session).
   * @return The wrapped length, `InvalidArgument`, `BufferTooSmall`, `WrongState` (inactive) or
   * `CryptoFailure`.
   */
  Result<std::size_t> Wrap(ByteSpan plain, MutableByteSpan buffer, std::size_t offset,
                           bool keep_le) noexcept;
  /**
   * @brief Check and unwrap a response at `buffer[kHeadroom, kHeadroom + length)`; advances the
   * counter by the rule.
   * @param buffer The buffer; the 16 bytes in front of the response are overwritten.
   * @param length The response length.
   * @param out The plain response (data and status word).
   * @return Its length, `SecureChannelError` (the owner must close), `BufferTooSmall` (the
   * response is checked and dropped), `WrongState` or `CryptoFailure`.
   */
  Result<std::size_t> Unwrap(MutableByteSpan buffer, std::size_t length,
                             MutableByteSpan out) noexcept;
  /** @brief Release the keys, wipe the chaining value, stop. Always succeeds. */
  void Stop() noexcept;
  /** @return true while started. */
  [[nodiscard]] bool Active() const noexcept {
    return active_;
  }
  /**
   * @brief The next answer may be a bare `90 00` that ends the session: the applet answers a
   * command that ends its own session without secure messaging (AN12543 4.20.5 p. 154,
   * `DeleteAll`). Any other answer is unwrapped as usual. One exchange only. No I/O.
   */
  void ExpectSessionEnd() noexcept {
    expect_end_ = true;
  }
  /** @return The GP security level byte in use (0x01 C-MAC, 0x02 C-DECRYPTION, 0x10 R-MAC, 0x20
   * R-ENCRYPTION), 0 while stopped. No I/O. */
  [[nodiscard]] uint8_t Level() const noexcept {
    return active_ ? level_ : 0U;
  }
  /** @return The encryption counter of the next command. */
  [[nodiscard]] uint32_t Counter() const noexcept {
    return counter_;
  }
  /** @return The current MAC chaining value, for the tests of the chaining rule. */
  [[nodiscard]] const std::array<uint8_t, kMcvBytes>& Mcv() const& noexcept {
    return mcv_;
  }
  /** @brief Not on a temporary. */
  void Mcv() const&& = delete;

private:
  Error counterIcv(bool response, std::span<uint8_t, 16> icv) noexcept;
  Result<std::size_t> encryptData(const CommandParts& parts, MutableByteSpan field) noexcept;
  Result<std::size_t> decryptData(MutableByteSpan body) noexcept;
  static void writeHeader(const CommandParts& parts, std::size_t lc, bool extended,
                          MutableByteSpan out) noexcept;
  Error appendMac(MutableByteSpan buffer, std::size_t offset, std::size_t mac_at) noexcept;
  Result<std::size_t> checkRmac(MutableByteSpan buffer, std::size_t length) noexcept;
  /// The bare 9000 of a command that ended the applet session: copied out, the engine stopped.
  Result<std::size_t> sessionEnded(MutableByteSpan out) noexcept;
  /// The body length of an answer after its R-MAC check (when the level has R-MAC).
  Result<std::size_t> authenticBody(MutableByteSpan buffer, std::size_t length,
                                    bool success) noexcept;
  bool advance() noexcept;

  K* crypto_{nullptr};
  SessionKeys keys_{};
  std::array<uint8_t, kMcvBytes> mcv_{};
  uint32_t counter_{0};
  uint8_t level_{0};
  CounterRule rule_{CounterRule::EveryCommand};
  bool last_had_data_{false};
  bool active_{false};
  bool expect_end_{false};
};

/**
 * @brief The buffers and the framing every secure session shares: plain commands
 * (`SendPlain`), secure ones (`SendSecure`), and a buffer wipe after each.
 * @tparam P The port set.
 * @tparam T The lower transport.
 */
template <PortSet P, ApduTransport T>
class Pipe {
public:
  /// Size of the command buffer: headroom, the largest command, Le.
  static constexpr std::size_t kTxBytes = session::kFrameHeadroom + kMaxCommandApdu + 3U;
  /// Size of the response buffer: headroom and the largest response.
  static constexpr std::size_t kRxBytes = kMcvBytes + kMaxResponse + 16U;

  /**
   * @brief Bind. No I/O.
   * @param ports The ports.
   * @param lower The lower transport.
   */
  Pipe(const P& ports, T& lower) noexcept : ports_(&ports), lower_(&lower) {}
  /** @brief One per session. */
  Pipe(const Pipe&) = delete;
  /** @brief One per session. */
  Pipe& operator=(const Pipe&) = delete;
  /** @brief Wipes the buffers and releases the session keys. */
  ~Pipe() noexcept {
    Reset();
  }

  /**
   * @brief Send a command without secure messaging, framed when a session is attached.
   * @param command The command.
   * @param response The response buffer.
   * @return The response length or an error.
   */
  Result<std::size_t> SendPlain(ByteSpan command, MutableByteSpan response) noexcept;
  /**
   * @brief Wrap, frame, send and unwrap.
   * @param command The plain command.
   * @param response The plain response buffer.
   * @return The plain response length, or the error; a `SecureChannelError` or transport error
   * leaves the engine stopped.
   */
  Result<std::size_t> SendSecure(ByteSpan command, MutableByteSpan response) noexcept;
  /** @brief Stop the engine, detach the framer, wipe the buffers. No I/O. */
  void Reset() noexcept;

  /** @return The engine. */
  [[nodiscard]] SecureMessaging<typename P::CryptoType>& Sm() noexcept {
    return sm_;
  }
  /** @return The engine. */
  [[nodiscard]] const SecureMessaging<typename P::CryptoType>& Sm() const noexcept {
    return sm_;
  }
  /** @return The framer. */
  [[nodiscard]] session::Framer& Frame() noexcept {
    return framer_;
  }
  /** @return The ports. */
  [[nodiscard]] const P& Ports() const noexcept {
    return *ports_;
  }
  /** @return The lower transport. */
  [[nodiscard]] T& Lower() const noexcept {
    return *lower_;
  }

private:
  const P* ports_;
  T* lower_;
  SecureMessaging<typename P::CryptoType> sm_{};
  session::Framer framer_;
  std::array<uint8_t, kTxBytes> tx_{};
  std::array<uint8_t, kRxBytes> rx_{};
};

/// What the SCP03 handshake carries between its steps.
struct Handshake {
  std::array<uint8_t, 16> context{};                       ///< Host challenge || card challenge.
  std::array<uint8_t, kCryptogramBytes> card_cryptogram{}; ///< From INITIALIZE UPDATE.
  SessionKeys keys{};                                      ///< The derived session keys.
};

} // namespace se05x::scp03::detail

namespace se05x::scp03 {

/**
 * @brief One SCP03 channel over a lower transport.
 *
 * @tparam P A `Ports<...>` set (the crypto port does the AES and CMAC).
 * @tparam T The lower transport, usually `t1::Link<P>`; never a UserID session (S-14).
 */
template <PortSet P, ApduTransport T>
class Channel {
  static_assert(!session::UserIdTransport<T>, "S-14: no secure messaging over a UserID session");

public:
  /**
   * @brief Bind the channel. No I/O.
   * @param ports The port set; it must outlive the channel.
   * @param lower The lower transport; it must outlive the channel.
   */
  Channel(const P& ports, T& lower) noexcept : pipe_(ports, lower) {}

  /** @brief One channel per link. */
  Channel(const Channel&) = delete;
  /** @brief One channel per link. */
  Channel& operator=(const Channel&) = delete;

  /** @brief Releases every session key (no I/O). */
  ~Channel() noexcept = default;

  /**
   * @brief Run INITIALIZE UPDATE and EXTERNAL AUTHENTICATE and derive the session keys; for an
   * AESKey session, CreateSession first.
   * @param params The key handles and the level.
   * @return `Ok`, `InvalidArgument` (missing key handle, value out of range, an AESKey session
   * without a credential or with AES-256), `WrongState` (already open), `AuthLocked` (the
   * host-side attempt limit is reached; nothing sent), `AuthFailed` (the chip refused; counted),
   * `SecureChannelError` (bad card cryptogram or malformed answer; counted), `CryptoFailure`,
   * `ThroughputLimited` or a transport error.
   */
  Result<void> Open(const ChannelParams& params) noexcept;

  /**
   * @brief Wrap, send and unwrap one command.
   * @param command The plain command APDU.
   * @param response The buffer for the plain response APDU.
   * @return The response length, or `NotInitialized`, `SecureChannelError` (the channel is then
   * closed), `BufferTooSmall` (the response was checked and dropped; the channel stays open) or a
   * transport error (the channel is then closed).
   */
  Result<std::size_t> Transceive(ByteSpan command, MutableByteSpan response) noexcept;

  /**
   * @brief Close the channel and release the session keys; never refused (RD-05). An AESKey
   * session sends CloseSession first, best effort.
   * @return `Ok`, or `NeedsReselect` when CloseSession could not be confirmed (the keys are
   * released all the same; the chip ends the session at deselect).
   */
  Result<void> Close() noexcept;

  /** @return true while the channel is open. No I/O. */
  [[nodiscard]] bool IsOpen() const noexcept {
    return open_;
  }
  /** @return The command counter of the channel (next value used in the IV). No I/O. */
  [[nodiscard]] uint32_t Counter() const noexcept {
    return pipe_.Sm().Counter();
  }
  /** @return The GP security level byte while open, 0 when closed. No I/O. */
  [[nodiscard]] uint8_t Level() const noexcept {
    return open_ ? pipe_.Sm().Level() : 0U;
  }
  /** @brief The next answer may be a bare `90 00` ending the session (`DeleteAll`). No I/O. */
  void ExpectSessionEnd() noexcept {
    pipe_.Sm().ExpectSessionEnd();
  }
  /**
   * @return true when a failed AESKey handshake left a half-open session on the chip: it cannot be
   * closed (AN12543 3.6.5, errata APP.2), so the applet must be selected again. No I/O.
   */
  [[nodiscard]] bool NeedsReselect() const noexcept {
    return needs_reselect_;
  }
  /**
   * @brief Set the host-side limit of failed handshakes in a row (S-14).
   * @param limit The limit; usually `Config::auth_attempt_limit`.
   */
  void SetAuthAttemptLimit(uint8_t limit) noexcept {
    attempts_ = AttemptLimiter{limit};
  }
  /** @return The host-side attempt limiter. No I/O. */
  [[nodiscard]] const AttemptLimiter& Attempts() const noexcept {
    return attempts_;
  }

private:
  static bool validParams(const ChannelParams& params) noexcept;
  Result<void> handshake(const ChannelParams& params) noexcept;
  Result<void> initializeUpdate(const ChannelParams& params, detail::Handshake& hs) noexcept;
  Result<void> deriveKeys(const ChannelParams& params, detail::Handshake& hs) noexcept;
  Result<void> externalAuthenticate(const ChannelParams& params, detail::Handshake& hs) noexcept;
  void closeLocal() noexcept;

  detail::Pipe<P, T> pipe_;
  AttemptLimiter attempts_;
  ChannelKind kind_{ChannelKind::Platform};
  bool open_{false};
  bool needs_reselect_{false};
};

} // namespace se05x::scp03

namespace se05x::session {

/**
 * @brief A UserID session (AN12543 3.6.3.1): CreateSession, then VerifySessionUserID; every
 * command after that is framed with the session id and travels in the clear (S-14).
 *
 * The UserID value is a secret: it is sent once, in the clear on the wire, and the command buffer
 * is wiped right after. The host counts failed verifications (`AttemptLimiter`) and refuses
 * further attempts without sending anything when the limit is reached. Secure channels refuse to
 * stack on this type at compile time.
 *
 * @tparam P The port set.
 * @tparam T The lower transport.
 */
template <PortSet P, ApduTransport T>
class UserIdSession {
public:
  /// Marks the transport as a UserID session for `UserIdTransport`.
  static constexpr bool kUserIdSession = true;

  /**
   * @brief Bind. No I/O.
   * @param ports The ports.
   * @param lower The lower transport.
   */
  UserIdSession(const P& ports, T& lower) noexcept : pipe_(ports, lower) {}
  /** @brief One session per object. */
  UserIdSession(const UserIdSession&) = delete;
  /** @brief One session per object. */
  UserIdSession& operator=(const UserIdSession&) = delete;
  /** @brief Wipes the buffers (no I/O). */
  ~UserIdSession() noexcept = default;

  /**
   * @brief Open the session.
   * @param credential The UserID object.
   * @param value The UserID value (secret), 1 to 16 bytes.
   * @return `Ok`, `InvalidArgument`, `WrongState` (already open), `AuthLocked` (host limit; nothing
   * sent), `AuthFailed` (wrong value, SW 6985; counted, and the half-open session needs a
   * reselect), or the error of CreateSession or the transport.
   */
  Result<void> Open(ObjectId credential, ByteSpan value) noexcept;
  /**
   * @brief Send one command inside the session, in the clear.
   * @param command The command.
   * @param response The response buffer.
   * @return The response length, `NotInitialized` or the transport's error.
   */
  Result<std::size_t> Transceive(ByteSpan command, MutableByteSpan response) noexcept;
  /**
   * @brief Send CloseSession, best effort, and forget the session; never refused (RD-05).
   * @return `Ok`, or `NeedsReselect` when the chip did not confirm.
   */
  Result<void> Close() noexcept;
  /** @return true while open. */
  [[nodiscard]] bool IsOpen() const noexcept {
    return open_;
  }
  /** @return true after a failed verification left a half-open session on the chip. */
  [[nodiscard]] bool NeedsReselect() const noexcept {
    return needs_reselect_;
  }
  /** @brief Set the host-side attempt limit. @param limit The limit. */
  void SetAuthAttemptLimit(uint8_t limit) noexcept {
    attempts_ = AttemptLimiter{limit};
  }
  /** @return The attempt limiter. */
  [[nodiscard]] const AttemptLimiter& Attempts() const noexcept {
    return attempts_;
  }

private:
  scp03::detail::Pipe<P, T> pipe_;
  AttemptLimiter attempts_;
  bool open_{false};
  bool needs_reselect_{false};
};

} // namespace se05x::session

// codeql::misra_deviation_next_line(MD-CPP-009)
#include "../src/se05x_scp03.ipp" // IWYU pragma: export

#endif // SE05X_SCP03_HPP
