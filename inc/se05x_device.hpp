/**
 * @file se05x_device.hpp
 * @brief `Device<P>`: the command layer. Opens the chip, derives its capabilities, runs sessions
 * and executes applet commands through the capability gate.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * A command is a `Command` enumerator; its argument and reply types are
 * `CommandTypes<C>`. `Execute<C>()` checks the state, runs the capability gate (`gate::Check`), the
 * role check (`RequiredRole`), the policy generation and the argument limits the codec cannot see
 * (the curve, the 919-byte EdDSA input of a UserID session, the UserID credential rules), encodes
 * through `Codec<C>`, sends through the transport stack, maps the status word in the context of
 * the command (`apdu::StatusToError`) and decodes the reply. A refusal sends nothing. Every
 * method returns a `Result`; nothing throws, nothing allocates.
 *
 * The transport stack (`se05x_device_stage.hpp`): the link; platform SCP03 over it when the
 * device opened it (then every applet command goes through it, and never in the clear again until
 * `Close()`); one applet session at a time over that (UserID, AESKey or ECKey). So an applet
 * session inside platform SCP03 is two secure-messaging layers, each with its own keys and
 * counters.
 *
 * Commands that the device runs itself (`detail::IsDeviceOwned`: the select, the session handshake
 * steps, `TriggerSelfTest`) and the irreversible ones do not compile through `Execute<C>()`.
 * Irreversible commands run only through `ExecuteIrreversible<C, Op>()`, which exists only when
 * `kIrreversibleEnabled` and needs `Confirmation<Op>` (S-10) and the session role of the command:
 * `SetLockState` RESERVED_ID_TRANSPORT, `SetPlatformScpRequest` RESERVED_ID_PLATFORM_SCP,
 * `SetAppletFeatures` RESERVED_ID_FEATURE, `DeleteAll`
 * RESERVED_ID_FACTORY_RESET, `DisableObjCreation` RESERVED_ID_RESTRICT (AN12543 4.6.1 to 4.6.5);
 * any other role is refused with `ConditionsNotSatisfied` before anything is sent. The answer of
 * `DeleteAll` is not secure-messaging wrapped (AN13030), so the session ends with it.
 *
 * Failures and recovery:
 *
 * - SW 0x66A6 (`ThroughputLimited`, S-17): the device drops every session (sending nothing),
 *   resets the chip once through the ladder (`t1::Rung::ChipReset`), selects the applet again,
 *   opens platform SCP03 again when it was open, and returns `ThroughputLimited` without repeating
 *   the command. It never resets twice for one call: a 0x66A6 to the select after the reset leaves
 *   the device `NeedsReopen`.
 * - A secure-channel or transport failure under a session or platform SCP03 ends the stack: the
 *   device is `NeedsReopen` and refuses commands with `NeedsReselect` until `Recover()` selects the
 *   applet again (and opens platform SCP03 again). A plain `Timeout` without a session keeps the
 *   device `Ready`: the link resynchronises before the next command.
 * - A session handshake that fails after CreateSession leaves a half-open session the chip cannot
 *   close (AN12543 3.6.5, errata APP.2): the device selects the applet again before it returns.
 * - `Close()` and `DeepPowerDown()` are never refused for an uncertain state (RD-05).
 *
 * Every wait is bounded by the link (S-05); the device adds no wait of its own and runs at most
 * two selects and one chip reset per call.
 *
 * Threading: one `Device` is not thread safe (S-11); the caller serialises, or uses the
 * facade's transaction scope. Memory: the device holds its command and response buffers and four
 * secure-messaging pipes (platform, AESKey, ECKey, UserID), about 11 KiB, as members (RD-06).
 */
#ifndef SE05X_DEVICE_HPP
#define SE05X_DEVICE_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "se05x_apdu_codec.hpp"
#include "se05x_attest.hpp"
#include "se05x_caps.hpp"
#include "se05x_codec.hpp"
#include "se05x_commands.hpp"
#include "se05x_confirm.hpp"
#include "se05x_detail.hpp"
#include "se05x_device_stage.hpp"
#include "se05x_device_types.hpp"
#include "se05x_eckey.hpp"
#include "se05x_gate.hpp"
#include "se05x_gp.hpp"
#include "se05x_ids.hpp"
#include "se05x_lifecycle.hpp"
#include "se05x_policy_types.hpp"
#include "se05x_ports.hpp"
#include "se05x_scp03.hpp"
#include "se05x_status.hpp"
#include "se05x_t1.hpp"
#include "se05x_types.hpp"

namespace se05x {

/**
 * @defgroup se05x_device Device
 * @brief The command layer.
 * @{
 */

/** @brief The state of a `Device`. */
enum class DeviceState : uint8_t {
  Closed = 0,      ///< `Open()` has not succeeded.
  Ready = 1,       ///< Open, no session.
  InSession = 2,   ///< A user, AESKey or ECKey session is open.
  NeedsReopen = 3, ///< A reset or a failed secure channel check ended the stack; call `Recover()`.
  Dead = 4,        ///< Unrecoverable; call `Close()`.
};

namespace detail {
/// Last enumerator of `DeviceState`.
template <>
struct EnumLast<DeviceState> {
  static constexpr DeviceState kValue = DeviceState::Dead; ///< The last enumerator.
};
} // namespace detail

/** @brief What an AESKey session needs. */
struct AesKeySessionParams {
  ObjectId credential{};    ///< The AESKey authentication object on the chip.
  scp03::StaticKeys keys{}; ///< The session keys as handles (S-16).
  scp03::SecurityLevel level{scp03::SecurityLevel::Full}; ///< Requested level.
  uint32_t session_policy_ms{0};                          ///< Reserved; 0.
};

/**
 * @brief What a user-id session needs: the PIN is a secret and is wiped by the caller. The session
 * has no secure messaging on the wire (S-14): the facade refuses secret use over it unless platform
 * SCP03 is active.
 */
struct UserIdSessionParams {
  ObjectId credential{}; ///< The user-id object.
  ByteSpan pin;          ///< The reference value (secret).
};

/** @brief The kind of the session now open. */
enum class SessionKind : uint8_t {
  None = 0,   ///< No session.
  UserId = 1, ///< User-id session.
  AesKey = 2, ///< AESKey session (SCP03).
  EcKey = 3,  ///< ECKey session.
};

namespace detail {
/// Last enumerator of `SessionKind`.
template <>
struct EnumLast<SessionKind> {
  static constexpr SessionKind kValue = SessionKind::EcKey; ///< The last enumerator.
};
} // namespace detail

/**
 * @brief The device command layer.
 *
 * @tparam P A `Ports<...>` set.
 */
template <PortSet P>
class Device {
public:
  /**
   * @brief Bind the device. No I/O.
   * @param ports The port set; it must outlive the device.
   * @param config The configuration; validated at `Open()`.
   */
  Device(const P& ports, const Config& config) noexcept
      : ports_(&ports), config_(config), link_(ports, config), wire_(link_),
        platform_(ports, wire_), applet_(wire_, platform_), aes_(ports, applet_),
        eckey_(ports, applet_), userid_(ports, applet_) {}

  /** @brief One device per chip. */
  Device(const Device&) = delete;
  /** @brief One device per chip. */
  Device& operator=(const Device&) = delete;
  /** @brief Wipes the buffers; the session objects release their keys. No I/O. */
  ~Device() noexcept {
    wipeBuffers();
  }

  /**
   * @name Lifecycle
   * @{
   */

  /**
   * @brief Give the platform SCP03 key set (handles, S-16) that `Open()` and `Recover()` use when
   * `Config::scp_policy` or the chip asks for platform SCP03. No I/O; the handles are kept, never
   * the keys.
   * @param params The key handles, the key version and the level; `kind` must be `Platform`.
   * @return `Ok`; `InvalidArgument` (a missing ENC or MAC handle, or not the platform kind);
   * `WrongState` (the device is open).
   */
  Result<void> SetPlatformKeys(const scp03::ChannelParams& params) noexcept;

  /**
   * @brief Validate the configuration, open the link, read the card identification data (OEF id)
   * from the card manager, select the applet, read the extended feature bits (applet 7.x), run the
   * probes (`Config::probe_capabilities`), read the lifecycle state (applet 7.x: `ReadState`),
   * derive the capabilities and open platform SCP03 when `Config::scp_policy` or the chip requires
   * it.
   * @return `Ok`; `InvalidArgument` (bad `Config`, nothing sent); `WrongState` (already open, or
   * platform SCP03 required and `scp_policy` is `Off` or no keys were given); `Counterfeit` (no
   * IoT applet answers the select); `DeviceIdMismatch` (an applet version or OEF id of no known
   * part); `ThroughputLimited`; or the error of the link, of a command or of platform SCP03. On
   * failure the link is closed and the device stays `Closed`.
   */
  Result<void> Open() noexcept;

  /**
   * @brief End the session (best effort), close platform SCP03, end the link session and wipe
   * every buffer. Never refused for an uncertain state (RD-05).
   * @return `Ok`, or the error of the link's end-of-session exchange; the device is `Closed`
   * either way.
   */
  Result<void> Close() noexcept;

  /**
   * @brief Bring a `NeedsReopen` (or `Ready`) device back: drop every session (sending nothing),
   * select the applet again, and open platform SCP03 again when it was open. When the select fails
   * on the transport, climb the link's ladder from the resynchronisation once and select again.
   * Sessions are lost; the caller opens them again (S-15).
   * @return `Ok`; `NotInitialized` (closed); `TransportDead` (the ladder is exhausted: `Close()`
   * then `Open()`); `DeviceIdMismatch` (the applet now reports another version); or the error of
   * the select or of platform SCP03 (the device stays `NeedsReopen`).
   */
  Result<void> Recover() noexcept;

  /**
   * @brief Power-cycle the chip through the reset port, then bring the device up as `Open()`
   * does. Only with a reset port. From `Closed` it is the power cycle and `Open()`.
   * @return As `Open()`; `Bus` when the reset port fails.
   */
  Result<void> PowerCycle() noexcept
    requires(P::kHasReset);

  /**
   * @brief Enter deep power-down (the link: ENA through the reset port, or the S-block 0xDF of the
   * SE052). Sessions and transient objects are lost (S-15); the device is `Closed` afterwards and
   * the next `Open()` wakes the chip. Sent from `NeedsReopen` and `Dead` too (RD-05).
   * @return `Ok`; `NotInitialized` (closed); `Unsupported` (the chip does not answer the
   * S-block: the device stays as it was, sessions dropped); or the error of the link.
   */
  Result<void> DeepPowerDown() noexcept;

  /** @return true while `Open()` has succeeded and `Close()` has not run. No I/O. */
  [[nodiscard]] bool IsOpen() const noexcept {
    return (state_ != DeviceState::Closed) && (state_ != DeviceState::Dead);
  }
  /** @return The device state. No I/O. */
  [[nodiscard]] DeviceState State() const noexcept {
    return state_;
  }
  /** @return The capabilities derived at `Open()`; all-default before. No I/O. */
  [[nodiscard]] const Capabilities& GetCapabilities() const& noexcept {
    return caps_;
  }
  void GetCapabilities() const&& = delete;
  /** @return The role of the session now open (`AuthRole::None` without one). No I/O. */
  [[nodiscard]] AuthRole Role() const noexcept {
    return role_;
  }
  /**
   * @return true when commands now travel under secure messaging (platform SCP03, an AESKey or an
   * ECKey session). A user-id session alone has none (S-14). No I/O.
   */
  [[nodiscard]] bool SecureMessagingActive() const noexcept {
    return platform_.IsOpen() || aes_.IsOpen() || eckey_.IsOpen();
  }
  /**
   * @return true when the chip's answers are authenticated: a secure-messaging layer now open
   * has R-MAC (GP level bit 0x10). At `CMac` or `CMacCDecrypt` an answer can be forged on the bus
   * (docs/secure-channels.md). No I/O.
   */
  [[nodiscard]] bool AnswersAuthenticated() const noexcept {
    return (static_cast<uint32_t>(levels()) & uint32_t{kLevelRMac}) != 0U;
  }
  /**
   * @return true when commands and answers are both encrypted on the bus: the open layers give
   * C-DECRYPTION and R-ENCRYPTION (GP level bits 0x02 and 0x20) and R-MAC. No I/O.
   */
  [[nodiscard]] bool TrafficConfidential() const noexcept {
    constexpr uint32_t kAll = uint32_t{kLevelRMac} | uint32_t{kLevelCDec} | uint32_t{kLevelREnc};
    return (static_cast<uint32_t>(levels()) & kAll) == kAll;
  }
  /** @return The authentication object of the applet session now open, or 0. No I/O. */
  [[nodiscard]] ObjectId SessionCredential() const noexcept {
    return session_credential_;
  }
  /** @return The status word of the last response (0 before any command). No I/O. */
  [[nodiscard]] uint16_t GetLastStatusWord() const noexcept {
    return last_sw_;
  }
  /** @return The details of the last failure (default when the last call succeeded). No I/O. */
  [[nodiscard]] const Detail& GetLastDetail() const& noexcept {
    return last_detail_;
  }
  void GetLastDetail() const&& = delete;
  /**
   * @return The APDUs this device object has sent, across every `Open()`, `Close()` and
   * `PowerCycle()` (the chip's throughput window does not restart with them), for the budget of
   * S-17. Saturates at 2^32 - 1. No I/O.
   */
  [[nodiscard]] uint32_t ApduCount() const noexcept {
    return apdu_count_;
  }
  /** @return How many times the device was brought up (`Open()`, `PowerCycle()`). No I/O. */
  [[nodiscard]] uint32_t OpenCount() const noexcept {
    return opens_;
  }
  /** @return The configuration. No I/O. */
  [[nodiscard]] const Config& GetConfig() const& noexcept {
    return config_;
  }
  void GetConfig() const&& = delete;
  /** @return The link, for counters and diagnostics. No I/O. */
  [[nodiscard]] const t1::Link<P>& GetLink() const& noexcept {
    return link_;
  }
  void GetLink() const&& = delete;
  /** @} */

  /**
   * @name Sessions
   * Each `Begin...Session()` needs a `Ready` device without a session, refuses on the host when
   * `Config::auth_attempt_limit` failed attempts in a row were counted (`AuthLocked`, S-14, nothing
   * sent), and on a failure after CreateSession selects the applet again (S-07). Platform SCP03,
   * when open, stays underneath.
   * @{
   */

  /**
   * @brief Open a user-id session: CreateSession and VerifySessionUserID. It carries no secure
   * messaging of its own (S-14): the value travels in the clear unless platform SCP03 is open.
   * @param params The credential and the value (secret, 1 to 16 bytes; the caller wipes it).
   * @return `Ok`; `NotInitialized`; `WrongState` (not `Ready`, or a session is open);
   * `InvalidArgument`; `Unsupported` (gate); `AuthFailed` (counted); `AuthLocked`;
   * `ThroughputLimited`; or a transport error.
   */
  Result<void> BeginUserIdSession(const UserIdSessionParams& params) noexcept;
  /**
   * @brief Open an AESKey session (SCP03 with the applet, AN12543 3.6.3.2).
   * @param params The credential, the key handle (`keys.enc`) and the level.
   * @return As `BeginUserIdSession()`, and `SecureChannelError` (bad card cryptogram),
   * `CryptoFailure`.
   */
  Result<void> BeginAesKeySession(const AesKeySessionParams& params) noexcept;
  /**
   * @brief Open an ECKey session. The chip's ECKA public key must first be read and verified with
   * `ReadEckaPublicKey()` in this open of the device, and `params.se_public_key` must be that key;
   * the receipt is checked when `Config::verify_eckey_receipt` or `params.verify_receipt` says so.
   * @param params The params.
   * @return As `BeginAesKeySession()`; `WrongState` (no verified ECKA key, or another key given);
   * `Unsupported` while `SE05X_ENABLE_ECKEY_SESSION` is off (nothing sent).
   */
  Result<void> BeginEcKeySession(const eckey::SessionParams& params) noexcept;
  /**
   * @brief Close the session now open and wipe its keys; without a session nothing is sent
   * (errata APP.2). When the chip does not confirm, the applet is selected again.
   * @return `Ok`, `NotInitialized`, or the error of the reselect.
   */
  Result<void> EndSession() noexcept;
  /**
   * @brief Refresh the session (applet 7.x, `RefreshSession` without a new policy).
   * @return `Ok`; `NotInitialized`; `WrongState` (no session); or the command's error.
   */
  Result<void> RefreshSession() noexcept;
  /** @return The kind of the session now open. No I/O. */
  [[nodiscard]] SessionKind Session() const noexcept {
    return session_;
  }
  /**
   * @brief Read the chip's ECKA public key (`RESERVED_ID_ECKEY_SESSION`) with an attested
   * `ReadObject` and verify it (fresh nonce from the host's crypto port, signature with the
   * caller's trusted attestation public key, timestamp later than the last one). On success the key
   * is kept for `BeginEcKeySession()` until `Close()`.
   * @param attestation_key The chip object that signs (with `POLICY_OBJ_ALLOW_ATTESTATION`).
   * @param attestation_public Its public key, uncompressed P-256, from a trusted source.
   * @param out Receives the verified ECKA public key (04 || x || y).
   * @return `Ok`; `NotInitialized`; `Unsupported` (gate); `AttestationInvalid`; `FrameError` (not
   * a 65-byte uncompressed point); or the command's error.
   */
  Result<void> ReadEckaPublicKey(ObjectId attestation_key,
                                 std::span<const uint8_t, 65> attestation_public,
                                 std::span<uint8_t, 65> out) noexcept;
  /** @} */

  /**
   * @name Execution
   * @{
   */

  /**
   * @brief Run one reversible command.
   *
   * Irreversible commands and the commands the device runs itself (`detail::IsDeviceOwned`) do not
   * satisfy the constraint: `Execute<Command::DeleteAll>(...)` does not compile.
   *
   * @tparam C The command.
   * @param args The arguments.
   * @return The reply or an error: `NotInitialized`; `NeedsReselect` (`NeedsReopen`: call
   * `Recover()`); `TransportDead`; `Unsupported` or `WrongState` from the gate;
   * `PolicyInvalid` (a policy for another applet generation, or an infinite UserID counter);
   * `InvalidArgument` (refused by the codec or an argument check; nothing sent);
   * `ThroughputLimited` (the chip was reset); a status word mapped by `apdu::StatusToError`
   * (the word is in the details and in `GetLastStatusWord()`); or a lower-layer error.
   */
  template <Command C>
    requires(!IsIrreversible(C) && !detail::IsDeviceOwned(C))
  Result<ReplyOf<C>> Execute(const ArgsOf<C>& args) noexcept;

  /**
   * @brief Run one irreversible command; exists only when `kIrreversibleEnabled`.
   *
   * @tparam C The irreversible command.
   * @tparam Op The operation tag whose `kCommand` is `C`.
   * @param args The arguments.
   * @param confirmation The confirmation for `Op`.
   * @return `IrreversibleNotConfirmed` without a valid confirmation; `ConditionsNotSatisfied`
   * when the session role is not the one of the command; `WrongState` when the chip is already in
   * the requested state (a persistent lock that is set, platform SCP03 already required); nothing
   * is sent in these cases; else as `Execute`.
   */
  template <Command C, typename Op>
    requires(kIrreversibleEnabled && IsIrreversible(C) && (Op::kCommand == C))
  Result<ReplyOf<C>> ExecuteIrreversible(const ArgsOf<C>& args,
                                         irreversible::Confirmation<Op> confirmation) noexcept;

  /**
   * @brief Send raw bytes through the transport stack. Lab use: refused with `Unsupported` unless
   * `Config::allow_lab_override`, and then still refused for the select, the session commands and
   * the irreversible management commands (S-10), which would leave the device's view wrong.
   * @param command The APDU.
   * @param response The buffer for the response.
   * @return The response length (status word included) or an error.
   */
  Result<std::size_t> ReadRaw(ByteSpan command, MutableByteSpan response) noexcept;

  /** @brief Mark the start of a run of commands (the facade's transaction scope). No I/O.
   * @return `Ok`; `NotInitialized`; `Busy` when one is already marked. */
  Result<void> BeginTransaction() noexcept;
  /** @brief Mark its end; never refused (RD-05). No I/O. @return `Ok`. */
  Result<void> EndTransaction() noexcept;
  /** @} */

  /**
   * @name Named wrappers
   * @brief Thin typed calls over `Execute<C>`; every one is gated and policy-checked by the chip.
   * @{
   */

  /**
   * @brief Run the self test; the chip may reset without answering, so the caller acknowledges it.
   * Run it from the default session (before AES GCM/GMAC, PBKDF and TLS KDF on SE052).
   * @param test The self test selector.
   * @param acknowledgement The caller's acknowledgement that no response may come.
   * @return true when passed; `Resynced` when the chip reset without a response (sessions are
   * gone, the applet is selected again).
   */
  Result<bool> TriggerSelfTest(uint16_t test, irreversible::ResetExpected acknowledgement) noexcept;
  /** @brief GET_VERSION. @return The applet info or an error. */
  Result<AppletInfo> GetVersion() noexcept;
  /** @brief GET_FREE_MEMORY. @param memory Which memory. @return Bytes free or an error. */
  Result<uint32_t> FreeMemory(MemoryType memory) noexcept;
  /** @brief GET_RANDOM from the chip RNG. @param out The buffer to fill (1 to 1024 bytes). @return
   * `Ok` or an error. */
  Result<void> GetRandom(MutableByteSpan out) noexcept;
  /**
   * @brief Create an EC key pair inside the chip. @return `Ok`, `ObjectExists`, ...
   * @param id The id.
   * @param policy The policy.
   * @param curve The curve.
   */
  Result<void> GenerateEcKey(ObjectId id, const Policy& policy, EcCurve curve) noexcept;
  /**
   * @brief ECDSA over a digest. @return The signature length (DER) or an error.
   * @param key The key.
   * @param algo The algo.
   * @param digest The digest.
   * @param signature The signature.
   */
  Result<std::size_t> EcdsaSign(ObjectId key, EcSignAlgo algo, ByteSpan digest,
                                MutableByteSpan signature) noexcept;
  /**
   * @brief ECDSA verification. @return true valid, false invalid, or an error.
   * @param key The key.
   * @param algo The algo.
   * @param digest The digest.
   * @param signature The signature.
   */
  Result<bool> EcdsaVerify(ObjectId key, EcSignAlgo algo, ByteSpan digest,
                           ByteSpan signature) noexcept;
  /**
   * @brief Read an object. @return The bytes read or an error.
   * @param id The id.
   * @param offset The offset.
   * @param out The out.
   */
  Result<std::size_t> ReadObject(ObjectId id, uint16_t offset, MutableByteSpan out) noexcept;
  /**
   * @brief Write a binary file, creating it with `policy` when `file_length` is not 0.
   * @param id The id.
   * @param policy The policy.
   * @param offset The offset.
   * @param data The data.
   * @param file_length The file length.
   * @return The result of the call.
   */
  Result<void> WriteBinary(ObjectId id, const Policy& policy, uint16_t offset, ByteSpan data,
                           uint16_t file_length) noexcept;
  /**
   * @brief Does an object exist. @return The answer or an error.
   * @param id The id.
   */
  Result<bool> ObjectExists(ObjectId id) noexcept;
  /**
   * @brief Delete an object (reversible command, but not recoverable: the facade asks first).
   * @param id The id.
   * @return The result of the call.
   */
  Result<void> DeleteObject(ObjectId id) noexcept;
  /**
   * @brief Attested read; the freshness comes from the host's crypto port (`CryptoPort::Random`,
   * AN12543 3.2.7.2), whatever `args.freshness`
   * holds. The reply's `echoed_command` holds the plain command sent (the first 100 bytes), which
   * the verifier needs; the answer is not verified here (`attest::Verifier`).
   * @param args The args.
   * @return The result or an error.
   */
  Result<AttestedRead> ReadAttested(const ReadObjectAttestedArgs& args) noexcept;
  /**
   * @brief Attested read, verified: `ReadAttested()` (fresh nonce from the host's crypto port),
   * then the verifier of the chip's format with the caller's trusted key and the timestamp of the
   * last verified read of this open (S-09). On success that timestamp advances.
   * @param args The object, the range, the attestation key and the output buffers.
   * @param attestation_public The trusted public key of `args.attestation_key`, uncompressed.
   * @return The checked fields; `AttestationInvalid`; or the error of the read.
   */
  Result<attest::Checked> ReadVerified(const ReadObjectAttestedArgs& args,
                                       std::span<const uint8_t, 65> attestation_public) noexcept;
  /**
   * @brief Increment a counter object. @return `Ok` or an error.
   * @param id The id.
   */
  Result<void> IncrementCounter(ObjectId id) noexcept;
  /** @} */

private:
  template <typename Q>
  friend class irreversible::Operations;

  using Wire = detail::LinkStage<P>;

  static constexpr uint8_t kLevelCDec = 0x02U; ///< GP level: C-DECRYPTION.
  static constexpr uint8_t kLevelRMac = 0x10U; ///< GP level: R-MAC.
  static constexpr uint8_t kLevelREnc = 0x20U; ///< GP level: R-ENCRYPTION.
  /// Count APDUs, saturating (S-17: an overflowing count would let the budget pass again).
  void countApdus(uint32_t n) noexcept {
    apdu_count_ = detail::SaturatingAdd(apdu_count_, n);
  }
  /// The GP level bits of every layer now open, together.
  [[nodiscard]] uint8_t levels() const noexcept {
    return static_cast<uint8_t>(platform_.Level() | aes_.Level() | eckey_.Level());
  }
  using Applet = detail::AppletStage<P>;

  // Admission and argument checks (no I/O).
  [[nodiscard]] Error admit(Command command, const Policy* policy) const noexcept;
  template <Command C>
  [[nodiscard]] Error checkArgs(const ArgsOf<C>& args, bool irreversible) const noexcept;
  /// The creating commands of `irreversible::Operations` (an immutable file, a UserID object).
  template <Command C>
    requires((C == Command::WriteBinary) || (C == Command::WriteUserId))
  Result<ReplyOf<C>> createIrreversible(const ArgsOf<C>& args) noexcept;
  template <typename T>
  Result<T> refuse(Command command, Error error) noexcept;

  // Exchange.
  template <Command C>
  Result<ByteSpan> send(const ArgsOf<C>& args) noexcept;
  template <Command C>
  Result<ReplyOf<C>> run(const ArgsOf<C>& args) noexcept;
  template <Command C>
  Result<ReplyOf<C>> runCardManager(const ArgsOf<C>& args) noexcept;
  Result<ByteSpan> exchange(Command command, std::size_t length) noexcept;
  Result<std::size_t> transmit(ByteSpan command) noexcept;
  Result<ByteSpan> afterTransport(Command command, Result<std::size_t> failed) noexcept;
  Result<ByteSpan> onThroughput(Command command) noexcept;
  template <Command C>
  Result<ReplyOf<C>> plain(const ArgsOf<C>& args) noexcept;

  // Bring-up, recovery, sessions.
  Result<void> bringUp() noexcept;
  Result<void> identify(AppletInfo& info, std::array<uint8_t, kExtFeatureLength>& ext,
                        bool& has_ext, uint16_t& oef) noexcept;
  Result<void> probeAndDerive(const AppletInfo& info, ByteSpan ext, uint16_t oef) noexcept;
  Result<gate::ProbeResult> runProbes() noexcept;
  Result<void> readLifecycle() noexcept;
  Result<void> openPlatform() noexcept;
  Result<AppletInfo> selectApplet() noexcept;
  Result<void> reselect() noexcept;
  Error sessionReady() const noexcept;
  [[nodiscard]] Error rawCheck(ByteSpan command, MutableByteSpan response) const noexcept;
  Result<attest::Checked> verifyAttested(const attest::Sent& sent, const AttestedRead& answer,
                                         ByteSpan data, ByteSpan signature,
                                         std::span<const uint8_t, 65> key) noexcept;
  Result<void> afterSessionOpen(Result<void> opened, SessionKind kind, ObjectId credential,
                                uint32_t sent_before) noexcept;
  void teardown() noexcept;
  void finishClose() noexcept;
  void wipeBuffers() noexcept;

  const P* ports_;
  Config config_;
  t1::Link<P> link_;
  Wire wire_;
  scp03::Channel<P, Wire> platform_;
  Applet applet_;
  scp03::Channel<P, Applet> aes_;
  eckey::Session<P, Applet> eckey_;
  session::UserIdSession<P, Applet> userid_;
  scp03::ChannelParams platform_params_{};
  bool platform_keys_{false};
  Capabilities caps_{};
  DeviceState state_{DeviceState::Closed};
  SessionKind session_{SessionKind::None};
  AuthRole role_{AuthRole::None};
  ObjectId session_credential_{};
  bool in_transaction_{false};
  bool probing_{false}; ///< `Open()` probes: a refusal by status word means "absent".
  bool ecka_verified_{false};
  uint32_t apdu_count_{0};
  uint32_t opens_{0};
  uint16_t last_sw_{0};
  Detail last_detail_{};
  Timestamp last_timestamp_{};
  std::array<uint8_t, 65> ecka_{};
  std::array<uint8_t, attest::kMaxEchoedCommand> sent_{}; ///< Start of the last attested command.
  std::size_t sent_length_{0};
  std::array<uint8_t, kMaxResponse> signed_{}; ///< The signed TLVs of the last attested answer.
  std::size_t signed_length_{0};
  std::array<uint8_t, kFreshnessLength> last_nonce_{}; ///< The nonce of the last attested read.
  std::array<uint8_t, kMaxPlainCommandApdu> tx_{}; ///< The command being sent (RD-06: a member).
  std::array<uint8_t, kMaxResponse> rx_{};         ///< The response (RD-06: a member).
};

/** @} */

} // namespace se05x

// codeql::misra_deviation_next_line(MD-CPP-009)
#include "../src/se05x_device_core.ipp" // IWYU pragma: export
// codeql::misra_deviation_next_line(MD-CPP-009)
#include "../src/se05x_device_objects.ipp" // IWYU pragma: export
// codeql::misra_deviation_next_line(MD-CPP-009)
#include "../src/se05x_device_crypto.ipp" // IWYU pragma: export

#endif // SE05X_DEVICE_HPP
