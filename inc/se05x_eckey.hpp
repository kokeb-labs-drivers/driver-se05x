/**
 * @file se05x_eckey.hpp
 * @brief The ECKey session: an applet session authenticated with an EC key, with SCP03 secure
 * messaging under keys from ECDH.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Written from AN12543 3.6.3.3 (pp. 33-34), 4.5.4.1 (Tables 85 to 88, pp. 72-73)
 * and 3.2.9 (pp. 22-23); AN12413 3.4.3 says the same for applet 3.x.
 *
 * The flow: the caller reads the chip's ECKA public key once with an attested `ReadObject` of
 * `RESERVED_ID_ECKEY_SESSION` and verifies it (not this layer). `Open()` then runs CreateSession
 * for the credential, makes an ephemeral P-256 key pair on the host, signs SHA-256 of the TLVs
 * 0xA6 (applet AID, SCP id 0xAB with parameters 01 and the level, key type 0x88, key length 0x10)
 * and 0x7F49 (0xB0 the ephemeral public point, 0xF0 curve 03) with the host key, and sends
 * ECKeySessionInternalAuthenticate (CLA 84, INS 88) inside the session. The chip answers a 16-byte
 * random DR.SE (tag 0x85) and a 16-byte receipt (tag 0x86). Both sides compute:
 *
 * - shared secret Z = x(eSK.host * PK.SE.ECKA) (the ephemeral key is released right after);
 * - master key = the first 16 bytes of SHA-256(00000001 || Z || DR.SE || 01 || level || 88 || 10);
 * - S-ENC, S-MAC, S-RMAC = SCP03 KDF of the master key with constants 04, 06, 07, L = 128 and no
 *   context (AN12543: CMAC(MK, 00..00 04 00 00 80 01) and so on);
 * - receipt = CMAC(S-RMAC, the 0xA6 and 0x7F49 TLVs), checked with `ct::Equal` (A15);
 * - the encryption counter starts at 1.
 *
 * Not in AN12543, taken from the middleware read as an oracle: the first MAC chaining value is the
 * SCP03 KDF of the master key with constant 08 and L = 128; the authentication payload is the bare
 * TLVs (Figure 14), not wrapped in TAG_1 as Table 85 suggests; the signature is DER encoded.
 *
 * **Behind a feature flag.** No end-to-end vector of a real chip or of the middleware exists yet,
 * so the session is compiled with `SE05X_ENABLE_ECKEY_SESSION` (default 0): without it `Open()`
 * returns `Unsupported` and sends nothing. The engine (`eckey::detail::Engine`) is always built
 * and tested against the independent model, so turning the flag on changes no code path but the
 * gate.
 *
 * Secrets: the shared secret and the master key exist only inside one call (wiped, released);
 * the session keys are `KeyRef` handles of the crypto port. A session never survives a link
 * reset or a failed response check (S-07, S-15).
 */
#ifndef SE05X_ECKEY_HPP
#define SE05X_ECKEY_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "se05x_ids.hpp"
#include "se05x_ports.hpp"
#include "se05x_scp03.hpp"
#include "se05x_secret.hpp"
#include "se05x_status.hpp"
#include "se05x_types.hpp"

namespace se05x::eckey {

/**
 * @defgroup se05x_eckey ECKey session
 * @brief The ECKey session.
 * @{
 */

/**
 * @brief Whether `Session::Open()` runs the handshake: the build flag `SE05X_ENABLE_ECKEY_SESSION`
 * (define it to 1; absent or 0 means off). Off until the KDF, the receipt and the first MAC
 * chaining value are checked against an oracle vector.
 */
#if defined(SE05X_ENABLE_ECKEY_SESSION) && (SE05X_ENABLE_ECKEY_SESSION != 0)
inline constexpr bool kEcKeySessionEnabled = true;
#else
inline constexpr bool kEcKeySessionEnabled = false;
#endif

/** @brief What `Session::Open()` needs. */
struct SessionParams {
  ObjectId credential{};  ///< The ECKey authentication object on the chip.
  KeyRef host_key{};      ///< The host's long-term P-256 private key handle; it signs.
  ByteSpan se_public_key; ///< The chip's verified ECKA public point, 65 bytes (04 || x || y).
  scp03::SecurityLevel level{scp03::SecurityLevel::Full}; ///< Secure messaging level; none is
                                                          ///< not allowed (AN12543 p. 33).
  bool verify_receipt{true}; ///< Check the receipt (A15); `Config::verify_eckey_receipt`.
};

/**
 * @name Wire constants (AN12543 Tables 85 to 87, Figure 14)
 * @{
 */
inline constexpr uint8_t kClaEcKey = 0x84U;         ///< CLA of ECKeySessionInternalAuthenticate.
inline constexpr uint8_t kInsInternalAuth = 0x88U;  ///< INS of it.
inline constexpr uint8_t kScpIdEcKey = 0xABU;       ///< SCP identifier.
inline constexpr uint8_t kScpParameter = 0x01U;     ///< First SCP parameter byte.
inline constexpr uint8_t kKeyTypeAes = 0x88U;       ///< Key type of the session keys.
inline constexpr uint8_t kKeyLengthAes128 = 0x10U;  ///< Key length of the session keys.
inline constexpr uint8_t kCurveNistP256 = 0x03U;    ///< ECCurve identifier of P-256.
inline constexpr uint8_t kTagChallenge = 0x85U;     ///< DR.SE in the response.
inline constexpr uint8_t kTagReceipt = 0x86U;       ///< Receipt in the response.
inline constexpr std::size_t kChallengeBytes = 16U; ///< DR.SE length.
inline constexpr std::size_t kReceiptBytes = 16U;   ///< Receipt length.
/// The IoT applet AID (AN12543 p. 68).
inline constexpr std::array<uint8_t, 16> kAppletAid{0xA0U, 0x00U, 0x00U, 0x03U, 0x96U, 0x54U,
                                                    0x53U, 0x00U, 0x00U, 0x00U, 0x01U, 0x03U,
                                                    0x00U, 0x00U, 0x00U, 0x00U};
/// Length of the 0xA6 and 0x7F49 TLVs together.
inline constexpr std::size_t kAuthDataBytes = 31U + 73U;
/// Longest ECKeySessionInternalAuthenticate command: header, Lc, the TLVs, 5F37 with a DER
/// signature of at most 72 bytes (no Le, AN13904 Figure 7).
inline constexpr std::size_t kAuthCommandBytes = 5U + kAuthDataBytes + 3U + 72U;
/** @} */

/** @} */

} // namespace se05x::eckey

namespace se05x::eckey::detail {

/**
 * @brief Build the 0xA6 and 0x7F49 TLVs of ECKeySessionInternalAuthenticate.
 * @param host_public The ephemeral public point.
 * @param level The GP level byte.
 * @param out `kAuthDataBytes` bytes.
 */
constexpr void BuildAuthData(std::span<const uint8_t, 65> host_public, uint8_t level,
                             std::span<uint8_t, kAuthDataBytes> out) noexcept;

/**
 * @brief Encode a raw r || s signature as an ASN.1 DER SEQUENCE of two INTEGERs.
 * @param raw r || s.
 * @param out At least 72 bytes.
 * @return The DER length.
 */
constexpr std::size_t EncodeDerSignature(std::span<const uint8_t, 64> raw,
                                         std::span<uint8_t, 72> out) noexcept;

/**
 * @brief The master key: the first 16 bytes of SHA-256(00000001 || Z || DR.SE || 01 || level ||
 * 88 || 10), imported into the crypto port.
 * @tparam K The crypto port.
 * @param crypto The port.
 * @param shared The ECDH shared secret.
 * @param challenge DR.SE (16 zero bytes for `ImportExternalObject`).
 * @param level The GP level byte.
 * @param master The master key handle; the caller releases it.
 * @return `Ok` or `CryptoFailure`.
 */
template <CryptoPort K>
Error DeriveMasterKey(K& crypto, std::span<const uint8_t, 32> shared,
                      std::span<const uint8_t, kChallengeBytes> challenge, uint8_t level,
                      KeyRef& master) noexcept;

/**
 * @brief S-ENC, S-MAC, S-RMAC and the first MAC chaining value from the master key.
 * @tparam K The crypto port.
 * @param crypto The port.
 * @param master The master key.
 * @param keys The session keys; on failure the ones made are released.
 * @param mcv The first chaining value.
 * @return `Ok` or `CryptoFailure`.
 */
template <CryptoPort K>
Error DeriveSessionKeys(K& crypto, KeyRef master, scp03::detail::SessionKeys& keys,
                        std::array<uint8_t, scp03::kMcvBytes>& mcv) noexcept;

/**
 * @brief The ECKey handshake and session, without the build-flag gate: what `Session` runs.
 * Tested against the independent model in every build.
 * @tparam P The port set.
 * @tparam T The lower transport.
 */
template <PortSet P, ApduTransport T>
class Engine {
public:
  /**
   * @brief Bind. No I/O.
   * @param ports The ports.
   * @param lower The lower transport.
   */
  Engine(const P& ports, T& lower) noexcept : pipe_(ports, lower) {}
  /** @brief One per session. */
  Engine(const Engine&) = delete;
  /** @brief One per session. */
  Engine& operator=(const Engine&) = delete;
  /** @brief Releases the session keys (no I/O). */
  ~Engine() noexcept = default;

  /** @brief See `Session::Open()`. @param params The parameters. @return The result. */
  Result<void> Open(const SessionParams& params) noexcept;
  /**
   * @brief See `Session::Transceive()`.
   * @param command The plain command.
   * @param response The plain response buffer.
   * @return The response length or an error.
   */
  Result<std::size_t> Transceive(ByteSpan command, MutableByteSpan response) noexcept;
  /** @brief See `Session::Close()`. @return The result. */
  Result<void> Close() noexcept;
  /** @return true while open. */
  [[nodiscard]] bool IsOpen() const noexcept {
    return open_;
  }
  /** @return true when a failed handshake left a half-open session on the chip. */
  [[nodiscard]] bool NeedsReselect() const noexcept {
    return needs_reselect_;
  }
  /** @return The encryption counter of the next command. */
  [[nodiscard]] uint32_t Counter() const noexcept {
    return pipe_.Sm().Counter();
  }
  /** @return The GP security level byte while open, 0 when closed. */
  [[nodiscard]] uint8_t Level() const noexcept {
    return IsOpen() ? pipe_.Sm().Level() : 0U;
  }
  /** @brief The next answer may be a bare `90 00` ending the session (`DeleteAll`). */
  void ExpectSessionEnd() noexcept {
    pipe_.Sm().ExpectSessionEnd();
  }
  /** @brief Set the host-side attempt limit (S-14). @param limit The limit. */
  void SetAuthAttemptLimit(uint8_t limit) noexcept {
    attempts_ = AttemptLimiter{limit};
  }
  /** @return The attempt limiter. */
  [[nodiscard]] const AttemptLimiter& Attempts() const noexcept {
    return attempts_;
  }

private:
  Result<void> handshake(const SessionParams& params) noexcept;
  Result<void> authenticate(const SessionParams& params, std::span<const uint8_t, 65> host_public,
                            std::span<uint8_t, kAuthDataBytes> auth,
                            std::span<uint8_t, kChallengeBytes> challenge,
                            std::span<uint8_t, kReceiptBytes> receipt) noexcept;
  Result<void> keys(const SessionParams& params, KeyRef ephemeral,
                    std::span<const uint8_t, kAuthDataBytes> auth,
                    std::span<const uint8_t, kChallengeBytes> challenge,
                    std::span<const uint8_t, kReceiptBytes> receipt) noexcept;

  scp03::detail::Pipe<P, T> pipe_;
  AttemptLimiter attempts_;
  bool open_{false};
  bool needs_reselect_{false};
};

} // namespace se05x::eckey::detail

namespace se05x::eckey {

/**
 * @brief One ECKey session over a lower transport.
 *
 * @tparam P A `Ports<...>` set.
 * @tparam T The lower transport (the link, or a platform SCP03 channel); never a UserID session.
 */
template <PortSet P, ApduTransport T>
class Session {
  static_assert(!session::UserIdTransport<T>, "S-14: no secure messaging over a UserID session");

public:
  /**
   * @brief Bind the session. No I/O.
   * @param ports The port set; it must outlive the session.
   * @param lower The lower transport; it must outlive the session.
   */
  Session(const P& ports, T& lower) noexcept : engine_(ports, lower) {}

  /** @brief One session per link. */
  Session(const Session&) = delete;
  /** @brief One session per link. */
  Session& operator=(const Session&) = delete;

  /**
   * @brief Run the handshake and derive the session keys.
   * @param params The credential, the host key and the chip's public key.
   * @return `Unsupported` while `SE05X_ENABLE_ECKEY_SESSION` is 0 (nothing sent); otherwise
   * `Ok`, `InvalidArgument`, `WrongState` (already open), `AuthLocked` (host limit; nothing sent),
   * `AuthFailed` (the chip refused the signature; counted), `SecureChannelError` (bad receipt or
   * malformed answer; counted), `CryptoFailure`, `ThroughputLimited`, the error of CreateSession
   * or of the transport.
   */
  Result<void> Open(const SessionParams& params) noexcept {
    if constexpr (!kEcKeySessionEnabled) {
      static_cast<void>(params);
      return Result<void>::Failure(Error::Unsupported, Detail{.sw = 0U,
                                                              .command = 0xFFU,
                                                              .layer = Layer::EcKey,
                                                              .step = 0U,
                                                              .attempts_left = 0xFFU});
    } else {
      return engine_.Open(params);
    }
  }

  /**
   * @brief Send one command under the session.
   * @param command The plain command APDU.
   * @param response The buffer for the plain response APDU.
   * @return The response length, `NotInitialized`, `SecureChannelError` (closed), `BufferTooSmall`
   * or a transport error (closed).
   */
  Result<std::size_t> Transceive(ByteSpan command, MutableByteSpan response) noexcept {
    return engine_.Transceive(command, response);
  }

  /**
   * @brief Send CloseSession under the session, best effort, and release the keys; never refused.
   * @return `Ok`, or `NeedsReselect` when the chip did not confirm.
   */
  Result<void> Close() noexcept {
    return engine_.Close();
  }

  /** @return true while the session is open. No I/O. */
  [[nodiscard]] bool IsOpen() const noexcept {
    return engine_.IsOpen();
  }
  /** @return true when a failed handshake left a half-open session on the chip. No I/O. */
  [[nodiscard]] bool NeedsReselect() const noexcept {
    return engine_.NeedsReselect();
  }
  /** @return The GP security level byte while open, 0 when closed. No I/O. */
  [[nodiscard]] uint8_t Level() const noexcept {
    return engine_.Level();
  }
  /** @brief The next answer may be a bare `90 00` ending the session (`DeleteAll`). No I/O. */
  void ExpectSessionEnd() noexcept {
    engine_.ExpectSessionEnd();
  }
  /** @brief Set the host-side attempt limit (S-14). @param limit The limit. */
  void SetAuthAttemptLimit(uint8_t limit) noexcept {
    engine_.SetAuthAttemptLimit(limit);
  }

private:
  detail::Engine<P, T> engine_;
};

} // namespace se05x::eckey

// codeql::misra_deviation_next_line(MD-CPP-009)
#include "../src/se05x_eckey.ipp" // IWYU pragma: export

#endif // SE05X_ECKEY_HPP
