/**
 * @file se05x_types.hpp
 * @brief Shared vocabulary of the SE05X driver: byte views, size limits, families, versions and
 * `Config`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Frozen contract. Plain data with no platform dependency, so handlers, tests and tools can include
 * it without the driver. `Config{}` holds the defaults of the design (`docs/ambiguities.md` names
 * the knob of every open question); `Validate()` checks a configuration with no I/O.
 */
#ifndef SE05X_TYPES_HPP
#define SE05X_TYPES_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "se05x_commands.hpp"
#include "se05x_detail.hpp"
#include "se05x_i2c_interface.hpp"
#include "se05x_status.hpp"
#include "se05x_version.h"

/** @brief The SE05X driver: everything it declares lives here; internals in `detail`. */
namespace se05x {

/**
 * @brief Whether the irreversible operations are compiled in (S-10): lifecycle locks, the platform
 * SCP requirement, platform key replacement, feature changes, `DeleteAll`. The build flag
 * `SE05X_ENABLE_IRREVERSIBLE` (define it to 1; absent or 0 means off) sets it; CMake sets the flag
 * with the option of the same name, Kconfig with `CONFIG_SE05X_ENABLE_IRREVERSIBLE`. Members that
 * perform an irreversible operation are constrained on this, so a default build cannot call them.
 */
#if defined(SE05X_ENABLE_IRREVERSIBLE) && (SE05X_ENABLE_IRREVERSIBLE != 0)
inline constexpr bool kIrreversibleEnabled = true;
#else
inline constexpr bool kIrreversibleEnabled = false;
#endif

/**
 * @defgroup se05x_types Shared types
 * @brief Byte views, limits, chip families, versions and the configuration.
 * @{
 */

/// A read-only view of bytes: every input of the library.
using ByteSpan = std::span<const uint8_t>;
/// A writable view of bytes: every output of the library (no heap, the caller owns the buffer).
using MutableByteSpan = std::span<uint8_t>;

/**
 * @brief Up to `N` bytes held by value: the reply type of commands whose answer is short and fixed
 * in size. `length` says how many are valid.
 * @tparam N Capacity in bytes.
 */
template <std::size_t N>
struct FixedBytes {
  std::array<uint8_t, N> bytes{}; ///< The storage; only the first `length` bytes are valid.
  std::size_t length{0};          ///< Number of valid bytes, at most `N`.

  /** @return A view of the valid bytes. */
  [[nodiscard]] constexpr ByteSpan View() const& noexcept {
    return ByteSpan{bytes.data(), length};
  }
  /** @brief Not on a temporary: the view would dangle (KB-CPP20-044). */
  void View() const&& = delete;
};

/**
 * @name Size limits
 * Every buffer of the library is sized from these; every loop is bounded by them (S-04).
 * @{
 */
/// Largest command or response payload of one APDU when the command sets no lower limit: the
/// applet's 1024-byte internal buffer (AN12543 2.2 p. 3). Its APDU buffer is 270 bytes
/// (`wire::kApduBuffer`); commands with their own limit (AEAD one-shot 888, EdDSA 940 or 919) check
/// it in their codec.
inline constexpr std::size_t kMaxApduPayload = 1024U;
/// Largest response the chip returns and the driver accepts: 1024 bytes (errata APP.1 refuses
/// more).
inline constexpr std::size_t kMaxResponse = 1024U;
/// Largest plain command APDU a codec writes: header (4), extended Lc (3), a data field as large as
/// the internal buffer (`kMaxApduPayload`) and an extended Le (2). A 940-byte EdDSA verify input is
/// a 1028-byte plain APDU (AN12543 4.10.2.2 p. 104).
inline constexpr std::size_t kMaxPlainCommandApdu = 4U + 3U + kMaxApduPayload + 2U;
/// What one secure-messaging layer adds at most: ISO/IEC 9797-1 method 2 padding (up to 16 bytes),
/// the 8-byte C-MAC and a short Lc that becomes extended (2 bytes).
inline constexpr std::size_t kSecureMessagingOverhead = 16U + 8U + 2U;
/// What `ProcessSessionCmd` framing adds around a session command: a header with an extended Lc
/// (7), the session id TLV (10), TAG_1 with a three-byte length (4) and an extended Le (2).
inline constexpr std::size_t kSessionFrameOverhead = 7U + 10U + 4U + 2U;
/// Largest command APDU on the wire: a plain command wrapped by an applet session, framed, and
/// wrapped again by platform SCP03 (the deepest stack, `se05x_device_stage.hpp`).
inline constexpr std::size_t kMaxCommandApdu = kMaxPlainCommandApdu + kSecureMessagingOverhead +
                                               kSessionFrameOverhead + kSecureMessagingOverhead;
/// Largest policy set of one object, in bytes (AN12413 policy chapter).
inline constexpr std::size_t kMaxPolicyBytes = 255U;
/// Default T=1 information field size of the chip, IFSC and IFSD (ATR/CIP default of the SE052F).
inline constexpr uint16_t kDefaultIfs = 254;
/// Default block waiting time in milliseconds (ATR/CIP default of the SE052F).
inline constexpr uint16_t kDefaultBwtMs = 1000;
/// Length of the unique chip identifier in an attested read, in bytes (AN12413, derived).
inline constexpr std::size_t kUniqueIdLength = 18U;
/// Length of the attestation freshness nonce, in bytes.
inline constexpr std::size_t kFreshnessLength = 16U;
/// Length of the chip timestamp in an attested read, in bytes.
inline constexpr std::size_t kTimestampLength = 12U;
/// Length of the extended feature bits of applet 7.x, in bytes.
inline constexpr std::size_t kExtFeatureLength = 30U;
/** @} */

/** @brief The chip families, named after the data sheets. A part is identified by what it reports.
 */
enum class Family : uint8_t {
  Unknown = 0, ///< Not identified, or not a member of the family.
  Se050A,      ///< SE050 A1/A2: ECC, applet 3.x.
  Se050B,      ///< SE050 B1/B2: RSA, applet 3.x.
  Se050C,      ///< SE050 C1/C2: ECC and RSA, more cloud keys.
  Se050D,      ///< SE050 D2: A plus MIFARE DESFire.
  Se050E,      ///< SE050 E2: applet 7.2.
  Se050F,      ///< SE050 F2: FIPS 140-2 configuration of applet 3.6.0.
  Se051A,      ///< SE051 A: applet 7.2.
  Se051C,      ///< SE051 C: applet 7.2.
  Se051H,      ///< SE051 H: adds NFC (T4T, Matter).
  Se051P,      ///< SE051 P: hosts a customer applet (no IoT applet).
  Se051W,      ///< SE051 W: adds UWB.
  Se052F,      ///< SE052 F2: FIPS 140-3, applet 7.2.22, no ENA pin.
};

/** @brief The T=1 frame flavours (ambiguity A9). */
enum class TransportFlavour : uint8_t {
  Auto = 0,    ///< Try the GP flavour (CIP), then UM11225 (ATR); fix on the first valid CRC.
  Um11225 = 1, ///< One-byte LEN (SE050, SE051).
  Gp = 2,      ///< Two-byte LEN, GlobalPlatform T=1' (SE052).
};

/** @brief When the library opens a platform SCP03 channel (S-13). */
enum class ScpPolicy : uint8_t {
  /// Open one when the chip requires it; report a plain bus in `Capabilities` otherwise. The
  /// requirement is read from ReadState, which is not authenticated: a host on the bus can make
  /// `Auto` skip platform SCP03 (the facade then fails closed). Use `Require` for a root of trust.
  Auto = 0,
  Require = 1, ///< Open one always; `Open()` fails when it cannot.
  Off = 2,     ///< Never; refused with `WrongState` when the chip requires it.
};

/** @brief Timeout class of a command (ambiguity A11): selects the entry of `Timeouts`. */
enum class CommandClass : uint8_t {
  Fast = 0,   ///< Most commands.
  KeyGen = 1, ///< RSA key generation and other long computations.
  Kdf = 2,    ///< PBKDF2 and friends.
  Attest = 3, ///< Attested reads and signatures.
};

namespace detail {
/// Last enumerator of `Family`.
template <>
struct EnumLast<Family> {
  static constexpr Family kValue = Family::Se052F; ///< The last enumerator.
};
/// Last enumerator of `TransportFlavour`.
template <>
struct EnumLast<TransportFlavour> {
  static constexpr TransportFlavour kValue = TransportFlavour::Gp; ///< The last enumerator.
};
/// Last enumerator of `ScpPolicy`.
template <>
struct EnumLast<ScpPolicy> {
  static constexpr ScpPolicy kValue = ScpPolicy::Off; ///< The last enumerator.
};
/// Last enumerator of `CommandClass`.
template <>
struct EnumLast<CommandClass> {
  static constexpr CommandClass kValue = CommandClass::Attest; ///< The last enumerator.
};
} // namespace detail

/**
 * @brief The applet generation: it decides the policy layout, the attestation format and the
 * command set. A first-class capability: the driver never derives behaviour from a part name.
 */
enum class AppletGeneration : uint8_t {
  V3 = 0, ///< Applet 3.x (SE050 A to D and F).
  V6 = 1, ///< Applet 6.x (SE051 boards before 2022, OEF A564): no oracle vectors exist for it.
  V7 = 2, ///< Applet 7.x (SE050E, SE051 7.2 and 7.3, SE052).
};

namespace detail {
/// Last enumerator of `AppletGeneration`.
template <>
struct EnumLast<AppletGeneration> {
  static constexpr AppletGeneration kValue = AppletGeneration::V7; ///< The last enumerator.
};
} // namespace detail

/** @brief An applet version, as reported by the select response. */
struct AppletVersion {
  uint8_t major{
      0}; ///< Major version: 3 (SE050 A to D and F), 6 (older SE051) or 7 (SE050E, SE051, SE052).
  uint8_t minor{0}; ///< Minor version.
  uint8_t patch{0}; ///< Patch version.

  /** @return The version as one comparable number, `major << 16 | minor << 8 | patch`. */
  [[nodiscard]] constexpr uint32_t Packed() const noexcept {
    return (static_cast<uint32_t>(major) << 16U) | (static_cast<uint32_t>(minor) << 8U) |
           static_cast<uint32_t>(patch);
  }
  /**
   * @brief Whether this version is at least `other`.
   * @param other The version to compare with.
   * @return true when `Packed()` is not below `other.Packed()`.
   */
  [[nodiscard]] constexpr bool AtLeast(AppletVersion other) const noexcept {
    return Packed() >= other.Packed();
  }
  /** @return The generation of this version; `V3` below 6, `V6` for 6.x, `V7` from 7. */
  [[nodiscard]] constexpr AppletGeneration Generation() const noexcept {
    if (major >= 7U) {
      return AppletGeneration::V7;
    }
    return (major == 6U) ? AppletGeneration::V6 : AppletGeneration::V3;
  }
};

/**
 * @brief The per-class timeouts of commands, in milliseconds (ambiguity A11).
 *
 * The middleware's consistent timeout of about 20 s when the chip does not answer is a reference,
 * not a contract; these are ours.
 */
struct Timeouts {
  uint32_t fast_ms{2000};     ///< `CommandClass::Fast`.
  uint32_t key_gen_ms{20000}; ///< `CommandClass::KeyGen`.
  uint32_t kdf_ms{10000};     ///< `CommandClass::Kdf`.
  uint32_t attest_ms{5000};   ///< `CommandClass::Attest`.

  /**
   * @param command_class The class.
   * @return The timeout of that class; the fast one for a value that is not an enumerator.
   */
  [[nodiscard]] constexpr uint32_t For(CommandClass command_class) const noexcept {
    switch (command_class) {
    case CommandClass::Fast:
      return fast_ms;
    case CommandClass::KeyGen:
      return key_gen_ms;
    case CommandClass::Kdf:
      return kdf_ms;
    case CommandClass::Attest:
      return attest_ms;
    default:
      break;
    }
    return fast_ms;
  }
};

/// Longest `boot_wait_ms` and `atr_poll_budget_ms` the driver accepts.
inline constexpr uint32_t kMaxWaitMs = 10000;
/// Longest per-command timeout the driver accepts, in milliseconds (KB-CPP20-058).
inline constexpr uint32_t kMaxCommandTimeoutMs = 120000;
/// Most block retries before the link escalates (design 5.2 `kFrameRetries`).
inline constexpr uint8_t kMaxFrameRetries = 10;
/// Block resends before a resynchronisation in the default configuration.
inline constexpr uint8_t kDefaultFrameRetries = 3;
/// Most waiting-time extensions one command may receive before it fails with `Timeout` (S-05).
/// The total time per command class (`Timeouts`) bounds it as well; the middleware's reference is a
/// consistent timeout of about 20 s, not a count (ambiguity A11).
inline constexpr uint16_t kMaxWtxCount = 255;
/// Waiting-time extensions the default configuration accepts per command.
inline constexpr uint16_t kDefaultWtxLimit = 64;
/// Waiting-time extensions the chip may send before the first response of a session open, to flush
/// an earlier transaction (middleware reference: up to 40); the link answers each within the
/// budget.
inline constexpr uint16_t kSessionOpenWtxAllowance = 40;
/// APDUs after which the chip may answer SW 0x66A6 until it is reset (S-17; AN14028 2.3.1: more
/// than one million within 34 days on SE052F; possible on SE051).
inline constexpr uint32_t kThroughputLimitApdus = 1000000U;
/// The window of that limit, in days.
inline constexpr uint32_t kThroughputWindowDays = 34U;
/// Most data bytes of one attested binary read; longer objects are read in verified chunks.
inline constexpr uint16_t kMaxAttestedBinaryRead = 500U;

/**
 * @brief Everything `Device::Open()` and the layers below it take. The defaults are the choices of
 * the design; every ambiguity of `docs/ambiguities.md` has a field here or a model knob.
 *
 * It has no `operator==`. Fields with a unit carry it as a suffix.
 */
struct Config {
  uint8_t i2c_address{kI2cAddress};                 ///< 7-bit target address; read-only in v1 (A7).
  TransportFlavour flavour{TransportFlavour::Auto}; ///< Frame flavour (A9).
  uint32_t boot_wait_ms{20};         ///< Wait after power-up before the first frame (A8).
  uint32_t atr_poll_budget_ms{1000}; ///< Longest wait for the ATR/CIP after boot (A8).
  uint32_t poll_interval_us{1000};   ///< Polling period of a chip that NAKs until ready (>= 1 ms).
  Timeouts timeouts{};               ///< Per-class command timeouts (A11).
  uint8_t frame_retries{kDefaultFrameRetries}; ///< Block resends before a resync (S-06).
  uint16_t wtx_limit{kDefaultWtxLimit};        ///< Waiting-time extensions per command (S-05).
  ScpPolicy scp_policy{ScpPolicy::Auto};       ///< Platform SCP03 use (S-13).
  uint8_t auth_attempt_limit{3}; ///< Host-side authentication attempts per session (S-14).
  bool probe_capabilities{true}; ///< Probe digest support and the curve list at `Open()` (A4, A5).
  bool verify_eckey_receipt{true}; ///< Check the ECKey session receipt (A15).
  bool allow_lab_override{false};  ///< Lab only: let `TransmitRaw()` bypass the capability gate.
  // The {} keeps `Config{.field = value}` free of -Wmissing-designated-field-initializers (clang).
  // NOLINTNEXTLINE(readability-redundant-member-init)
  CommandSet held_commands{}; ///< Commands refused as `Unsupported` (A6 knob).
};

namespace detail {
/// The bus and enumeration fields of `Validate`.
constexpr bool BusFieldsValid(const Config& config) noexcept {
  return IsEnumerator(config.flavour) && IsEnumerator(config.scp_policy) &&
         (config.i2c_address <= 0x7FU) && (config.boot_wait_ms <= kMaxWaitMs) &&
         (config.atr_poll_budget_ms != 0U) && (config.atr_poll_budget_ms <= kMaxWaitMs) &&
         (config.poll_interval_us >= 1000U) && (config.poll_interval_us <= 1'000'000U);
}
/// The timeout fields of `Validate`.
constexpr bool TimeoutsValid(const Timeouts& timeouts) noexcept {
  const auto in_range = [](uint32_t ms) { return (ms != 0U) && (ms <= kMaxCommandTimeoutMs); };
  return in_range(timeouts.fast_ms) && in_range(timeouts.key_gen_ms) && in_range(timeouts.kdf_ms) &&
         in_range(timeouts.attest_ms);
}
/// The retry and limit fields of `Validate`.
constexpr bool LimitsValid(const Config& config) noexcept {
  return (config.frame_retries != 0U) && (config.frame_retries <= kMaxFrameRetries) &&
         (config.wtx_limit != 0U) && (config.wtx_limit <= kMaxWtxCount) &&
         (config.auth_attempt_limit != 0U);
}
} // namespace detail

/**
 * @brief Check a configuration without touching the chip.
 *
 * Fails when an enumeration holds a value that is not an enumerator, a wait or timeout is zero or
 * above its maximum, the poll interval is below 1 ms or above one second, the retry, WTX or attempt
 * limit is zero or above its maximum, or the I2C address is not a 7-bit address.
 *
 * @param config The configuration.
 * @return `Error::Ok` or `Error::InvalidArgument`.
 */
constexpr Error Validate(const Config& config) noexcept {
  if (detail::BusFieldsValid(config) && detail::TimeoutsValid(config.timeouts) &&
      detail::LimitsValid(config)) {
    return Error::Ok;
  }
  return Error::InvalidArgument;
}

static_assert(Validate(Config{}) == Error::Ok);

/**
 * @brief Reached only when a `CheckedConfig` is built from an invalid configuration: it is never
 * defined, so the build fails and names it (KB-CPP20-013).
 */
void ConfigIsInvalid() noexcept;

/**
 * @brief A configuration proven valid at build time.
 *
 * `constexpr CheckedConfig kBoard{Config{.boot_wait_ms = 50}};` fails to compile, naming
 * `ConfigIsInvalid`, when `Validate()` rejects the configuration. Pass `kBoard.Get()` to the
 * driver; the driver still validates at `Open()`, for configurations built at run time.
 */
class CheckedConfig {
public:
  /**
   * @brief Check `config` at build time.
   * @param config The configuration; it must pass `Validate()`.
   */
  consteval explicit CheckedConfig(const Config& config) noexcept : config_(config) {
    if (Validate(config) != Error::Ok) {
      ConfigIsInvalid();
    }
  }
  /** @return The checked configuration. */
  [[nodiscard]] constexpr const Config& Get() const& noexcept {
    return config_;
  }
  /** @brief Not on a temporary: the reference would dangle (KB-CPP20-044). */
  void Get() const&& = delete;

private:
  Config config_;
};

/** @return The driver version, e.g. `"0.1.0"`, from the generated `se05x_version.h`. No I/O. */
constexpr const char* GetDriverVersion() noexcept {
  return SE05X_VERSION_STRING;
}
/** @return The major version. No I/O. */
constexpr uint32_t GetDriverVersionMajor() noexcept {
  return SE05X_VERSION_MAJOR;
}
/** @return The minor version. No I/O. */
constexpr uint32_t GetDriverVersionMinor() noexcept {
  return SE05X_VERSION_MINOR;
}
/** @return The patch version. No I/O. */
constexpr uint32_t GetDriverVersionPatch() noexcept {
  return SE05X_VERSION_PATCH;
}

/** @} */

} // namespace se05x

#endif // SE05X_TYPES_HPP
