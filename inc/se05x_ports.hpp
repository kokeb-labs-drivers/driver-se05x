// clang-format off: the tables below must keep one row per line.
/**
 * @file se05x_ports.hpp
 * @brief The ports of the SE05X driver: I2C bus, clock, crypto with key handles, reset and log, and
 * the `Ports` set that binds them.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Frozen contract. The library calls no SDK. It calls hooks on classes you derive from the CRTP bases
 * below; each base is checked by a concept that matches every hook with its exact signature,
 * `noexcept` included (KB-CPP20-006).
 *
 * | Port | Required | Hooks |
 * | --- | --- | --- |
 * | Bus (`BusInterface<D>`) | yes | `bool EnsureInitialized()`, `BusStatus Write(uint8_t addr7, ByteSpan)`, `BusRead Read(uint8_t addr7, MutableByteSpan)`; optional `uint32_t MaxClockKhz() const` |
 * | Clock (`ClockInterface<D>`) | yes | `uint64_t NowUs()` (monotonic microseconds since boot that never wrap in the life of the device: every deadline is an absolute 64-bit time, so a widened 32-bit counter must count its wraps), `void DelayUs(uint32_t)` (at least the time asked) |
 * | Crypto (`CryptoInterface<D>`) | yes | key handles: `ImportKey`, `ReleaseKey`, `AesCmac`, `AesCbc`, `GenerateP256`, `EcdhP256`, `EcdsaP256Sign`, `EcdsaP256Verify`, `Hash`, `Random` |
 * | Reset (`ResetInterface<D>`) | no | `bool Reset()` (must really reset the chip: ENA on an I2C-only SE050/SE051, RST_N on the SE052), `bool PowerCycle()`, `bool SetEnable(bool)` (ENA pin; false on a part without one) |
 * | Log (`LogInterface<D>`) | no | `void Log(const LogRecord&)` |
 *
 * A call that needs a port the user did not provide does not compile: the member is constrained on
 * `Ports::kHasReset` or `kHasLog`. A missing `ResetInterface` removes the power-cycle rung of the
 * recovery ladder (S-06) and `Device::PowerCycle()`.
 *
 * **What the bus port must do.** `Write` never gets an empty span, and the library never sends an
 * address-only frame (errata I2C.2). `Read` returns the bytes read and a `BusStatus`: `Nack` while the
 * chip is not ready (the link polls), `Timeout`, `BusError` (arbitration, framing) and `BusStuck` (SCL
 * or SDA held low) are distinct, because only the last one needs a power cycle (errata I2C.1). The
 * port moves bytes: it never retries and never frames. Keep SDA and SCL high around a reset (errata
 * I2C.3) and change SCL before SDA with the data sheet's margin (errata I2C.4).
 *
 * **What the crypto port must do.** Keys are handles (`KeyRef`): a hardware key store or a library
 * context sits behind them, and the library never keeps raw key bytes beyond one operation (S-16).
 * `ImportKey` consumes the bytes (the caller wipes its copy with `Zeroize()`); `ReleaseKey` frees the
 * handle and must wipe whatever the port holds. Only operations the secure channels need are here
 * (design section 4); there is no signing with a long-term key on the host.
 */
// clang-format on
#ifndef SE05X_PORTS_HPP
#define SE05X_PORTS_HPP

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

#include "se05x_detail.hpp"
#include "se05x_status.hpp"
#include "se05x_types.hpp"

namespace se05x {

/**
 * @defgroup se05x_ports Ports
 * @brief The hooks the library calls, their concepts and the `Ports` set.
 * @{
 */

/** @brief Outcome of one I2C transaction; the port reports what happened, the link decides. */
enum class BusStatus : uint8_t {
  Ok = 0,       ///< The transaction completed.
  Nack = 1,     ///< The target did not acknowledge: not ready yet, or absent.
  Timeout = 2,  ///< The transaction did not complete in the port's own bound.
  BusError = 3, ///< Arbitration lost or a framing error.
  BusStuck = 4, ///< SCL or SDA held low (errata I2C.1): only a power cycle clears it.
};

/** @brief The result of a bus read: the status and the number of bytes stored in the buffer. */
struct BusRead {
  BusStatus status{BusStatus::Ok}; ///< What happened.
  std::size_t count{0};            ///< Bytes stored; 0 unless `status` is `Ok`.
};

/** @brief Outcome of a crypto port call. */
enum class CryptoStatus : uint8_t {
  Ok = 0,         ///< The operation completed (a verification: the signature is valid).
  Failed = 1,     ///< The operation failed: out of resources, hardware error.
  InvalidKey = 2, ///< A key handle or key bytes are not valid for the operation.
  Mismatch = 3,   ///< A verification ran and the signature is not valid.
};

/** @brief What a key handle holds. */
enum class KeyKind : uint8_t {
  Aes128 = 0,      ///< AES-128 key (SCP03, AESKey session).
  Aes192 = 1,      ///< AES-192 key.
  Aes256 = 2,      ///< AES-256 key (SCP03 with AES-256).
  P256Private = 3, ///< NIST P-256 private key (ECKey session).
};

/** @brief Hash algorithms of the crypto port: pre-hashing of public data only (design section 4).
 */
enum class HashAlg : uint8_t {
  Sha1 = 0,   ///< SHA-1.
  Sha224 = 1, ///< SHA-224.
  Sha256 = 2, ///< SHA-256.
  Sha384 = 3, ///< SHA-384.
  Sha512 = 4, ///< SHA-512.
};

/** @brief Severity of a log record. */
enum class LogLevel : uint8_t {
  Error = 0,   ///< A call failed.
  Warning = 1, ///< Something unexpected that the library recovered from.
  Info = 2,    ///< Lifecycle events: opened, recovered, closed.
  Debug = 3,   ///< Detail for bring-up: still never secret bearing.
};

namespace detail {
/// Last enumerator of `BusStatus`.
template <>
struct EnumLast<BusStatus> {
  static constexpr BusStatus kValue = BusStatus::BusStuck; ///< The last enumerator.
};
/// Last enumerator of `CryptoStatus`.
template <>
struct EnumLast<CryptoStatus> {
  static constexpr CryptoStatus kValue = CryptoStatus::Mismatch; ///< The last enumerator.
};
/// Last enumerator of `KeyKind`.
template <>
struct EnumLast<KeyKind> {
  static constexpr KeyKind kValue = KeyKind::P256Private; ///< The last enumerator.
};
/// Last enumerator of `HashAlg`.
template <>
struct EnumLast<HashAlg> {
  static constexpr HashAlg kValue = HashAlg::Sha512; ///< The last enumerator.
};
/// Last enumerator of `LogLevel`.
template <>
struct EnumLast<LogLevel> {
  static constexpr LogLevel kValue = LogLevel::Debug; ///< The last enumerator.
};
} // namespace detail

/**
 * @brief An opaque handle to a key held by the crypto port. Id 0 is "no key".
 *
 * The id is the port's own index or identifier; the library never interprets it.
 */
struct KeyRef {
  uint32_t id{0}; ///< Port-defined; 0 is invalid.

  /** @return true when the handle refers to a key. */
  [[nodiscard]] constexpr bool IsValid() const noexcept {
    return id != 0U;
  }
};

/**
 * @brief One log record (S-02): which layer, which command, which status word and error, and a
 * payload length. Never a span, never a key, never a payload: the type has nowhere to put one.
 */
struct LogRecord {
  LogLevel level{LogLevel::Info}; ///< Severity.
  Layer layer{Layer::None};       ///< The layer that logs.
  uint8_t command{0xFF};          ///< `Command` value, 0xFF when none.
  uint16_t sw{0};                 ///< Chip status word, 0 when none.
  Error error{Error::Ok};         ///< The error being reported, `Ok` for an event.
  uint16_t length{0};   ///< Length of the command or response in bytes, never its content.
  const char* text{""}; ///< A static plain-text event name; never a format string.
};

namespace detail {

/// The tag types that make each port base a distinct class template (so a port derives from exactly
/// the base it implements).
struct BusTag {};
/// Tag of the clock port.
struct ClockTag {};
/// Tag of the crypto port.
struct CryptoTag {};
/// Tag of the reset port.
struct ResetTag {};
/// Tag of the log port.
struct LogTag {};

/**
 * @brief CRTP base of every port. It declares no hook itself (a forwarding hook would turn a
 * missing override into infinite recursion) and no data; the concepts check the derived class.
 *
 * @tparam Derived Your port class.
 * @tparam Tag Which port this base marks.
 */
template <typename Derived, typename Tag>
class PortBase {
public:
  /** @brief Ports are not copied: the library holds a reference. */
  PortBase(const PortBase&) = delete;
  /** @brief Ports are not copied: the library holds a reference. */
  PortBase& operator=(const PortBase&) = delete;

protected:
  /** @brief Only the derived port is constructed. */
  PortBase() noexcept = default;
  /** @brief Destroyed through the derived port only. */
  ~PortBase() noexcept = default;
};

} // namespace detail

/** @brief CRTP base of the I2C bus port. */
template <typename Derived>
using BusInterface = detail::PortBase<Derived, detail::BusTag>;
/** @brief CRTP base of the clock port. */
template <typename Derived>
using ClockInterface = detail::PortBase<Derived, detail::ClockTag>;
/** @brief CRTP base of the crypto port. */
template <typename Derived>
using CryptoInterface = detail::PortBase<Derived, detail::CryptoTag>;
/** @brief CRTP base of the optional reset port. */
template <typename Derived>
using ResetInterface = detail::PortBase<Derived, detail::ResetTag>;
/** @brief CRTP base of the optional log port. */
template <typename Derived>
using LogInterface = detail::PortBase<Derived, detail::LogTag>;

/// Satisfied by a class that derives from `BusInterface` and has the three bus hooks, exactly.
template <typename Port>
concept BusPort = std::derived_from<Port, BusInterface<Port>> && requires {
  detail::ExactHook<Port, bool() noexcept>::Take(&Port::EnsureInitialized);
  detail::ExactHook<Port, BusStatus(uint8_t, ByteSpan) noexcept>::Take(&Port::Write);
  detail::ExactHook<Port, BusRead(uint8_t, MutableByteSpan) noexcept>::Take(&Port::Read);
};

/// Satisfied by a class that derives from `ClockInterface` and has `NowUs()` and `DelayUs()`,
/// exactly.
template <typename Port>
concept ClockPort = std::derived_from<Port, ClockInterface<Port>> && requires {
  detail::ExactHook<Port, uint64_t() noexcept>::Take(&Port::NowUs);
  detail::ExactHook<Port, void(uint32_t) noexcept>::Take(&Port::DelayUs);
};

/// Satisfied by a class that derives from `CryptoInterface` and has every crypto hook, exactly.
template <typename Port>
concept CryptoPort = std::derived_from<Port, CryptoInterface<Port>> && requires {
  detail::ExactHook<Port, CryptoStatus(KeyKind, ByteSpan, KeyRef&) noexcept>::Take(
      &Port::ImportKey);
  detail::ExactHook<Port, CryptoStatus(KeyRef) noexcept>::Take(&Port::ReleaseKey);
  detail::ExactHook<Port, CryptoStatus(KeyRef, ByteSpan, std::span<uint8_t, 16>) noexcept>::Take(
      &Port::AesCmac);
  detail::ExactHook<Port, CryptoStatus(KeyRef, bool, std::span<uint8_t, 16>,
                                       MutableByteSpan) noexcept>::Take(&Port::AesCbc);
  detail::ExactHook<Port, CryptoStatus(KeyRef&, std::span<uint8_t, 65>) noexcept>::Take(
      &Port::GenerateP256);
  detail::ExactHook<Port, CryptoStatus(KeyRef, std::span<const uint8_t, 65>,
                                       std::span<uint8_t, 32>) noexcept>::Take(&Port::EcdhP256);
  detail::ExactHook<Port,
                    CryptoStatus(KeyRef, std::span<const uint8_t, 32>,
                                 std::span<uint8_t, 64>) noexcept>::Take(&Port::EcdsaP256Sign);
  detail::ExactHook<Port, CryptoStatus(
                              std::span<const uint8_t, 65>, std::span<const uint8_t, 32>,
                              std::span<const uint8_t, 64>) noexcept>::Take(&Port::EcdsaP256Verify);
  detail::ExactHook<Port, CryptoStatus(HashAlg, ByteSpan, MutableByteSpan) noexcept>::Take(
      &Port::Hash);
  detail::ExactHook<Port, CryptoStatus(MutableByteSpan) noexcept>::Take(&Port::Random);
};

/// Satisfied by a class that derives from `ResetInterface` and has `Reset()`, `PowerCycle()` and
/// `SetEnable()`, exactly.
template <typename Port>
concept ResetPort = std::derived_from<Port, ResetInterface<Port>> && requires {
  detail::ExactHook<Port, bool() noexcept>::Take(&Port::Reset);
  detail::ExactHook<Port, bool() noexcept>::Take(&Port::PowerCycle);
  detail::ExactHook<Port, bool(bool) noexcept>::Take(&Port::SetEnable);
};

/// Satisfied by a class that derives from `LogInterface` and has `Log(const LogRecord&)`, exactly.
template <typename Port>
concept LogPort = std::derived_from<Port, LogInterface<Port>> && requires {
  detail::ExactHook<Port, void(const LogRecord&) noexcept>::Take(&Port::Log);
};

/// The port declares something called `MaxClockKhz` (used to reject a misdeclared hook).
template <typename Port>
concept DeclaresMaxClockKhz = requires(const Port& port) { port.MaxClockKhz(); };
/// The bus port reports its clock: `uint32_t MaxClockKhz() const noexcept`.
template <typename Port>
concept HasMaxClockKhz =
    requires { detail::ExactHook<Port, uint32_t() noexcept>::Take(&Port::MaxClockKhz); };

/// The placeholder of an absent optional port; it satisfies no port concept.
struct Absent {};

/**
 * @brief The set of ports one `Device` works through: references to the bus, the clock and the
 * crypto port, and, when given, the reset and log ports.
 *
 * `Ports<Bus, Clock, Crypto>` is the smallest set. `Ports<Bus, Clock, Crypto, Reset, Log>` adds the
 * optional ones; pass `Absent` for the one you leave out (`Ports<B, C, K, Absent, MyLog>`). The set
 * owns nothing: every port must outlive it.
 *
 * @tparam B The bus port.
 * @tparam C The clock port.
 * @tparam K The crypto port.
 * @tparam R The reset port or `Absent`.
 * @tparam L The log port or `Absent`.
 */
template <BusPort B, ClockPort C, CryptoPort K, typename R = Absent, typename L = Absent>
  requires(std::same_as<R, Absent> || ResetPort<R>) && (std::same_as<L, Absent> || LogPort<L>)
class Ports {
public:
  /// The bus port type.
  using BusType = B;
  /// The clock port type.
  using ClockType = C;
  /// The crypto port type.
  using CryptoType = K;
  /// The reset port type, or `Absent`.
  using ResetType = R;
  /// The log port type, or `Absent`.
  using LogType = L;
  /// Whether a reset port is present.
  static constexpr bool kHasReset = !std::same_as<R, Absent>;
  /// Whether a log port is present.
  static constexpr bool kHasLog = !std::same_as<L, Absent>;

  /**
   * @brief Bind the required ports; the optional ones stay absent.
   * @param bus The bus port.
   * @param clock The clock port.
   * @param crypto The crypto port.
   */
  Ports(B& bus, C& clock, K& crypto) noexcept
    requires(!kHasReset && !kHasLog)
      : bus_(&bus), clock_(&clock), crypto_(&crypto) {}

  /**
   * @brief Bind the required ports and a reset port.
   * @param bus The bus port.
   * @param clock The clock port.
   * @param crypto The crypto port.
   * @param reset The reset port.
   */
  Ports(B& bus, C& clock, K& crypto, R& reset) noexcept
    requires(kHasReset && !kHasLog)
      : bus_(&bus), clock_(&clock), crypto_(&crypto), reset_(&reset) {}

  /**
   * @brief Bind the required ports and a log port.
   * @param bus The bus port.
   * @param clock The clock port.
   * @param crypto The crypto port.
   * @param log The log port.
   */
  Ports(B& bus, C& clock, K& crypto, L& log) noexcept
    requires(!kHasReset && kHasLog)
      : bus_(&bus), clock_(&clock), crypto_(&crypto), log_(&log) {}

  /**
   * @brief Bind every port.
   * @param bus The bus port.
   * @param clock The clock port.
   * @param crypto The crypto port.
   * @param reset The reset port.
   * @param log The log port.
   */
  Ports(B& bus, C& clock, K& crypto, R& reset, L& log) noexcept
    requires(kHasReset && kHasLog)
      : bus_(&bus), clock_(&clock), crypto_(&crypto), reset_(&reset), log_(&log) {}

  /** @return The bus port. */
  [[nodiscard]] B& GetBus() const noexcept {
    return *bus_;
  }
  /** @return The clock port. */
  [[nodiscard]] C& GetClock() const noexcept {
    return *clock_;
  }
  /** @return The crypto port. */
  [[nodiscard]] K& GetCrypto() const noexcept {
    return *crypto_;
  }
  /** @return The reset port; present only when the set has one. */
  [[nodiscard]] R& GetReset() const noexcept
    requires(kHasReset)
  {
    return *reset_;
  }

  /**
   * @brief Hand a record to the log port, or drop it when the set has none. The record has no
   * secret (S-02).
   * @param record The record.
   */
  void Emit(const LogRecord& record) const noexcept {
    if constexpr (kHasLog) {
      log_->Log(record);
    } else {
      static_cast<void>(record);
    }
  }

private:
  B* bus_;
  C* clock_;
  K* crypto_;
  R* reset_{nullptr};
  L* log_{nullptr};
};

/// Satisfied by every `Ports<...>`: what the layers take as their template argument.
template <typename T>
concept PortSet =
    requires {
      typename T::BusType;
      typename T::ClockType;
      typename T::CryptoType;
      { T::kHasReset } -> std::convertible_to<bool>;
      { T::kHasLog } -> std::convertible_to<bool>;
    } && BusPort<typename T::BusType> && ClockPort<typename T::ClockType> &&
    CryptoPort<typename T::CryptoType>;

/// Satisfied by a layer that can carry one command APDU: `Result<size_t> Transceive(ByteSpan,
/// MutableByteSpan)`.
template <typename T>
concept ApduTransport = requires(T& transport, ByteSpan command, MutableByteSpan response) {
  { transport.Transceive(command, response) } -> std::same_as<Result<std::size_t>>;
};

/** @} */

} // namespace se05x

#endif // SE05X_PORTS_HPP
