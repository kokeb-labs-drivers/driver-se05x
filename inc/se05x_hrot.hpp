/**
 * @file se05x_hrot.hpp
 * @brief The "easy root of trust" facade: identity, keys by slot, sign, verify, ECDH, attest,
 * stored data and certificates, monotonic counters, random numbers, the APDU budget and a
 * transaction scope.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * The facade is a small, hard-to-misuse layer over `se05x::Device`. Each common job of a hardware
 * root of trust is one call with a typed result:
 *
 * - Objects are named by typed slots (`Slot` for keys, `DataSlot`, `CounterSlot`, `CertSlot`), so
 *   a data slot cannot be passed where a key slot is meant: it does not compile. Each kind maps to
 *   its own id range `kObjectBase | kind << 8 | index` (user ids, never a reserved one).
 * - Keys are `Key<U>` values typed by their use (`SignKey`, `AttestKey`, `AgreeKey`, `TlsKey`,
 *   `VerifyKey`); only the facade creates a valid one, and each call takes only the key type it
 *   is for: `Sign()` does not accept an `AgreeKey`. Keys are NIST P-256, generated inside the chip
 *   (`Origin::Internal`); a key handle never holds key material.
 * - Policies are built by the strict profile only (S-03): every facade key forbids write, delete
 *   and generate, and requires secure messaging; a counter forbids delete. A facade key or counter
 *   can therefore never be deleted or replaced; only a factory reset
 *   (`irreversible::DeleteAllObjects`) removes it. Each policy names the default session
 *   (authentication object 0) and, when the facade runs inside an AESKey or ECKey session, that
 *   session's credential too: id 0 does not cover other sessions (AN12543 3.7.1.2 p. 36), so an
 *   object used from another session is refused by the chip (fail closed, docs/ambiguities.md A20).
 * - A call whose result the caller acts on (a key, a counter, a verification) needs authenticated
 *   answers: a secure-messaging layer with R-MAC (`Device::AnswersAuthenticated()`). A call that
 *   moves a secret (ECDH, `Protection::Secret` data) needs encryption both ways as well
 *   (`Device::TrafficConfidential()`). Otherwise the facade refuses with `PolicyDenied` (layer
 *   `Hrot`) and sends nothing (S-14): over a bus that can be probed, an unauthenticated answer
 *   could be forged, and an unencrypted one read.
 * - A value read with an attestation comes back only as `Verified<T>`, a type that exists only
 *   after the signature, the freshness, the timestamp order and the unique identifier have been
 *   checked (S-04, S-09).
 * - The facade cannot reach an irreversible operation: there is no path from here to
 *   `irreversible::Operations`.
 * - Every call is counted against the APDU budget (S-17, `ApduBudget`): a call is admitted only
 *   when its worst-case APDU count (`cost`) fits under the chip's throughput ceiling, else it is
 *   refused with `ThroughputLimited` (layer `Hrot`) before anything is sent. One path sends more
 *   than the admitted cost: when the chip answers SW 0x66A6 anyway, the device resets it and
 *   selects the applet again, which sends up to four APDUs (the select, the lifecycle read and,
 *   with platform SCP03, the two handshake commands). They are counted in `Used()`, and the call
 *   sends nothing after them, so one call ends at most four APDUs past the ceiling.
 * - The facade needs applet 7.x (SE050E, SE051, SE052). On applet 3.x (SE050 A to D, F) and 6.x
 *   (SE051 on early boards, OEF A564 and A565) every call returns `Unsupported` before anything is
 *   sent, after its argument checks (an invalid key, an off-curve point or an empty buffer is
 *   refused first with `InvalidArgument`): AN12413 has no plain attribute read, so a key or
 *   counter made on 3.x could never be adopted again after a reboot, and applet 6.x has no
 *   specification in hand. Use `se05x::Device` directly on 3.x and 6.x.
 *
 * Certificates: the facade stores and reads the bytes only. Parsing, building and verifying DER,
 * X.509 and PKCS#10 is the optional `se05x::pki` layer; the integration point is the trusted
 * public key of `TrustAttestationKey()`, which should come from a certificate that layer verified.
 *
 * Rules S-01 to S-17 are in `docs/safety.md`; the jobs, with compiled examples, in
 * `docs/getting-started.md` and `docs/hrot-cookbook.md`.
 */
#ifndef SE05X_HROT_HPP
#define SE05X_HROT_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "se05x_attest.hpp"
#include "se05x_caps.hpp"
#include "se05x_crypto.hpp"
#include "se05x_detail.hpp"
#include "se05x_device.hpp"
#include "se05x_device_types.hpp"
#include "se05x_ids.hpp"
#include "se05x_policy.hpp"
#include "se05x_ports.hpp"
#include "se05x_secret.hpp"
#include "se05x_status.hpp"
#include "se05x_types.hpp"

namespace se05x::hrot {

/**
 * @defgroup se05x_hrot Root-of-trust facade
 * @brief Slots, keys, verified values, the APDU budget and the facade device.
 * @{
 */

/** @brief Number of slots of each kind. */
inline constexpr uint8_t kSlotCount = 16U;

/** @brief First object id of the facade's objects: `kObjectBase | kind << 8 | index`. */
inline constexpr uint32_t kObjectBase = 0x5E050000U;

/** @brief Largest data object or certificate the facade stores, in bytes. */
inline constexpr std::size_t kMaxStoredBytes = 2048U;

/** @brief Bytes written or read per APDU when the facade stores or loads an object. */
inline constexpr std::size_t kChunkBytes = 256U;

/**
 * @brief The APDUs each facade call may send at most: what `admit()` checks against the budget
 * before the first APDU (S-17). `docs/hrot-cookbook.md` shows this table; the CTest
 * `se05x_docs_costs` checks that the two agree.
 */
namespace cost {
inline constexpr uint32_t kIdentify = 1U;  ///< ReadObject of the unique id.
inline constexpr uint32_t kProvision = 2U; ///< CheckObjectExists, WriteECKey.
inline constexpr uint32_t kFind = 3U;      ///< CheckObjectExists, ReadObjectAttributes, ReadType.
inline constexpr uint32_t kGetPublicKey = 1U;    ///< ReadObject.
inline constexpr uint32_t kImportPublicKey = 2U; ///< CheckObjectExists, WriteECKey.
inline constexpr uint32_t kSign = 1U;            ///< ECDSASign (`Sign` and `TlsSign`).
inline constexpr uint32_t kVerifySignature = 1U; ///< ECDSAVerify.
inline constexpr uint32_t kAgree = 1U;           ///< ECDHGenerateSharedSecret.
inline constexpr uint32_t kAttest = 2U;    ///< The unique id once per open, the attested read.
inline constexpr uint32_t kStoreBase = 3U; ///< CheckObjectExists, the marker, a delete on failure;
                                           ///< plus one per `kChunkBytes` of data.
inline constexpr uint32_t kLoadBase = 2U;  ///< ReadSize, the marker; plus one per `kChunkBytes`
                                           ///< of the buffer, at most `kMaxStoredBytes`.
inline constexpr uint32_t kErase = 1U;     ///< DeleteSecureObject.
inline constexpr uint32_t kCreateCounter = 5U;    ///< CheckObjectExists and WriteCounter; on an
                                                  ///< existing counter ReadObjectAttributes,
                                                  ///< ReadType, ReadObject and WriteCounter.
inline constexpr uint32_t kCounterValue = 1U;     ///< ReadObject (also `CheckFloor`).
inline constexpr uint32_t kCounterIncrement = 2U; ///< WriteCounter, ReadObject.
inline constexpr uint32_t kRaiseCounterTo = 1U;   ///< WriteCounter.
inline constexpr uint32_t kRandomPer512 = 1U;     ///< GetRandom, per 512 bytes.
} // namespace cost

/** @brief Largest value an attested read returns through the facade (`AttestedValue::data`). */
inline constexpr std::size_t kMaxAttestedBytes = 256U;

/** @brief Width of a facade counter in bytes (values 0 to 2^32 - 1). */
inline constexpr uint8_t kCounterBytes = 4U;

/** @brief Length of a SHA-256 digest: the input of `Sign()`, `TlsSign()` and `VerifySignature()`.
 */
inline constexpr std::size_t kDigestLength = 32U;

/** @brief Longest DER-encoded P-256 ECDSA signature. */
inline constexpr std::size_t kMaxSignatureLength = 72U;

/** @brief Length of an uncompressed P-256 point (`04 || x || y`). */
inline constexpr std::size_t kPointLength = 65U;

/** @brief What a slot holds. Each kind has its own object id range. */
enum class SlotKind : uint8_t {
  Key = 1,         ///< A key (`Key<U>`).
  Data = 2,        ///< A binary object of application data.
  Counter = 3,     ///< A monotonic counter.
  Certificate = 4, ///< A certificate (the bytes only; see `se05x::pki`).
};

/**
 * @brief A facade slot of kind `K`: an index below `kSlotCount`. Build one with `At<N>()` (checked
 * at compile time) or `Make(index)` (checked at run time).
 * @tparam K The kind.
 */
template <SlotKind K>
class SlotOf {
public:
  /** @brief Slot 0: the value a failed `Result<SlotOf>` carries; build a real one with `Make`. */
  constexpr SlotOf() noexcept : index_(0U) {}

  /**
   * @brief The slot `N`, checked at compile time.
   * @tparam N The index; a value at or above `kSlotCount` does not compile.
   * @return The slot.
   */
  template <uint8_t N>
    requires(N < kSlotCount)
  [[nodiscard]] static consteval SlotOf At() noexcept {
    return SlotOf{N};
  }

  /**
   * @brief The slot `index`, checked at run time.
   * @param index The index.
   * @return The slot, or `InvalidArgument` when `index >= kSlotCount`.
   */
  [[nodiscard]] static constexpr Result<SlotOf> Make(uint8_t index) noexcept {
    if (index >= kSlotCount) {
      return Result<SlotOf>::Failure(Error::InvalidArgument);
    }
    return Result<SlotOf>::Success(SlotOf{index});
  }

  /** @return The index, below `kSlotCount`. */
  [[nodiscard]] constexpr uint8_t Index() const noexcept {
    return index_;
  }
  /** @return The chip object of this slot. */
  [[nodiscard]] constexpr ObjectId Object() const noexcept {
    return ObjectId{kObjectBase | (static_cast<uint32_t>(K) << 8U) | static_cast<uint32_t>(index_)};
  }
  /**
   * @brief Whether two slots are the same.
   * @param lhs One slot.
   * @param rhs The other slot.
   * @return true when the indices are equal.
   */
  [[nodiscard]] friend constexpr bool operator==(const SlotOf& lhs, const SlotOf& rhs) noexcept {
    return lhs.index_ == rhs.index_;
  }

private:
  constexpr explicit SlotOf(uint8_t index) noexcept : index_(index) {}
  uint8_t index_;
};

/// A key slot.
using Slot = SlotOf<SlotKind::Key>;
/// A data slot.
using DataSlot = SlotOf<SlotKind::Data>;
/// A counter slot.
using CounterSlot = SlotOf<SlotKind::Counter>;
/// A certificate slot.
using CertSlot = SlotOf<SlotKind::Certificate>;

/**
 * @brief Make a key slot.
 * @param index The slot number.
 * @return The slot, or `InvalidArgument` when `index >= kSlotCount`.
 */
constexpr Result<Slot> MakeSlot(uint8_t index) noexcept {
  return Slot::Make(index);
}

/** @brief What a facade key may be used for. Each use has its own key type. */
enum class KeyUse : uint8_t {
  Sign = 0,      ///< Sign SHA-256 digests (ECDSA): `SignKey`.
  Attest = 1,    ///< Sign attested reads only: `AttestKey`.
  Agree = 2,     ///< Key agreement (ECDH): `AgreeKey`.
  TlsClient = 3, ///< Sign TLS handshake digests: `TlsKey`.
  Verify = 4,    ///< A public key that verifies signatures (a trust anchor): `VerifyKey`.
};

/**
 * @brief A key of use `U`. Only the facade creates a valid one (`Provision`, `Find`,
 * `ImportPublicKey`); it names a chip object and never holds key material.
 * @tparam U The use.
 */
template <KeyUse U>
class Key {
public:
  /** @brief The invalid key a failed `Result<Key>` carries. */
  constexpr Key() noexcept = default;
  /** @return true for a key the facade created. */
  [[nodiscard]] constexpr bool IsValid() const noexcept {
    return valid_;
  }
  /** @return The slot. */
  [[nodiscard]] constexpr Slot GetSlot() const noexcept {
    return slot_;
  }
  /** @return The chip object. */
  [[nodiscard]] constexpr ObjectId Id() const noexcept {
    return slot_.Object();
  }
  /** @return The use, `U`. */
  [[nodiscard]] static constexpr KeyUse Use() noexcept {
    return U;
  }

private:
  template <PortSet P>
  friend class Device;
  constexpr explicit Key(Slot slot) noexcept : slot_(slot), valid_(true) {}
  Slot slot_;
  bool valid_{false};
};

/// A key that signs digests.
using SignKey = Key<KeyUse::Sign>;
/// A key that signs attested reads.
using AttestKey = Key<KeyUse::Attest>;
/// A key for ECDH.
using AgreeKey = Key<KeyUse::Agree>;
/// A key that signs TLS handshakes.
using TlsKey = Key<KeyUse::TlsClient>;
/// A public key that verifies signatures (a trust anchor kept in the chip).
using VerifyKey = Key<KeyUse::Verify>;

/** @brief An uncompressed P-256 public key, `04 || x || y`. */
struct EcPublicKey {
  std::array<uint8_t, kPointLength> point{}; ///< The point.
  /** @return The bytes. */
  [[nodiscard]] constexpr ByteSpan View() const& noexcept {
    return ByteSpan{point};
  }
  /** @brief Not on a temporary: the view would dangle. */
  void View() const&& = delete;
};

/** @brief A DER-encoded ECDSA signature. */
using Signature = FixedBytes<kMaxSignatureLength>;

/** @brief A SHA-256 digest. */
using Digest = std::span<const uint8_t, kDigestLength>;

/** @brief The identity of the chip. */
struct Identity {
  std::array<uint8_t, kUniqueIdLength> unique_id{}; ///< The 18-byte unique identifier.
  Family family{Family::Unknown};                   ///< The derived family.
  AppletVersion applet{};                           ///< The applet version.
  uint16_t oef_id{0};                               ///< The OEF identifier.
};

/** @brief The fields of an attested read that were checked. */
struct AttestedValue {
  FixedBytes<kMaxAttestedBytes> data{};             ///< The object data (a public key: the point).
  Timestamp timestamp{};                            ///< The chip timestamp.
  std::array<uint8_t, kUniqueIdLength> unique_id{}; ///< The signing chip.
  /// The object size the chip signed (format 2); for a data or certificate slot, without the
  /// one-byte completion marker `Store` adds (the signed size is one more).
  uint32_t object_size{0};
};

/**
 * @brief A value that was checked: only the facade creates it.
 * @tparam T The checked value type.
 */
template <typename T>
class Verified {
public:
  /** @brief The invalid value a failed `Result<Verified<T>>` carries; `IsValid()` is false. */
  constexpr Verified() noexcept = default;
  /** @return true only for a value the facade created after every check passed. */
  [[nodiscard]] constexpr bool IsValid() const noexcept {
    return valid_;
  }
  /** @return The checked value; meaningful only when `IsValid()`. */
  [[nodiscard]] constexpr const T& Get() const& noexcept {
    return value_;
  }
  /** @brief Not on a temporary: the reference would dangle. */
  void Get() const&& = delete;

private:
  template <PortSet P>
  friend class Device;
  constexpr explicit Verified(const T& value) noexcept : value_(value), valid_(true) {}
  T value_{};
  bool valid_{false};
};

/**
 * @brief An attestation key the caller trusts: the chip object that signs and its public key from
 * a trusted source. Build one with `TrustAttestationKey()`.
 *
 * Where the public key comes from decides what an attestation proves. For the vendor key
 * (`ReservedId::RootOfTrustKey`), take it from the vendor certificate after the certificate chain
 * was verified (the `se05x::pki` layer); for a facade `AttestKey`, from the factory record made
 * when it was provisioned. Reading it from the same chip proves nothing.
 */
class AttestationKey {
public:
  /** @brief The invalid key a failed `Result<AttestationKey>` carries. */
  constexpr AttestationKey() noexcept = default;
  /** @return true for a key built by `TrustAttestationKey()`. */
  [[nodiscard]] constexpr bool IsValid() const noexcept {
    return valid_;
  }
  /** @return The chip object that signs. */
  [[nodiscard]] constexpr ObjectId Id() const noexcept {
    return id_;
  }
  /** @return The trusted public key. */
  [[nodiscard]] constexpr const EcPublicKey& Public() const& noexcept {
    return public_;
  }
  /** @brief Not on a temporary: the reference would dangle. */
  void Public() const&& = delete;

private:
  friend constexpr Result<AttestationKey> TrustAttestationKey(ObjectId id,
                                                              const EcPublicKey& trusted) noexcept;
  constexpr AttestationKey(ObjectId id, const EcPublicKey& trusted) noexcept
      : id_(id), public_(trusted), valid_(true) {}
  ObjectId id_{};
  EcPublicKey public_{};
  bool valid_{false};
};

/**
 * @brief Name the attestation key and the public key the caller trusts for it. No I/O.
 * @param id The chip object that signs (`FromReserved(ReservedId::RootOfTrustKey)`, or the id of a
 * facade `AttestKey`).
 * @param trusted Its public key, from a verified certificate or a factory record.
 * @return The key, or `InvalidArgument` (id 0, or not an uncompressed point).
 */
constexpr Result<AttestationKey> TrustAttestationKey(ObjectId id,
                                                     const EcPublicKey& trusted) noexcept {
  if ((id.value == 0U) || (trusted.point[0] != 0x04U)) {
    return Result<AttestationKey>::Failure(Error::InvalidArgument);
  }
  return Result<AttestationKey>::Success(AttestationKey{id, trusted});
}

/** @brief Who may read stored data (`Store`). */
enum class Protection : uint8_t {
  Secret = 0, ///< Read, write and delete only under secure messaging, over encrypted traffic.
  Public = 1, ///< Anyone on the bus may read, write and delete (integrity from elsewhere).
};

/**
 * @brief The APDU budget (S-17): the chip may refuse every command with SW 0x66A6 after more than
 * one million APDUs within 34 days (AN14028 2.3.1; SE052F, possible on SE051) until it is reset.
 * The facade counts every APDU the device sends and refuses a call that would pass the ceiling.
 * The recovery after a 0x66A6 answer may add up to four APDUs past the admitted cost (see the
 * file comment); they are counted too.
 */
struct ApduBudget {
  uint32_t issued_by_device{0}; ///< APDUs the device has sent, across reopens (`ApduCount()`).
  uint32_t limit{kThroughputLimitApdus};       ///< The documented ceiling.
  uint32_t window_days{kThroughputWindowDays}; ///< The window of the ceiling.
  bool applies{false};                         ///< The chip's capabilities say the limit applies.
  bool persistent_counter_known{false};        ///< `SetWindowCount()` gave a count over the window.
  uint32_t issued_in_window{0};                ///< That count plus the APDUs sent since.

  /** @return The APDUs counted against the ceiling: the window count when known, else this boot's.
   */
  [[nodiscard]] constexpr uint32_t Used() const noexcept {
    return persistent_counter_known ? issued_in_window : issued_by_device;
  }
  /**
   * @brief Whether `cost` more APDUs stay within the ceiling.
   * @param cost The APDUs a call will send.
   * @return true when the limit does not apply, or when `Used() + cost` is at most `limit`.
   */
  [[nodiscard]] constexpr bool Allows(uint32_t cost) const noexcept {
    if (!applies) {
      return true;
    }
    const uint32_t used = Used();
    return (used <= limit) && (cost <= (limit - used));
  }
};

/** @brief One line of the provisioning plan. */
struct SlotPlan {
  Slot slot;                ///< The slot.
  KeyUse use{KeyUse::Sign}; ///< The use.
};

namespace detail {
/// What a facade call needs from the secure-messaging layers.
enum class Need : uint8_t {
  None = 0,         ///< Nothing: public data, identity, random numbers, attestation.
  Authentic = 1,    ///< Authenticated answers (R-MAC): keys, counters, verification results.
  Confidential = 2, ///< And encrypted commands and answers: ECDH secrets, secret data.
};
} // namespace detail

/**
 * @brief The facade over a `se05x::Device`.
 * @tparam P A `Ports<...>` set.
 */
template <PortSet P>
class Device {
public:
  /**
   * @brief Bind the facade. No I/O.
   * @param device The device; it must outlive the facade. Open it before the first call.
   */
  explicit Device(se05x::Device<P>& device) noexcept : device_(&device) {}

  /** @name Budget and identity
   * @{ */

  /** @return The APDU budget so far. No I/O. */
  [[nodiscard]] ApduBudget Budget() const noexcept;

  /**
   * @brief Give the count of APDUs sent to this chip over the last `kThroughputWindowDays` days,
   * as the application persisted it; the facade adds every APDU sent from now on. No I/O.
   * @param issued_in_window The persisted count.
   */
  void SetWindowCount(uint32_t issued_in_window) noexcept;

  /**
   * @brief Read the chip identity: the unique id (`ReservedId::UniqueId`) and the family, applet
   * and OEF id the device derived at `Open()`. One APDU; no secure messaging needed (the answer is
   * not authenticated without it: prove the id with `Attest()`).
   * @return The identity, or `NotInitialized`, `ThroughputLimited`, a device error.
   */
  Result<Identity> Identify() noexcept;
  /** @} */

  /** @name Keys
   * @{ */

  /**
   * @brief Check a provisioning plan: no slot twice, every policy builds for this chip. No I/O.
   * @param plans The plan lines.
   * @return `Ok`; `InvalidArgument` (empty, more than `kSlotCount` lines, a slot twice);
   * `NotInitialized`; `Unsupported` (applet 3.x or 6.x, or P-256 not offered).
   */
  Result<void> CheckPlan(std::span<const SlotPlan> plans) const noexcept;

  /**
   * @brief Generate a NIST P-256 key pair inside the chip in `slot`, with the strict policy of use
   * `U`. The private key never leaves the chip; the public part is readable (`GetPublicKey`). The
   * policy grants no write, generate or delete, so the key cannot be replaced or deleted: only a
   * factory reset (`irreversible::DeleteAllObjects`) removes it. Two APDUs.
   * @tparam U The use; not `Verify` (use `ImportPublicKey`).
   * @param slot The slot.
   * @return The key; `ObjectExists` (the slot is in use: nothing is changed, use `Find`);
   * `PolicyDenied` (answers not authenticated: no R-MAC layer); `NotInitialized`;
   * `ThroughputLimited`; a device error.
   */
  template <KeyUse U>
    requires(U != KeyUse::Verify)
  Result<Key<U>> Provision(Slot slot) noexcept;

  /**
   * @brief The key of use `U` in `slot`. Three APDUs: the existence check, the attributes and the
   * type. Only a key the facade itself could have made is adopted: a persistent EC key pair
   * generated in the chip (an EC public key imported from outside for `Verify`) whose policy is,
   * byte for byte, the strict policy the facade builds for `U` in the open session. A `Sign` key
   * and a `TlsClient` key have the same policy (the chip has no separate TLS signing rule), so
   * `Find` cannot tell them apart: keep them in different slots of your plan.
   * @tparam U The use the slot was provisioned with.
   * @param slot The slot.
   * @return The key; `ObjectNotFound`; `PolicyDenied` (answers not authenticated, or the slot holds
   * another object); `Unsupported` (applet 3.x or 6.x); a device error.
   */
  template <KeyUse U>
  Result<Key<U>> Find(Slot slot) noexcept;

  /**
   * @brief Read the public key of a key. One APDU.
   * @tparam U The use.
   * @param key The key.
   * @return The point; `InvalidArgument` (not a valid key); `FrameError` (not an uncompressed
   * P-256 point); `PolicyDenied`; a device error.
   */
  template <KeyUse U>
  Result<EcPublicKey> GetPublicKey(const Key<U>& key) noexcept;

  /**
   * @brief Store a trusted public key (a firmware-signing root, a server key) in `slot`. It can
   * verify, never be changed or deleted. Two APDUs. The public key enters as `Origin::External`.
   * @param slot The slot.
   * @param trusted The public key.
   * @return The key; `InvalidArgument` (not an uncompressed point); `ObjectExists`;
   * `PolicyDenied` (answers not authenticated); a device error.
   */
  Result<VerifyKey> ImportPublicKey(Slot slot, const EcPublicKey& trusted) noexcept;

  /**
   * @brief Sign a SHA-256 digest with a `SignKey`. One APDU.
   * @param key The key.
   * @param digest The digest you computed (the chip does not hash).
   * @return The DER signature; `InvalidArgument`; `PolicyDenied` (answers not authenticated, S-14);
   * a device error.
   */
  Result<Signature> Sign(const Key<KeyUse::Sign>& key, Digest digest) noexcept;

  /**
   * @brief Sign the digest of a TLS handshake with a `TlsKey`. One APDU.
   * @param key The key.
   * @param digest The handshake digest (SHA-256).
   * @return As `Sign()`.
   */
  Result<Signature> TlsSign(const Key<KeyUse::TlsClient>& key, Digest digest) noexcept;

  /**
   * @brief Verify a signature on the chip. Fails closed: `Ok` only for a valid signature. One APDU.
   * @tparam U `Sign`, `TlsClient` or `Verify`.
   * @param key The key.
   * @param digest The SHA-256 digest of the message.
   * @param signature The DER signature.
   * @return `Ok`; `AttestationInvalid` (the signature does not verify); `InvalidArgument`;
   * `PolicyDenied` (answers not authenticated: an unauthenticated "valid" could be forged); a
   * device error.
   */
  template <KeyUse U>
    requires((U == KeyUse::Sign) || (U == KeyUse::TlsClient) || (U == KeyUse::Verify))
  Result<void> VerifySignature(const Key<U>& key, Digest digest, ByteSpan signature) noexcept;

  /**
   * @brief ECDH with an `AgreeKey`: the 32-byte x coordinate of the shared point. The secret
   * crosses the bus encrypted only (C-DEC and R-ENC: `Device::TrafficConfidential()`). One APDU.
   * @param key The key.
   * @param peer The peer's public key: an uncompressed NIST P-256 point, checked on the curve
   * before anything is sent.
   * @param shared Receives the secret; wiped first, and on failure.
   * @return `Ok`; `InvalidArgument` (an invalid key or a point not on P-256); `PolicyDenied`
   * (traffic not encrypted both ways); a device error.
   */
  Result<void> Agree(const Key<KeyUse::Agree>& key, const EcPublicKey& peer,
                     SecretBuffer<32>& shared) noexcept;
  /** @} */

  /** @name Attestation
   * @{ */

  /**
   * @brief Read the object of a slot with an attestation and verify it on the host (format 2,
   * applet 7.x): a fresh nonce from the host's crypto port, the byte-for-byte echoed command, a
   * timestamp later than the last one, the signature with the trusted key over the TLVs as
   * returned, and the unique identifier against the one read in this open of the device. A data
   * or certificate slot must be read whole and end with the completion marker of `Store`; the
   * marker is removed from the value and the size. One APDU, two the first time after an open.
   * @tparam K The slot kind.
   * @param key The attestation key and the public key the caller trusts.
   * @param slot The slot (a key slot attests the public key).
   * @return The verified value; `AttestationInvalid`; `Counterfeit` (the signed unique id differs
   * from the one read in this open); `FrameError` (a stored object without its marker);
   * `BufferTooSmall` (an object above `kMaxAttestedBytes`, marker included: a stored value
   * above `kMaxAttestedBytes - 1` bytes); `InvalidArgument`; `Unsupported`
   * (applet 3.x or 6.x); a device error.
   */
  template <SlotKind K>
  Result<Verified<AttestedValue>> Attest(const AttestationKey& key, SlotOf<K> slot) noexcept;
  /** @} */

  /** @name Stored data and certificates
   * @{ */

  /**
   * @brief Create a data object in `slot` holding `data`. `Secret` data needs encrypted traffic.
   * One APDU per `kChunkBytes`, plus two (the existence check and the completion marker). The
   * object is one byte longer than the data: its last byte is a completion marker, written by its
   * own command after the data, so `Load` refuses a store cut short by a power loss. When a command
   * fails while powered, the object is deleted again (best effort), except after SW 0x66A6
   * (`ThroughputLimited`): then no delete is sent, and the object stays until `Erase`.
   * @param slot The slot.
   * @param data 1 to `kMaxStoredBytes` bytes.
   * @param protection Who may read it.
   * @return `Ok`; `ObjectExists` (use `Erase` first); `InvalidArgument`; `PolicyDenied`; a device
   * error.
   */
  Result<void> Store(SlotOf<SlotKind::Data> slot, ByteSpan data, Protection protection) noexcept;
  /**
   * @brief Read a data object. Two APDUs (the size and the completion marker), plus one per
   * `kChunkBytes` of the object; the budget admits the worst case for `out` (`cost::kLoadBase`
   * plus one per `kChunkBytes` of `out`, at most `kMaxStoredBytes`). An object without its
   * completion marker is `FrameError`; so is an object some other tool wrote without the marker,
   * and one that happens to end in 0xA5 is read back one byte short (docs/ambiguities.md A35).
   * @param slot The slot.
   * @param out The buffer; wiped when the read fails.
   * @param protection How the object was stored: `Secret` needs encrypted traffic, so the data
   * never crosses the bus in clear.
   * @return The length; `ObjectNotFound`; `BufferTooSmall`; `PolicyDenied` (no encrypted traffic
   * for secret data, nothing sent; or refused by the chip); `FrameError` (no completion marker, or
   * an impossible size); a device error.
   */
  Result<std::size_t> Load(SlotOf<SlotKind::Data> slot, MutableByteSpan out,
                           Protection protection) noexcept;
  /**
   * @brief Delete a data object. One APDU.
   * @param slot The slot.
   * @return `Ok`; `ObjectNotFound`; a device error.
   */
  Result<void> Erase(SlotOf<SlotKind::Data> slot) noexcept;

  /**
   * @brief Store a certificate (the bytes as given; nothing is parsed). Anyone may read it; its
   * integrity is its signature, so anyone on the bus may also replace it.
   * @param slot The slot.
   * @param der 1 to `kMaxStoredBytes` bytes.
   * @return As `Store()`.
   */
  Result<void> StoreCertificate(SlotOf<SlotKind::Certificate> slot, ByteSpan der) noexcept;
  /**
   * @brief Read a certificate. @return As `Load()`.
   * @param slot The slot.
   * @param out The buffer.
   */
  Result<std::size_t> LoadCertificate(SlotOf<SlotKind::Certificate> slot,
                                      MutableByteSpan out) noexcept;
  /**
   * @brief Delete a certificate. @return As `Erase()`.
   * @param slot The slot.
   */
  Result<void> EraseCertificate(SlotOf<SlotKind::Certificate> slot) noexcept;
  /** @} */

  /** @name Monotonic counters (authenticated answers needed: a forged value would defeat the
   * floor). A facade counter cannot be deleted (its policy grants no delete): only a factory
   * reset removes it.
   * @{ */

  /**
   * @brief Create a 4-byte counter in `slot` with a start value, in one command (AN12543 4.7.1.6:
   * the value at creation). Two APDUs for a new counter. When the slot already holds a counter the
   * facade made, it is adopted and, when below `initial`, raised to it: a floor is never left lower
   * than asked; that path sends five APDUs (`cost::kCreateCounter`, the amount admitted).
   * @param slot The slot.
   * @param initial The start value.
   * @return `Ok`; `ObjectExists` (the counter is now at least `initial`); `PolicyDenied`; a device
   * error.
   */
  Result<void> CreateCounter(SlotOf<SlotKind::Counter> slot, uint32_t initial) noexcept;
  /**
   * @brief Read a counter. One APDU. @return The value or an error.
   * @param slot The slot.
   */
  Result<uint32_t> CounterValue(SlotOf<SlotKind::Counter> slot) noexcept;
  /**
   * @brief Increment a counter by one and return the new value. Two APDUs.
   * @param slot The slot.
   * @return The value; a device error (the chip refuses past the maximum).
   */
  Result<uint32_t> CounterIncrement(SlotOf<SlotKind::Counter> slot) noexcept;
  /**
   * @brief Raise a counter to `value` in one APDU (instead of a loop of increments, S-17). The
   * chip never lowers a counter.
   * @param slot The slot.
   * @param value The new value, not below the current one.
   * @return `Ok`; `InvalidArgument` (the chip refused a lower value); a device error.
   */
  Result<void> RaiseCounterTo(SlotOf<SlotKind::Counter> slot, uint32_t value) noexcept;
  /**
   * @brief The anti-rollback check: the counter is the floor. Fails closed: `Ok` only when
   * `version` is not below it. One APDU.
   * @param floor The counter that holds the floor.
   * @param version The version of the image (or record) to accept.
   * @return `Ok`; `PolicyDenied` (layer `Hrot`: `version` is below the floor, a rollback); a
   * device error.
   */
  Result<void> CheckFloor(SlotOf<SlotKind::Counter> floor, uint32_t version) noexcept;
  /** @} */

  /**
   * @brief Random bytes from the chip RNG. One APDU per 512 bytes. Without secure messaging the
   * bytes are not authenticated.
   * @param out The buffer, 1 to 1024 bytes.
   * @return `Ok` or an error.
   */
  Result<void> Random(MutableByteSpan out) noexcept;

private:
  [[nodiscard]] Error admit(uint32_t cost, detail::Need need) noexcept;
  [[nodiscard]] uint32_t sessionCredential() const noexcept;
  void syncOpen() noexcept;
  template <typename T>
  [[nodiscard]] static Result<T> refuse(Error error) noexcept;
  template <KeyUse U>
  Result<Policy> keyPolicy() const noexcept;
  Result<Policy> dataPolicy(Protection protection) const noexcept;
  Result<Policy> counterPolicy() const noexcept;
  Result<void> storeBytes(ObjectId id, ByteSpan data, Protection protection) noexcept;
  void dropUnfinished(ObjectId id, const Result<void>& written) noexcept;
  Result<std::size_t> loadBytes(ObjectId id, MutableByteSpan out, detail::Need need) noexcept;
  Result<void> eraseObject(ObjectId id) noexcept;
  Result<Signature> signDigest(ObjectId id, Digest digest) noexcept;
  Result<void> createKey(ObjectId id, const Policy& policy) noexcept;
  Result<void> adoptable(ObjectId id, ObjectClass object_class, Origin origin,
                         const Policy& expected) noexcept;
  Result<void> uniqueId() noexcept;

  se05x::Device<P>* device_;
  uint32_t window_base_{0};
  bool window_known_{false};
  bool id_known_{false};
  uint32_t seen_open_{0};
  std::array<uint8_t, kUniqueIdLength> unique_id_{};
};

/**
 * @brief A transaction scope: takes the bus on construction and releases it on destruction.
 * @tparam P A `Ports<...>` set.
 */
template <PortSet P>
class Transaction {
public:
  /**
   * @brief Begin a transaction on `device`.
   * @param device The device; it must outlive the scope.
   */
  explicit Transaction(se05x::Device<P>& device) noexcept
      : device_(&device), status_(device.BeginTransaction()) {}
  /** @brief One scope per transaction. */
  Transaction(const Transaction&) = delete;
  /** @brief One scope per transaction. */
  Transaction& operator=(const Transaction&) = delete;
  /** @brief Ends the transaction when it began. */
  ~Transaction() noexcept {
    if (status_.ok()) {
      static_cast<void>(device_->EndTransaction());
    }
  }
  /** @return The result of beginning. */
  [[nodiscard]] Error Status() const noexcept {
    return status_.error;
  }

private:
  se05x::Device<P>* device_;
  Result<void> status_;
};

/** @} */

} // namespace se05x::hrot

// codeql::misra_deviation_next_line(MD-CPP-009)
#include "../src/se05x_hrot.ipp" // IWYU pragma: export

#endif // SE05X_HROT_HPP
