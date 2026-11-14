/**
 * @file se05x_ids.hpp
 * @brief Object identifiers, the reserved ids and the secure object classes of the applet.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Frozen contract. An `ObjectId` is a 4-byte identifier, big endian on the wire. A caller makes one
 * with `MakeUserObject()`, which refuses the range the applet reserves (0x7FFF0000 to 0x7FFFFFFF,
 * AN12543 3.2.4.1 p. 10) and 0xE0000000 and up: 0xF0000000 and up is where NXP pre-provisions keys
 * (AN12436), and the whole of 0x80000000 and up is the NXP reserved area of the SE052F (AN13904
 * Table 1, p. 7). AN12543 reserves neither, so the 0xE range is a choice for every part
 * (docs/ambiguities.md A27); 0x80000000 to 0xDFFFFFFF stays open for the SE050 and SE051, and
 * AN13904 advises 0x00000000 to 0x7BFFFFFF for in-field objects. The reserved ids have names
 * in `ReservedId`, and `IsNxpOwned()` marks the ones the driver never writes (AN12413 reserved
 * objects, AN12436 pre-provisioned objects; the middleware's reserved id list for the 0x7FFF02xx
 * values).
 */
#ifndef SE05X_IDS_HPP
#define SE05X_IDS_HPP

#include <cstdint>

#include "se05x_detail.hpp"
#include "se05x_status.hpp"

namespace se05x {

/**
 * @defgroup se05x_ids Object identifiers
 * @brief `ObjectId`, `ReservedId`, `ObjectClass` and friends.
 * @{
 */

/** @brief The identifier of a secure object. Make one with `MakeUserObject()` or `FromReserved()`.
 */
struct ObjectId {
  uint32_t value{0}; ///< The identifier; 0 is not a valid object.

  /**
   * @brief Whether two ids are the same.
   * @param lhs One id.
   * @param rhs The other id.
   * @return true when equal.
   */
  [[nodiscard]] friend constexpr bool operator==(const ObjectId& lhs,
                                                 const ObjectId& rhs) noexcept {
    return lhs.value == rhs.value;
  }
};

/** @brief First id of the range the chip reserves for authentication and system objects. */
inline constexpr uint32_t kReservedSystemBase = 0x7FFF0000U;
/** @brief Last id of the system range. */
inline constexpr uint32_t kReservedSystemLast = 0x7FFFFFFFU;
/** @brief First id of the range NXP provisions (connectivity, cloud and attestation keys). */
inline constexpr uint32_t kReservedNxpBase = 0xF0000000U;
/** @brief Last id of the NXP range. */
inline constexpr uint32_t kReservedNxpLast = 0xFFFFFFFFU;
/** @brief First id of the range kept for crypto contexts and curves (inside the SE052F's NXP
 * reserved area, AN13904 Table 1 p. 7; not reserved by AN12543: docs/ambiguities.md A27). */
inline constexpr uint32_t kReservedCurveBase = 0xE0000000U;
/** @brief Last id of the curve range. */
inline constexpr uint32_t kReservedCurveLast = 0xEFFFFFFFU;

/** @brief The reserved objects with a name. Values from AN12413, AN12436 and the middleware. */
enum class ReservedId : uint32_t {
  Transport = 0x7FFF0200U,         ///< Transport lock authentication object.
  EcKeySession = 0x7FFF0201U,      ///< Key pair for ECKey sessions.
  ExternalImport = 0x7FFF0202U,    ///< Key for `ImportExternalObject`.
  Feature = 0x7FFF0204U,           ///< Authentication object for `SetAppletFeatures`.
  FactoryReset = 0x7FFF0205U,      ///< Authentication object for factory reset.
  UniqueId = 0x7FFF0206U,          ///< The chip's unique identifier.
  PlatformScp = 0x7FFF0207U,       ///< Platform SCP03 requirement object.
  I2cmAccess = 0x7FFF0208U,        ///< Access control for the I2C controller commands.
  Restrict = 0x7FFF020AU,          ///< Object-creation restriction.
  RootOfTrustKey = 0xF0000012U,    ///< Die-individual attestation key (AN12436).
  RootOfTrustCert = 0xF0000013U,   ///< Its certificate.
  ConnectivityKey0 = 0xF0000000U,  ///< Default connectivity key 0.
  ConnectivityCert0 = 0xF0000001U, ///< Its certificate.
  ConnectivityKey1 = 0xF0000002U,  ///< Default connectivity key 1.
  ConnectivityCert1 = 0xF0000003U, ///< Its certificate.
  CloudKey0 = 0xF0000100U,         ///< Cloud connection key 0 (ECC256).
  CloudCert0 = 0xF0000101U,        ///< Its certificate.
  CloudKey1 = 0xF0000102U,         ///< Cloud connection key 1 (ECC256).
  CloudCert1 = 0xF0000103U,        ///< Its certificate.
};

/**
 * @brief Whether an id is in a range the chip reserves.
 * @param id The identifier.
 * @return true for 0 and for every id in the system, curve and NXP ranges.
 */
constexpr bool IsReservedValue(uint32_t id) noexcept {
  return (id == 0U) || ((id >= kReservedSystemBase) && (id <= kReservedSystemLast)) ||
         ((id >= kReservedCurveBase) && (id <= kReservedCurveLast)) ||
         ((id >= kReservedNxpBase) && (id <= kReservedNxpLast));
}

/**
 * @brief Make the id of a user object.
 * @param value The identifier.
 * @return The id, or `InvalidArgument` when it is 0 or in a reserved range (system, curve, NXP).
 */
constexpr Result<ObjectId> MakeUserObject(uint32_t value) noexcept {
  if (IsReservedValue(value)) {
    return Result<ObjectId>::Failure(Error::InvalidArgument);
  }
  return Result<ObjectId>::Success(ObjectId{value});
}

/**
 * @brief The id of a named reserved object, for the commands that take one (authentication,
 * reads of public NXP objects).
 * @param id The reserved object.
 * @return Its `ObjectId`.
 */
constexpr ObjectId FromReserved(ReservedId id) noexcept {
  return ObjectId{static_cast<uint32_t>(id)};
}

/**
 * @brief Whether the driver refuses to write or delete this reserved object: NXP provisioned it.
 * @param id The reserved object.
 * @return true for the connectivity, cloud and root-of-trust objects.
 */
constexpr bool IsNxpOwned(ReservedId id) noexcept {
  return static_cast<uint32_t>(id) >= kReservedNxpBase;
}

/** @brief The class of a secure object (AN12413 object types; the EC curve variants are `EcCurve`).
 */
enum class ObjectClass : uint8_t {
  EcKeyPair = 0,  ///< EC key pair.
  EcPrivKey = 1,  ///< EC private key.
  EcPubKey = 2,   ///< EC public key.
  RsaKeyPair = 3, ///< RSA key pair.
  RsaPrivKey = 4, ///< RSA private key.
  RsaPubKey = 5,  ///< RSA public key.
  AesKey = 6,     ///< AES key (also CMAC).
  DesKey = 7,     ///< DES or 3DES key.
  HmacKey = 8,    ///< HMAC key.
  BinaryFile = 9, ///< Binary file.
  UserId = 10,    ///< UserID authentication object.
  Counter = 11,   ///< Monotonic counter.
  Pcr = 12,       ///< Platform configuration register.
  Curve = 13,     ///< EC curve object.
};

/** @brief How an object came to be (AN12413): shown in attestation. */
enum class Origin : uint8_t {
  External = 0,    ///< Imported from the host.
  Internal = 1,    ///< Generated inside the chip.
  Provisioned = 2, ///< Provisioned by NXP.
};

/** @brief The lifetime of an object. */
enum class Lifetime : uint8_t {
  Persistent = 0,        ///< Kept across reset and power loss.
  TransientReset = 1,    ///< Lost at reset or power-down.
  TransientDeselect = 2, ///< Lost when the applet is deselected.
};

namespace detail {
/// Last enumerator of `ObjectClass`.
template <>
struct EnumLast<ObjectClass> {
  static constexpr ObjectClass kValue = ObjectClass::Curve; ///< The last enumerator.
};
/// Last enumerator of `Origin`.
template <>
struct EnumLast<Origin> {
  static constexpr Origin kValue = Origin::Provisioned; ///< The last enumerator.
};
/// Last enumerator of `Lifetime`.
template <>
struct EnumLast<Lifetime> {
  static constexpr Lifetime kValue = Lifetime::TransientDeselect; ///< The last enumerator.
};
} // namespace detail

static_assert(!MakeUserObject(0U).ok());
static_assert(!MakeUserObject(0x7FFF0201U).ok());
static_assert(!MakeUserObject(0xF0000012U).ok());
static_assert(!MakeUserObject(0xE0000000U).ok());
static_assert(MakeUserObject(0x00000100U).ok());
static_assert(MakeUserObject(0x7FFEFFFFU).ok());
static_assert(IsNxpOwned(ReservedId::RootOfTrustKey) && !IsNxpOwned(ReservedId::EcKeySession));

/** @} */

} // namespace se05x

#endif // SE05X_IDS_HPP
