/**
 * @file se05x_device_types.hpp
 * @brief The argument and reply type of every applet command, keyed by `Command`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Frozen contract. `CommandTypes<C>` names, for each `Command`, the `Args` the caller fills and the
 * `Reply` the call returns. The APDU codec (`Codec<C>`, `se05x_codec.hpp`) turns an `Args` into
 * bytes and the response bytes into a `Reply`; the device (`Device::Execute<C>()`) runs the gate,
 * the secure channel and the link around it; the chip model decodes the same bytes independently.
 * Enumerations here are abstract and contiguous: the codec maps them to the wire values of AN12413
 * (applet 3.x) and the middleware enumerations (applet 7.x), so a wire value never leaks into the
 * public API.
 *
 * Inputs and outputs are views (`ByteSpan`, `MutableByteSpan`): the caller owns every buffer,
 * nothing is allocated, and a reply holds only counts and short fixed fields. A secret-bearing
 * field is named
 * `*_key`, `*_secret` or `*_private`; the logs never see an `Args` (S-02).
 */
#ifndef SE05X_DEVICE_TYPES_HPP
#define SE05X_DEVICE_TYPES_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "se05x_caps.hpp"
#include "se05x_commands.hpp"
#include "se05x_detail.hpp"
#include "se05x_ids.hpp"
#include "se05x_policy_types.hpp"
#include "se05x_types.hpp"

namespace se05x {

/**
 * @defgroup se05x_device_types Command argument and reply types
 * @brief One `Args` and one `Reply` per command, and the enumerations they use.
 * @{
 */

/** @brief The elliptic curves of the applet. */
enum class EcCurve : uint8_t {
  NistP192 = 0,         ///< NIST P-192.
  NistP224 = 1,         ///< NIST P-224.
  NistP256 = 2,         ///< NIST P-256.
  NistP384 = 3,         ///< NIST P-384.
  NistP521 = 4,         ///< NIST P-521.
  Brainpool160 = 5,     ///< Brainpool P160r1.
  Brainpool192 = 6,     ///< Brainpool P192r1.
  Brainpool224 = 7,     ///< Brainpool P224r1.
  Brainpool256 = 8,     ///< Brainpool P256r1.
  Brainpool320 = 9,     ///< Brainpool P320r1.
  Brainpool384 = 10,    ///< Brainpool P384r1.
  Brainpool512 = 11,    ///< Brainpool P512r1.
  Secp160k1 = 12,       ///< secp160k1.
  Secp192k1 = 13,       ///< secp192k1.
  Secp224k1 = 14,       ///< secp224k1.
  Secp256k1 = 15,       ///< secp256k1.
  BnP256 = 16,          ///< TPM BN-P256 (applet 3.x).
  Ed25519 = 17,         ///< Ed25519 (not on SE052F).
  Montgomery25519 = 18, ///< Curve25519 (not on SE052F).
  Montgomery448 = 19,   ///< Curve448 (SE050E, SE051).
};

/** @brief Symmetric key types of `WriteSymmKey`. */
enum class SymmKeyType : uint8_t {
  Aes = 0,  ///< AES (128, 192, 256 bit); also CMAC keys.
  Des = 1,  ///< DES and 3DES.
  Hmac = 2, ///< HMAC key.
};

/** @brief Digest algorithms of the applet. */
enum class DigestMode : uint8_t {
  Sha1 = 0,   ///< SHA-1.
  Sha224 = 1, ///< SHA-224.
  Sha256 = 2, ///< SHA-256.
  Sha384 = 3, ///< SHA-384.
  Sha512 = 4, ///< SHA-512.
};

/** @brief Signature algorithms of the EC commands. */
enum class EcSignAlgo : uint8_t {
  Plain = 0,       ///< ECDSA over the input as it is (a precomputed digest).
  Sha1 = 1,        ///< ECDSA with SHA-1 (refused on the FIPS configuration).
  Sha224 = 2,      ///< ECDSA with SHA-224.
  Sha256 = 3,      ///< ECDSA with SHA-256.
  Sha384 = 4,      ///< ECDSA with SHA-384.
  Sha512 = 5,      ///< ECDSA with SHA-512.
  Ed25519Pure = 6, ///< EdDSA, Ed25519 pure.
};

/** @brief Signature algorithms of the RSA commands. */
enum class RsaSignAlgo : uint8_t {
  Sha1Pss = 0,     ///< SHA-1, PKCS#1 PSS.
  Sha224Pss = 1,   ///< SHA-224, PSS.
  Sha256Pss = 2,   ///< SHA-256, PSS.
  Sha384Pss = 3,   ///< SHA-384, PSS.
  Sha512Pss = 4,   ///< SHA-512, PSS.
  Sha1Pkcs1 = 5,   ///< SHA-1, PKCS#1 v1.5.
  Sha224Pkcs1 = 6, ///< SHA-224, PKCS#1 v1.5.
  Sha256Pkcs1 = 7, ///< SHA-256, PKCS#1 v1.5.
  Sha384Pkcs1 = 8, ///< SHA-384, PKCS#1 v1.5.
  Sha512Pkcs1 = 9, ///< SHA-512, PKCS#1 v1.5.
};

/** @brief Encryption algorithms of the RSA commands. */
enum class RsaCryptAlgo : uint8_t {
  NoPad = 0,     ///< No padding.
  Pkcs1 = 1,     ///< PKCS#1 v1.5.
  Pkcs1Oaep = 2, ///< OAEP with SHA-1.
};

/** @brief Cipher modes of the symmetric commands. */
enum class CipherMode : uint8_t {
  DesCbcNoPad = 0,      ///< DES CBC, no padding.
  DesCbcIso9797M1 = 1,  ///< DES CBC, ISO 9797 method 1.
  DesCbcIso9797M2 = 2,  ///< DES CBC, ISO 9797 method 2.
  DesCbcPkcs5 = 3,      ///< DES CBC, PKCS#5.
  DesEcbNoPad = 4,      ///< DES ECB, no padding.
  DesEcbIso9797M1 = 5,  ///< DES ECB, ISO 9797 method 1.
  DesEcbIso9797M2 = 6,  ///< DES ECB, ISO 9797 method 2.
  DesEcbPkcs5 = 7,      ///< DES ECB, PKCS#5.
  AesEcbNoPad = 8,      ///< AES ECB, no padding.
  AesCbcNoPad = 9,      ///< AES CBC, no padding.
  AesCbcIso9797M1 = 10, ///< AES CBC, ISO 9797 method 1.
  AesCbcIso9797M2 = 11, ///< AES CBC, ISO 9797 method 2.
  AesCbcPkcs5 = 12,     ///< AES CBC, PKCS#5.
  AesCtr = 13,          ///< AES CTR.
};

/** @brief AEAD modes (applet 7.x). */
enum class AeadMode : uint8_t {
  AesGcm = 0, ///< AES-GCM (SE052F: encryption with the internal IV only).
  AesCcm = 1, ///< AES-CCM.
};

/** @brief MAC algorithms. */
enum class MacAlgo : uint8_t {
  HmacSha1 = 0,   ///< HMAC-SHA-1.
  HmacSha256 = 1, ///< HMAC-SHA-256.
  HmacSha384 = 2, ///< HMAC-SHA-384.
  HmacSha512 = 3, ///< HMAC-SHA-512.
  Cmac128 = 4,    ///< AES-CMAC.
  DesCmac8 = 5,   ///< DES CMAC with an 8-byte tag.
};

/** @brief HKDF modes. */
enum class HkdfMode : uint8_t {
  ExtractExpand = 0, ///< Extract and expand.
  ExpandOnly = 1,    ///< Expand only.
};

/** @brief Attestation signature algorithms. */
enum class AttestationAlgo : uint8_t {
  EcPlain = 0,         ///< ECDSA over the input.
  EcSha1 = 1,          ///< ECDSA with SHA-1.
  EcSha224 = 2,        ///< ECDSA with SHA-224.
  EcSha256 = 3,        ///< ECDSA with SHA-256.
  EcSha384 = 4,        ///< ECDSA with SHA-384.
  EcSha512 = 5,        ///< ECDSA with SHA-512.
  Ed25519 = 6,         ///< Ed25519 pure.
  RsaSha256Pss = 7,    ///< RSA PSS with SHA-256.
  RsaSha384Pss = 8,    ///< RSA PSS with SHA-384.
  RsaSha512Pss = 9,    ///< RSA PSS with SHA-512.
  RsaSha256Pkcs1 = 10, ///< RSA PKCS#1 v1.5 with SHA-256.
  RsaSha384Pkcs1 = 11, ///< RSA PKCS#1 v1.5 with SHA-384.
  RsaSha512Pkcs1 = 12, ///< RSA PKCS#1 v1.5 with SHA-512.
};

/** @brief The format of an attested read (design S-09). */
enum class AttestationFormat : uint8_t {
  V1 = 0, ///< Applet 3.x: the chip echoes the freshness; the signature covers TAG_1 to TAG_5.
  V2 = 1, ///< Applet 7.x: no freshness echo; the chip returns the command; the host compares it
          ///< first.
};

/** @brief The ECDH variant (applet 7.x). */
enum class EcdhAlgo : uint8_t {
  SvdpDh = 0,      ///< `EC_SVDP_DH`: the hashed form.
  SvdpDhPlain = 1, ///< `EC_SVDP_DH_PLAIN`: the plain x coordinate.
};

/** @brief Memory kinds of `GetFreeMemory`. */
enum class MemoryType : uint8_t {
  Persistent = 0,        ///< Persistent memory.
  TransientReset = 1,    ///< Transient memory cleared on reset.
  TransientDeselect = 2, ///< Transient memory cleared on deselect.
};

/** @brief The transport lock state a caller can set (irreversible: S-10). */
enum class LockStateValue : uint8_t {
  Locked = 0, ///< Lock the applet: only the transport credential is accepted.
};

/** @brief The platform SCP requirement (irreversible: S-10). */
enum class ScpRequirement : uint8_t {
  Required = 0,    ///< Every command must run inside platform SCP03.
  NotRequired = 1, ///< Plain commands are accepted.
};

/** @brief The restriction mode of `DisableObjCreation` (irreversible: S-10). */
enum class RestrictMode : uint8_t {
  RestrictNew = 0, ///< No new objects.
  RestrictAll = 1, ///< No new objects and no changes.
};

/** @brief The type of a crypto object (a streaming context). */
enum class CryptoObjectType : uint8_t {
  Digest = 0, ///< A digest context.
  Cipher = 1, ///< A cipher context.
  Mac = 2,    ///< A MAC context.
  Aead = 3,   ///< An AEAD context.
};

/**
 * @brief The TLS role of the host in `TlsPerformPrf`: it names whose random the chip generated with
 * `TlsGenerateRandom` and so which random the host passes (AN12543 4.17.3).
 */
enum class TlsRole : uint8_t {
  Client = 0, ///< The host is the TLS client: the chip made the client random, the host passes the
              ///< server random (P2_TLS_PRF_SRV_HELLO, P2_TLS_PRF_SRV_RND).
  Server = 1, ///< The host is the TLS server: the chip made the server random, the host passes the
              ///< client random (P2_TLS_PRF_CLI_HELLO, P2_TLS_PRF_CLI_RND).
};

namespace detail {
/// Last enumerator of `EcCurve`.
template <>
struct EnumLast<TlsRole> {
  static constexpr TlsRole kValue = TlsRole::Server; ///< The last enumerator.
};
template <>
struct EnumLast<EcCurve> {
  static constexpr EcCurve kValue = EcCurve::Montgomery448; ///< The last enumerator.
};
/// Last enumerator of `SymmKeyType`.
template <>
struct EnumLast<SymmKeyType> {
  static constexpr SymmKeyType kValue = SymmKeyType::Hmac; ///< The last enumerator.
};
/// Last enumerator of `DigestMode`.
template <>
struct EnumLast<DigestMode> {
  static constexpr DigestMode kValue = DigestMode::Sha512; ///< The last enumerator.
};
/// Last enumerator of `EcSignAlgo`.
template <>
struct EnumLast<EcSignAlgo> {
  static constexpr EcSignAlgo kValue = EcSignAlgo::Ed25519Pure; ///< The last enumerator.
};
/// Last enumerator of `RsaSignAlgo`.
template <>
struct EnumLast<RsaSignAlgo> {
  static constexpr RsaSignAlgo kValue = RsaSignAlgo::Sha512Pkcs1; ///< The last enumerator.
};
/// Last enumerator of `RsaCryptAlgo`.
template <>
struct EnumLast<RsaCryptAlgo> {
  static constexpr RsaCryptAlgo kValue = RsaCryptAlgo::Pkcs1Oaep; ///< The last enumerator.
};
/// Last enumerator of `CipherMode`.
template <>
struct EnumLast<CipherMode> {
  static constexpr CipherMode kValue = CipherMode::AesCtr; ///< The last enumerator.
};
/// Last enumerator of `AeadMode`.
template <>
struct EnumLast<AeadMode> {
  static constexpr AeadMode kValue = AeadMode::AesCcm; ///< The last enumerator.
};
/// Last enumerator of `MacAlgo`.
template <>
struct EnumLast<MacAlgo> {
  static constexpr MacAlgo kValue = MacAlgo::DesCmac8; ///< The last enumerator.
};
/// Last enumerator of `HkdfMode`.
template <>
struct EnumLast<HkdfMode> {
  static constexpr HkdfMode kValue = HkdfMode::ExpandOnly; ///< The last enumerator.
};
/// Last enumerator of `AttestationAlgo`.
template <>
struct EnumLast<AttestationAlgo> {
  static constexpr AttestationAlgo kValue =
      AttestationAlgo::RsaSha512Pkcs1; ///< The last enumerator.
};
/// Last enumerator of `AttestationFormat`.
template <>
struct EnumLast<AttestationFormat> {
  static constexpr AttestationFormat kValue = AttestationFormat::V2; ///< The last enumerator.
};
/// Last enumerator of `EcdhAlgo`.
template <>
struct EnumLast<EcdhAlgo> {
  static constexpr EcdhAlgo kValue = EcdhAlgo::SvdpDhPlain; ///< The last enumerator.
};
/// Last enumerator of `MemoryType`.
template <>
struct EnumLast<MemoryType> {
  static constexpr MemoryType kValue = MemoryType::TransientDeselect; ///< The last enumerator.
};
/// Last enumerator of `LockStateValue`.
template <>
struct EnumLast<LockStateValue> {
  static constexpr LockStateValue kValue = LockStateValue::Locked; ///< The last enumerator.
};
/// Last enumerator of `ScpRequirement`.
template <>
struct EnumLast<ScpRequirement> {
  static constexpr ScpRequirement kValue = ScpRequirement::NotRequired; ///< The last enumerator.
};
/// Last enumerator of `RestrictMode`.
template <>
struct EnumLast<RestrictMode> {
  static constexpr RestrictMode kValue = RestrictMode::RestrictAll; ///< The last enumerator.
};
/// Last enumerator of `CryptoObjectType`.
template <>
struct EnumLast<CryptoObjectType> {
  static constexpr CryptoObjectType kValue = CryptoObjectType::Aead; ///< The last enumerator.
};
} // namespace detail

/// The `rsa_component` value that selects no RSA component (the object is not an RSA key, or the
/// whole key is meant). The component values themselves are 0 (modulus) to 7 (AN12543 Table 41).
inline constexpr uint8_t kNoRsaComponent = 0xFFU;

/// Longest attribute block of an object: 19 fixed bytes (AN12543 Tables 3 and 4: identifier 4,
/// type 1, authentication indicator 1, counter or tag length 2, owner 4, maximum attempts or output
/// length 2, origin 1, version 4) and the policy set.
inline constexpr std::size_t kMaxAttributeBytes = 19U + kMaxPolicyBytes;

/** @brief The identifier of a crypto object (a streaming context), 16 bits. */
struct CryptoObjectId {
  uint16_t value{0}; ///< The identifier.
};

/** @brief The RSA key components of `WriteRsaKey`; unused components stay empty. */
struct RsaKeyParts {
  ByteSpan modulus;          ///< n.
  ByteSpan public_exponent;  ///< e.
  ByteSpan private_exponent; ///< d (plain form only).
  ByteSpan prime_p;          ///< p (CRT form).
  ByteSpan prime_q;          ///< q (CRT form).
  ByteSpan exponent_dp;      ///< d mod (p - 1) (CRT form).
  ByteSpan exponent_dq;      ///< d mod (q - 1) (CRT form).
  ByteSpan coefficient_iq;   ///< q^-1 mod p (CRT form).
};

/// @name Replies
/// @{
/** @brief No value: the reply of a command that returns only a status. */
struct Empty {};
/** @brief The select and version response: applet version, AppletConfig and SecureBox. */
struct AppletInfo {
  AppletVersion version{};   ///< Applet version.
  uint16_t applet_config{0}; ///< AppletConfig bits.
  uint16_t secure_box{0};    ///< SecureBox bits.
};
/** @brief The extended feature bits (applet 7.x). */
using ExtFeatures = FixedBytes<kExtFeatureLength>;
/** @brief The card identification data: the OEF id and the raw bytes (layout: AN13030 pp.
 * 227-228; the sample there is 66 bytes, and applets after 7.2.0 add a JCOP core id TLV). */
struct CardId {
  uint16_t oef_id{0};    ///< The OEF identifier (bytes 2 and 3 of the configuration id).
  FixedBytes<128> raw{}; ///< The value of tag DF28 as read.
};
/** @brief The card production life cycle data (GP tag 9F7F). */
using Cplc = FixedBytes<42>;
/** @brief An applet session identifier, 8 bytes. */
using SessionId = FixedBytes<8>;
/** @brief A short fixed-size answer whose layout the caller or a higher layer interprets. */
using SmallBlob = FixedBytes<256>;
/** @brief A 32-bit unsigned number. */
struct U32Reply {
  uint32_t value{0}; ///< The number.
};
/** @brief The chip timestamp. */
using Timestamp = std::array<uint8_t, kTimestampLength>;
/** @brief A boolean answer. */
struct BoolReply {
  bool value{false}; ///< The answer.
};
/** @brief The number of bytes written to the caller's output buffer. */
struct LengthReply {
  std::size_t length{0}; ///< Bytes written.
};
/** @brief The result of a self test. */
struct SelfTestReply {
  bool passed{false}; ///< Whether the test passed.
};
/** @brief The object type answer. */
struct TypeReply {
  ObjectClass object_class{ObjectClass::EcKeyPair}; ///< The class.
  Lifetime lifetime{Lifetime::Persistent};          ///< The lifetime.
};
/** @brief The curve of an EC key. */
struct CurveReply {
  EcCurve curve{EcCurve::NistP256}; ///< The curve.
};
/** @brief The ids returned by `ReadIdList`. */
struct IdListReply {
  std::size_t count{0}; ///< Ids written to the caller's buffer.
  bool more{false};     ///< More ids follow: call again with a larger offset.
};
/** @brief The attributes of an object (`ReadObjectAttributes`). */
struct ObjectAttributes {
  ObjectClass object_class{ObjectClass::EcKeyPair}; ///< The class.
  Origin origin{Origin::External};                  ///< How the object was created.
  Lifetime lifetime{Lifetime::Persistent};          ///< The lifetime.
  ObjectId authentication{};            ///< The authentication object bound to it, or 0.
  uint16_t max_attempts{0};             ///< Attempt limit of an authentication object.
  uint16_t attempts_left{0};            ///< Attempts left.
  uint32_t version{0};                  ///< Object version (applet 7.x), 0 when none.
  FixedBytes<kMaxPolicyBytes> policy{}; ///< The policy set in the chip's format.
};
/** @brief The signed answer of an attested read or an attested I2C controller command set. */
struct AttestedRead {
  std::size_t data_length{0};                       ///< Bytes written to the data buffer.
  std::size_t signature_length{0};                  ///< Bytes written to the signature buffer.
  Timestamp timestamp{};                            ///< The chip timestamp.
  std::array<uint8_t, kUniqueIdLength> unique_id{}; ///< The chip's unique identifier.
  std::array<uint8_t, kFreshnessLength>
      freshness{}; ///< Format 1: the freshness the chip echoed; zero in format 2.
  FixedBytes<kMaxAttributeBytes> attributes{};     ///< The attribute block that was signed.
  AttestationFormat format{AttestationFormat::V1}; ///< Which layout the chip answered with.
  FixedBytes<100> echoed_command{}; ///< Format 2: the command the chip received, up to 100 bytes.
  uint32_t object_size{0};          ///< Format 2: the object size the chip signed.
};
/** @brief The receipt of an external object import (CMAC under the import session's R-MAC key). */
struct ExternalImportReceipt {
  FixedBytes<16> receipt{}; ///< The receipt the host verifies (S-08).
};
/// @}

/// @name Arguments
/// @{
/** @brief The argument of a command that takes only an object id. */
struct IdArgs {
  ObjectId id{}; ///< The object.
};
/** @brief The argument of a command that takes only an input. */
struct InputArgs {
  CryptoObjectId context{}; ///< The crypto object.
  ByteSpan input;           ///< The data.
};
/** @brief The argument of a command that names a crypto object only. */
struct CryptoObjectArgs {
  CryptoObjectId context{}; ///< The crypto object.
};
/** @brief The argument of a command that names a curve only. */
struct CurveArgs {
  EcCurve curve{EcCurve::NistP256}; ///< The curve.
};
/** @brief `CreateSession`. */
struct CreateSessionArgs {
  ObjectId authentication{}; ///< The authentication object the session is bound to.
};
/** @brief `ExchangeSessionData`. */
struct ExchangeSessionDataArgs {
  SessionPolicy policy{}; ///< The session policy.
};
/** @brief `RefreshSession`. */
struct RefreshSessionArgs {
  SessionPolicy policy{}; ///< The new policy, when `has_policy`.
  bool has_policy{false}; ///< Whether to send a policy.
};
/** @brief `VerifySessionUserId`. */
struct VerifyUserIdArgs {
  ByteSpan user_secret; ///< The UserID value (secret).
};
/** @brief `ScpInitializeUpdate`. */
struct ScpInitArgs {
  ByteSpan host_challenge; ///< The host challenge, from the chip RNG.
};
/** @brief `ScpExternalAuthenticate`. */
struct ScpExternalAuthArgs {
  ByteSpan host_cryptogram; ///< The host cryptogram.
};
/** @brief `EcKeySessionInternalAuthenticate`. */
struct EcKeyAuthArgs {
  ByteSpan host_data; ///< The host's public key and signature, as the codec lays them out.
};
/** @brief `SetLockState` (irreversible). */
struct SetLockStateArgs {
  LockStateValue state{LockStateValue::Locked}; ///< The state.
};
/** @brief `SetPlatformScpRequest` (irreversible). */
struct SetPlatformScpRequestArgs {
  ScpRequirement requirement{ScpRequirement::Required}; ///< The requirement.
};
/** @brief `SetAppletFeatures` (irreversible). */
struct SetAppletFeaturesArgs {
  uint16_t applet_config{0};                    ///< The AppletConfig bits to set.
  std::array<uint8_t, kExtFeatureLength> ext{}; ///< The extended feature bits (applet 7.x).
  bool has_ext{false};                          ///< Whether `ext` is sent.
};
/** @brief `DisableObjCreation` (irreversible). */
struct DisableObjCreationArgs {
  RestrictMode mode{RestrictMode::RestrictNew}; ///< The mode.
};
/** @brief `GetFreeMemory`. */
struct FreeMemoryArgs {
  MemoryType memory{MemoryType::Persistent}; ///< Which memory.
};
/** @brief `GetRandom`: fills `out` with random bytes; `out.size()` is the count (at most 1024). */
struct GetRandomArgs {
  MutableByteSpan out; ///< The output buffer.
};
/** @brief `TriggerSelfTest`. */
struct SelfTestArgs {
  uint16_t test{0}; ///< The self test selector of the applet specification.
};
/** @brief `WriteEcKey`. */
struct WriteEcKeyArgs {
  ObjectId id{};                    ///< The new object.
  const Policy* policy{nullptr};    ///< Its policy; null or empty is `InvalidArgument`.
  EcCurve curve{EcCurve::NistP256}; ///< The curve.
  ByteSpan private_key;             ///< The private key (secret; provisioning only), may be empty.
  ByteSpan public_key;              ///< The public key, may be empty.
  Lifetime lifetime{Lifetime::Persistent}; ///< Persistent or transient.
  uint32_t version{0};                     ///< Object version (applet 7.x); 0 for none.
};
/** @brief `GenerateEcKey`: the key is created inside the chip (`Origin::Internal`). */
struct GenerateEcKeyArgs {
  ObjectId id{};                           ///< The new object.
  const Policy* policy{nullptr};           ///< Its policy.
  EcCurve curve{EcCurve::NistP256};        ///< The curve.
  Lifetime lifetime{Lifetime::Persistent}; ///< Persistent or transient.
  uint32_t version{0};                     ///< Object version (applet 7.x); 0 for none.
};
/** @brief `WriteRsaKey`. */
struct WriteRsaKeyArgs {
  ObjectId id{};                           ///< The new object.
  const Policy* policy{nullptr};           ///< Its policy.
  uint16_t key_bits{0};                    ///< Modulus size in bits (512 to 4096).
  RsaKeyParts parts{};                     ///< The components (secret; provisioning only).
  Lifetime lifetime{Lifetime::Persistent}; ///< Persistent or transient.
  uint32_t version{0};                     ///< Object version (applet 7.x); 0 for none.
};
/** @brief `GenerateRsaKey`: the key is created inside the chip. */
struct GenerateRsaKeyArgs {
  ObjectId id{};                           ///< The new object.
  const Policy* policy{nullptr};           ///< Its policy.
  uint16_t key_bits{2048};                 ///< Modulus size in bits.
  Lifetime lifetime{Lifetime::Persistent}; ///< Persistent or transient.
};
/** @brief `WriteSymmKey`. */
struct WriteSymmKeyArgs {
  ObjectId id{};                      ///< The new object.
  const Policy* policy{nullptr};      ///< Its policy.
  SymmKeyType type{SymmKeyType::Aes}; ///< The key type.
  ByteSpan key;   ///< The key bytes (secret), or the wrapped blob when `kek` is set.
  ObjectId kek{}; ///< Key encryption key object that unwraps `key`, or 0.
  Lifetime lifetime{Lifetime::Persistent}; ///< Persistent or transient.
  uint32_t version{0};                     ///< Object version (applet 7.x); 0 for none.
};
/** @brief `WriteBinary`. */
struct WriteBinaryArgs {
  ObjectId id{};                 ///< The file.
  const Policy* policy{nullptr}; ///< Its policy, required when the file is created.
  uint16_t offset{0};            ///< Offset of the write.
  ByteSpan data;                 ///< The bytes.
  uint16_t file_length{0};       ///< Length of the file when it is created, else 0.
  uint32_t version{0};           ///< Object version, sent as TAG_11 (applet 7.x); 0 for none.
};
/** @brief `WriteUserId`. */
struct WriteUserIdArgs {
  ObjectId id{};                 ///< The new authentication object.
  const Policy* policy{nullptr}; ///< Its policy.
  ByteSpan user_secret;          ///< The UserID value (secret), 4 to 16 bytes.
  uint8_t max_attempts{0}; ///< Attempt limit; 0 is infinite and refused by the library (S-14).
};
/** @brief `WriteCounter`. */
struct WriteCounterArgs {
  ObjectId id{};                 ///< The counter.
  const Policy* policy{nullptr}; ///< Its policy, required when the counter is created.
  uint8_t counter_bytes{8};      ///< Width of the counter in bytes (1 to 8), when created.
  uint64_t value{0};             ///< The value to set, when `set_value`.
  bool set_value{false};         ///< Whether to set the value.
};
/** @brief `WritePcr`. */
struct WritePcrArgs {
  ObjectId id{};                 ///< The PCR.
  const Policy* policy{nullptr}; ///< Its policy.
  ByteSpan initial_value;        ///< The initial value.
};
/** @brief `ExtendPcr`. */
struct ExtendPcrArgs {
  ObjectId id{}; ///< The PCR.
  ByteSpan data; ///< The data to extend with.
};
/** @brief `ImportObject`. */
struct ImportObjectArgs {
  ObjectId id{};                          ///< The object.
  uint8_t rsa_component{kNoRsaComponent}; ///< RSA component (0 to 7) when the object is RSA.
  ByteSpan serialised;                    ///< The serialised object.
};
/** @brief `ExportObject`. */
struct ExportObjectArgs {
  ObjectId id{};                          ///< The object.
  uint8_t rsa_component{kNoRsaComponent}; ///< RSA component (0 to 7) when the object is RSA.
  MutableByteSpan out;                    ///< The output buffer.
};
/** @brief `ImportExternalObject`. */
struct ImportExternalObjectArgs {
  ByteSpan envelope;         ///< The envelope: ECKey import parameters, IV and serialised object.
  bool verify_receipt{true}; ///< Check the receipt with the key the session derives (single-sided
                             ///< import, SCP id 0xAB).
};
/** @brief `SendCardManagerCmd`: a card manager command tunnelled through the applet. */
struct CardManagerCmdArgs {
  ByteSpan command;    ///< The card manager APDU.
  MutableByteSpan out; ///< The response buffer.
};
/** @brief `WritePcrWithType`: a PCR that may be transient. */
struct WritePcrTypedArgs {
  ObjectId id{};                           ///< The PCR.
  const Policy* policy{nullptr};           ///< Its policy.
  ByteSpan initial_value;                  ///< The initial value.
  Lifetime lifetime{Lifetime::Persistent}; ///< Persistent or transient.
};
/** @brief `ReadObject`. */
struct ReadObjectArgs {
  ObjectId id{};                          ///< The object.
  uint16_t offset{0};                     ///< Offset into the object.
  uint16_t length{0};                     ///< Bytes to read; 0 reads all.
  uint8_t rsa_component{kNoRsaComponent}; ///< 0 (modulus) or 1 (public exponent) of an RSA key.
  MutableByteSpan out;                    ///< The output buffer.
};
/** @brief `ReadObjectAttested`. */
struct ReadObjectAttestedArgs {
  ObjectId id{};                                     ///< The object.
  uint16_t offset{0};                                ///< Offset into the object.
  uint16_t length{0};                                ///< Bytes to read; 0 reads all.
  ObjectId attestation_key{};                        ///< The key that signs.
  AttestationAlgo algo{AttestationAlgo::EcSha256};   ///< The signature algorithm.
  std::array<uint8_t, kFreshnessLength> freshness{}; ///< A fresh host nonce per request (S-09).
  MutableByteSpan data_out;                          ///< Buffer for the object data.
  MutableByteSpan signature_out;                     ///< Buffer for the signature.
};
/** @brief `ReadObjectAttributesAttested`: the attributes block signed by an attestation key. */
struct AttributesAttestedArgs {
  ObjectId id{};                                     ///< The object.
  ObjectId attestation_key{};                        ///< The key that signs.
  AttestationAlgo algo{AttestationAlgo::EcSha256};   ///< The signature algorithm.
  std::array<uint8_t, kFreshnessLength> freshness{}; ///< A fresh host nonce per request (S-09).
  MutableByteSpan signature_out;                     ///< Buffer for the signature.
};
/** @brief `ReadRsaAttested`: one RSA component, signed. */
struct ReadRsaAttestedArgs {
  ObjectId id{};                                     ///< The RSA key.
  uint8_t rsa_component{0};                          ///< The component index.
  ObjectId attestation_key{};                        ///< The key that signs.
  AttestationAlgo algo{AttestationAlgo::EcSha256};   ///< The signature algorithm.
  std::array<uint8_t, kFreshnessLength> freshness{}; ///< A fresh host nonce per request (S-09).
  MutableByteSpan data_out;                          ///< Buffer for the component.
  MutableByteSpan signature_out;                     ///< Buffer for the signature.
};
/** @brief `ReadIdList`. */
struct ReadIdListArgs {
  uint16_t offset{0};                               ///< How many ids to skip.
  bool filter_by_class{false};                      ///< Whether `object_class` filters the list.
  ObjectClass object_class{ObjectClass::EcKeyPair}; ///< The class filter.
  std::span<ObjectId> out;                          ///< The output buffer.
};
/** @brief `SetEcCurveParam`. */
struct SetCurveParamArgs {
  EcCurve curve{EcCurve::NistP256}; ///< The curve.
  uint8_t parameter{0};             ///< The parameter selector of the applet specification.
  ByteSpan value;                   ///< The parameter value.
};
/** @brief `CreateCryptoObject`. */
struct CreateCryptoObjectArgs {
  CryptoObjectId context{};                        ///< The new identifier.
  CryptoObjectType type{CryptoObjectType::Digest}; ///< What it computes.
  uint8_t algorithm{0}; ///< The enumerator of `DigestMode`, `CipherMode`, `MacAlgo` or `AeadMode`
                        ///< that matches `type`.
};
/** @brief `EcdsaSign` and `EddsaSign`. */
struct SignArgs {
  ObjectId key{};                      ///< The signing key.
  EcSignAlgo algo{EcSignAlgo::Sha256}; ///< The algorithm; `Ed25519Pure` for `EddsaSign`.
  ByteSpan input;                      ///< The digest or message.
  MutableByteSpan signature;           ///< The signature buffer (DER for ECDSA).
};
/** @brief `EcdsaVerify` and `EddsaVerify`. */
struct VerifyArgs {
  ObjectId key{};                      ///< The verification key (public or key pair).
  EcSignAlgo algo{EcSignAlgo::Sha256}; ///< The algorithm.
  ByteSpan input;                      ///< The digest or message.
  ByteSpan signature;                  ///< The signature.
};
/** @brief `EcdaaSign`. */
struct EcdaaSignArgs {
  ObjectId key{};            ///< The signing key.
  ByteSpan random;           ///< The 32-byte random.
  ByteSpan digest;           ///< The 32-byte digest.
  MutableByteSpan signature; ///< The signature buffer.
};
/** @brief `EcdhGenerateSharedSecret`. */
struct EcdhArgs {
  ObjectId key{};                       ///< The private key.
  EcdhAlgo algo{EcdhAlgo::SvdpDhPlain}; ///< The variant: `SvdpDhPlain` (the x coordinate) works on
                                        ///< every applet; `SvdpDh` (SHA-1 of x) needs 7.x.
                                        ///< Montgomery curves write NVM on every call.
  ByteSpan peer_public;                 ///< The peer's public key.
  MutableByteSpan secret;               ///< The shared secret buffer (secret).
};
/** @brief `EcdhIntoObject`: the shared secret stays in a chip object. */
struct EcdhIntoObjectArgs {
  ObjectId key{};                ///< The private key.
  ByteSpan peer_public;          ///< The peer's public key.
  ObjectId target{};             ///< The object that receives the secret.
  const Policy* policy{nullptr}; ///< Must be null: the target exists before (AN12543 3.7.6.2).
  EcdhAlgo algo{EcdhAlgo::SvdpDhPlain}; ///< The variant (`SvdpDh` needs applet 7.x).
};
/** @brief `EcPointMultiply`. */
struct EcPointMultiplyArgs {
  ObjectId key{};      ///< The scalar key.
  ByteSpan point;      ///< The point.
  MutableByteSpan out; ///< The result buffer.
};
/** @brief `EcPointMultiplyInputObj`: the point is a key object. */
struct EcPointMultiplyObjArgs {
  ObjectId key{};      ///< The scalar key.
  ObjectId point{};    ///< The object that holds the point.
  MutableByteSpan out; ///< The result buffer.
};
/** @brief `RsaSign`. */
struct RsaSignArgs {
  ObjectId key{};                           ///< The key.
  RsaSignAlgo algo{RsaSignAlgo::Sha256Pss}; ///< The algorithm.
  ByteSpan input;                           ///< The message or digest.
  MutableByteSpan signature;                ///< The signature buffer.
};
/** @brief `RsaVerify`. */
struct RsaVerifyArgs {
  ObjectId key{};                           ///< The key.
  RsaSignAlgo algo{RsaSignAlgo::Sha256Pss}; ///< The algorithm.
  ByteSpan input;                           ///< The message or digest.
  ByteSpan signature;                       ///< The signature.
};
/** @brief `RsaEncrypt` and `RsaDecrypt`. */
struct RsaCryptArgs {
  ObjectId key{};                             ///< The key.
  RsaCryptAlgo algo{RsaCryptAlgo::Pkcs1Oaep}; ///< The algorithm.
  ByteSpan input;                             ///< The input block.
  MutableByteSpan out;                        ///< The output buffer.
};
/** @brief `CipherInit`. */
struct CipherInitArgs {
  CryptoObjectId context{}; ///< The crypto object.
  ObjectId key{};           ///< The key object.
  ByteSpan iv;              ///< The IV, when the mode needs one.
  bool encrypt{true};       ///< Direction.
};
/** @brief `CipherUpdate`, `CipherFinal` and `AeadUpdate`. */
struct StreamArgs {
  CryptoObjectId context{}; ///< The crypto object.
  ByteSpan input;           ///< The data.
  MutableByteSpan out;      ///< The output buffer.
};
/** @brief `CipherOneShot`. */
struct CipherOneShotArgs {
  ObjectId key{};                           ///< The key object.
  CipherMode mode{CipherMode::AesCbcNoPad}; ///< The mode.
  ByteSpan iv;                              ///< The IV, when the mode needs one.
  bool encrypt{true};                       ///< Direction.
  ByteSpan input;                           ///< The data.
  MutableByteSpan out;                      ///< The output buffer.
};
/** @brief `AeadInit`. */
struct AeadInitArgs {
  CryptoObjectId context{}; ///< The crypto object.
  ObjectId key{};           ///< The key object.
  ByteSpan iv; ///< The nonce; empty when the chip generates it (internal IV, `iv_out`).
  AeadMode mode{AeadMode::AesGcm}; ///< GCM or CCM.
  MutableByteSpan
      iv_out;         ///< Receives the IV the chip generated when `iv` is empty (encryption only).
  bool encrypt{true}; ///< Direction.
  uint16_t aad_length{0};  ///< Total associated data length, when the mode needs it up front.
  uint16_t data_length{0}; ///< Total data length, when the mode needs it up front.
  uint8_t tag_length{16};  ///< Tag length in bytes.
};
/** @brief `AeadUpdateAad`. */
struct AeadAadArgs {
  CryptoObjectId context{}; ///< The crypto object.
  ByteSpan aad;             ///< The associated data.
};
/** @brief `AeadFinal`. */
struct AeadFinalArgs {
  CryptoObjectId context{}; ///< The crypto object.
  ByteSpan input;           ///< The last data.
  MutableByteSpan out;      ///< The output buffer.
  ByteSpan tag_in;          ///< The tag to check, when decrypting.
  MutableByteSpan tag_out;  ///< The tag buffer, when encrypting.
};
/** @brief `AeadOneShot`. */
struct AeadOneShotArgs {
  ObjectId key{};                  ///< The key object.
  AeadMode mode{AeadMode::AesGcm}; ///< The mode.
  ByteSpan iv;                     ///< The nonce; empty when the chip generates it.
  ByteSpan aad;                    ///< The associated data.
  bool encrypt{true};              ///< Direction.
  ByteSpan input;                  ///< The data.
  MutableByteSpan out;             ///< The output buffer.
  ByteSpan tag_in;                 ///< The tag to check, when decrypting.
  MutableByteSpan tag_out;         ///< The tag buffer, when encrypting.
};
/** @brief `MacInit`. */
struct MacInitArgs {
  CryptoObjectId context{}; ///< The crypto object.
  ObjectId key{};           ///< The key object.
  bool generate{true};      ///< Generate a MAC (true) or validate one (false).
};
/** @brief `MacFinal`. */
struct MacFinalArgs {
  CryptoObjectId context{}; ///< The crypto object.
  ByteSpan input;           ///< The last data.
  ByteSpan tag_in;          ///< The MAC to validate, when validating.
  MutableByteSpan tag_out;  ///< The MAC buffer, when generating.
};
/** @brief `MacOneShot`. */
struct MacOneShotArgs {
  ObjectId key{};                    ///< The key object.
  MacAlgo algo{MacAlgo::HmacSha256}; ///< The algorithm.
  ByteSpan input;                    ///< The data.
  bool generate{true};               ///< Generate (true) or validate (false).
  ByteSpan tag_in;                   ///< The MAC to validate.
  MutableByteSpan tag_out;           ///< The MAC buffer.
};
/** @brief `DigestFinal`. */
struct DigestFinalArgs {
  CryptoObjectId context{}; ///< The crypto object.
  ByteSpan input;           ///< The last data.
  MutableByteSpan out;      ///< The digest buffer.
};
/** @brief `DigestOneShot`. */
struct DigestOneShotArgs {
  DigestMode mode{DigestMode::Sha256}; ///< The algorithm.
  ByteSpan input;                      ///< The data.
  MutableByteSpan out;                 ///< The digest buffer.
};
/** @brief `Hkdf`. */
struct HkdfArgs {
  ObjectId key{};                         ///< The input key object.
  DigestMode digest{DigestMode::Sha256};  ///< The hash.
  HkdfMode mode{HkdfMode::ExtractExpand}; ///< Extract and expand, or expand only.
  ByteSpan salt;                          ///< The salt.
  ByteSpan info;                          ///< The info (at most 80 bytes on applet 7.x).
  uint16_t derived_length{0};             ///< Bytes to derive.
  MutableByteSpan out;                    ///< The output buffer, or empty when `target` is set.
  ObjectId target{};                      ///< A chip object that keeps the derived key, or 0.
};
/** @brief `Pbkdf2`. */
struct Pbkdf2Args {
  ObjectId key{};                        ///< The password object.
  ByteSpan salt;                         ///< The salt.
  uint16_t iterations{0};                ///< The iteration count (1 to 0x7FFF).
  DigestMode digest{DigestMode::Sha256}; ///< The hash.
  uint16_t derived_length{0};            ///< Bytes to derive.
  MutableByteSpan out;                   ///< The output buffer.
};
/** @brief `TlsGenerateRandom`. */
struct TlsRandomArgs {
  MutableByteSpan out; ///< The 32-byte random buffer.
};
/** @brief `TlsCalculatePreMasterSecret`. */
struct TlsPmsArgs {
  ObjectId key{};                ///< The PSK, ECDH or RSA key object.
  ObjectId target{};             ///< The object that receives the premaster secret.
  ByteSpan input;                ///< The peer data (public key, ClientHello random, encrypted PMS).
  const Policy* policy{nullptr}; ///< The policy of `target`.
};
/** @brief `TlsPerformPrf`. */
struct TlsPrfArgs {
  ObjectId key{};                        ///< The master secret or premaster object.
  DigestMode digest{DigestMode::Sha256}; ///< The hash.
  ByteSpan label;                        ///< The PRF label.
  ByteSpan random;                       ///< The server and client random.
  uint16_t length{0};                    ///< Bytes to derive.
  MutableByteSpan out;                   ///< The output buffer.
  TlsRole role{TlsRole::Client};         ///< The host's role (ignored for a 64-byte random).
};
/** @brief The shared argument of the DESFire commands. */
struct DfArgs {
  ObjectId key{};      ///< The DESFire key object.
  ObjectId target{};   ///< The target object, when the command writes one.
  ByteSpan input;      ///< The command data.
  MutableByteSpan out; ///< The output buffer.
};
/** @brief `I2cmExecuteCommandSet`. */
struct I2cmArgs {
  ByteSpan commands;   ///< The command set in the applet's TLV format.
  MutableByteSpan out; ///< The response buffer.
};
/** @brief `I2cmExecuteCommandSetAttested`. */
struct I2cmAttestedArgs {
  ByteSpan commands;                                 ///< The command set.
  ObjectId attestation_key{};                        ///< The key that signs.
  AttestationAlgo algo{AttestationAlgo::EcSha256};   ///< The signature algorithm.
  std::array<uint8_t, kFreshnessLength> freshness{}; ///< The freshness nonce.
  MutableByteSpan data_out;                          ///< The response buffer.
  MutableByteSpan signature_out;                     ///< The signature buffer.
};
/// @}

/**
 * @brief The argument and reply types of command `C`. Specialised once per command below.
 * @tparam C The command.
 */
template <Command C>
struct CommandTypes;

/// Types of `Command::SelectApplet`.
template <>
struct CommandTypes<Command::SelectApplet> {
  using Args = Empty;       ///< The argument.
  using Reply = AppletInfo; ///< The reply.
};

/// Types of `Command::GetVersion`.
template <>
struct CommandTypes<Command::GetVersion> {
  using Args = Empty;       ///< The argument.
  using Reply = AppletInfo; ///< The reply.
};

/// Types of `Command::GetExtVersion`.
template <>
struct CommandTypes<Command::GetExtVersion> {
  using Args = Empty;        ///< The argument.
  using Reply = ExtFeatures; ///< The reply.
};

/// Types of `Command::GetCardIdentification`.
template <>
struct CommandTypes<Command::GetCardIdentification> {
  using Args = Empty;   ///< The argument.
  using Reply = CardId; ///< The reply.
};

/// Types of `Command::GetCplc`.
template <>
struct CommandTypes<Command::GetCplc> {
  using Args = Empty; ///< The argument.
  using Reply = Cplc; ///< The reply.
};

/// Types of `Command::CreateSession`.
template <>
struct CommandTypes<Command::CreateSession> {
  using Args = CreateSessionArgs; ///< The argument.
  using Reply = SessionId;        ///< The reply.
};

/// Types of `Command::ExchangeSessionData`.
template <>
struct CommandTypes<Command::ExchangeSessionData> {
  using Args = ExchangeSessionDataArgs; ///< The argument.
  using Reply = Empty;                  ///< The reply.
};

/// Types of `Command::RefreshSession`.
template <>
struct CommandTypes<Command::RefreshSession> {
  using Args = RefreshSessionArgs; ///< The argument.
  using Reply = Empty;             ///< The reply.
};

/// Types of `Command::CloseSession`.
template <>
struct CommandTypes<Command::CloseSession> {
  using Args = Empty;  ///< The argument.
  using Reply = Empty; ///< The reply.
};

/// Types of `Command::VerifySessionUserId`.
template <>
struct CommandTypes<Command::VerifySessionUserId> {
  using Args = VerifyUserIdArgs; ///< The argument.
  using Reply = Empty;           ///< The reply.
};

/// Types of `Command::ScpInitializeUpdate`.
template <>
struct CommandTypes<Command::ScpInitializeUpdate> {
  using Args = ScpInitArgs; ///< The argument.
  using Reply = SmallBlob;  ///< The reply.
};

/// Types of `Command::ScpExternalAuthenticate`.
template <>
struct CommandTypes<Command::ScpExternalAuthenticate> {
  using Args = ScpExternalAuthArgs; ///< The argument.
  using Reply = Empty;              ///< The reply.
};

/// Types of `Command::EcKeySessionInternalAuthenticate`.
template <>
struct CommandTypes<Command::EcKeySessionInternalAuthenticate> {
  using Args = EcKeyAuthArgs; ///< The argument.
  using Reply = SmallBlob;    ///< The reply.
};

/// Types of `Command::EcKeySessionGetEckaPublicKey`.
template <>
struct CommandTypes<Command::EcKeySessionGetEckaPublicKey> {
  using Args = Empty;      ///< The argument.
  using Reply = SmallBlob; ///< The reply.
};

/// Types of `Command::SetLockState`.
template <>
struct CommandTypes<Command::SetLockState> {
  using Args = SetLockStateArgs; ///< The argument.
  using Reply = Empty;           ///< The reply.
};

/// Types of `Command::SetPlatformScpRequest`.
template <>
struct CommandTypes<Command::SetPlatformScpRequest> {
  using Args = SetPlatformScpRequestArgs; ///< The argument.
  using Reply = Empty;                    ///< The reply.
};

/// Types of `Command::SetAppletFeatures`.
template <>
struct CommandTypes<Command::SetAppletFeatures> {
  using Args = SetAppletFeaturesArgs; ///< The argument.
  using Reply = Empty;                ///< The reply.
};

/// Types of `Command::DeleteAll`.
template <>
struct CommandTypes<Command::DeleteAll> {
  using Args = Empty;  ///< The argument.
  using Reply = Empty; ///< The reply.
};

/// Types of `Command::DisableObjCreation`.
template <>
struct CommandTypes<Command::DisableObjCreation> {
  using Args = DisableObjCreationArgs; ///< The argument.
  using Reply = Empty;                 ///< The reply.
};

/// Types of `Command::GetFreeMemory`.
template <>
struct CommandTypes<Command::GetFreeMemory> {
  using Args = FreeMemoryArgs; ///< The argument.
  using Reply = U32Reply;      ///< The reply.
};

/// Types of `Command::GetTimestamp`.
template <>
struct CommandTypes<Command::GetTimestamp> {
  using Args = Empty;      ///< The argument.
  using Reply = Timestamp; ///< The reply.
};

/// Types of `Command::GetRandom`.
template <>
struct CommandTypes<Command::GetRandom> {
  using Args = GetRandomArgs; ///< The argument.
  using Reply = LengthReply;  ///< The reply.
};

/// Types of `Command::ReadState`.
template <>
struct CommandTypes<Command::ReadState> {
  using Args = Empty;      ///< The argument.
  using Reply = SmallBlob; ///< The reply.
};

/// Types of `Command::CmInvokeGarbageCollection`.
template <>
struct CommandTypes<Command::CmInvokeGarbageCollection> {
  using Args = Empty;  ///< The argument.
  using Reply = Empty; ///< The reply.
};

/// Types of `Command::SendCardManagerCmd`.
template <>
struct CommandTypes<Command::SendCardManagerCmd> {
  using Args = CardManagerCmdArgs; ///< The argument.
  using Reply = LengthReply;       ///< The reply.
};

/// Types of `Command::TriggerSelfTest`.
template <>
struct CommandTypes<Command::TriggerSelfTest> {
  using Args = SelfTestArgs;   ///< The argument.
  using Reply = SelfTestReply; ///< The reply.
};

/// Types of `Command::WriteEcKey`.
template <>
struct CommandTypes<Command::WriteEcKey> {
  using Args = WriteEcKeyArgs; ///< The argument.
  using Reply = Empty;         ///< The reply.
};

/// Types of `Command::GenerateEcKey`.
template <>
struct CommandTypes<Command::GenerateEcKey> {
  using Args = GenerateEcKeyArgs; ///< The argument.
  using Reply = Empty;            ///< The reply.
};

/// Types of `Command::WriteRsaKey`.
template <>
struct CommandTypes<Command::WriteRsaKey> {
  using Args = WriteRsaKeyArgs; ///< The argument.
  using Reply = Empty;          ///< The reply.
};

/// Types of `Command::GenerateRsaKey`.
template <>
struct CommandTypes<Command::GenerateRsaKey> {
  using Args = GenerateRsaKeyArgs; ///< The argument.
  using Reply = Empty;             ///< The reply.
};

/// Types of `Command::WriteSymmKey`.
template <>
struct CommandTypes<Command::WriteSymmKey> {
  using Args = WriteSymmKeyArgs; ///< The argument.
  using Reply = Empty;           ///< The reply.
};

/// Types of `Command::WriteBinary`.
template <>
struct CommandTypes<Command::WriteBinary> {
  using Args = WriteBinaryArgs; ///< The argument.
  using Reply = Empty;          ///< The reply.
};

/// Types of `Command::WriteUserId`.
template <>
struct CommandTypes<Command::WriteUserId> {
  using Args = WriteUserIdArgs; ///< The argument.
  using Reply = Empty;          ///< The reply.
};

/// Types of `Command::WriteCounter`.
template <>
struct CommandTypes<Command::WriteCounter> {
  using Args = WriteCounterArgs; ///< The argument.
  using Reply = Empty;           ///< The reply.
};

/// Types of `Command::IncrementCounter`.
template <>
struct CommandTypes<Command::IncrementCounter> {
  using Args = IdArgs; ///< The argument.
  using Reply = Empty; ///< The reply.
};

/// Types of `Command::WritePcr`.
template <>
struct CommandTypes<Command::WritePcr> {
  using Args = WritePcrArgs; ///< The argument.
  using Reply = Empty;       ///< The reply.
};

/// Types of `Command::ExtendPcr`.
template <>
struct CommandTypes<Command::ExtendPcr> {
  using Args = ExtendPcrArgs; ///< The argument.
  using Reply = Empty;        ///< The reply.
};

/// Types of `Command::ImportObject`.
template <>
struct CommandTypes<Command::ImportObject> {
  using Args = ImportObjectArgs; ///< The argument.
  using Reply = Empty;           ///< The reply.
};

/// Types of `Command::ExportObject`.
template <>
struct CommandTypes<Command::ExportObject> {
  using Args = ExportObjectArgs; ///< The argument.
  using Reply = LengthReply;     ///< The reply.
};

/// Types of `Command::ImportExternalObject`.
template <>
struct CommandTypes<Command::ImportExternalObject> {
  using Args = ImportExternalObjectArgs; ///< The argument.
  using Reply = ExternalImportReceipt;   ///< The reply.
};

/// Types of `Command::WritePcrWithType`.
template <>
struct CommandTypes<Command::WritePcrWithType> {
  using Args = WritePcrTypedArgs; ///< The argument.
  using Reply = Empty;            ///< The reply.
};

/// Types of `Command::ReadObject`.
template <>
struct CommandTypes<Command::ReadObject> {
  using Args = ReadObjectArgs; ///< The argument.
  using Reply = LengthReply;   ///< The reply.
};

/// Types of `Command::ReadObjectAttested`.
template <>
struct CommandTypes<Command::ReadObjectAttested> {
  using Args = ReadObjectAttestedArgs; ///< The argument.
  using Reply = AttestedRead;          ///< The reply.
};

/// Types of `Command::ReadObjectAttributes`.
template <>
struct CommandTypes<Command::ReadObjectAttributes> {
  using Args = IdArgs;            ///< The argument.
  using Reply = ObjectAttributes; ///< The reply.
};

/// Types of `Command::ReadObjectAttributesAttested`.
template <>
struct CommandTypes<Command::ReadObjectAttributesAttested> {
  using Args = AttributesAttestedArgs; ///< The argument.
  using Reply = AttestedRead;          ///< The reply.
};

/// Types of `Command::ReadRsaAttested`.
template <>
struct CommandTypes<Command::ReadRsaAttested> {
  using Args = ReadRsaAttestedArgs; ///< The argument.
  using Reply = AttestedRead;       ///< The reply.
};

/// Types of `Command::ReadType`.
template <>
struct CommandTypes<Command::ReadType> {
  using Args = IdArgs;     ///< The argument.
  using Reply = TypeReply; ///< The reply.
};

/// Types of `Command::ReadSize`.
template <>
struct CommandTypes<Command::ReadSize> {
  using Args = IdArgs;    ///< The argument.
  using Reply = U32Reply; ///< The reply.
};

/// Types of `Command::ReadIdList`.
template <>
struct CommandTypes<Command::ReadIdList> {
  using Args = ReadIdListArgs; ///< The argument.
  using Reply = IdListReply;   ///< The reply.
};

/// Types of `Command::CheckObjectExists`.
template <>
struct CommandTypes<Command::CheckObjectExists> {
  using Args = IdArgs;     ///< The argument.
  using Reply = BoolReply; ///< The reply.
};

/// Types of `Command::DeleteSecureObject`.
template <>
struct CommandTypes<Command::DeleteSecureObject> {
  using Args = IdArgs; ///< The argument.
  using Reply = Empty; ///< The reply.
};

/// Types of `Command::CreateEcCurve`.
template <>
struct CommandTypes<Command::CreateEcCurve> {
  using Args = CurveArgs; ///< The argument.
  using Reply = Empty;    ///< The reply.
};

/// Types of `Command::SetEcCurveParam`.
template <>
struct CommandTypes<Command::SetEcCurveParam> {
  using Args = SetCurveParamArgs; ///< The argument.
  using Reply = Empty;            ///< The reply.
};

/// Types of `Command::GetEcCurveId`.
template <>
struct CommandTypes<Command::GetEcCurveId> {
  using Args = IdArgs;      ///< The argument.
  using Reply = CurveReply; ///< The reply.
};

/// Types of `Command::ReadEcCurveList`.
template <>
struct CommandTypes<Command::ReadEcCurveList> {
  using Args = Empty;      ///< The argument.
  using Reply = SmallBlob; ///< The reply.
};

/// Types of `Command::DeleteEcCurve`.
template <>
struct CommandTypes<Command::DeleteEcCurve> {
  using Args = CurveArgs; ///< The argument.
  using Reply = Empty;    ///< The reply.
};

/// Types of `Command::CreateCryptoObject`.
template <>
struct CommandTypes<Command::CreateCryptoObject> {
  using Args = CreateCryptoObjectArgs; ///< The argument.
  using Reply = Empty;                 ///< The reply.
};

/// Types of `Command::ReadCryptoObjectList`.
template <>
struct CommandTypes<Command::ReadCryptoObjectList> {
  using Args = Empty;      ///< The argument.
  using Reply = SmallBlob; ///< The reply.
};

/// Types of `Command::DeleteCryptoObject`.
template <>
struct CommandTypes<Command::DeleteCryptoObject> {
  using Args = CryptoObjectArgs; ///< The argument.
  using Reply = Empty;           ///< The reply.
};

/// Types of `Command::EcdsaSign`.
template <>
struct CommandTypes<Command::EcdsaSign> {
  using Args = SignArgs;     ///< The argument.
  using Reply = LengthReply; ///< The reply.
};

/// Types of `Command::EcdsaVerify`.
template <>
struct CommandTypes<Command::EcdsaVerify> {
  using Args = VerifyArgs; ///< The argument.
  using Reply = BoolReply; ///< The reply.
};

/// Types of `Command::EddsaSign`.
template <>
struct CommandTypes<Command::EddsaSign> {
  using Args = SignArgs;     ///< The argument.
  using Reply = LengthReply; ///< The reply.
};

/// Types of `Command::EddsaVerify`.
template <>
struct CommandTypes<Command::EddsaVerify> {
  using Args = VerifyArgs; ///< The argument.
  using Reply = BoolReply; ///< The reply.
};

/// Types of `Command::EcdaaSign`.
template <>
struct CommandTypes<Command::EcdaaSign> {
  using Args = EcdaaSignArgs; ///< The argument.
  using Reply = LengthReply;  ///< The reply.
};

/// Types of `Command::EcdhGenerateSharedSecret`.
template <>
struct CommandTypes<Command::EcdhGenerateSharedSecret> {
  using Args = EcdhArgs;     ///< The argument.
  using Reply = LengthReply; ///< The reply.
};

/// Types of `Command::EcdhIntoObject`.
template <>
struct CommandTypes<Command::EcdhIntoObject> {
  using Args = EcdhIntoObjectArgs; ///< The argument.
  using Reply = Empty;             ///< The reply.
};

/// Types of `Command::EcPointMultiply`.
template <>
struct CommandTypes<Command::EcPointMultiply> {
  using Args = EcPointMultiplyArgs; ///< The argument.
  using Reply = LengthReply;        ///< The reply.
};

/// Types of `Command::EcPointMultiplyInputObj`.
template <>
struct CommandTypes<Command::EcPointMultiplyInputObj> {
  using Args = EcPointMultiplyObjArgs; ///< The argument.
  using Reply = LengthReply;           ///< The reply.
};

/// Types of `Command::RsaSign`.
template <>
struct CommandTypes<Command::RsaSign> {
  using Args = RsaSignArgs;  ///< The argument.
  using Reply = LengthReply; ///< The reply.
};

/// Types of `Command::RsaVerify`.
template <>
struct CommandTypes<Command::RsaVerify> {
  using Args = RsaVerifyArgs; ///< The argument.
  using Reply = BoolReply;    ///< The reply.
};

/// Types of `Command::RsaEncrypt`.
template <>
struct CommandTypes<Command::RsaEncrypt> {
  using Args = RsaCryptArgs; ///< The argument.
  using Reply = LengthReply; ///< The reply.
};

/// Types of `Command::RsaDecrypt`.
template <>
struct CommandTypes<Command::RsaDecrypt> {
  using Args = RsaCryptArgs; ///< The argument.
  using Reply = LengthReply; ///< The reply.
};

/// Types of `Command::CipherInit`.
template <>
struct CommandTypes<Command::CipherInit> {
  using Args = CipherInitArgs; ///< The argument.
  using Reply = Empty;         ///< The reply.
};

/// Types of `Command::CipherUpdate`.
template <>
struct CommandTypes<Command::CipherUpdate> {
  using Args = StreamArgs;   ///< The argument.
  using Reply = LengthReply; ///< The reply.
};

/// Types of `Command::CipherFinal`.
template <>
struct CommandTypes<Command::CipherFinal> {
  using Args = StreamArgs;   ///< The argument.
  using Reply = LengthReply; ///< The reply.
};

/// Types of `Command::CipherOneShot`.
template <>
struct CommandTypes<Command::CipherOneShot> {
  using Args = CipherOneShotArgs; ///< The argument.
  using Reply = LengthReply;      ///< The reply.
};

/// Types of `Command::AeadInit`.
template <>
struct CommandTypes<Command::AeadInit> {
  using Args = AeadInitArgs; ///< The argument.
  using Reply = Empty;       ///< The reply.
};

/// Types of `Command::AeadUpdateAad`.
template <>
struct CommandTypes<Command::AeadUpdateAad> {
  using Args = AeadAadArgs; ///< The argument.
  using Reply = Empty;      ///< The reply.
};

/// Types of `Command::AeadUpdate`.
template <>
struct CommandTypes<Command::AeadUpdate> {
  using Args = StreamArgs;   ///< The argument.
  using Reply = LengthReply; ///< The reply.
};

/// Types of `Command::AeadFinal`.
template <>
struct CommandTypes<Command::AeadFinal> {
  using Args = AeadFinalArgs; ///< The argument.
  using Reply = LengthReply;  ///< The reply.
};

/// Types of `Command::AeadOneShot`.
template <>
struct CommandTypes<Command::AeadOneShot> {
  using Args = AeadOneShotArgs; ///< The argument.
  using Reply = LengthReply;    ///< The reply.
};

/// Types of `Command::MacInit`.
template <>
struct CommandTypes<Command::MacInit> {
  using Args = MacInitArgs; ///< The argument.
  using Reply = Empty;      ///< The reply.
};

/// Types of `Command::MacUpdate`.
template <>
struct CommandTypes<Command::MacUpdate> {
  using Args = InputArgs; ///< The argument.
  using Reply = Empty;    ///< The reply.
};

/// Types of `Command::MacFinal`.
template <>
struct CommandTypes<Command::MacFinal> {
  using Args = MacFinalArgs; ///< The argument.
  using Reply = LengthReply; ///< The reply.
};

/// Types of `Command::MacOneShot`.
template <>
struct CommandTypes<Command::MacOneShot> {
  using Args = MacOneShotArgs; ///< The argument.
  using Reply = LengthReply;   ///< The reply.
};

/// Types of `Command::DigestInit`.
template <>
struct CommandTypes<Command::DigestInit> {
  using Args = CryptoObjectArgs; ///< The argument.
  using Reply = Empty;           ///< The reply.
};

/// Types of `Command::DigestUpdate`.
template <>
struct CommandTypes<Command::DigestUpdate> {
  using Args = InputArgs; ///< The argument.
  using Reply = Empty;    ///< The reply.
};

/// Types of `Command::DigestFinal`.
template <>
struct CommandTypes<Command::DigestFinal> {
  using Args = DigestFinalArgs; ///< The argument.
  using Reply = LengthReply;    ///< The reply.
};

/// Types of `Command::DigestOneShot`.
template <>
struct CommandTypes<Command::DigestOneShot> {
  using Args = DigestOneShotArgs; ///< The argument.
  using Reply = LengthReply;      ///< The reply.
};

/// Types of `Command::Hkdf`.
template <>
struct CommandTypes<Command::Hkdf> {
  using Args = HkdfArgs;     ///< The argument.
  using Reply = LengthReply; ///< The reply.
};

/// Types of `Command::Pbkdf2`.
template <>
struct CommandTypes<Command::Pbkdf2> {
  using Args = Pbkdf2Args;   ///< The argument.
  using Reply = LengthReply; ///< The reply.
};

/// Types of `Command::TlsGenerateRandom`.
template <>
struct CommandTypes<Command::TlsGenerateRandom> {
  using Args = TlsRandomArgs; ///< The argument.
  using Reply = LengthReply;  ///< The reply.
};

/// Types of `Command::TlsCalculatePreMasterSecret`.
template <>
struct CommandTypes<Command::TlsCalculatePreMasterSecret> {
  using Args = TlsPmsArgs; ///< The argument.
  using Reply = Empty;     ///< The reply.
};

/// Types of `Command::TlsPerformPrf`.
template <>
struct CommandTypes<Command::TlsPerformPrf> {
  using Args = TlsPrfArgs;   ///< The argument.
  using Reply = LengthReply; ///< The reply.
};

/// Types of `Command::DfDiversifyKey`.
template <>
struct CommandTypes<Command::DfDiversifyKey> {
  using Args = DfArgs; ///< The argument.
  using Reply = Empty; ///< The reply.
};

/// Types of `Command::DfAuthenticateFirstPart1`.
template <>
struct CommandTypes<Command::DfAuthenticateFirstPart1> {
  using Args = DfArgs;       ///< The argument.
  using Reply = LengthReply; ///< The reply.
};

/// Types of `Command::DfAuthenticateFirstPart2`.
template <>
struct CommandTypes<Command::DfAuthenticateFirstPart2> {
  using Args = DfArgs;       ///< The argument.
  using Reply = LengthReply; ///< The reply.
};

/// Types of `Command::DfAuthenticateNonFirstPart1`.
template <>
struct CommandTypes<Command::DfAuthenticateNonFirstPart1> {
  using Args = DfArgs;       ///< The argument.
  using Reply = LengthReply; ///< The reply.
};

/// Types of `Command::DfAuthenticateNonFirstPart2`.
template <>
struct CommandTypes<Command::DfAuthenticateNonFirstPart2> {
  using Args = DfArgs;       ///< The argument.
  using Reply = LengthReply; ///< The reply.
};

/// Types of `Command::DfDumpSessionKeys`.
template <>
struct CommandTypes<Command::DfDumpSessionKeys> {
  using Args = DfArgs;       ///< The argument.
  using Reply = LengthReply; ///< The reply.
};

/// Types of `Command::DfChangeKeyPart1`.
template <>
struct CommandTypes<Command::DfChangeKeyPart1> {
  using Args = DfArgs;       ///< The argument.
  using Reply = LengthReply; ///< The reply.
};

/// Types of `Command::DfChangeKeyPart2`.
template <>
struct CommandTypes<Command::DfChangeKeyPart2> {
  using Args = DfArgs;       ///< The argument.
  using Reply = LengthReply; ///< The reply.
};

/// Types of `Command::DfKillAuthentication`.
template <>
struct CommandTypes<Command::DfKillAuthentication> {
  using Args = DfArgs; ///< The argument.
  using Reply = Empty; ///< The reply.
};

/// Types of `Command::I2cmExecuteCommandSet`.
template <>
struct CommandTypes<Command::I2cmExecuteCommandSet> {
  using Args = I2cmArgs;     ///< The argument.
  using Reply = LengthReply; ///< The reply.
};

/// Types of `Command::I2cmExecuteCommandSetAttested`.
template <>
struct CommandTypes<Command::I2cmExecuteCommandSetAttested> {
  using Args = I2cmAttestedArgs; ///< The argument.
  using Reply = AttestedRead;    ///< The reply.
};

/// The argument type of command `C`.
template <Command C>
using ArgsOf = typename CommandTypes<C>::Args;
/// The reply type of command `C`.
template <Command C>
using ReplyOf = typename CommandTypes<C>::Reply;

/** @} */

} // namespace se05x

#endif // SE05X_DEVICE_TYPES_HPP
