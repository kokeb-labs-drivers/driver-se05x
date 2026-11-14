/**
 * @file se05x_pki_types.hpp
 * @brief The vocabulary of the optional PKI layer (`se05x::pki`): reasons, key and signature
 * types, key usage bits, calendar time, object identifiers and limits.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * The PKI layer is opt-in: nothing else in the library includes its
 * headers, and `se05x.hpp` does not either. Include `se05x_pki.hpp` for all of it.
 *
 * Every fallible call of the layer returns a `Result<T>`. On failure `Detail::layer` is
 * `Layer::Pki` and `Detail::step` holds the precise `Reason` (`ReasonOf()` reads it back), while
 * `Result::error` is the coarse `Error` of `ErrorOf()`: `InvalidArgument` for a malformed input or
 * a bad builder argument, `Unsupported` for a well-formed input this layer does not handle,
 * `AttestationInvalid` for a certificate or signature check that failed, `BufferTooSmall` and
 * `CryptoFailure`. A failure from the device keeps the device's own details.
 */
#ifndef SE05X_PKI_TYPES_HPP
#define SE05X_PKI_TYPES_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "se05x_detail.hpp"
#include "se05x_status.hpp"
#include "se05x_types.hpp"

/** @brief The optional device-side PKI layer: DER, CSR, X.509 and certificate storage. */
namespace se05x::pki {

/**
 * @defgroup se05x_pki_types PKI types
 * @brief Reasons, key types, time, object identifiers and limits of the PKI layer.
 * @{
 */

/** @brief Why a PKI call failed, precisely; `Detail::step` carries it. */
enum class Reason : uint8_t {
  Ok = 0,                    ///< No failure.
  Truncated = 1,             ///< An element runs past the end of its input.
  HighTagNumber = 2,         ///< A tag number above 30 (multi-byte tag): not used by this profile.
  IndefiniteLength = 3,      ///< The length byte 0x80: BER, never DER.
  NonMinimalLength = 4,      ///< A length in more bytes than it needs.
  LengthTooLarge = 5,        ///< A length above `der::kMaxLength`, or a reserved length form.
  TrailingData = 6,          ///< Bytes after the last element where none may follow.
  TooDeep = 7,               ///< Nesting deeper than `der::kMaxDepth`.
  UnexpectedTag = 8,         ///< Another tag than the structure needs.
  BadInteger = 9,            ///< An empty, non-minimal, negative or too large INTEGER.
  BadBoolean = 10,           ///< A BOOLEAN that is not one byte 0x00 or 0xFF.
  BadBitString = 11,         ///< A BIT STRING with a bad unused-bit count or a non-zero pad bit.
  BadOid = 12,               ///< An OBJECT IDENTIFIER that is empty, too long or not minimal.
  BadString = 13,            ///< A string type the layer does not accept, or a bad character.
  BadTime = 14,              ///< A UTCTime or GeneralizedTime that is not of the RFC 5280 form.
  BadNull = 15,              ///< A NULL with content.
  UnsupportedVersion = 16,   ///< A certificate that is not X.509 v3, or a CSR that is not v1.
  UnsupportedAlgorithm = 17, ///< A signature or key algorithm this layer does not handle.
  UnsupportedCurve = 18,     ///< An EC public key on another curve than P-256 or P-384.
  BadPublicKey = 19,         ///< A public key of the wrong length or form (compressed, no 04).
  AlgorithmMismatch = 20,    ///< The two signature algorithms differ, or key and hash do not pair.
  UnknownCriticalExtension = 21, ///< A critical extension this layer does not process.
  DuplicateExtension = 22,       ///< The same extension twice.
  BadExtension = 23,             ///< An extension whose value does not parse.
  UniqueIdPresent = 24,          ///< An issuerUniqueID or subjectUniqueID (not supported).
  BadName = 25,                  ///< An empty issuer, or a Name that is not well formed.
  BadSignatureValue = 26,        ///< A signature value that is not a valid ECDSA-Sig-Value.
  NameMismatch = 27,             ///< A certificate's issuer is not its issuer's subject.
  SignatureInvalid = 28,         ///< A signature does not verify.
  NotYetValid = 29,              ///< The time is before notBefore.
  Expired = 30,                  ///< The time is after notAfter.
  NotCa = 31,                    ///< An issuing certificate without basicConstraints cA TRUE.
  KeyCertSignMissing = 32,       ///< An issuing certificate whose key usage lacks keyCertSign.
  PathLengthExceeded = 33,       ///< More intermediates than a pathLenConstraint allows.
  ChainTooLong = 34,             ///< More than `kMaxChain` certificates.
  NoTrustAnchor = 35,            ///< No trust anchor has the subject the chain needs.
  LeafKeyUsageMissing = 36,      ///< The end-entity certificate lacks a required key usage.
  LeafIsCa = 37,                 ///< The end-entity certificate is a CA and the options refuse it.
  CurveNotSupported = 38,        ///< The verifier cannot verify on this curve.
  CryptoFailure = 39,            ///< The crypto port or the verifier failed.
  NoTime = 40,                   ///< No time was given (0): the validity check cannot run.
  EmptyInput = 41,               ///< An empty chain, name or input where one is needed.
  BufferTooSmall = 42,           ///< The output buffer is too small.
  InvalidInput = 43,             ///< A builder argument is out of range (length, character set).
  TooManyEntries = 44,           ///< More attributes or alternative names than the builder holds.
  SignerFailed = 45,             ///< The signer (chip or port) failed.
  SignerOutputInvalid = 46,      ///< The signer returned a signature that does not parse.
  ObjectTooLarge = 47,           ///< A certificate that does not fit one WriteBinary command.
  PolicyAllowsWrite = 48,        ///< A storage policy that lets someone change the certificate.
  ReadBackMismatch = 49,         ///< The object read back differs from what was written.
  NotACertificate = 50,          ///< A stored object that is not exactly one certificate.
};

namespace detail {
/// Names of the reasons, indexed by value.
inline constexpr std::array<const char*, 51> kReasonNames{"Ok",
                                                          "Truncated",
                                                          "HighTagNumber",
                                                          "IndefiniteLength",
                                                          "NonMinimalLength",
                                                          "LengthTooLarge",
                                                          "TrailingData",
                                                          "TooDeep",
                                                          "UnexpectedTag",
                                                          "BadInteger",
                                                          "BadBoolean",
                                                          "BadBitString",
                                                          "BadOid",
                                                          "BadString",
                                                          "BadTime",
                                                          "BadNull",
                                                          "UnsupportedVersion",
                                                          "UnsupportedAlgorithm",
                                                          "UnsupportedCurve",
                                                          "BadPublicKey",
                                                          "AlgorithmMismatch",
                                                          "UnknownCriticalExtension",
                                                          "DuplicateExtension",
                                                          "BadExtension",
                                                          "UniqueIdPresent",
                                                          "BadName",
                                                          "BadSignatureValue",
                                                          "NameMismatch",
                                                          "SignatureInvalid",
                                                          "NotYetValid",
                                                          "Expired",
                                                          "NotCa",
                                                          "KeyCertSignMissing",
                                                          "PathLengthExceeded",
                                                          "ChainTooLong",
                                                          "NoTrustAnchor",
                                                          "LeafKeyUsageMissing",
                                                          "LeafIsCa",
                                                          "CurveNotSupported",
                                                          "CryptoFailure",
                                                          "NoTime",
                                                          "EmptyInput",
                                                          "BufferTooSmall",
                                                          "InvalidInput",
                                                          "TooManyEntries",
                                                          "SignerFailed",
                                                          "SignerOutputInvalid",
                                                          "ObjectTooLarge",
                                                          "PolicyAllowsWrite",
                                                          "ReadBackMismatch",
                                                          "NotACertificate"};
} // namespace detail

} // namespace se05x::pki

namespace se05x::detail {
/// Last enumerator of `pki::Reason`.
template <>
struct EnumLast<pki::Reason> {
  static constexpr pki::Reason kValue = pki::Reason::NotACertificate; ///< The last enumerator.
};
} // namespace se05x::detail

namespace se05x::pki {

/**
 * @brief The name of a reason, for logs.
 * @param reason The reason.
 * @return A static string such as `"Expired"`; `"Unknown"` for a value that is not an enumerator.
 */
constexpr const char* ToString(Reason reason) noexcept {
  if (!se05x::detail::IsEnumerator(reason)) {
    return "Unknown";
  }
  return detail::kReasonNames[static_cast<std::size_t>(se05x::detail::ToUnderlying(reason))];
}

/**
 * @brief The coarse `Error` of a reason (see the file comment).
 * @param reason The reason.
 * @return The error; `Error::Ok` for `Reason::Ok`.
 */
constexpr Error ErrorOf(Reason reason) noexcept {
  const auto v = static_cast<uint32_t>(se05x::detail::ToUnderlying(reason));
  Error error = Error::InvalidArgument;
  if (reason == Reason::Ok) {
    error = Error::Ok;
  } else if ((reason == Reason::UnsupportedVersion) || (reason == Reason::UnsupportedAlgorithm) ||
             (reason == Reason::UnsupportedCurve) || (reason == Reason::UnknownCriticalExtension) ||
             (reason == Reason::UniqueIdPresent) || (reason == Reason::CurveNotSupported) ||
             (reason == Reason::HighTagNumber)) {
    error = Error::Unsupported;
  } else if ((v >= static_cast<uint32_t>(Reason::NameMismatch)) &&
             (v <= static_cast<uint32_t>(Reason::LeafIsCa))) {
    error = Error::AttestationInvalid;
  } else if ((reason == Reason::BufferTooSmall) || (reason == Reason::ObjectTooLarge)) {
    error = Error::BufferTooSmall;
  } else if ((reason == Reason::CryptoFailure) || (reason == Reason::SignerFailed)) {
    error = Error::CryptoFailure;
  } else {
    error = Error::InvalidArgument;
  }
  return error;
}

/**
 * @brief The reason a PKI call failed.
 * @param detail The details of the failed `Result`.
 * @return The reason when the PKI layer failed the call; `Reason::Ok` when another layer did (the
 * device, the bus: read `Result::error` and `Detail` then) or for a value that is not a reason.
 */
constexpr Reason ReasonOf(const Detail& detail) noexcept {
  const auto last = static_cast<uint32_t>(se05x::detail::ToUnderlying(Reason::NotACertificate));
  if ((detail.layer != Layer::Pki) || (static_cast<uint32_t>(detail.step) > last)) {
    return Reason::Ok;
  }
  return static_cast<Reason>(detail.step);
}

/**
 * @brief A failed result of the PKI layer.
 * @tparam T The value type.
 * @param reason Why; never `Reason::Ok`.
 * @return `Result<T>::Failure(ErrorOf(reason))` with the reason in the details.
 */
template <typename T>
constexpr Result<T> Fail(Reason reason) noexcept {
  return Result<T>::Failure(ErrorOf(reason), Detail{.sw = static_cast<uint16_t>(0U),
                                                    .command = static_cast<uint8_t>(0xFFU),
                                                    .layer = Layer::Pki,
                                                    .step = static_cast<uint8_t>(reason),
                                                    .attempts_left = static_cast<uint8_t>(0xFFU)});
}

/** @brief The public key types of the layer. */
enum class KeyType : uint8_t {
  EcP256 = 0,  ///< NIST P-256 (prime256v1): an uncompressed point, 65 bytes `04 || X || Y`.
  EcP384 = 1,  ///< NIST P-384 (secp384r1): an uncompressed point, 97 bytes.
  Ed25519 = 2, ///< Ed25519 (RFC 8410): 32 bytes in RFC 8032 order.
};

/** @brief The signature algorithms of the layer. */
enum class SignatureAlgorithm : uint8_t {
  EcdsaSha256 = 0, ///< ecdsa-with-SHA256 (RFC 5758 3.2), with a P-256 key.
  EcdsaSha384 = 1, ///< ecdsa-with-SHA384 (RFC 5758 3.2), with a P-384 key.
  Ed25519 = 2,     ///< Ed25519, pure (RFC 8410 3): signs the whole message.
};

} // namespace se05x::pki

namespace se05x::detail {
/// Last enumerator of `pki::KeyType`.
template <>
struct EnumLast<pki::KeyType> {
  static constexpr pki::KeyType kValue = pki::KeyType::Ed25519; ///< The last enumerator.
};
/// Last enumerator of `pki::SignatureAlgorithm`.
template <>
struct EnumLast<pki::SignatureAlgorithm> {
  static constexpr pki::SignatureAlgorithm kValue =
      pki::SignatureAlgorithm::Ed25519; ///< The last enumerator.
};
} // namespace se05x::detail

namespace se05x::pki {

/**
 * @brief The length of a public key of a type.
 * @param type The key type.
 * @return 65, 97 or 32; 0 for a value that is not an enumerator.
 */
constexpr std::size_t PublicKeyLength(KeyType type) noexcept {
  std::size_t length = 0U;
  if (type == KeyType::EcP256) {
    length = 65U;
  } else if (type == KeyType::EcP384) {
    length = 97U;
  } else if (type == KeyType::Ed25519) {
    length = 32U;
  } else {
    length = 0U;
  }
  return length;
}

/**
 * @brief The only pairs of key and signature algorithm the layer signs and verifies with (RFC 5480
 * section 4 recommends these pairs; another pair is refused, never truncated silently).
 * @param type The key type.
 * @return The signature algorithm of that key type.
 */
constexpr SignatureAlgorithm AlgorithmFor(KeyType type) noexcept {
  SignatureAlgorithm algorithm = SignatureAlgorithm::EcdsaSha256;
  if (type == KeyType::EcP384) {
    algorithm = SignatureAlgorithm::EcdsaSha384;
  } else if (type == KeyType::Ed25519) {
    algorithm = SignatureAlgorithm::Ed25519;
  } else {
    algorithm = SignatureAlgorithm::EcdsaSha256;
  }
  return algorithm;
}

/**
 * @brief The digest length an ECDSA algorithm signs.
 * @param algorithm The algorithm.
 * @return 32 (SHA-256), 48 (SHA-384), 0 for Ed25519 (it signs the message).
 */
constexpr std::size_t DigestLength(SignatureAlgorithm algorithm) noexcept {
  std::size_t length = 0U;
  if (algorithm == SignatureAlgorithm::EcdsaSha256) {
    length = 32U;
  } else if (algorithm == SignatureAlgorithm::EcdsaSha384) {
    length = 48U;
  } else {
    length = 0U;
  }
  return length;
}

/** @brief A public key: its type and its bytes (the caller's buffer). */
struct PublicKey {
  KeyType type{KeyType::EcP256}; ///< The type.
  ByteSpan bytes;                ///< `PublicKeyLength(type)` bytes.
};

/** @brief The named bits of the keyUsage extension (RFC 5280 4.2.1.3): bit `i` is `1 << i`. */
namespace key_usage {
inline constexpr uint16_t kDigitalSignature = 0x0001U; ///< digitalSignature (0).
inline constexpr uint16_t kNonRepudiation = 0x0002U;   ///< nonRepudiation (contentCommitment, 1).
inline constexpr uint16_t kKeyEncipherment = 0x0004U;  ///< keyEncipherment (2).
inline constexpr uint16_t kDataEncipherment = 0x0008U; ///< dataEncipherment (3).
inline constexpr uint16_t kKeyAgreement = 0x0010U;     ///< keyAgreement (4).
inline constexpr uint16_t kKeyCertSign = 0x0020U;      ///< keyCertSign (5).
inline constexpr uint16_t kCrlSign = 0x0040U;          ///< cRLSign (6).
inline constexpr uint16_t kEncipherOnly = 0x0080U;     ///< encipherOnly (7).
inline constexpr uint16_t kDecipherOnly = 0x0100U;     ///< decipherOnly (8).
inline constexpr uint16_t kAll = 0x01FFU;              ///< Every named bit.
} // namespace key_usage

/**
 * @param have A set of key usage bits.
 * @param need The bits needed.
 * @return true when every bit of `need` is in `have`.
 */
constexpr bool HasBits(uint16_t have, uint16_t need) noexcept {
  const uint32_t n = need;
  return (static_cast<uint32_t>(have) & n) == n;
}

/** @brief A calendar time in UTC, to the second (RFC 5280 4.1.2.5). */
struct Time {
  uint16_t year{0};  ///< 1950 to 9999.
  uint8_t month{0};  ///< 1 to 12.
  uint8_t day{0};    ///< 1 to the length of the month.
  uint8_t hour{0};   ///< 0 to 23.
  uint8_t minute{0}; ///< 0 to 59.
  uint8_t second{0}; ///< 0 to 59 (RFC 5280 has no leap second).
};

/**
 * @param year A year.
 * @return true for a Gregorian leap year.
 */
constexpr bool IsLeapYear(uint32_t year) noexcept {
  return (((year % 4U) == 0U) && ((year % 100U) != 0U)) || ((year % 400U) == 0U);
}

/**
 * @param year The year.
 * @param month The month, 1 to 12.
 * @return The number of days of the month; 0 for a month out of range.
 */
constexpr uint32_t DaysInMonth(uint32_t year, uint32_t month) noexcept {
  constexpr std::array<uint8_t, 12> kDays{31U, 28U, 31U, 30U, 31U, 30U,
                                          31U, 31U, 30U, 31U, 30U, 31U};
  if ((month == 0U) || (month > 12U)) {
    return 0U;
  }
  const uint32_t extra = ((month == 2U) && IsLeapYear(year)) ? 1U : 0U;
  return static_cast<uint32_t>(kDays[month - 1U]) + extra;
}

/**
 * @param t A time.
 * @return true when every field is in range (years 1950 to 9999, the RFC 5280 span).
 */
constexpr bool IsValid(const Time& t) noexcept {
  return (t.year >= 1950U) && (t.year <= 9999U) && (t.month >= 1U) && (t.month <= 12U) &&
         (t.day >= 1U) && (t.day <= DaysInMonth(t.year, t.month)) && (t.hour <= 23U) &&
         (t.minute <= 59U) && (t.second <= 59U);
}

/**
 * @brief Seconds since 1970-01-01T00:00:00Z (Unix time) of a calendar time; the proleptic
 * Gregorian day count, no leap seconds.
 * @param t A valid time (`IsValid()`), 1970 or later.
 * @return The seconds; 0 for an invalid time or one before 1970.
 */
constexpr uint64_t ToUnixSeconds(const Time& t) noexcept {
  if (!IsValid(t) || (t.year < 1970U)) {
    return 0U;
  }
  uint64_t days = 0U;
  for (uint32_t y = 1970U; y < t.year; ++y) {
    days += IsLeapYear(y) ? 366U : 365U;
  }
  for (uint32_t m = 1U; m < t.month; ++m) {
    days += DaysInMonth(t.year, m);
  }
  days += static_cast<uint64_t>(t.day) - 1U;
  return (days * 86400U) + (static_cast<uint64_t>(t.hour) * 3600U) +
         (static_cast<uint64_t>(t.minute) * 60U) + t.second;
}

/**
 * @brief Compare two times.
 * @param a A valid time.
 * @param b A valid time.
 * @return -1, 0 or 1 as `a` is before, equal to or after `b`.
 */
constexpr int32_t Compare(const Time& a, const Time& b) noexcept {
  const std::array<uint32_t, 6> x{a.year, a.month, a.day, a.hour, a.minute, a.second};
  const std::array<uint32_t, 6> y{b.year, b.month, b.day, b.hour, b.minute, b.second};
  for (std::size_t i = 0U; i < x.size(); ++i) {
    if (x[i] != y[i]) {
      return (x[i] < y[i]) ? -1 : 1;
    }
  }
  return 0;
}

/**
 * @brief The content bytes of the object identifiers the layer writes and recognises (X.690 8.19;
 * the dotted form is in each comment).
 */
namespace oid {
/// id-ecPublicKey 1.2.840.10045.2.1 (RFC 5480 2.1.1).
inline constexpr std::array<uint8_t, 7> kEcPublicKey{0x2AU, 0x86U, 0x48U, 0xCEU,
                                                     0x3DU, 0x02U, 0x01U};
/// secp256r1 1.2.840.10045.3.1.7 (RFC 5480 2.1.1.1).
inline constexpr std::array<uint8_t, 8> kP256{0x2AU, 0x86U, 0x48U, 0xCEU,
                                              0x3DU, 0x03U, 0x01U, 0x07U};
/// secp384r1 1.3.132.0.34 (RFC 5480 2.1.1.1).
inline constexpr std::array<uint8_t, 5> kP384{0x2BU, 0x81U, 0x04U, 0x00U, 0x22U};
/// ecdsa-with-SHA256 1.2.840.10045.4.3.2 (RFC 5758 3.2).
inline constexpr std::array<uint8_t, 8> kEcdsaSha256{0x2AU, 0x86U, 0x48U, 0xCEU,
                                                     0x3DU, 0x04U, 0x03U, 0x02U};
/// ecdsa-with-SHA384 1.2.840.10045.4.3.3 (RFC 5758 3.2).
inline constexpr std::array<uint8_t, 8> kEcdsaSha384{0x2AU, 0x86U, 0x48U, 0xCEU,
                                                     0x3DU, 0x04U, 0x03U, 0x03U};
/// id-Ed25519 1.3.101.112 (RFC 8410 3).
inline constexpr std::array<uint8_t, 3> kEd25519{0x2BU, 0x65U, 0x70U};
/// commonName 2.5.4.3.
inline constexpr std::array<uint8_t, 3> kCommonName{0x55U, 0x04U, 0x03U};
/// serialNumber 2.5.4.5.
inline constexpr std::array<uint8_t, 3> kSerialNumber{0x55U, 0x04U, 0x05U};
/// countryName 2.5.4.6.
inline constexpr std::array<uint8_t, 3> kCountry{0x55U, 0x04U, 0x06U};
/// localityName 2.5.4.7.
inline constexpr std::array<uint8_t, 3> kLocality{0x55U, 0x04U, 0x07U};
/// stateOrProvinceName 2.5.4.8.
inline constexpr std::array<uint8_t, 3> kState{0x55U, 0x04U, 0x08U};
/// organizationName 2.5.4.10.
inline constexpr std::array<uint8_t, 3> kOrganization{0x55U, 0x04U, 0x0AU};
/// organizationalUnitName 2.5.4.11.
inline constexpr std::array<uint8_t, 3> kOrganizationalUnit{0x55U, 0x04U, 0x0BU};
/// pkcs-9-at-extensionRequest 1.2.840.113549.1.9.14 (RFC 2985 5.4.2).
inline constexpr std::array<uint8_t, 9> kExtensionRequest{0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U,
                                                          0x0DU, 0x01U, 0x09U, 0x0EU};
/// id-ce-subjectKeyIdentifier 2.5.29.14.
inline constexpr std::array<uint8_t, 3> kSubjectKeyId{0x55U, 0x1DU, 0x0EU};
/// id-ce-keyUsage 2.5.29.15.
inline constexpr std::array<uint8_t, 3> kKeyUsage{0x55U, 0x1DU, 0x0FU};
/// id-ce-subjectAltName 2.5.29.17.
inline constexpr std::array<uint8_t, 3> kSubjectAltName{0x55U, 0x1DU, 0x11U};
/// id-ce-basicConstraints 2.5.29.19.
inline constexpr std::array<uint8_t, 3> kBasicConstraints{0x55U, 0x1DU, 0x13U};
/// id-ce-authorityKeyIdentifier 2.5.29.35.
inline constexpr std::array<uint8_t, 3> kAuthorityKeyId{0x55U, 0x1DU, 0x23U};
/// id-ce-extKeyUsage 2.5.29.37.
inline constexpr std::array<uint8_t, 3> kExtKeyUsage{0x55U, 0x1DU, 0x25U};
} // namespace oid

/// Most certificates in a chain, end entity included, trust anchor excluded.
inline constexpr std::size_t kMaxChain = 6U;
/// Most trust anchors one verification searches.
inline constexpr std::size_t kMaxAnchors = 8U;
/// Most attributes of a `Name` the builder holds (one per relative distinguished name).
inline constexpr std::size_t kMaxNameAttributes = 8U;
/// Most entries of a subjectAltName the builder holds.
inline constexpr std::size_t kMaxAltNames = 8U;
/// Longest attribute value the builder writes (RFC 5280 Appendix A: ub-common-name 64, and the
/// other upper bounds of the attributes it writes are 64 or 128).
inline constexpr std::size_t kMaxAttributeValue = 128U;
/// Longest alternative name the builder writes (a DNS name is at most 253 bytes, RFC 1035 2.3.4).
inline constexpr std::size_t kMaxAltNameValue = 253U;
/// Longest DER signature value of the algorithms of the layer (P-384: 2 x (2 + 49) + 3 = 105).
inline constexpr std::size_t kMaxSignatureDer = 105U;
/// Longest raw signature (`r || s` of P-384).
inline constexpr std::size_t kMaxRawSignature = 96U;
/// Longest digest the layer computes (SHA-384).
inline constexpr std::size_t kMaxDigest = 48U;

/** @} */

} // namespace se05x::pki

#endif // SE05X_PKI_TYPES_HPP
