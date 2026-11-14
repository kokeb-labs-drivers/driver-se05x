/**
 * @file se05x_pki_x509.hpp
 * @brief A minimal, strict X.509 v3 certificate parser (an RFC 5280 subset) for the PKI layer.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * `ParseCertificate()` reads one DER certificate into a `Certificate` of
 * views into the caller's bytes (nothing is copied, nothing allocates). It accepts what a device
 * certificate chain needs and refuses the rest with a `Reason`, never by ignoring it:
 *
 * | Accepted | Refused |
 * | --- | --- |
 * | version 3 (RFC 5280 4.1.2.1) | v1 and v2 (`UnsupportedVersion`) |
 * | serial: positive, at most 20 octets (4.1.2.2) | zero, negative, longer (`BadInteger`) |
 * | ecdsa-with-SHA256 / -SHA384 without parameters (RFC 5758 3.2), Ed25519 (RFC 8410 3) | any other
 * algorithm (`UnsupportedAlgorithm`); the inner and outer algorithm differing
 * (`AlgorithmMismatch`, 4.1.1.2) | | keys: P-256, P-384 uncompressed (RFC 5480 2), Ed25519 (RFC
 * 8410 4) | other curves (`UnsupportedCurve`), compressed points (`BadPublicKey`) | | names of
 * UTF8String, PrintableString, IA5String values | other string types (`BadString`); an empty issuer
 * (`BadName`, 4.1.2.4); an empty subject without a critical subjectAltName (`BadName`, 4.1.2.6) |
 * | UTCTime through 2049, GeneralizedTime from 2050, both `Z` to the second (4.1.2.5) | any other
 * form (`BadTime`) | | basicConstraints, keyUsage, subjectAltName, extKeyUsage,
 * subjectKeyIdentifier, authorityKeyIdentifier; other extensions when not critical (4.2) | an
 * unknown critical extension (`UnknownCriticalExtension`); a duplicate (`DuplicateExtension`);
 * unique ids (`UniqueIdPresent`) |
 *
 * The parser checks the encoding and the profile; it does not check a signature, a time or a
 * chain: that is `VerifyChain()` (`se05x_pki_verify.hpp`). Names are compared byte for byte there
 * (a stricter rule than RFC 5280 7.1, which a chain from one issuer meets).
 */
#ifndef SE05X_PKI_X509_HPP
#define SE05X_PKI_X509_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "se05x_pki_der.hpp"
#include "se05x_pki_types.hpp"
#include "se05x_status.hpp"
#include "se05x_types.hpp"

namespace se05x::pki {

/**
 * @defgroup se05x_pki_x509 X.509
 * @brief The certificate parser.
 * @{
 */

/// `Certificate::path_length` when the certificate has no pathLenConstraint.
inline constexpr uint8_t kNoPathLength = 0xFFU;
/// Most extensions of one certificate the parser reads.
inline constexpr std::size_t kMaxExtensions = 16U;

/** @brief A parsed certificate: views into the DER the caller keeps. */
struct Certificate {
  ByteSpan der;      ///< The whole certificate.
  ByteSpan tbs;      ///< The encoded TBSCertificate: what the issuer signed.
  ByteSpan serial;   ///< The serial number's content octets.
  ByteSpan issuer;   ///< The encoded issuer Name.
  ByteSpan subject;  ///< The encoded subject Name (`30 00` when empty).
  Time not_before{}; ///< Start of validity.
  Time not_after{};  ///< End of validity.
  SignatureAlgorithm signature_algorithm{SignatureAlgorithm::EcdsaSha256}; ///< How it is signed.
  ByteSpan signature;     ///< The ECDSA-Sig-Value (DER), or the 64-byte Ed25519 signature.
  PublicKey public_key{}; ///< The subject's public key.
  bool has_basic_constraints{false};  ///< basicConstraints present.
  bool is_ca{false};                  ///< basicConstraints cA is TRUE.
  uint8_t path_length{kNoPathLength}; ///< pathLenConstraint, `kNoPathLength` when absent.
  bool has_key_usage{false};          ///< keyUsage present.
  uint16_t key_usage{0};              ///< keyUsage bits (`key_usage::`), 0 when absent.
  ByteSpan subject_alt_names;         ///< The encoded GeneralNames, empty when absent.
  bool alt_names_critical{false};     ///< subjectAltName is critical.
  ByteSpan ext_key_usage;             ///< The encoded ExtKeyUsageSyntax, empty when absent.
  ByteSpan subject_key_id;            ///< subjectKeyIdentifier content, empty when absent.
  ByteSpan authority_key_id;          ///< The encoded AuthorityKeyIdentifier, empty when absent.
};

/**
 * @brief Parse one DER certificate; nothing may follow it.
 * @param der The certificate; the result points into it.
 * @return The certificate, or a failure whose `ReasonOf()` names the first rule it breaks.
 */
Result<Certificate> ParseCertificate(ByteSpan der) noexcept;

/**
 * @brief Check an encoded Name (RFC 5280 4.1.2.4: a SEQUENCE of non-empty SETs of
 * AttributeTypeAndValue whose values are UTF8String, PrintableString or IA5String).
 * @param name The whole encoded Name.
 * @param empty Receives true for the empty name `30 00`.
 * @return `Ok`, or why the name is refused.
 */
Reason CheckName(ByteSpan name, bool& empty) noexcept;

/**
 * @brief Read an AlgorithmIdentifier of a signature.
 * @param element The AlgorithmIdentifier element.
 * @param out Receives the algorithm.
 * @return `Ok`, `UnsupportedAlgorithm`, or a structure reason (parameters present: `BadOid`).
 */
Reason ParseSignatureAlgorithm(const der::Element& element, SignatureAlgorithm& out) noexcept;

/**
 * @brief Read a SubjectPublicKeyInfo (RFC 5480 2, RFC 8410 4).
 * @param element The SubjectPublicKeyInfo element.
 * @param out Receives the key; its bytes point into `element`.
 * @return `Ok`, `UnsupportedAlgorithm`, `UnsupportedCurve`, `BadPublicKey`, or a structure reason.
 */
Reason ParsePublicKeyInfo(const der::Element& element, PublicKey& out) noexcept;

/**
 * @brief Check a signature value against its algorithm: an ECDSA-Sig-Value whose integers fit the
 * curve of the algorithm, or 64 bytes for Ed25519.
 * @param algorithm The algorithm.
 * @param signature The signature bytes (the content of the BIT STRING).
 * @return `Ok` or `BadSignatureValue`.
 */
Reason CheckSignatureValue(SignatureAlgorithm algorithm, ByteSpan signature) noexcept;

/** @} */

} // namespace se05x::pki

// codeql::misra_deviation_next_line(MD-CPP-009)
#include "../src/se05x_pki_x509.ipp" // IWYU pragma: export

#endif // SE05X_PKI_X509_HPP
