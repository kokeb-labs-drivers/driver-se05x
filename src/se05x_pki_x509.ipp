/**
 * @file se05x_pki_x509.ipp
 * @brief The X.509 parser, included by `se05x_pki_x509.hpp`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#ifndef SE05X_PKI_X509_IPP
#define SE05X_PKI_X509_IPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace se05x::pki {

namespace detail {

/// Most relative distinguished names of one Name.
inline constexpr std::size_t kMaxRdns = 16U;
/// Most attributes of one relative distinguished name.
inline constexpr std::size_t kMaxRdnAttributes = 4U;
/// Most entries of a GeneralNames or an ExtKeyUsageSyntax.
inline constexpr std::size_t kMaxListEntries = 16U;
/// Longest serial number (RFC 5280 4.1.2.2).
inline constexpr std::size_t kMaxSerial = 20U;
/// The first year that GeneralizedTime encodes (RFC 5280 4.1.2.5).
inline constexpr uint16_t kGeneralizedFrom = 2050U;

/**
 * @brief Check one attribute value of a Name.
 * @param element The value.
 * @return `Ok` or `BadString`.
 */
inline Reason CheckAttributeValue(const der::Element& element) noexcept {
  if (element.value.empty()) {
    return Reason::BadString;
  }
  switch (element.tag) {
  case der::kUtf8String:
    return der::CheckUtf8(element.value);
  case der::kPrintableString:
    return der::CheckPrintable(element.value);
  case der::kIa5String:
    return der::CheckIa5(element.value);
  default:
    break;
  }
  return Reason::BadString; // TeletexString, BMPString, UniversalString, ...: not accepted
}

/**
 * @brief Check one relative distinguished name (a non-empty SET of AttributeTypeAndValue).
 * @param rdn The SET's reader.
 * @return `Ok` or why not.
 */
inline Reason CheckRdn(der::Reader& rdn) noexcept {
  if (rdn.AtEnd()) {
    return Reason::BadName;
  }
  for (std::size_t i = 0U; !rdn.AtEnd(); ++i) {
    der::Reader atv{};
    der::Element type{};
    der::Element value{};
    if (i >= kMaxRdnAttributes) {
      return Reason::BadName;
    }
    Reason r = rdn.ExpectEnter(der::kSequence, atv);
    r = (r == Reason::Ok) ? atv.Expect(der::kOid, type) : r;
    r = (r == Reason::Ok) ? der::CheckOid(type.value) : r;
    r = (r == Reason::Ok) ? atv.Next(value) : r;
    r = (r == Reason::Ok) ? CheckAttributeValue(value) : r;
    r = (r == Reason::Ok) ? atv.Finish() : r;
    if (r != Reason::Ok) {
      return r;
    }
  }
  return Reason::Ok;
}

/**
 * @brief The width of r and s of an ECDSA algorithm.
 * @param algorithm The algorithm.
 * @return 32, 48, or 0 for Ed25519.
 */
constexpr std::size_t ScalarWidth(SignatureAlgorithm algorithm) noexcept {
  return DigestLength(algorithm);
}

/**
 * @brief Read the validity (RFC 5280 4.1.2.5).
 * @param tbs The TBSCertificate reader.
 * @param cert Receives the times.
 * @return `Ok` or why not.
 */
inline Reason ParseValidity(der::Reader& tbs, Certificate& cert) noexcept {
  der::Reader validity{};
  Reason r = tbs.ExpectEnter(der::kSequence, validity);
  std::array<Time, 2> times{};
  for (std::size_t i = 0U; (r == Reason::Ok) && (i < times.size()); ++i) {
    der::Element e{};
    r = validity.Next(e);
    r = (r == Reason::Ok) ? der::ParseTime(e, times[i]) : r;
    // Dates through 2049 are UTCTime, from 2050 GeneralizedTime: no other form.
    const bool generalized = (e.tag == der::kGeneralizedTime);
    if ((r == Reason::Ok) && (generalized != (times[i].year >= kGeneralizedFrom))) {
      r = Reason::BadTime;
    }
  }
  r = (r == Reason::Ok) ? validity.Finish() : r;
  if ((r == Reason::Ok) && (Compare(times[0], times[1]) > 0)) {
    r = Reason::BadTime; // notAfter before notBefore
  }
  if (r == Reason::Ok) {
    cert.not_before = times[0];
    cert.not_after = times[1];
  }
  return r;
}

/**
 * @brief Read the extnValue of basicConstraints (RFC 5280 4.2.1.9).
 * @param value The DER inside the OCTET STRING.
 * @param cert Receives the constraints.
 * @return `Ok` or `BadExtension`.
 */
inline Reason ParseBasicConstraints(ByteSpan value, Certificate& cert) noexcept {
  der::Reader outer(value, der::kMaxDepth - 1U);
  der::Reader seq{};
  if ((outer.ExpectEnter(der::kSequence, seq) != Reason::Ok) || (outer.Finish() != Reason::Ok)) {
    return Reason::BadExtension;
  }
  der::Element e{};
  bool ca = false;
  if (seq.Peek(der::kBoolean)) {
    // DEFAULT FALSE: DER leaves a default value out (X.690 11.5), so a present one is TRUE.
    if ((seq.Next(e) != Reason::Ok) || (der::ParseBoolean(e.value, ca) != Reason::Ok) || !ca) {
      return Reason::BadExtension;
    }
  }
  uint8_t path = kNoPathLength;
  if (seq.Peek(der::kInteger)) {
    uint32_t v = 0U;
    // A pathLenConstraint only on a CA (4.2.1.9), at most 254 here (255 marks "absent").
    if (!ca || (seq.Next(e) != Reason::Ok) || (der::ParseSmall(e.value, 254U, v) != Reason::Ok)) {
      return Reason::BadExtension;
    }
    path = static_cast<uint8_t>(v & 0xFFU);
  }
  if (seq.Finish() != Reason::Ok) {
    return Reason::BadExtension;
  }
  cert.has_basic_constraints = true;
  cert.is_ca = ca;
  cert.path_length = path;
  return Reason::Ok;
}

/**
 * @brief Check one GeneralName: a context tag 0 to 8; rfc822Name, dNSName and URI are non-empty
 * IA5String, an iPAddress is a primitive of 4 or 16 bytes.
 * @param e The name.
 * @return `Ok` or `BadExtension`.
 */
inline Reason CheckGeneralName(const der::Element& e) noexcept {
  const auto number = static_cast<uint8_t>(e.tag & 0x1FU);
  if (((e.tag & der::kContext) != der::kContext) || (number > 8U)) {
    return Reason::BadExtension;
  }
  const bool text = (e.tag == der::ContextPrimitive(1U)) || (e.tag == der::ContextPrimitive(2U)) ||
                    (e.tag == der::ContextPrimitive(6U));
  if (text && (e.value.empty() || (der::CheckIa5(e.value) != Reason::Ok))) {
    return Reason::BadExtension;
  }
  if ((number == 7U) && ((e.tag != der::ContextPrimitive(7U)) ||
                         ((e.value.size() != 4U) && (e.value.size() != 16U)))) {
    return Reason::BadExtension;
  }
  return Reason::Ok;
}

/**
 * @brief Check a GeneralNames (RFC 5280 4.2.1.6): a non-empty SEQUENCE of `CheckGeneralName()`.
 * @param value The DER inside the OCTET STRING.
 * @return `Ok` or `BadExtension`.
 */
inline Reason CheckGeneralNames(ByteSpan value) noexcept {
  der::Reader outer(value, der::kMaxDepth - 1U);
  der::Reader seq{};
  if ((outer.ExpectEnter(der::kSequence, seq) != Reason::Ok) || (outer.Finish() != Reason::Ok) ||
      seq.AtEnd()) {
    return Reason::BadExtension;
  }
  for (std::size_t i = 0U; !seq.AtEnd(); ++i) {
    der::Element e{};
    if ((i >= kMaxListEntries) || (seq.Next(e) != Reason::Ok) ||
        (CheckGeneralName(e) != Reason::Ok)) {
      return Reason::BadExtension;
    }
  }
  return Reason::Ok;
}

/**
 * @brief Check an ExtKeyUsageSyntax (RFC 5280 4.2.1.12): a non-empty SEQUENCE of OIDs.
 * @param value The DER inside the OCTET STRING.
 * @return `Ok` or `BadExtension`.
 */
inline Reason CheckOidList(ByteSpan value) noexcept {
  der::Reader outer(value, der::kMaxDepth - 1U);
  der::Reader seq{};
  if ((outer.ExpectEnter(der::kSequence, seq) != Reason::Ok) || (outer.Finish() != Reason::Ok) ||
      seq.AtEnd()) {
    return Reason::BadExtension;
  }
  for (std::size_t i = 0U; !seq.AtEnd(); ++i) {
    der::Element e{};
    if ((i >= kMaxListEntries) || (seq.Expect(der::kOid, e) != Reason::Ok) ||
        (der::CheckOid(e.value) != Reason::Ok)) {
      return Reason::BadExtension;
    }
  }
  return Reason::Ok;
}

/**
 * @brief The single element inside an extnValue.
 * @param value The OCTET STRING content.
 * @param tag The tag it must have.
 * @param out Receives it.
 * @return `Ok` or `BadExtension`.
 */
inline Reason SingleElement(ByteSpan value, uint8_t tag, der::Element& out) noexcept {
  der::Reader r(value, der::kMaxDepth - 1U);
  if ((r.Expect(tag, out) != Reason::Ok) || (r.Finish() != Reason::Ok)) {
    return Reason::BadExtension;
  }
  return Reason::Ok;
}

/**
 * @brief Apply one known extension.
 * @param id The extnID content.
 * @param critical The criticality.
 * @param value The extnValue content.
 * @param cert Receives what it says.
 * @param known Receives false for an extension this parser does not know.
 * @return `Ok` or `BadExtension`.
 */
inline Reason ApplyExtension(ByteSpan id, bool critical, ByteSpan value, Certificate& cert,
                             bool& known) noexcept {
  der::Element e{};
  Reason r = Reason::Ok;
  known = true;
  if (der::SameBytes(id, ByteSpan{oid::kBasicConstraints})) {
    r = ParseBasicConstraints(value, cert);
  } else if (der::SameBytes(id, ByteSpan{oid::kKeyUsage})) {
    r = SingleElement(value, der::kBitString, e);
    r = ((r == Reason::Ok) && (der::ParseNamedBits(e.value, cert.key_usage) == Reason::Ok) &&
         ((static_cast<uint32_t>(cert.key_usage) & ~static_cast<uint32_t>(key_usage::kAll)) == 0U))
            ? Reason::Ok
            : Reason::BadExtension;
    cert.has_key_usage = (r == Reason::Ok);
  } else if (der::SameBytes(id, ByteSpan{oid::kSubjectAltName})) {
    r = CheckGeneralNames(value);
    cert.subject_alt_names = value;
    cert.alt_names_critical = critical;
  } else if (der::SameBytes(id, ByteSpan{oid::kExtKeyUsage})) {
    r = CheckOidList(value);
    cert.ext_key_usage = value;
  } else if (der::SameBytes(id, ByteSpan{oid::kSubjectKeyId})) {
    r = SingleElement(value, der::kOctetString, e);
    cert.subject_key_id = e.value;
  } else if (der::SameBytes(id, ByteSpan{oid::kAuthorityKeyId})) {
    r = SingleElement(value, der::kSequence, e);
    cert.authority_key_id = value;
  } else {
    known = false;
  }
  return r;
}

/**
 * @brief Read one Extension (RFC 5280 4.1: extnID, critical DEFAULT FALSE, extnValue).
 * @param ext The Extension's reader.
 * @param id Receives the extnID content.
 * @param critical Receives the criticality.
 * @param value Receives the extnValue content.
 * @return `Ok` or why not.
 */
inline Reason ReadExtension(der::Reader& ext, ByteSpan& id, bool& critical,
                            ByteSpan& value) noexcept {
  der::Element e{};
  Reason r = ext.Expect(der::kOid, e);
  r = (r == Reason::Ok) ? der::CheckOid(e.value) : r;
  id = e.value;
  critical = false;
  if ((r == Reason::Ok) && ext.Peek(der::kBoolean)) {
    r = ext.Next(e);
    r = (r == Reason::Ok) ? der::ParseBoolean(e.value, critical) : r;
    if ((r == Reason::Ok) && !critical) {
      r = Reason::BadBoolean; // DER leaves out the default FALSE (X.690 11.5)
    }
  }
  r = (r == Reason::Ok) ? ext.Expect(der::kOctetString, e) : r;
  value = e.value;
  return (r == Reason::Ok) ? ext.Finish() : r;
}

/**
 * @brief Read the next Extension of the list and apply it.
 * @param list The Extensions reader.
 * @param seen The extnIDs read so far; the new one is stored at `n`.
 * @param n How many were read.
 * @param cert Receives what it says.
 * @return `Ok` or why not.
 */
inline Reason NextExtension(der::Reader& list, std::array<ByteSpan, kMaxExtensions>& seen,
                            std::size_t n, Certificate& cert) noexcept {
  der::Reader ext{};
  ByteSpan id{};
  ByteSpan value{};
  bool critical = false;
  bool known = false;
  Reason r = (n < seen.size()) ? list.ExpectEnter(der::kSequence, ext) : Reason::BadExtension;
  r = (r == Reason::Ok) ? ReadExtension(ext, id, critical, value) : r;
  for (std::size_t k = 0U; (r == Reason::Ok) && (k < n); ++k) {
    r = der::SameBytes(seen[k], id) ? Reason::DuplicateExtension : r;
  }
  if (r != Reason::Ok) {
    return r;
  }
  seen[n] = id;
  r = ApplyExtension(id, critical, value, cert, known);
  if ((r == Reason::Ok) && !known && critical) {
    r = Reason::UnknownCriticalExtension;
  }
  return r;
}

/**
 * @brief Read the extensions (`[3] EXPLICIT Extensions`, SIZE (1..MAX)).
 * @param tbs The TBSCertificate reader, at the `[3]` element.
 * @param cert Receives what they say.
 * @return `Ok` or why not.
 */
inline Reason ParseExtensions(der::Reader& tbs, Certificate& cert) noexcept {
  der::Reader wrap{};
  der::Reader list{};
  Reason r = tbs.ExpectEnter(der::ContextConstructed(3U), wrap);
  r = (r == Reason::Ok) ? wrap.ExpectEnter(der::kSequence, list) : r;
  r = (r == Reason::Ok) ? wrap.Finish() : r;
  if ((r == Reason::Ok) && list.AtEnd()) {
    r = Reason::BadExtension;
  }
  std::array<ByteSpan, kMaxExtensions> seen{};
  for (std::size_t n = 0U; (r == Reason::Ok) && !list.AtEnd(); ++n) {
    r = NextExtension(list, seen, n, cert);
  }
  return r;
}

/**
 * @brief Read the version: `[0] EXPLICIT INTEGER`, which must be 2 (v3).
 * @param tbs The TBSCertificate reader.
 * @return `Ok` or `UnsupportedVersion` (absent: a v1 certificate; another value), or a structure
 * reason.
 */
inline Reason ParseVersion(der::Reader& tbs) noexcept {
  der::Reader version{};
  der::Element e{};
  uint32_t v = 0U;
  if (!tbs.Peek(der::ContextConstructed(0U))) {
    return Reason::UnsupportedVersion; // a v1 certificate leaves the version out
  }
  Reason r = tbs.ExpectEnter(der::ContextConstructed(0U), version);
  r = (r == Reason::Ok) ? version.Expect(der::kInteger, e) : r;
  r = (r == Reason::Ok) ? der::ParseSmall(e.value, 0xFFU, v) : r;
  r = (r == Reason::Ok) ? version.Finish() : r;
  if ((r == Reason::Ok) && (v != 2U)) {
    r = Reason::UnsupportedVersion;
  }
  return r;
}

/**
 * @brief Read the serial number (RFC 5280 4.1.2.2: positive, at most 20 octets).
 * @param tbs The TBSCertificate reader.
 * @param cert Receives it.
 * @return `Ok` or `BadInteger`, or a structure reason.
 */
inline Reason ParseSerial(der::Reader& tbs, Certificate& cert) noexcept {
  der::Element e{};
  ByteSpan serial{};
  Reason r = tbs.Expect(der::kInteger, e);
  r = (r == Reason::Ok) ? der::ParseUnsigned(e.value, serial) : r;
  if ((r == Reason::Ok) &&
      ((serial.size() > kMaxSerial) || ((serial.size() == 1U) && (serial[0] == 0U)))) {
    r = Reason::BadInteger;
  }
  cert.serial = e.value;
  return r;
}

/**
 * @brief Read the start of a TBSCertificate: version, serial, signature, issuer.
 * @param tbs Its reader.
 * @param cert Receives the fields.
 * @param inner Receives the inner AlgorithmIdentifier.
 * @return `Ok` or why not.
 */
inline Reason ParseTbsHead(der::Reader& tbs, Certificate& cert, der::Element& inner) noexcept {
  der::Element e{};
  bool empty = false;
  Reason r = ParseVersion(tbs);
  r = (r == Reason::Ok) ? ParseSerial(tbs, cert) : r;
  r = (r == Reason::Ok) ? tbs.Expect(der::kSequence, inner) : r;
  r = (r == Reason::Ok) ? ParseSignatureAlgorithm(inner, cert.signature_algorithm) : r;
  r = (r == Reason::Ok) ? tbs.Expect(der::kSequence, e) : r;
  r = (r == Reason::Ok) ? CheckName(e.encoded, empty) : r;
  if ((r == Reason::Ok) && empty) {
    r = Reason::BadName; // RFC 5280 4.1.2.4: the issuer is not empty
  }
  cert.issuer = e.encoded;
  return r;
}

/**
 * @param tbs A TBSCertificate reader after the key.
 * @return true when an issuerUniqueID or subjectUniqueID follows (in either form).
 */
inline bool HasUniqueId(const der::Reader& tbs) noexcept {
  return tbs.Peek(der::ContextPrimitive(1U)) || tbs.Peek(der::ContextPrimitive(2U)) ||
         tbs.Peek(der::ContextConstructed(1U)) || tbs.Peek(der::ContextConstructed(2U));
}

/**
 * @brief Read the rest of a TBSCertificate: validity, subject, key, unique ids, extensions.
 * @param tbs Its reader.
 * @param cert Receives the fields.
 * @return `Ok` or why not.
 */
inline Reason ParseTbsTail(der::Reader& tbs, Certificate& cert) noexcept {
  der::Element e{};
  bool empty = false;
  Reason r = ParseValidity(tbs, cert);
  r = (r == Reason::Ok) ? tbs.Expect(der::kSequence, e) : r;
  r = (r == Reason::Ok) ? CheckName(e.encoded, empty) : r;
  cert.subject = e.encoded;
  r = (r == Reason::Ok) ? tbs.Expect(der::kSequence, e) : r;
  r = (r == Reason::Ok) ? ParsePublicKeyInfo(e, cert.public_key) : r;
  if ((r == Reason::Ok) && HasUniqueId(tbs)) {
    r = Reason::UniqueIdPresent;
  }
  if ((r == Reason::Ok) && !tbs.AtEnd()) {
    r = ParseExtensions(tbs, cert);
  }
  r = (r == Reason::Ok) ? tbs.Finish() : r;
  const bool named = !empty || (!cert.subject_alt_names.empty() && cert.alt_names_critical);
  if ((r == Reason::Ok) && !named) {
    r = Reason::BadName; // RFC 5280 4.1.2.6: an empty subject needs a critical subjectAltName
  }
  return r;
}

} // namespace detail

inline Reason CheckName(ByteSpan name, bool& empty) noexcept {
  der::Reader outer(name, der::kMaxDepth - 3U);
  der::Reader rdns{};
  Reason r = outer.ExpectEnter(der::kSequence, rdns);
  r = (r == Reason::Ok) ? outer.Finish() : r;
  if (r != Reason::Ok) {
    return (r == Reason::UnexpectedTag) ? Reason::BadName : r;
  }
  empty = rdns.AtEnd();
  for (std::size_t i = 0U; !rdns.AtEnd(); ++i) {
    der::Reader rdn{};
    r = (i < detail::kMaxRdns) ? rdns.ExpectEnter(der::kSet, rdn) : Reason::BadName;
    r = (r == Reason::Ok) ? detail::CheckRdn(rdn) : r;
    if (r != Reason::Ok) {
      return r;
    }
  }
  return Reason::Ok;
}

inline Reason ParseSignatureAlgorithm(const der::Element& element,
                                      SignatureAlgorithm& out) noexcept {
  der::Reader outer(element.encoded, der::kMaxDepth - 2U);
  der::Reader seq{};
  der::Element id{};
  Reason r = outer.ExpectEnter(der::kSequence, seq);
  r = (r == Reason::Ok) ? seq.Expect(der::kOid, id) : r;
  r = (r == Reason::Ok) ? der::CheckOid(id.value) : r;
  if (r != Reason::Ok) {
    return r;
  }
  if (der::SameBytes(id.value, ByteSpan{oid::kEcdsaSha256})) {
    out = SignatureAlgorithm::EcdsaSha256;
  } else if (der::SameBytes(id.value, ByteSpan{oid::kEcdsaSha384})) {
    out = SignatureAlgorithm::EcdsaSha384;
  } else if (der::SameBytes(id.value, ByteSpan{oid::kEd25519})) {
    out = SignatureAlgorithm::Ed25519;
  } else {
    return Reason::UnsupportedAlgorithm;
  }
  // RFC 5758 3.2 and RFC 8410 3: the parameters are absent (a NULL is refused too).
  return (seq.Finish() == Reason::Ok) ? Reason::Ok : Reason::UnsupportedAlgorithm;
}

namespace detail {
/**
 * @brief Read the AlgorithmIdentifier of a key (RFC 5480 2.1.1: id-ecPublicKey with a namedCurve;
 * RFC 8410 3: id-Ed25519 without parameters).
 * @param alg Its reader.
 * @param type Receives the key type.
 * @return `Ok`, `UnsupportedAlgorithm`, `UnsupportedCurve`, or a structure reason.
 */
inline Reason ParseKeyAlgorithm(der::Reader& alg, KeyType& type) noexcept {
  der::Element id{};
  der::Element curve{};
  Reason r = alg.Expect(der::kOid, id);
  r = (r == Reason::Ok) ? der::CheckOid(id.value) : r;
  if (r != Reason::Ok) {
    return r;
  }
  if (der::SameBytes(id.value, ByteSpan{oid::kEd25519})) {
    type = KeyType::Ed25519;
  } else if (!der::SameBytes(id.value, ByteSpan{oid::kEcPublicKey})) {
    return Reason::UnsupportedAlgorithm;
  } else if (alg.Expect(der::kOid, curve) != Reason::Ok) {
    return Reason::UnsupportedCurve; // implicitCurve and specifiedCurve are not allowed
  } else if (der::SameBytes(curve.value, ByteSpan{oid::kP256})) {
    type = KeyType::EcP256;
  } else if (der::SameBytes(curve.value, ByteSpan{oid::kP384})) {
    type = KeyType::EcP384;
  } else {
    return Reason::UnsupportedCurve;
  }
  return alg.Finish();
}
} // namespace detail

inline Reason ParsePublicKeyInfo(const der::Element& element, PublicKey& out) noexcept {
  der::Reader outer(element.encoded, der::kMaxDepth - 3U);
  der::Reader spki{};
  der::Reader alg{};
  der::Element e{};
  KeyType type = KeyType::EcP256;
  ByteSpan key{};
  Reason r = outer.ExpectEnter(der::kSequence, spki);
  r = (r == Reason::Ok) ? spki.ExpectEnter(der::kSequence, alg) : r;
  r = (r == Reason::Ok) ? detail::ParseKeyAlgorithm(alg, type) : r;
  r = (r == Reason::Ok) ? spki.Expect(der::kBitString, e) : r;
  r = (r == Reason::Ok) ? der::ParseOctetBits(e.value, key) : r;
  r = (r == Reason::Ok) ? spki.Finish() : r;
  const bool ec = (type != KeyType::Ed25519);
  if ((r == Reason::Ok) && ((key.size() != PublicKeyLength(type)) || (ec && (key[0] != 0x04U)))) {
    r = Reason::BadPublicKey; // RFC 5480 2.2: the uncompressed form only
  }
  if (r == Reason::Ok) {
    out = PublicKey{.type = type, .bytes = key};
  }
  return r;
}

inline Reason CheckSignatureValue(SignatureAlgorithm algorithm, ByteSpan signature) noexcept {
  if (algorithm == SignatureAlgorithm::Ed25519) {
    return (signature.size() == 64U) ? Reason::Ok : Reason::BadSignatureValue;
  }
  std::array<uint8_t, kMaxRawSignature> raw{};
  return der::ParseEcdsaSignature(signature, detail::ScalarWidth(algorithm), MutableByteSpan{raw});
}

namespace detail {
/**
 * @brief The shape check of a certificate's signature at parse time: the issuer's curve is not
 * known yet, so the integers may be as wide as the widest curve (P-384); `VerifySigned()` checks
 * the exact width.
 * @param algorithm The algorithm.
 * @param signature The signature bytes.
 * @return `Ok` or `BadSignatureValue`.
 */
inline Reason CheckSignatureShape(SignatureAlgorithm algorithm, ByteSpan signature) noexcept {
  if (algorithm == SignatureAlgorithm::Ed25519) {
    return CheckSignatureValue(algorithm, signature);
  }
  std::array<uint8_t, kMaxRawSignature> raw{};
  return der::ParseEcdsaSignature(signature, kMaxRawSignature / 2U, MutableByteSpan{raw});
}
} // namespace detail

inline Result<Certificate> ParseCertificate(ByteSpan der) noexcept {
  Certificate cert{};
  der::Reader input(der);
  der::Reader top{};
  der::Reader tbs{};
  der::Element tbs_element{};
  der::Element inner{};
  der::Element outer_alg{};
  der::Element sig{};
  Reason r = input.ExpectEnter(der::kSequence, top);
  r = (r == Reason::Ok) ? input.Finish() : r;
  r = (r == Reason::Ok) ? top.Expect(der::kSequence, tbs_element) : r;
  r = (r == Reason::Ok) ? top.Enter(tbs_element, tbs) : r;
  r = (r == Reason::Ok) ? detail::ParseTbsHead(tbs, cert, inner) : r;
  r = (r == Reason::Ok) ? detail::ParseTbsTail(tbs, cert) : r;
  r = (r == Reason::Ok) ? top.Expect(der::kSequence, outer_alg) : r;
  if ((r == Reason::Ok) && !der::SameBytes(outer_alg.encoded, inner.encoded)) {
    r = Reason::AlgorithmMismatch; // RFC 5280 4.1.1.2: the same algorithm in both places
  }
  r = (r == Reason::Ok) ? top.Expect(der::kBitString, sig) : r;
  r = (r == Reason::Ok) ? der::ParseOctetBits(sig.value, cert.signature) : r;
  r = (r == Reason::Ok) ? top.Finish() : r;
  r = (r == Reason::Ok) ? detail::CheckSignatureShape(cert.signature_algorithm, cert.signature) : r;
  if (r != Reason::Ok) {
    return Fail<Certificate>(r);
  }
  cert.der = der;
  cert.tbs = tbs_element.encoded;
  return Result<Certificate>::Success(cert);
}

} // namespace se05x::pki

#endif // SE05X_PKI_X509_IPP
