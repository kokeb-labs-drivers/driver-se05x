/**
 * @file se05x_pki_csr.hpp
 * @brief PKCS#10 certification requests (RFC 2986) signed by a key that never leaves the chip or
 * the crypto port: subject name and subjectAltName builders, `BuildCsr()`, `VerifyCsr()`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * The request is
 *
 *     CertificationRequest ::= SEQUENCE {
 *       certificationRequestInfo SEQUENCE { version 0, subject Name, subjectPKInfo,
 *                                           [0] attributes (extensionRequest, RFC 2985 5.4.2) },
 *       signatureAlgorithm, signature BIT STRING }
 *
 * The signer (`CsrSigner`) gets the SHA-256 or SHA-384 digest of the info for ECDSA, or the info
 * itself for Ed25519, and returns the signature; the private key stays where it is (the chip:
 * `DeviceSigner` in `se05x_pki_device.hpp`; the crypto port: `PortSigner`). The builder checks the
 * signature it gets back parses before it writes it, and `VerifyCsr()` checks the whole request
 * against its own public key, which catches a key id that does not belong to the public key given.
 *
 * Names are written with UTF8String values (RFC 5280 4.1.2.6), except countryName and
 * serialNumber, which X.520 makes PrintableString. Attribute values are bytes (UTF-8): the layer
 * never converts characters; `Name::AddHex()` writes bytes (the chip's unique id) as upper-case
 * hex.
 */
#ifndef SE05X_PKI_CSR_HPP
#define SE05X_PKI_CSR_HPP

#include <algorithm>
#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>

#include "se05x_pki_der.hpp"
#include "se05x_pki_types.hpp"
#include "se05x_pki_verify.hpp"
#include "se05x_pki_x509.hpp"
#include "se05x_ports.hpp"
#include "se05x_status.hpp"
#include "se05x_types.hpp"

namespace se05x::pki {

/**
 * @defgroup se05x_pki_csr Certification requests
 * @brief Name builders, signers, `BuildCsr()` and `VerifyCsr()`.
 * @{
 */

/** @brief The attributes `Name` writes (X.520, RFC 5280 4.1.2.4). */
enum class Attribute : uint8_t {
  CommonName = 0,         ///< commonName, UTF8String, 1 to 64 bytes.
  SerialNumber = 1,       ///< serialNumber, PrintableString, 1 to 64 bytes.
  Country = 2,            ///< countryName, PrintableString, two upper-case letters (ISO 3166).
  Locality = 3,           ///< localityName, UTF8String, 1 to 128 bytes.
  State = 4,              ///< stateOrProvinceName, UTF8String, 1 to 128 bytes.
  Organization = 5,       ///< organizationName, UTF8String, 1 to 64 bytes.
  OrganizationalUnit = 6, ///< organizationalUnitName, UTF8String, 1 to 64 bytes.
};

/** @brief The alternative name types `AltNames` writes (RFC 5280 4.2.1.6). */
enum class AltNameType : uint8_t {
  Dns = 0,   ///< dNSName `[2]`, IA5String.
  Uri = 1,   ///< uniformResourceIdentifier `[6]`, IA5String.
  Email = 2, ///< rfc822Name `[1]`, IA5String.
  Ip = 3,    ///< iPAddress `[7]`, 4 or 16 bytes.
};

} // namespace se05x::pki

namespace se05x::detail {
/// Last enumerator of `pki::Attribute`.
template <>
struct EnumLast<pki::Attribute> {
  static constexpr pki::Attribute kValue = pki::Attribute::OrganizationalUnit; ///< The last.
};
/// Last enumerator of `pki::AltNameType`.
template <>
struct EnumLast<pki::AltNameType> {
  static constexpr pki::AltNameType kValue = pki::AltNameType::Ip; ///< The last enumerator.
};
} // namespace se05x::detail

namespace se05x::pki {

/// Most input bytes of `Name::AddHex()` (the 18-byte unique id fits).
inline constexpr std::size_t kMaxHexInput = 32U;

namespace detail {

/**
 * @brief The object identifier and the length limit of an attribute.
 * @param attribute The attribute.
 * @param max Receives the longest value.
 * @return The identifier's content octets.
 */
constexpr ByteSpan AttributeOid(Attribute attribute, std::size_t& max) noexcept {
  ByteSpan id{};
  max = 64U;
  if (attribute == Attribute::CommonName) {
    id = ByteSpan{oid::kCommonName};
  } else if (attribute == Attribute::SerialNumber) {
    id = ByteSpan{oid::kSerialNumber};
  } else if (attribute == Attribute::Country) {
    id = ByteSpan{oid::kCountry};
    max = 2U;
  } else if (attribute == Attribute::Locality) {
    id = ByteSpan{oid::kLocality};
    max = kMaxAttributeValue;
  } else if (attribute == Attribute::State) {
    id = ByteSpan{oid::kState};
    max = kMaxAttributeValue;
  } else if (attribute == Attribute::Organization) {
    id = ByteSpan{oid::kOrganization};
  } else if (attribute == Attribute::OrganizationalUnit) {
    id = ByteSpan{oid::kOrganizationalUnit};
  } else {
    max = 0U;
  }
  return id;
}

/**
 * @brief Check an attribute value.
 * @param attribute The attribute.
 * @param value The bytes.
 * @return `Ok` or `InvalidInput`.
 */
constexpr Reason CheckAttribute(Attribute attribute, ByteSpan value) noexcept {
  std::size_t max = 0U;
  static_cast<void>(AttributeOid(attribute, max));
  if (value.empty() || (value.size() > max)) {
    return Reason::InvalidInput;
  }
  Reason r = Reason::Ok;
  if (attribute == Attribute::Country) {
    const auto upper = [](uint8_t b) noexcept { return (b >= 0x41U) && (b <= 0x5AU); };
    r = std::all_of(value.begin(), value.end(), upper) ? Reason::Ok : Reason::InvalidInput;
  } else if (attribute == Attribute::SerialNumber) {
    r = (der::CheckPrintable(value) == Reason::Ok) ? Reason::Ok : Reason::InvalidInput;
  } else {
    r = (der::CheckUtf8(value) == Reason::Ok) ? Reason::Ok : Reason::InvalidInput;
  }
  return r;
}

/**
 * @brief Check an alternative name.
 * @param type The type.
 * @param value The bytes.
 * @return `Ok` or `InvalidInput`.
 */
constexpr Reason CheckAltName(AltNameType type, ByteSpan value) noexcept {
  if (!se05x::detail::IsEnumerator(type)) {
    return Reason::InvalidInput;
  }
  if (type == AltNameType::Ip) {
    return ((value.size() == 4U) || (value.size() == 16U)) ? Reason::Ok : Reason::InvalidInput;
  }
  const bool ok =
      !value.empty() && (value.size() <= kMaxAltNameValue) && (der::CheckIa5(value) == Reason::Ok);
  return ok ? Reason::Ok : Reason::InvalidInput;
}

/**
 * @param type An alternative name type.
 * @return Its GeneralName tag.
 */
constexpr uint8_t AltNameTag(AltNameType type) noexcept {
  uint8_t number = 2U;
  if (type == AltNameType::Uri) {
    number = 6U;
  } else if (type == AltNameType::Email) {
    number = 1U;
  } else if (type == AltNameType::Ip) {
    number = 7U;
  } else {
    number = 2U;
  }
  return der::ContextPrimitive(number);
}

} // namespace detail

/**
 * @brief A subject name: up to `kMaxNameAttributes` attributes, each its own relative
 * distinguished name, in the order added. Values are views into the caller's bytes, except those
 * of `AddHex()`, which the name holds. The first error latches (`Status()`).
 */
class Name {
public:
  /** @brief An empty name. */
  constexpr Name() noexcept = default;

  /**
   * @brief Add an attribute.
   * @param attribute The attribute.
   * @param value Its value, UTF-8 bytes (see `Attribute` for the limits); must outlive the name.
   * @return This name.
   */
  constexpr Name& Add(Attribute attribute, ByteSpan value) noexcept {
    Entry* e = next(attribute, value);
    if (e != nullptr) {
      e->value = value;
    }
    return *this;
  }
  /**
   * @brief Add an attribute whose value is the upper-case hex of some bytes (for example the
   * chip's unique id as the commonName or serialNumber).
   * @param attribute The attribute.
   * @param bytes 1 to `kMaxHexInput` bytes; the name keeps the hex.
   * @return This name.
   */
  constexpr Name& AddHex(Attribute attribute, ByteSpan bytes) noexcept {
    constexpr std::array<uint8_t, 16> kHex{0x30U, 0x31U, 0x32U, 0x33U, 0x34U, 0x35U, 0x36U, 0x37U,
                                           0x38U, 0x39U, 0x41U, 0x42U, 0x43U, 0x44U, 0x45U, 0x46U};
    if (bytes.empty() || (bytes.size() > kMaxHexInput)) {
      fail(Reason::InvalidInput);
      return *this;
    }
    std::array<uint8_t, 2U * kMaxHexInput> hex{};
    for (std::size_t i = 0U; i < bytes.size(); ++i) {
      hex[2U * i] = kHex[(static_cast<uint32_t>(bytes[i]) >> 4U) & 0x0FU];
      hex[(2U * i) + 1U] = kHex[static_cast<uint32_t>(bytes[i]) & 0x0FU];
    }
    const ByteSpan text = ByteSpan{hex}.first(2U * bytes.size());
    Entry* e = next(attribute, text);
    if (e != nullptr) {
      e->hex = hex;
      e->hex_length = text.size();
      e->owns = true;
    }
    return *this;
  }
  /** @return The first error, or `Ok`. */
  [[nodiscard]] constexpr Reason Status() const noexcept {
    return error_;
  }
  /** @return The number of attributes. */
  [[nodiscard]] constexpr std::size_t Count() const noexcept {
    return count_;
  }
  /**
   * @brief Write the Name (RFC 5280 4.1.2.4).
   * @param w The writer.
   */
  constexpr void Encode(der::Writer& w) const noexcept {
    if (error_ != Reason::Ok) {
      w.Fail(error_);
      return;
    }
    w.Begin(der::kSequence);
    for (std::size_t i = 0U; i < count_; ++i) {
      const Entry& e = entries_[i];
      std::size_t max = 0U;
      const bool printable =
          (e.attribute == Attribute::Country) || (e.attribute == Attribute::SerialNumber);
      w.Begin(der::kSet);
      w.Begin(der::kSequence);
      w.Oid(detail::AttributeOid(e.attribute, max));
      w.Primitive(printable ? der::kPrintableString : der::kUtf8String,
                  e.owns ? ByteSpan{e.hex}.first(e.hex_length) : e.value);
      w.End();
      w.End();
    }
    w.End();
  }

private:
  struct Entry {
    Attribute attribute{Attribute::CommonName};
    ByteSpan value;
    std::array<uint8_t, 2U * kMaxHexInput> hex{};
    std::size_t hex_length{0};
    bool owns{false};
  };
  constexpr void fail(Reason reason) noexcept {
    if (error_ == Reason::Ok) {
      error_ = reason;
    }
  }
  constexpr Entry* next(Attribute attribute, ByteSpan value) noexcept {
    if (!se05x::detail::IsEnumerator(attribute) ||
        (detail::CheckAttribute(attribute, value) != Reason::Ok)) {
      fail(Reason::InvalidInput);
      return nullptr;
    }
    if (count_ >= entries_.size()) {
      fail(Reason::TooManyEntries);
      return nullptr;
    }
    entries_[count_] = Entry{};
    entries_[count_].attribute = attribute;
    ++count_;
    return &entries_[count_ - 1U];
  }

  std::array<Entry, kMaxNameAttributes> entries_{};
  std::size_t count_{0};
  Reason error_{Reason::Ok};
};

/**
 * @brief The entries of a subjectAltName: up to `kMaxAltNames`, views into the caller's bytes.
 * The first error latches (`Status()`).
 */
class AltNames {
public:
  /** @brief No entries. */
  constexpr AltNames() noexcept = default;
  /**
   * @brief Add an entry.
   * @param type The type.
   * @param value IA5 text (1 to `kMaxAltNameValue` bytes) or a 4- or 16-byte address; it must
   * outlive this object.
   * @return This object.
   */
  constexpr AltNames& Add(AltNameType type, ByteSpan value) noexcept {
    if (detail::CheckAltName(type, value) != Reason::Ok) {
      fail(Reason::InvalidInput);
    } else if (count_ >= entries_.size()) {
      fail(Reason::TooManyEntries);
    } else {
      entries_[count_] = Entry{.type = type, .value = value};
      ++count_;
    }
    return *this;
  }
  /** @return The first error, or `Ok`. */
  [[nodiscard]] constexpr Reason Status() const noexcept {
    return error_;
  }
  /** @return The number of entries. */
  [[nodiscard]] constexpr std::size_t Count() const noexcept {
    return count_;
  }
  /**
   * @brief Write the GeneralNames.
   * @param w The writer.
   */
  constexpr void Encode(der::Writer& w) const noexcept {
    if ((error_ != Reason::Ok) || (count_ == 0U)) {
      w.Fail((error_ != Reason::Ok) ? error_ : Reason::EmptyInput);
      return;
    }
    w.Begin(der::kSequence);
    for (std::size_t i = 0U; i < count_; ++i) {
      w.Primitive(detail::AltNameTag(entries_[i].type), entries_[i].value);
    }
    w.End();
  }

private:
  struct Entry {
    AltNameType type{AltNameType::Dns};
    ByteSpan value;
  };
  constexpr void fail(Reason reason) noexcept {
    if (error_ == Reason::Ok) {
      error_ = reason;
    }
  }
  std::array<Entry, kMaxAltNames> entries_{};
  std::size_t count_{0};
  Reason error_{Reason::Ok};
};

/**
 * @brief A signer: `Algorithm()` names the signature algorithm, and `Sign(input, signature)`
 * signs (for ECDSA `input` is the digest and the result is the DER ECDSA-Sig-Value; for Ed25519
 * `input` is the message and the result is 64 bytes) and returns the length written.
 */
template <typename S>
concept CsrSigner = requires(S& s, const S& cs, ByteSpan input, MutableByteSpan out) {
  { cs.Algorithm() } noexcept -> std::same_as<SignatureAlgorithm>;
  { s.Sign(input, out) } noexcept -> std::same_as<Result<std::size_t>>;
};

/**
 * @brief Encode a fixed-width `r || s` as an ECDSA-Sig-Value.
 * @param raw `r || s`, an even length.
 * @param out The buffer.
 * @return The length, or `InvalidInput` / `BufferTooSmall`.
 */
constexpr Result<std::size_t> EncodeEcdsaSignature(ByteSpan raw, MutableByteSpan out) noexcept {
  if (raw.empty() || ((raw.size() % 2U) != 0U)) {
    return Fail<std::size_t>(Reason::InvalidInput);
  }
  const std::size_t half = raw.size() / 2U;
  der::Writer w(out);
  w.Begin(der::kSequence);
  w.Integer(raw.first(half));
  w.Integer(raw.subspan(half));
  w.End();
  return w.Finish();
}

/**
 * @brief A signer over a P-256 key handle of a crypto port (`EcdsaP256Sign`): the key stays in
 * the port.
 * @tparam C A `CryptoPort`.
 */
template <CryptoPort C>
class PortSigner {
public:
  /**
   * @brief Bind the port and the key.
   * @param port The port; it must outlive the signer.
   * @param key The P-256 private key handle.
   */
  PortSigner(C& port, KeyRef key) noexcept : port_(&port), key_(key) {}
  /** @return ecdsa-with-SHA256. */
  [[nodiscard]] SignatureAlgorithm Algorithm() const noexcept {
    return SignatureAlgorithm::EcdsaSha256;
  }
  /**
   * @brief Sign a digest.
   * @param digest The 32-byte digest.
   * @param signature Receives the DER signature.
   * @return Its length; `InvalidInput`, `SignerFailed`, `BufferTooSmall`.
   */
  Result<std::size_t> Sign(ByteSpan digest, MutableByteSpan signature) noexcept {
    if (digest.size() != 32U) {
      return Fail<std::size_t>(Reason::InvalidInput);
    }
    std::array<uint8_t, 64> raw{};
    if (port_->EcdsaP256Sign(key_, digest.template first<32U>(), std::span<uint8_t, 64>{raw}) !=
        CryptoStatus::Ok) {
      return Fail<std::size_t>(Reason::SignerFailed);
    }
    return EncodeEcdsaSignature(ByteSpan{raw}, signature);
  }

private:
  C* port_;
  KeyRef key_;
};

/** @brief What a certification request asks for. */
struct CsrRequest {
  const Name* subject{nullptr};       ///< The subject; may be empty only with alternative names.
  PublicKey key{};                    ///< The public key of the signing key.
  const AltNames* alt_names{nullptr}; ///< subjectAltName entries, or none.
  uint16_t key_usage{0};              ///< keyUsage bits to request (critical), 0 for none.
};

namespace detail {

/**
 * @brief Write an AlgorithmIdentifier of a signature (no parameters: RFC 5758 3.2, RFC 8410 3).
 * @param w The writer.
 * @param algorithm The algorithm.
 */
constexpr void WriteSignatureAlgorithm(der::Writer& w, SignatureAlgorithm algorithm) noexcept {
  w.Begin(der::kSequence);
  if (algorithm == SignatureAlgorithm::EcdsaSha256) {
    w.Oid(ByteSpan{oid::kEcdsaSha256});
  } else if (algorithm == SignatureAlgorithm::EcdsaSha384) {
    w.Oid(ByteSpan{oid::kEcdsaSha384});
  } else {
    w.Oid(ByteSpan{oid::kEd25519});
  }
  w.End();
}

/**
 * @brief Write a SubjectPublicKeyInfo (RFC 5480 2, RFC 8410 4).
 * @param w The writer.
 * @param key The key.
 */
constexpr void WritePublicKeyInfo(der::Writer& w, const PublicKey& key) noexcept {
  w.Begin(der::kSequence);
  w.Begin(der::kSequence);
  if (key.type == KeyType::Ed25519) {
    w.Oid(ByteSpan{oid::kEd25519});
  } else {
    w.Oid(ByteSpan{oid::kEcPublicKey});
    w.Oid((key.type == KeyType::EcP384) ? ByteSpan{oid::kP384} : ByteSpan{oid::kP256});
  }
  w.End();
  w.BitString(key.bytes);
  w.End();
}

/**
 * @brief Write the `[0]` attributes: an extensionRequest with keyUsage and subjectAltName, or
 * nothing.
 * @param w The writer.
 * @param request The request.
 */
constexpr void WriteAttributes(der::Writer& w, const CsrRequest& request) noexcept {
  const bool alt = (request.alt_names != nullptr) && (request.alt_names->Count() != 0U);
  const bool no_subject = (request.subject == nullptr) || (request.subject->Count() == 0U);
  w.Begin(der::ContextConstructed(0U));
  if (alt || (request.key_usage != 0U)) {
    w.Begin(der::kSequence);
    w.Oid(ByteSpan{oid::kExtensionRequest});
    w.Begin(der::kSet);
    w.Begin(der::kSequence);
    if (request.key_usage != 0U) {
      w.Begin(der::kSequence);
      w.Oid(ByteSpan{oid::kKeyUsage});
      w.Boolean(true); // RFC 5280 4.2.1.3: SHOULD be critical
      w.Begin(der::kOctetString);
      w.NamedBits(request.key_usage);
      w.End();
      w.End();
    }
    if (alt) {
      w.Begin(der::kSequence);
      w.Oid(ByteSpan{oid::kSubjectAltName});
      if (no_subject) {
        w.Boolean(true); // RFC 5280 4.2.1.6: critical when the subject is empty
      }
      w.Begin(der::kOctetString);
      request.alt_names->Encode(w);
      w.End();
      w.End();
    }
    w.End();
    w.End();
    w.End();
  }
  w.End();
}

/**
 * @brief Check a request before anything is written.
 * @param request The request.
 * @param algorithm The signer's algorithm.
 * @return `Ok`, `InvalidInput`, `EmptyInput`, `BadPublicKey` or `AlgorithmMismatch`.
 */
constexpr Reason CheckRequest(const CsrRequest& request, SignatureAlgorithm algorithm) noexcept {
  const bool alt = (request.alt_names != nullptr) && (request.alt_names->Count() != 0U);
  Reason r = Reason::Ok;
  if ((request.subject == nullptr) || !se05x::detail::IsEnumerator(request.key.type) ||
      ((static_cast<uint32_t>(request.key_usage) & ~static_cast<uint32_t>(key_usage::kAll)) !=
       0U)) {
    r = Reason::InvalidInput;
  } else if (request.subject->Status() != Reason::Ok) {
    r = request.subject->Status();
  } else if ((request.alt_names != nullptr) && (request.alt_names->Status() != Reason::Ok)) {
    r = request.alt_names->Status();
  } else if ((request.subject->Count() == 0U) && !alt) {
    r = Reason::EmptyInput;
  } else if ((request.key.bytes.size() != PublicKeyLength(request.key.type)) ||
             ((request.key.type != KeyType::Ed25519) && (request.key.bytes[0] != 0x04U))) {
    r = Reason::BadPublicKey;
  } else if (AlgorithmFor(request.key.type) != algorithm) {
    r = Reason::AlgorithmMismatch;
  } else {
    r = Reason::Ok;
  }
  return r;
}

/**
 * @brief Sign the info and check what the signer returns.
 * @tparam S A `CsrSigner`.
 * @tparam H A `DigestPort`.
 * @param signer The signer.
 * @param hasher The hash.
 * @param info The encoded CertificationRequestInfo.
 * @param signature Receives the signature.
 * @return Its length, or the signer's failure, `SignerOutputInvalid`, `CryptoFailure`.
 */
template <CsrSigner S, DigestPort H>
Result<std::size_t> SignInfo(S& signer, H& hasher, ByteSpan info,
                             std::array<uint8_t, kMaxSignatureDer>& signature) noexcept {
  const SignatureAlgorithm algorithm = signer.Algorithm();
  std::array<uint8_t, kMaxDigest> digest{};
  ByteSpan input = info;
  if (algorithm != SignatureAlgorithm::Ed25519) {
    const Reason d = Digest(hasher, algorithm, info, digest);
    if (d != Reason::Ok) {
      return Fail<std::size_t>(d);
    }
    input = ByteSpan{digest}.first(DigestLength(algorithm));
  }
  const Result<std::size_t> s = signer.Sign(input, MutableByteSpan{signature});
  if (!s.ok()) {
    return s;
  }
  if ((s.value > signature.size()) ||
      (CheckSignatureValue(algorithm, ByteSpan{signature}.first(s.value)) != Reason::Ok)) {
    return Fail<std::size_t>(Reason::SignerOutputInvalid);
  }
  return s;
}

} // namespace detail

/**
 * @brief Build and sign a PKCS#10 request.
 * @tparam S A `CsrSigner` (`DeviceSigner`, `PortSigner`, or your own).
 * @tparam H A `DigestPort` (the crypto port).
 * @param request What to ask for; the key must pair with the signer's algorithm.
 * @param signer The signer; the private key stays with it.
 * @param hasher The hash for ECDSA.
 * @param out The buffer; on failure it is zeroed.
 * @return The length of the request; `InvalidInput`, `EmptyInput`, `TooManyEntries`,
 * `BadPublicKey`, `AlgorithmMismatch`, `BufferTooSmall`, `SignerOutputInvalid`, `CryptoFailure`, or
 * the signer's own failure (a device error keeps the device's details).
 */
template <CsrSigner S, DigestPort H>
Result<std::size_t> BuildCsr(const CsrRequest& request, S& signer, H& hasher,
                             MutableByteSpan out) noexcept {
  const SignatureAlgorithm algorithm = signer.Algorithm();
  const Reason check = detail::CheckRequest(request, algorithm);
  Result<std::size_t> result = Result<std::size_t>::Success(0U);
  if (check != Reason::Ok) {
    result = Fail<std::size_t>(check);
  } else {
    der::Writer w(out);
    w.Begin(der::kSequence);
    w.Begin(der::kSequence);
    w.Small(0U);
    if (request.subject != nullptr) {
      request.subject->Encode(w);
    }
    detail::WritePublicKeyInfo(w, request.key);
    detail::WriteAttributes(w, request);
    w.End();
    std::array<uint8_t, kMaxSignatureDer> signature{};
    const Result<std::size_t> signed_info =
        (w.Status() == Reason::Ok) ? detail::SignInfo(signer, hasher, w.LastClosed(), signature)
                                   : Fail<std::size_t>(w.Status());
    if (signed_info.ok()) {
      detail::WriteSignatureAlgorithm(w, algorithm);
      w.BeginBitString();
      w.Raw(ByteSpan{signature}.first(signed_info.value));
      w.End();
      w.End();
      result = w.Finish();
    } else {
      result = signed_info;
    }
  }
  if (!result.ok()) {
    std::fill(out.begin(), out.end(), uint8_t{0});
  }
  return result;
}

/** @brief What a verified request holds: views into the caller's request. */
struct CsrInfo {
  ByteSpan subject;    ///< The encoded subject Name.
  PublicKey key{};     ///< The public key.
  ByteSpan attributes; ///< The content of `[0]` (empty when there are none).
  SignatureAlgorithm signature_algorithm{SignatureAlgorithm::EcdsaSha256}; ///< How it is signed.
};

namespace detail {

/**
 * @brief Check the attributes of a request: each a SEQUENCE of an OID and a SET (RFC 2986 4.1).
 * @param attributes The reader of the `[0]` content.
 * @return `Ok`, `TooManyEntries`, or a structure reason.
 */
inline Reason CheckCsrAttributes(der::Reader& attributes) noexcept {
  Reason r = Reason::Ok;
  for (std::size_t i = 0U; (r == Reason::Ok) && !attributes.AtEnd(); ++i) {
    der::Reader attribute{};
    der::Element e{};
    r = (i < kMaxListEntries) ? attributes.ExpectEnter(der::kSequence, attribute)
                              : Reason::TooManyEntries;
    r = (r == Reason::Ok) ? attribute.Expect(der::kOid, e) : r;
    r = (r == Reason::Ok) ? attribute.Expect(der::kSet, e) : r;
    r = (r == Reason::Ok) ? attribute.Finish() : r;
  }
  return r;
}

/**
 * @brief Parse a CertificationRequestInfo (RFC 2986 4.1).
 * @param element The info element.
 * @param out Receives the fields.
 * @return `Ok` or why not.
 */
inline Reason ParseCsrInfo(const der::Element& element, CsrInfo& out) noexcept {
  der::Reader outer(element.encoded, 1U);
  der::Reader info{};
  der::Element e{};
  uint32_t version = 1U;
  bool empty = false;
  Reason r = outer.ExpectEnter(der::kSequence, info);
  r = (r == Reason::Ok) ? info.Expect(der::kInteger, e) : r;
  r = (r == Reason::Ok) ? der::ParseSmall(e.value, 0xFFU, version) : r;
  if ((r == Reason::Ok) && (version != 0U)) {
    r = Reason::UnsupportedVersion;
  }
  r = (r == Reason::Ok) ? info.Expect(der::kSequence, e) : r;
  r = (r == Reason::Ok) ? CheckName(e.encoded, empty) : r;
  out.subject = e.encoded;
  r = (r == Reason::Ok) ? info.Expect(der::kSequence, e) : r;
  r = (r == Reason::Ok) ? ParsePublicKeyInfo(e, out.key) : r;
  der::Reader attributes{};
  r = (r == Reason::Ok) ? info.Expect(der::ContextConstructed(0U), e) : r;
  r = (r == Reason::Ok) ? info.Enter(e, attributes) : r;
  out.attributes = e.value;
  r = (r == Reason::Ok) ? CheckCsrAttributes(attributes) : r;
  r = (r == Reason::Ok) ? info.Finish() : r;
  return (r == Reason::Ok) ? outer.Finish() : r;
}

} // namespace detail

/**
 * @brief Parse a request strictly and verify its signature with its own public key (RFC 2986
 * section 3, step 3 from the requester's side).
 * @tparam V A `SignatureVerifier`.
 * @tparam H A `DigestPort`.
 * @param csr The DER request.
 * @param verifier The verifier.
 * @param hasher The hash.
 * @return The request's fields, or why it is refused (`UnsupportedAlgorithm` for an Ed25519
 * request: this layer does not verify Ed25519).
 */
template <SignatureVerifier V, DigestPort H>
Result<CsrInfo> VerifyCsr(ByteSpan csr, V& verifier, H& hasher) noexcept {
  CsrInfo out{};
  der::Reader input(csr);
  der::Reader top{};
  der::Element info{};
  der::Element alg{};
  der::Element sig{};
  ByteSpan signature{};
  Reason r = input.ExpectEnter(der::kSequence, top);
  r = (r == Reason::Ok) ? input.Finish() : r;
  r = (r == Reason::Ok) ? top.Expect(der::kSequence, info) : r;
  r = (r == Reason::Ok) ? detail::ParseCsrInfo(info, out) : r;
  r = (r == Reason::Ok) ? top.Expect(der::kSequence, alg) : r;
  r = (r == Reason::Ok) ? ParseSignatureAlgorithm(alg, out.signature_algorithm) : r;
  r = (r == Reason::Ok) ? top.Expect(der::kBitString, sig) : r;
  r = (r == Reason::Ok) ? der::ParseOctetBits(sig.value, signature) : r;
  r = (r == Reason::Ok) ? top.Finish() : r;
  r = (r == Reason::Ok) ? VerifySigned(verifier, hasher, out.key, out.signature_algorithm,
                                       info.encoded, signature)
                        : r;
  if (r != Reason::Ok) {
    return Fail<CsrInfo>(r);
  }
  return Result<CsrInfo>::Success(out);
}

/** @} */

} // namespace se05x::pki

#endif // SE05X_PKI_CSR_HPP
