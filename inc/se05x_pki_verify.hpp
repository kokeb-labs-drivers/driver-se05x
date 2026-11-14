/**
 * @file se05x_pki_verify.hpp
 * @brief Certificate chain verification up to a caller's trust anchor (an RFC 5280 section 6
 * subset), with ECDSA P-256 and P-384 through a verifier port.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * `VerifyChain()` takes the chain end entity first, without the trust
 * anchor, and the anchors the caller trusts (a name and a key, `TrustAnchor`), and checks, from the
 * anchor down (RFC 5280 6.1.3 and 6.1.4):
 *
 * - each certificate parses under the profile of `ParseCertificate()` (an unknown critical
 *   extension is refused there);
 * - its issuer is, byte for byte, the subject of the certificate above it (or of the anchor);
 * - its signature verifies with the key above it: ecdsa-with-SHA256 with a P-256 key,
 *   ecdsa-with-SHA384 with a P-384 key (another pairing is `AlgorithmMismatch`; Ed25519
 *   signatures are `UnsupportedAlgorithm`);
 * - the caller's time lies in its validity, both ends included (a time of 0 is `NoTime`: the
 *   check is never skipped);
 * - every certificate above the end entity has basicConstraints cA TRUE, keyCertSign when it has
 *   a keyUsage, and the path length allowed by every pathLenConstraint above it (and by the
 *   anchor's) is not exceeded; each intermediate counts, self-issued or not (stricter than 6.1.4
 *   (l));
 * - the end entity has the key usage bits the options require, and is not a CA unless allowed.
 *
 * Not checked (out of scope; say so where it matters): revocation (CRL, OCSP), certificate
 * policies, name constraints (a CA with a critical nameConstraints is refused at parse time),
 * extended key usage (reported in `Certificate::ext_key_usage`), the anchor's own validity.
 *
 * The verifier port (`SignatureVerifier`) verifies a raw `r || s` over a digest; `PortVerifier`
 * adapts any `CryptoPort` (P-256 only, the port's `EcdsaP256Verify`). A P-384 chain needs a
 * verifier that supports P-384 (a hardware engine or a vetted library behind the same concept).
 */
#ifndef SE05X_PKI_VERIFY_HPP
#define SE05X_PKI_VERIFY_HPP

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>

#include "se05x_pki_der.hpp"
#include "se05x_pki_types.hpp"
#include "se05x_pki_x509.hpp"
#include "se05x_ports.hpp"
#include "se05x_status.hpp"
#include "se05x_types.hpp"

namespace se05x::pki {

/**
 * @defgroup se05x_pki_verify Chain verification
 * @brief Verifier and digest ports, trust anchors, `VerifyChain()`.
 * @{
 */

/**
 * @brief A signature verifier: `Supports(type)` says which key types it verifies, and
 * `VerifySignature(type, public_key, digest, raw)` verifies the fixed-width `r || s` over the
 * digest: `Ok` valid, `Mismatch` invalid, `InvalidKey` a key that is not a valid point, `Failed`.
 */
template <typename V>
concept SignatureVerifier = requires(V& v, const V& cv, KeyType type, ByteSpan bytes) {
  { cv.Supports(type) } noexcept -> std::same_as<bool>;
  { v.VerifySignature(type, bytes, bytes, bytes) } noexcept -> std::same_as<CryptoStatus>;
};

/** @brief A hash function: the crypto port's `Hash` hook (every `CryptoPort` satisfies it). */
template <typename H>
concept DigestPort = requires(H& h, HashAlg alg, ByteSpan in, MutableByteSpan out) {
  { h.Hash(alg, in, out) } noexcept -> std::same_as<CryptoStatus>;
};

/**
 * @brief The verifier of a crypto port: P-256 through `EcdsaP256Verify`.
 * @tparam C A `CryptoPort`.
 */
template <CryptoPort C>
class PortVerifier {
public:
  /** @brief Bind the port. @param port The port; it must outlive the verifier. */
  explicit PortVerifier(C& port) noexcept : port_(&port) {}
  /** @param type A key type. @return true for P-256 only. */
  [[nodiscard]] bool Supports(KeyType type) const noexcept {
    return type == KeyType::EcP256;
  }
  /**
   * @brief Verify with the port.
   * @param type The key type; anything but P-256 is `Failed`.
   * @param public_key The 65-byte point.
   * @param digest The 32-byte digest.
   * @param raw The 64-byte `r || s`.
   * @return The port's status, or `Failed` for another size or type.
   */
  CryptoStatus VerifySignature(KeyType type, ByteSpan public_key, ByteSpan digest,
                               ByteSpan raw) noexcept {
    if ((type != KeyType::EcP256) || (public_key.size() != 65U) || (digest.size() != 32U) ||
        (raw.size() != 64U)) {
      return CryptoStatus::Failed;
    }
    return port_->EcdsaP256Verify(public_key.template first<65U>(), digest.template first<32U>(),
                                  raw.template first<64U>());
  }

private:
  C* port_;
};

/** @brief A trust anchor: the name and key the caller trusts (RFC 5914 in its simplest form). */
struct TrustAnchor {
  ByteSpan subject;                   ///< The encoded Name that issued the top of the chain.
  PublicKey key{};                    ///< Its public key.
  uint8_t path_length{kNoPathLength}; ///< Most intermediates below it; `kNoPathLength` for none.
};

/** @brief What `VerifyChain()` checks besides the chain itself. */
struct VerifyOptions {
  uint64_t now_unix{0};           ///< The time, Unix seconds (UTC); 0 is refused (`NoTime`).
  uint16_t required_key_usage{0}; ///< keyUsage bits the end entity must have (it then needs the
                                  ///< extension); 0 for none.
  bool allow_ca_leaf{false};      ///< Accept an end entity that is a CA (cA TRUE).
};

/** @brief The outcome of a verified chain. */
struct VerifiedChain {
  PublicKey leaf_key{};        ///< The end entity's key (points into the caller's DER).
  ByteSpan leaf_subject;       ///< The end entity's encoded subject.
  std::size_t length{0};       ///< Certificates checked.
  std::size_t anchor_index{0}; ///< The anchor that verified it.
};

/**
 * @brief A trust anchor from a CA certificate the caller trusts (its own signature, validity and
 * issuer are not checked: trust comes from where the caller got it).
 * @param cert A parsed certificate; the anchor points into it.
 * @return The anchor; `NotCa` without cA TRUE, `KeyCertSignMissing` with a keyUsage that lacks it.
 */
constexpr Result<TrustAnchor> AnchorFromCertificate(const Certificate& cert) noexcept {
  if (!cert.is_ca) {
    return Fail<TrustAnchor>(Reason::NotCa);
  }
  if (cert.has_key_usage && !HasBits(cert.key_usage, key_usage::kKeyCertSign)) {
    return Fail<TrustAnchor>(Reason::KeyCertSignMissing);
  }
  return Result<TrustAnchor>::Success(TrustAnchor{
      .subject = cert.subject, .key = cert.public_key, .path_length = cert.path_length});
}

/**
 * @brief Hash a message for an ECDSA algorithm.
 * @tparam H A `DigestPort`.
 * @param hasher The hash.
 * @param algorithm ecdsa-with-SHA256 or -SHA384.
 * @param message The message.
 * @param digest Receives the digest at its start.
 * @return `Ok`, `UnsupportedAlgorithm` (Ed25519) or `CryptoFailure`.
 */
template <DigestPort H>
Reason Digest(H& hasher, SignatureAlgorithm algorithm, ByteSpan message,
              std::array<uint8_t, kMaxDigest>& digest) noexcept {
  HashAlg alg = HashAlg::Sha256;
  if (algorithm == SignatureAlgorithm::EcdsaSha256) {
    alg = HashAlg::Sha256;
  } else if (algorithm == SignatureAlgorithm::EcdsaSha384) {
    alg = HashAlg::Sha384;
  } else {
    return Reason::UnsupportedAlgorithm;
  }
  return (hasher.Hash(alg, message, MutableByteSpan{digest}) == CryptoStatus::Ok)
             ? Reason::Ok
             : Reason::CryptoFailure;
}

/**
 * @brief Verify a signature over a message (a TBSCertificate, a CertificationRequestInfo).
 * @tparam V A `SignatureVerifier`.
 * @tparam H A `DigestPort`.
 * @param verifier The verifier.
 * @param hasher The hash.
 * @param key The signer's key.
 * @param algorithm The signature algorithm; it must pair with the key (`AlgorithmFor`).
 * @param message The signed bytes.
 * @param signature The ECDSA-Sig-Value.
 * @return `Ok`, `SignatureInvalid`, `AlgorithmMismatch`, `UnsupportedAlgorithm`,
 * `CurveNotSupported`, `BadSignatureValue`, `BadPublicKey` (a key of the wrong length, or one the
 * verifier says is not a point) or `CryptoFailure`.
 */
template <SignatureVerifier V, DigestPort H>
Reason VerifySigned(V& verifier, H& hasher, const PublicKey& key, SignatureAlgorithm algorithm,
                    ByteSpan message, ByteSpan signature) noexcept {
  if ((key.type == KeyType::Ed25519) || (algorithm == SignatureAlgorithm::Ed25519)) {
    return Reason::UnsupportedAlgorithm;
  }
  if (AlgorithmFor(key.type) != algorithm) {
    return Reason::AlgorithmMismatch;
  }
  if (!verifier.Supports(key.type)) {
    return Reason::CurveNotSupported;
  }
  if (key.bytes.size() != PublicKeyLength(key.type)) {
    return Reason::BadPublicKey; // an anchor built by hand with the wrong length
  }
  const std::size_t width = DigestLength(algorithm);
  std::array<uint8_t, kMaxRawSignature> raw{};
  std::array<uint8_t, kMaxDigest> digest{};
  Reason r = der::ParseEcdsaSignature(signature, width, MutableByteSpan{raw});
  r = (r == Reason::Ok) ? Digest(hasher, algorithm, message, digest) : r;
  if (r != Reason::Ok) {
    return r;
  }
  const CryptoStatus s = verifier.VerifySignature(
      key.type, key.bytes, ByteSpan{digest}.first(width), ByteSpan{raw}.first(2U * width));
  Reason out = Reason::CryptoFailure;
  if (s == CryptoStatus::Ok) {
    out = Reason::Ok;
  } else if (s == CryptoStatus::Mismatch) {
    out = Reason::SignatureInvalid;
  } else if (s == CryptoStatus::InvalidKey) {
    out = Reason::BadPublicKey;
  } else {
    out = Reason::CryptoFailure;
  }
  return out;
}

namespace detail {

/** @brief The issuer side while walking down a chain. */
struct Issuer {
  ByteSpan name;           ///< Its subject.
  PublicKey key{};         ///< Its key.
  std::size_t max_path{0}; ///< Intermediates still allowed below it.
};

/**
 * @brief The time check (RFC 5280 6.1.3 (a)(2)).
 * @param cert The certificate.
 * @param now Unix seconds.
 * @return `Ok`, `NotYetValid` or `Expired`.
 */
constexpr Reason CheckTime(const Certificate& cert, uint64_t now) noexcept {
  if (now < ToUnixSeconds(cert.not_before)) {
    return Reason::NotYetValid;
  }
  if (now > ToUnixSeconds(cert.not_after)) {
    return Reason::Expired;
  }
  return Reason::Ok;
}

/**
 * @brief The checks of a certificate that issues the next one (RFC 5280 6.1.4 (k), (l), (m),
 * (n)); updates the path length.
 * @param cert The issuing certificate.
 * @param issuer The issuer above it; `max_path` is updated.
 * @return `Ok`, `NotCa`, `KeyCertSignMissing` or `PathLengthExceeded`.
 */
constexpr Reason CheckIssuing(const Certificate& cert, Issuer& issuer) noexcept {
  if (!cert.has_basic_constraints || !cert.is_ca) {
    return Reason::NotCa;
  }
  if (cert.has_key_usage && !HasBits(cert.key_usage, key_usage::kKeyCertSign)) {
    return Reason::KeyCertSignMissing;
  }
  if (issuer.max_path == 0U) {
    return Reason::PathLengthExceeded;
  }
  std::size_t left = issuer.max_path - 1U;
  if ((cert.path_length != kNoPathLength) && (cert.path_length < left)) {
    left = cert.path_length;
  }
  issuer.name = cert.subject;
  issuer.key = cert.public_key;
  issuer.max_path = left;
  return Reason::Ok;
}

/**
 * @brief The checks of the end entity.
 * @param cert The end-entity certificate.
 * @param options The options.
 * @return `Ok`, `LeafIsCa` or `LeafKeyUsageMissing`.
 */
constexpr Reason CheckLeaf(const Certificate& cert, const VerifyOptions& options) noexcept {
  if (cert.is_ca && !options.allow_ca_leaf) {
    return Reason::LeafIsCa;
  }
  const uint16_t need = options.required_key_usage;
  if ((need != 0U) && (!cert.has_key_usage || !HasBits(cert.key_usage, need))) {
    return Reason::LeafKeyUsageMissing;
  }
  return Reason::Ok;
}

/**
 * @brief Walk the chain from one anchor down.
 * @tparam V A `SignatureVerifier`.
 * @tparam H A `DigestPort`.
 * @param chain The chain, end entity first.
 * @param anchor The anchor.
 * @param options The options.
 * @param verifier The verifier.
 * @param hasher The hash.
 * @param out Receives the outcome.
 * @return `Ok` or the first failed check.
 */
template <SignatureVerifier V, DigestPort H>
Reason Walk(std::span<const ByteSpan> chain, const TrustAnchor& anchor,
            const VerifyOptions& options, V& verifier, H& hasher, VerifiedChain& out) noexcept {
  const std::size_t allowed =
      (anchor.path_length == kNoPathLength) ? kMaxChain : anchor.path_length;
  Issuer issuer{.name = anchor.subject, .key = anchor.key, .max_path = allowed};
  for (std::size_t k = 0U; k < chain.size(); ++k) {
    const std::size_t index = chain.size() - 1U - k;
    const Result<Certificate> parsed = ParseCertificate(chain[index]);
    if (!parsed.ok()) {
      return ReasonOf(parsed.detail);
    }
    const Certificate& cert = parsed.value;
    Reason r = der::SameBytes(cert.issuer, issuer.name) ? Reason::Ok : Reason::NameMismatch;
    r = (r == Reason::Ok) ? VerifySigned(verifier, hasher, issuer.key, cert.signature_algorithm,
                                         cert.tbs, cert.signature)
                          : r;
    r = (r == Reason::Ok) ? CheckTime(cert, options.now_unix) : r;
    if (r == Reason::Ok) {
      r = (index != 0U) ? CheckIssuing(cert, issuer) : CheckLeaf(cert, options);
    }
    if (r != Reason::Ok) {
      return r;
    }
    if (index == 0U) {
      out.leaf_key = cert.public_key;
      out.leaf_subject = cert.subject;
    }
  }
  out.length = chain.size();
  return Reason::Ok;
}

} // namespace detail

/**
 * @brief Verify a certificate chain up to one of the caller's trust anchors.
 * @tparam V A `SignatureVerifier`.
 * @tparam H A `DigestPort`.
 * @param chain The DER certificates, end entity first, the anchor left out; at most `kMaxChain`.
 * @param anchors The trust anchors; at most `kMaxAnchors`. Every anchor whose subject is the top
 * certificate's issuer is tried in order.
 * @param options The time and the end-entity rules.
 * @param verifier The signature verifier.
 * @param hasher The hash (the crypto port).
 * @return The end entity's key and subject, or the reason of the last anchor tried (see the file
 * comment); `EmptyInput`, `ChainTooLong`, `TooManyEntries`, `NoTime`, `NoTrustAnchor`.
 */
template <SignatureVerifier V, DigestPort H>
Result<VerifiedChain> VerifyChain(std::span<const ByteSpan> chain,
                                  std::span<const TrustAnchor> anchors,
                                  const VerifyOptions& options, V& verifier, H& hasher) noexcept {
  Reason r = Reason::Ok;
  if (chain.empty()) {
    r = Reason::EmptyInput;
  } else if (chain.size() > kMaxChain) {
    r = Reason::ChainTooLong;
  } else if (anchors.size() > kMaxAnchors) {
    r = Reason::TooManyEntries;
  } else if (options.now_unix == 0U) {
    r = Reason::NoTime;
  } else {
    r = Reason::Ok;
  }
  const Result<Certificate> top =
      (r == Reason::Ok) ? ParseCertificate(chain[chain.size() - 1U]) : Fail<Certificate>(r);
  if (!top.ok()) {
    return Fail<VerifiedChain>(ReasonOf(top.detail));
  }
  Reason last = Reason::NoTrustAnchor;
  for (std::size_t i = 0U; i < anchors.size(); ++i) {
    if (der::SameBytes(anchors[i].subject, top.value.issuer)) {
      VerifiedChain out{};
      last = detail::Walk(chain, anchors[i], options, verifier, hasher, out);
      if (last == Reason::Ok) {
        out.anchor_index = i;
        return Result<VerifiedChain>::Success(out);
      }
    }
  }
  return Fail<VerifiedChain>(last);
}

/** @} */

} // namespace se05x::pki

#endif // SE05X_PKI_VERIFY_HPP
