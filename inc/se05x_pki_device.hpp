/**
 * @file se05x_pki_device.hpp
 * @brief The chip side of the PKI layer: a CSR signer over a key in the chip, reading a public key
 * back, and storing certificates and trust anchors in binary objects with read-only policies.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Every call goes through `Device<P>`, so the capability gate, the role
 * check, secure messaging and the recovery rules of the device apply unchanged; a device failure
 * comes back with the device's own `Error` and `Detail`.
 *
 * Storage rules (AN12543 4.7.1.4 WriteBinary, 3.7.1 policies):
 *
 * - A certificate is written by one WriteBinary command that creates the object with its policy
 *   and its whole content, because a read-only policy refuses every later write. So it must fit
 *   one command (`MaxStoredCertificate()`, about 980 bytes with the default policy); a larger one
 *   is refused with `ObjectTooLarge` before anything is sent.
 * - The policy may not grant `Write` to anyone, nor `Delete` to everybody (authentication object
 *   0): either would let the certificate be replaced (`PolicyAllowsWrite`, nothing sent).
 *   `CertificatePolicy(admin)` builds the default: everybody reads; the administrator may also
 *   delete, for rotation by delete-and-create. A certificate nobody may delete can never change:
 *   that is an irreversible operation, created only by
 *   `irreversible::Operations::PlanCreateImmutableObject`; `Device` refuses it everywhere else
 *   (`IrreversibleNotConfirmed`, nothing sent).
 * - An existing object is never overwritten (`ObjectExists`); the object is read back and compared
 *   after the write (`ReadBackMismatch`).
 *
 * Not verified on hardware: the chip model of the tests stores binary objects and P-256 keys only;
 * the P-384 and Ed25519 paths are checked against the codecs, not a chip.
 */
#ifndef SE05X_PKI_DEVICE_HPP
#define SE05X_PKI_DEVICE_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

#include "se05x_device.hpp"
#include "se05x_objects.hpp"
#include "se05x_pki_der.hpp"
#include "se05x_pki_types.hpp"
#include "se05x_pki_verify.hpp"
#include "se05x_pki_x509.hpp"
#include "se05x_policy.hpp"
#include "se05x_status.hpp"
#include "se05x_types.hpp"
#include "se05x_wire.hpp"

namespace se05x::pki {

/**
 * @defgroup se05x_pki_device PKI on the chip
 * @brief `DeviceSigner`, `ReadPublicKey()`, certificate storage.
 * @{
 */

/**
 * @brief A `CsrSigner` over a key pair inside the chip: ECDSASign with the precomputed digest
 * (AN12543 4.10.1.1) or EdDSASign with the message (4.10.1.2, at most 940 bytes, 919 in a UserID
 * session; not on SE052F). The private key never leaves the chip.
 * @tparam P The port set of the device.
 */
template <PortSet P>
class DeviceSigner {
public:
  /**
   * @brief Bind the device and the key.
   * @param device The open device; it must outlive the signer.
   * @param key The key pair object.
   * @param type Its key type.
   */
  DeviceSigner(Device<P>& device, ObjectId key, KeyType type) noexcept
      : device_(&device), key_(key), type_(type) {}
  /** @return The algorithm of the key type (`AlgorithmFor`). */
  [[nodiscard]] SignatureAlgorithm Algorithm() const noexcept {
    return AlgorithmFor(type_);
  }
  /**
   * @brief Sign on the chip.
   * @param input The digest (ECDSA) or the message (Ed25519).
   * @param signature Receives the DER signature (ECDSA) or 64 bytes (Ed25519).
   * @return The length, `InvalidInput` (a digest of the wrong length), or the device's error.
   */
  Result<std::size_t> Sign(ByteSpan input, MutableByteSpan signature) noexcept {
    if (type_ == KeyType::Ed25519) {
      const auto r = device_->template Execute<Command::EddsaSign>(SignArgs{
          .key = key_, .algo = EcSignAlgo::Ed25519Pure, .input = input, .signature = signature});
      return r.ok() ? Result<std::size_t>::Success(r.value.length)
                    : Result<std::size_t>::Failure(r.error, r.detail);
    }
    const SignatureAlgorithm algorithm = AlgorithmFor(type_);
    if (input.size() != DigestLength(algorithm)) {
      return Fail<std::size_t>(Reason::InvalidInput);
    }
    const EcSignAlgo algo =
        (algorithm == SignatureAlgorithm::EcdsaSha384) ? EcSignAlgo::Sha384 : EcSignAlgo::Sha256;
    return device_->EcdsaSign(key_, algo, input, signature);
  }

private:
  Device<P>* device_;
  ObjectId key_;
  KeyType type_;
};

/**
 * @brief Read the public key of a key pair in the chip (ReadObject, AN12543 4.7.3.1). An Ed25519
 * key comes from the chip byte-reversed (AN12543 7.1) and is returned in RFC 8032 order.
 * @tparam P The port set.
 * @param device The open device.
 * @param key The key pair (or public key) object.
 * @param type The key type it must have.
 * @param out The buffer, at least `PublicKeyLength(type)` bytes.
 * @return The key (its bytes point into `out`); `BufferTooSmall`, `BadPublicKey` (another length
 * or form), or the device's error.
 */
template <PortSet P>
Result<PublicKey> ReadPublicKey(Device<P>& device, ObjectId key, KeyType type,
                                MutableByteSpan out) noexcept {
  const std::size_t length = PublicKeyLength(type);
  if ((length == 0U) || (out.size() < length)) {
    return Fail<PublicKey>((length == 0U) ? Reason::InvalidInput : Reason::BufferTooSmall);
  }
  const Result<std::size_t> read = device.ReadObject(key, 0U, out);
  if (!read.ok()) {
    return Result<PublicKey>::Failure(read.error, read.detail);
  }
  const MutableByteSpan bytes = out.first(std::min(read.value, out.size()));
  if ((bytes.size() != length) || ((type != KeyType::Ed25519) && (bytes[0] != 0x04U))) {
    return Fail<PublicKey>(Reason::BadPublicKey);
  }
  if (type == KeyType::Ed25519) {
    wire::ReverseBytes(bytes);
  }
  return Result<PublicKey>::Success(PublicKey{.type = type, .bytes = ByteSpan{bytes}});
}

/**
 * @brief The default policy of a stored certificate or trust anchor: everybody may read it;
 * `admin` may read and delete it (rotation). Nobody may write it.
 * @tparam G The applet generation of the chip.
 * @param admin The administrator's authentication object. Without one the certificate could never
 * be deleted: an irreversible operation (`irreversible::Operations::PlanCreateImmutableObject`).
 * @return The policy; `InvalidArgument` for `AuthObject{}`; or the builder's error.
 */
template <AppletGeneration G>
constexpr Result<Policy> CertificatePolicy(AuthObject admin) noexcept {
  if (admin.id.value == 0U) {
    return Result<Policy>::Failure(Error::InvalidArgument);
  }
  PolicyBuilder<G, ObjectClass::BinaryFile, Profile::Strict> builder{};
  static_cast<void>(builder.ForAllOthers().template Allow<Rule::Read>());
  static_cast<void>(builder.For(admin).template Allow<Rule::Read>().template Allow<Rule::Delete>());
  return builder.Build();
}

/**
 * @brief Whether a policy keeps a stored certificate unchanged: no entry allows Write, and the
 * entry for everybody (authentication object 0) does not allow Delete.
 * @param policy The policy bytes.
 * @return `Ok`, `PolicyAllowsWrite`, or `InvalidInput` (empty or malformed).
 */
constexpr Reason CheckReadOnlyPolicy(ByteSpan policy) noexcept {
  if (policy.empty() || (ValidatePolicyBytes(policy) != Error::Ok)) {
    return Reason::InvalidInput;
  }
  const uint32_t write = policy::HeaderBit(Rule::Write);
  const uint32_t remove = policy::HeaderBit(Rule::Delete);
  std::size_t pos = 0U;
  for (std::size_t n = 0U; (pos < policy.size()) && (n < policy.size()); ++n) {
    uint32_t auth = 0U;
    uint32_t header = 0U;
    for (std::size_t i = 0U; i < 4U; ++i) {
      auth = (auth << 8U) | policy[pos + 1U + i];
      header = (header << 8U) | policy[pos + 5U + i];
    }
    if (((header & write) != 0U) || ((auth == 0U) && ((header & remove) != 0U))) {
      return Reason::PolicyAllowsWrite;
    }
    pos += 1U + static_cast<std::size_t>(policy[pos]);
  }
  return Reason::Ok;
}

/**
 * @brief The longest certificate one WriteBinary command creates with a policy (AN12543 4.7.1.4:
 * TLV[TAG_POLICY] TLV[TAG_1] id TLV[TAG_3] length TLV[TAG_4] data in the 1024-byte command body).
 * @param policy The policy.
 * @return The most certificate bytes.
 */
constexpr std::size_t MaxStoredCertificate(const Policy& policy) noexcept {
  const std::size_t p = policy.Bytes().size();
  const std::size_t policy_tlv = 1U + der::LengthFieldSize(p) + p;
  constexpr std::size_t kFixed = 6U + 4U + 1U + 3U; // TAG_1 id, TAG_3 length, TAG_4 header
  return kMaxApduPayload - policy_tlv - kFixed;
}

namespace detail {
/**
 * @brief Compare what was read back with what was written.
 * @param back The read: its length, or the device's error.
 * @param scratch The bytes read.
 * @param written The bytes written.
 * @return `Ok`; `ReadBackMismatch` (other bytes, or fewer); or the read's error.
 */
constexpr Result<void> CheckReadBack(const Result<std::size_t>& back, ByteSpan scratch,
                                     ByteSpan written) noexcept {
  if (!back.ok()) {
    return Result<void>::Failure(back.error, back.detail);
  }
  const bool same = (back.value == written.size()) && (scratch.size() >= written.size()) &&
                    der::SameBytes(scratch.first(written.size()), written);
  return same ? Result<void>::Success() : Fail<void>(Reason::ReadBackMismatch);
}
} // namespace detail

/**
 * @brief Store a certificate in a new binary object with a read-only policy, then read it back.
 * @tparam P The port set.
 * @param device The open device (inside the session the policy's authentication object needs).
 * @param id The new object.
 * @param der The certificate; it must parse (`ParseCertificate()`).
 * @param policy The object's policy (`CertificatePolicy()`); see the file comment.
 * @param scratch A buffer of at least `der.size()` bytes for the read-back.
 * @return `Ok`; `PolicyAllowsWrite`, `InvalidInput`, `ObjectTooLarge` or a parse reason (nothing
 * sent); `ObjectExists` (nothing written); `ReadBackMismatch`; or the device's error.
 */
template <PortSet P>
Result<void> StoreCertificate(Device<P>& device, ObjectId id, ByteSpan der, const Policy& policy,
                              MutableByteSpan scratch) noexcept {
  const Result<Certificate> parsed = ParseCertificate(der);
  Reason r = parsed.ok() ? CheckReadOnlyPolicy(policy.Bytes()) : ReasonOf(parsed.detail);
  if ((r == Reason::Ok) && (der.size() > MaxStoredCertificate(policy))) {
    r = Reason::ObjectTooLarge;
  }
  if ((r == Reason::Ok) && (scratch.size() < der.size())) {
    r = Reason::BufferTooSmall;
  }
  if (r != Reason::Ok) {
    return Fail<void>(r);
  }
  const Result<bool> exists = device.ObjectExists(id);
  if (!exists.ok() || exists.value) {
    return exists.ok() ? Result<void>::Failure(Error::ObjectExists, Detail{})
                       : Result<void>::Failure(exists.error, exists.detail);
  }
  const auto length = static_cast<uint16_t>(der.size() & 0xFFFFU);
  const Result<void> written = device.WriteBinary(id, policy, 0U, der, length);
  if (!written.ok()) {
    return written;
  }
  return detail::CheckReadBack(device.ReadObject(id, 0U, scratch.first(der.size())), scratch, der);
}

/**
 * @brief Read a stored certificate and parse it.
 * @tparam P The port set.
 * @param device The open device.
 * @param id The object.
 * @param buffer Receives the bytes; the certificate points into it.
 * @return The certificate; `NotACertificate` (the object is not exactly one DER element), a parse
 * reason, or the device's error.
 */
template <PortSet P>
Result<Certificate> ReadCertificate(Device<P>& device, ObjectId id,
                                    MutableByteSpan buffer) noexcept {
  const Result<std::size_t> read = device.ReadObject(id, 0U, buffer);
  if (!read.ok()) {
    return Result<Certificate>::Failure(read.error, read.detail);
  }
  const ByteSpan bytes = ByteSpan{buffer}.first(std::min(read.value, buffer.size()));
  der::Reader reader(bytes);
  der::Element element{};
  if ((reader.Expect(der::kSequence, element) != Reason::Ok) || (reader.Finish() != Reason::Ok)) {
    return Fail<Certificate>(Reason::NotACertificate);
  }
  return ParseCertificate(bytes);
}

/**
 * @brief Read a stored CA certificate as a trust anchor.
 * @tparam P The port set.
 * @param device The open device.
 * @param id The object.
 * @param buffer Receives the bytes; the anchor points into it.
 * @return The anchor; as `ReadCertificate()` and `AnchorFromCertificate()`.
 */
template <PortSet P>
Result<TrustAnchor> LoadTrustAnchor(Device<P>& device, ObjectId id,
                                    MutableByteSpan buffer) noexcept {
  const Result<Certificate> cert = ReadCertificate(device, id, buffer);
  if (!cert.ok()) {
    return Result<TrustAnchor>::Failure(cert.error, cert.detail);
  }
  return AnchorFromCertificate(cert.value);
}

/** @} */

} // namespace se05x::pki

#endif // SE05X_PKI_DEVICE_HPP
