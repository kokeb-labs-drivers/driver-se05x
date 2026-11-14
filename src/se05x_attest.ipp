/**
 * @file se05x_attest.ipp
 * @brief Attestation verifiers, included by `se05x_attest.hpp`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#ifndef SE05X_ATTEST_IPP
#define SE05X_ATTEST_IPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "se05x_secret.hpp"

namespace se05x::attest {

namespace detail {

/// Longest digest (SHA-512).
inline constexpr std::size_t kMaxDigest = 64U;
/// Length of a P-256 coordinate, of `r` and of `s`.
inline constexpr std::size_t kP256 = 32U;
/// Length of an uncompressed P-256 point.
inline constexpr std::size_t kP256Point = 65U;
/// Longest signed message: a digest, five TLVs with three-byte lengths, the data, the attributes,
/// the chip id, the size, the timestamp and (format 1) the freshness.
inline constexpr std::size_t kMaxSigned = kMaxDigest + static_cast<std::size_t>(5U * 4U) +
                                          kMaxResponse + kMaxAttributeBytes + kUniqueIdLength + 2U +
                                          kTimestampLength + kFreshnessLength;

/**
 * @brief The hash of an ECDSA attestation algorithm.
 * @param algo The algorithm.
 * @param hash Receives the hash.
 * @param length Receives its length.
 * @return false for an algorithm the port cannot verify (RSA, Ed25519, plain).
 */
constexpr bool HashOf(AttestationAlgo algo, HashAlg& hash, std::size_t& length) noexcept {
  switch (algo) {
  case AttestationAlgo::EcSha1:
    hash = HashAlg::Sha1;
    length = 20U;
    return true;
  case AttestationAlgo::EcSha224:
    hash = HashAlg::Sha224;
    length = 28U;
    return true;
  case AttestationAlgo::EcSha256:
    hash = HashAlg::Sha256;
    length = 32U;
    return true;
  case AttestationAlgo::EcSha384:
    hash = HashAlg::Sha384;
    length = 48U;
    return true;
  case AttestationAlgo::EcSha512:
    hash = HashAlg::Sha512;
    length = 64U;
    return true;
  case AttestationAlgo::EcPlain:
  case AttestationAlgo::Ed25519:
  case AttestationAlgo::RsaSha256Pss:
  case AttestationAlgo::RsaSha384Pss:
  case AttestationAlgo::RsaSha512Pss:
  case AttestationAlgo::RsaSha256Pkcs1:
  case AttestationAlgo::RsaSha384Pkcs1:
  case AttestationAlgo::RsaSha512Pkcs1:
  default:
    break;
  }
  return false;
}

/**
 * @brief The command without its Le field: the part a format 2 signature hashes (AN12543 3.2.7.2:
 * "the complete APDU except the Le bytes"). Every ISO 7816-4 case is recognised by its lengths.
 * @param command The command APDU.
 * @param plain Receives the command without Le.
 * @return false when `command` is not a well-formed APDU.
 */
constexpr bool WithoutLe(ByteSpan command, ByteSpan& plain) noexcept {
  const std::size_t n = command.size();
  std::size_t keep = 4U; // cases 1 and 2
  if (n < 4U) {
    return false;
  }
  if ((n > 5U) && (command[4] != 0U)) {
    const std::size_t lc = command[4]; // short Lc: case 3 or case 4
    if ((n != (5U + lc)) && (n != (6U + lc))) {
      return false;
    }
    keep = 5U + lc;
  } else if (n > 7U) {
    const std::size_t lc = (static_cast<std::size_t>(command[5]) << 8U) | command[6];
    if ((command[4] != 0U) || (lc == 0U) || ((n != (7U + lc)) && (n != (9U + lc)))) {
      return false; // extended Lc: case 3 or case 4
    }
    keep = 7U + lc;
  } else if ((n == 6U) || ((n == 7U) && (command[4] != 0U))) {
    return false;
  } else {
    keep = 4U; // n is 4 (case 1), 5 (case 2 short) or 7 (case 2 extended)
  }
  plain = command.first(keep);
  return true;
}

/** @brief A fixed buffer the signed message is assembled in. */
class Message {
public:
  /** @brief Append bytes. @param bytes The bytes. */
  void Append(ByteSpan bytes) noexcept {
    if (bytes.size() > (buffer_.size() - size_)) {
      overflow_ = true;
      return;
    }
    for (std::size_t i = 0U; i < bytes.size(); ++i) {
      buffer_[size_ + i] = bytes[i];
    }
    size_ += bytes.size();
  }
  /** @brief Append a TLV with the three-byte length form. @param tag The tag. @param v The value.
   */
  void AppendTlv(uint8_t tag, ByteSpan v) noexcept {
    const std::array<uint8_t, 4> header{tag, 0x82U, static_cast<uint8_t>((v.size() >> 8U) & 0xFFU),
                                        static_cast<uint8_t>(v.size() & 0xFFU)};
    Append(ByteSpan{header});
    Append(v);
  }
  /** @return The message; empty after an overflow. */
  [[nodiscard]] ByteSpan View() const noexcept {
    return overflow_ ? ByteSpan{} : ByteSpan{buffer_.data(), size_};
  }

private:
  std::array<uint8_t, kMaxSigned> buffer_{};
  std::size_t size_{0};
  bool overflow_{false};
};

/**
 * @brief Read one DER INTEGER of a P-256 signature into 32 bytes, big endian, left padded.
 * Strict DER: a positive integer of at most 32 significant bytes, with a leading zero only before
 * a byte whose top bit is set.
 * @param der The signature.
 * @param pos The position; advanced.
 * @param out The 32 bytes.
 * @return true when well formed.
 */
inline bool DerInteger(ByteSpan der, std::size_t& pos, std::span<uint8_t, kP256> out) noexcept {
  if (((der.size() - pos) < 3U) || (der[pos] != 0x02U)) {
    return false;
  }
  std::size_t length = der[pos + 1U];
  std::size_t start = pos + 2U;
  if ((length == 0U) || (length > (der.size() - start)) || (length > (kP256 + 1U))) {
    return false;
  }
  if ((static_cast<uint32_t>(der[start]) & 0x80U) != 0U) {
    return false; // negative
  }
  if ((der[start] == 0U) && (length > 1U)) {
    if ((static_cast<uint32_t>(der[start + 1U]) & 0x80U) == 0U) {
      return false; // a leading zero that is not needed
    }
    ++start;
    --length;
  }
  if (length > kP256) {
    return false;
  }
  for (std::size_t i = 0U; i < kP256; ++i) {
    out[i] = 0U;
  }
  for (std::size_t i = 0U; i < length; ++i) {
    out[kP256 - length + i] = der[start + i];
  }
  pos = start + length;
  return true;
}

/**
 * @brief Convert a DER ECDSA signature (SEQUENCE of two INTEGERs) into raw `r || s` for P-256.
 * @param der The signature.
 * @param raw The 64 bytes.
 * @return true when well formed, with nothing after the sequence.
 */
inline bool DerToRaw(ByteSpan der, std::span<uint8_t, 2U * kP256> raw) noexcept {
  if ((der.size() < 8U) || (der[0] != 0x30U) || (der[1] != (der.size() - 2U)) ||
      ((static_cast<uint32_t>(der[1]) & 0x80U) != 0U)) {
    return false;
  }
  std::size_t pos = 2U;
  return DerInteger(der, pos, raw.first<kP256>()) && DerInteger(der, pos, raw.last<kP256>()) &&
         (pos == der.size());
}

/** @brief What `Verify` checks, gathered. */
struct Inputs {
  const Sent& sent;           ///< What the host sent.
  const AttestedRead& answer; ///< The answer.
  ByteSpan data;              ///< The data.
  ByteSpan signature;         ///< The DER signature.
  ByteSpan key;               ///< The attestation key.
};

/**
 * @brief The shape checks: format, lengths that match the answer, the key form, the command.
 * @param format The verifier's format.
 * @param in The inputs.
 * @param plain Receives the command without Le (format 2).
 * @return `Ok`, `InvalidArgument` or `Unsupported`.
 */
constexpr Error CheckInputs(AttestationFormat format, const Inputs& in, ByteSpan& plain) noexcept {
  HashAlg hash = HashAlg::Sha256;
  std::size_t length = 0U;
  if ((in.answer.format != format) || (in.data.size() != in.answer.data_length) ||
      (in.signature.size() != in.answer.signature_length) || (in.key.size() != kP256Point) ||
      (in.key[0] != 0x04U) || (in.data.size() > kMaxResponse)) {
    return Error::InvalidArgument;
  }
  if ((format == AttestationFormat::V2) && !WithoutLe(in.sent.command, plain)) {
    return Error::InvalidArgument;
  }
  return HashOf(in.sent.algo, hash, length) ? Error::Ok : Error::Unsupported;
}

/**
 * @brief The freshness check (S-09): format 1 compares the echo with the nonce; format 2 compares
 * a returned command, if a lower layer filled one, with the command sent. Constant time (S-08).
 * @param format The format.
 * @param in The inputs.
 * @return true when fresh.
 */
inline bool Fresh(AttestationFormat format, const Inputs& in) noexcept {
  if (format == AttestationFormat::V1) {
    return ct::Equal(ByteSpan{in.answer.freshness}, ByteSpan{in.sent.nonce});
  }
  return (in.answer.echoed_command.length == 0U) ||
         ct::Equal(in.answer.echoed_command.View(), in.sent.command);
}

/**
 * @brief The signed message of format 1: the concatenated values (AN12413 Table 106).
 * @param in The inputs.
 * @param message The message.
 */
inline void BuildV1(const Inputs& in, Message& message) noexcept {
  message.Append(in.data);
  message.Append(in.answer.attributes.View());
  message.Append(ByteSpan{in.answer.timestamp});
  message.Append(ByteSpan{in.answer.freshness});
  message.Append(ByteSpan{in.answer.unique_id});
}

/**
 * @brief The signed message of format 2: the command digest and the TLVs (AN12543 Figure 4).
 * @param in The inputs.
 * @param command_digest The digest of the command without Le.
 * @param message The message.
 */
inline void BuildV2(const Inputs& in, ByteSpan command_digest, Message& message) noexcept {
  const uint32_t size = in.answer.object_size;
  const std::array<uint8_t, 2> size_bytes{static_cast<uint8_t>((size >> 8U) & 0xFFU),
                                          static_cast<uint8_t>(size & 0xFFU)};
  message.Append(command_digest);
  if (!in.data.empty()) {
    message.AppendTlv(apdu::kTag1, in.data);
  }
  message.AppendTlv(apdu::kTag2, ByteSpan{in.answer.unique_id});
  if (in.answer.attributes.length != 0U) {
    message.AppendTlv(apdu::kTag3, in.answer.attributes.View());
  }
  message.AppendTlv(apdu::kTag4, ByteSpan{size_bytes});
  message.AppendTlv(apdu::kTagTimestamp, ByteSpan{in.answer.timestamp});
}

/**
 * @brief The 32-byte ECDSA input of a P-256 key from a digest: its leftmost 32 bytes, or the digest
 * padded with zeros on the left (FIPS 186-4 6.4: the same integer).
 * @param digest The digest.
 * @return The 32 bytes.
 */
constexpr std::array<uint8_t, kP256> P256Input(ByteSpan digest) noexcept {
  std::array<uint8_t, kP256> e{};
  const std::size_t n = (digest.size() < kP256) ? digest.size() : kP256;
  for (std::size_t i = 0U; i < n; ++i) {
    e[kP256 - n + i] = digest[i];
  }
  return e;
}

} // namespace detail

template <PortSet P, AttestationFormat F>
Result<Checked> Verifier<P, F>::Verify(const Sent& sent, const AttestedRead& answer, ByteSpan data,
                                       ByteSpan signature,
                                       std::span<const uint8_t, 65> attestation_key,
                                       const Timestamp& last) noexcept {
  const Detail where{
      .sw = 0U, .command = 0xFFU, .layer = Layer::Apdu, .step = 0U, .attempts_left = 0xFFU};
  const detail::Inputs in{.sent = sent,
                          .answer = answer,
                          .data = data,
                          .signature = signature,
                          .key = ByteSpan{attestation_key}};
  ByteSpan plain{};
  const Error shape = detail::CheckInputs(F, in, plain);
  if (shape != Error::Ok) {
    return Result<Checked>::Failure(shape, where);
  }
  std::array<uint8_t, 2U * detail::kP256> raw{};
  if (!detail::Fresh(F, in) || !TimestampAfter(answer.timestamp, last) ||
      !detail::DerToRaw(signature, raw)) {
    return Result<Checked>::Failure(Error::AttestationInvalid, where);
  }
  HashAlg hash = HashAlg::Sha256;
  std::size_t hash_length = 0U;
  static_cast<void>(detail::HashOf(sent.algo, hash, hash_length));
  auto& crypto = ports_->GetCrypto();
  std::array<uint8_t, detail::kMaxDigest> digest{};
  const MutableByteSpan digest_out{digest.data(), hash_length};
  detail::Message message{};
  bool hashed = true;
  if (F == AttestationFormat::V1) {
    detail::BuildV1(in, message);
  } else {
    hashed = (crypto.Hash(hash, plain, digest_out) == CryptoStatus::Ok);
    if (sent.signed_tlvs.empty()) {
      detail::BuildV2(in, digest_out, message);
    } else {
      message.Append(digest_out);
      message.Append(sent.signed_tlvs); // the bytes the chip returned (A21)
    }
  }
  hashed = hashed && !message.View().empty() &&
           (crypto.Hash(hash, message.View(), digest_out) == CryptoStatus::Ok);
  if (!hashed) {
    return Result<Checked>::Failure(Error::CryptoFailure, where);
  }
  const std::array<uint8_t, detail::kP256> e = detail::P256Input(digest_out);
  const CryptoStatus verified = crypto.EcdsaP256Verify(
      attestation_key, std::span<const uint8_t, 32>{e}, std::span<const uint8_t, 64>{raw});
  if (verified != CryptoStatus::Ok) {
    return Result<Checked>::Failure(
        (verified == CryptoStatus::Mismatch) ? Error::AttestationInvalid : Error::CryptoFailure,
        where);
  }
  return Result<Checked>::Success(Checked{.data_length = answer.data_length,
                                          .timestamp = answer.timestamp,
                                          .unique_id = answer.unique_id,
                                          .object_size = answer.object_size});
}

} // namespace se05x::attest

#endif // SE05X_ATTEST_IPP
