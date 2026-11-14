/**
 * @file se05x_apdu_crypto.hpp
 * @brief The `Codec<C>` specialisations of the commands of the groups Ec, Rsa, Cipher, Aead, Mac,
 * Digest and Kdf.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Layouts: AN12543 Rev 4.5 sections 4.10 to 4.13, 4.16 and 4.17 (applet 7.x) and
 * AN12413 Rev 2.12 sections 4.10 to 4.14 (applet 3.x; ECDAA). INS is INS_CRYPTO (0x03) throughout.
 * Byte order (AN12543 section 7): an EdDSA signature is given and returned in RFC 8032 order, r and
 * s each reversed on the wire; a Montgomery peer key in RFC 7748 order is reversed on the wire, and
 * a plain Montgomery shared secret is reversed back. A failed verification of an authenticated
 * decryption or a MAC (Result 02 with SW 0x9000) is `AuthFailed`, and the output buffer is zeroed.
 */
#ifndef SE05X_APDU_CRYPTO_HPP
#define SE05X_APDU_CRYPTO_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "se05x_apdu.hpp"
#include "se05x_apdu_base.hpp"
#include "se05x_apdu_consts.hpp"
#include "se05x_codec.hpp"
#include "se05x_wire.hpp"

namespace se05x {

namespace apdu::detail {

/// Longest DER ECDSA signature: P-521 (2 x 66 bytes, each with a sign byte, tags and lengths).
inline constexpr std::size_t kMaxDerSignature = 141U;
/// Longest RSA block (RSA-4096).
inline constexpr std::size_t kMaxRsaBlock = 512U;

/**
 * @brief The response of a verification or validation: Result 01 is `Ok`, Result 02 is
 * `AuthFailed`.
 * @param data The body.
 * @return `Ok`, `AuthFailed` or `FrameError`.
 */
constexpr Result<void> RequireSuccess(ByteSpan data) noexcept {
  bool success = false;
  const Result<void> r = DecodeResult(data, success);
  if (!r.ok()) {
    return r;
  }
  return success ? Result<void>::Success() : Fail<void>(Error::AuthFailed);
}

/**
 * @brief The shape `[T1 output] T2 tag-or-Result` of `AEADFinal` and `AEADOneShot` answers, and
 * `T1 MAC-or-Result` of `MACFinal` and `MACOneShot` answers.
 */
struct TaggedAnswer {
  uint8_t result_tag{0};   ///< The tag of the tag or Result element.
  bool validating{false};  ///< A tag is checked (decrypt, validate).
  MutableByteSpan out;     ///< The output buffer (AEAD data); empty for MAC.
  MutableByteSpan tag_out; ///< The tag buffer (encrypt, generate).
};

/**
 * @brief Decode a tagged answer.
 * @param data The body.
 * @param a The shape.
 * @param out_length Receives the output length.
 * @param tag_length Receives the tag length.
 * @return `Ok`, `AuthFailed`, `FrameError` or `BufferTooSmall`.
 */
constexpr Result<void> DecodeTagged(ByteSpan data, const TaggedAnswer& a, std::size_t& out_length,
                                    std::size_t& tag_length) noexcept {
  out_length = 0U;
  tag_length = 0U;
  ReplyParser p(data);
  Result<OptionalTlv> output = Result<OptionalTlv>::Success(OptionalTlv{});
  if (a.result_tag != kTag1) {
    output = p.Optional(kTag1);
  }
  const Result<ByteSpan> tag = p.Need(a.result_tag);
  if (!output.ok() || !tag.ok() || !p.End().ok()) {
    return Fail<void>(Error::FrameError);
  }
  if (a.validating) {
    if ((tag.value.size() != 1U) ||
        ((tag.value[0] != kResultSuccess) && (tag.value[0] != kResultFailure))) {
      return Fail<void>(Error::FrameError);
    }
    if (tag.value[0] == kResultFailure) {
      Wipe(a.out, a.out.size());
      return Fail<void>(Error::AuthFailed);
    }
  } else {
    const Result<void> t = CopyOut(tag.value, a.tag_out, tag_length);
    if (!t.ok()) {
      return t;
    }
  }
  return CopyOut(output.value.value, a.out, out_length);
}

/**
 * @brief The 888-byte rule of `AEADOneShot` (AN12543 4.13.4): the C-APDU length plus AAD and data,
 * each rounded up to a multiple of 16, must not exceed 888. The length is that of the APDU as
 * encoded; the example of the specification leaves TLV[TAG_6] out of its sum.
 * @param apdu The encoded length.
 * @param aad The AAD length.
 * @param data The data length.
 * @return true when the command fits.
 */
constexpr bool AeadOneShotFits(std::size_t apdu, std::size_t aad, std::size_t data) noexcept {
  const auto up16 = [](std::size_t n) { return ((n + 15U) / 16U) * 16U; };
  return (apdu + up16(aad) + up16(data)) <= wire::kAeadOneShotMax;
}

/**
 * @brief Whether a DER signature has the outer SEQUENCE and a length the applet takes.
 * @param signature The signature.
 * @return true when it can be an ASN.1 ECDSA signature.
 */
constexpr bool LooksLikeDer(ByteSpan signature) noexcept {
  return (signature.size() >= 8U) && (signature.size() <= kMaxDerSignature) &&
         (signature[0] == 0x30U);
}

} // namespace apdu::detail

/// `EcdsaSign`: `80 03 0C 09` TLV[TAG_1] key TLV[TAG_2] ECSignatureAlgo TLV[TAG_3] digest, Le;
/// answer TLV[TAG_1] ASN.1 DER signature (AN12543 4.10.1.1). The host hashes; the digest length
/// must be the algorithm's.
template <>
struct Codec<Command::EcdsaSign> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.signature`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error (`Unsupported` for the NOT SUPPORTED `Plain`). */
  static constexpr Result<std::size_t> Encode(const SignArgs& args, MutableByteSpan out) noexcept {
    uint8_t algo = 0U;
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Signature,
                                  apdu::kP2Sign);
    if (args.algo == EcSignAlgo::Plain) {
      w.Refuse(Error::Unsupported);
    }
    if (!apdu::EcSignWire(args.algo, algo) || (args.algo == EcSignAlgo::Ed25519Pure) ||
        (args.key.value == 0U) || (args.input.size() != apdu::EcSignDigestLength(args.algo)) ||
        args.signature.empty()) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(apdu::kTag1, args.key.value);
    w.TlvU8(apdu::kTag2, algo);
    w.Tlv(apdu::kTag3, args.input);
    w.ExpectResponse(apdu::detail::TlvBudget(args.signature.size()));
    return w.Finish();
  }
  /** @brief Refused: the output goes to `args.signature`. @param data The body. @param reply The
   * reply. @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` (not a DER sequence) or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const SignArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    apdu::detail::ReplyParser p(data);
    const Result<ByteSpan> sig = p.Need(apdu::kTag1);
    if (!sig.ok() || !p.End().ok() || !apdu::detail::LooksLikeDer(sig.value)) {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    return apdu::detail::CopyOut(sig.value, args.signature, reply.length);
  }
};

/// `EcdsaVerify`: `80 03 0C 0A` TLV[TAG_1] key TLV[TAG_2] algo TLV[TAG_3] digest TLV[TAG_5] DER
/// signature, Le; answer TLV[TAG_1] Result (AN12543 4.10.2.1).
template <>
struct Codec<Command::EcdsaVerify> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const VerifyArgs& args,
                                              MutableByteSpan out) noexcept {
    uint8_t algo = 0U;
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Signature,
                                  apdu::kP2Verify);
    if (args.algo == EcSignAlgo::Plain) {
      w.Refuse(Error::Unsupported);
    }
    if (!apdu::EcSignWire(args.algo, algo) || (args.algo == EcSignAlgo::Ed25519Pure) ||
        (args.key.value == 0U) || (args.input.size() != apdu::EcSignDigestLength(args.algo)) ||
        !apdu::detail::LooksLikeDer(args.signature)) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(apdu::kTag1, args.key.value);
    w.TlvU8(apdu::kTag2, algo);
    w.Tlv(apdu::kTag3, args.input);
    w.Tlv(apdu::kTag5, args.signature);
    w.ExpectResponse(apdu::detail::TlvBudget(1U));
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply (true: the signature is valid).
   * @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, BoolReply& reply) noexcept {
    return apdu::detail::DecodeResult(data, reply.value);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const VerifyArgs& args, ByteSpan data,
                                       BoolReply& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `EddsaSign`: `80 03 0C 09` TLV[TAG_1] key TLV[TAG_2] A3 TLV[TAG_3] message (1 to 940 bytes;
/// 919 in a UserID session, which the device checks), Le; answer TLV[TAG_1] 64 bytes r || s, each
/// reversed (AN12543 4.10.1.2, 7.1). The reply holds the signature in RFC 8032 order.
template <>
struct Codec<Command::EddsaSign> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.signature`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const SignArgs& args, MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Signature,
                                  apdu::kP2Sign);
    if ((args.algo != EcSignAlgo::Ed25519Pure) || (args.key.value == 0U) || args.input.empty() ||
        (args.input.size() > wire::kEddsaSignMax) ||
        (args.signature.size() < apdu::detail::kEdSignatureLength)) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(apdu::kTag1, args.key.value);
    w.TlvU8(apdu::kTag2, apdu::kSigEd25519Pure);
    w.Tlv(apdu::kTag3, args.input);
    w.ExpectResponse(apdu::detail::TlvBudget(apdu::detail::kEdSignatureLength));
    return w.Finish();
  }
  /** @brief Refused: the output goes to `args.signature`. @param data The body. @param reply The
   * reply. @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const SignArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    apdu::detail::ReplyParser p(data);
    const Result<ByteSpan> sig = p.NeedLength(apdu::kTag1, apdu::detail::kEdSignatureLength);
    if (!sig.ok() || !p.End().ok()) {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    if (args.signature.size() < apdu::detail::kEdSignatureLength) {
      return apdu::detail::Fail<void>(Error::BufferTooSmall);
    }
    apdu::detail::EdSignatureSwap(sig.value, args.signature);
    reply.length = apdu::detail::kEdSignatureLength;
    return Result<void>::Success();
  }
};

/// `EddsaVerify`: `80 03 0C 0A` TLV[TAG_1] key TLV[TAG_2] A3 TLV[TAG_3] message TLV[TAG_5] 64-byte
/// signature (given in RFC 8032 order, sent with r and s reversed), Le; answer TLV[TAG_1] Result.
template <>
struct Codec<Command::EddsaVerify> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const VerifyArgs& args,
                                              MutableByteSpan out) noexcept {
    std::array<uint8_t, apdu::detail::kEdSignatureLength> wire_sig{};
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Signature,
                                  apdu::kP2Verify);
    if ((args.algo != EcSignAlgo::Ed25519Pure) || (args.key.value == 0U) || args.input.empty() ||
        (args.input.size() > wire::kEddsaVerifyMax) ||
        (args.signature.size() != apdu::detail::kEdSignatureLength)) {
      w.Refuse(Error::InvalidArgument);
    } else {
      apdu::detail::EdSignatureSwap(args.signature, MutableByteSpan{wire_sig});
    }
    w.TlvU32(apdu::kTag1, args.key.value);
    w.TlvU8(apdu::kTag2, apdu::kSigEd25519Pure);
    w.Tlv(apdu::kTag3, args.input);
    w.Tlv(apdu::kTag5, ByteSpan{wire_sig});
    w.ExpectResponse(apdu::detail::TlvBudget(1U));
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply (true: valid). @return `Ok` or
   * `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, BoolReply& reply) noexcept {
    return apdu::detail::DecodeResult(data, reply.value);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const VerifyArgs& args, ByteSpan data,
                                       BoolReply& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `EcdaaSign` (applet 3.x): `80 03 0C 09` TLV[TAG_1] key TLV[TAG_2] F4 TLV[TAG_3] 32-byte digest
/// TLV[TAG_4] 32-byte random, Le; answer TLV[TAG_1] r || s (AN12413 Tables 156, 157; the command
/// table prints P2_SIGN although Table 23 also lists P2_SIGN_ECDAA 0x35: P2_SIGN is used).
template <>
struct Codec<Command::EcdaaSign> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.signature`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const EcdaaSignArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Signature,
                                  apdu::kP2Sign);
    if ((args.key.value == 0U) || (args.digest.size() != 32U) || (args.random.size() != 32U) ||
        args.signature.empty()) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(apdu::kTag1, args.key.value);
    w.TlvU8(apdu::kTag2, apdu::kSigEcdaa);
    w.Tlv(apdu::kTag3, args.digest);
    w.Tlv(apdu::kTag4, args.random);
    w.ExpectResponse(apdu::detail::TlvBudget(args.signature.size()));
    return w.Finish();
  }
  /** @brief Refused: the output goes to `args.signature`. @param data The body. @param reply The
   * reply. @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const EcdaaSignArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    return apdu::detail::DecodeTag1Into(data, args.signature, reply.length);
  }
};

namespace apdu::detail {

/**
 * @brief The common part of the two ECDH commands: `80 03 01 0F` TLV[TAG_1] key TLV[TAG_2] peer
 * key [TLV[TAG_4] ECDHAlgo]. A Montgomery peer key is reversed (AN12543 7.2). `SvdpDhPlain` is the
 * default of applet 7.x when TAG_4 is absent and the only behaviour of 3.x, so it sends no TAG_4.
 * @param w The writer.
 * @param key The private key.
 * @param peer The peer key, RFC 7748 order for Montgomery.
 * @param algo The variant.
 */
constexpr void PutEcdh(CommandWriter& w, ObjectId key, ByteSpan peer, EcdhAlgo algo) noexcept {
  if ((key.value == 0U) || !IsPlausiblePeerKey(peer) || !se05x::detail::IsEnumerator(algo)) {
    w.Refuse(Error::InvalidArgument);
  }
  w.TlvU32(kTag1, key.value);
  if (IsMontgomeryKey(peer)) {
    w.TlvReversed(kTag2, peer);
  } else {
    w.Tlv(kTag2, peer);
  }
  if (algo == EcdhAlgo::SvdpDh) {
    w.TlvU8(kTag4, kEcdhSvdpDh);
  }
}

} // namespace apdu::detail

/// `EcdhGenerateSharedSecret`: `80 03 01 0F` (P2_DH) TLV[TAG_1] TLV[TAG_2] [TLV[TAG_4]], Le;
/// answer TLV[TAG_1] the secret (AN12543 4.10.3.1). A plain Montgomery secret comes reversed
/// (P2_DH; P2_DH_REVERSE exists only on 7.x) and is returned in RFC 7748 order.
template <>
struct Codec<Command::EcdhGenerateSharedSecret> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.secret`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const EcdhArgs& args, MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Ec, apdu::kP2Dh);
    if (args.secret.empty()) {
      w.Refuse(Error::InvalidArgument);
    }
    apdu::detail::PutEcdh(w, args.key, args.peer_public, args.algo);
    w.ExpectResponse(apdu::detail::TlvBudget(args.secret.size()));
    return w.Finish();
  }
  /** @brief Refused: the output goes to `args.secret`. @param data The body. @param reply The
   * reply. @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const EcdhArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    const Result<void> r = apdu::detail::DecodeTag1Into(data, args.secret, reply.length);
    if (r.ok() && (args.algo == EcdhAlgo::SvdpDhPlain) &&
        apdu::detail::IsMontgomeryKey(args.peer_public)) {
      wire::ReverseBytes(args.secret.first(reply.length));
    }
    return r;
  }
};

/// `EcdhIntoObject` (applet 7.x): `80 03 01 0F` TLV[TAG_1] TLV[TAG_2] [TLV[TAG_4]] TLV[TAG_7]
/// target (AN12543 4.10.3.1). The target is created first (AN12543 3.7.6.2); `policy` must be null.
template <>
struct Codec<Command::EcdhIntoObject> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const EcdhIntoObjectArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Ec, apdu::kP2Dh);
    if ((args.policy != nullptr) || (args.target.value == 0U)) {
      w.Refuse(Error::InvalidArgument);
    }
    apdu::detail::PutEcdh(w, args.key, args.peer_public, args.algo);
    w.TlvU32(apdu::kTag7, args.target.value);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const EcdhIntoObjectArgs& args, ByteSpan data,
                                       Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `EcPointMultiply` (applet 7.x): `80 03 01 62` TLV[TAG_1] key TLV[TAG_2] point TLV[TAG_4] 06
/// (EC_SVDP_DH_PLAIN_XY), Le; answer TLV[TAG_1] the uncompressed point (AN12543 4.10.4.1).
template <>
struct Codec<Command::EcPointMultiply> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error (`InvalidArgument` unless the point is an uncompressed Weierstrass point). */
  static constexpr Result<std::size_t> Encode(const EcPointMultiplyArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Ec,
                                  apdu::kP2Ecpm);
    if ((args.key.value == 0U) || args.out.empty() ||
        !apdu::detail::IsPlausiblePeerKey(args.point) ||
        apdu::detail::IsMontgomeryKey(args.point)) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(apdu::kTag1, args.key.value);
    w.Tlv(apdu::kTag2, args.point);
    w.TlvU8(apdu::kTag4, apdu::kEcpmDhPlainXy);
    w.ExpectResponse(apdu::detail::TlvBudget(args.out.size()));
    return w.Finish();
  }
  /** @brief Refused: the output goes to `args.out`. @param data The body. @param reply The reply.
   * @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const EcPointMultiplyArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    return apdu::detail::DecodeTag1Into(data, args.out, reply.length);
  }
};

/// `EcPointMultiplyInputObj` (applet 7.x): `80 03 01 62` TLV[TAG_1] key TLV[TAG_3] 4-byte public
/// key object TLV[TAG_4] 06, Le (AN12543 4.10.4.1).
template <>
struct Codec<Command::EcPointMultiplyInputObj> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const EcPointMultiplyObjArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Ec,
                                  apdu::kP2Ecpm);
    if ((args.key.value == 0U) || (args.point.value == 0U) || args.out.empty()) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(apdu::kTag1, args.key.value);
    w.TlvU32(apdu::kTag3, args.point.value);
    w.TlvU8(apdu::kTag4, apdu::kEcpmDhPlainXy);
    w.ExpectResponse(apdu::detail::TlvBudget(args.out.size()));
    return w.Finish();
  }
  /** @brief Refused: the output goes to `args.out`. @param data The body. @param reply The reply.
   * @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const EcPointMultiplyObjArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    return apdu::detail::DecodeTag1Into(data, args.out, reply.length);
  }
};

/// `RsaSign`: `80 03 0C 09` TLV[TAG_1] key TLV[TAG_2] RSASignatureAlgo TLV[TAG_3] digest, Le;
/// answer TLV[TAG_1] signature (AN12543 4.11.1.1). The digest length must be the algorithm's
/// (derived: the specification does not say whether TAG_3 is the digest; the middleware sends it).
template <>
struct Codec<Command::RsaSign> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.signature`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const RsaSignArgs& args,
                                              MutableByteSpan out) noexcept {
    uint8_t algo = 0U;
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Signature,
                                  apdu::kP2Sign);
    if (!apdu::RsaSignWire(args.algo, algo) || (args.key.value == 0U) ||
        (args.input.size() != apdu::RsaSignDigestLength(args.algo)) || args.signature.empty()) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(apdu::kTag1, args.key.value);
    w.TlvU8(apdu::kTag2, algo);
    w.Tlv(apdu::kTag3, args.input);
    w.ExpectResponse(apdu::detail::TlvBudget(args.signature.size()));
    return w.Finish();
  }
  /** @brief Refused: the output goes to `args.signature`. @param data The body. @param reply The
   * reply. @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const RsaSignArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    return apdu::detail::DecodeTag1Into(data, args.signature, reply.length);
  }
};

/// `RsaVerify`: `80 03 0C 0A` TLV[TAG_1] key TLV[TAG_2] algo TLV[TAG_3] digest TLV[TAG_5]
/// signature, Le; answer TLV[TAG_1] Result (AN12543 4.11.2.1).
template <>
struct Codec<Command::RsaVerify> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const RsaVerifyArgs& args,
                                              MutableByteSpan out) noexcept {
    uint8_t algo = 0U;
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Signature,
                                  apdu::kP2Verify);
    if (!apdu::RsaSignWire(args.algo, algo) || (args.key.value == 0U) ||
        (args.input.size() != apdu::RsaSignDigestLength(args.algo)) || args.signature.empty() ||
        (args.signature.size() > apdu::detail::kMaxRsaBlock)) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(apdu::kTag1, args.key.value);
    w.TlvU8(apdu::kTag2, algo);
    w.Tlv(apdu::kTag3, args.input);
    w.Tlv(apdu::kTag5, args.signature);
    w.ExpectResponse(apdu::detail::TlvBudget(1U));
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply (true: valid). @return `Ok` or
   * `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, BoolReply& reply) noexcept {
    return apdu::detail::DecodeResult(data, reply.value);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const RsaVerifyArgs& args, ByteSpan data,
                                       BoolReply& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

namespace apdu::detail {

/**
 * @brief `RSAEncrypt` and `RSADecrypt`: `80 03 02 <37|38>` TLV[TAG_1] key TLV[TAG_2]
 * RSAEncryptionAlgo TLV[TAG_3] data, Le (AN12543 4.11.3.1, 4.11.3.2).
 * @param out The buffer.
 * @param p2 P2.
 * @param args The arguments.
 * @return The length or an error.
 */
constexpr Result<std::size_t> EncodeRsaCrypt(MutableByteSpan out, uint8_t p2,
                                             const RsaCryptArgs& args) noexcept {
  uint8_t algo = 0U;
  CommandWriter w(out, kClaPlain, kInsCrypto, kP1Rsa, p2);
  if (!RsaCryptWire(args.algo, algo) || (args.key.value == 0U) || args.input.empty() ||
      (args.input.size() > kMaxRsaBlock) || args.out.empty()) {
    w.Refuse(Error::InvalidArgument);
  }
  w.TlvU32(kTag1, args.key.value);
  w.TlvU8(kTag2, algo);
  w.Tlv(kTag3, args.input);
  w.ExpectResponse(TlvBudget(args.out.size()));
  return w.Finish();
}

} // namespace apdu::detail

/// `RsaEncrypt`: P2_ENCRYPT_ONESHOT; answer TLV[TAG_1] the cryptogram.
template <>
struct Codec<Command::RsaEncrypt> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const RsaCryptArgs& args,
                                              MutableByteSpan out) noexcept {
    return apdu::detail::EncodeRsaCrypt(out, apdu::kP2EncryptOneShot, args);
  }
  /** @brief Refused: the output goes to `args.out`. @param data The body. @param reply The reply.
   * @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const RsaCryptArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    return apdu::detail::DecodeTag1Into(data, args.out, reply.length);
  }
};

/// `RsaDecrypt`: P2_DECRYPT_ONESHOT; answer TLV[TAG_1] the plain data.
template <>
struct Codec<Command::RsaDecrypt> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const RsaCryptArgs& args,
                                              MutableByteSpan out) noexcept {
    return apdu::detail::EncodeRsaCrypt(out, apdu::kP2DecryptOneShot, args);
  }
  /** @brief Refused: the output goes to `args.out`. @param data The body. @param reply The reply.
   * @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const RsaCryptArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    return apdu::detail::DecodeTag1Into(data, args.out, reply.length);
  }
};

/// `CipherInit`: `80 03 0E <42|43>` TLV[TAG_1] key TLV[TAG_2] 2-byte crypto object [TLV[TAG_4]
/// IV: 8 bytes DES, 16 AES; none for ECB] (AN12543 4.12.1). The chip-generated CTR IV is not
/// offered (the arguments have no IV output).
template <>
struct Codec<Command::CipherInit> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const CipherInitArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Cipher,
                                  args.encrypt ? apdu::kP2Encrypt : apdu::kP2Decrypt);
    if ((args.key.value == 0U) ||
        (!args.iv.empty() && (args.iv.size() != 8U) && (args.iv.size() != 16U))) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(apdu::kTag1, args.key.value);
    w.TlvU16(apdu::kTag2, args.context.value);
    if (!args.iv.empty()) {
      w.Tlv(apdu::kTag4, args.iv);
    }
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const CipherInitArgs& args, ByteSpan data,
                                       Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

namespace apdu::detail {

/**
 * @brief A streaming step `80 03 <p1> <p2>` TLV[TAG_2] crypto object TLV[TAG_3] input, Le.
 * @param out The buffer.
 * @param p1 P1.
 * @param p2 P2.
 * @param args The arguments.
 * @param allow_empty Whether an empty input is allowed (a final step).
 * @return The length or an error.
 */
constexpr Result<std::size_t> EncodeStream(MutableByteSpan out, uint8_t p1, uint8_t p2,
                                           const StreamArgs& args, bool allow_empty) noexcept {
  CommandWriter w(out, kClaPlain, kInsCrypto, p1, p2);
  if (!allow_empty && args.input.empty()) {
    w.Refuse(Error::InvalidArgument);
  }
  w.TlvU16(kTag2, args.context.value);
  w.Tlv(kTag3, args.input);
  w.ExpectResponse(TlvBudget(args.out.size()));
  return w.Finish();
}

} // namespace apdu::detail

/// `CipherUpdate`: `80 03 0E 0C` TLV[TAG_2] TLV[TAG_3], Le; answer [TLV[TAG_1] output].
template <>
struct Codec<Command::CipherUpdate> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const StreamArgs& args,
                                              MutableByteSpan out) noexcept {
    return apdu::detail::EncodeStream(out, apdu::kP1Cipher, apdu::kP2Update, args, false);
  }
  /** @brief Refused: the output goes to `args.out`. @param data The body. @param reply The reply.
   * @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const StreamArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    return apdu::detail::DecodeOptionalTag1Into(data, args.out, reply.length);
  }
};

/// `CipherFinal`: `80 03 0E 0D` TLV[TAG_2] TLV[TAG_3] (may be empty), Le; answer [TLV[TAG_1]].
template <>
struct Codec<Command::CipherFinal> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const StreamArgs& args,
                                              MutableByteSpan out) noexcept {
    return apdu::detail::EncodeStream(out, apdu::kP1Cipher, apdu::kP2Final, args, true);
  }
  /** @brief Refused: the output goes to `args.out`. @param data The body. @param reply The reply.
   * @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const StreamArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    return apdu::detail::DecodeOptionalTag1Into(data, args.out, reply.length);
  }
};

/// `CipherOneShot`: `80 03 0E <37|38>` TLV[TAG_1] key TLV[TAG_2] CipherMode TLV[TAG_3] input
/// [TLV[TAG_4] IV], Le; answer TLV[TAG_1] output (AN12543 4.12.4). A NOT SUPPORTED mode of
/// Table 46 is `Unsupported`; the IV length must be the mode's.
template <>
struct Codec<Command::CipherOneShot> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const CipherOneShotArgs& args,
                                              MutableByteSpan out) noexcept {
    const apdu::CipherModeInfo mode = apdu::CipherModeOf(args.mode);
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Cipher,
                                  args.encrypt ? apdu::kP2EncryptOneShot : apdu::kP2DecryptOneShot);
    if (detail::IsEnumerator(args.mode) && (mode.wire == 0U)) {
      w.Refuse(Error::Unsupported);
    }
    if ((mode.wire == 0U) || (args.key.value == 0U) || args.input.empty() ||
        (args.iv.size() != mode.iv_length) || args.out.empty()) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(apdu::kTag1, args.key.value);
    w.TlvU8(apdu::kTag2, mode.wire);
    w.Tlv(apdu::kTag3, args.input);
    if (!args.iv.empty()) {
      w.Tlv(apdu::kTag4, args.iv);
    }
    w.ExpectResponse(apdu::detail::TlvBudget(args.out.size()));
    return w.Finish();
  }
  /** @brief Refused: the output goes to `args.out`. @param data The body. @param reply The reply.
   * @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const CipherOneShotArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    return apdu::detail::DecodeTag1Into(data, args.out, reply.length);
  }
};

namespace apdu::detail {

/**
 * @brief Whether an AEAD nonce length suits the mode (GCM 12 to 60, CCM 7 to 13).
 * @param mode The mode.
 * @param length The nonce length.
 * @return true when valid.
 */
constexpr bool AeadIvValid(AeadMode mode, std::size_t length) noexcept {
  if (mode == AeadMode::AesGcm) {
    return (length >= kGcmIvMin) && (length <= kGcmIvMax);
  }
  return (length >= kCcmNonceMin) && (length <= kCcmNonceMax);
}

/**
 * @brief Whether a CCM tag length is valid: 4 to 16, even (NIST SP 800-38C).
 * @param length The length.
 * @return true when valid.
 */
constexpr bool CcmTagValid(std::size_t length) noexcept {
  return (length >= kAeadTagMin) && (length <= kAeadTagMax) && ((length % 2U) == 0U);
}

} // namespace apdu::detail

namespace apdu::detail {

/**
 * @brief Whether the tag buffers of an authenticated operation suit its direction: a 4 to
 * 16-byte tag to check when decrypting, a buffer for the 16-byte tag when encrypting, never both.
 * @param decrypt The direction.
 * @param tag_in The tag to check.
 * @param tag_out The tag buffer.
 * @return true when valid.
 */
constexpr bool AeadTagsValid(bool decrypt, ByteSpan tag_in, MutableByteSpan tag_out) noexcept {
  if (decrypt) {
    return (tag_in.size() >= kAeadTagMin) && (tag_in.size() <= kAeadTagMax) && tag_out.empty();
  }
  return (tag_out.size() >= kAeadTagMax) && tag_in.empty();
}

/**
 * @brief The argument checks of `AEADOneShot` (GCM only; CCM is refused by the caller).
 * @param args The arguments.
 * @return true when valid.
 */
constexpr bool AeadOneShotArgsValid(const AeadOneShotArgs& args) noexcept {
  return (args.mode == AeadMode::AesGcm) && (args.key.value != 0U) &&
         AeadIvValid(AeadMode::AesGcm, args.iv.size()) &&
         !(args.input.empty() && args.aad.empty()) && (args.out.size() >= args.input.size()) &&
         AeadTagsValid(!args.encrypt, args.tag_in, args.tag_out);
}

/**
 * @brief The argument checks of `HKDF` (AN12543 Tables 265, 268). Expand-only takes no salt: its
 * TAG_3 is an IV that turns the command into the NIST SP 800-108 feedback-mode KDF (Table 268),
 * which a caller asking for the RFC 5869 expand step does not expect, so a salt is refused.
 * @param args The arguments.
 * @return true when valid.
 */
constexpr bool HkdfArgsValid(const HkdfArgs& args) noexcept {
  const bool expand_only = (args.mode == HkdfMode::ExpandOnly);
  const bool to_object = (args.target.value != 0U);
  const bool out_ok = to_object ? args.out.empty() : (args.out.size() >= args.derived_length);
  const bool lengths = (args.salt.size() <= kHkdfSaltMax) && (args.info.size() <= kHkdfInfoMax) &&
                       (!expand_only || args.salt.empty()) && (args.derived_length != 0U) &&
                       (args.derived_length <= kHkdfOutputMax);
  return se05x::detail::IsEnumerator(args.mode) && (args.digest != DigestMode::Sha224) &&
         (args.key.value != 0U) && lengths && out_ok;
}

} // namespace apdu::detail

/// `AeadInit` (applet 7.x): `80 03 11 <42|43>` TLV[TAG_1] key TLV[TAG_2] crypto object TLV[TAG_5]
/// nonce, or its 2-byte length when the chip generates it (encryption only), then for CCM
/// TLV[TAG_6] AAD length TLV[TAG_7] message length TLV[TAG_8] tag length (AN12543 4.13.1). A
/// generated nonce comes back in TLV[TAG_3] and goes to `iv_out`.
template <>
struct Codec<Command::AeadInit> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.iv_out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const AeadInitArgs& args,
                                              MutableByteSpan out) noexcept {
    const bool generated = args.iv.empty();
    const std::size_t nonce = generated ? args.iv_out.size() : args.iv.size();
    const bool ccm = (args.mode == AeadMode::AesCcm);
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Aead,
                                  args.encrypt ? apdu::kP2Encrypt : apdu::kP2Decrypt);
    if (!detail::IsEnumerator(args.mode) || (args.key.value == 0U) ||
        !apdu::detail::AeadIvValid(args.mode, nonce) || (generated && !args.encrypt) ||
        (!generated && !args.iv_out.empty()) ||
        (ccm && !apdu::detail::CcmTagValid(args.tag_length))) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(apdu::kTag1, args.key.value);
    w.TlvU16(apdu::kTag2, args.context.value);
    if (generated) {
      w.TlvU16(apdu::kTag5, static_cast<uint16_t>(nonce & 0xFFFFU));
    } else {
      w.Tlv(apdu::kTag5, args.iv);
    }
    if (ccm) {
      w.TlvU16(apdu::kTag6, args.aad_length);
      w.TlvU16(apdu::kTag7, args.data_length);
      w.TlvU16(apdu::kTag8, args.tag_length);
    }
    if (generated) {
      w.ExpectResponse(apdu::detail::TlvBudget(nonce));
    }
    return w.Finish();
  }
  /** @brief Refused: the output goes to `args.iv_out`. @param data The body. @param reply The
   * reply. @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, Empty& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(const AeadInitArgs& args, ByteSpan data,
                                       Empty& reply) noexcept {
    static_cast<void>(reply);
    if (!args.iv.empty()) {
      return apdu::detail::ExpectEmpty(data);
    }
    apdu::detail::ReplyParser p(data);
    const Result<ByteSpan> iv = p.NeedLength(apdu::kTag3, args.iv_out.size());
    if (!iv.ok() || !p.End().ok()) {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    std::size_t written = 0U;
    return apdu::detail::CopyOut(iv.value, args.iv_out, written);
  }
};

/// `AeadUpdateAad` (applet 7.x): `80 03 11 0C` TLV[TAG_2] crypto object TLV[TAG_4] AAD (AN12543
/// 4.13.2: AAD and data never in one APDU, AAD first).
template <>
struct Codec<Command::AeadUpdateAad> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const AeadAadArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Aead,
                                  apdu::kP2Update);
    if (args.aad.empty()) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU16(apdu::kTag2, args.context.value);
    w.Tlv(apdu::kTag4, args.aad);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const AeadAadArgs& args, ByteSpan data,
                                       Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `AeadUpdate` (applet 7.x): `80 03 11 0C` TLV[TAG_2] TLV[TAG_3] data, Le; answer [TLV[TAG_1]].
template <>
struct Codec<Command::AeadUpdate> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const StreamArgs& args,
                                              MutableByteSpan out) noexcept {
    return apdu::detail::EncodeStream(out, apdu::kP1Aead, apdu::kP2Update, args, false);
  }
  /** @brief Refused: the output goes to `args.out`. @param data The body. @param reply The reply.
   * @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const StreamArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    return apdu::detail::DecodeOptionalTag1Into(data, args.out, reply.length);
  }
};

/// `AeadFinal` (applet 7.x): `80 03 11 0D` TLV[TAG_2] crypto object [TLV[TAG_6] tag, decrypt
/// only], Le; answer [TLV[TAG_1] output] TLV[TAG_2] 16-byte tag (encrypt) or Result (decrypt)
/// (AN12543 Tables 247, 248). The command carries no input, so `input` must be empty; the
/// direction is told by which tag buffer is given.
template <>
struct Codec<Command::AeadFinal> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `out` and `tag_out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const AeadFinalArgs& args,
                                              MutableByteSpan out) noexcept {
    const bool decrypt = !args.tag_in.empty();
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Aead,
                                  apdu::kP2Final);
    if (!args.input.empty() || !apdu::detail::AeadTagsValid(decrypt, args.tag_in, args.tag_out)) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU16(apdu::kTag2, args.context.value);
    if (decrypt) {
      w.Tlv(apdu::kTag6, args.tag_in);
    }
    w.ExpectResponse(apdu::detail::TlvBudget(args.out.size()) + apdu::detail::TlvBudget(16U));
    return w.Finish();
  }
  /** @brief Refused: the output goes to the caller buffers. @param data The body. @param reply The
   * reply. @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply (the
   * output length). @return `Ok`, `AuthFailed` (tag mismatch; `out` zeroed), `FrameError` or
   * `BufferTooSmall`. */
  static constexpr Result<void> Decode(const AeadFinalArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    std::size_t tag_length = 0U;
    const apdu::detail::TaggedAnswer shape{.result_tag = apdu::kTag2,
                                           .validating = !args.tag_in.empty(),
                                           .out = args.out,
                                           .tag_out = args.tag_out};
    return apdu::detail::DecodeTagged(data, shape, reply.length, tag_length);
  }
};

/// `AeadOneShot` (applet 7.x): `80 03 11 <37|38>` TLV[TAG_1] key TLV[TAG_2] B0 (GCM only)
/// [TLV[TAG_3] data] [TLV[TAG_4] AAD] TLV[TAG_5] nonce TLV[TAG_6] tag length 16 (encrypt) or the
/// tag (decrypt, 4 to 16), Le (AN12543 4.13.4); the 888-byte rule applies. A chip nonce is not
/// offered (the arguments have no nonce output).
template <>
struct Codec<Command::AeadOneShot> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `out` and `tag_out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error (`Unsupported` for CCM, which has no one-shot). */
  static constexpr Result<std::size_t> Encode(const AeadOneShotArgs& args,
                                              MutableByteSpan out) noexcept {
    const bool decrypt = !args.encrypt;
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Aead,
                                  args.encrypt ? apdu::kP2EncryptOneShot : apdu::kP2DecryptOneShot);
    if (args.mode == AeadMode::AesCcm) {
      w.Refuse(Error::Unsupported);
    }
    if (!apdu::detail::AeadOneShotArgsValid(args)) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(apdu::kTag1, args.key.value);
    w.TlvU8(apdu::kTag2, 0xB0U);
    if (!args.input.empty()) {
      w.Tlv(apdu::kTag3, args.input);
    }
    if (!args.aad.empty()) {
      w.Tlv(apdu::kTag4, args.aad);
    }
    w.Tlv(apdu::kTag5, args.iv);
    if (decrypt) {
      w.Tlv(apdu::kTag6, args.tag_in);
    } else {
      w.TlvU16(apdu::kTag6, static_cast<uint16_t>(apdu::kAeadTagMax));
    }
    w.ExpectResponse(apdu::detail::TlvBudget(args.out.size()) + apdu::detail::TlvBudget(16U));
    const Result<std::size_t> r = w.Finish();
    if (r.ok() && !apdu::detail::AeadOneShotFits(r.value, args.aad.size(), args.input.size())) {
      apdu::detail::Wipe(out, r.value);
      return apdu::detail::Fail<std::size_t>(Error::InvalidArgument);
    }
    return r;
  }
  /** @brief Refused: the output goes to the caller buffers. @param data The body. @param reply The
   * reply. @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `AuthFailed` (tag mismatch; `out` zeroed), `FrameError` or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const AeadOneShotArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    std::size_t tag_length = 0U;
    const apdu::detail::TaggedAnswer shape{.result_tag = apdu::kTag2,
                                           .validating = !args.encrypt,
                                           .out = args.out,
                                           .tag_out = args.tag_out};
    return apdu::detail::DecodeTagged(data, shape, reply.length, tag_length);
  }
};

/// `MacInit`: `80 03 0D <03|44>` TLV[TAG_1] key TLV[TAG_2] crypto object (AN12543 4.14.1).
template <>
struct Codec<Command::MacInit> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const MacInitArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Mac,
                                  args.generate ? apdu::kP2Generate : apdu::kP2Validate);
    if (args.key.value == 0U) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(apdu::kTag1, args.key.value);
    w.TlvU16(apdu::kTag2, args.context.value);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const MacInitArgs& args, ByteSpan data,
                                       Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `MacUpdate`: `80 03 0D 0C` TLV[TAG_1] data TLV[TAG_2] crypto object (AN12543 4.14.2: the data
/// comes first in this command).
template <>
struct Codec<Command::MacUpdate> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const InputArgs& args, MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Mac,
                                  apdu::kP2Update);
    if (args.input.empty()) {
      w.Refuse(Error::InvalidArgument);
    }
    w.Tlv(apdu::kTag1, args.input);
    w.TlvU16(apdu::kTag2, args.context.value);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const InputArgs& args, ByteSpan data,
                                       Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `MacFinal`: `80 03 0D 0D` TLV[TAG_1] data TLV[TAG_2] crypto object [TLV[TAG_3] MAC to
/// validate], Le; answer TLV[TAG_1] the MAC or Result (AN12543 4.14.3).
template <>
struct Codec<Command::MacFinal> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `tag_out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const MacFinalArgs& args,
                                              MutableByteSpan out) noexcept {
    const bool validate = !args.tag_in.empty();
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Mac,
                                  apdu::kP2Final);
    if (validate == !args.tag_out.empty()) {
      w.Refuse(Error::InvalidArgument);
    }
    w.Tlv(apdu::kTag1, args.input);
    w.TlvU16(apdu::kTag2, args.context.value);
    if (validate) {
      w.Tlv(apdu::kTag3, args.tag_in);
    }
    w.ExpectResponse(apdu::detail::TlvBudget(validate ? 1U : args.tag_out.size()));
    return w.Finish();
  }
  /** @brief Refused: the output goes to `tag_out`. @param data The body. @param reply The reply.
   * @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply (the
   * MAC length; 0 after a validation). @return `Ok`, `AuthFailed` (mismatch), `FrameError` or
   * `BufferTooSmall`. */
  static constexpr Result<void> Decode(const MacFinalArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    std::size_t output = 0U;
    const apdu::detail::TaggedAnswer shape{.result_tag = apdu::kTag1,
                                           .validating = !args.tag_in.empty(),
                                           .out = MutableByteSpan{},
                                           .tag_out = args.tag_out};
    return apdu::detail::DecodeTagged(data, shape, output, reply.length);
  }
};

/// `MacOneShot`: `80 03 0D <45|46>` TLV[TAG_1] key TLV[TAG_2] MACAlgo TLV[TAG_3] data
/// [TLV[TAG_5] MAC to validate], Le; answer TLV[TAG_1] the MAC or Result (AN12543 4.14.4).
/// DES_CMAC8 is only in DigestOneShot (Table 43): `Unsupported` here.
template <>
struct Codec<Command::MacOneShot> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `tag_out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const MacOneShotArgs& args,
                                              MutableByteSpan out) noexcept {
    uint8_t algo = 0U;
    apdu::detail::CommandWriter w(
        out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Mac,
        args.generate ? apdu::kP2GenerateOneShot : apdu::kP2ValidateOneShot);
    if (args.algo == MacAlgo::DesCmac8) {
      w.Refuse(Error::Unsupported);
    }
    if (!apdu::MacWire(args.algo, algo) || (args.key.value == 0U) || args.input.empty() ||
        (args.generate && (args.tag_out.empty() || !args.tag_in.empty())) ||
        (!args.generate && (args.tag_in.empty() || !args.tag_out.empty()))) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(apdu::kTag1, args.key.value);
    w.TlvU8(apdu::kTag2, algo);
    w.Tlv(apdu::kTag3, args.input);
    if (!args.generate) {
      w.Tlv(apdu::kTag5, args.tag_in);
    }
    w.ExpectResponse(apdu::detail::TlvBudget(args.generate ? args.tag_out.size() : 1U));
    return w.Finish();
  }
  /** @brief Refused: the output goes to `tag_out`. @param data The body. @param reply The reply.
   * @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply (the
   * MAC length; 0 after a validation). @return `Ok`, `AuthFailed`, `FrameError` or
   * `BufferTooSmall`. */
  static constexpr Result<void> Decode(const MacOneShotArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    std::size_t output = 0U;
    const apdu::detail::TaggedAnswer shape{.result_tag = apdu::kTag1,
                                           .validating = !args.generate,
                                           .out = MutableByteSpan{},
                                           .tag_out = args.tag_out};
    return apdu::detail::DecodeTagged(data, shape, output, reply.length);
  }
};

/// `DigestInit`: `80 03 00 0B` TLV[TAG_2] crypto object (AN12543 4.19.1).
template <>
struct Codec<Command::DigestInit> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const CryptoObjectArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Default,
                                  apdu::kP2Init);
    w.TlvU16(apdu::kTag2, args.context.value);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const CryptoObjectArgs& args, ByteSpan data,
                                       Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `DigestUpdate`: `80 03 00 0C` TLV[TAG_2] crypto object TLV[TAG_3] data (AN12543 4.19.2).
template <>
struct Codec<Command::DigestUpdate> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const InputArgs& args, MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Default,
                                  apdu::kP2Update);
    if (args.input.empty()) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU16(apdu::kTag2, args.context.value);
    w.Tlv(apdu::kTag3, args.input);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const InputArgs& args, ByteSpan data,
                                       Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `DigestFinal`: `80 03 00 0D` TLV[TAG_2] crypto object TLV[TAG_3] last data, Le; answer
/// TLV[TAG_1] the digest (AN12543 4.19.3).
template <>
struct Codec<Command::DigestFinal> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const DigestFinalArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Default,
                                  apdu::kP2Final);
    if (args.out.empty()) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU16(apdu::kTag2, args.context.value);
    w.Tlv(apdu::kTag3, args.input);
    w.ExpectResponse(apdu::detail::TlvBudget(args.out.size()));
    return w.Finish();
  }
  /** @brief Refused: the output goes to `args.out`. @param data The body. @param reply The reply.
   * @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const DigestFinalArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    return apdu::detail::DecodeTag1Into(data, args.out, reply.length);
  }
};

/// `DigestOneShot`: `80 03 00 0E` TLV[TAG_1] DigestMode TLV[TAG_2] data, Le; answer TLV[TAG_1]
/// the digest, of the mode's length (AN12543 4.19.4).
template <>
struct Codec<Command::DigestOneShot> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const DigestOneShotArgs& args,
                                              MutableByteSpan out) noexcept {
    uint8_t mode = 0U;
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Default,
                                  apdu::kP2OneShot);
    if (!apdu::DigestWire(args.mode, mode) || args.input.empty() ||
        (args.out.size() < apdu::DigestLength(args.mode))) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU8(apdu::kTag1, mode);
    w.Tlv(apdu::kTag2, args.input);
    w.ExpectResponse(apdu::detail::TlvBudget(apdu::DigestLength(args.mode)));
    return w.Finish();
  }
  /** @brief Refused: the output goes to `args.out`. @param data The body. @param reply The reply.
   * @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` (another length than the mode's) or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const DigestOneShotArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    apdu::detail::ReplyParser p(data);
    const Result<ByteSpan> v = p.NeedLength(apdu::kTag1, apdu::DigestLength(args.mode));
    if (!v.ok() || !p.End().ok()) {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    return apdu::detail::CopyOut(v.value, args.out, reply.length);
  }
};

/// `Hkdf`: `80 03 00 <2D|2F>` TLV[TAG_1] key TLV[TAG_2] DigestMode (not SHA-224) [TLV[TAG_3] salt
/// at most 64 bytes; never with expand-only] [TLV[TAG_4] info, at most 80 bytes]
/// TLV[TAG_5] 2-byte length 1 to 768 [TLV[TAG_7] target], Le when the output comes back (AN12543
/// 4.15.1, Tables 265 and 268). Expand-only (P2 2F) is applet 7.x.
template <>
struct Codec<Command::Hkdf> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const HkdfArgs& args, MutableByteSpan out) noexcept {
    uint8_t digest = 0U;
    const bool expand_only = (args.mode == HkdfMode::ExpandOnly);
    const bool to_object = (args.target.value != 0U);
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Default,
                                  expand_only ? apdu::kP2HkdfExpandOnly : apdu::kP2Hkdf);
    if (!apdu::DigestWire(args.digest, digest) || !apdu::detail::HkdfArgsValid(args)) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(apdu::kTag1, args.key.value);
    w.TlvU8(apdu::kTag2, digest);
    if (!args.salt.empty()) {
      w.Tlv(apdu::kTag3, args.salt);
    }
    if (!args.info.empty()) {
      w.Tlv(apdu::kTag4, args.info);
    }
    w.TlvU16(apdu::kTag5, args.derived_length);
    if (to_object) {
      w.TlvU32(apdu::kTag7, args.target.value);
    } else {
      w.ExpectResponse(apdu::detail::TlvBudget(args.derived_length));
    }
    return w.Finish();
  }
  /** @brief Refused: the output goes to `args.out`. @param data The body. @param reply The reply.
   * @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const HkdfArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    if (args.target.value != 0U) {
      reply.length = 0U;
      return apdu::detail::ExpectEmpty(data);
    }
    apdu::detail::ReplyParser p(data);
    const Result<ByteSpan> v = p.NeedLength(apdu::kTag1, args.derived_length);
    if (!v.ok() || !p.End().ok()) {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    return apdu::detail::CopyOut(v.value, args.out, reply.length);
  }
};

/// `Pbkdf2`: `80 03 00 2E` TLV[TAG_1] password key [TLV[TAG_2] salt, at most 64] TLV[TAG_3]
/// 2-byte iterations 1 to 0x7FFF TLV[TAG_4] 2-byte length 1 to 512 [TLV[TAG_5] HMAC MACAlgo, sent
/// only for a hash other than SHA-1, applet 7.x], Le; answer TLV[TAG_1] (AN12543 4.15.2.1, Table
/// 271; AN12413 Table 207).
template <>
struct Codec<Command::Pbkdf2> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const Pbkdf2Args& args,
                                              MutableByteSpan out) noexcept {
    uint8_t mac = 0U;
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Default,
                                  apdu::kP2Pbkdf);
    if (!apdu::HmacOfDigest(args.digest, mac) || (args.key.value == 0U) ||
        (args.salt.size() > apdu::kPbkdfSaltMax) || (args.iterations == 0U) ||
        (args.iterations > apdu::kPbkdfIterationsMax) || (args.derived_length == 0U) ||
        (args.derived_length > apdu::kPbkdfOutputMax) || (args.out.size() < args.derived_length)) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(apdu::kTag1, args.key.value);
    if (!args.salt.empty()) {
      w.Tlv(apdu::kTag2, args.salt);
    }
    w.TlvU16(apdu::kTag3, args.iterations);
    w.TlvU16(apdu::kTag4, args.derived_length);
    if (args.digest != DigestMode::Sha1) {
      // TAG_5 exists on 7.x only (AN12543 Table 271, default HMAC_SHA1; AN12413 Table 207 has no
      // TAG_5), so the default is left out and an HMAC-SHA1 derivation is the same on 3.x and 7.x.
      w.TlvU8(apdu::kTag5, mac);
    }
    w.ExpectResponse(apdu::detail::TlvBudget(args.derived_length));
    return w.Finish();
  }
  /** @brief Refused: the output goes to `args.out`. @param data The body. @param reply The reply.
   * @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const Pbkdf2Args& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    apdu::detail::ReplyParser p(data);
    const Result<ByteSpan> v = p.NeedLength(apdu::kTag1, args.derived_length);
    if (!v.ok() || !p.End().ok()) {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    return apdu::detail::CopyOut(v.value, args.out, reply.length);
  }
};

/// `TlsGenerateRandom`: `80 03 0F 49 00`; answer TLV[TAG_1] 32 bytes (AN12543 4.17.1).
template <>
struct Codec<Command::TlsGenerateRandom> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const TlsRandomArgs& args,
                                              MutableByteSpan out) noexcept {
    if (args.out.size() < apdu::kTlsRandom) {
      return apdu::detail::Fail<std::size_t>(Error::InvalidArgument);
    }
    return apdu::detail::EncodeBare(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Tls,
                                    apdu::kP2Random, apdu::detail::TlvBudget(apdu::kTlsRandom));
  }
  /** @brief Refused: the output goes to `args.out`. @param data The body. @param reply The reply.
   * @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const TlsRandomArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    apdu::detail::ReplyParser p(data);
    const Result<ByteSpan> v = p.NeedLength(apdu::kTag1, apdu::kTlsRandom);
    if (!v.ok() || !p.End().ok()) {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    return apdu::detail::CopyOut(v.value, args.out, reply.length);
  }
};

/// `TlsCalculatePreMasterSecret`: `80 03 0F 4A` (AN12543 4.17.2, Table 304). With no `input`, a
/// PSK key exchange: TLV[TAG_1] PSK TLV[TAG_3] target. With `input`, an RSA or EC key exchange:
/// TLV[TAG_2] key pair TLV[TAG_3] target TLV[TAG_4] input. The two PSK-plus-key exchanges need two
/// key ids, which the arguments cannot carry: not offered. The target exists before; `policy` must
/// be null.
template <>
struct Codec<Command::TlsCalculatePreMasterSecret> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const TlsPmsArgs& args,
                                              MutableByteSpan out) noexcept {
    const bool psk = args.input.empty();
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Tls,
                                  apdu::kP2TlsPms);
    if ((args.key.value == 0U) || (args.target.value == 0U) || (args.policy != nullptr)) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(psk ? apdu::kTag1 : apdu::kTag2, args.key.value);
    w.TlvU32(apdu::kTag3, args.target.value);
    if (!psk) {
      w.Tlv(apdu::kTag4, args.input);
    }
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const TlsPmsArgs& args, ByteSpan data,
                                       Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

namespace apdu::detail {

/**
 * @brief Whether a label is exactly an ASCII text.
 * @param label The label.
 * @param text The text.
 * @return true when equal.
 */
template <std::size_t N>
constexpr bool LabelIs(ByteSpan label, const std::array<uint8_t, N>& text) noexcept {
  if (label.size() != N) {
    return false;
  }
  bool same = true;
  for (std::size_t i = 0U; i < N; ++i) {
    same = same && (label[i] == text[i]);
  }
  return same;
}

/**
 * @brief The P2 of `TLSPerformPRF` (AN12543 4.17.3). The role names whose random the chip
 * generated: as the TLS client the host passes the server random, P2_TLS_PRF_SRV_HELLO for the
 * label "master secret" and P2_TLS_PRF_SRV_RND for "key expansion"; as the server it passes the
 * client random, P2_TLS_PRF_CLI_HELLO and P2_TLS_PRF_CLI_RND. A 64-byte random is P2_PRF_BOTH
 * whatever the label and the role.
 * @param label The label.
 * @param random The random.
 * @param role The host's role.
 * @param p2 Receives P2.
 * @return false for a 32-byte random with another label, a random of another length, or a role
 * that is not an enumerator.
 */
constexpr bool TlsPrfP2(ByteSpan label, ByteSpan random, TlsRole role, uint8_t& p2) noexcept {
  constexpr std::array<uint8_t, 13> kMaster{0x6DU, 0x61U, 0x73U, 0x74U, 0x65U, 0x72U, 0x20U,
                                            0x73U, 0x65U, 0x63U, 0x72U, 0x65U, 0x74U};
  constexpr std::array<uint8_t, 13> kExpansion{0x6BU, 0x65U, 0x79U, 0x20U, 0x65U, 0x78U, 0x70U,
                                               0x61U, 0x6EU, 0x73U, 0x69U, 0x6FU, 0x6EU};
  if (random.size() == (2U * kTlsRandom)) {
    p2 = kP2PrfBoth;
    return true;
  }
  if ((random.size() != kTlsRandom) || !se05x::detail::IsEnumerator(role)) {
    return false;
  }
  const bool server = role == TlsRole::Server;
  if (LabelIs(label, kMaster)) {
    p2 = server ? kP2TlsPrfCliHello : kP2TlsPrfSrvHello;
    return true;
  }
  if (LabelIs(label, kExpansion)) {
    p2 = server ? kP2TlsPrfCliRnd : kP2TlsPrfSrvRnd;
    return true;
  }
  return false;
}

} // namespace apdu::detail

/// `TlsPerformPrf`: `80 03 0F <P2>` TLV[TAG_1] key TLV[TAG_2] DigestMode (not SHA-224) TLV[TAG_3]
/// label 1 to 64 TLV[TAG_4] random TLV[TAG_5] 2-byte length 1 to 512, Le (AN12543 Table 308; P2
/// as `apdu::detail::TlsPrfP2`).
template <>
struct Codec<Command::TlsPerformPrf> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const TlsPrfArgs& args,
                                              MutableByteSpan out) noexcept {
    uint8_t digest = 0U;
    uint8_t p2 = 0U;
    const bool p2_ok = apdu::detail::TlsPrfP2(args.label, args.random, args.role, p2);
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Tls, p2);
    if (!p2_ok || !apdu::DigestWire(args.digest, digest) || (args.digest == DigestMode::Sha224) ||
        (args.key.value == 0U) || args.label.empty() || (args.label.size() > apdu::kTlsLabelMax) ||
        (args.length == 0U) || (args.length > apdu::kTlsPrfOutputMax) ||
        (args.out.size() < args.length)) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(apdu::kTag1, args.key.value);
    w.TlvU8(apdu::kTag2, digest);
    w.Tlv(apdu::kTag3, args.label);
    w.Tlv(apdu::kTag4, args.random);
    w.TlvU16(apdu::kTag5, args.length);
    w.ExpectResponse(apdu::detail::TlvBudget(args.length));
    return w.Finish();
  }
  /** @brief Refused: the output goes to `args.out`. @param data The body. @param reply The reply.
   * @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const TlsPrfArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    apdu::detail::ReplyParser p(data);
    const Result<ByteSpan> v = p.NeedLength(apdu::kTag1, args.length);
    if (!v.ok() || !p.End().ok()) {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    return apdu::detail::CopyOut(v.value, args.out, reply.length);
  }
};

} // namespace se05x

#endif // SE05X_APDU_CRYPTO_HPP
