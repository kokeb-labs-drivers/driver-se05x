/**
 * @file se05x_apdu_objects.hpp
 * @brief The codecs (`Codec<C>`) of the commands of the groups ObjectWrite, ObjectRead,
 * Curve and CryptoObject.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Layouts: AN12543 Rev 4.5 sections 4.7 to 4.9 (applet 7.x) and AN12413 Rev 2.12
 * sections 4.7 to 4.9 (applet 3.x). TLV order in a command is the order of the tables (AN12543
 * 4.1.5). Every key length is checked against the curve before anything is sent (errata JOS.1: an
 * EC key of the wrong length resets the chip). Edwards and Montgomery keys are taken in RFC 8032 /
 * RFC 7748 order and reversed on the wire (AN12543 section 7); `ReadObject` returns what the chip
 * stores, so a reader of such a public key reverses it with `wire::ReverseBytes`.
 */
#ifndef SE05X_APDU_OBJECTS_HPP
#define SE05X_APDU_OBJECTS_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "se05x_apdu.hpp"
#include "se05x_apdu_base.hpp"
#include "se05x_apdu_consts.hpp"
#include "se05x_codec.hpp"
#include "se05x_objects.hpp"

namespace se05x {

namespace apdu::detail {

/**
 * @brief Whether an object id may be written or deleted from the host: not 0, not in the range NXP
 * provisions (AN13030 p. 157; AN12436), which the driver never changes.
 * @param id The object.
 * @return true for a writable id.
 */
constexpr bool Writable(ObjectId id) noexcept {
  return (id.value != 0U) && (id.value < kReservedNxpBase);
}

/**
 * @brief A component without its leading zero bytes (an ASN.1 integer may carry a sign byte); the
 * middleware strips them too. At least one byte stays.
 * @param bytes The component.
 * @return The view without leading zeros.
 */
constexpr ByteSpan StripLeadingZeros(ByteSpan bytes) noexcept {
  std::size_t skip = 0U;
  while (((skip + 1U) < bytes.size()) && (bytes[skip] == 0U)) {
    ++skip;
  }
  return bytes.subspan(skip);
}

/**
 * @brief Whether a key size is an RSABitLength (AN12543 Table 40).
 * @param bits The size.
 * @return true for 512, 1024, 1152, 2048, 3072 and 4096.
 */
constexpr bool IsRsaBits(uint16_t bits) noexcept {
  constexpr std::array<uint16_t, 6> kBits{512U, 1024U, 1152U, 2048U, 3072U, 4096U};
  bool found = false;
  for (const uint16_t b : kBits) {
    found = found || (b == bits);
  }
  return found;
}

/** @brief The RSA components in TLV order (TAG_3 to TAG_10). */
struct RsaComponents {
  std::array<ByteSpan, 8> part{}; ///< p, q, dp, dq, q^-1, e, d, n; empty when absent.
  std::size_t count{0};           ///< Present components.
  uint8_t key_type{0};            ///< P1KeyType.
  uint8_t p2{0};                  ///< P2_DEFAULT (CRT and public) or P2_RAW (private exponent).
  bool valid{false};              ///< A combination of AN12543 Table 117.
};

/**
 * @brief Classify the components of `WriteRsaKey` against AN12543 Table 117 and check their sizes.
 * @param parts The components.
 * @param bits The key size.
 * @return The components in order and the P1 and P2 they need; `valid` false otherwise.
 */
constexpr RsaComponents ClassifyRsa(const RsaKeyParts& parts, uint16_t bits) noexcept {
  RsaComponents c{};
  c.part = {parts.prime_p,        parts.prime_q,         parts.exponent_dp,      parts.exponent_dq,
            parts.coefficient_iq, parts.public_exponent, parts.private_exponent, parts.modulus};
  uint32_t mask = 0U;
  for (std::size_t i = 0U; i < c.part.size(); ++i) {
    if (!c.part[i].empty()) {
      c.part[i] = StripLeadingZeros(c.part[i]);
      mask |= (1U << i);
      ++c.count;
    }
  }
  constexpr uint32_t kCrt = 0x1FU; // p q dp dq q^-1
  constexpr uint32_t kE = 0x20U;
  constexpr uint32_t kD = 0x40U;
  constexpr uint32_t kN = 0x80U;
  c.p2 = kP2Default;
  if (mask == (kCrt | kE | kN)) {
    c.key_type = kP1KeyPair;
  } else if (mask == (kE | kD | kN)) {
    c.key_type = kP1KeyPair;
    c.p2 = kP2Raw;
  } else if (mask == kCrt) {
    c.key_type = kP1Private;
  } else if (mask == (kD | kN)) {
    c.key_type = kP1Private;
    c.p2 = kP2Raw;
  } else if (mask == (kE | kN)) {
    c.key_type = kP1Public;
  } else {
    return c;
  }
  const std::size_t full = static_cast<std::size_t>(bits) / 8U;
  bool sizes = IsRsaBits(bits);
  for (std::size_t i = 0U; i < c.part.size(); ++i) {
    const std::size_t limit = (i < 5U) ? (full / 2U) : full;
    sizes = sizes && (c.part[i].size() <= limit);
  }
  sizes = sizes && (((mask & kN) == 0U) || (c.part[7].size() == full));
  c.valid = sizes;
  return c;
}

/**
 * @brief Whether a symmetric key value has a length the applet takes (AN12543 4.7.1.3): AES 16, 24
 * or 32 bytes, DES 8, 16 or 24, HMAC 1 to 256; an RFC 3394 wrapped value is 8 bytes longer and its
 * plain length must be a multiple of 8.
 * @param type The key type.
 * @param length The value length.
 * @param wrapped Whether the value is wrapped.
 * @return true when valid.
 */
constexpr bool SymmLengthValid(SymmKeyType type, std::size_t length, bool wrapped) noexcept {
  if (wrapped && ((length < 16U) || ((length % 8U) != 0U))) {
    return false;
  }
  const std::size_t plain = wrapped ? (length - 8U) : length;
  switch (type) {
  case SymmKeyType::Aes:
    return (plain == 16U) || (plain == 24U) || (plain == 32U);
  case SymmKeyType::Des:
    return (plain == 8U) || (plain == 16U) || (plain == 24U);
  case SymmKeyType::Hmac:
    return (plain >= 1U) && (plain <= kHmacKeyMax);
  default:
    break;
  }
  return false;
}

/**
 * @brief Check an EC key value against its curve.
 * @param info The curve.
 * @param key The value.
 * @param is_private Whether it is the private key.
 * @return `Ok`, `Unsupported` (an import whose length the specification leaves open) or
 * `InvalidArgument`.
 */
constexpr Error CheckEcKey(const CurveInfo& info, ByteSpan key, bool is_private) noexcept {
  if (key.empty()) {
    return Error::Ok;
  }
  if (is_private) {
    if (info.private_length == 0U) {
      return Error::Unsupported;
    }
    return (key.size() == info.private_length) ? Error::Ok : Error::InvalidArgument;
  }
  if ((key.size() != info.public_length) || (info.weierstrass && (key[0] != 0x04U))) {
    return Error::InvalidArgument;
  }
  return Error::Ok;
}

/**
 * @brief The argument checks of `WriteEcKey`.
 * @param args The arguments.
 * @param curve The curve.
 * @param ins Receives the INS byte.
 * @return `Ok`, `Unsupported` (a private key length the specification leaves open) or
 * `InvalidArgument`.
 */
constexpr Error EcKeyArgsError(const WriteEcKeyArgs& args, const CurveInfo& curve,
                               uint8_t& ins) noexcept {
  const Error priv = CheckEcKey(curve, args.private_key, true);
  const Error pub = CheckEcKey(curve, args.public_key, false);
  if (!HasPolicy(args.policy) || !WriteIns(args.lifetime, ins) || (curve.id == 0U) ||
      !Writable(args.id) || (args.private_key.empty() && args.public_key.empty())) {
    return Error::InvalidArgument;
  }
  return (priv != Error::Ok) ? priv : pub;
}

/**
 * @brief The response budget of an attested read: the data and the attestation overhead.
 * @param data The data buffer.
 * @return The budget.
 */
constexpr std::size_t AttestedBudget(MutableByteSpan data) noexcept {
  return TlvBudget(data.size()) + kAttestedOverhead;
}

/**
 * @brief Write the offset and length TLVs of a binary read: both or neither (AN12543 Table 127).
 * @param w The writer.
 * @param offset The offset.
 * @param length The length; with the offset 0 nothing is written (the whole object).
 */
constexpr void PutRange(CommandWriter& w, uint16_t offset, uint16_t length) noexcept {
  if ((offset != 0U) || (length != 0U)) {
    w.TlvU16(kTag2, offset);
    w.TlvU16(kTag3, length);
  }
}

/**
 * @brief Write the RSA component TLV when one is selected.
 * @param w The writer.
 * @param tag The tag.
 * @param component The component, or `kNoRsaComponent`.
 * @param last The highest component allowed.
 */
constexpr void PutRsaComponent(CommandWriter& w, uint8_t tag, uint8_t component,
                               uint8_t last) noexcept {
  if (component == kNoRsaComponent) {
    return;
  }
  if (component > last) {
    w.Refuse(Error::InvalidArgument);
    return;
  }
  w.TlvU8(tag, component);
}

} // namespace apdu::detail

namespace codecs {

/// `WriteEcKey`: `80 01[|80] <P1KeyType|01> 00` TLV[TAG_POLICY] TLV[TAG_1] id TLV[TAG_2] curve
/// [TLV[TAG_3] private] [TLV[TAG_4] public] [TLV[TAG_11] version] (AN12543 Table 115).
struct WriteEcKeyCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const WriteEcKeyArgs& args,
                                              MutableByteSpan out) noexcept {
    const apdu::CurveInfo curve = apdu::CurveOf(args.curve);
    uint8_t ins = 0U;
    const Error error = apdu::detail::EcKeyArgsError(args, curve, ins);
    uint8_t key_type = apdu::kP1Public;
    if (!args.private_key.empty()) {
      key_type = args.public_key.empty() ? apdu::kP1Private : apdu::kP1KeyPair;
    }
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, ins,
                                  static_cast<uint8_t>(key_type | apdu::kP1Ec), apdu::kP2Default);
    if (error != Error::Ok) {
      w.Refuse(error);
    }
    apdu::detail::PutPolicy(w, args.policy);
    w.TlvU32(apdu::kTag1, args.id.value);
    w.TlvU8(apdu::kTag2, curve.id);
    if (!args.private_key.empty()) {
      if (curve.montgomery) {
        w.TlvReversed(apdu::kTag3, args.private_key);
      } else {
        w.Tlv(apdu::kTag3, args.private_key); // the EdDSA secret key is not reversed (7.1)
      }
    }
    if (!args.public_key.empty()) {
      if (curve.montgomery || curve.edwards) {
        w.TlvReversed(apdu::kTag4, args.public_key);
      } else {
        w.Tlv(apdu::kTag4, args.public_key);
      }
    }
    apdu::detail::PutVersion(w, args.version);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, const Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const WriteEcKeyArgs& args, ByteSpan data,
                                       const Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::WriteEcKey` (selects it for `Codec<Command::WriteEcKey>`). */
constexpr WriteEcKeyCodec CodecFor(CommandTag<Command::WriteEcKey> /*tag*/) noexcept {
  return {};
}

/// `GenerateEcKey`: `80 01[|80] 61 00` TLV[TAG_POLICY] TLV[TAG_1] id TLV[TAG_2] curve
/// [TLV[TAG_11] version] (AN12543 4.7.1.1: both key values absent and P1_KEY_PAIR).
struct GenerateEcKeyCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const GenerateEcKeyArgs& args,
                                              MutableByteSpan out) noexcept {
    const apdu::CurveInfo curve = apdu::CurveOf(args.curve);
    uint8_t ins = 0U;
    const bool valid = apdu::detail::HasPolicy(args.policy) &&
                       apdu::detail::WriteIns(args.lifetime, ins) && (curve.id != 0U) &&
                       apdu::detail::Writable(args.id);
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, ins,
                                  static_cast<uint8_t>(apdu::kP1KeyPair | apdu::kP1Ec),
                                  apdu::kP2Default);
    if (!valid) {
      w.Refuse(Error::InvalidArgument);
    }
    apdu::detail::PutPolicy(w, args.policy);
    w.TlvU32(apdu::kTag1, args.id.value);
    w.TlvU8(apdu::kTag2, curve.id);
    apdu::detail::PutVersion(w, args.version);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, const Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const GenerateEcKeyArgs& args, ByteSpan data,
                                       const Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::GenerateEcKey` (selects it for `Codec<Command::GenerateEcKey>`).
 */
constexpr GenerateEcKeyCodec CodecFor(CommandTag<Command::GenerateEcKey> /*tag*/) noexcept {
  return {};
}

/// `WriteRsaKey`: an externally generated key takes one APDU per component (AN12543 4.7.1.2):
/// `Step(args, 0)` carries the key type in P1, the policy, the id, the size and the first
/// component; each next step the id and one more component, in TLV order (TAG_3 to TAG_10). P2 is
/// P2_RAW for a key in the private-exponent form and P2_DEFAULT otherwise, on every step (the
/// middleware does the same). `Encode` is `Step(args, 0)`; the device sends `Steps(args)` APDUs.
struct WriteRsaKeyCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /**
   * @brief The number of APDUs the key takes.
   * @param args The arguments.
   * @return The number of components, or 0 when the combination is not one of Table 117.
   */
  static constexpr std::size_t Steps(const WriteRsaKeyArgs& args) noexcept {
    const apdu::detail::RsaComponents c = apdu::detail::ClassifyRsa(args.parts, args.key_bits);
    return c.valid ? c.count : 0U;
  }
  /**
   * @brief Encode step `step` of the key insertion.
   * @param args The arguments.
   * @param step 0 to `Steps(args) - 1`.
   * @param out The buffer.
   * @return The length or an error (`InvalidArgument` for an invalid combination, size or step).
   */
  static constexpr Result<std::size_t> Step(const WriteRsaKeyArgs& args, std::size_t step,
                                            MutableByteSpan out) noexcept {
    const apdu::detail::RsaComponents c = apdu::detail::ClassifyRsa(args.parts, args.key_bits);
    uint8_t ins = 0U;
    const bool first = (step == 0U);
    const bool valid = c.valid && (step < c.count) && apdu::detail::WriteIns(args.lifetime, ins) &&
                       apdu::detail::Writable(args.id) &&
                       (!first || apdu::detail::HasPolicy(args.policy));
    const uint8_t p1 = first ? static_cast<uint8_t>(c.key_type | apdu::kP1Rsa) : apdu::kP1Rsa;
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, ins, p1, c.p2);
    if (!valid) {
      w.Refuse(Error::InvalidArgument);
    }
    if (first) {
      apdu::detail::PutPolicy(w, args.policy);
    }
    w.TlvU32(apdu::kTag1, args.id.value);
    if (first) {
      w.TlvU16(apdu::kTag2, args.key_bits);
    }
    std::size_t seen = 0U;
    for (std::size_t i = 0U; i < c.part.size(); ++i) {
      if (!c.part[i].empty()) {
        if (seen == step) {
          w.Tlv(static_cast<uint8_t>(apdu::kTag3 + i), c.part[i]);
        }
        ++seen;
      }
    }
    apdu::detail::PutVersion(w, args.version);
    return w.Finish();
  }
  /** @brief Encode the first step. @param args The arguments. @param out The buffer.
   * @return As `Step(args, 0, out)`. */
  static constexpr Result<std::size_t> Encode(const WriteRsaKeyArgs& args,
                                              MutableByteSpan out) noexcept {
    return Step(args, 0U, out);
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, const Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const WriteRsaKeyArgs& args, ByteSpan data,
                                       const Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::WriteRsaKey` (selects it for `Codec<Command::WriteRsaKey>`). */
constexpr WriteRsaKeyCodec CodecFor(CommandTag<Command::WriteRsaKey> /*tag*/) noexcept {
  return {};
}

/// `GenerateRsaKey`: `80 01[|80] 62 00` TLV[TAG_POLICY] TLV[TAG_1] id TLV[TAG_2] size: one APDU, a
/// CRT key pair (P2_DEFAULT; AN12543 4.7.1.2).
struct GenerateRsaKeyCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const GenerateRsaKeyArgs& args,
                                              MutableByteSpan out) noexcept {
    uint8_t ins = 0U;
    const bool valid = apdu::detail::HasPolicy(args.policy) &&
                       apdu::detail::WriteIns(args.lifetime, ins) &&
                       apdu::detail::IsRsaBits(args.key_bits) && apdu::detail::Writable(args.id);
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, ins,
                                  static_cast<uint8_t>(apdu::kP1KeyPair | apdu::kP1Rsa),
                                  apdu::kP2Default);
    if (!valid) {
      w.Refuse(Error::InvalidArgument);
    }
    apdu::detail::PutPolicy(w, args.policy);
    w.TlvU32(apdu::kTag1, args.id.value);
    w.TlvU16(apdu::kTag2, args.key_bits);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, const Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const GenerateRsaKeyArgs& args, ByteSpan data,
                                       const Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::GenerateRsaKey` (selects it for
 * `Codec<Command::GenerateRsaKey>`). */
constexpr GenerateRsaKeyCodec CodecFor(CommandTag<Command::GenerateRsaKey> /*tag*/) noexcept {
  return {};
}

/// `WriteSymmKey`: `80 01[|80] <03|04|05> 00` TLV[TAG_POLICY] TLV[TAG_1] id [TLV[TAG_2] KEK id]
/// TLV[TAG_3] key [TLV[TAG_11] version] (AN12543 Table 118). The key bytes are a secret (S-01):
/// on any error the buffer is zeroed.
struct WriteSymmKeyCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const WriteSymmKeyArgs& args,
                                              MutableByteSpan out) noexcept {
    constexpr std::array<uint8_t, 3> kP1{apdu::kP1Aes, apdu::kP1Des, apdu::kP1Hmac};
    uint8_t ins = 0U;
    const bool wrapped = (args.kek.value != 0U);
    const bool type_ok = detail::IsEnumerator(args.type);
    const bool valid = type_ok && apdu::detail::HasPolicy(args.policy) &&
                       apdu::detail::WriteIns(args.lifetime, ins) &&
                       apdu::detail::Writable(args.id) &&
                       apdu::detail::SymmLengthValid(args.type, args.key.size(), wrapped);
    const uint8_t p1 =
        type_ok ? kP1[static_cast<std::size_t>(detail::ToUnderlying(args.type))] : apdu::kP1Aes;
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, ins, p1, apdu::kP2Default);
    if (!valid) {
      w.Refuse(Error::InvalidArgument);
    }
    apdu::detail::PutPolicy(w, args.policy);
    w.TlvU32(apdu::kTag1, args.id.value);
    if (wrapped) {
      w.TlvU32(apdu::kTag2, args.kek.value);
    }
    w.Tlv(apdu::kTag3, args.key);
    apdu::detail::PutVersion(w, args.version);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, const Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const WriteSymmKeyArgs& args, ByteSpan data,
                                       const Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::WriteSymmKey` (selects it for `Codec<Command::WriteSymmKey>`). */
constexpr WriteSymmKeyCodec CodecFor(CommandTag<Command::WriteSymmKey> /*tag*/) noexcept {
  return {};
}

/// `WriteBinary`: `80 01 06 00` (AN12543 Table 119). Creation (`file_length` not 0):
/// TLV[TAG_POLICY] TLV[TAG_1] id [TLV[TAG_2] offset] TLV[TAG_3] length [TLV[TAG_4] data]
/// [TLV[TAG_11] version]; the policy is required. Update (`file_length` 0): TLV[TAG_1] [TLV[TAG_2]]
/// TLV[TAG_4] data [TLV[TAG_11]]; a policy is refused (the chip rejects TAG_POLICY on an existing
/// object).
struct WriteBinaryCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const WriteBinaryArgs& args,
                                              MutableByteSpan out) noexcept {
    const bool create = (args.file_length != 0U);
    const std::size_t end = static_cast<std::size_t>(args.offset) + args.data.size();
    bool valid = apdu::detail::Writable(args.id);
    if (create) {
      valid = valid && apdu::detail::HasPolicy(args.policy) &&
              (args.file_length <= apdu::kBinaryFileMax) && (end <= args.file_length);
    } else {
      valid =
          valid && (args.policy == nullptr) && !args.data.empty() && (end <= apdu::kBinaryFileMax);
    }
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsWrite, apdu::kP1Binary,
                                  apdu::kP2Default);
    if (!valid) {
      w.Refuse(Error::InvalidArgument);
    }
    apdu::detail::PutPolicy(w, args.policy);
    w.TlvU32(apdu::kTag1, args.id.value);
    if (args.offset != 0U) {
      w.TlvU16(apdu::kTag2, args.offset);
    }
    if (create) {
      w.TlvU16(apdu::kTag3, args.file_length);
    }
    if (!args.data.empty()) {
      w.Tlv(apdu::kTag4, args.data);
    }
    apdu::detail::PutVersion(w, args.version);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, const Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const WriteBinaryArgs& args, ByteSpan data,
                                       const Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::WriteBinary` (selects it for `Codec<Command::WriteBinary>`). */
constexpr WriteBinaryCodec CodecFor(CommandTag<Command::WriteBinary> /*tag*/) noexcept {
  return {};
}

/// `WriteUserId`: `80 41 07 00` TLV[TAG_POLICY] TLV[TAG_MAX_ATTEMPTS] 2 bytes TLV[TAG_1] id
/// TLV[TAG_2] 4 to 16 bytes (AN12543 Table 120: INS_AUTH_OBJECT is mandatory). An attempt limit
/// of 0 means unlimited and is refused (S-14).
struct WriteUserIdCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const WriteUserIdArgs& args,
                                              MutableByteSpan out) noexcept {
    const bool valid = apdu::detail::HasPolicy(args.policy) && apdu::detail::Writable(args.id) &&
                       (args.max_attempts != 0U) && (args.user_secret.size() >= apdu::kUserIdMin) &&
                       (args.user_secret.size() <= apdu::kUserIdMax);
    apdu::detail::CommandWriter w(out, apdu::kClaPlain,
                                  static_cast<uint8_t>(apdu::kInsWrite | apdu::kInsAuthObject),
                                  apdu::kP1UserId, apdu::kP2Default);
    if (!valid) {
      w.Refuse(Error::InvalidArgument);
    }
    apdu::detail::PutPolicy(w, args.policy);
    w.TlvU16(apdu::kTagMaxAttempts, args.max_attempts);
    w.TlvU32(apdu::kTag1, args.id.value);
    w.Tlv(apdu::kTag2, args.user_secret);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, const Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const WriteUserIdArgs& args, ByteSpan data,
                                       const Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::WriteUserId` (selects it for `Codec<Command::WriteUserId>`). */
constexpr WriteUserIdCodec CodecFor(CommandTag<Command::WriteUserId> /*tag*/) noexcept {
  return {};
}

/// `WriteCounter`: `80 01 08 00` (AN12543 Table 121). Creation (a policy given): TLV[TAG_POLICY]
/// TLV[TAG_1] id, then TLV[TAG_2] the 2-byte width when no value is set, or TLV[TAG_3] the value,
/// `counter_bytes` wide, which gives the width (TAG_2 only "if TAG_3 is not given"). Set (no
/// policy): TLV[TAG_1] TLV[TAG_3] value, `counter_bytes` wide (it must equal the counter's width).
/// An absent TAG_3 on an existing counter increments it: that is `IncrementCounter`.
struct WriteCounterCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const WriteCounterArgs& args,
                                              MutableByteSpan out) noexcept {
    const bool create = (args.policy != nullptr);
    const bool valid = apdu::detail::Writable(args.id) && (args.counter_bytes >= 1U) &&
                       (args.counter_bytes <= 8U) &&
                       (create ? apdu::detail::HasPolicy(args.policy) : args.set_value);
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsWrite, apdu::kP1Counter,
                                  apdu::kP2Default);
    if (!valid) {
      w.Refuse(Error::InvalidArgument);
    }
    apdu::detail::PutPolicy(w, args.policy);
    w.TlvU32(apdu::kTag1, args.id.value);
    if (create && !args.set_value) {
      w.TlvU16(apdu::kTag2, args.counter_bytes);
    }
    if (args.set_value) {
      w.TlvUint(apdu::kTag3, args.value, args.counter_bytes);
    }
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, const Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const WriteCounterArgs& args, ByteSpan data,
                                       const Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::WriteCounter` (selects it for `Codec<Command::WriteCounter>`). */
constexpr WriteCounterCodec CodecFor(CommandTag<Command::WriteCounter> /*tag*/) noexcept {
  return {};
}

/// `IncrementCounter`: `80 01 08 00` TLV[TAG_1] id (AN12543 Table 121: no value increments by 1).
struct IncrementCounterCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const IdArgs& args, MutableByteSpan out) noexcept {
    if (!apdu::detail::Writable(args.id)) {
      return apdu::detail::Fail<std::size_t>(Error::InvalidArgument);
    }
    return apdu::detail::EncodeId(out, apdu::kInsWrite, apdu::kP1Counter, apdu::kP2Default, args.id,
                                  0U);
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, const Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const IdArgs& args, ByteSpan data,
                                       const Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::IncrementCounter` (selects it for
 * `Codec<Command::IncrementCounter>`). */
constexpr IncrementCounterCodec CodecFor(CommandTag<Command::IncrementCounter> /*tag*/) noexcept {
  return {};
}

} // namespace codecs

namespace apdu::detail {

/// A PCR is a SHA-256 register (AN12543 4.7.1.7).
inline constexpr std::size_t kPcrLength = 32U;

/**
 * @brief The creation of a PCR: `80 01[|80] 09 00` TLV[TAG_POLICY] TLV[TAG_1] id TLV[TAG_2]
 * 32-byte initial value.
 * @param out The buffer.
 * @param id The PCR.
 * @param policy Its policy (required).
 * @param initial The initial value.
 * @param lifetime Persistent or transient.
 * @return The length or an error.
 */
constexpr Result<std::size_t> EncodePcrCreate(MutableByteSpan out, ObjectId id,
                                              const Policy* policy, ByteSpan initial,
                                              Lifetime lifetime) noexcept {
  uint8_t ins = 0U;
  const bool valid = HasPolicy(policy) && WriteIns(lifetime, ins) && Writable(id) &&
                     (initial.size() == kPcrLength);
  CommandWriter w(out, kClaPlain, ins, kP1Pcr, kP2Default);
  if (!valid) {
    w.Refuse(Error::InvalidArgument);
  }
  PutPolicy(w, policy);
  w.TlvU32(kTag1, id.value);
  w.Tlv(kTag2, initial);
  return w.Finish();
}

} // namespace apdu::detail

namespace codecs {

/// `WritePcr`: create a persistent PCR (AN12543 Table 122).
struct WritePcrCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const WritePcrArgs& args,
                                              MutableByteSpan out) noexcept {
    return apdu::detail::EncodePcrCreate(out, args.id, args.policy, args.initial_value,
                                         Lifetime::Persistent);
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, const Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const WritePcrArgs& args, ByteSpan data,
                                       const Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::WritePcr` (selects it for `Codec<Command::WritePcr>`). */
constexpr WritePcrCodec CodecFor(CommandTag<Command::WritePcr> /*tag*/) noexcept {
  return {};
}

/// `ExtendPcr`: `80 01 09 00` TLV[TAG_1] id TLV[TAG_3] data (AN12543 Table 122; an absent TAG_3
/// would reset the PCR, which this command never sends).
struct ExtendPcrCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const ExtendPcrArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsWrite, apdu::kP1Pcr,
                                  apdu::kP2Default);
    if (!apdu::detail::Writable(args.id) || args.data.empty()) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(apdu::kTag1, args.id.value);
    w.Tlv(apdu::kTag3, args.data);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, const Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const ExtendPcrArgs& args, ByteSpan data,
                                       const Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::ExtendPcr` (selects it for `Codec<Command::ExtendPcr>`). */
constexpr ExtendPcrCodec CodecFor(CommandTag<Command::ExtendPcr> /*tag*/) noexcept {
  return {};
}

/// `ImportObject`: `80 01 00 18` TLV[TAG_1] id [TLV[TAG_2] RSAKeyComponent] TLV[TAG_3] serialised
/// object (AN12543 Table 123; transient objects only, after `ExportObject`).
struct ImportObjectCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const ImportObjectArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsWrite, apdu::kP1Default,
                                  apdu::kP2Import);
    if (!apdu::detail::Writable(args.id) || args.serialised.empty()) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(apdu::kTag1, args.id.value);
    apdu::detail::PutRsaComponent(w, apdu::kTag2, args.rsa_component, apdu::kRsaCompLast);
    w.Tlv(apdu::kTag3, args.serialised);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, const Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const ImportObjectArgs& args, ByteSpan data,
                                       const Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::ImportObject` (selects it for `Codec<Command::ImportObject>`). */
constexpr ImportObjectCodec CodecFor(CommandTag<Command::ImportObject> /*tag*/) noexcept {
  return {};
}

/// `ExportObject`: `80 02 00 19` TLV[TAG_1] id [TLV[TAG_2] RSAKeyComponent], Le; answer
/// TLV[TAG_1] the serialised object (AN12543 4.7.3.3).
struct ExportObjectCodec {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const ExportObjectArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsRead, apdu::kP1Default,
                                  apdu::kP2Export);
    if ((args.id.value == 0U) || args.out.empty()) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(apdu::kTag1, args.id.value);
    apdu::detail::PutRsaComponent(w, apdu::kTag2, args.rsa_component, apdu::kRsaCompLast);
    w.ExpectResponse(apdu::detail::TlvBudget(args.out.size()));
    return w.Finish();
  }
  /** @brief Refused: the output goes to `args.out`. @param data The body. @param reply The reply.
   * @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, const LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const ExportObjectArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    return apdu::detail::DecodeTag1Into(data, args.out, reply.length);
  }
};
/** @return The codec of `Command::ExportObject` (selects it for `Codec<Command::ExportObject>`). */
constexpr ExportObjectCodec CodecFor(CommandTag<Command::ExportObject> /*tag*/) noexcept {
  return {};
}

/// `ImportExternalObject`: `80 06 00 00 <envelope> 00` (AN12543 Table 124; Le 00 asks for the
/// receipt, whose length the decoder checks). The envelope is the
/// whole payload: TLV[TAG_IMPORT_AUTH_DATA] TLV[TAG_IMPORT_AUTH_KEY_ID] 4 bytes TLV[TAG_1] wrapped
/// write command, in that order (built by the ECKey layer). The answer is the 8-byte receipt, not a
/// TLV (Table 125). NXP asks to be contacted before this command is used (AN12543 p. 88).
struct ImportExternalObjectCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /// Length of the receipt (an 8-byte CMAC).
  static constexpr std::size_t kReceiptLength = 8U;
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error (`InvalidArgument` for an envelope that is not the three TLVs). */
  static constexpr Result<std::size_t> Encode(const ImportExternalObjectArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::ReplyParser envelope(args.envelope);
    const bool valid = envelope.Need(apdu::kTagImportAuthData).ok() &&
                       envelope.NeedLength(apdu::kTagImportAuthKeyId, 4U).ok() &&
                       envelope.Need(apdu::kTag1).ok() && envelope.End().ok();
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsImportExternal, apdu::kP1Default,
                                  apdu::kP2Default);
    if (!valid) {
      w.Refuse(Error::InvalidArgument);
    }
    w.Raw(args.envelope);
    w.ExpectResponse(kReceiptLength);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, ExternalImportReceipt& reply) noexcept {
    if (data.size() != kReceiptLength) {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    return apdu::detail::CopyFixed(data, reply.receipt);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const ImportExternalObjectArgs& args, ByteSpan data,
                                       ExternalImportReceipt& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::ImportExternalObject` (selects it for
 * `Codec<Command::ImportExternalObject>`). */
constexpr ImportExternalObjectCodec CodecFor(
    CommandTag<Command::ImportExternalObject> /*tag*/) noexcept {
  return {};
}

/// `WritePcrWithType` (applet 7.x): a PCR that may be transient, `80 01|80 09 00` (AN12543
/// Table 122 with INS_TRANSIENT).
struct WritePcrWithTypeCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const WritePcrTypedArgs& args,
                                              MutableByteSpan out) noexcept {
    return apdu::detail::EncodePcrCreate(out, args.id, args.policy, args.initial_value,
                                         args.lifetime);
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, const Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const WritePcrTypedArgs& args, ByteSpan data,
                                       const Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::WritePcrWithType` (selects it for
 * `Codec<Command::WritePcrWithType>`). */
constexpr WritePcrWithTypeCodec CodecFor(CommandTag<Command::WritePcrWithType> /*tag*/) noexcept {
  return {};
}

/// `ReadObject`: `80 02 00 00` TLV[TAG_1] id [TLV[TAG_2] offset TLV[TAG_3] length]
/// [TLV[TAG_4] component], Le (extended when the answer may exceed 256 bytes); answer TLV[TAG_1]
/// (AN12543 Tables 127, 128).
struct ReadObjectCodec {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const ReadObjectArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsRead, apdu::kP1Default,
                                  apdu::kP2Default);
    if ((args.id.value == 0U) || args.out.empty()) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(apdu::kTag1, args.id.value);
    apdu::detail::PutRange(w, args.offset, args.length);
    apdu::detail::PutRsaComponent(w, apdu::kTag4, args.rsa_component, apdu::kRsaCompPubExp);
    w.ExpectResponse(apdu::detail::TlvBudget(args.out.size()));
    return w.Finish();
  }
  /** @brief Refused: the output goes to `args.out`. @param data The body. @param reply The reply.
   * @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, const LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const ReadObjectArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    return apdu::detail::DecodeTag1Into(data, args.out, reply.length);
  }
};
/** @return The codec of `Command::ReadObject` (selects it for `Codec<Command::ReadObject>`). */
constexpr ReadObjectCodec CodecFor(CommandTag<Command::ReadObject> /*tag*/) noexcept {
  return {};
}

/// `ReadObjectAttested`: `80 22 00 00` TLV[TAG_1] id [TAG_2, TAG_3] TLV[TAG_5] attestation key
/// TLV[TAG_6] algorithm TLV[TAG_7] freshness, extended Le (AN12543 Table 127). A binary read takes
/// at most `kMaxAttestedBinaryRead` bytes (AN13030 pp. 248-252). The answer format is told by its
/// tags (`AttestedRead::format`).
struct ReadObjectAttestedCodec {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `data_out` and `signature_out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const ReadObjectAttestedArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain,
                                  static_cast<uint8_t>(apdu::kInsRead | apdu::kInsAttest),
                                  apdu::kP1Default, apdu::kP2Default);
    if ((args.id.value == 0U) || (args.length > kMaxAttestedBinaryRead) ||
        args.signature_out.empty()) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(apdu::kTag1, args.id.value);
    apdu::detail::PutRange(w, args.offset, args.length);
    apdu::detail::PutAttestation(w, apdu::kTag5, apdu::kTag6, args.attestation_key, args.algo,
                                 args.freshness);
    w.ExpectResponse(apdu::detail::AttestedBudget(args.data_out));
    return w.Finish();
  }
  /** @brief Refused: the output goes to the caller buffers. @param data The body. @param reply The
   * reply. @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, const AttestedRead& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const ReadObjectAttestedArgs& args, ByteSpan data,
                                       AttestedRead& reply) noexcept {
    return apdu::detail::DecodeAttested(
        data, {.data = args.data_out, .signature = args.signature_out}, reply);
  }
};
/** @return The codec of `Command::ReadObjectAttested` (selects it for
 * `Codec<Command::ReadObjectAttested>`). */
constexpr ReadObjectAttestedCodec CodecFor(
    CommandTag<Command::ReadObjectAttested> /*tag*/) noexcept {
  return {};
}

/// `ReadObjectAttributes` (applet 7.x): `80 02 00 3B` TLV[TAG_1] id, Le; answer TLV[TAG_3] the
/// attribute block (AN12543 Tables 130, 131), parsed by `ParseObjectAttributes`.
struct ReadObjectAttributesCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const IdArgs& args, MutableByteSpan out) noexcept {
    return apdu::detail::EncodeId(out, apdu::kInsRead, apdu::kP1Default, apdu::kP2Attributes,
                                  args.id, apdu::detail::TlvBudget(kMaxAttributeBytes));
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, ObjectAttributes& reply) noexcept {
    apdu::detail::ReplyParser p(data);
    const Result<ByteSpan> v = p.Need(apdu::kTag3);
    if (!v.ok() || !p.End().ok()) {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    const Result<ObjectAttributes> parsed = ParseObjectAttributes(v.value);
    if (!parsed.ok()) {
      return Result<void>::Failure(parsed.error, parsed.detail);
    }
    reply = parsed.value;
    return Result<void>::Success();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const IdArgs& args, ByteSpan data,
                                       ObjectAttributes& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::ReadObjectAttributes` (selects it for
 * `Codec<Command::ReadObjectAttributes>`). */
constexpr ReadObjectAttributesCodec CodecFor(
    CommandTag<Command::ReadObjectAttributes> /*tag*/) noexcept {
  return {};
}

/// `ReadObjectAttributesAttested` (applet 7.x): `80 22 00 3B` TLV[TAG_1] id TLV[TAG_5] TLV[TAG_6]
/// TLV[TAG_7], Le; answer TAG_2 chip id, TAG_3 attributes, TAG_4 size, TAG_TS, TAG_ATT_SIG.
struct ReadObjectAttributesAttestedCodec {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `signature_out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const AttributesAttestedArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain,
                                  static_cast<uint8_t>(apdu::kInsRead | apdu::kInsAttest),
                                  apdu::kP1Default, apdu::kP2Attributes);
    if ((args.id.value == 0U) || args.signature_out.empty()) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(apdu::kTag1, args.id.value);
    apdu::detail::PutAttestation(w, apdu::kTag5, apdu::kTag6, args.attestation_key, args.algo,
                                 args.freshness);
    w.ExpectResponse(apdu::detail::kAttestedOverhead);
    return w.Finish();
  }
  /** @brief Refused: the output goes to `signature_out`. @param data The body. @param reply The
   * reply. @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, const AttestedRead& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` (also when the chip returns data) or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const AttributesAttestedArgs& args, ByteSpan data,
                                       AttestedRead& reply) noexcept {
    return apdu::detail::DecodeAttested(
        data, {.data = MutableByteSpan{}, .signature = args.signature_out}, reply);
  }
};
/** @return The codec of `Command::ReadObjectAttributesAttested` (selects it for
 * `Codec<Command::ReadObjectAttributesAttested>`). */
constexpr ReadObjectAttributesAttestedCodec CodecFor(
    CommandTag<Command::ReadObjectAttributesAttested> /*tag*/) noexcept {
  return {};
}

/// `ReadRsaAttested`: `80 22 00 00` TLV[TAG_1] id TLV[TAG_4] component (modulus or public
/// exponent) TLV[TAG_5] TLV[TAG_6] TLV[TAG_7], extended Le (AN12543 Table 127).
struct ReadRsaAttestedCodec {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `data_out` and `signature_out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const ReadRsaAttestedArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain,
                                  static_cast<uint8_t>(apdu::kInsRead | apdu::kInsAttest),
                                  apdu::kP1Default, apdu::kP2Default);
    if ((args.id.value == 0U) || (args.rsa_component > apdu::kRsaCompPubExp) ||
        args.data_out.empty() || args.signature_out.empty()) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU32(apdu::kTag1, args.id.value);
    w.TlvU8(apdu::kTag4, args.rsa_component);
    apdu::detail::PutAttestation(w, apdu::kTag5, apdu::kTag6, args.attestation_key, args.algo,
                                 args.freshness);
    w.ExpectResponse(apdu::detail::AttestedBudget(args.data_out));
    return w.Finish();
  }
  /** @brief Refused: the output goes to the caller buffers. @param data The body. @param reply The
   * reply. @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, const AttestedRead& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const ReadRsaAttestedArgs& args, ByteSpan data,
                                       AttestedRead& reply) noexcept {
    return apdu::detail::DecodeAttested(
        data, {.data = args.data_out, .signature = args.signature_out}, reply);
  }
};
/** @return The codec of `Command::ReadRsaAttested` (selects it for
 * `Codec<Command::ReadRsaAttested>`). */
constexpr ReadRsaAttestedCodec CodecFor(CommandTag<Command::ReadRsaAttested> /*tag*/) noexcept {
  return {};
}

/// `ReadType`: `80 02 00 26` TLV[TAG_1] id, Le; answer TLV[TAG_1] SecureObjectType TLV[TAG_2]
/// TransientIndicator (AN12543 4.7.4.1).
struct ReadTypeCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const IdArgs& args, MutableByteSpan out) noexcept {
    return apdu::detail::EncodeId(out, apdu::kInsRead, apdu::kP1Default, apdu::kP2Type, args.id,
                                  2U * apdu::detail::TlvBudget(1U));
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, TypeReply& reply) noexcept {
    apdu::detail::ReplyParser p(data);
    const Result<ByteSpan> type = p.NeedLength(apdu::kTag1, 1U);
    const Result<ByteSpan> transient = p.NeedLength(apdu::kTag2, 1U);
    if (!type.ok() || !transient.ok() || !p.End().ok() ||
        !apdu::ClassFromWire(type.value[0], reply.object_class)) {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    if (transient.value[0] == apdu::kPersistent) {
      reply.lifetime = Lifetime::Persistent;
    } else if (transient.value[0] == apdu::kTransient) {
      reply.lifetime = Lifetime::TransientDeselect;
    } else {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    return Result<void>::Success();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const IdArgs& args, ByteSpan data,
                                       TypeReply& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::ReadType` (selects it for `Codec<Command::ReadType>`). */
constexpr ReadTypeCodec CodecFor(CommandTag<Command::ReadType> /*tag*/) noexcept {
  return {};
}

/// `ReadSize`: `80 02 00 07` TLV[TAG_1] id, Le; answer TLV[TAG_1] the size, 1 to 4 bytes big
/// endian (AN12543 4.7.4.2).
struct ReadSizeCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const IdArgs& args, MutableByteSpan out) noexcept {
    return apdu::detail::EncodeId(out, apdu::kInsRead, apdu::kP1Default, apdu::kP2Size, args.id,
                                  apdu::detail::TlvBudget(4U));
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, U32Reply& reply) noexcept {
    apdu::detail::ReplyParser p(data);
    const Result<ByteSpan> v = p.Need(apdu::kTag1);
    if (!v.ok() || !p.End().ok() || v.value.empty() || (v.value.size() > 4U)) {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    reply.value = apdu::detail::BigEndian(v.value);
    return Result<void>::Success();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const IdArgs& args, ByteSpan data,
                                       U32Reply& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::ReadSize` (selects it for `Codec<Command::ReadSize>`). */
constexpr ReadSizeCodec CodecFor(CommandTag<Command::ReadSize> /*tag*/) noexcept {
  return {};
}

/// `ReadIdList`: `80 02 00 25` TLV[TAG_1] 2-byte offset TLV[TAG_2] type filter (FF for all), Le;
/// answer TLV[TAG_1] MoreIndicator TLV[TAG_2] the 4-byte ids (AN12543 Tables 142, 143; Table 56:
/// 01 NO_MORE, 02 MORE, the text of p. 94 says the reverse and is not followed).
struct ReadIdListCodec {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const ReadIdListArgs& args,
                                              MutableByteSpan out) noexcept {
    uint8_t filter = apdu::kIdListAnyType;
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsRead, apdu::kP1Default,
                                  apdu::kP2List);
    if (args.out.empty() ||
        (args.filter_by_class && !apdu::ClassFilterWire(args.object_class, filter))) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU16(apdu::kTag1, args.offset);
    w.TlvU8(apdu::kTag2, filter);
    w.ExpectResponse(apdu::detail::TlvBudget(1U) + apdu::detail::TlvBudget(4U * args.out.size()));
    return w.Finish();
  }
  /** @brief Refused: the output goes to `args.out`. @param data The body. @param reply The reply.
   * @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, const IdListReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return `Ok`, `FrameError` or `BufferTooSmall` (more ids than `args.out` holds). */
  static constexpr Result<void> Decode(const ReadIdListArgs& args, ByteSpan data,
                                       IdListReply& reply) noexcept {
    reply = IdListReply{};
    apdu::detail::ReplyParser p(data);
    const Result<ByteSpan> more = p.NeedLength(apdu::kTag1, 1U);
    const Result<ByteSpan> ids = p.Need(apdu::kTag2);
    if (!more.ok() || !ids.ok() || !p.End().ok() || ((ids.value.size() % 4U) != 0U) ||
        ((more.value[0] != apdu::kMore) && (more.value[0] != apdu::kNoMore))) {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    const std::size_t count = ids.value.size() / 4U;
    if (count > args.out.size()) {
      return apdu::detail::Fail<void>(Error::BufferTooSmall);
    }
    for (std::size_t i = 0U; i < count; ++i) {
      args.out[i] = ObjectId{apdu::detail::BigEndian(ids.value.subspan(4U * i, 4U))};
    }
    reply.count = count;
    reply.more = (more.value[0] == apdu::kMore);
    return Result<void>::Success();
  }
};
/** @return The codec of `Command::ReadIdList` (selects it for `Codec<Command::ReadIdList>`). */
constexpr ReadIdListCodec CodecFor(CommandTag<Command::ReadIdList> /*tag*/) noexcept {
  return {};
}

/// `CheckObjectExists`: `80 04 00 27` TLV[TAG_1] id, Le; answer TLV[TAG_1] Result, 01 exists
/// (AN12543 4.7.4.4).
struct CheckObjectExistsCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const IdArgs& args, MutableByteSpan out) noexcept {
    return apdu::detail::EncodeId(out, apdu::kInsMgmt, apdu::kP1Default, apdu::kP2Exist, args.id,
                                  apdu::detail::TlvBudget(1U));
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, BoolReply& reply) noexcept {
    return apdu::detail::DecodeResult(data, reply.value);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const IdArgs& args, ByteSpan data,
                                       BoolReply& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::CheckObjectExists` (selects it for
 * `Codec<Command::CheckObjectExists>`). */
constexpr CheckObjectExistsCodec CodecFor(CommandTag<Command::CheckObjectExists> /*tag*/) noexcept {
  return {};
}

/// `DeleteSecureObject`: `80 04 00 28` TLV[TAG_1] id (AN12543 4.7.4.5). An id in the NXP range is
/// refused before sending (provisioned objects cannot be deleted; the driver never tries).
struct DeleteSecureObjectCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const IdArgs& args, MutableByteSpan out) noexcept {
    if (!apdu::detail::Writable(args.id)) {
      return apdu::detail::Fail<std::size_t>(Error::InvalidArgument);
    }
    return apdu::detail::EncodeId(out, apdu::kInsMgmt, apdu::kP1Default, apdu::kP2DeleteObject,
                                  args.id, 0U);
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, const Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const IdArgs& args, ByteSpan data,
                                       const Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::DeleteSecureObject` (selects it for
 * `Codec<Command::DeleteSecureObject>`). */
constexpr DeleteSecureObjectCodec CodecFor(
    CommandTag<Command::DeleteSecureObject> /*tag*/) noexcept {
  return {};
}

} // namespace codecs

namespace apdu::detail {

/**
 * @brief A curve command `80 <ins> 0B <p2>` TLV[TAG_1] curve id. Ed25519 is refused: it is never
 * created or deleted (AN12543 Table 44 note).
 * @param out The buffer.
 * @param ins INS.
 * @param p2 P2.
 * @param curve The curve.
 * @return The length or an error.
 */
constexpr Result<std::size_t> EncodeCurve(MutableByteSpan out, uint8_t ins, uint8_t p2,
                                          EcCurve curve) noexcept {
  const CurveInfo info = CurveOf(curve);
  CommandWriter w(out, kClaPlain, ins, kP1Curve, p2);
  if ((info.id == 0U) || info.edwards) {
    w.Refuse(Error::InvalidArgument);
  }
  w.TlvU8(kTag1, info.id);
  return w.Finish();
}

} // namespace apdu::detail

namespace codecs {

/// `CreateEcCurve`: `80 01 0B 04` TLV[TAG_1] curve id (AN12543 4.8.1).
struct CreateEcCurveCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const CurveArgs& args, MutableByteSpan out) noexcept {
    return apdu::detail::EncodeCurve(out, apdu::kInsWrite, apdu::kP2Create, args.curve);
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, const Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const CurveArgs& args, ByteSpan data,
                                       const Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::CreateEcCurve` (selects it for `Codec<Command::CreateEcCurve>`).
 */
constexpr CreateEcCurveCodec CodecFor(CommandTag<Command::CreateEcCurve> /*tag*/) noexcept {
  return {};
}

/// `SetEcCurveParam`: `80 01 0B 40` TLV[TAG_1] curve TLV[TAG_2] ECCurveParam (01 A, 02 B, 04 G,
/// 08 N, 10 prime) TLV[TAG_3] value (AN12543 4.8.2; Weierstrass curves only).
struct SetEcCurveParamCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const SetCurveParamArgs& args,
                                              MutableByteSpan out) noexcept {
    const apdu::CurveInfo info = apdu::CurveOf(args.curve);
    const uint32_t p = args.parameter;
    const bool known = (p == 0x01U) || (p == 0x02U) || (p == 0x04U) || (p == 0x08U) || (p == 0x10U);
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsWrite, apdu::kP1Curve,
                                  apdu::kP2Param);
    if (!info.weierstrass || !known || args.value.empty() ||
        (args.value.size() > info.public_length)) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU8(apdu::kTag1, info.id);
    w.TlvU8(apdu::kTag2, args.parameter);
    w.Tlv(apdu::kTag3, args.value);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, const Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const SetCurveParamArgs& args, ByteSpan data,
                                       const Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::SetEcCurveParam` (selects it for
 * `Codec<Command::SetEcCurveParam>`). */
constexpr SetEcCurveParamCodec CodecFor(CommandTag<Command::SetEcCurveParam> /*tag*/) noexcept {
  return {};
}

/// `GetEcCurveId`: `80 02 0B 36` TLV[TAG_1] object id, Le; answer TLV[TAG_1] curve id.
struct GetEcCurveIdCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const IdArgs& args, MutableByteSpan out) noexcept {
    return apdu::detail::EncodeId(out, apdu::kInsRead, apdu::kP1Curve, apdu::kP2Id, args.id,
                                  apdu::detail::TlvBudget(1U));
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, CurveReply& reply) noexcept {
    apdu::detail::ReplyParser p(data);
    const Result<ByteSpan> v = p.NeedLength(apdu::kTag1, 1U);
    if (!v.ok() || !p.End().ok() || !apdu::CurveFromWire(v.value[0], reply.curve)) {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    return Result<void>::Success();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const IdArgs& args, ByteSpan data,
                                       CurveReply& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::GetEcCurveId` (selects it for `Codec<Command::GetEcCurveId>`). */
constexpr GetEcCurveIdCodec CodecFor(CommandTag<Command::GetEcCurveId> /*tag*/) noexcept {
  return {};
}

/// `ReadEcCurveList`: `80 02 0B 25 00`; answer TLV[TAG_1] one SetIndicator per curve id below
/// 0x40 (AN12543 4.8.4).
struct ReadEcCurveListCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args None. @param out The buffer. @return The length or an error. */
  static constexpr Result<std::size_t> Encode(const Empty& args, MutableByteSpan out) noexcept {
    static_cast<void>(args);
    return apdu::detail::EncodeBare(out, apdu::kClaPlain, apdu::kInsRead, apdu::kP1Curve,
                                    apdu::kP2List, apdu::detail::TlvBudget(0x40U));
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, SmallBlob& reply) noexcept {
    return apdu::detail::Tag1Fixed(data, 0U, reply);
  }
  /** @brief Decode. @param args None. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const Empty& args, ByteSpan data,
                                       SmallBlob& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::ReadEcCurveList` (selects it for
 * `Codec<Command::ReadEcCurveList>`). */
constexpr ReadEcCurveListCodec CodecFor(CommandTag<Command::ReadEcCurveList> /*tag*/) noexcept {
  return {};
}

/// `DeleteEcCurve`: `80 04 0B 28` TLV[TAG_1] curve id (AN12543 4.8.5).
struct DeleteEcCurveCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const CurveArgs& args, MutableByteSpan out) noexcept {
    return apdu::detail::EncodeCurve(out, apdu::kInsMgmt, apdu::kP2DeleteObject, args.curve);
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, const Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const CurveArgs& args, ByteSpan data,
                                       const Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::DeleteEcCurve` (selects it for `Codec<Command::DeleteEcCurve>`).
 */
constexpr DeleteEcCurveCodec CodecFor(CommandTag<Command::DeleteEcCurve> /*tag*/) noexcept {
  return {};
}

} // namespace codecs

namespace apdu::detail {

/**
 * @brief The 2-byte CryptoObject type: CryptoContext and the subtype of `algorithm`, which is the
 * enumerator value of the enumeration that matches `type` (AN12543 4.3.39).
 * @param type The context.
 * @param algorithm The enumerator value.
 * @param context Receives the CryptoContext.
 * @param subtype Receives the subtype.
 * @return `Ok`, `Unsupported` (a NOT SUPPORTED cipher mode) or `InvalidArgument`.
 */
constexpr Error CryptoObjectWire(se05x::CryptoObjectType type, uint8_t algorithm, uint8_t& context,
                                 uint8_t& subtype) noexcept {
  if (!CryptoContextWire(type, context)) {
    return Error::InvalidArgument;
  }
  bool ok = false;
  switch (type) {
  case se05x::CryptoObjectType::Digest:
    ok = (algorithm <= static_cast<uint8_t>(DigestMode::Sha512)) &&
         DigestWire(static_cast<DigestMode>(algorithm), subtype);
    break;
  case se05x::CryptoObjectType::Mac:
    ok = (algorithm <= static_cast<uint8_t>(MacAlgo::DesCmac8)) &&
         MacWire(static_cast<MacAlgo>(algorithm), subtype);
    break;
  case se05x::CryptoObjectType::Aead:
    ok = (algorithm <= static_cast<uint8_t>(AeadMode::AesCcm)) &&
         AeadWire(static_cast<AeadMode>(algorithm), subtype);
    break;
  case se05x::CryptoObjectType::Cipher:
    if (algorithm > static_cast<uint8_t>(CipherMode::AesCtr)) {
      return Error::InvalidArgument;
    }
    subtype = CipherModeOf(static_cast<CipherMode>(algorithm)).wire;
    return (subtype == 0U) ? Error::Unsupported : Error::Ok;
  default:
    break;
  }
  return ok ? Error::Ok : Error::InvalidArgument;
}

} // namespace apdu::detail

namespace codecs {

/// `CreateCryptoObject`: `80 01 10 00` TLV[TAG_1] 2-byte id TLV[TAG_2] CryptoContext TLV[TAG_3]
/// subtype (AN12543 4.9.1; the PAKE context is held, A6).
struct CreateCryptoObjectCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const CreateCryptoObjectArgs& args,
                                              MutableByteSpan out) noexcept {
    uint8_t context = 0U;
    uint8_t subtype = 0U;
    const Error error = apdu::detail::CryptoObjectWire(args.type, args.algorithm, context, subtype);
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsWrite, apdu::kP1CryptoObj,
                                  apdu::kP2Default);
    if (error != Error::Ok) {
      w.Refuse(error);
    }
    w.TlvU16(apdu::kTag1, args.context.value);
    w.TlvU8(apdu::kTag2, context);
    w.TlvU8(apdu::kTag3, subtype);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, const Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const CreateCryptoObjectArgs& args, ByteSpan data,
                                       const Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::CreateCryptoObject` (selects it for
 * `Codec<Command::CreateCryptoObject>`). */
constexpr CreateCryptoObjectCodec CodecFor(
    CommandTag<Command::CreateCryptoObject> /*tag*/) noexcept {
  return {};
}

/// `ReadCryptoObjectList`: `80 02 10 25 00`; answer TLV[TAG_1] 4-byte entries (2-byte id,
/// CryptoContext, subtype) (AN12543 4.9.2).
struct ReadCryptoObjectListCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args None. @param out The buffer. @return The length or an error. */
  static constexpr Result<std::size_t> Encode(const Empty& args, MutableByteSpan out) noexcept {
    static_cast<void>(args);
    return apdu::detail::EncodeBare(out, apdu::kClaPlain, apdu::kInsRead, apdu::kP1CryptoObj,
                                    apdu::kP2List, apdu::detail::kShortLeMax);
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok`, `FrameError` or
   * `BufferTooSmall`. */
  static constexpr Result<void> Decode(ByteSpan data, SmallBlob& reply) noexcept {
    const Result<void> r = apdu::detail::Tag1Fixed(data, 0U, reply);
    if (r.ok() && ((reply.length % 4U) != 0U)) {
      reply = SmallBlob{};
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    return r;
  }
  /** @brief Decode. @param args None. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const Empty& args, ByteSpan data,
                                       SmallBlob& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::ReadCryptoObjectList` (selects it for
 * `Codec<Command::ReadCryptoObjectList>`). */
constexpr ReadCryptoObjectListCodec CodecFor(
    CommandTag<Command::ReadCryptoObjectList> /*tag*/) noexcept {
  return {};
}

/// `DeleteCryptoObject`: `80 04 10 28` TLV[TAG_1] 2-byte id (AN12543 4.9.3).
struct DeleteCryptoObjectCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const CryptoObjectArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsMgmt, apdu::kP1CryptoObj,
                                  apdu::kP2DeleteObject);
    w.TlvU16(apdu::kTag1, args.context.value);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, const Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const CryptoObjectArgs& args, ByteSpan data,
                                       const Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::DeleteCryptoObject` (selects it for
 * `Codec<Command::DeleteCryptoObject>`). */
constexpr DeleteCryptoObjectCodec CodecFor(
    CommandTag<Command::DeleteCryptoObject> /*tag*/) noexcept {
  return {};
}

} // namespace codecs

} // namespace se05x

#endif // SE05X_APDU_OBJECTS_HPP
