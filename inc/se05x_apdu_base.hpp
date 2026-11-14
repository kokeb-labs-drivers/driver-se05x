/**
 * @file se05x_apdu_base.hpp
 * @brief Helpers shared by the codec group headers (not part of the contract).
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Encoding and decoding steps that several commands share: the policy TLV, the
 * transient INS flag, the "one TLV into a caller buffer" response, the 1-byte Result response and
 * the attested response of both formats (AN12413 Table 106 for format 1, AN12543 Tables 128, 131
 * and 313 for format 2).
 */
#ifndef SE05X_APDU_BASE_HPP
#define SE05X_APDU_BASE_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

#include "se05x_apdu.hpp"
#include "se05x_apdu_consts.hpp"
#include "se05x_device_types.hpp"
#include "se05x_ids.hpp"
#include "se05x_policy_types.hpp"
#include "se05x_status.hpp"
#include "se05x_types.hpp"

namespace se05x::apdu::detail {

/// Response budget of a TLV that carries `n` bytes (tag and the three-byte length form).
constexpr std::size_t TlvBudget(std::size_t n) noexcept {
  return n + 4U;
}

/// Most random bytes one `GetRandom` returns: the response (TLV header 4, status word 2) stays
/// within `kMaxResponse` (errata APP.1).
inline constexpr std::size_t kMaxRandom = kMaxResponse - 6U;

/// Response budget of an attested answer beyond its data: chip id, attributes, size, timestamp and
/// an RSA-4096 signature, each with a three-byte length.
inline constexpr std::size_t kAttestedOverhead =
    TlvBudget(kUniqueIdLength) + TlvBudget(kMaxAttributeBytes) + TlvBudget(2U) +
    TlvBudget(kTimestampLength) + TlvBudget(kFreshnessLength) + TlvBudget(kAttestedSignatureMax);

/**
 * @brief Whether a policy pointer names a built policy.
 * @param policy The pointer.
 * @return false for null and for the empty policy.
 */
constexpr bool HasPolicy(const Policy* policy) noexcept {
  return (policy != nullptr) && !policy->IsEmpty();
}

/**
 * @brief Write TLV[TAG_POLICY] when a policy is given.
 * @param w The writer.
 * @param policy The policy, or null.
 */
constexpr void PutPolicy(CommandWriter& w, const Policy* policy) noexcept {
  if (HasPolicy(policy)) {
    w.Tlv(kTagPolicy, policy->Bytes());
  }
}

/**
 * @brief INS_WRITE with INS_TRANSIENT for a transient object. The applet has one kind of
 * transient object: its content lives until deselect, which a reset implies (AN12543 3.2.2.2).
 * @param lifetime The lifetime.
 * @param ins Receives the INS byte.
 * @return false for a value that is not an enumerator.
 */
constexpr bool WriteIns(Lifetime lifetime, uint8_t& ins) noexcept {
  if (!se05x::detail::IsEnumerator(lifetime)) {
    return false;
  }
  ins = (lifetime == Lifetime::Persistent) ? kInsWrite
                                           : static_cast<uint8_t>(kInsWrite | kInsTransient);
  return true;
}

/**
 * @brief Write TLV[TAG_11] for a non-zero version (applet 7.x, AN12543 3.10).
 * @param w The writer.
 * @param version The version; 0 sends nothing; above `kVersionMax` is refused.
 */
constexpr void PutVersion(CommandWriter& w, uint32_t version) noexcept {
  if (version == 0U) {
    return;
  }
  if (version > kVersionMax) {
    w.Refuse(Error::InvalidArgument);
    return;
  }
  w.TlvU32(kTag11, version);
}

/**
 * @brief The common shape "TLV[TAG_1] into a caller buffer".
 * @param data The response body.
 * @param out The caller buffer.
 * @param written Receives the length.
 * @return `Ok`, `FrameError` or `BufferTooSmall`.
 */
constexpr Result<void> DecodeTag1Into(ByteSpan data, MutableByteSpan out,
                                      std::size_t& written) noexcept {
  written = 0U;
  ReplyParser p(data);
  const Result<ByteSpan> value = p.Need(kTag1);
  if (!value.ok()) {
    return Result<void>::Failure(value.error, value.detail);
  }
  const Result<void> end = p.End();
  if (!end.ok()) {
    return end;
  }
  return CopyOut(value.value, out, written);
}

/**
 * @brief "An optional TLV[TAG_1] into a caller buffer" (streaming updates may return no output).
 * @param data The response body.
 * @param out The caller buffer.
 * @param written Receives the length.
 * @return `Ok`, `FrameError` or `BufferTooSmall`.
 */
constexpr Result<void> DecodeOptionalTag1Into(ByteSpan data, MutableByteSpan out,
                                              std::size_t& written) noexcept {
  written = 0U;
  if (data.empty()) {
    return Result<void>::Success();
  }
  return DecodeTag1Into(data, out, written);
}

/**
 * @brief The 1-byte Result in TLV[TAG_1] (AN12543 Table 53).
 * @param data The response body.
 * @param success Receives true for RESULT_SUCCESS.
 * @return `Ok`, or `FrameError` for a malformed body or a value other than 01 and 02.
 */
constexpr Result<void> DecodeResult(ByteSpan data, bool& success) noexcept {
  ReplyParser p(data);
  const Result<ByteSpan> value = p.NeedLength(kTag1, 1U);
  if (!value.ok()) {
    return Result<void>::Failure(value.error, value.detail);
  }
  const Result<void> end = p.End();
  if (!end.ok()) {
    return end;
  }
  if (value.value[0] == kResultSuccess) {
    success = true;
    return Result<void>::Success();
  }
  if (value.value[0] == kResultFailure) {
    success = false;
    return Result<void>::Success();
  }
  return Fail<void>(Error::FrameError);
}

/**
 * @brief The two-argument `Decode` of a command that writes caller buffers: refused, because the
 * output would be lost.
 * @return `InvalidArgument`.
 */
constexpr Result<void> NeedsArgs() noexcept {
  return Fail<void>(Error::InvalidArgument);
}

/**
 * @brief Encode a command whose only argument is TLV[TAG_1] = a 4-byte object id.
 * @param out The buffer.
 * @param ins INS.
 * @param p1 P1.
 * @param p2 P2.
 * @param id The object.
 * @param response Response budget; 0 sends no Le.
 * @return The length or an error.
 */
constexpr Result<std::size_t> EncodeId(MutableByteSpan out, uint8_t ins, uint8_t p1, uint8_t p2,
                                       ObjectId id, std::size_t response) noexcept {
  CommandWriter w(out, kClaPlain, ins, p1, p2);
  if (id.value == 0U) {
    w.Refuse(Error::InvalidArgument);
  }
  w.TlvU32(kTag1, id.value);
  if (response != 0U) {
    w.ExpectResponse(response);
  }
  return w.Finish();
}

/**
 * @brief Encode a command without a body.
 * @param out The buffer.
 * @param cla CLA.
 * @param ins INS.
 * @param p1 P1.
 * @param p2 P2.
 * @param response Response budget; 0 sends no Le (ISO case 1).
 * @return The length or an error.
 */
constexpr Result<std::size_t> EncodeBare(MutableByteSpan out, uint8_t cla, uint8_t ins, uint8_t p1,
                                         uint8_t p2, std::size_t response) noexcept {
  CommandWriter w(out, cla, ins, p1, p2);
  if (response != 0U) {
    w.ExpectResponse(response);
  }
  return w.Finish();
}

/**
 * @brief Copy a 64-byte EdDSA signature between RFC 8032 order and the wire order: r and s are
 * each byte-reversed (AN12543 7.1). The same function converts in both directions.
 * @param in The 64 bytes.
 * @param out The 64 bytes, converted.
 */
constexpr void EdSignatureSwap(ByteSpan in, MutableByteSpan out) noexcept {
  constexpr std::size_t kHalf = 32U;
  for (std::size_t i = 0U; i < kHalf; ++i) {
    out[i] = in[kHalf - 1U - i];
    out[kHalf + i] = in[(2U * kHalf) - 1U - i];
  }
}

/// Length of an Ed25519 signature (r || s).
inline constexpr std::size_t kEdSignatureLength = 64U;

/**
 * @brief Whether a public key is a Montgomery u-coordinate (32 or 56 bytes). A Weierstrass point
 * in the uncompressed form of SEC 1 is `04 || X || Y`, always of odd length, so an even length of
 * 32 or 56 bytes can only be an X25519 or X448 key.
 * @param public_key The key.
 * @return true for a Montgomery key.
 */
constexpr bool IsMontgomeryKey(ByteSpan public_key) noexcept {
  return (public_key.size() == 32U) || (public_key.size() == 56U);
}

/**
 * @brief Whether a public key has a shape the applet takes: a Montgomery u-coordinate, or an
 * uncompressed Weierstrass point of a known curve.
 * @param public_key The key.
 * @return true when the length belongs to a curve of `kCurves`.
 */
constexpr bool IsPlausiblePeerKey(ByteSpan public_key) noexcept {
  if (IsMontgomeryKey(public_key)) {
    return true;
  }
  if (public_key.empty() || (public_key[0] != 0x04U)) {
    return false;
  }
  return std::ranges::any_of(detail::kCurves, [&public_key](const CurveInfo& c) {
    return c.weierstrass && (c.public_length == public_key.size());
  });
}

/**
 * @brief Write the attestation TLVs of a C-APDU: TAG_5 key id, TAG_6 algorithm, TAG_7 freshness
 * (ReadObject; I2CM uses TAG_2 and TAG_3 for the first two).
 * @param w The writer.
 * @param key_tag The tag of the key id.
 * @param algo_tag The tag of the algorithm.
 * @param key The attestation key.
 * @param algo The algorithm.
 * @param freshness The 16-byte nonce.
 */
constexpr void PutAttestation(CommandWriter& w, uint8_t key_tag, uint8_t algo_tag, ObjectId key,
                              AttestationAlgo algo,
                              const std::array<uint8_t, kFreshnessLength>& freshness) noexcept {
  uint8_t wire = 0U;
  if ((key.value == 0U) || !AttestationWire(algo, wire)) {
    w.Refuse(Error::InvalidArgument);
    return;
  }
  w.TlvU32(key_tag, key.value);
  w.TlvU8(algo_tag, wire);
  w.Tlv(kTag7, ByteSpan{freshness});
}

/** @brief Where the parts of an attested answer go. */
struct AttestedSinks {
  MutableByteSpan data;      ///< The caller buffer for the data (empty when none is expected).
  MutableByteSpan signature; ///< The caller buffer for the signature.
};

/**
 * @brief Parse a format 2 attested answer (applet 7.x: AN12543 Tables 128, 131, 313):
 * `[TAG_1 data] TAG_2 chip id [TAG_3 attributes] TAG_4 size TAG_TS timestamp TAG_ATT_SIG sig`.
 * @param data The response body.
 * @param sinks The caller buffers.
 * @param reply The reply.
 * @return `Ok`, `FrameError` or `BufferTooSmall`.
 */
constexpr Result<void> DecodeAttestedV2(ByteSpan data, const AttestedSinks& sinks,
                                        AttestedRead& reply) noexcept {
  ReplyParser p(data);
  const Result<OptionalTlv> value = p.Optional(kTag1);
  const Result<ByteSpan> uid = p.NeedLength(kTag2, kUniqueIdLength);
  const Result<OptionalTlv> attributes = p.Optional(kTag3);
  const Result<ByteSpan> size = p.NeedLength(kTag4, 2U);
  const Result<ByteSpan> ts = p.NeedLength(kTagTimestamp, kTimestampLength);
  const Result<ByteSpan> sig = p.Need(kTagSignature);
  const Result<void> end = p.End();
  if (!value.ok() || !uid.ok() || !attributes.ok() || !size.ok() || !ts.ok() || !sig.ok() ||
      !end.ok()) {
    return Fail<void>(Error::FrameError);
  }
  reply.format = AttestationFormat::V2;
  reply.object_size = BigEndian(size.value);
  static_cast<void>(CopyExact(uid.value, reply.unique_id));
  static_cast<void>(CopyExact(ts.value, reply.timestamp));
  const Result<void> a = CopyFixed(attributes.value.value, reply.attributes);
  if (!a.ok()) {
    return a;
  }
  const Result<void> d = CopyOut(value.value.value, sinks.data, reply.data_length);
  if (!d.ok()) {
    return d;
  }
  return CopyOut(sig.value, sinks.signature, reply.signature_length);
}

/**
 * @brief Parse a format 1 attested answer (applet 3.x: AN12413 Tables 106 and 248):
 * `[TAG_1 data] [TAG_2 attributes] TAG_3 timestamp TAG_4 freshness TAG_5 chip id TAG_6 sig`.
 * @param data The response body.
 * @param sinks The caller buffers.
 * @param reply The reply.
 * @return `Ok`, `FrameError` or `BufferTooSmall`.
 */
constexpr Result<void> DecodeAttestedV1(ByteSpan data, const AttestedSinks& sinks,
                                        AttestedRead& reply) noexcept {
  ReplyParser p(data);
  const Result<OptionalTlv> value = p.Optional(kTag1);
  const Result<OptionalTlv> attributes = p.Optional(kTag2);
  const Result<ByteSpan> ts = p.NeedLength(kTag3, kTimestampLength);
  const Result<ByteSpan> fresh = p.NeedLength(kTag4, kFreshnessLength);
  const Result<ByteSpan> uid = p.NeedLength(kTag5, kUniqueIdLength);
  const Result<ByteSpan> sig = p.Need(kTag6);
  const Result<void> end = p.End();
  if (!value.ok() || !attributes.ok() || !ts.ok() || !fresh.ok() || !uid.ok() || !sig.ok() ||
      !end.ok()) {
    return Fail<void>(Error::FrameError);
  }
  reply.format = AttestationFormat::V1;
  static_cast<void>(CopyExact(uid.value, reply.unique_id));
  static_cast<void>(CopyExact(ts.value, reply.timestamp));
  static_cast<void>(CopyExact(fresh.value, reply.freshness));
  const Result<void> a = CopyFixed(attributes.value.value, reply.attributes);
  if (!a.ok()) {
    return a;
  }
  const Result<void> d = CopyOut(value.value.value, sinks.data, reply.data_length);
  if (!d.ok()) {
    return d;
  }
  return CopyOut(sig.value, sinks.signature, reply.signature_length);
}

/**
 * @brief Parse an attested answer of either format. The format is told by the tags, not trusted
 * from the caller: format 2 carries TAG_TS (0x4F) and TAG_ATT_SIG (0x52), format 1 only TAG_1 to
 * TAG_6. The verifier then refuses an answer whose format is not the one of the chip's generation
 * (a downgrade).
 * @param data The response body.
 * @param sinks The caller buffers.
 * @param reply The reply; reset first.
 * @return `Ok`, `FrameError` or `BufferTooSmall`.
 */
constexpr Result<void> DecodeAttested(ByteSpan data, const AttestedSinks& sinks,
                                      AttestedRead& reply) noexcept {
  reply = AttestedRead{};
  TlvReader scan(data);
  bool v2 = false;
  for (std::size_t i = 0U; (i < 8U) && !scan.AtEnd(); ++i) {
    const Result<Tlv> t = scan.Next();
    if (!t.ok()) {
      return Fail<void>(Error::FrameError);
    }
    v2 = v2 || (t.value.tag == kTagTimestamp) || (t.value.tag == kTagSignature);
  }
  return v2 ? DecodeAttestedV2(data, sinks, reply) : DecodeAttestedV1(data, sinks, reply);
}

/**
 * @brief One item of an I2C controller command set at `pos` (see `ValidI2cmCommands`): a known
 * tag, its length, CONFIGURE first and only first, a valid CONFIGURE clock byte.
 * @param commands The command set; at least 3 bytes from `pos`.
 * @param pos The item's offset.
 * @param item The item's index.
 * @return true when the item is well formed.
 */
constexpr bool ValidI2cmItem(ByteSpan commands, std::size_t pos, std::size_t item) noexcept {
  const uint8_t tag = commands[pos];
  const std::size_t length = BigEndian(commands.subspan(pos + 1U, 2U));
  const bool fixed_two = (tag == 0x01U) || (tag == 0x04U);
  if (((tag != 0x01U) && (tag != 0x03U) && (tag != 0x04U)) || (fixed_two && (length != 2U)) ||
      (length > (commands.size() - pos - 3U)) || ((item == 0U) != (tag == 0x01U))) {
    return false;
  }
  // The clock byte of CONFIGURE: 0x00 100 kHz, 0x01 400 kHz.
  return (tag != 0x01U) || (commands[pos + 4U] <= 0x01U);
}

/**
 * @brief Check an I2C controller command set (AN12543 Table 311, p. 146): a sequence of CONFIGURE
 * (0x01, `0002 addr clk`), WRITE (0x03, `len2 data`) and READ (0x04, `0002 len2`) items, at most
 * 255 bytes. The strict reading of p. 146 (Figure 21 reads several times; docs/ambiguities.md
 * A25): CONFIGURE first, its clock byte 0x00 (100 kHz) or 0x01 (400 kHz), at most one READ and
 * only as the last item.
 * @param commands The command set.
 * @return true when well formed.
 */
constexpr bool ValidI2cmCommands(ByteSpan commands) noexcept {
  if (commands.empty() || (commands.size() > kI2cmCommandMax)) {
    return false;
  }
  std::size_t pos = 0U;
  for (std::size_t item = 0U; (item < kI2cmCommandMax) && (pos < commands.size()); ++item) {
    if (((commands.size() - pos) < 3U) || !ValidI2cmItem(commands, pos, item)) {
      return false;
    }
    const uint8_t tag = commands[pos];
    pos += 3U + BigEndian(commands.subspan(pos + 1U, 2U));
    if ((tag == 0x04U) && (pos != commands.size())) {
      return false;
    }
  }
  return pos == commands.size();
}

/**
 * @brief An answer that is exactly TLV[TAG_1] of `length` bytes, copied into a fixed reply.
 * @tparam N The capacity of the reply.
 * @param data The body.
 * @param length The length; 0 accepts any length that fits.
 * @param reply The reply.
 * @return `Ok`, `FrameError` or `BufferTooSmall`.
 */
template <std::size_t N>
constexpr Result<void> Tag1Fixed(ByteSpan data, std::size_t length, FixedBytes<N>& reply) noexcept {
  ReplyParser p(data);
  const Result<ByteSpan> v = (length == 0U) ? p.Need(kTag1) : p.NeedLength(kTag1, length);
  if (!v.ok() || !p.End().ok()) {
    return Fail<void>(Error::FrameError);
  }
  return CopyFixed(v.value, reply);
}

} // namespace se05x::apdu::detail

#endif // SE05X_APDU_BASE_HPP
