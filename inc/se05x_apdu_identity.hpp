/**
 * @file se05x_apdu_identity.hpp
 * @brief The `Codec<C>` specialisations of the commands of the groups Identity, Session and
 * Management.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Layouts: AN12543 Rev 4.5 sections 4.4 to 4.6 and 4.16 (applet 7.x), AN12413
 * Rev 2.12 sections 4.4 to 4.6 and 4.19 (applet 3.x), GlobalPlatform Card Specification (GET DATA,
 * INITIALIZE UPDATE, EXTERNAL AUTHENTICATE). Three layouts are derived, not printed in the
 * specifications, and say so where they are: the GET DATA of the card identification (tag DF28;
 * AN13030 pp. 227-228 show only the answer), of the CPLC (tag 9F7F) and of the card manager
 * garbage collection (tag DF25; AN13030 p. 262 shows only the answer). Those three go to the card
 * manager, so the device selects it first and selects the IoT applet again afterwards.
 */
#ifndef SE05X_APDU_IDENTITY_HPP
#define SE05X_APDU_IDENTITY_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "se05x_apdu.hpp"
#include "se05x_apdu_base.hpp"
#include "se05x_apdu_consts.hpp"
#include "se05x_codec.hpp"
#include "se05x_policy.hpp"

namespace se05x {

namespace apdu::detail {

/**
 * @brief The 7-byte VersionInfo (AN12543 4.3.40).
 * @param bytes The 7 bytes.
 * @param info Receives the version.
 * @return `Ok`, or `FrameError` for another length.
 */
constexpr Result<void> ParseVersionInfo(ByteSpan bytes, AppletInfo& info) noexcept {
  if (bytes.size() != 7U) {
    return Fail<void>(Error::FrameError);
  }
  info.version = AppletVersion{.major = bytes[0], .minor = bytes[1], .patch = bytes[2]};
  info.applet_config = static_cast<uint16_t>(BigEndian(bytes.subspan(3U, 2U)));
  info.secure_box = static_cast<uint16_t>(BigEndian(bytes.subspan(5U, 2U)));
  return Result<void>::Success();
}

/**
 * @brief Read one element with a two-byte tag (GP GET DATA answers: 9F7F, DF28, DF25).
 * @param data The bytes.
 * @param pos The position; advanced past the element.
 * @param tag The expected two-byte tag.
 * @param value Receives the value.
 * @return true when the element is well formed and fits.
 */
constexpr bool TwoByteTag(ByteSpan data, std::size_t& pos, uint16_t tag, ByteSpan& value) noexcept {
  if ((pos > data.size()) || ((data.size() - pos) < 3U) ||
      (BigEndian(data.subspan(pos, 2U)) != static_cast<uint32_t>(tag))) {
    return false;
  }
  TlvReader r(data.subspan(pos + 1U)); // the second tag byte stands in for a one-byte tag
  const Result<Tlv> t = r.Next();
  if (!t.ok()) {
    return false;
  }
  const uint8_t first = data[pos + 2U];
  std::size_t length_bytes = 1U;
  if (first == 0x81U) {
    length_bytes = 2U;
  } else if (first == 0x82U) {
    length_bytes = 3U;
  } else {
    length_bytes = 1U;
  }
  value = t.value.value;
  pos += 2U + length_bytes + value.size();
  return true;
}

/**
 * @brief Unwrap the proprietary template FE of a GP GET DATA answer and the two-byte-tag element
 * inside it, which must fill the template exactly.
 * @param data The response body.
 * @param tag The inner tag (DF28 or DF25).
 * @param value Receives the inner value.
 * @return `Ok` or `FrameError`.
 */
constexpr Result<void> UnwrapFe(ByteSpan data, uint16_t tag, ByteSpan& value) noexcept {
  ReplyParser p(data);
  const Result<ByteSpan> fe = p.Need(0xFEU);
  if (!fe.ok() || !p.End().ok()) {
    return Fail<void>(Error::FrameError);
  }
  std::size_t pos = 0U;
  if (!TwoByteTag(fe.value, pos, tag, value) || (pos != fe.value.size())) {
    return Fail<void>(Error::FrameError);
  }
  return Result<void>::Success();
}

/**
 * @brief GP GET DATA `80 CA <P1 P2> [Lc tag list] 00`.
 * @param out The buffer.
 * @param p1p2 P1 and P2.
 * @param tags The tag list, or empty.
 * @return The length or an error.
 */
constexpr Result<std::size_t> EncodeGetData(MutableByteSpan out, uint16_t p1p2,
                                            ByteSpan tags) noexcept {
  CommandWriter w(out, kClaPlain, kInsGetData,
                  static_cast<uint8_t>((static_cast<uint32_t>(p1p2) >> 8U) & 0xFFU),
                  static_cast<uint8_t>(static_cast<uint32_t>(p1p2) & 0xFFU));
  w.Raw(tags);
  w.ExpectResponse(kShortLeMax);
  return w.Finish();
}

/**
 * @brief Whether a UserID or AESKey secret, SCP challenge or cryptogram has one of two lengths.
 * @param bytes The bytes.
 * @param a The first allowed length.
 * @param b The second allowed length.
 * @return true when the length is `a` or `b`.
 */
constexpr bool LengthIs(ByteSpan bytes, std::size_t a, std::size_t b) noexcept {
  return (bytes.size() == a) || (bytes.size() == b);
}

/**
 * @brief The management commands with only small TLVs: `80 04 00 P2 [TLVs]` without an answer.
 * @param out The buffer.
 * @param p2 P2.
 * @param t1 TAG_1 value.
 * @param t2 TAG_2 value, or empty.
 * @return The length or an error.
 */
constexpr Result<std::size_t> EncodeMgmt(MutableByteSpan out, uint8_t p2, ByteSpan t1,
                                         ByteSpan t2) noexcept {
  CommandWriter w(out, kClaPlain, kInsMgmt, kP1Default, p2);
  w.Tlv(kTag1, t1);
  if (!t2.empty()) {
    w.Tlv(kTag2, t2);
  }
  return w.Finish();
}

} // namespace apdu::detail

/// `SelectApplet`: `00 A4 04 00 10 <AID> 00` (AN12543 Table 64); answer: 7-byte VersionInfo.
template <>
struct Codec<Command::SelectApplet> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args None. @param out The buffer. @return The length or an error. */
  static constexpr Result<std::size_t> Encode(const Empty& args, MutableByteSpan out) noexcept {
    static_cast<void>(args);
    apdu::detail::CommandWriter w(out, apdu::kClaIso, apdu::kInsSelect, 0x04U, 0x00U);
    w.Raw(ByteSpan{apdu::kAppletAid});
    w.ExpectResponse(7U);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or an error. */
  static constexpr Result<void> Decode(ByteSpan data, AppletInfo& reply) noexcept {
    return apdu::detail::ParseVersionInfo(data, reply);
  }
  /** @brief Decode. @param args None. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const Empty& args, ByteSpan data,
                                       AppletInfo& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `GetVersion`: `80 04 00 20 00`; answer: TLV[TAG_1] with the 7-byte VersionInfo.
template <>
struct Codec<Command::GetVersion> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args None. @param out The buffer. @return The length or an error. */
  static constexpr Result<std::size_t> Encode(const Empty& args, MutableByteSpan out) noexcept {
    static_cast<void>(args);
    return apdu::detail::EncodeBare(out, apdu::kClaPlain, apdu::kInsMgmt, apdu::kP1Default,
                                    apdu::kP2Version, apdu::detail::TlvBudget(7U));
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or an error. */
  static constexpr Result<void> Decode(ByteSpan data, AppletInfo& reply) noexcept {
    apdu::detail::ReplyParser p(data);
    const Result<ByteSpan> v = p.Need(apdu::kTag1);
    if (!v.ok() || !p.End().ok()) {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    return apdu::detail::ParseVersionInfo(v.value, reply);
  }
  /** @brief Decode. @param args None. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const Empty& args, ByteSpan data,
                                       AppletInfo& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `GetExtVersion`: `80 04 00 21 00`; answer: TLV[TAG_1] with 37 bytes, the VersionInfo and the
/// 30-byte extended feature bitmap (AN12543 4.20.1). The reply keeps the 30 bitmap bytes.
template <>
struct Codec<Command::GetExtVersion> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args None. @param out The buffer. @return The length or an error. */
  static constexpr Result<std::size_t> Encode(const Empty& args, MutableByteSpan out) noexcept {
    static_cast<void>(args);
    return apdu::detail::EncodeBare(out, apdu::kClaPlain, apdu::kInsMgmt, apdu::kP1Default,
                                    apdu::kP2VersionExt, apdu::detail::TlvBudget(37U));
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or an error. */
  static constexpr Result<void> Decode(ByteSpan data, ExtFeatures& reply) noexcept {
    apdu::detail::ReplyParser p(data);
    const Result<ByteSpan> v = p.NeedLength(apdu::kTag1, 7U + kExtFeatureLength);
    if (!v.ok() || !p.End().ok()) {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    return apdu::detail::CopyFixed(v.value.subspan(7U), reply);
  }
  /** @brief Decode. @param args None. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const Empty& args, ByteSpan data,
                                       ExtFeatures& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `GetCardIdentification`: GP GET DATA `80 CA 00 FE 02 DF 28 00` to the card manager (derived:
/// the command is not printed; AN13030 pp. 227-228 show the answer `FE L DF28 L {01 0C config id
/// ...}`). The OEF id is bytes 2 and 3 of the 12-byte configuration id.
template <>
struct Codec<Command::GetCardIdentification> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args None. @param out The buffer. @return The length or an error. */
  static constexpr Result<std::size_t> Encode(const Empty& args, MutableByteSpan out) noexcept {
    static_cast<void>(args);
    constexpr std::array<uint8_t, 2> kTag{0xDFU, 0x28U};
    return apdu::detail::EncodeGetData(out, 0x00FEU, ByteSpan{kTag});
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or an error. */
  static constexpr Result<void> Decode(ByteSpan data, CardId& reply) noexcept {
    ByteSpan value{};
    const Result<void> fe = apdu::detail::UnwrapFe(data, 0xDF28U, value);
    if (!fe.ok()) {
      return fe;
    }
    apdu::TlvReader rest(value);
    const Result<apdu::Tlv> config = rest.Expect(0x01U);
    if (!config.ok() || (config.value.value.size() != 12U)) {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    for (std::size_t i = 0U; (i < kMaxResponse) && !rest.AtEnd(); ++i) {
      if (!rest.Next().ok()) {
        return apdu::detail::Fail<void>(Error::FrameError);
      }
    }
    reply.oef_id =
        static_cast<uint16_t>(apdu::detail::BigEndian(config.value.value.subspan(2U, 2U)));
    return apdu::detail::CopyFixed(value, reply.raw);
  }
  /** @brief Decode. @param args None. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const Empty& args, ByteSpan data, CardId& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `GetCplc`: GP GET DATA `80 CA 9F 7F 00` (derived from the GP Card Specification); answer:
/// `9F 7F 2A <42 bytes>`.
template <>
struct Codec<Command::GetCplc> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /// Length of the CPLC data.
  static constexpr std::size_t kCplcLength = 42U;
  /** @brief Encode. @param args None. @param out The buffer. @return The length or an error. */
  static constexpr Result<std::size_t> Encode(const Empty& args, MutableByteSpan out) noexcept {
    static_cast<void>(args);
    return apdu::detail::EncodeGetData(out, 0x9F7FU, ByteSpan{});
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or an error. */
  static constexpr Result<void> Decode(ByteSpan data, Cplc& reply) noexcept {
    std::size_t pos = 0U;
    ByteSpan value{};
    if (!apdu::detail::TwoByteTag(data, pos, 0x9F7FU, value) || (pos != data.size()) ||
        (value.size() != kCplcLength)) {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    return apdu::detail::CopyFixed(value, reply);
  }
  /** @brief Decode. @param args None. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const Empty& args, ByteSpan data, Cplc& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `CreateSession`: `80 04 00 1B` TLV[TAG_1] 4-byte authentication object, Le; answer:
/// TLV[TAG_1] 8-byte session id (AN12543 Tables 67, 68).
template <>
struct Codec<Command::CreateSession> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error (`InvalidArgument` for the id 0). */
  static constexpr Result<std::size_t> Encode(const CreateSessionArgs& args,
                                              MutableByteSpan out) noexcept {
    return apdu::detail::EncodeId(out, apdu::kInsMgmt, apdu::kP1Default, apdu::kP2SessionCreate,
                                  args.authentication, apdu::detail::TlvBudget(8U));
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or an error. */
  static constexpr Result<void> Decode(ByteSpan data, SessionId& reply) noexcept {
    return apdu::detail::Tag1Fixed(data, 8U, reply);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const CreateSessionArgs& args, ByteSpan data,
                                       SessionId& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `ExchangeSessionData`: `80 04 00 1F` TLV[TAG_1] session policy (AN12543 Table 70); no answer
/// body on the plain channel (an R-MAC is the secure channel's).
template <>
struct Codec<Command::ExchangeSessionData> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const ExchangeSessionDataArgs& args,
                                              MutableByteSpan out) noexcept {
    const Result<FixedBytes<8>> policy = EncodeSessionPolicy(args.policy);
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsMgmt, apdu::kP1Default,
                                  apdu::kP2SessionPolicy);
    if (!policy.ok()) {
      w.Refuse(policy.error);
    }
    w.Tlv(apdu::kTag1, policy.value.View());
    w.ExpectResponse(apdu::detail::kShortLeMax);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const ExchangeSessionDataArgs& args, ByteSpan data,
                                       Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `RefreshSession`: `80 04 00 1E [TLV[TAG_POLICY] session policy]` (AN12543 Table 76).
template <>
struct Codec<Command::RefreshSession> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const RefreshSessionArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsMgmt, apdu::kP1Default,
                                  apdu::kP2SessionRefresh);
    if (args.has_policy) {
      const Result<FixedBytes<8>> policy = EncodeSessionPolicy(args.policy);
      if (!policy.ok()) {
        w.Refuse(policy.error);
      }
      w.Tlv(apdu::kTagPolicy, policy.value.View());
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
  static constexpr Result<void> Decode(const RefreshSessionArgs& args, ByteSpan data,
                                       Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `CloseSession`: `80 04 00 1C` (ISO case 1, AN12543 Table 79). Never sent without a session
/// (errata APP.2: that is the device's rule).
template <>
struct Codec<Command::CloseSession> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args None. @param out The buffer. @return The length or an error. */
  static constexpr Result<std::size_t> Encode(const Empty& args, MutableByteSpan out) noexcept {
    static_cast<void>(args);
    return apdu::detail::EncodeBare(out, apdu::kClaPlain, apdu::kInsMgmt, apdu::kP1Default,
                                    apdu::kP2SessionClose, 0U);
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args None. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const Empty& args, ByteSpan data, Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `VerifySessionUserId`: `80 04 00 2C` TLV[TAG_1] UserID value, 1 to 16 bytes (AN12543 Table 82;
/// SE050 accepts 1 to 16 bytes, SE051 4 to 16; the chip refuses a wrong length with 0x6985).
template <>
struct Codec<Command::VerifySessionUserId> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const VerifyUserIdArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsMgmt, apdu::kP1Default,
                                  apdu::kP2SessionUserId);
    if (args.user_secret.empty() || (args.user_secret.size() > apdu::kUserIdMax)) {
      w.Refuse(Error::InvalidArgument);
    }
    w.Tlv(apdu::kTag1, args.user_secret);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const VerifyUserIdArgs& args, ByteSpan data,
                                       Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `ScpInitializeUpdate` (AESKey session): GP INITIALIZE UPDATE `80 50 00 00 <Lc> <host
/// challenge> 00`, KVN 00 (AN12543 4.5.3.1); the host challenge is 8 bytes (S8) or 16 (S16). The
/// answer is not TLV: key diversification data (10), key information (3), card challenge,
/// card cryptogram and an optional 3-byte sequence counter; it is kept raw in the reply.
template <>
struct Codec<Command::ScpInitializeUpdate> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const ScpInitArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsInitializeUpdate, 0x00U, 0x00U);
    if (!apdu::detail::LengthIs(args.host_challenge, 8U, 16U)) {
      w.Refuse(Error::InvalidArgument);
    }
    w.Raw(args.host_challenge);
    w.ExpectResponse(apdu::detail::kShortLeMax);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`
   * for a length other than 29, 32 (S8) or 45, 48 (S16). */
  static constexpr Result<void> Decode(ByteSpan data, SmallBlob& reply) noexcept {
    if (!apdu::detail::LengthIs(data, 29U, 32U) && !apdu::detail::LengthIs(data, 45U, 48U)) {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    return apdu::detail::CopyFixed(data, reply);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const ScpInitArgs& args, ByteSpan data,
                                       SmallBlob& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `ScpExternalAuthenticate` (AESKey session): GP EXTERNAL AUTHENTICATE `84 82 33 00 <Lc> <host
/// cryptogram>`; security level 0x33 (C-MAC, C-DECRYPTION, R-MAC, R-ENCRYPTION). The secure
/// channel appends the C-MAC and corrects Lc.
template <>
struct Codec<Command::ScpExternalAuthenticate> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /// The security level of the session (full secure messaging).
  static constexpr uint8_t kSecurityLevel = 0x33U;
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const ScpExternalAuthArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaSecure, apdu::kInsExternalAuthenticate,
                                  kSecurityLevel, 0x00U);
    if (!apdu::detail::LengthIs(args.host_cryptogram, 8U, 16U)) {
      w.Refuse(Error::InvalidArgument);
    }
    w.Raw(args.host_cryptogram);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const ScpExternalAuthArgs& args, ByteSpan data,
                                       Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `EcKeySessionInternalAuthenticate`: `84 88 00 00 <Lc> <A6 ... 7F49 ... 5F37 ...> 00`
/// (AN12543 Tables 85, 86). `host_data` is the whole payload, built by the ECKey layer; the
/// middleware sends it without an outer TAG_1. The answer `85 10 <challenge> 86 10 <receipt>` is
/// checked and kept raw in the reply.
template <>
struct Codec<Command::EcKeySessionInternalAuthenticate> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error (`InvalidArgument` unless the payload starts with the template A6). */
  static constexpr Result<std::size_t> Encode(const EcKeyAuthArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaSecure, apdu::kInsInternalAuthenticate, 0x00U,
                                  0x00U);
    if (args.host_data.empty() || (args.host_data[0] != 0xA6U) ||
        (args.host_data.size() > apdu::detail::kShortLcMax)) {
      w.Refuse(Error::InvalidArgument);
    }
    w.Raw(args.host_data);
    w.ExpectResponse(apdu::detail::kShortLeMax);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, SmallBlob& reply) noexcept {
    apdu::detail::ReplyParser p(data);
    if (!p.NeedLength(0x85U, 16U).ok() || !p.NeedLength(0x86U, 16U).ok() || !p.End().ok()) {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    return apdu::detail::CopyFixed(data, reply);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const EcKeyAuthArgs& args, ByteSpan data,
                                       SmallBlob& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `EcKeySessionGetEckaPublicKey` (applet 3.x): `84 CA BF 21 06 A6 04 83 02 00 00 00`, key
/// identifier 00 (user authentication) and key version 00 (AN12413 Tables 76, 77). The answer
/// `7F49 ... 5F37 ...` is checked to start with 7F49 and kept raw.
template <>
struct Codec<Command::EcKeySessionGetEckaPublicKey> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args None. @param out The buffer. @return The length or an error. */
  static constexpr Result<std::size_t> Encode(const Empty& args, MutableByteSpan out) noexcept {
    static_cast<void>(args);
    constexpr std::array<uint8_t, 6> kPayload{0xA6U, 0x04U, 0x83U, 0x02U, 0x00U, 0x00U};
    apdu::detail::CommandWriter w(out, apdu::kClaSecure, apdu::kInsGetData, 0xBFU, 0x21U);
    w.Raw(ByteSpan{kPayload});
    w.ExpectResponse(apdu::detail::kShortLeMax);
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, SmallBlob& reply) noexcept {
    std::size_t pos = 0U;
    ByteSpan key{};
    if (!apdu::detail::TwoByteTag(data, pos, 0x7F49U, key) || key.empty()) {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    return apdu::detail::CopyFixed(data, reply);
  }
  /** @brief Decode. @param args None. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const Empty& args, ByteSpan data,
                                       SmallBlob& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `SetLockState`: `80 04 00 3E` TLV[TAG_1] PERSISTENT_LOCK (02), TLV[TAG_2] LOCKED (01)
/// (AN12543 Table 90). Irreversible: run only through `irreversible::` (S-10).
template <>
struct Codec<Command::SetLockState> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const SetLockStateArgs& args,
                                              MutableByteSpan out) noexcept {
    if (args.state != LockStateValue::Locked) {
      return apdu::detail::Fail<std::size_t>(Error::InvalidArgument);
    }
    constexpr std::array<uint8_t, 1> kIndicator{apdu::kLockPersistent};
    constexpr std::array<uint8_t, 1> kState{apdu::kLockLocked};
    return apdu::detail::EncodeMgmt(out, apdu::kP2Transport, ByteSpan{kIndicator},
                                    ByteSpan{kState});
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const SetLockStateArgs& args, ByteSpan data,
                                       Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `SetPlatformScpRequest`: `80 04 00 52` TLV[TAG_1] 01 required or 02 not required (AN12543
/// Table 96). Irreversible (S-10).
template <>
struct Codec<Command::SetPlatformScpRequest> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const SetPlatformScpRequestArgs& args,
                                              MutableByteSpan out) noexcept {
    if (!detail::IsEnumerator(args.requirement)) {
      return apdu::detail::Fail<std::size_t>(Error::InvalidArgument);
    }
    const std::array<uint8_t, 1> value{(args.requirement == ScpRequirement::Required)
                                           ? apdu::kScpRequired
                                           : apdu::kScpNotRequired};
    return apdu::detail::EncodeMgmt(out, apdu::kP2Scp, ByteSpan{value}, ByteSpan{});
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const SetPlatformScpRequestArgs& args, ByteSpan data,
                                       Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `SetAppletFeatures`: `80 04 00 3F` TLV[TAG_1] 2-byte AppletConfig, or 32 bytes with the
/// extended feature bitmap (AN12543 Table 99; applet 3.x takes the 2-byte form only, AN12413
/// Table 87). Irreversible (S-10).
template <>
struct Codec<Command::SetAppletFeatures> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const SetAppletFeaturesArgs& args,
                                              MutableByteSpan out) noexcept {
    std::array<uint8_t, 2U + kExtFeatureLength> value{};
    value[0] = static_cast<uint8_t>((static_cast<uint32_t>(args.applet_config) >> 8U) & 0xFFU);
    value[1] = static_cast<uint8_t>(static_cast<uint32_t>(args.applet_config) & 0xFFU);
    std::size_t length = 2U;
    if (args.has_ext) {
      for (std::size_t i = 0U; i < kExtFeatureLength; ++i) {
        value[2U + i] = args.ext[i];
      }
      length = value.size();
    }
    return apdu::detail::EncodeMgmt(out, apdu::kP2Variant, ByteSpan{value.data(), length},
                                    ByteSpan{});
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const SetAppletFeaturesArgs& args, ByteSpan data,
                                       Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `DeleteAll`: `80 04 00 2A 00` (AN12543 Table 339 prints `Lc 0x00`; the byte is sent).
/// Irreversible (S-10); inside a secure session the answer is not wrapped (the device closes the
/// channel).
template <>
struct Codec<Command::DeleteAll> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args None. @param out The buffer. @return The length or an error. */
  static constexpr Result<std::size_t> Encode(const Empty& args, MutableByteSpan out) noexcept {
    static_cast<void>(args);
    return apdu::detail::EncodeBare(out, apdu::kClaPlain, apdu::kInsMgmt, apdu::kP1Default,
                                    apdu::kP2DeleteAll, 1U);
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args None. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const Empty& args, ByteSpan data, Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `DisableObjCreation` (applet 7.x): `80 04 00 57` TLV[TAG_1] PERSISTENT_LOCK (02), TLV[TAG_2]
/// RestrictMode 01 new or 02 all (AN12543 Table 93). Irreversible (S-10).
template <>
struct Codec<Command::DisableObjCreation> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const DisableObjCreationArgs& args,
                                              MutableByteSpan out) noexcept {
    if (!detail::IsEnumerator(args.mode)) {
      return apdu::detail::Fail<std::size_t>(Error::InvalidArgument);
    }
    constexpr std::array<uint8_t, 1> kIndicator{apdu::kLockPersistent};
    const std::array<uint8_t, 1> mode{
        (args.mode == RestrictMode::RestrictNew) ? apdu::kRestrictNew : apdu::kRestrictAll};
    return apdu::detail::EncodeMgmt(out, apdu::kP2Restrict, ByteSpan{kIndicator}, ByteSpan{mode});
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const DisableObjCreationArgs& args, ByteSpan data,
                                       Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `GetFreeMemory`: `80 04 00 22` TLV[TAG_1] Memory, Le; answer TLV[TAG_1] of 2 bytes (SE050,
/// SE051; 0x7FFF means 32768 or more) or 4 bytes (SE052) (AN12543 4.20.3).
template <>
struct Codec<Command::GetFreeMemory> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const FreeMemoryArgs& args,
                                              MutableByteSpan out) noexcept {
    uint8_t memory = 0U;
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsMgmt, apdu::kP1Default,
                                  apdu::kP2Memory);
    if (!apdu::MemoryWire(args.memory, memory)) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU8(apdu::kTag1, memory);
    w.ExpectResponse(apdu::detail::TlvBudget(4U));
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, U32Reply& reply) noexcept {
    apdu::detail::ReplyParser p(data);
    const Result<ByteSpan> v = p.Need(apdu::kTag1);
    if (!v.ok() || !p.End().ok() || !apdu::detail::LengthIs(v.value, 2U, 4U)) {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    reply.value = apdu::detail::BigEndian(v.value);
    return Result<void>::Success();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const FreeMemoryArgs& args, ByteSpan data,
                                       U32Reply& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `GetTimestamp`: `80 04 00 3D 00`; answer TLV[TAG_1] 12 bytes (AN12543 4.20.2).
template <>
struct Codec<Command::GetTimestamp> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args None. @param out The buffer. @return The length or an error. */
  static constexpr Result<std::size_t> Encode(const Empty& args, MutableByteSpan out) noexcept {
    static_cast<void>(args);
    return apdu::detail::EncodeBare(out, apdu::kClaPlain, apdu::kInsMgmt, apdu::kP1Default,
                                    apdu::kP2Time, apdu::detail::TlvBudget(kTimestampLength));
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, Timestamp& reply) noexcept {
    apdu::detail::ReplyParser p(data);
    const Result<ByteSpan> v = p.Need(apdu::kTag1);
    if (!v.ok() || !p.End().ok()) {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    return apdu::detail::CopyExact(v.value, reply);
  }
  /** @brief Decode. @param args None. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const Empty& args, ByteSpan data,
                                       Timestamp& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `GetRandom`: `80 04 00 49` TLV[TAG_1] 2-byte size, Le; answer TLV[TAG_1] of exactly that many
/// bytes (AN12543 4.20.4). The size is `out.size()`, 1 to `kMaxRandom`.
template <>
struct Codec<Command::GetRandom> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const GetRandomArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsMgmt, apdu::kP1Default,
                                  apdu::kP2Random);
    if (args.out.empty() || (args.out.size() > apdu::detail::kMaxRandom)) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU16(apdu::kTag1, static_cast<uint16_t>(args.out.size() & 0xFFFFU));
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
   * @return `Ok`, `FrameError` (another length than requested) or `BufferTooSmall`. */
  static constexpr Result<void> Decode(const GetRandomArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    apdu::detail::ReplyParser p(data);
    const Result<ByteSpan> v = p.NeedLength(apdu::kTag1, args.out.size());
    if (!v.ok() || !p.End().ok()) {
      return apdu::detail::Fail<void>(Error::FrameError);
    }
    return apdu::detail::CopyOut(v.value, args.out, reply.length);
  }
};

/// `ReadState` (applet 7.x): `80 02 00 5B 00`; answer TLV[TAG_1] 3 bytes: LockState,
/// RestrictMode, PlatformSCPRequest (AN12543 4.6.7; AN13030 p. 259 sample `41 82 00 03 02 00 02`).
template <>
struct Codec<Command::ReadState> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args None. @param out The buffer. @return The length or an error. */
  static constexpr Result<std::size_t> Encode(const Empty& args, MutableByteSpan out) noexcept {
    static_cast<void>(args);
    return apdu::detail::EncodeBare(out, apdu::kClaPlain, apdu::kInsRead, apdu::kP1Default,
                                    apdu::kP2State, apdu::detail::TlvBudget(3U));
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, SmallBlob& reply) noexcept {
    return apdu::detail::Tag1Fixed(data, 3U, reply);
  }
  /** @brief Decode. @param args None. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const Empty& args, ByteSpan data,
                                       SmallBlob& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `CmInvokeGarbageCollection`: GP GET DATA `80 CA 00 FE 02 DF 25 00` to the card manager
/// (derived: AN13030 p. 262 prints only the answer `FE 03 DF 25 00`). Wears the memory and
/// closes the session.
template <>
struct Codec<Command::CmInvokeGarbageCollection> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args None. @param out The buffer. @return The length or an error. */
  static constexpr Result<std::size_t> Encode(const Empty& args, MutableByteSpan out) noexcept {
    static_cast<void>(args);
    constexpr std::array<uint8_t, 2> kTag{0xDFU, 0x25U};
    return apdu::detail::EncodeGetData(out, 0x00FEU, ByteSpan{kTag});
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, Empty& reply) noexcept {
    static_cast<void>(reply);
    ByteSpan value{};
    return apdu::detail::UnwrapFe(data, 0xDF25U, value);
  }
  /** @brief Decode. @param args None. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const Empty& args, ByteSpan data, Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

/// `SendCardManagerCmd` (applet 7.x): `80 04 00 55` TLV[TAG_1] card manager APDU, Le; answer
/// TLV[TAG_1] card manager response (AN12543 Tables 102, 103). The card manager still demands its
/// own authentication.
template <>
struct Codec<Command::SendCardManagerCmd> {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error (`InvalidArgument` for a command shorter than an APDU header). */
  static constexpr Result<std::size_t> Encode(const CardManagerCmdArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsMgmt, apdu::kP1Default,
                                  apdu::kP2CmCommand);
    if (args.command.size() < 4U) {
      w.Refuse(Error::InvalidArgument);
    }
    w.Tlv(apdu::kTag1, args.command);
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
  static constexpr Result<void> Decode(const CardManagerCmdArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    return apdu::detail::DecodeTag1Into(data, args.out, reply.length);
  }
};

/// `TriggerSelfTest` (applet 7.x): `80 04 00 58` TLV[TAG_1] 2-byte HealthCheckMode, Le; answer
/// TLV[TAG_1] Result (AN12543 4.6.6). On a failure the chip may reset without an answer.
template <>
struct Codec<Command::TriggerSelfTest> {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error (`InvalidArgument` for a value that is not a HealthCheckMode of Table 57). */
  static constexpr Result<std::size_t> Encode(const SelfTestArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsMgmt, apdu::kP1Default,
                                  apdu::kP2Sanity);
    bool known = false;
    for (const uint16_t mode : apdu::kHealthCheckModes) {
      known = known || (mode == args.test);
    }
    if (!known) {
      w.Refuse(Error::InvalidArgument);
    }
    w.TlvU16(apdu::kTag1, args.test);
    w.ExpectResponse(apdu::detail::TlvBudget(1U));
    return w.Finish();
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, SelfTestReply& reply) noexcept {
    return apdu::detail::DecodeResult(data, reply.passed);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const SelfTestArgs& args, ByteSpan data,
                                       SelfTestReply& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};

} // namespace se05x

#endif // SE05X_APDU_IDENTITY_HPP
