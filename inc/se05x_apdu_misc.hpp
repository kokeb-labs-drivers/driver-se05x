/**
 * @file se05x_apdu_misc.hpp
 * @brief The codecs (`Codec<C>`) of the commands of the groups Desfire and I2cm.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Layouts: AN12543 Rev 4.5 sections 4.16 (MIFARE DESFire, AES-128 EV2 S-mode)
 * and 4.18 (I2C controller). The DESFire P2 values are those of Table 29 (FIRST_PART1 53,
 * FIRST_PART2 12, NONFIRST_PART1 54, NONFIRST_PART2 13); the summary table 342 swaps two of them
 * and is not followed (the middleware agrees with Table 29). The DESFire commands share one
 * argument type: a field a command does not use must stay 0 or empty, so nothing is silently
 * ignored.
 */
#ifndef SE05X_APDU_MISC_HPP
#define SE05X_APDU_MISC_HPP

#include <cstddef>
#include <cstdint>

#include "se05x_apdu.hpp"
#include "se05x_apdu_base.hpp"
#include "se05x_apdu_consts.hpp"
#include "se05x_codec.hpp"

namespace se05x {

namespace apdu::detail {

/// Length of the DESFire challenges and cryptograms (AN12543 4.16).
inline constexpr std::size_t kDfBlock = 16U;

/** @brief Which fields of `DfArgs` a DESFire command uses, and the lengths it needs. */
struct DfShape {
  uint8_t p2{0};            ///< P2.
  bool uses_key{false};     ///< `key` goes in TLV[TAG_1].
  bool uses_target{false};  ///< `target` is sent (TAG_2).
  std::size_t input_min{0}; ///< Shortest `input`; 0 with `input_max` 0: no input.
  std::size_t input_max{0}; ///< Longest `input`.
  std::size_t answer{0};    ///< Length of TLV[TAG_1] in the answer; 0: no answer data.
};

/**
 * @brief Check the fields of `DfArgs` against a shape.
 * @param args The arguments.
 * @param s The shape.
 * @return true when every used field is set and every unused one is empty.
 */
constexpr bool DfArgsFit(const DfArgs& args, const DfShape& s) noexcept {
  const bool key_ok = s.uses_key ? (args.key.value != 0U) : (args.key.value == 0U);
  const bool target_ok = s.uses_target ? (args.target.value != 0U) : (args.target.value == 0U);
  const bool input_ok = (args.input.size() >= s.input_min) && (args.input.size() <= s.input_max);
  const bool out_ok = (s.answer == 0U) ? args.out.empty() : (args.out.size() >= s.answer);
  return key_ok && target_ok && input_ok && out_ok;
}

/**
 * @brief Encode a DESFire command of the simple shapes: `80 03 00 <P2>` [TLV[TAG_1] key]
 * [TLV[TAG_2] target] then the input in the next TLV ([TAG_1] when no key, else TAG_2 or TAG_3).
 * @param out The buffer.
 * @param args The arguments.
 * @param s The shape.
 * @return The length or an error.
 */
constexpr Result<std::size_t> EncodeDf(MutableByteSpan out, const DfArgs& args,
                                       const DfShape& s) noexcept {
  CommandWriter w(out, kClaPlain, kInsCrypto, kP1Default, s.p2);
  if (!DfArgsFit(args, s)) {
    w.Refuse(Error::InvalidArgument);
  }
  uint8_t next = kTag1;
  if (s.uses_key) {
    w.TlvU32(next, args.key.value);
    ++next;
  }
  if (s.uses_target) {
    w.TlvU32(next, args.target.value);
    ++next;
  }
  if (s.input_max != 0U) {
    w.Tlv(next, args.input);
  }
  if (s.answer != 0U) {
    w.ExpectResponse(TlvBudget(s.answer));
  }
  return w.Finish();
}

/**
 * @brief Decode a DESFire answer of a fixed length into `out`, or an empty answer.
 * @param args The arguments.
 * @param data The body.
 * @param s The shape.
 * @param length Receives the length.
 * @return `Ok`, `FrameError` or `BufferTooSmall`.
 */
constexpr Result<void> DecodeDf(const DfArgs& args, ByteSpan data, const DfShape& s,
                                std::size_t& length) noexcept {
  length = 0U;
  if (s.answer == 0U) {
    return ExpectEmpty(data);
  }
  ReplyParser p(data);
  const Result<ByteSpan> v = p.NeedLength(kTag1, s.answer);
  if (!v.ok() || !p.End().ok()) {
    return Fail<void>(Error::FrameError);
  }
  return CopyOut(v.value, args.out, length);
}

/// DFDiversifyKey (Table 274): master key, target key, divInput 1 to 31 bytes.
inline constexpr DfShape kDfDiversify{.p2 = kP2Diversify,
                                      .uses_key = true,
                                      .uses_target = true,
                                      .input_min = 1U,
                                      .input_max = kDfDivInputMax,
                                      .answer = 0U};
/// DFAuthenticateFirstPart1 (Table 277): key, E(Kx, RndB); answer 32 bytes.
inline constexpr DfShape kDfFirst1{.p2 = kP2AuthFirstPart1,
                                   .uses_key = true,
                                   .uses_target = false,
                                   .input_min = kDfBlock,
                                   .input_max = kDfBlock,
                                   .answer = 32U};
/// DFAuthenticateFirstPart2 (Table 280): 32 bytes; answer PDcap2 || PCDcap2, 12 bytes.
inline constexpr DfShape kDfFirst2{.p2 = kP2AuthFirstPart2,
                                   .uses_key = false,
                                   .uses_target = false,
                                   .input_min = 32U,
                                   .input_max = 32U,
                                   .answer = 12U};
/// DFAuthenticateNonFirstPart1 (Table 283): key, E(Kx, RndB); answer 32 bytes.
inline constexpr DfShape kDfNonFirst1{.p2 = kP2AuthNonFirstPart1,
                                      .uses_key = true,
                                      .uses_target = false,
                                      .input_min = kDfBlock,
                                      .input_max = kDfBlock,
                                      .answer = 32U};
/// DFAuthenticateNonFirstPart2 (Table 286): E(Kx, RndA'); no answer data.
inline constexpr DfShape kDfNonFirst2{.p2 = kP2AuthNonFirstPart2,
                                      .uses_key = false,
                                      .uses_target = false,
                                      .input_min = kDfBlock,
                                      .input_max = kDfBlock,
                                      .answer = 0U};
/// DFDumpSessionKeys (Table 289): no input; answer 38 bytes.
inline constexpr DfShape kDfDump{.p2 = kP2DumpKey,
                                 .uses_key = false,
                                 .uses_target = false,
                                 .input_min = 0U,
                                 .input_max = 0U,
                                 .answer = 38U};
/// DFKillAuthentication (Table 298): nothing.
inline constexpr DfShape kDfKill{.p2 = kP2KillAuth,
                                 .uses_key = false,
                                 .uses_target = false,
                                 .input_min = 0U,
                                 .input_max = 0U,
                                 .answer = 0U};

} // namespace apdu::detail

namespace codecs {

/// `DfDiversifyKey`: `80 03 00 10` TLV[TAG_1] master key TLV[TAG_2] target AES key TLV[TAG_3]
/// divInput (AN12543 4.16.1).
struct DfDiversifyKeyCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const DfArgs& args, MutableByteSpan out) noexcept {
    return apdu::detail::EncodeDf(out, args, apdu::detail::kDfDiversify);
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, const Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const DfArgs& args, ByteSpan data,
                                       const Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::DfDiversifyKey` (selects it for
 * `Codec<Command::DfDiversifyKey>`). */
constexpr DfDiversifyKeyCodec CodecFor(CommandTag<Command::DfDiversifyKey> /*tag*/) noexcept {
  return {};
}

/// `DfAuthenticateFirstPart1`: `80 03 00 53` TLV[TAG_1] key TLV[TAG_2] 16 bytes, Le; answer
/// TLV[TAG_1] 32 bytes (AN12543 4.16.2.1).
struct DfAuthenticateFirstPart1Codec {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const DfArgs& args, MutableByteSpan out) noexcept {
    return apdu::detail::EncodeDf(out, args, apdu::detail::kDfFirst1);
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
  static constexpr Result<void> Decode(const DfArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    return apdu::detail::DecodeDf(args, data, apdu::detail::kDfFirst1, reply.length);
  }
};
/** @return The codec of `Command::DfAuthenticateFirstPart1` (selects it for
 * `Codec<Command::DfAuthenticateFirstPart1>`). */
constexpr DfAuthenticateFirstPart1Codec CodecFor(
    CommandTag<Command::DfAuthenticateFirstPart1> /*tag*/) noexcept {
  return {};
}

/// `DfAuthenticateFirstPart2`: `80 03 00 12` TLV[TAG_1] 32 bytes, Le; answer TLV[TAG_1] 12 bytes
/// (AN12543 4.16.2.2).
struct DfAuthenticateFirstPart2Codec {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const DfArgs& args, MutableByteSpan out) noexcept {
    return apdu::detail::EncodeDf(out, args, apdu::detail::kDfFirst2);
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
  static constexpr Result<void> Decode(const DfArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    return apdu::detail::DecodeDf(args, data, apdu::detail::kDfFirst2, reply.length);
  }
};
/** @return The codec of `Command::DfAuthenticateFirstPart2` (selects it for
 * `Codec<Command::DfAuthenticateFirstPart2>`). */
constexpr DfAuthenticateFirstPart2Codec CodecFor(
    CommandTag<Command::DfAuthenticateFirstPart2> /*tag*/) noexcept {
  return {};
}

/// `DfAuthenticateNonFirstPart1`: `80 03 00 54` TLV[TAG_1] key TLV[TAG_2] 16 bytes, Le; answer
/// TLV[TAG_1] 32 bytes (AN12543 4.16.3.1).
struct DfAuthenticateNonFirstPart1Codec {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const DfArgs& args, MutableByteSpan out) noexcept {
    return apdu::detail::EncodeDf(out, args, apdu::detail::kDfNonFirst1);
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
  static constexpr Result<void> Decode(const DfArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    return apdu::detail::DecodeDf(args, data, apdu::detail::kDfNonFirst1, reply.length);
  }
};
/** @return The codec of `Command::DfAuthenticateNonFirstPart1` (selects it for
 * `Codec<Command::DfAuthenticateNonFirstPart1>`). */
constexpr DfAuthenticateNonFirstPart1Codec CodecFor(
    CommandTag<Command::DfAuthenticateNonFirstPart1> /*tag*/) noexcept {
  return {};
}

/// `DfAuthenticateNonFirstPart2`: `80 03 00 13` TLV[TAG_1] 16 bytes; no answer data (AN12543
/// 4.16.3.2; SW 0x6A80 when the authentication fails, mapped to `AuthFailed`).
struct DfAuthenticateNonFirstPart2Codec {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Shares the DESFire reply shape.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const DfArgs& args, MutableByteSpan out) noexcept {
    return apdu::detail::EncodeDf(out, args, apdu::detail::kDfNonFirst2);
  }
  /** @brief Refused, as for the other DESFire commands. @param data The body. @param reply The
   * reply. @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, const LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply
   * (length 0). @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(const DfArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    return apdu::detail::DecodeDf(args, data, apdu::detail::kDfNonFirst2, reply.length);
  }
};
/** @return The codec of `Command::DfAuthenticateNonFirstPart2` (selects it for
 * `Codec<Command::DfAuthenticateNonFirstPart2>`). */
constexpr DfAuthenticateNonFirstPart2Codec CodecFor(
    CommandTag<Command::DfAuthenticateNonFirstPart2> /*tag*/) noexcept {
  return {};
}

/// `DfDumpSessionKeys`: `80 03 00 14`, Le; answer TLV[TAG_1] 38 bytes: SesAuthENCKey,
/// SesAuthMACKey, TI, Cmd-Ctr (AN12543 4.16.4; secret-bearing, S-02).
struct DfDumpSessionKeysCodec {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const DfArgs& args, MutableByteSpan out) noexcept {
    return apdu::detail::EncodeDf(out, args, apdu::detail::kDfDump);
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
  static constexpr Result<void> Decode(const DfArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    return apdu::detail::DecodeDf(args, data, apdu::detail::kDfDump, reply.length);
  }
};
/** @return The codec of `Command::DfDumpSessionKeys` (selects it for
 * `Codec<Command::DfDumpSessionKeys>`). */
constexpr DfDumpSessionKeysCodec CodecFor(CommandTag<Command::DfDumpSessionKeys> /*tag*/) noexcept {
  return {};
}

/// `DfChangeKeyPart1`: `80 03 00 15` [TLV[TAG_1] old key, `key`; absent when 0] TLV[TAG_2] new
/// key, `target` [TLV[TAG_3] key set number] TLV[TAG_4] DESFire key number TLV[TAG_5] key version,
/// Le; answer TLV[TAG_1] the cryptogram (AN12543 4.16.5.1). `input` is `[key set] key number key
/// version`, 2 or 3 bytes.
struct DfChangeKeyPart1Codec {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const DfArgs& args, MutableByteSpan out) noexcept {
    const bool key_set = (args.input.size() == 3U);
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Default,
                                  apdu::kP2ChangeKeyPart1);
    if ((args.target.value == 0U) || ((args.input.size() != 2U) && !key_set) || args.out.empty()) {
      w.Refuse(Error::InvalidArgument);
      return w.Finish();
    }
    if (args.key.value != 0U) {
      w.TlvU32(apdu::kTag1, args.key.value);
    }
    w.TlvU32(apdu::kTag2, args.target.value);
    const std::size_t first = key_set ? 1U : 0U;
    if (key_set) {
      w.TlvU8(apdu::kTag3, args.input[0]);
    }
    w.TlvU8(apdu::kTag4, args.input[first]);
    w.TlvU8(apdu::kTag5, args.input[first + 1U]);
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
  static constexpr Result<void> Decode(const DfArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    return apdu::detail::DecodeTag1Into(data, args.out, reply.length);
  }
};
/** @return The codec of `Command::DfChangeKeyPart1` (selects it for
 * `Codec<Command::DfChangeKeyPart1>`). */
constexpr DfChangeKeyPart1Codec CodecFor(CommandTag<Command::DfChangeKeyPart1> /*tag*/) noexcept {
  return {};
}

/// `DfChangeKeyPart2`: `80 03 00 16` TLV[TAG_1] the card's MAC, Le; answer TLV[TAG_1] Result
/// (AN12543 4.16.5.2). Result 02 is `AuthFailed`.
struct DfChangeKeyPart2Codec {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Shares the DESFire reply shape.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const DfArgs& args, MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Default,
                                  apdu::kP2ChangeKeyPart2);
    if ((args.key.value != 0U) || (args.target.value != 0U) || args.input.empty() ||
        (args.input.size() > apdu::detail::kDfBlock) || !args.out.empty()) {
      w.Refuse(Error::InvalidArgument);
    }
    w.Tlv(apdu::kTag1, args.input);
    w.ExpectResponse(apdu::detail::TlvBudget(1U));
    return w.Finish();
  }
  /** @brief Refused, as for the other DESFire commands. @param data The body. @param reply The
   * reply. @return `InvalidArgument`. */
  static constexpr Result<void> Decode(ByteSpan data, const LengthReply& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return apdu::detail::NeedsArgs();
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply
   * (length 0). @return `Ok`, `AuthFailed` or `FrameError`. */
  static constexpr Result<void> Decode(const DfArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    static_cast<void>(args);
    reply.length = 0U;
    bool success = false;
    const Result<void> r = apdu::detail::DecodeResult(data, success);
    if (!r.ok()) {
      return r;
    }
    return success ? Result<void>::Success() : apdu::detail::Fail<void>(Error::AuthFailed);
  }
};
/** @return The codec of `Command::DfChangeKeyPart2` (selects it for
 * `Codec<Command::DfChangeKeyPart2>`). */
constexpr DfChangeKeyPart2Codec CodecFor(CommandTag<Command::DfChangeKeyPart2> /*tag*/) noexcept {
  return {};
}

/// `DfKillAuthentication`: `80 03 00 17` (AN12543 4.16.6).
struct DfKillAuthenticationCodec {
  static constexpr bool kImplemented = true;          ///< Implemented.
  static constexpr bool kWritesCallerBuffers = false; ///< No caller buffer.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const DfArgs& args, MutableByteSpan out) noexcept {
    return apdu::detail::EncodeDf(out, args, apdu::detail::kDfKill);
  }
  /** @brief Decode. @param data The body. @param reply The reply. @return `Ok` or `FrameError`. */
  static constexpr Result<void> Decode(ByteSpan data, const Empty& reply) noexcept {
    static_cast<void>(reply);
    return apdu::detail::ExpectEmpty(data);
  }
  /** @brief Decode. @param args The arguments. @param data The body. @param reply The reply.
   * @return As the two-argument form. */
  static constexpr Result<void> Decode(const DfArgs& args, ByteSpan data,
                                       const Empty& reply) noexcept {
    static_cast<void>(args);
    return Decode(data, reply);
  }
};
/** @return The codec of `Command::DfKillAuthentication` (selects it for
 * `Codec<Command::DfKillAuthentication>`). */
constexpr DfKillAuthenticationCodec CodecFor(
    CommandTag<Command::DfKillAuthentication> /*tag*/) noexcept {
  return {};
}

/// `I2cmExecuteCommandSet`: `80 03 00 30` TLV[TAG_1] command set (at most 255 bytes, checked
/// against Table 311), Le; answer TLV[TAG_1] the result sequence (AN12543 4.18.1).
struct I2cmExecuteCommandSetCodec {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `args.out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const I2cmArgs& args, MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain, apdu::kInsCrypto, apdu::kP1Default,
                                  apdu::kP2I2cm);
    if (!apdu::detail::ValidI2cmCommands(args.commands) || args.out.empty()) {
      w.Refuse(Error::InvalidArgument);
    }
    w.Tlv(apdu::kTag1, args.commands);
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
  static constexpr Result<void> Decode(const I2cmArgs& args, ByteSpan data,
                                       LengthReply& reply) noexcept {
    return apdu::detail::DecodeTag1Into(data, args.out, reply.length);
  }
};
/** @return The codec of `Command::I2cmExecuteCommandSet` (selects it for
 * `Codec<Command::I2cmExecuteCommandSet>`). */
constexpr I2cmExecuteCommandSetCodec CodecFor(
    CommandTag<Command::I2cmExecuteCommandSet> /*tag*/) noexcept {
  return {};
}

/// `I2cmExecuteCommandSetAttested`: `80 23 00 30` TLV[TAG_1] command set TLV[TAG_2] attestation
/// key TLV[TAG_3] algorithm TLV[TAG_7] freshness, extended Le (AN12543 Table 312: the attestation
/// tags are TAG_2 and TAG_3 here; the INS flag is used, not P2_I2CM_ATTESTED, as the middleware
/// does). The answer format is told by its tags.
struct I2cmExecuteCommandSetAttestedCodec {
  static constexpr bool kImplemented = true;         ///< Implemented.
  static constexpr bool kWritesCallerBuffers = true; ///< Writes `data_out` and `signature_out`.
  /** @brief Encode. @param args The arguments. @param out The buffer. @return The length or an
   * error. */
  static constexpr Result<std::size_t> Encode(const I2cmAttestedArgs& args,
                                              MutableByteSpan out) noexcept {
    apdu::detail::CommandWriter w(out, apdu::kClaPlain,
                                  static_cast<uint8_t>(apdu::kInsCrypto | apdu::kInsAttest),
                                  apdu::kP1Default, apdu::kP2I2cm);
    if (!apdu::detail::ValidI2cmCommands(args.commands) || args.data_out.empty() ||
        args.signature_out.empty()) {
      w.Refuse(Error::InvalidArgument);
    }
    w.Tlv(apdu::kTag1, args.commands);
    apdu::detail::PutAttestation(w, apdu::kTag2, apdu::kTag3, args.attestation_key, args.algo,
                                 args.freshness);
    w.ExpectResponse(apdu::detail::TlvBudget(args.data_out.size()) +
                     apdu::detail::kAttestedOverhead);
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
  static constexpr Result<void> Decode(const I2cmAttestedArgs& args, ByteSpan data,
                                       AttestedRead& reply) noexcept {
    return apdu::detail::DecodeAttested(
        data, {.data = args.data_out, .signature = args.signature_out}, reply);
  }
};
/** @return The codec of `Command::I2cmExecuteCommandSetAttested` (selects it for
 * `Codec<Command::I2cmExecuteCommandSetAttested>`). */
constexpr I2cmExecuteCommandSetAttestedCodec CodecFor(
    CommandTag<Command::I2cmExecuteCommandSetAttested> /*tag*/) noexcept {
  return {};
}

} // namespace codecs

} // namespace se05x

#endif // SE05X_APDU_MISC_HPP
