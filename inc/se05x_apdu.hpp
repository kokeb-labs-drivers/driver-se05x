/**
 * @file se05x_apdu.hpp
 * @brief The APDU layer core: TLV writer and reader, response splitting and status word mapping.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * The public surface below is frozen; the helpers in `se05x::apdu::detail`, which the codecs use,
 * are not part of the contract. The per-command codecs (`Codec<C>`) are in the group headers
 * `se05x_apdu_*.hpp`, included by `se05x_apdu_codec.hpp`.
 *
 * Wire facts (AN12543 section 4.1, AN12413 section 4.1): CLA 0x80 (0x84 with secure messaging),
 * INS = group code or'ed with the characteristics 0x80 (transient), 0x40 (auth object), 0x20
 * (attest); a body of TLVs with one-byte tags and ISO 7816-4 BER lengths (one byte below 0x80,
 * `81 xx`, or `82 xx xx`; a response may use the three-byte form even for short values); a
 * response of TLVs and a two-byte status word. The framing of a command (ISO 7816-4 cases 1 to 4,
 * short or extended) is decided once in `detail::CommandWriter::Finish()`.
 */
#ifndef SE05X_APDU_HPP
#define SE05X_APDU_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "se05x_commands.hpp"
#include "se05x_status.hpp"
#include "se05x_types.hpp"

namespace se05x::apdu {

/**
 * @defgroup se05x_apdu APDU layer
 * @brief TLV, response parsing and status words.
 * @{
 */

/// The status word of success.
inline constexpr uint16_t kSwOk = 0x9000U;

/** @brief One TLV element: a tag and a view of its value. */
struct Tlv {
  uint8_t tag{0}; ///< The one-byte tag.
  ByteSpan value; ///< The value, a view into the parsed buffer.
};

/** @brief A response split into its body and status word. */
struct ResponseView {
  ByteSpan body;  ///< The bytes before the status word.
  uint16_t sw{0}; ///< The status word.
};

namespace detail {

/// The detail of every error of this layer.
inline constexpr Detail kApduDetail{
    .sw = 0U, .command = 0xFFU, .layer = Layer::Apdu, .step = 0U, .attempts_left = 0xFFU};

/**
 * @brief A failure of the APDU layer.
 * @tparam T The value type.
 * @param error The error.
 * @return The failed result, with `Layer::Apdu` in the detail.
 */
template <typename T>
constexpr Result<T> Fail(Error error) noexcept {
  return Result<T>::Failure(error, kApduDetail);
}

/// Largest TLV value the BER length forms of the applet carry (`82 xx xx`).
inline constexpr std::size_t kMaxTlvValue = 0xFFFFU;

/**
 * @brief The number of bytes of the BER length of a value.
 * @param length The value length, at most `kMaxTlvValue`.
 * @return 1, 2 or 3.
 */
constexpr std::size_t LengthBytes(std::size_t length) noexcept {
  if (length < 0x80U) {
    return 1U;
  }
  return (length <= 0xFFU) ? 2U : 3U;
}

/**
 * @brief Write a BER length at `out[pos]`; the caller has checked the room.
 * @param out The buffer.
 * @param pos Where the length starts.
 * @param length The value length, at most `kMaxTlvValue`.
 * @return The number of bytes written.
 */
constexpr std::size_t PutLength(MutableByteSpan out, std::size_t pos, std::size_t length) noexcept {
  const std::size_t n = LengthBytes(length);
  if (n == 1U) {
    out[pos] = static_cast<uint8_t>(length);
  } else if (n == 2U) {
    out[pos] = 0x81U;
    out[pos + 1U] = static_cast<uint8_t>(length);
  } else {
    out[pos] = 0x82U;
    out[pos + 1U] = static_cast<uint8_t>((length >> 8U) & 0xFFU);
    out[pos + 2U] = static_cast<uint8_t>(length & 0xFFU);
  }
  return n;
}

/**
 * @brief An unsigned big-endian number of 1 to 4 bytes.
 * @param bytes The bytes.
 * @return The number; 0 for an empty span.
 */
constexpr uint32_t BigEndian(ByteSpan bytes) noexcept {
  uint32_t value = 0U;
  for (std::size_t i = 0U; (i < bytes.size()) && (i < 4U); ++i) {
    value = (value << 8U) | static_cast<uint32_t>(bytes[i]);
  }
  return value;
}

/**
 * @brief Zero `out[0, n)`, bounded by the buffer (S-01: a failed encode leaves no secret behind).
 * @param out The buffer.
 * @param n The number of bytes.
 */
constexpr void Wipe(MutableByteSpan out, std::size_t n) noexcept {
  for (std::size_t i = 0U; (i < n) && (i < out.size()); ++i) {
    out[i] = 0U;
  }
}

} // namespace detail

/**
 * @brief Appends TLV elements to a caller buffer; never writes past it (S-04).
 *
 * Once an element does not fit, every later call fails with `BufferTooSmall` and `Size()` stays at
 * the last complete element.
 */
class TlvWriter {
public:
  /**
   * @brief Write into `out`.
   * @param out The destination buffer.
   */
  explicit constexpr TlvWriter(MutableByteSpan out) noexcept : out_(out) {}

  /**
   * @brief Append an element with a byte value.
   * @param tag The tag.
   * @param value The value, at most 65535 bytes (the `82 xx xx` length form).
   * @return `Ok` or `BufferTooSmall`.
   */
  constexpr Result<void> Put(uint8_t tag, ByteSpan value) noexcept {
    if (failed_ || (value.size() > detail::kMaxTlvValue)) {
      failed_ = true;
      return detail::Fail<void>(Error::BufferTooSmall);
    }
    const std::size_t need = 1U + detail::LengthBytes(value.size()) + value.size();
    if (need > (out_.size() - size_)) {
      failed_ = true;
      return detail::Fail<void>(Error::BufferTooSmall);
    }
    out_[size_] = tag;
    std::size_t pos = size_ + 1U;
    pos += detail::PutLength(out_, pos, value.size());
    for (std::size_t i = 0U; i < value.size(); ++i) {
      out_[pos + i] = value[i];
    }
    size_ += need;
    return Result<void>::Success();
  }
  /**
   * @brief Append an element with a one-byte value.
   * @param tag The tag.
   * @param value The value.
   * @return `Ok` or `BufferTooSmall`.
   */
  constexpr Result<void> PutU8(uint8_t tag, uint8_t value) noexcept {
    const std::array<uint8_t, 1> bytes{value};
    return Put(tag, ByteSpan{bytes});
  }
  /**
   * @brief Append an element with a two-byte big-endian value.
   * @param tag The tag.
   * @param value The value.
   * @return `Ok` or `BufferTooSmall`.
   */
  constexpr Result<void> PutU16(uint8_t tag, uint16_t value) noexcept {
    const std::array<uint8_t, 2> bytes{static_cast<uint8_t>((static_cast<uint32_t>(value) >> 8U)),
                                       static_cast<uint8_t>(static_cast<uint32_t>(value) & 0xFFU)};
    return Put(tag, ByteSpan{bytes});
  }
  /**
   * @brief Append an element with a four-byte big-endian value.
   * @param tag The tag.
   * @param value The value.
   * @return `Ok` or `BufferTooSmall`.
   */
  constexpr Result<void> PutU32(uint8_t tag, uint32_t value) noexcept {
    const std::array<uint8_t, 4> bytes{
        static_cast<uint8_t>((value >> 24U) & 0xFFU), static_cast<uint8_t>((value >> 16U) & 0xFFU),
        static_cast<uint8_t>((value >> 8U) & 0xFFU), static_cast<uint8_t>(value & 0xFFU)};
    return Put(tag, ByteSpan{bytes});
  }

  /** @return The number of bytes written so far. */
  [[nodiscard]] constexpr std::size_t Size() const noexcept {
    return size_;
  }

private:
  MutableByteSpan out_;
  std::size_t size_{0};
  bool failed_{false};
};

/** @brief Reads TLV elements from a buffer; every length is checked against the buffer (S-04). */
class TlvReader {
public:
  /**
   * @brief Read from `data`.
   * @param data The bytes to parse.
   */
  explicit constexpr TlvReader(ByteSpan data) noexcept : data_(data) {}

  /**
   * @brief The next element. A malformed element is not consumed.
   * @return The element, or `FrameError` for a missing length, a length form other than one byte,
   * `81 xx` or `82 xx xx`, or a value that runs past the buffer.
   */
  constexpr Result<Tlv> Next() noexcept {
    const std::size_t left = data_.size() - pos_;
    if (left < 2U) {
      return detail::Fail<Tlv>(Error::FrameError);
    }
    const uint8_t tag = data_[pos_];
    const uint8_t first = data_[pos_ + 1U];
    std::size_t header = 2U;
    std::size_t length = first;
    if (first == 0x81U) {
      header = 3U;
    } else if (first == 0x82U) {
      header = 4U;
    } else if (first >= 0x80U) {
      return detail::Fail<Tlv>(Error::FrameError);
    } else {
      header = 2U;
    }
    if (left < header) {
      return detail::Fail<Tlv>(Error::FrameError);
    }
    if (header > 2U) {
      length = detail::BigEndian(data_.subspan(pos_ + 2U, header - 2U));
    }
    if (length > (left - header)) {
      return detail::Fail<Tlv>(Error::FrameError);
    }
    const Tlv tlv{.tag = tag, .value = data_.subspan(pos_ + header, length)};
    pos_ += header + length;
    return Result<Tlv>::Success(tlv);
  }
  /**
   * @brief The next element, which must have `tag`; a wrong tag is not consumed.
   * @param tag The expected tag.
   * @return The element, or `FrameError` (wrong tag or malformed).
   */
  constexpr Result<Tlv> Expect(uint8_t tag) noexcept {
    const std::size_t before = pos_;
    const Result<Tlv> next = Next();
    if (!next.ok()) {
      return next;
    }
    if (next.value.tag != tag) {
      pos_ = before;
      return detail::Fail<Tlv>(Error::FrameError);
    }
    return next;
  }
  /** @return true when every byte has been read. */
  [[nodiscard]] constexpr bool AtEnd() const noexcept {
    return pos_ >= data_.size();
  }

private:
  ByteSpan data_;
  std::size_t pos_{0};
};

/**
 * @brief Split a response APDU into body and status word.
 * @param response The response bytes, at least two.
 * @return The view, or `FrameError` when shorter than two bytes.
 */
constexpr Result<ResponseView> SplitResponse(ByteSpan response) noexcept {
  if (response.size() < 2U) {
    return detail::Fail<ResponseView>(Error::FrameError);
  }
  const std::size_t n = response.size() - 2U;
  const auto sw = static_cast<uint16_t>((static_cast<uint32_t>(response[n]) << 8U) |
                                        static_cast<uint32_t>(response[n + 1U]));
  return Result<ResponseView>::Success(ResponseView{.body = response.first(n), .sw = sw});
}

namespace detail {

/** @brief One row of the generic status word table. */
struct SwRow {
  uint16_t sw; ///< The status word.
  Error error; ///< Its error when the command gives no better name.
};

/// The generic map: AN12543 Table 21 and the ISO 7816-4 words the applet is known to return
/// (0x66A6: AN14028 2.3.1, AN13030 p. 217; 0x6D00: AN13030 p. 10; 0x6A82, 0x6A89, 0x6983, 0x6987,
/// 0x6988, 0x6A81, 0x6A86, 0x6B00, 0x6E00, 0x6F00: ISO 7816-4 meanings).
inline constexpr std::array<SwRow, 19> kSwTable{{
    {.sw = 0x66A6U, .error = Error::ThroughputLimited},
    {.sw = 0x6700U, .error = Error::BufferTooSmall},
    {.sw = 0x6982U, .error = Error::PolicyDenied},
    {.sw = 0x6983U, .error = Error::AuthLocked},
    {.sw = 0x6984U, .error = Error::PolicyInvalid},
    {.sw = 0x6985U, .error = Error::ConditionsNotSatisfied},
    {.sw = 0x6986U, .error = Error::PolicyDenied},
    {.sw = 0x6987U, .error = Error::SecureChannelError},
    {.sw = 0x6988U, .error = Error::SecureChannelError},
    {.sw = 0x6A80U, .error = Error::ConditionsNotSatisfied},
    {.sw = 0x6A81U, .error = Error::Unsupported},
    {.sw = 0x6A82U, .error = Error::ObjectNotFound},
    {.sw = 0x6A84U, .error = Error::MemoryFull},
    {.sw = 0x6A86U, .error = Error::Unsupported},
    {.sw = 0x6A89U, .error = Error::ObjectExists},
    {.sw = 0x6B00U, .error = Error::Unsupported},
    {.sw = 0x6D00U, .error = Error::NeedsReselect},
    {.sw = 0x6E00U, .error = Error::NeedsReselect},
    {.sw = 0x6F00U, .error = Error::DeviceFault},
}};

/**
 * @brief Whether a command is an authentication step: a refusal of it is a failed authentication.
 * @param command The command.
 * @return true for the session authentication and DESFire authentication commands.
 */
constexpr bool IsAuthStep(Command command) noexcept {
  return (command == Command::ScpExternalAuthenticate) ||
         (command == Command::EcKeySessionInternalAuthenticate) ||
         (command == Command::VerifySessionUserId) ||
         (command == Command::DfAuthenticateFirstPart2) ||
         (command == Command::DfAuthenticateNonFirstPart2);
}

/**
 * @brief Whether a command creates or writes an object: SW 0x6A80 on it is a refused policy
 * (AN12543 3.7.1.4: "if the policy validation fails, the error code 0x6A80 is returned").
 * @param command The command.
 * @return true for the object write group.
 */
constexpr bool IsObjectWrite(Command command) noexcept {
  return GroupOf(command) == Group::ObjectWrite;
}

/**
 * @brief SW 0x6985 in the context of a command.
 * @param command The command.
 * @return The error.
 */
constexpr Error Map6985(Command command) noexcept {
  if (command == Command::VerifySessionUserId) {
    return Error::AuthFailed; // AN12543 Table 84: wrong UserID value.
  }
  if ((command == Command::ExchangeSessionData) || (command == Command::RefreshSession)) {
    return Error::PolicyInvalid; // AN12543 Table 72: invalid policies.
  }
  return Error::ConditionsNotSatisfied;
}

/**
 * @brief SW 0x6A80 in the context of a command.
 * @param command The command.
 * @return The error.
 */
constexpr Error Map6A80(Command command) noexcept {
  if (IsObjectWrite(command)) {
    return Error::PolicyInvalid;
  }
  if (command == Command::DfAuthenticateNonFirstPart2) {
    return Error::AuthFailed; // AN12543 4.15.5: 6A80 if the authentication fails.
  }
  return Error::ConditionsNotSatisfied;
}

} // namespace detail

/**
 * @brief Map a status word to an `Error` in the context of a command.
 *
 * The same word maps differently by command: any word but 0x9000 after `CloseSession` is
 * `NeedsReselect` (AN12543 4.5.1.5: the applet must be selected again; errata APP.2); 0x6985 is
 * `AuthFailed` after `VerifySessionUserId` and `PolicyInvalid` after a session policy; 0x6A80 is
 * `PolicyInvalid` on an object write; 0x6982 and 0x63Cx are `AuthFailed` on an authentication
 * step. An unknown word is `ChipSwUnknown`. Applet 3.x may answer 0x6985 where 7.x answers 0x6A84
 * on a full memory; the map has no generation, so that case stays `ConditionsNotSatisfied`.
 *
 * @param command The command that was sent.
 * @param sw The status word.
 * @return `Error::Ok` for 0x9000, else the mapped error.
 */
constexpr Error StatusToError(Command command, uint16_t sw) noexcept {
  if (sw == kSwOk) {
    return Error::Ok;
  }
  if (command == Command::CloseSession) {
    return Error::NeedsReselect;
  }
  if ((static_cast<uint32_t>(sw) & 0xFFF0U) == 0x63C0U) {
    return Error::AuthFailed;
  }
  if (sw == 0x6985U) {
    return detail::Map6985(command);
  }
  if (sw == 0x6A80U) {
    return detail::Map6A80(command);
  }
  if ((sw == 0x6982U) && detail::IsAuthStep(command)) {
    return Error::AuthFailed;
  }
  for (const detail::SwRow& row : detail::kSwTable) {
    if (row.sw == sw) {
      return row.error;
    }
  }
  return Error::ChipSwUnknown;
}

/** @} */

namespace detail {

/// Where the body of a command starts in the caller's buffer while it is written: header (4) plus
/// the longest Lc (3). `CommandWriter::Finish()` moves it down for a short Lc.
inline constexpr std::size_t kBodyOffset = 7U;
/// Longest body a short Lc carries (ISO 7816-4).
inline constexpr std::size_t kShortLcMax = 255U;
/// Longest response a short Le asks for (ISO 7816-4: `00` means 256).
inline constexpr std::size_t kShortLeMax = 256U;

/**
 * @brief Writes one command APDU: header, TLV body, Lc and Le, short or extended.
 *
 * The body is written at `kBodyOffset`; `Finish()` decides the case: extended when the body is
 * longer than 255 bytes or the response may be longer than 256 bytes (AN12543 4.1: otherwise the
 * applet answers 0x6985), short otherwise. A short Le is `00`; an extended Le is `00 00`, as the
 * middleware sends it (AN12543 4.1.2: the applet does not check Le). The first error latches;
 * `Finish()` then zeroes every byte written (S-01) and returns it.
 */
class CommandWriter {
public:
  /**
   * @brief Start a command.
   * @param out The caller's buffer.
   * @param cla CLA.
   * @param ins INS.
   * @param p1 P1.
   * @param p2 P2.
   */
  constexpr CommandWriter(MutableByteSpan out, uint8_t cla, uint8_t ins, uint8_t p1,
                          uint8_t p2) noexcept
      : out_(out) {
    if (out_.size() < 4U) {
      error_ = Error::BufferTooSmall;
      return;
    }
    out_[0] = cla;
    out_[1] = ins;
    out_[2] = p1;
    out_[3] = p2;
  }

  /**
   * @brief The command has a response body of at most `max_body` bytes: send an Le.
   * @param max_body The longest response body the caller can take.
   */
  constexpr void ExpectResponse(std::size_t max_body) noexcept {
    has_le_ = true;
    max_response_ = max_body;
  }

  /**
   * @brief Record an argument error; nothing is sent.
   * @param error The error.
   */
  constexpr void Refuse(Error error) noexcept {
    if (error_ == Error::Ok) {
      error_ = error;
    }
  }

  /**
   * @brief Append raw bytes to the body.
   * @param bytes The bytes.
   */
  constexpr void Raw(ByteSpan bytes) noexcept {
    if (!reserve(bytes.size())) {
      return;
    }
    for (std::size_t i = 0U; i < bytes.size(); ++i) {
      out_[pos_ + i] = bytes[i];
    }
    pos_ += bytes.size();
  }

  /**
   * @brief Append a TLV.
   * @param tag The tag.
   * @param value The value.
   */
  constexpr void Tlv(uint8_t tag, ByteSpan value) noexcept {
    tlvHeader(tag, value.size());
    Raw(value);
  }

  /**
   * @brief Append a TLV whose value is `value` byte-reversed (the wire form of an Edwards or
   * Montgomery value, AN12543 section 7).
   * @param tag The tag.
   * @param value The value in RFC 8032 or RFC 7748 order.
   */
  constexpr void TlvReversed(uint8_t tag, ByteSpan value) noexcept {
    tlvHeader(tag, value.size());
    if (!reserve(value.size())) {
      return;
    }
    for (std::size_t i = 0U; i < value.size(); ++i) {
      out_[pos_ + i] = value[value.size() - 1U - i];
    }
    pos_ += value.size();
  }

  /**
   * @brief Append a TLV with an unsigned big-endian value of `width` bytes.
   * @param tag The tag.
   * @param value The value; it must fit in `width` bytes.
   * @param width 1 to 8.
   */
  constexpr void TlvUint(uint8_t tag, uint64_t value, std::size_t width) noexcept {
    std::array<uint8_t, 8> bytes{};
    if ((width == 0U) || (width > bytes.size())) {
      Refuse(Error::InvalidArgument);
      return;
    }
    uint64_t v = value;
    for (std::size_t i = 0U; i < width; ++i) {
      bytes[width - 1U - i] = static_cast<uint8_t>(v & 0xFFU);
      v >>= 8U;
    }
    if (v != 0U) {
      Refuse(Error::InvalidArgument);
      return;
    }
    Tlv(tag, ByteSpan{bytes.data(), width});
  }

  /** @brief A one-byte TLV. @param tag The tag. @param value The value. */
  constexpr void TlvU8(uint8_t tag, uint8_t value) noexcept {
    TlvUint(tag, value, 1U);
  }
  /** @brief A two-byte TLV. @param tag The tag. @param value The value. */
  constexpr void TlvU16(uint8_t tag, uint16_t value) noexcept {
    TlvUint(tag, value, 2U);
  }
  /** @brief A four-byte TLV. @param tag The tag. @param value The value. */
  constexpr void TlvU32(uint8_t tag, uint32_t value) noexcept {
    TlvUint(tag, value, 4U);
  }

  /**
   * @brief Close the command: Lc, Le, the move of a short body.
   * @return The APDU length, or the first error (`InvalidArgument` when the data field would exceed
   * `kMaxApduPayload`, `BufferTooSmall` when the caller's buffer is short); on an error every byte
   * written is zero.
   */
  [[nodiscard]] constexpr Result<std::size_t> Finish() noexcept {
    const std::size_t body = (pos_ > kBodyOffset) ? (pos_ - kBodyOffset) : 0U;
    const bool extended = (body > kShortLcMax) || (has_le_ && (max_response_ > kShortLeMax));
    std::size_t lc_bytes = 0U;
    if (body != 0U) {
      lc_bytes = extended ? 3U : 1U;
    }
    const std::size_t le_bytes = leBytes(body, extended);
    const std::size_t total = 4U + lc_bytes + body + le_bytes;
    // The data field must fit the applet's internal buffer (AN12543 2.2 p. 3); with it the APDU is
    // at most `kMaxPlainCommandApdu` (header, extended Lc and Le).
    static_assert((4U + 3U + kMaxApduPayload + 2U) <= kMaxPlainCommandApdu);
    if ((error_ == Error::Ok) && (body > kMaxApduPayload)) {
      error_ = Error::InvalidArgument;
    }
    if ((error_ == Error::Ok) && (total > out_.size())) {
      error_ = Error::BufferTooSmall;
    }
    if (error_ != Error::Ok) {
      Wipe(out_, (pos_ > kBodyOffset) ? pos_ : 4U);
      return Fail<std::size_t>(error_);
    }
    place(body, lc_bytes, le_bytes);
    return Result<std::size_t>::Success(total);
  }

private:
  /// Length of the Le field: none, one byte (short), `00 xx xx` alone or `xx xx` after an Lc.
  [[nodiscard]] constexpr std::size_t leBytes(std::size_t body, bool extended) const noexcept {
    if (!has_le_) {
      return 0U;
    }
    if (!extended) {
      return 1U;
    }
    return (body == 0U) ? 3U : 2U;
  }

  constexpr bool reserve(std::size_t n) noexcept {
    if (error_ != Error::Ok) {
      return false;
    }
    if ((pos_ > out_.size()) || (n > (out_.size() - pos_)) || (n > kMaxPlainCommandApdu)) {
      error_ = Error::BufferTooSmall;
      return false;
    }
    return true;
  }

  constexpr void tlvHeader(uint8_t tag, std::size_t length) noexcept {
    if (length > kMaxTlvValue) {
      Refuse(Error::InvalidArgument);
      return;
    }
    if (!reserve(1U + LengthBytes(length))) {
      return;
    }
    out_[pos_] = tag;
    pos_ += 1U + PutLength(out_, pos_ + 1U, length);
  }

  constexpr void place(std::size_t body, std::size_t lc_bytes, std::size_t le_bytes) noexcept {
    const std::size_t start = 4U + lc_bytes;
    if (body != 0U) {
      for (std::size_t i = 0U; i < body; ++i) {
        out_[start + i] = out_[kBodyOffset + i]; // start <= kBodyOffset: a forward copy is safe
      }
      if (lc_bytes == 1U) {
        out_[4] = static_cast<uint8_t>(body);
      } else {
        out_[4] = 0U;
        out_[5] = static_cast<uint8_t>((body >> 8U) & 0xFFU);
        out_[6] = static_cast<uint8_t>(body & 0xFFU);
      }
    }
    const std::size_t le_at = start + body;
    for (std::size_t i = 0U; i < le_bytes; ++i) {
      out_[le_at + i] = 0U;
    }
  }

  MutableByteSpan out_;
  std::size_t pos_{kBodyOffset};
  std::size_t max_response_{0};
  bool has_le_{false};
  Error error_{Error::Ok};
};

/** @brief An optional TLV of a response: whether it was there and its value. */
struct OptionalTlv {
  bool present{false}; ///< The element was present.
  ByteSpan value;      ///< Its value.
};

/**
 * @brief Reads the TLVs of one response body in the order the specification gives them.
 */
class ReplyParser {
public:
  /**
   * @brief Parse `data`.
   * @param data The response body.
   */
  explicit constexpr ReplyParser(ByteSpan data) noexcept : reader_(data) {}

  /**
   * @brief The next element, which must have `tag`.
   * @param tag The tag.
   * @return Its value, or `FrameError`.
   */
  constexpr Result<ByteSpan> Need(uint8_t tag) noexcept {
    const Result<apdu::Tlv> tlv = reader_.Expect(tag);
    if (!tlv.ok()) {
      return Fail<ByteSpan>(Error::FrameError);
    }
    return Result<ByteSpan>::Success(tlv.value.value);
  }
  /**
   * @brief The next element, which must have `tag` and `length` bytes.
   * @param tag The tag.
   * @param length The length.
   * @return Its value, or `FrameError`.
   */
  constexpr Result<ByteSpan> NeedLength(uint8_t tag, std::size_t length) noexcept {
    const Result<ByteSpan> value = Need(tag);
    if (value.ok() && (value.value.size() != length)) {
      return Fail<ByteSpan>(Error::FrameError);
    }
    return value;
  }
  /**
   * @brief The next element if it has `tag`; nothing is consumed otherwise.
   * @param tag The tag.
   * @return Whether it was present and its value; `FrameError` for a malformed element.
   */
  constexpr Result<OptionalTlv> Optional(uint8_t tag) noexcept {
    if (reader_.AtEnd()) {
      return Result<OptionalTlv>::Success(OptionalTlv{});
    }
    TlvReader probe = reader_;
    const Result<apdu::Tlv> tlv = probe.Next();
    if (!tlv.ok()) {
      return Fail<OptionalTlv>(Error::FrameError);
    }
    if (tlv.value.tag != tag) {
      return Result<OptionalTlv>::Success(OptionalTlv{});
    }
    reader_ = probe;
    return Result<OptionalTlv>::Success(OptionalTlv{.present = true, .value = tlv.value.value});
  }
  /** @return `Ok` when every byte was read, else `FrameError` (no trailing data is ignored). */
  [[nodiscard]] constexpr Result<void> End() const noexcept {
    return reader_.AtEnd() ? Result<void>::Success() : Fail<void>(Error::FrameError);
  }

private:
  TlvReader reader_;
};

/**
 * @brief Copy a response value into a caller buffer; never truncates.
 * @param value The value.
 * @param out The caller's buffer.
 * @param written Receives the number of bytes copied.
 * @return `Ok`, or `BufferTooSmall` (nothing copied).
 */
constexpr Result<void> CopyOut(ByteSpan value, MutableByteSpan out, std::size_t& written) noexcept {
  if (value.size() > out.size()) {
    written = 0U;
    return Fail<void>(Error::BufferTooSmall);
  }
  for (std::size_t i = 0U; i < value.size(); ++i) {
    out[i] = value[i];
  }
  written = value.size();
  return Result<void>::Success();
}

/**
 * @brief Copy a response value into a fixed reply buffer; never truncates.
 * @tparam N The capacity.
 * @param value The value.
 * @param dest The reply buffer.
 * @return `Ok`, or `BufferTooSmall`.
 */
template <std::size_t N>
constexpr Result<void> CopyFixed(ByteSpan value, FixedBytes<N>& dest) noexcept {
  return CopyOut(value, MutableByteSpan{dest.bytes}, dest.length);
}

/**
 * @brief Copy a value of exactly `N` bytes into an array.
 * @tparam N The length.
 * @param value The value.
 * @param dest The array.
 * @return `Ok`, or `FrameError` for another length.
 */
template <std::size_t N>
constexpr Result<void> CopyExact(ByteSpan value, std::array<uint8_t, N>& dest) noexcept {
  if (value.size() != N) {
    return Fail<void>(Error::FrameError);
  }
  for (std::size_t i = 0U; i < N; ++i) {
    dest[i] = value[i];
  }
  return Result<void>::Success();
}

/**
 * @brief A response body that must be empty.
 * @param data The body.
 * @return `Ok`, or `FrameError`.
 */
constexpr Result<void> ExpectEmpty(ByteSpan data) noexcept {
  return data.empty() ? Result<void>::Success() : Fail<void>(Error::FrameError);
}

/**
 * @brief Forward a failed `Result<void>` as `Result<T>`.
 * @tparam T The value type.
 * @param r The failure.
 * @return The same error and detail.
 */
template <typename T>
constexpr Result<T> Forward(const Result<void>& r) noexcept {
  return Result<T>::Failure(r.error, r.detail);
}

} // namespace detail

} // namespace se05x::apdu

#endif // SE05X_APDU_HPP
