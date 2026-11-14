/**
 * @file se05x_pki_der.hpp
 * @brief A strict, bounded DER reader and a DER writer (X.690 clause 10, the distinguished
 * encoding), for the PKI layer.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * The reader accepts DER only and refuses everything else with a `Reason`:
 * a tag number above 30 (`HighTagNumber`), the indefinite length (`IndefiniteLength`), a length in
 * more bytes than it needs (`NonMinimalLength`), a length above `kMaxLength` (`LengthTooLarge`), an
 * element that runs past its parent (`Truncated`) and nesting deeper than `kMaxDepth` (`TooDeep`).
 * It never recurses: a constructed element is opened as a child `Reader` one level deeper, and the
 * depth is counted. The primitive checks (`ParseInteger`, `ParseBoolean`, `ParseBitString`,
 * `CheckOid`, `ParseTime`, the string checks) apply the DER rules of X.690 8 and 11: minimal
 * integers, booleans 00 or FF, zero pad bits, minimal sub-identifiers, times in UTC to the second.
 *
 * The writer works forwards in the caller's buffer: `Begin()` opens a constructed element with a
 * one-byte length, `End()` closes it and moves the content when the length needs the long form, so
 * the result is DER without a second pass. Up to `kMaxDepth` elements are open at a time. The first
 * error latches (`Status()`); `Finish()` returns the length or the error. Nothing allocates.
 */
#ifndef SE05X_PKI_DER_HPP
#define SE05X_PKI_DER_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

#include "se05x_pki_types.hpp"
#include "se05x_status.hpp"
#include "se05x_types.hpp"

/** @brief DER encoding and decoding (X.690). */
namespace se05x::pki::der {

/**
 * @defgroup se05x_pki_der DER
 * @brief The strict reader and the writer.
 * @{
 */

inline constexpr uint8_t kBoolean = 0x01U;         ///< BOOLEAN.
inline constexpr uint8_t kInteger = 0x02U;         ///< INTEGER.
inline constexpr uint8_t kBitString = 0x03U;       ///< BIT STRING (primitive).
inline constexpr uint8_t kOctetString = 0x04U;     ///< OCTET STRING (primitive).
inline constexpr uint8_t kNull = 0x05U;            ///< NULL.
inline constexpr uint8_t kOid = 0x06U;             ///< OBJECT IDENTIFIER.
inline constexpr uint8_t kUtf8String = 0x0CU;      ///< UTF8String.
inline constexpr uint8_t kPrintableString = 0x13U; ///< PrintableString.
inline constexpr uint8_t kIa5String = 0x16U;       ///< IA5String.
inline constexpr uint8_t kUtcTime = 0x17U;         ///< UTCTime.
inline constexpr uint8_t kGeneralizedTime = 0x18U; ///< GeneralizedTime.
inline constexpr uint8_t kSequence = 0x30U;        ///< SEQUENCE (constructed).
inline constexpr uint8_t kSet = 0x31U;             ///< SET (constructed).
inline constexpr uint8_t kConstructed = 0x20U;     ///< The constructed bit of a tag.
inline constexpr uint8_t kContext = 0x80U;         ///< The context-specific class bits of a tag.

/**
 * @param number The tag number, 0 to 30.
 * @return The tag of `[number] EXPLICIT` (constructed, context specific).
 */
constexpr uint8_t ContextConstructed(uint8_t number) noexcept {
  return static_cast<uint8_t>(static_cast<uint32_t>(kContext) |
                              static_cast<uint32_t>(kConstructed) |
                              (static_cast<uint32_t>(number) & 0x1FU));
}
/**
 * @param number The tag number, 0 to 30.
 * @return The tag of a primitive `[number] IMPLICIT`.
 */
constexpr uint8_t ContextPrimitive(uint8_t number) noexcept {
  return static_cast<uint8_t>(static_cast<uint32_t>(kContext) |
                              (static_cast<uint32_t>(number) & 0x1FU));
}

/// Deepest nesting the reader opens and the writer keeps open (a certificate needs 7).
inline constexpr std::size_t kMaxDepth = 10U;
/// Longest element: two length bytes (a certificate of the layer is far shorter).
inline constexpr std::size_t kMaxLength = 0xFFFFU;
/// Longest object identifier content (the identifiers of the layer are at most 9 bytes).
inline constexpr std::size_t kMaxOidBytes = 32U;

/** @brief One element: its tag, its content and its whole encoding. */
struct Element {
  uint8_t tag{0};   ///< The identifier octet.
  ByteSpan value;   ///< The content octets.
  ByteSpan encoded; ///< Tag, length and content.
};

/**
 * @brief The length of a DER length field.
 * @param length The content length.
 * @return 1, 2 or 3 bytes; 0 above `kMaxLength`.
 */
constexpr std::size_t LengthFieldSize(std::size_t length) noexcept {
  std::size_t size = 0U;
  if (length < 0x80U) {
    size = 1U;
  } else if (length <= 0xFFU) {
    size = 2U;
  } else if (length <= kMaxLength) {
    size = 3U;
  } else {
    size = 0U;
  }
  return size;
}

/**
 * @brief Whether two byte views hold the same bytes. Public data only (names, identifiers):
 * not constant time.
 * @param a The first.
 * @param b The second.
 * @return true when equal.
 */
constexpr bool SameBytes(ByteSpan a, ByteSpan b) noexcept {
  return (a.size() == b.size()) && std::equal(a.begin(), a.end(), b.begin());
}

/** @brief A strict DER reader over one level of elements. */
class Reader {
public:
  /**
   * @brief Read `data` as a list of elements at nesting depth `depth`.
   * @param data The bytes; they must outlive the reader and every element it returns.
   * @param depth The depth of `data` (0 for the outermost input).
   */
  constexpr explicit Reader(ByteSpan data, std::size_t depth = 0U) noexcept
      : data_(data), depth_(depth) {}
  /** @brief A reader of nothing (`AtEnd()`), to be assigned by `Enter()`. */
  constexpr Reader() noexcept = default;

  /** @return true when every byte has been read. */
  [[nodiscard]] constexpr bool AtEnd() const noexcept {
    return pos_ >= data_.size();
  }
  /** @return The nesting depth of this reader. */
  [[nodiscard]] constexpr std::size_t Depth() const noexcept {
    return depth_;
  }
  /**
   * @param tag A tag.
   * @return true when the next element has this tag (nothing is read).
   */
  [[nodiscard]] constexpr bool Peek(uint8_t tag) const noexcept {
    return !AtEnd() && (data_[pos_] == tag);
  }

  /**
   * @brief Read the next element.
   * @param out Receives it; unchanged on failure.
   * @return `Ok`, or why the header is not DER (nothing is consumed then).
   */
  constexpr Reason Next(Element& out) noexcept {
    const std::size_t left = data_.size() - std::min(pos_, data_.size());
    if (left < 2U) {
      return Reason::Truncated;
    }
    const uint8_t tag = data_[pos_];
    if ((tag & 0x1FU) == 0x1FU) {
      return Reason::HighTagNumber;
    }
    std::size_t length = 0U;
    std::size_t header = 0U;
    const Reason r = readLength(data_.subspan(pos_ + 1U), length, header);
    if (r != Reason::Ok) {
      return r;
    }
    if ((1U + header + length) > left) {
      return Reason::Truncated;
    }
    out.tag = tag;
    out.value = data_.subspan(pos_ + 1U + header, length);
    out.encoded = data_.subspan(pos_, 1U + header + length);
    pos_ += 1U + header + length;
    return Reason::Ok;
  }

  /**
   * @brief Read the next element and require its tag.
   * @param tag The tag.
   * @param out Receives the element.
   * @return `Ok`, `UnexpectedTag` (nothing consumed), or a reason of `Next()`.
   */
  constexpr Reason Expect(uint8_t tag, Element& out) noexcept {
    if (AtEnd()) {
      return Reason::Truncated;
    }
    if (data_[pos_] != tag) {
      return Reason::UnexpectedTag;
    }
    return Next(out);
  }

  /**
   * @brief Open the content of a constructed element one level deeper.
   * @param element An element this reader (or one at the same depth) returned.
   * @param child Receives the reader of its content.
   * @return `Ok`, `UnexpectedTag` (a primitive element) or `TooDeep`.
   */
  constexpr Reason Enter(const Element& element, Reader& child) const noexcept {
    if ((element.tag & kConstructed) == 0U) {
      return Reason::UnexpectedTag;
    }
    if ((depth_ + 1U) > kMaxDepth) {
      return Reason::TooDeep;
    }
    child = Reader(element.value, depth_ + 1U);
    return Reason::Ok;
  }

  /**
   * @brief Read an element with a tag and open it.
   * @param tag The constructed tag.
   * @param child Receives the reader of its content.
   * @return As `Expect()` and `Enter()`.
   */
  constexpr Reason ExpectEnter(uint8_t tag, Reader& child) noexcept {
    Element e{};
    const Reason r = Expect(tag, e);
    return (r == Reason::Ok) ? Enter(e, child) : r;
  }

  /** @return `Ok` when every byte was read, else `TrailingData`. */
  [[nodiscard]] constexpr Reason Finish() const noexcept {
    return AtEnd() ? Reason::Ok : Reason::TrailingData;
  }

private:
  static constexpr Reason readLength(ByteSpan in, std::size_t& length,
                                     std::size_t& header) noexcept {
    const uint8_t first = in[0];
    if (first < 0x80U) {
      length = first;
      header = 1U;
      return Reason::Ok;
    }
    if (first == 0x80U) {
      return Reason::IndefiniteLength;
    }
    const auto count = static_cast<std::size_t>(first & 0x7FU);
    if (count > 2U) {
      return Reason::LengthTooLarge; // longer than kMaxLength, or the reserved form 0xFF
    }
    if (in.size() < (1U + count)) {
      return Reason::Truncated;
    }
    std::size_t value = 0U;
    for (std::size_t i = 0U; i < count; ++i) {
      value = (value << 8U) | in[1U + i];
    }
    if (LengthFieldSize(value) != (1U + count)) {
      return Reason::NonMinimalLength; // X.690 10.1: the definite form in the fewest octets
    }
    length = value;
    header = 1U + count;
    return Reason::Ok;
  }

  ByteSpan data_;
  std::size_t pos_{0};
  std::size_t depth_{0};
};

/**
 * @brief Check a DER INTEGER that must not be negative (X.690 8.3.2: no redundant leading byte).
 * @param value The content octets.
 * @param magnitude Receives the value without the leading 0x00 of a positive value whose top bit
 * is set (`{0x00}` for zero).
 * @return `Ok` or `BadInteger` (empty, non-minimal or negative).
 */
constexpr Reason ParseUnsigned(ByteSpan value, ByteSpan& magnitude) noexcept {
  if (value.empty() || ((value[0] & 0x80U) != 0U)) {
    return Reason::BadInteger;
  }
  if (value.size() == 1U) {
    magnitude = value;
    return Reason::Ok;
  }
  if ((value[0] == 0x00U) && ((value[1] & 0x80U) == 0U)) {
    return Reason::BadInteger;
  }
  magnitude = (value[0] == 0x00U) ? value.subspan(1U) : value;
  return Reason::Ok;
}

/**
 * @brief Read a small non-negative INTEGER.
 * @param value The content octets.
 * @param max The largest value allowed.
 * @param out Receives the value.
 * @return `Ok` or `BadInteger` (not minimal, negative or above `max`).
 */
constexpr Reason ParseSmall(ByteSpan value, uint32_t max, uint32_t& out) noexcept {
  ByteSpan m{};
  const Reason r = ParseUnsigned(value, m);
  if ((r != Reason::Ok) || (m.size() > 4U)) {
    return Reason::BadInteger;
  }
  uint32_t v = 0U;
  for (const uint8_t b : m) {
    v = (v << 8U) | b;
  }
  if (v > max) {
    return Reason::BadInteger;
  }
  out = v;
  return Reason::Ok;
}

/**
 * @brief Read a DER BOOLEAN (X.690 11.1: FALSE is 0x00, TRUE is 0xFF).
 * @param value The content octets.
 * @param out Receives the value.
 * @return `Ok` or `BadBoolean`.
 */
constexpr Reason ParseBoolean(ByteSpan value, bool& out) noexcept {
  if ((value.size() != 1U) || ((value[0] != 0x00U) && (value[0] != 0xFFU))) {
    return Reason::BadBoolean;
  }
  out = (value[0] == 0xFFU);
  return Reason::Ok;
}

/**
 * @brief Read a DER BIT STRING (X.690 8.6.2, 11.2.1: the pad bits are zero).
 * @param value The content octets.
 * @param bits Receives the bit bytes (after the unused-bit count).
 * @param unused Receives the number of unused bits of the last byte, 0 to 7.
 * @return `Ok` or `BadBitString`.
 */
constexpr Reason ParseBitString(ByteSpan value, ByteSpan& bits, uint8_t& unused) noexcept {
  if (value.empty() || (value[0] > 7U) || ((value.size() == 1U) && (value[0] != 0U))) {
    return Reason::BadBitString;
  }
  const uint8_t pad = value[0];
  if (value.size() > 1U) {
    const uint32_t mask = (uint32_t{1} << pad) - 1U;
    if ((static_cast<uint32_t>(value[value.size() - 1U]) & mask) != 0U) {
      return Reason::BadBitString;
    }
  }
  bits = value.subspan(1U);
  unused = pad;
  return Reason::Ok;
}

/**
 * @brief Read a BIT STRING that holds whole bytes (a key or a signature).
 * @param value The content octets.
 * @param bytes Receives the bytes.
 * @return `Ok` or `BadBitString` (a non-zero unused-bit count).
 */
constexpr Reason ParseOctetBits(ByteSpan value, ByteSpan& bytes) noexcept {
  uint8_t unused = 0U;
  const Reason r = ParseBitString(value, bytes, unused);
  if ((r == Reason::Ok) && (unused != 0U)) {
    return Reason::BadBitString;
  }
  return r;
}

/**
 * @brief Read a DER named-bit list of up to 16 bits (X.690 11.2.2: no trailing zero bits).
 * @param value The content octets.
 * @param out Receives bit `i` of the list as `1 << i`.
 * @return `Ok` or `BadBitString` (empty, trailing zero bits, more than 16 bits).
 */
constexpr Reason ParseNamedBits(ByteSpan value, uint16_t& out) noexcept {
  ByteSpan bits{};
  uint8_t unused = 0U;
  const Reason r = ParseBitString(value, bits, unused);
  if ((r != Reason::Ok) || bits.empty() || (bits.size() > 2U)) {
    return Reason::BadBitString;
  }
  const uint32_t last = bits[bits.size() - 1U];
  if ((last & (uint32_t{1} << unused)) == 0U) {
    return Reason::BadBitString; // the last used bit is a trailing zero
  }
  uint32_t v = 0U;
  for (std::size_t i = 0U; i < (bits.size() * 8U); ++i) {
    const uint32_t byte = bits[i / 8U];
    if (((byte >> (7U - (i % 8U))) & 1U) != 0U) {
      v |= uint32_t{1} << i;
    }
  }
  out = static_cast<uint16_t>(v & 0xFFFFU);
  return Reason::Ok;
}

/**
 * @brief Check the content of an OBJECT IDENTIFIER (X.690 8.19.2: each sub-identifier in the
 * fewest octets).
 * @param value The content octets.
 * @return `Ok` or `BadOid` (empty, longer than `kMaxOidBytes`, a leading 0x80, an unfinished
 * last sub-identifier).
 */
constexpr Reason CheckOid(ByteSpan value) noexcept {
  if (value.empty() || (value.size() > kMaxOidBytes)) {
    return Reason::BadOid;
  }
  bool start = true;
  for (const uint8_t b : value) {
    if (start && (b == 0x80U)) {
      return Reason::BadOid;
    }
    start = ((b & 0x80U) == 0U);
  }
  return start ? Reason::Ok : Reason::BadOid;
}

/**
 * @brief Check a NULL.
 * @param value The content octets.
 * @return `Ok` or `BadNull`.
 */
constexpr Reason CheckNull(ByteSpan value) noexcept {
  return value.empty() ? Reason::Ok : Reason::BadNull;
}

/**
 * @param b A byte.
 * @return true for a character of PrintableString (X.680 41.4).
 */
constexpr bool IsPrintableByte(uint8_t b) noexcept {
  const bool alnum = ((b >= 0x41U) && (b <= 0x5AU)) || ((b >= 0x61U) && (b <= 0x7AU)) ||
                     ((b >= 0x30U) && (b <= 0x39U));
  constexpr std::array<uint8_t, 13> kMarks{0x20U, 0x27U, 0x28U, 0x29U, 0x2BU, 0x2CU, 0x2DU,
                                           0x2EU, 0x2FU, 0x3AU, 0x3DU, 0x3FU, 0x00U};
  bool mark = false;
  for (std::size_t i = 0U; (i + 1U) < kMarks.size(); ++i) {
    mark = mark || (kMarks[i] == b);
  }
  return alnum || mark;
}

/**
 * @brief Check PrintableString content.
 * @param value The bytes.
 * @return `Ok` or `BadString`.
 */
constexpr Reason CheckPrintable(ByteSpan value) noexcept {
  return std::all_of(value.begin(), value.end(), IsPrintableByte) ? Reason::Ok : Reason::BadString;
}

/**
 * @brief Check IA5String content (7-bit, no NUL).
 * @param value The bytes.
 * @return `Ok` or `BadString`.
 */
constexpr Reason CheckIa5(ByteSpan value) noexcept {
  for (const uint8_t b : value) {
    if ((b == 0U) || (b >= 0x80U)) {
      return Reason::BadString;
    }
  }
  return Reason::Ok;
}

namespace detail {
/**
 * @brief Decode the lead byte of a UTF-8 sequence.
 * @param b The byte.
 * @param more Receives the number of continuation bytes.
 * @param cp Receives the bits of the lead byte.
 * @param min Receives the smallest code point of that length (an overlong form is below it).
 * @return false for NUL, a continuation byte or 0xF8 and above.
 */
constexpr bool Utf8Lead(uint32_t b, std::size_t& more, uint32_t& cp, uint32_t& min) noexcept {
  bool ok = true;
  if ((b > 0U) && (b < 0x80U)) {
    more = 0U;
    cp = b;
    min = 0U;
  } else if ((b & 0xE0U) == 0xC0U) {
    more = 1U;
    cp = b & 0x1FU;
    min = 0x80U;
  } else if ((b & 0xF0U) == 0xE0U) {
    more = 2U;
    cp = b & 0x0FU;
    min = 0x800U;
  } else if ((b & 0xF8U) == 0xF0U) {
    more = 3U;
    cp = b & 0x07U;
    min = 0x10000U;
  } else {
    ok = false;
  }
  return ok;
}
} // namespace detail

/**
 * @brief Check UTF-8 (RFC 3629: no overlong form, no surrogate, at most U+10FFFF, no NUL).
 * @param value The bytes.
 * @return `Ok` or `BadString`.
 */
constexpr Reason CheckUtf8(ByteSpan value) noexcept {
  std::size_t i = 0U;
  while (i < value.size()) {
    std::size_t more = 0U;
    uint32_t cp = 0U;
    uint32_t min = 0U;
    if (!detail::Utf8Lead(value[i], more, cp, min) ||
        ((more != 0U) && ((i + more) >= value.size()))) {
      return Reason::BadString;
    }
    for (std::size_t k = 1U; k <= more; ++k) {
      const uint32_t c = value[i + k];
      if ((c & 0xC0U) != 0x80U) {
        return Reason::BadString;
      }
      cp = (cp << 6U) | (c & 0x3FU);
    }
    if ((cp < min) || (cp > 0x10FFFFU) || ((cp >= 0xD800U) && (cp <= 0xDFFFU))) {
      return Reason::BadString;
    }
    i += 1U + more;
  }
  return Reason::Ok;
}

/**
 * @brief Read a time (RFC 5280 4.1.2.5: UTCTime `YYMMDDHHMMSSZ`, a two-digit year below 50 is
 * 20YY, else 19YY; GeneralizedTime `YYYYMMDDHHMMSSZ`, no fraction).
 * @param element A UTCTime or GeneralizedTime element.
 * @param out Receives the time.
 * @return `Ok`, `UnexpectedTag` or `BadTime` (form, digit or range).
 */
constexpr Reason ParseTime(const Element& element, Time& out) noexcept {
  const bool utc = (element.tag == kUtcTime);
  if (!utc && (element.tag != kGeneralizedTime)) {
    return Reason::UnexpectedTag;
  }
  const ByteSpan v = element.value;
  const std::size_t digits = utc ? 12U : 14U;
  if ((v.size() != (digits + 1U)) || (v[digits] != 0x5AU)) {
    return Reason::BadTime; // the length, or no 'Z'
  }
  std::array<uint32_t, 7> f{};
  for (std::size_t i = 0U; i < digits; ++i) {
    if ((v[i] < 0x30U) || (v[i] > 0x39U)) {
      return Reason::BadTime;
    }
    f[i / 2U] = (f[i / 2U] * 10U) + (static_cast<uint32_t>(v[i]) - 0x30U);
  }
  uint32_t year = 0U;
  std::size_t at = 1U;
  if (utc) {
    year = (f[0] < 50U) ? (2000U + f[0]) : (1900U + f[0]);
  } else {
    year = (f[0] * 100U) + f[1];
    at = 2U;
  }
  Time t{};
  t.year = static_cast<uint16_t>(year & 0xFFFFU);
  t.month = static_cast<uint8_t>(f[at] & 0xFFU);
  t.day = static_cast<uint8_t>(f[at + 1U] & 0xFFU);
  t.hour = static_cast<uint8_t>(f[at + 2U] & 0xFFU);
  t.minute = static_cast<uint8_t>(f[at + 3U] & 0xFFU);
  t.second = static_cast<uint8_t>(f[at + 4U] & 0xFFU);
  if (!IsValid(t)) {
    return Reason::BadTime;
  }
  out = t;
  return Reason::Ok;
}

/**
 * @brief Read an ECDSA-Sig-Value (RFC 5480 2.2.3 via RFC 3279: SEQUENCE of two INTEGERs r and s)
 * into the fixed-width `r || s` form.
 * @param der The signature value.
 * @param width Bytes of each of r and s (32 for P-256, 48 for P-384).
 * @param raw Receives `r || s`; at least `2 * width` bytes.
 * @return `Ok` or `BadSignatureValue` (structure, a non-minimal, negative, zero or too wide
 * integer, trailing bytes).
 */
constexpr Reason ParseEcdsaSignature(ByteSpan der, std::size_t width,
                                     MutableByteSpan raw) noexcept {
  if ((width == 0U) || (raw.size() < (2U * width))) {
    return Reason::BadSignatureValue;
  }
  Reader outer(der, kMaxDepth - 1U);
  Reader seq(ByteSpan{}, 0U);
  if ((outer.ExpectEnter(kSequence, seq) != Reason::Ok) || (outer.Finish() != Reason::Ok)) {
    return Reason::BadSignatureValue;
  }
  for (std::size_t k = 0U; k < 2U; ++k) {
    Element e{};
    ByteSpan m{};
    if ((seq.Expect(kInteger, e) != Reason::Ok) || (ParseUnsigned(e.value, m) != Reason::Ok) ||
        (m.size() > width) || ((m.size() == 1U) && (m[0] == 0U))) {
      return Reason::BadSignatureValue;
    }
    const MutableByteSpan slot = raw.subspan(k * width, width);
    std::fill(slot.begin(), slot.end(), uint8_t{0});
    static_cast<void>(std::copy(m.begin(), m.end(),
                                slot.begin() + static_cast<std::ptrdiff_t>(width - m.size())));
  }
  return (seq.Finish() == Reason::Ok) ? Reason::Ok : Reason::BadSignatureValue;
}

/** @brief A forward DER writer into the caller's buffer. */
class Writer {
public:
  /**
   * @brief Write into `out`.
   * @param out The buffer; it must outlive the writer.
   */
  constexpr explicit Writer(MutableByteSpan out) noexcept : out_(out) {}

  /** @return The first error, or `Ok`. */
  [[nodiscard]] constexpr Reason Status() const noexcept {
    return error_;
  }
  /** @return The bytes written so far. */
  [[nodiscard]] constexpr std::size_t Size() const noexcept {
    return pos_;
  }
  /**
   * @return The whole encoding of the element the last `End()` closed; empty before the first
   * one. It is valid until the next `End()` (which may move it).
   */
  [[nodiscard]] constexpr ByteSpan LastClosed() const noexcept {
    return ByteSpan{out_.data(), out_.size()}.subspan(closed_at_, closed_size_);
  }

  /**
   * @brief Open a constructed element.
   * @param tag Its tag (the constructed bit is the caller's: `kSequence`, `kSet`, `[n]`).
   */
  constexpr void Begin(uint8_t tag) noexcept {
    if (depth_ >= kMaxDepth) {
      fail(Reason::TooDeep);
      return;
    }
    if (!room(2U)) {
      return;
    }
    open_[depth_] = pos_;
    ++depth_;
    out_[pos_] = tag;
    out_[pos_ + 1U] = 0U;
    pos_ += 2U;
  }
  /** @brief Open a BIT STRING with no unused bits; its content follows, closed with `End()`. */
  constexpr void BeginBitString() noexcept {
    Begin(kBitString);
    Byte(0U);
  }
  /**
   * @brief Close the innermost open element.
   */
  constexpr void End() noexcept {
    if (error_ != Reason::Ok) {
      return;
    }
    if (depth_ == 0U) {
      fail(Reason::InvalidInput);
      return;
    }
    --depth_;
    const std::size_t start = open_[depth_];
    const std::size_t length = pos_ - (start + 2U);
    const std::size_t field = LengthFieldSize(length);
    if (field == 0U) {
      fail(Reason::LengthTooLarge);
      return;
    }
    if (field > 1U) {
      if (!room(field - 1U)) {
        return;
      }
      const auto first = out_.begin() + static_cast<std::ptrdiff_t>(start + 2U);
      const auto last = out_.begin() + static_cast<std::ptrdiff_t>(pos_);
      static_cast<void>(
          std::copy_backward(first, last, last + static_cast<std::ptrdiff_t>(field - 1U)));
      pos_ += field - 1U;
    }
    putLength(start + 1U, length, field);
    closed_at_ = start;
    closed_size_ = pos_ - start;
  }

  /**
   * @brief Append one raw byte (inside an open element).
   * @param b The byte.
   */
  constexpr void Byte(uint8_t b) noexcept {
    if (room(1U)) {
      out_[pos_] = b;
      ++pos_;
    }
  }
  /**
   * @brief Append raw bytes: content, or one complete element encoded elsewhere.
   * @param bytes The bytes.
   */
  constexpr void Raw(ByteSpan bytes) noexcept {
    if (room(bytes.size())) {
      static_cast<void>(
          std::copy(bytes.begin(), bytes.end(), out_.begin() + static_cast<std::ptrdiff_t>(pos_)));
      pos_ += bytes.size();
    }
  }
  /**
   * @brief Append a primitive element.
   * @param tag Its tag.
   * @param value Its content.
   */
  constexpr void Primitive(uint8_t tag, ByteSpan value) noexcept {
    const std::size_t field = LengthFieldSize(value.size());
    if (field == 0U) {
      fail(Reason::LengthTooLarge);
      return;
    }
    if (!room(1U + field + value.size())) {
      return;
    }
    out_[pos_] = tag;
    putLength(pos_ + 1U, value.size(), field);
    pos_ += 1U + field;
    Raw(value);
  }
  /**
   * @brief Append a non-negative INTEGER from its big-endian magnitude (leading zero bytes are
   * dropped, a 0x00 is added when the top bit is set: X.690 8.3.2).
   * @param magnitude The value; empty means zero.
   */
  constexpr void Integer(ByteSpan magnitude) noexcept {
    std::size_t skip = 0U;
    while (((skip + 1U) < magnitude.size()) && (magnitude[skip] == 0U)) {
      ++skip;
    }
    const ByteSpan m = magnitude.subspan(skip);
    const bool pad = m.empty() || ((m[0] & 0x80U) != 0U);
    const std::size_t length = m.size() + (pad ? 1U : 0U);
    const std::size_t field = LengthFieldSize(length);
    if ((field == 0U) || !room(1U + field + length)) {
      fail(Reason::LengthTooLarge);
      return;
    }
    out_[pos_] = kInteger;
    putLength(pos_ + 1U, length, field);
    pos_ += 1U + field;
    if (pad) {
      Byte(0U);
    }
    Raw(m);
  }
  /**
   * @brief Append a small non-negative INTEGER.
   * @param value The value.
   */
  constexpr void Small(uint32_t value) noexcept {
    const std::array<uint8_t, 4> be{
        static_cast<uint8_t>((value >> 24U) & 0xFFU), static_cast<uint8_t>((value >> 16U) & 0xFFU),
        static_cast<uint8_t>((value >> 8U) & 0xFFU), static_cast<uint8_t>(value & 0xFFU)};
    Integer(ByteSpan{be});
  }
  /**
   * @brief Append a BOOLEAN (DER: 0x00 or 0xFF).
   * @param value The value.
   */
  constexpr void Boolean(bool value) noexcept {
    const std::array<uint8_t, 1> v{value ? static_cast<uint8_t>(0xFFU)
                                         : static_cast<uint8_t>(0x00U)};
    Primitive(kBoolean, ByteSpan{v});
  }
  /**
   * @brief Append an OBJECT IDENTIFIER; its content is checked (`CheckOid`).
   * @param content The content octets.
   */
  constexpr void Oid(ByteSpan content) noexcept {
    if (CheckOid(content) != Reason::Ok) {
      fail(Reason::BadOid);
      return;
    }
    Primitive(kOid, content);
  }
  /**
   * @brief Append a BIT STRING with no unused bits.
   * @param bytes The bits.
   */
  constexpr void BitString(ByteSpan bytes) noexcept {
    BeginBitString();
    Raw(bytes);
    End();
  }
  /**
   * @brief Append a named-bit list in its DER form (trailing zero bits removed, X.690 11.2.2).
   * @param bits Bit `i` as `1 << i`; not 0.
   */
  constexpr void NamedBits(uint16_t bits) noexcept {
    if (bits == 0U) {
      fail(Reason::InvalidInput);
      return;
    }
    uint32_t highest = 0U;
    for (uint32_t i = 0U; i < 16U; ++i) {
      if (((static_cast<uint32_t>(bits) >> i) & 1U) != 0U) {
        highest = i;
      }
    }
    std::array<uint8_t, 3> v{};
    const std::size_t bytes = static_cast<std::size_t>(highest / 8U) + 1U;
    v[0] = static_cast<uint8_t>((7U - (highest % 8U)) & 0xFFU);
    for (uint32_t i = 0U; i <= highest; ++i) {
      if (((static_cast<uint32_t>(bits) >> i) & 1U) != 0U) {
        const std::size_t at = 1U + static_cast<std::size_t>(i / 8U);
        v[at] = static_cast<uint8_t>(v[at] | ((0x80U >> (i % 8U)) & 0xFFU));
      }
    }
    Primitive(kBitString, ByteSpan{v}.first(1U + bytes));
  }

  /**
   * @brief Mark the writer failed (a caller's own check).
   * @param reason Why; the first reason is kept.
   */
  constexpr void Fail(Reason reason) noexcept {
    fail(reason);
  }

  /**
   * @return The length written, or the first error; `InvalidInput` while an element is open.
   */
  [[nodiscard]] constexpr Result<std::size_t> Finish() const noexcept {
    if (error_ != Reason::Ok) {
      return pki::Fail<std::size_t>(error_);
    }
    if (depth_ != 0U) {
      return pki::Fail<std::size_t>(Reason::InvalidInput);
    }
    return Result<std::size_t>::Success(pos_);
  }

private:
  constexpr void fail(Reason reason) noexcept {
    if (error_ == Reason::Ok) {
      error_ = reason;
    }
  }
  [[nodiscard]] constexpr bool room(std::size_t n) noexcept {
    if (error_ != Reason::Ok) {
      return false;
    }
    if (n > (out_.size() - pos_)) {
      fail(Reason::BufferTooSmall);
      return false;
    }
    return true;
  }
  constexpr void putLength(std::size_t at, std::size_t length, std::size_t field) noexcept {
    if (field == 1U) {
      out_[at] = static_cast<uint8_t>(length & 0x7FU);
    } else if (field == 2U) {
      out_[at] = 0x81U;
      out_[at + 1U] = static_cast<uint8_t>(length & 0xFFU);
    } else {
      out_[at] = 0x82U;
      out_[at + 1U] = static_cast<uint8_t>((length >> 8U) & 0xFFU);
      out_[at + 2U] = static_cast<uint8_t>(length & 0xFFU);
    }
  }

  MutableByteSpan out_;
  std::size_t pos_{0};
  std::array<std::size_t, kMaxDepth> open_{};
  std::size_t depth_{0};
  std::size_t closed_at_{0};
  std::size_t closed_size_{0};
  Reason error_{Reason::Ok};
};

/** @} */

} // namespace se05x::pki::der

#endif // SE05X_PKI_DER_HPP
