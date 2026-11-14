/**
 * @file test_pki_der.cpp
 * @brief PKI layer: the strict DER reader, the primitive checks, the writer, time and reasons
 * (X.690 clause 10 and 11, RFC 5280 4.1.2.5).
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <array>
#include <cstddef>
#include <cstdint>

#include "pki_test_util.hpp"
#include "se05x_pki_der.hpp"
#include "test_harness.hpp"

using namespace se05x;
using namespace se05x::pki;

namespace {

template <std::size_t N>
Reason ReadOne(const std::array<uint8_t, N>& bytes, der::Element& e) {
  der::Reader r(ByteSpan{bytes});
  const Reason first = r.Next(e);
  return (first == Reason::Ok) ? r.Finish() : first;
}

template <std::size_t N>
Reason ReadOne(const std::array<uint8_t, N>& bytes) {
  der::Element e{};
  return ReadOne(bytes, e);
}

template <std::size_t N>
Reason TimeOf(const std::array<uint8_t, N>& text, uint8_t tag, Time& t) {
  der::Element e{};
  e.tag = tag;
  e.value = ByteSpan{text};
  return der::ParseTime(e, t);
}

} // namespace

TEST_CASE("PKI DER: short and long definite lengths are read; header and content are split") {
  const std::array<uint8_t, 5> shortform{0x30U, 0x03U, 0x02U, 0x01U, 0x05U};
  der::Element e{};
  CHECK_EQ(ReadOne(shortform, e), Reason::Ok);
  CHECK_EQ(e.tag, der::kSequence);
  CHECK_EQ(e.value.size(), 3U);
  CHECK_EQ(e.encoded.size(), 5U);
  std::array<uint8_t, 131> longform{};
  longform[0] = 0x04U;
  longform[1] = 0x81U;
  longform[2] = 0x80U;
  CHECK_EQ(ReadOne(longform, e), Reason::Ok);
  CHECK_EQ(e.value.size(), 128U);
  std::array<uint8_t, 260> two{};
  two[0] = 0x04U;
  two[1] = 0x82U;
  two[2] = 0x01U;
  two[3] = 0x00U;
  CHECK_EQ(ReadOne(two, e), Reason::Ok);
  CHECK_EQ(e.value.size(), 256U);
}

TEST_CASE("PKI DER: the indefinite length and reserved length forms are refused") {
  CHECK_EQ(ReadOne(std::array<uint8_t, 4>{0x30U, 0x80U, 0x00U, 0x00U}), Reason::IndefiniteLength);
  CHECK_EQ(ReadOne(std::array<uint8_t, 6>{0x04U, 0x83U, 0x00U, 0x00U, 0x01U, 0x00U}),
           Reason::LengthTooLarge);
  CHECK_EQ(ReadOne(std::array<uint8_t, 2>{0x04U, 0xFFU}), Reason::LengthTooLarge);
}

TEST_CASE("PKI DER: a length in more bytes than it needs is refused (X.690 10.1)") {
  CHECK_EQ(ReadOne(std::array<uint8_t, 4>{0x04U, 0x81U, 0x01U, 0xAAU}), Reason::NonMinimalLength);
  CHECK_EQ(ReadOne(std::array<uint8_t, 5>{0x04U, 0x82U, 0x00U, 0x01U, 0xAAU}),
           Reason::NonMinimalLength);
  std::array<uint8_t, 132> edge{};
  edge[0] = 0x04U;
  edge[1] = 0x81U;
  edge[2] = 0x7FU; // 127 fits the short form
  CHECK_EQ(ReadOne(edge), Reason::NonMinimalLength);
  std::array<uint8_t, 259> edge2{};
  edge2[0] = 0x04U;
  edge2[1] = 0x82U;
  edge2[2] = 0x00U;
  edge2[3] = 0xFFU; // 255 fits one length byte
  CHECK_EQ(ReadOne(edge2), Reason::NonMinimalLength);
}

TEST_CASE("PKI DER: truncation, high tag numbers and trailing bytes are refused") {
  CHECK_EQ(ReadOne(std::array<uint8_t, 4>{0x04U, 0x05U, 0x01U, 0x02U}), Reason::Truncated);
  CHECK_EQ(ReadOne(std::array<uint8_t, 4>{0x04U, 0x03U, 0x01U, 0x02U}), Reason::Truncated);
  CHECK_EQ(ReadOne(std::array<uint8_t, 4>{0x04U, 0x02U, 0x01U, 0x02U}), Reason::Ok);
  CHECK_EQ(ReadOne(std::array<uint8_t, 1>{0x04U}), Reason::Truncated);
  CHECK_EQ(ReadOne(std::array<uint8_t, 3>{0x04U, 0x82U, 0x01U}), Reason::Truncated);
  CHECK_EQ(ReadOne(std::array<uint8_t, 3>{0x1FU, 0x01U, 0x00U}), Reason::HighTagNumber);
  CHECK_EQ(ReadOne(std::array<uint8_t, 3>{0x05U, 0x00U, 0x00U}), Reason::TrailingData);
  CHECK_EQ(ReadOne(std::array<uint8_t, 2>{0x05U, 0x00U}), Reason::Ok);
}

TEST_CASE("PKI DER: Expect refuses another tag and consumes nothing") {
  const std::array<uint8_t, 4> two{0x05U, 0x00U, 0x05U, 0x00U};
  der::Reader r(ByteSpan{two});
  der::Element e{};
  CHECK_EQ(r.Expect(der::kInteger, e), Reason::UnexpectedTag);
  CHECK(r.Peek(der::kNull));
  CHECK_EQ(r.Expect(der::kNull, e), Reason::Ok);
  CHECK_EQ(r.Expect(der::kNull, e), Reason::Ok);
  CHECK(r.AtEnd());
  CHECK_EQ(r.Expect(der::kNull, e), Reason::Truncated);
}

TEST_CASE("PKI DER: nesting is counted and stops at kMaxDepth") {
  std::array<uint8_t, 2U * (der::kMaxDepth + 2U)> nested{};
  const std::size_t levels = der::kMaxDepth + 1U;
  for (std::size_t i = 0U; i < levels; ++i) {
    nested[2U * i] = 0x30U;
    nested[(2U * i) + 1U] = static_cast<uint8_t>(2U * (levels - 1U - i));
  }
  der::Reader r(ByteSpan{nested}.first(2U * levels));
  std::size_t opened = 0U;
  Reason last = Reason::Ok;
  for (std::size_t i = 0U; (i < levels) && (last == Reason::Ok); ++i) {
    der::Element e{};
    der::Reader child(ByteSpan{});
    last = r.Next(e);
    last = (last == Reason::Ok) ? r.Enter(e, child) : last;
    if (last == Reason::Ok) {
      ++opened;
      r = child;
    }
  }
  CHECK_EQ(opened, der::kMaxDepth);
  CHECK_EQ(last, Reason::TooDeep);
  der::Element prim{};
  const std::array<uint8_t, 2> null{0x05U, 0x00U};
  der::Reader p(ByteSpan{null});
  der::Reader child(ByteSpan{});
  CHECK_EQ(p.Next(prim), Reason::Ok);
  CHECK_EQ(p.Enter(prim, child), Reason::UnexpectedTag);
}

TEST_CASE("PKI DER: INTEGERs must be minimal and, here, not negative (X.690 8.3.2)") {
  ByteSpan m{};
  CHECK_EQ(der::ParseUnsigned(std::array<uint8_t, 1>{0x00U}, m), Reason::Ok);
  CHECK_EQ(m.size(), 1U);
  const std::array<uint8_t, 2> padded{0x00U, 0x80U};
  CHECK_EQ(der::ParseUnsigned(ByteSpan{padded}, m), Reason::Ok);
  CHECK_EQ(m.size(), 1U);
  CHECK_EQ(m[0], 0x80U);
  CHECK_EQ(der::ParseUnsigned(std::array<uint8_t, 2>{0x00U, 0x7FU}, m), Reason::BadInteger);
  CHECK_EQ(der::ParseUnsigned(std::array<uint8_t, 1>{0x80U}, m), Reason::BadInteger);
  CHECK_EQ(der::ParseUnsigned(std::array<uint8_t, 1>{0xFFU}, m), Reason::BadInteger);
  CHECK_EQ(der::ParseUnsigned(ByteSpan{}, m), Reason::BadInteger);
  uint32_t v = 0U;
  CHECK_EQ(der::ParseSmall(std::array<uint8_t, 2>{0x01U, 0x00U}, 256U, v), Reason::Ok);
  CHECK_EQ(v, 256U);
  CHECK_EQ(der::ParseSmall(std::array<uint8_t, 2>{0x01U, 0x01U}, 256U, v), Reason::BadInteger);
  CHECK_EQ(
      der::ParseSmall(std::array<uint8_t, 5>{0x01U, 0x00U, 0x00U, 0x00U, 0x00U}, 0xFFFFFFFFU, v),
      Reason::BadInteger);
}

TEST_CASE("PKI DER: BOOLEAN is 00 or FF only (X.690 11.1)") {
  bool b = false;
  CHECK_EQ(der::ParseBoolean(std::array<uint8_t, 1>{0xFFU}, b), Reason::Ok);
  CHECK(b);
  CHECK_EQ(der::ParseBoolean(std::array<uint8_t, 1>{0x00U}, b), Reason::Ok);
  CHECK(!b);
  CHECK_EQ(der::ParseBoolean(std::array<uint8_t, 1>{0x01U}, b), Reason::BadBoolean);
  CHECK_EQ(der::ParseBoolean(std::array<uint8_t, 2>{0xFFU, 0xFFU}, b), Reason::BadBoolean);
  CHECK_EQ(der::ParseBoolean(ByteSpan{}, b), Reason::BadBoolean);
}

TEST_CASE("PKI DER: BIT STRING pad bits are zero and the count is 0 to 7 (X.690 11.2.1)") {
  ByteSpan bits{};
  uint8_t unused = 0U;
  CHECK_EQ(der::ParseBitString(std::array<uint8_t, 2>{0x01U, 0x02U}, bits, unused), Reason::Ok);
  CHECK_EQ(unused, 1U);
  CHECK_EQ(der::ParseBitString(std::array<uint8_t, 2>{0x01U, 0x03U}, bits, unused),
           Reason::BadBitString);
  CHECK_EQ(der::ParseBitString(std::array<uint8_t, 2>{0x08U, 0x00U}, bits, unused),
           Reason::BadBitString);
  CHECK_EQ(der::ParseBitString(std::array<uint8_t, 1>{0x00U}, bits, unused), Reason::Ok);
  CHECK(bits.empty());
  CHECK_EQ(der::ParseBitString(std::array<uint8_t, 1>{0x01U}, bits, unused), Reason::BadBitString);
  CHECK_EQ(der::ParseOctetBits(std::array<uint8_t, 2>{0x01U, 0x02U}, bits), Reason::BadBitString);
  CHECK_EQ(der::ParseOctetBits(std::array<uint8_t, 2>{0x00U, 0x02U}, bits), Reason::Ok);
}

TEST_CASE("PKI DER: named bit lists carry no trailing zero bit (X.690 11.2.2)") {
  uint16_t ku = 0U;
  CHECK_EQ(der::ParseNamedBits(std::array<uint8_t, 2>{0x07U, 0x80U}, ku), Reason::Ok);
  CHECK_EQ(ku, key_usage::kDigitalSignature);
  CHECK_EQ(der::ParseNamedBits(std::array<uint8_t, 2>{0x01U, 0x06U}, ku), Reason::Ok);
  CHECK_EQ(ku, static_cast<uint16_t>(key_usage::kKeyCertSign | key_usage::kCrlSign));
  CHECK_EQ(der::ParseNamedBits(std::array<uint8_t, 3>{0x07U, 0x00U, 0x80U}, ku), Reason::Ok);
  CHECK_EQ(ku, key_usage::kDecipherOnly);
  CHECK_EQ(der::ParseNamedBits(std::array<uint8_t, 2>{0x06U, 0x80U}, ku), Reason::BadBitString);
  CHECK_EQ(der::ParseNamedBits(std::array<uint8_t, 2>{0x00U, 0x80U}, ku), Reason::BadBitString);
  CHECK_EQ(der::ParseNamedBits(std::array<uint8_t, 1>{0x00U}, ku), Reason::BadBitString);
}

TEST_CASE("PKI DER: OBJECT IDENTIFIER sub-identifiers are minimal and finished") {
  CHECK_EQ(der::CheckOid(ByteSpan{oid::kExtensionRequest}), Reason::Ok);
  CHECK_EQ(der::CheckOid(std::array<uint8_t, 2>{0x2AU, 0x86U}), Reason::BadOid);
  CHECK_EQ(der::CheckOid(std::array<uint8_t, 3>{0x2AU, 0x80U, 0x01U}), Reason::BadOid);
  CHECK_EQ(der::CheckOid(std::array<uint8_t, 2>{0x80U, 0x01U}), Reason::BadOid);
  CHECK_EQ(der::CheckOid(ByteSpan{}), Reason::BadOid);
  std::array<uint8_t, der::kMaxOidBytes + 1U> longer{};
  CHECK_EQ(der::CheckOid(ByteSpan{longer}.first(der::kMaxOidBytes)), Reason::Ok);
  CHECK_EQ(der::CheckOid(ByteSpan{longer}), Reason::BadOid);
  CHECK_EQ(der::CheckNull(ByteSpan{}), Reason::Ok);
  CHECK_EQ(der::CheckNull(std::array<uint8_t, 1>{0x00U}), Reason::BadNull);
}

TEST_CASE("PKI DER: PrintableString and IA5String character sets") {
  CHECK_EQ(der::CheckPrintable(std::array<uint8_t, 6>{0x41U, 0x7AU, 0x30U, 0x20U, 0x3FU, 0x2FU}),
           Reason::Ok);
  CHECK_EQ(der::CheckPrintable(std::array<uint8_t, 1>{0x40U}), Reason::BadString); // '@'
  CHECK_EQ(der::CheckPrintable(std::array<uint8_t, 1>{0x2AU}), Reason::BadString); // '*'
  CHECK_EQ(der::CheckPrintable(std::array<uint8_t, 1>{0x00U}), Reason::BadString);
  CHECK_EQ(der::CheckIa5(std::array<uint8_t, 2>{0x40U, 0x7FU}), Reason::Ok);
  CHECK_EQ(der::CheckIa5(std::array<uint8_t, 1>{0x80U}), Reason::BadString);
  CHECK_EQ(der::CheckIa5(std::array<uint8_t, 1>{0x00U}), Reason::BadString);
}

TEST_CASE("PKI DER: UTF-8 is well formed (RFC 3629)") {
  CHECK_EQ(der::CheckUtf8(std::array<uint8_t, 2>{0xC3U, 0xA9U}), Reason::Ok);
  CHECK_EQ(der::CheckUtf8(std::array<uint8_t, 4>{0xF0U, 0x9FU, 0x98U, 0x80U}), Reason::Ok);
  CHECK_EQ(der::CheckUtf8(std::array<uint8_t, 3>{0xE2U, 0x82U, 0xACU}), Reason::Ok);
  CHECK_EQ(der::CheckUtf8(std::array<uint8_t, 2>{0xC0U, 0xAFU}), Reason::BadString);
  CHECK_EQ(der::CheckUtf8(std::array<uint8_t, 3>{0xEDU, 0xA0U, 0x80U}), Reason::BadString);
  CHECK_EQ(der::CheckUtf8(std::array<uint8_t, 2>{0xE2U, 0x82U}), Reason::BadString);
  CHECK_EQ(der::CheckUtf8(std::array<uint8_t, 4>{0xF4U, 0x90U, 0x80U, 0x80U}), Reason::BadString);
  CHECK_EQ(der::CheckUtf8(std::array<uint8_t, 1>{0x80U}), Reason::BadString);
  CHECK_EQ(der::CheckUtf8(std::array<uint8_t, 2>{0xC3U, 0x29U}), Reason::BadString);
  CHECK_EQ(der::CheckUtf8(std::array<uint8_t, 1>{0x00U}), Reason::BadString);
  CHECK_EQ(der::CheckUtf8(std::array<uint8_t, 1>{0xF8U}), Reason::BadString);
}

TEST_CASE("PKI DER: UTCTime and GeneralizedTime in the RFC 5280 form") {
  Time t{};
  // "250601123456Z"
  CHECK_EQ(TimeOf(std::array<uint8_t, 13>{0x32U, 0x35U, 0x30U, 0x36U, 0x30U, 0x31U, 0x31U, 0x32U,
                                          0x33U, 0x34U, 0x35U, 0x36U, 0x5AU},
                  der::kUtcTime, t),
           Reason::Ok);
  CHECK_EQ(t.year, 2025U);
  CHECK_EQ(t.month, 6U);
  CHECK_EQ(t.day, 1U);
  CHECK_EQ(t.hour, 12U);
  CHECK_EQ(t.minute, 34U);
  CHECK_EQ(t.second, 56U);
  // "491231235959Z" is 2049, "500101000000Z" is 1950
  CHECK_EQ(TimeOf(std::array<uint8_t, 13>{0x34U, 0x39U, 0x31U, 0x32U, 0x33U, 0x31U, 0x32U, 0x33U,
                                          0x35U, 0x39U, 0x35U, 0x39U, 0x5AU},
                  der::kUtcTime, t),
           Reason::Ok);
  CHECK_EQ(t.year, 2049U);
  CHECK_EQ(TimeOf(std::array<uint8_t, 13>{0x35U, 0x30U, 0x30U, 0x31U, 0x30U, 0x31U, 0x30U, 0x30U,
                                          0x30U, 0x30U, 0x30U, 0x30U, 0x5AU},
                  der::kUtcTime, t),
           Reason::Ok);
  CHECK_EQ(t.year, 1950U);
  // "20550229000000Z" is not a date; "20560229000000Z" is
  CHECK_EQ(TimeOf(std::array<uint8_t, 15>{0x32U, 0x30U, 0x35U, 0x35U, 0x30U, 0x32U, 0x32U, 0x39U,
                                          0x30U, 0x30U, 0x30U, 0x30U, 0x30U, 0x30U, 0x5AU},
                  der::kGeneralizedTime, t),
           Reason::BadTime);
  CHECK_EQ(TimeOf(std::array<uint8_t, 15>{0x32U, 0x30U, 0x35U, 0x36U, 0x30U, 0x32U, 0x32U, 0x39U,
                                          0x30U, 0x30U, 0x30U, 0x30U, 0x30U, 0x30U, 0x5AU},
                  der::kGeneralizedTime, t),
           Reason::Ok);
  CHECK_EQ(t.year, 2056U);
}

TEST_CASE("PKI DER: malformed times are refused") {
  Time t{};
  // no Z, a letter, hour 24, a fraction, the wrong tag
  CHECK_EQ(TimeOf(std::array<uint8_t, 13>{0x32U, 0x35U, 0x30U, 0x36U, 0x30U, 0x31U, 0x31U, 0x32U,
                                          0x33U, 0x34U, 0x35U, 0x36U, 0x30U},
                  der::kUtcTime, t),
           Reason::BadTime);
  CHECK_EQ(TimeOf(std::array<uint8_t, 13>{0x32U, 0x35U, 0x30U, 0x36U, 0x30U, 0x41U, 0x31U, 0x32U,
                                          0x33U, 0x34U, 0x35U, 0x36U, 0x5AU},
                  der::kUtcTime, t),
           Reason::BadTime);
  CHECK_EQ(TimeOf(std::array<uint8_t, 13>{0x32U, 0x35U, 0x30U, 0x36U, 0x30U, 0x31U, 0x32U, 0x34U,
                                          0x30U, 0x30U, 0x30U, 0x30U, 0x5AU},
                  der::kUtcTime, t),
           Reason::BadTime);
  CHECK_EQ(
      TimeOf(std::array<uint8_t, 17>{0x32U, 0x30U, 0x35U, 0x35U, 0x30U, 0x31U, 0x30U, 0x31U, 0x30U,
                                     0x30U, 0x30U, 0x30U, 0x30U, 0x30U, 0x2EU, 0x35U, 0x5AU},
             der::kGeneralizedTime, t),
      Reason::BadTime);
  CHECK_EQ(TimeOf(std::array<uint8_t, 13>{0x32U, 0x35U, 0x30U, 0x36U, 0x30U, 0x31U, 0x31U, 0x32U,
                                          0x33U, 0x34U, 0x35U, 0x36U, 0x5AU},
                  der::kGeneralizedTime, t),
           Reason::BadTime);
  CHECK_EQ(TimeOf(std::array<uint8_t, 1>{0x5AU}, der::kOctetString, t), Reason::UnexpectedTag);
}

TEST_CASE("PKI DER: ECDSA-Sig-Value into r || s, and its refusals") {
  std::array<uint8_t, 64> raw{};
  // r = 0x80 (needs a 0x00 pad), s = 1
  const std::array<uint8_t, 9> ok{0x30U, 0x07U, 0x02U, 0x02U, 0x00U, 0x80U, 0x02U, 0x01U, 0x01U};
  CHECK_EQ(der::ParseEcdsaSignature(ByteSpan{ok}, 32U, MutableByteSpan{raw}), Reason::Ok);
  CHECK_EQ(raw[31], 0x80U);
  CHECK_EQ(raw[63], 0x01U);
  CHECK_EQ(raw[0], 0x00U);
  const std::array<uint8_t, 8> zero{0x30U, 0x06U, 0x02U, 0x01U, 0x00U, 0x02U, 0x01U, 0x01U};
  CHECK_EQ(der::ParseEcdsaSignature(ByteSpan{zero}, 32U, MutableByteSpan{raw}),
           Reason::BadSignatureValue);
  const std::array<uint8_t, 8> neg{0x30U, 0x06U, 0x02U, 0x01U, 0x81U, 0x02U, 0x01U, 0x01U};
  CHECK_EQ(der::ParseEcdsaSignature(ByteSpan{neg}, 32U, MutableByteSpan{raw}),
           Reason::BadSignatureValue);
  const std::array<uint8_t, 10> trailing{0x30U, 0x06U, 0x02U, 0x01U, 0x01U,
                                         0x02U, 0x01U, 0x01U, 0x00U, 0x00U};
  CHECK_EQ(der::ParseEcdsaSignature(ByteSpan{trailing}, 32U, MutableByteSpan{raw}),
           Reason::BadSignatureValue);
  std::array<uint8_t, 40> wide{0x30U, 0x26U, 0x02U, 0x21U, 0x01U};
  wide[37] = 0x02U;
  wide[38] = 0x01U;
  wide[39] = 0x01U;
  CHECK_EQ(der::ParseEcdsaSignature(ByteSpan{wide}, 32U, MutableByteSpan{raw}),
           Reason::BadSignatureValue);
  CHECK_EQ(der::ParseEcdsaSignature(ByteSpan{ok}, 32U, MutableByteSpan{raw}.first(63U)),
           Reason::BadSignatureValue);
}

TEST_CASE("PKI DER: the writer picks the shortest length and moves content when it grows") {
  for (const std::size_t n : {std::size_t{0U}, std::size_t{127U}, std::size_t{128U},
                              std::size_t{255U}, std::size_t{256U}, std::size_t{300U}}) {
    std::array<uint8_t, 320> buf{};
    der::Writer w(MutableByteSpan{buf});
    w.Begin(der::kSequence);
    for (std::size_t i = 0U; i < n; ++i) {
      w.Byte(static_cast<uint8_t>(i & 0xFFU));
    }
    w.End();
    const Result<std::size_t> r = w.Finish();
    REQUIRE(r.ok());
    CHECK_EQ(r.value, 1U + der::LengthFieldSize(n) + n);
    der::Element e{};
    der::Reader reader(ByteSpan{buf}.first(r.value));
    CHECK_EQ(reader.Next(e), Reason::Ok);
    CHECK_EQ(e.value.size(), n);
    if (n != 0U) {
      CHECK_EQ(e.value[n - 1U], static_cast<uint8_t>((n - 1U) & 0xFFU));
      CHECK_EQ(e.value[0], 0U);
    }
    CHECK(der::SameBytes(w.LastClosed(), ByteSpan{buf}.first(r.value)));
  }
}

TEST_CASE("PKI DER: the writer's INTEGER, BOOLEAN and named bits are DER") {
  std::array<uint8_t, 64> buf{};
  der::Writer w(MutableByteSpan{buf});
  w.Integer(std::array<uint8_t, 3>{0x00U, 0x00U, 0x01U});                            // 02 01 01
  w.Integer(std::array<uint8_t, 1>{0x80U});                                          // 02 02 00 80
  w.Integer(ByteSpan{});                                                             // 02 01 00
  w.Small(256U);                                                                     // 02 02 01 00
  w.Boolean(true);                                                                   // 01 01 FF
  w.NamedBits(key_usage::kDigitalSignature);                                         // 03 02 07 80
  w.NamedBits(static_cast<uint16_t>(key_usage::kKeyCertSign | key_usage::kCrlSign)); // 03 02 01 06
  w.NamedBits(key_usage::kDecipherOnly); // 03 03 07 00 80
  const Result<std::size_t> r = w.Finish();
  REQUIRE(r.ok());
  const std::array<uint8_t, 30> expected{0x02U, 0x01U, 0x01U, 0x02U, 0x02U, 0x00U, 0x80U, 0x02U,
                                         0x01U, 0x00U, 0x02U, 0x02U, 0x01U, 0x00U, 0x01U, 0x01U,
                                         0xFFU, 0x03U, 0x02U, 0x07U, 0x80U, 0x03U, 0x02U, 0x01U,
                                         0x06U, 0x03U, 0x03U, 0x07U, 0x00U, 0x80U};
  CHECK(der::SameBytes(ByteSpan{buf}.first(r.value), ByteSpan{expected}));
}

TEST_CASE("PKI DER: writer errors latch: buffer, depth, open elements, bad input") {
  std::array<uint8_t, 4> small{};
  der::Writer a(MutableByteSpan{small});
  a.Primitive(der::kOctetString, std::array<uint8_t, 3>{1U, 2U, 3U});
  CHECK_EQ(a.Status(), Reason::BufferTooSmall);
  CHECK_EQ(a.Finish().error, Error::BufferTooSmall);
  std::array<uint8_t, 64> buf{};
  der::Writer b(MutableByteSpan{buf});
  for (std::size_t i = 0U; i <= der::kMaxDepth; ++i) {
    b.Begin(der::kSequence);
  }
  CHECK_EQ(b.Status(), Reason::TooDeep);
  der::Writer c(MutableByteSpan{buf});
  c.Begin(der::kSequence);
  CHECK_EQ(ReasonOf(c.Finish().detail), Reason::InvalidInput);
  der::Writer d(MutableByteSpan{buf});
  d.End();
  CHECK_EQ(d.Status(), Reason::InvalidInput);
  der::Writer e(MutableByteSpan{buf});
  e.Oid(std::array<uint8_t, 1>{0x80U});
  e.NamedBits(0U);
  CHECK_EQ(e.Status(), Reason::BadOid);
  std::array<uint8_t, 130> grow{};
  der::Writer f(MutableByteSpan{grow});
  f.Begin(der::kSequence);
  for (std::size_t i = 0U; i < 128U; ++i) {
    f.Byte(0U);
  }
  f.End(); // needs one more byte to move the content: none left
  CHECK_EQ(f.Status(), Reason::BufferTooSmall);
}

TEST_CASE("PKI time: Unix seconds, leap years and ordering") {
  CHECK_EQ(ToUnixSeconds(Time{1970U, 1U, 1U, 0U, 0U, 0U}), 0U);
  CHECK_EQ(ToUnixSeconds(Time{2000U, 1U, 1U, 0U, 0U, 0U}), 946684800U);
  CHECK_EQ(ToUnixSeconds(Time{2024U, 2U, 29U, 0U, 0U, 0U}), 1709164800U);
  CHECK_EQ(ToUnixSeconds(Time{2038U, 1U, 19U, 3U, 14U, 8U}), 2147483648U);
  CHECK_EQ(ToUnixSeconds(Time{1969U, 12U, 31U, 23U, 59U, 59U}), 0U);
  CHECK(IsLeapYear(2000U));
  CHECK(!IsLeapYear(2100U));
  CHECK(IsLeapYear(2024U));
  CHECK(!IsValid(Time{2100U, 2U, 29U, 0U, 0U, 0U}));
  CHECK(IsValid(Time{2000U, 2U, 29U, 0U, 0U, 0U}));
  CHECK(!IsValid(Time{2025U, 4U, 31U, 0U, 0U, 0U}));
  CHECK(!IsValid(Time{2025U, 1U, 1U, 0U, 0U, 60U}));
  CHECK_EQ(DaysInMonth(2025U, 13U), 0U);
  CHECK_EQ(Compare(Time{2025U, 1U, 1U, 0U, 0U, 1U}, Time{2025U, 1U, 1U, 0U, 0U, 0U}), 1);
  CHECK_EQ(Compare(Time{2025U, 1U, 1U, 0U, 0U, 0U}, Time{2025U, 2U, 1U, 0U, 0U, 0U}), -1);
  CHECK_EQ(Compare(Time{2025U, 1U, 1U, 0U, 0U, 0U}, Time{2025U, 1U, 1U, 0U, 0U, 0U}), 0);
}

TEST_CASE("PKI reasons: names, the coarse error and the round trip through Detail") {
  CHECK(der::SameBytes(ByteSpan{}, ByteSpan{}));
  CHECK_EQ(ErrorOf(Reason::Ok), Error::Ok);
  CHECK_EQ(ErrorOf(Reason::NonMinimalLength), Error::InvalidArgument);
  CHECK_EQ(ErrorOf(Reason::UnknownCriticalExtension), Error::Unsupported);
  CHECK_EQ(ErrorOf(Reason::CurveNotSupported), Error::Unsupported);
  CHECK_EQ(ErrorOf(Reason::NameMismatch), Error::AttestationInvalid);
  CHECK_EQ(ErrorOf(Reason::LeafIsCa), Error::AttestationInvalid);
  CHECK_EQ(ErrorOf(Reason::CurveNotSupported), Error::Unsupported);
  CHECK_EQ(ErrorOf(Reason::NoTime), Error::InvalidArgument);
  CHECK_EQ(ErrorOf(Reason::ObjectTooLarge), Error::BufferTooSmall);
  CHECK_EQ(ErrorOf(Reason::SignerFailed), Error::CryptoFailure);
  const Result<int> r = Fail<int>(Reason::Expired);
  CHECK_EQ(r.error, Error::AttestationInvalid);
  CHECK_EQ(r.detail.layer, Layer::Pki);
  CHECK_EQ(ReasonOf(r.detail), Reason::Expired);
  CHECK_EQ(ReasonOf(Detail{}), Reason::Ok);
  Detail bad{};
  bad.layer = Layer::Pki;
  bad.step = 0xF0U;
  CHECK_EQ(ReasonOf(bad), Reason::Ok);
  CHECK(ToString(Reason::Expired) == pki::detail::kReasonNames[30]);
  // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange): a value that is no enumerator
  CHECK(ToString(static_cast<Reason>(200U)) != ToString(Reason::Ok));
}
