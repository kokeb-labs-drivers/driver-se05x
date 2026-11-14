/**
 * @file test_apdu_tlv.cpp
 * @brief The TLV writer and reader, the response split and the command framing (ISO 7816-4
 * cases 1 to 4, short and extended; AN12543 4.1).
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <array>
#include <cstddef>
#include <cstdint>

#include "test_apdu_util.hpp"

namespace {

using se05x::ByteSpan;
using se05x::Error;
using se05x::MutableByteSpan;
using se05x::apdu::TlvReader;
using se05x::apdu::TlvWriter;
using se05x::apdu::detail::CommandWriter;

} // namespace

TEST_CASE("TlvWriter uses the three BER length forms at 0x7F, 0x80, 0xFF and 0x100") {
  std::array<uint8_t, 300> value{};
  std::array<uint8_t, 600> out{};
  TlvWriter w(MutableByteSpan{out});
  CHECK(w.Put(0x41U, ByteSpan{value.data(), 0x7FU}).ok());
  CHECK_EQ(out[1], 0x7FU);
  CHECK_EQ(w.Size(), 0x81U);
  TlvWriter w2(MutableByteSpan{out});
  CHECK(w2.Put(0x42U, ByteSpan{value.data(), 0x80U}).ok());
  CHECK(tu::Prefix(ByteSpan{out}, 3U, "42 81 80"));
  CHECK_EQ(w2.Size(), 3U + 0x80U);
  TlvWriter w3(MutableByteSpan{out});
  CHECK(w3.Put(0x43U, ByteSpan{value.data(), 0xFFU}).ok());
  CHECK(tu::Prefix(ByteSpan{out}, 3U, "43 81 FF"));
  TlvWriter w4(MutableByteSpan{out});
  CHECK(w4.Put(0x44U, ByteSpan{value.data(), 0x100U}).ok());
  CHECK(tu::Prefix(ByteSpan{out}, 4U, "44 82 01 00"));
  CHECK_EQ(w4.Size(), 4U + 0x100U);
}

TEST_CASE("TlvWriter writes big-endian integers and latches the first overflow") {
  std::array<uint8_t, 13> out{};
  TlvWriter w(MutableByteSpan{out});
  CHECK(w.PutU8(0x41U, 0xA5U).ok());
  CHECK(w.PutU16(0x42U, 0x1234U).ok());
  CHECK(w.PutU32(0x43U, 0x7FFF0201U).ok());
  CHECK(tu::Same(ByteSpan{out}, tu::Hex("41 01 A5 42 02 12 34 43 04 7F FF 02 01").View()));
  CHECK_EQ(w.Size(), 13U);
  CHECK_EQ(w.PutU8(0x44U, 1U).error, Error::BufferTooSmall);
  CHECK_EQ(w.Size(), 13U);
  std::array<uint8_t, 3> small{};
  TlvWriter z(MutableByteSpan{small});
  CHECK_EQ(z.PutU16(0x41U, 1U).error, Error::BufferTooSmall); // needs 4
  CHECK_EQ(z.Size(), 0U);
  CHECK(z.PutU8(0x41U, 1U).error == Error::BufferTooSmall); // latched
}

TEST_CASE("TlvWriter fits an element that fills the buffer exactly, then refuses the next") {
  std::array<uint8_t, 4> out{};
  TlvWriter w(MutableByteSpan{out});
  CHECK(w.PutU16(0x41U, 0xBEEFU).ok());
  CHECK_EQ(w.Size(), 4U);
  CHECK(!w.PutU8(0x42U, 0U).ok());
  CHECK(!w.Put(0x43U, ByteSpan{}).ok()); // latched even for an element that would fit
}

TEST_CASE("TlvReader reads the three length forms and refuses others") {
  const tu::Bytes b = tu::Hex("41 01 AA 42 81 02 BB CC 43 82 00 01 DD");
  TlvReader r(b.View());
  const auto t1 = r.Next();
  const auto t2 = r.Next();
  const auto t3 = r.Next();
  REQUIRE(t1.ok() && t2.ok() && t3.ok());
  CHECK_EQ(t1.value.tag, 0x41U);
  CHECK_EQ(t2.value.value.size(), 2U);
  CHECK_EQ(t2.value.value[1], 0xCCU);
  CHECK_EQ(t3.value.value.size(), 1U);
  CHECK_EQ(t3.value.value[0], 0xDDU);
  CHECK(r.AtEnd());
  CHECK_EQ(r.Next().error, Error::FrameError);
  for (const char* bad : {"41 80", "41 83 00 00 01 00", "41 84 00 00 00 01 00", "41 FF"}) {
    const tu::Bytes b2 = tu::Hex(bad);
    TlvReader x(b2.View());
    CHECK_EQ(x.Next().error, Error::FrameError);
  }
}

TEST_CASE("TlvReader refuses a value that runs past the buffer and does not consume it") {
  for (const char* bad : {"41", "41 02 AA", "41 81", "41 81 02 AA", "41 82 00", "41 82 00 02 AA"}) {
    const tu::Bytes b = tu::Hex(bad);
    TlvReader r(b.View());
    CHECK_EQ(r.Next().error, Error::FrameError);
    CHECK(!r.AtEnd() || (b.n == 0U));
  }
  const tu::Bytes exact = tu::Hex("41 82 00 02 AA BB");
  TlvReader ok(exact.View());
  CHECK(ok.Next().ok());
  CHECK(ok.AtEnd());
}

TEST_CASE("TlvReader::Expect refuses another tag without consuming it") {
  const tu::Bytes b = tu::Hex("42 01 00 41 00");
  TlvReader r(b.View());
  CHECK_EQ(r.Expect(0x41U).error, Error::FrameError);
  CHECK(r.Expect(0x42U).ok());
  const auto empty = r.Expect(0x41U);
  CHECK(empty.ok());
  CHECK(empty.value.value.empty());
  CHECK(r.AtEnd());
}

TEST_CASE("SplitResponse separates the status word and refuses fewer than two bytes") {
  const tu::Bytes full = tu::Hex("41 01 07 90 00");
  const auto r = se05x::apdu::SplitResponse(full.View());
  REQUIRE(r.ok());
  CHECK_EQ(r.value.sw, 0x9000U);
  CHECK_EQ(r.value.body.size(), 3U);
  const tu::Bytes bare = tu::Hex("6A 82");
  const auto sw_only = se05x::apdu::SplitResponse(bare.View());
  CHECK(sw_only.ok());
  CHECK_EQ(sw_only.value.sw, 0x6A82U);
  CHECK(sw_only.value.body.empty());
  CHECK_EQ(se05x::apdu::SplitResponse(tu::Hex("90").View()).error, Error::FrameError);
  CHECK_EQ(se05x::apdu::SplitResponse(ByteSpan{}).error, Error::FrameError);
}

TEST_CASE("CommandWriter frames ISO cases 1 to 4, short") {
  std::array<uint8_t, 64> out{};
  CommandWriter c1(MutableByteSpan{out}, 0x80U, 0x04U, 0x00U, 0x1CU);
  const auto r1 = c1.Finish();
  CHECK(r1.ok() && tu::Prefix(ByteSpan{out}, r1.value, "80 04 00 1C"));
  CommandWriter c2(MutableByteSpan{out}, 0x80U, 0x04U, 0x00U, 0x20U);
  c2.ExpectResponse(11U);
  const auto r2 = c2.Finish();
  CHECK(r2.ok() && tu::Prefix(ByteSpan{out}, r2.value, "80 04 00 20 00"));
  CommandWriter c3(MutableByteSpan{out}, 0x80U, 0x04U, 0x00U, 0x28U);
  c3.TlvU32(0x41U, 0x00000100U);
  const auto r3 = c3.Finish();
  CHECK(r3.ok() && tu::Prefix(ByteSpan{out}, r3.value, "80 04 00 28 06 41 04 00 00 01 00"));
  CommandWriter c4(MutableByteSpan{out}, 0x80U, 0x04U, 0x00U, 0x1BU);
  c4.TlvU32(0x41U, 0x7FFF0201U);
  c4.ExpectResponse(256U);
  const auto r4 = c4.Finish();
  CHECK(r4.ok() && tu::Prefix(ByteSpan{out}, r4.value, "80 04 00 1B 06 41 04 7F FF 02 01 00"));
}

TEST_CASE("CommandWriter goes extended above 255 data bytes or 256 response bytes") {
  std::array<uint8_t, 300> out{};
  CommandWriter e2(MutableByteSpan{out}, 0x80U, 0x02U, 0x00U, 0x25U);
  e2.ExpectResponse(257U);
  const auto r2 = e2.Finish();
  CHECK(r2.ok() && tu::Prefix(ByteSpan{out}, r2.value, "80 02 00 25 00 00 00"));
  CommandWriter e4(MutableByteSpan{out}, 0x80U, 0x02U, 0x00U, 0x00U);
  e4.TlvU32(0x41U, 0x10U);
  e4.ExpectResponse(257U);
  const auto r4 = e4.Finish();
  CHECK(r4.ok() &&
        tu::Prefix(ByteSpan{out}, r4.value, "80 02 00 00 00 00 06 41 04 00 00 00 10 00 00"));
  std::array<uint8_t, 252> data{};
  CommandWriter e3(MutableByteSpan{out}, 0x80U, 0x01U, 0x06U, 0x00U);
  e3.Tlv(0x44U, ByteSpan{data}); // 2 + 252 = 254 bytes: short
  const auto s3 = e3.Finish();
  CHECK(s3.ok() && (s3.value == (5U + 255U)) && (out[4] == 0xFFU));
  std::array<uint8_t, 253> more{};
  CommandWriter x3(MutableByteSpan{out}, 0x80U, 0x01U, 0x06U, 0x00U);
  x3.Tlv(0x44U, ByteSpan{more}); // 3 + 253 = 256 bytes: extended Lc
  const auto l3 = x3.Finish();
  CHECK(l3.ok() && (l3.value == (7U + 256U)) &&
        tu::Prefix(ByteSpan{out}, 7U, "80 01 06 00 00 01 00"));
}

TEST_CASE("CommandWriter refuses a short buffer and wipes what it wrote") {
  std::array<uint8_t, 10> out{};
  CommandWriter w(MutableByteSpan{out}, 0x80U, 0x01U, 0x03U, 0x00U);
  w.TlvU32(0x41U, 0x100U);
  w.TlvU32(0x43U, 0x11223344U);
  const auto r = w.Finish();
  CHECK_EQ(r.error, Error::BufferTooSmall);
  bool zero = true;
  for (const uint8_t v : out) {
    zero = zero && (v == 0U);
  }
  CHECK(zero);
  std::array<uint8_t, 3> tiny{};
  CommandWriter t(MutableByteSpan{tiny}, 0x80U, 0x04U, 0x00U, 0x1CU);
  CHECK_EQ(t.Finish().error, Error::BufferTooSmall);
  std::array<uint8_t, 4> four{};
  CommandWriter f(MutableByteSpan{four}, 0x80U, 0x04U, 0x00U, 0x1CU);
  CHECK(f.Finish().ok());
  CommandWriter g(MutableByteSpan{four}, 0x80U, 0x04U, 0x00U, 0x20U);
  g.ExpectResponse(1U);
  CHECK_EQ(g.Finish().error, Error::BufferTooSmall);
}

TEST_CASE("CommandWriter refuses a data field above 1024 bytes and an argument error") {
  std::array<uint8_t, 1100> out{};
  std::array<uint8_t, 1021> big{};
  CommandWriter w(MutableByteSpan{out}, 0x80U, 0x01U, 0x06U, 0x00U);
  w.Tlv(0x44U, ByteSpan{big}.first(1020U)); // a 4 + 1020 = 1024-byte data field: fits
  w.ExpectResponse(0x200U);                 // with an extended Le: 4 + 3 + 1024 + 2 = 1033
  const auto fits = w.Finish();
  CHECK(fits.ok());
  CHECK_EQ(fits.value, se05x::kMaxPlainCommandApdu);
  CommandWriter x(MutableByteSpan{out}, 0x80U, 0x01U, 0x06U, 0x00U);
  x.Tlv(0x44U, ByteSpan{big}); // 1025 bytes, no Le: 1032 would fit the APDU, not the buffer
  CHECK_EQ(x.Finish().error, Error::InvalidArgument);
  CommandWriter y(MutableByteSpan{out}, 0x80U, 0x01U, 0x06U, 0x00U);
  y.Refuse(Error::Unsupported);
  y.Refuse(Error::InvalidArgument); // the first error stays
  CHECK_EQ(y.Finish().error, Error::Unsupported);
  CommandWriter z(MutableByteSpan{out}, 0x80U, 0x01U, 0x06U, 0x00U);
  z.TlvUint(0x43U, 0x100U, 1U); // does not fit one byte
  CHECK_EQ(z.Finish().error, Error::InvalidArgument);
}

TEST_CASE("CommandWriter reverses an Edwards value and writes a counter width") {
  std::array<uint8_t, 32> out{};
  const tu::Bytes v = tu::Hex("01 02 03");
  CommandWriter w(MutableByteSpan{out}, 0x80U, 0x01U, 0x01U, 0x00U);
  w.TlvReversed(0x44U, v.View());
  w.TlvUint(0x43U, 0x0102U, 8U);
  const auto r = w.Finish();
  CHECK(r.ok() && tu::Prefix(ByteSpan{out}, r.value,
                             "80 01 01 00 0F 44 03 03 02 01 43 08 00 00 00 00 00 00 01 02"));
}
