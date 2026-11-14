/**
 * @file test_apdu_codec_misc.cpp
 * @brief The codecs of the groups Desfire and I2cm, byte for byte against AN12543 sections 4.16
 * (P2 values of Table 29) and 4.18 (the command set of Figure 21, vector V6); and the coverage of
 * the codec set: every one of the 105 commands has a specialisation.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <array>
#include <cstdint>
#include <utility>

#include "test_apdu_util.hpp"

namespace {

using se05x::ByteSpan;
using se05x::Command;
using se05x::DfArgs;
using se05x::Error;
using se05x::MutableByteSpan;
using se05x::ObjectId;

constexpr ObjectId kKey{0x00000100U};
constexpr ObjectId kTarget{0x00000200U};
constexpr const char* k16 = "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F";

template <std::size_t... I>
constexpr bool AllImplemented(std::index_sequence<I...> /*unused*/) {
  return (se05x::Codec<static_cast<Command>(static_cast<uint8_t>(I))>::kImplemented && ...);
}
static_assert(AllImplemented(std::make_index_sequence<se05x::kCommandCount>{}),
              "every command has a codec");

template <std::size_t... I>
constexpr std::size_t BufferCodecs(std::index_sequence<I...> /*unused*/) {
  return (static_cast<std::size_t>(
              se05x::Codec<static_cast<Command>(static_cast<uint8_t>(I))>::kWritesCallerBuffers) +
          ...);
}

} // namespace

TEST_CASE("Every command has a codec; the two-argument Decode refuses the buffer commands") {
  CHECK_EQ(BufferCodecs(std::make_index_sequence<se05x::kCommandCount>{}), 41U);
  se05x::LengthReply n{};
  CHECK_EQ(se05x::Codec<Command::DfAuthenticateFirstPart1>::Decode(ByteSpan{}, n).error,
           Error::InvalidArgument);
  se05x::Empty e{};
  CHECK_EQ(se05x::Codec<Command::DfKillAuthentication>::Decode(ByteSpan{}, e).error, Error::Ok);
}

TEST_CASE("DESFire diversify and authenticate first: P2 10, 53 and 12 (Table 29)") {
  const tu::Bytes div = tu::Hex("A1 A2 A3");
  CHECK(tu::EncodesTo<Command::DfDiversifyKey>(
      {kKey, kTarget, div.View(), MutableByteSpan{}},
      "80 03 00 10 11 41 04 00 00 01 00 42 04 00 00 02 00 43 03 A1 A2 A3"));
  std::array<uint8_t, 32> d32{};
  const tu::Bytes long_div =
      tu::Hex("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 "
              "17 18 19 1A 1B 1C 1D 1E 1F");
  CHECK_EQ(
      tu::EncodeError<Command::DfDiversifyKey>({kKey, kTarget, long_div.View(), MutableByteSpan{}}),
      Error::InvalidArgument);
  CHECK(tu::EncodeError<Command::DfDiversifyKey>(
            {kKey, kTarget, long_div.View().first(31U), MutableByteSpan{}}) == Error::Ok);
  CHECK_EQ(
      tu::EncodeError<Command::DfDiversifyKey>({kKey, ObjectId{}, div.View(), MutableByteSpan{}}),
      Error::InvalidArgument);
  const tu::Bytes rnd = tu::Hex(k16);
  const DfArgs p1{kKey, ObjectId{}, rnd.View(), MutableByteSpan{d32}};
  CHECK(tu::EncodesTo<Command::DfAuthenticateFirstPart1>(
      p1,
      "80 03 00 53 18 41 04 00 00 01 00 42 10 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 00"));
  se05x::LengthReply n{};
  const tu::Bytes ans =
      tu::Hex("41 20 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 "
              "16 17 18 19 1A 1B 1C 1D 1E 1F");
  CHECK(se05x::Codec<Command::DfAuthenticateFirstPart1>::Decode(p1, ans.View(), n).ok());
  CHECK_EQ(n.length, 32U);
  CHECK_EQ(
      se05x::Codec<Command::DfAuthenticateFirstPart1>::Decode(p1, ans.View().first(33U), n).error,
      Error::FrameError);
  const DfArgs with_target{kKey, kTarget, rnd.View(), MutableByteSpan{d32}};
  CHECK_EQ(tu::EncodeError<Command::DfAuthenticateFirstPart1>(with_target), Error::InvalidArgument);
  std::array<uint8_t, 12> caps{};
  const DfArgs p2{ObjectId{}, ObjectId{}, long_div.View(), MutableByteSpan{caps}};
  tu::CommandBuffer buf{};
  const auto r2 = se05x::Codec<Command::DfAuthenticateFirstPart2>::Encode(p2, MutableByteSpan{buf});
  CHECK(r2.ok() && (r2.value == 40U) && tu::Prefix(ByteSpan{buf}, 7U, "80 03 00 12 22 41 20"));
  CHECK_EQ(tu::Decode<Command::DfAuthenticateFirstPart2>(
               p2, "41 0C 01 02 03 04 05 06 07 08 09 0A 0B 0C", n),
           Error::Ok);
  CHECK_EQ(caps[11], 0x0CU);
}

TEST_CASE("DESFire authenticate non-first: P2 54 and 13 (Table 29, not Table 342)") {
  const tu::Bytes rnd = tu::Hex(k16);
  std::array<uint8_t, 32> d32{};
  CHECK(tu::EncodesTo<Command::DfAuthenticateNonFirstPart1>(
      {kKey, ObjectId{}, rnd.View(), MutableByteSpan{d32}},
      "80 03 00 54 18 41 04 00 00 01 00 42 10 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 00"));
  const DfArgs p2{ObjectId{}, ObjectId{}, rnd.View(), MutableByteSpan{}};
  CHECK(tu::EncodesTo<Command::DfAuthenticateNonFirstPart2>(
      p2, "80 03 00 13 12 41 10 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"));
  se05x::LengthReply n{};
  CHECK_EQ(tu::Decode<Command::DfAuthenticateNonFirstPart2>(p2, "", n), Error::Ok);
  CHECK_EQ(tu::Decode<Command::DfAuthenticateNonFirstPart2>(p2, "41 00", n), Error::FrameError);
  CHECK_EQ(tu::EncodeError<Command::DfAuthenticateNonFirstPart2>(
               {ObjectId{}, ObjectId{}, rnd.View().first(15U), MutableByteSpan{}}),
           Error::InvalidArgument);
}

TEST_CASE("DESFire dump, change key both parts and kill (Tables 289 to 298)") {
  std::array<uint8_t, 38> keys{};
  const DfArgs dump{ObjectId{}, ObjectId{}, ByteSpan{}, MutableByteSpan{keys}};
  CHECK(tu::EncodesTo<Command::DfDumpSessionKeys>(dump, "80 03 00 14 00"));
  CHECK_EQ(tu::EncodeError<Command::DfDumpSessionKeys>(
               {ObjectId{}, ObjectId{}, ByteSpan{}, MutableByteSpan{keys}.first(37U)}),
           Error::InvalidArgument);
  std::array<uint8_t, 32> crypt{};
  const tu::Bytes plain = tu::Hex("05 01");
  CHECK(tu::EncodesTo<Command::DfChangeKeyPart1>(
      {ObjectId{}, kTarget, plain.View(), MutableByteSpan{crypt}},
      "80 03 00 15 0C 42 04 00 00 02 00 44 01 05 45 01 01 00"));
  const tu::Bytes with_set = tu::Hex("02 05 01");
  CHECK(tu::EncodesTo<Command::DfChangeKeyPart1>(
      {kKey, kTarget, with_set.View(), MutableByteSpan{crypt}},
      "80 03 00 15 15 41 04 00 00 01 00 42 04 00 00 02 00 43 01 02 44 01 05 45 01 01 00"));
  CHECK_EQ(tu::EncodeError<Command::DfChangeKeyPart1>(
               {kKey, kTarget, ByteSpan{}, MutableByteSpan{crypt}}),
           Error::InvalidArgument);
  const tu::Bytes mac = tu::Hex("01 02 03 04 05 06 07 08");
  const DfArgs p2{ObjectId{}, ObjectId{}, mac.View(), MutableByteSpan{}};
  CHECK(tu::EncodesTo<Command::DfChangeKeyPart2>(
      p2, "80 03 00 16 0A 41 08 01 02 03 04 05 06 07 08 00"));
  se05x::LengthReply n{};
  CHECK_EQ(tu::Decode<Command::DfChangeKeyPart2>(p2, "41 01 01", n), Error::Ok);
  CHECK_EQ(tu::Decode<Command::DfChangeKeyPart2>(p2, "41 01 02", n), Error::AuthFailed);
  CHECK(tu::EncodesTo<Command::DfKillAuthentication>({}, "80 03 00 17"));
  CHECK_EQ(tu::EncodeError<Command::DfKillAuthentication>(
               {kKey, ObjectId{}, ByteSpan{}, MutableByteSpan{}}),
           Error::InvalidArgument);
}

TEST_CASE("I2C controller: the command set of Figure 21 (V6), its structure check, attested form") {
  // CONFIGURE address 7E at 400 kHz, WRITE AA BB 00 02, READ 2 bytes (AN12543 Figure 21).
  const tu::Bytes set = tu::Hex("01 00 02 7E 01 03 00 04 AA BB 00 02 04 00 02 00 02");
  std::array<uint8_t, 16> out{};
  CHECK(tu::EncodesTo<Command::I2cmExecuteCommandSet>(
      {set.View(), MutableByteSpan{out}},
      "80 03 00 30 13 41 11 01 00 02 7E 01 03 00 04 AA BB 00 02 04 00 02 00 02 00"));
  se05x::LengthReply n{};
  CHECK_EQ(tu::Decode<Command::I2cmExecuteCommandSet>({set.View(), MutableByteSpan{out}},
                                                      "41 08 01 5A 03 5A 04 5A 00 02", n),
           Error::Ok);
  CHECK_EQ(n.length, 8U);
  for (const char* bad :
       {"04 00 02 00 02 01 00 02 7E 01", "01 00 03 7E 01 00", "05 00 00", "03 00 05 AA", "03 00",
        "03 00 01 AA 04 00 02 00 02",                   // CONFIGURE is not first (AN12543 p. 146)
        "01 00 02 7E 02 04 00 02 00 02",                // a clock byte other than 0x00 or 0x01
        "01 00 02 7E 01 01 00 02 7E 00",                // a second CONFIGURE
        "01 00 02 7E 01 04 00 02 00 02 03 00 01 AA"}) { // a READ that is not last
    const tu::Bytes b = tu::Hex(bad);
    CHECK_EQ(tu::EncodeError<Command::I2cmExecuteCommandSet>({b.View(), MutableByteSpan{out}}),
             Error::InvalidArgument);
  }
  std::array<uint8_t, 256> big{};
  big[0] = 0x01U; // CONFIGURE 0x7E at 100 kHz
  big[2] = 0x02U;
  big[3] = 0x7EU;
  big[5] = 0x03U;
  big[6] = 0x00U;
  big[7] = 0xF7U; // then one WRITE of 247 bytes: 255 bytes in all, the maximum
  CHECK(tu::EncodeError<Command::I2cmExecuteCommandSet>(
            {ByteSpan{big}.first(255U), MutableByteSpan{out}}) == Error::Ok);
  CHECK(tu::EncodeError<Command::I2cmExecuteCommandSet>(
            {ByteSpan{big}.first(5U), MutableByteSpan{out}}) == Error::Ok); // CONFIGURE alone
  big[7] = 0xF8U;                                                           // 256 bytes
  CHECK(tu::EncodeError<Command::I2cmExecuteCommandSet>(
            {ByteSpan{big}.first(256U), MutableByteSpan{out}}) == Error::InvalidArgument);
  std::array<uint8_t, 80> sig{};
  se05x::I2cmAttestedArgs a{};
  a.commands = set.View();
  a.attestation_key = ObjectId{0xF0000012U};
  a.data_out = MutableByteSpan{out};
  a.signature_out = MutableByteSpan{sig};
  CHECK(tu::EncodesTo<Command::I2cmExecuteCommandSetAttested>(
      a, "80 23 00 30 00 00 2E 41 11 01 00 02 7E 01 03 00 04 AA BB 00 02 04 00 02 00 02 42 04 F0 "
         "00 00 12 "
         "43 01 21 47 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"));
}
