/**
 * @file test_apdu_codec_objects.cpp
 * @brief The codecs of the groups ObjectWrite, ObjectRead, Curve and CryptoObject, byte for byte
 * against AN12543 sections 4.7 to 4.9, with the Edwards and Montgomery byte order of section 7
 * checked with the RFC 8032 and RFC 7748 values of vectors V1 and V2.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <array>
#include <cstdint>

#include "se05x_policy.hpp"
#include "test_apdu_util.hpp"

namespace {

using se05x::AppletGeneration;
using se05x::ByteSpan;
using se05x::Command;
using se05x::EcCurve;
using se05x::Error;
using se05x::MutableByteSpan;
using se05x::ObjectClass;
using se05x::ObjectId;
using se05x::Rule;

constexpr ObjectId kId{0x00000100U};

/// One policy: `08 7FFF0001 10020000` (ALLOW_SIGN | REQUIRE_SM for 0x7FFF0001).
const se05x::Policy& TestPolicy() {
  static const se05x::Result<se05x::Policy> kPolicy =
      se05x::PolicyBuilder<AppletGeneration::V7, ObjectClass::EcKeyPair>{}
          .For(se05x::AuthObject{ObjectId{0x7FFF0001U}})
          .Allow<Rule::Sign>()
          .RequireSecureMessaging()
          .Forbid<Rule::Write>()
          .Forbid<Rule::Delete>()
          .Forbid<Rule::Gen>()
          .Build();
  return kPolicy.value;
}

// RFC 8032 test 3 public key, RFC order, and its wire form (AN12543 Figure 22).
constexpr const char* kEdPublic = "FC 51 CD 8E 62 18 A1 A3 8D A4 7E D0 02 30 F0 58 08 16 ED 13 BA "
                                  "33 03 AC 5D EB 91 15 48 90 80 25";
constexpr const char* kEdPublicWire = "25 80 90 48 15 91 EB 5D AC 03 33 BA 13 ED 16 08 58 F0 30 02 "
                                      "D0 7E A4 8D A3 A1 18 62 8E CD 51 FC";
// RFC 8032 test 3 secret key: not reversed on the wire.
constexpr const char* kEdSecret = "C5 AA 8D F4 3F 9F 83 7B ED B7 44 2F 31 DC B7 B1 66 D3 85 35 07 "
                                  "6F 09 4B 85 CE 3A 2E 0B 44 58 F7";
// RFC 7748 Alice private key and its wire form (AN12543 Figure 23).
constexpr const char* kXPrivate = "77 07 6D 0A 73 18 A5 7D 3C 16 C1 72 51 B2 66 45 DF 4C 2F 87 EB "
                                  "C0 99 2A B1 77 FB A5 1D B9 2C 2A";
constexpr const char* kXPrivateWire = "2A 2C B9 1D A5 FB 77 B1 2A 99 C0 EB 87 2F 4C DF 45 66 B2 51 "
                                      "72 C1 16 3C 7D A5 18 73 0A 6D 07 77";

} // namespace

TEST_CASE("WriteEcKey: a P-256 public key, the policy first (AN12543 Table 115)") {
  CHECK(tu::Same(TestPolicy().Bytes(), tu::Hex("08 7F FF 00 01 10 02 00 00").View()));
  const tu::Bytes pub =
      tu::Hex("04 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 "
              "16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C "
              "2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F");
  se05x::WriteEcKeyArgs a{};
  a.id = kId;
  a.policy = &TestPolicy();
  a.curve = EcCurve::NistP256;
  a.public_key = pub.View();
  CHECK(tu::EncodesTo<Command::WriteEcKey>(
      a, "80 01 21 00 57 11 09 08 7F FF 00 01 10 02 00 00 41 04 00 00 01 00 42 01 03 44 41 04 00 "
         "01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D "
         "1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A "
         "3B 3C 3D 3E 3F"));
  a.public_key = pub.View().first(64U);
  CHECK_EQ(tu::EncodeError<Command::WriteEcKey>(a), Error::InvalidArgument);
  tu::Bytes compressed = pub;
  compressed.b[0] = 0x03U;
  a.public_key = compressed.View();
  CHECK_EQ(tu::EncodeError<Command::WriteEcKey>(a), Error::InvalidArgument);
}

TEST_CASE("WriteEcKey: Ed25519 reverses the public key, not the secret key (AN12543 7.1, V1)") {
  const tu::Bytes pub = tu::Hex(kEdPublic);
  const tu::Bytes secret = tu::Hex(kEdSecret);
  se05x::WriteEcKeyArgs a{};
  a.id = kId;
  a.policy = &TestPolicy();
  a.curve = EcCurve::Ed25519;
  a.public_key = pub.View();
  CHECK(tu::EncodesTo<Command::WriteEcKey>(
      a,
      "80 01 21 00 36 11 09 08 7F FF 00 01 10 02 00 00 41 04 00 00 01 00 42 01 40 44 20 25 80 90 "
      "48 15 91 EB 5D AC 03 33 BA 13 ED 16 08 58 F0 30 02 D0 7E A4 8D A3 A1 18 62 8E CD 51 FC"));
  a.private_key = secret.View();
  CHECK(tu::EncodesTo<Command::WriteEcKey>(
      a,
      "80 01 61 00 58 11 09 08 7F FF 00 01 10 02 00 00 41 04 00 00 01 00 42 01 40 43 20 C5 AA "
      "8D F4 3F 9F 83 7B ED B7 44 2F 31 DC B7 B1 66 D3 85 35 07 6F 09 4B 85 CE 3A 2E 0B 44 58 F7 "
      "44 20 25 80 90 48 15 91 EB 5D AC 03 33 BA 13 ED 16 08 58 F0 30 02 D0 7E A4 8D A3 A1 18 62 "
      "8E CD 51 FC"));
  static_cast<void>(kEdPublicWire);
}

TEST_CASE("WriteEcKey: X25519 reverses the private key (AN12543 7.2, V2); JOS.1 length checks") {
  const tu::Bytes priv = tu::Hex(kXPrivate);
  se05x::WriteEcKeyArgs a{};
  a.id = kId;
  a.policy = &TestPolicy();
  a.curve = EcCurve::Montgomery25519;
  a.private_key = priv.View();
  a.lifetime = se05x::Lifetime::TransientDeselect;
  CHECK(tu::EncodesTo<Command::WriteEcKey>(
      a,
      "80 81 41 00 36 11 09 08 7F FF 00 01 10 02 00 00 41 04 00 00 01 00 42 01 41 43 20 2A 2C B9 "
      "1D A5 FB 77 B1 2A 99 C0 EB 87 2F 4C DF 45 66 B2 51 72 C1 16 3C 7D A5 18 73 0A 6D 07 77"));
  static_cast<void>(kXPrivateWire);
  a.private_key = priv.View().first(31U);
  CHECK_EQ(tu::EncodeError<Command::WriteEcKey>(a), Error::InvalidArgument);
  a.curve = EcCurve::Secp160k1;
  a.private_key = priv.View().first(20U);
  CHECK_EQ(tu::EncodeError<Command::WriteEcKey>(a), Error::Unsupported);
  a.curve = EcCurve::NistP256;
  a.private_key = ByteSpan{};
  CHECK_EQ(tu::EncodeError<Command::WriteEcKey>(a), Error::InvalidArgument); // no key at all
  a.private_key = priv.View();
  a.policy = nullptr;
  CHECK_EQ(tu::EncodeError<Command::WriteEcKey>(a), Error::InvalidArgument);
  a.policy = &TestPolicy();
  a.id = ObjectId{0xF0000012U};
  CHECK_EQ(tu::EncodeError<Command::WriteEcKey>(a), Error::InvalidArgument); // NXP-provisioned
  a.id = kId;
  a.curve = tu::NotAnEnumerator<EcCurve>(20U);
  CHECK_EQ(tu::EncodeError<Command::WriteEcKey>(a), Error::InvalidArgument);
}

TEST_CASE("GenerateEcKey: P1 61, the curve, a transient object and a version") {
  se05x::GenerateEcKeyArgs g{kId, &TestPolicy(), EcCurve::NistP256, se05x::Lifetime::TransientReset,
                             5U};
  CHECK(tu::EncodesTo<Command::GenerateEcKey>(g, "80 81 61 00 1A 11 09 08 7F FF 00 01 10 02 00 00 "
                                                 "41 04 00 00 01 00 42 01 03 4B 04 00 00 00 05"));
  g.lifetime = se05x::Lifetime::Persistent;
  g.version = 0U;
  CHECK(tu::EncodesTo<Command::GenerateEcKey>(
      g, "80 01 61 00 14 11 09 08 7F FF 00 01 10 02 00 00 41 04 00 00 01 00 42 01 03"));
  g.version = 0x08000000U;
  CHECK_EQ(tu::EncodeError<Command::GenerateEcKey>(g), Error::InvalidArgument);
  g.version = 0x07FFFFFFU;
  CHECK(tu::EncodeError<Command::GenerateEcKey>(g) == Error::Ok);
  g.policy = nullptr;
  CHECK_EQ(tu::EncodeError<Command::GenerateEcKey>(g), Error::InvalidArgument);
}

TEST_CASE("WriteRsaKey: one component per APDU, P1 key type on the first only (AN12543 4.7.1.2)") {
  const tu::Bytes e = tu::Hex("00 01 00 01"); // a DER sign byte, stripped
  std::array<uint8_t, 64> n{};
  for (std::size_t i = 0U; i < n.size(); ++i) {
    n[i] = static_cast<uint8_t>(0xC0U + (i & 0x3FU));
  }
  se05x::WriteRsaKeyArgs a{};
  a.id = kId;
  a.policy = &TestPolicy();
  a.key_bits = 512U;
  a.parts.public_exponent = e.View();
  a.parts.modulus = ByteSpan{n};
  using Rsa = se05x::Codec<Command::WriteRsaKey>;
  CHECK_EQ(Rsa::Steps(a), 2U);
  CHECK(tu::EncodesTo<Command::WriteRsaKey>(a, "80 01 22 00 1A 11 09 08 7F FF 00 01 10 02 00 00 41 "
                                               "04 00 00 01 00 42 02 02 00 48 03 01 00 01"));
  tu::CommandBuffer buf{};
  const auto s1 = Rsa::Step(a, 1U, MutableByteSpan{buf});
  REQUIRE(s1.ok());
  CHECK(tu::Prefix(ByteSpan{buf}, 13U, "80 01 02 00 48 41 04 00 00 01 00 4A 40"));
  CHECK_EQ(s1.value, 5U + 0x48U);
  CHECK_EQ(buf[13], 0xC0U);
  CHECK_EQ(Rsa::Step(a, 2U, MutableByteSpan{buf}).error, Error::InvalidArgument);
  a.parts.private_exponent = ByteSpan{n};
  a.parts.public_exponent = ByteSpan{};
  const auto raw = Rsa::Step(a, 0U, MutableByteSpan{buf});
  CHECK(raw.ok() && tu::Prefix(ByteSpan{buf}, 4U, "80 01 42 4F")); // private, P2_RAW
  a.parts.private_exponent = ByteSpan{};
  CHECK_EQ(Rsa::Steps(a), 0U); // a modulus alone is not a key
  CHECK_EQ(tu::EncodeError<Command::WriteRsaKey>(a), Error::InvalidArgument);
  a.parts.public_exponent = e.View();
  a.parts.modulus = ByteSpan{n}.first(63U);
  CHECK_EQ(tu::EncodeError<Command::WriteRsaKey>(a), Error::InvalidArgument);
  a.parts.modulus = ByteSpan{n};
  a.key_bits = 2000U;
  CHECK_EQ(tu::EncodeError<Command::WriteRsaKey>(a), Error::InvalidArgument);
}

TEST_CASE("GenerateRsaKey: P1 62 and the size in bits") {
  CHECK(tu::EncodesTo<Command::GenerateRsaKey>(
      {kId, &TestPolicy(), 2048U, se05x::Lifetime::Persistent},
      "80 01 62 00 15 11 09 08 7F FF 00 01 10 02 00 00 41 04 00 00 01 00 42 02 08 00"));
  CHECK_EQ(tu::EncodeError<Command::GenerateRsaKey>(
               {kId, &TestPolicy(), 2047U, se05x::Lifetime::Persistent}),
           Error::InvalidArgument);
}

TEST_CASE("WriteSymmKey: AES plain and RFC 3394 wrapped, DES and HMAC lengths (Table 118)") {
  const tu::Bytes k16 = tu::Hex("00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF");
  se05x::WriteSymmKeyArgs a{};
  a.id = kId;
  a.policy = &TestPolicy();
  a.key = k16.View();
  CHECK(tu::EncodesTo<Command::WriteSymmKey>(
      a,
      "80 01 03 00 23 11 09 08 7F FF 00 01 10 02 00 00 41 04 00 00 01 00 43 10 00 11 22 33 44 55 "
      "66 77 88 99 AA BB CC DD EE FF"));
  const tu::Bytes w24 =
      tu::Hex("A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF B0 B1 B2 B3 B4 B5 B6 B7");
  a.kek = ObjectId{0x00000200U};
  a.key = w24.View();
  CHECK(tu::EncodesTo<Command::WriteSymmKey>(
      a,
      "80 01 03 00 31 11 09 08 7F FF 00 01 10 02 00 00 41 04 00 00 01 00 42 04 00 00 02 00 43 18 "
      "A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF B0 B1 B2 B3 B4 B5 B6 B7"));
  a.key = w24.View().first(20U);
  CHECK_EQ(tu::EncodeError<Command::WriteSymmKey>(a), Error::InvalidArgument);
  a.kek = ObjectId{};
  a.key = k16.View().first(15U);
  CHECK_EQ(tu::EncodeError<Command::WriteSymmKey>(a), Error::InvalidArgument);
  a.type = se05x::SymmKeyType::Des;
  a.key = k16.View().first(8U);
  CHECK(tu::EncodeError<Command::WriteSymmKey>(a) == Error::Ok);
  tu::CommandBuffer buf{};
  CHECK(se05x::Codec<Command::WriteSymmKey>::Encode(a, MutableByteSpan{buf}).ok() &&
        (buf[2] == 0x04U));
  a.type = se05x::SymmKeyType::Hmac;
  a.key = k16.View().first(1U);
  CHECK(se05x::Codec<Command::WriteSymmKey>::Encode(a, MutableByteSpan{buf}).ok() &&
        (buf[2] == 0x05U));
  std::array<uint8_t, 257> long_key{};
  a.key = ByteSpan{long_key};
  CHECK_EQ(tu::EncodeError<Command::WriteSymmKey>(a), Error::InvalidArgument);
  a.key = ByteSpan{long_key}.first(256U);
  CHECK(tu::EncodeError<Command::WriteSymmKey>(a) == Error::Ok);
}

TEST_CASE("WriteBinary: the data field fits the 1024-byte internal buffer (AN12543 2.2 p. 3)") {
  // An update: TAG_1 id (6) + TAG_2 offset (4) + TAG_4 with a three-byte length (4 + n) = n + 14.
  static std::array<uint8_t, 1011> big{};
  se05x::WriteBinaryArgs u{kId, nullptr, 0x0010U, ByteSpan{big}.first(1010U), 0U, 0U};
  CHECK(tu::EncodeError<Command::WriteBinary>(u) == Error::Ok); // a 1024-byte data field
  u.data = ByteSpan{big};
  CHECK_EQ(tu::EncodeError<Command::WriteBinary>(u), Error::InvalidArgument); // 1025 bytes
}

TEST_CASE("WriteBinary: creation with a policy and length, update without (Table 119)") {
  const tu::Bytes data = tu::Hex("DE AD BE EF");
  se05x::WriteBinaryArgs a{kId, &TestPolicy(), 0U, data.View(), 0x0100U, 0U};
  CHECK(tu::EncodesTo<Command::WriteBinary>(a, "80 01 06 00 1B 11 09 08 7F FF 00 01 10 02 00 00 41 "
                                               "04 00 00 01 00 43 02 01 00 44 04 DE AD BE EF"));
  const se05x::WriteBinaryArgs u{kId, nullptr, 0x0010U, data.View().first(2U), 0U, 0U};
  CHECK(tu::EncodesTo<Command::WriteBinary>(
      u, "80 01 06 00 0E 41 04 00 00 01 00 42 02 00 10 44 02 DE AD"));
  se05x::WriteBinaryArgs bad = u;
  bad.policy = &TestPolicy();
  CHECK_EQ(tu::EncodeError<Command::WriteBinary>(bad), Error::InvalidArgument);
  bad = a;
  bad.offset = 0x00FEU; // 0xFE + 4 > 0x100
  CHECK_EQ(tu::EncodeError<Command::WriteBinary>(bad), Error::InvalidArgument);
  bad.offset = 0x00FCU;
  CHECK(tu::EncodeError<Command::WriteBinary>(bad) == Error::Ok);
  bad = a;
  bad.file_length = 0x8000U;
  CHECK_EQ(tu::EncodeError<Command::WriteBinary>(bad), Error::InvalidArgument);
  bad = u;
  bad.data = ByteSpan{};
  CHECK_EQ(tu::EncodeError<Command::WriteBinary>(bad), Error::InvalidArgument);
}

TEST_CASE("WriteUserId: INS_AUTH_OBJECT, the attempt limit before the id (Table 120; S-14)") {
  const tu::Bytes secret = tu::Hex("01 02 03 04");
  se05x::WriteUserIdArgs a{kId, &TestPolicy(), secret.View(), 5U};
  CHECK(tu::EncodesTo<Command::WriteUserId>(a, "80 41 07 00 1B 11 09 08 7F FF 00 01 10 02 00 00 12 "
                                               "02 00 05 41 04 00 00 01 00 42 04 01 02 03 04"));
  a.max_attempts = 0U;
  CHECK_EQ(tu::EncodeError<Command::WriteUserId>(a), Error::InvalidArgument);
  a.max_attempts = 1U;
  a.user_secret = secret.View().first(3U);
  CHECK_EQ(tu::EncodeError<Command::WriteUserId>(a), Error::InvalidArgument);
}

TEST_CASE("WriteCounter: TAG_2 only without a value; IncrementCounter (Table 121)") {
  se05x::WriteCounterArgs c{kId, &TestPolicy(), 4U, 0U, false};
  CHECK(tu::EncodesTo<Command::WriteCounter>(
      c, "80 01 08 00 15 11 09 08 7F FF 00 01 10 02 00 00 41 04 00 00 01 00 42 02 00 04"));
  c = se05x::WriteCounterArgs{kId, &TestPolicy(), 2U, 7U, true};
  CHECK(tu::EncodesTo<Command::WriteCounter>(
      c, "80 01 08 00 15 11 09 08 7F FF 00 01 10 02 00 00 41 04 00 00 01 00 43 02 00 07"));
  c = se05x::WriteCounterArgs{kId, nullptr, 2U, 7U, true};
  CHECK(tu::EncodesTo<Command::WriteCounter>(c, "80 01 08 00 0A 41 04 00 00 01 00 43 02 00 07"));
  c.set_value = false;
  CHECK_EQ(tu::EncodeError<Command::WriteCounter>(c), Error::InvalidArgument);
  c = se05x::WriteCounterArgs{kId, nullptr, 1U, 0x100U, true};
  CHECK_EQ(tu::EncodeError<Command::WriteCounter>(c), Error::InvalidArgument);
  c.counter_bytes = 9U;
  CHECK_EQ(tu::EncodeError<Command::WriteCounter>(c), Error::InvalidArgument);
  CHECK(tu::EncodesTo<Command::IncrementCounter>({kId}, "80 01 08 00 06 41 04 00 00 01 00"));
}

TEST_CASE("WritePcr, ExtendPcr and WritePcrWithType (Table 122)") {
  std::array<uint8_t, 32> init{};
  init[31] = 0x01U;
  CHECK(tu::EncodesTo<Command::WritePcr>(
      {kId, &TestPolicy(), ByteSpan{init}},
      "80 01 09 00 33 11 09 08 7F FF 00 01 10 02 00 00 41 04 00 00 01 00 42 20 00 00 00 00 00 00 "
      "00 "
      "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01"));
  CHECK_EQ(tu::EncodeError<Command::WritePcr>({kId, &TestPolicy(), ByteSpan{init}.first(31U)}),
           Error::InvalidArgument);
  const tu::Bytes data = tu::Hex("AA BB CC");
  CHECK(tu::EncodesTo<Command::ExtendPcr>({kId, data.View()},
                                          "80 01 09 00 0B 41 04 00 00 01 00 43 03 AA BB CC"));
  CHECK_EQ(tu::EncodeError<Command::ExtendPcr>({kId, ByteSpan{}}), Error::InvalidArgument);
  tu::CommandBuffer buf{};
  const se05x::WritePcrTypedArgs t{kId, &TestPolicy(), ByteSpan{init},
                                   se05x::Lifetime::TransientDeselect};
  CHECK(se05x::Codec<Command::WritePcrWithType>::Encode(t, MutableByteSpan{buf}).ok());
  CHECK(tu::Prefix(ByteSpan{buf}, 4U, "80 81 09 00"));
}

TEST_CASE("ImportObject, ExportObject and ImportExternalObject (Tables 123, 124, 133)") {
  const tu::Bytes blob = tu::Hex("01 02 03");
  se05x::ImportObjectArgs i{kId, se05x::kNoRsaComponent, blob.View()};
  CHECK(tu::EncodesTo<Command::ImportObject>(i, "80 01 00 18 0B 41 04 00 00 01 00 43 03 01 02 03"));
  i.rsa_component = 3U;
  CHECK(tu::EncodesTo<Command::ImportObject>(
      i, "80 01 00 18 0E 41 04 00 00 01 00 42 01 03 43 03 01 02 03"));
  i.rsa_component = 8U;
  CHECK_EQ(tu::EncodeError<Command::ImportObject>(i), Error::InvalidArgument);
  std::array<uint8_t, 64> out{};
  const se05x::ExportObjectArgs x{kId, se05x::kNoRsaComponent, MutableByteSpan{out}};
  CHECK(tu::EncodesTo<Command::ExportObject>(x, "80 02 00 19 06 41 04 00 00 01 00 00"));
  se05x::LengthReply n{};
  CHECK_EQ(tu::Decode<Command::ExportObject>(x, "41 03 AA BB CC", n), Error::Ok);
  CHECK_EQ(n.length, 3U);
  const se05x::ExportObjectArgs tiny{kId, se05x::kNoRsaComponent, MutableByteSpan{out}.first(2U)};
  CHECK_EQ(tu::Decode<Command::ExportObject>(tiny, "41 03 AA BB CC", n), Error::BufferTooSmall);
  const tu::Bytes env = tu::Hex("13 01 AA 14 04 00 00 03 00 41 02 BB CC");
  CHECK(tu::EncodesTo<Command::ImportExternalObject>(
      {env.View(), true}, "80 06 00 00 0D 13 01 AA 14 04 00 00 03 00 41 02 BB CC 00"));
  const tu::Bytes no_key = tu::Hex("13 01 AA 41 02 BB CC");
  CHECK_EQ(tu::EncodeError<Command::ImportExternalObject>({no_key.View(), true}),
           Error::InvalidArgument);
  se05x::ExternalImportReceipt r{};
  CHECK_EQ(tu::Decode<Command::ImportExternalObject>({}, "01 02 03 04 05 06 07 08", r), Error::Ok);
  CHECK(tu::Holds(r.receipt, "01 02 03 04 05 06 07 08"));
  CHECK_EQ(tu::Decode<Command::ImportExternalObject>({}, "01 02 03 04 05 06 07", r),
           Error::FrameError);
}

TEST_CASE("ReadObject: range both or neither, component, extended Le (Table 127)") {
  std::array<uint8_t, 64> out{};
  se05x::ReadObjectArgs r{kId, 0U, 0U, se05x::kNoRsaComponent, MutableByteSpan{out}};
  CHECK(tu::EncodesTo<Command::ReadObject>(r, "80 02 00 00 06 41 04 00 00 01 00 00"));
  r.offset = 2U;
  r.length = 4U;
  CHECK(tu::EncodesTo<Command::ReadObject>(
      r, "80 02 00 00 0E 41 04 00 00 01 00 42 02 00 02 43 02 00 04 00"));
  r.offset = 0U;
  r.length = 0U;
  r.rsa_component = 0U;
  CHECK(tu::EncodesTo<Command::ReadObject>(r, "80 02 00 00 09 41 04 00 00 01 00 44 01 00 00"));
  r.rsa_component = 2U;
  CHECK_EQ(tu::EncodeError<Command::ReadObject>(r), Error::InvalidArgument);
  std::array<uint8_t, 300> big{};
  const se05x::ReadObjectArgs e{kId, 0U, 0U, se05x::kNoRsaComponent, MutableByteSpan{big}};
  CHECK(tu::EncodesTo<Command::ReadObject>(e, "80 02 00 00 00 00 06 41 04 00 00 01 00 00 00"));
  se05x::LengthReply n{};
  r.rsa_component = se05x::kNoRsaComponent;
  CHECK_EQ(tu::Decode<Command::ReadObject>(r, "41 82 00 02 CA FE", n), Error::Ok);
  CHECK_EQ(n.length, 2U);
  CHECK_EQ(out[1], 0xFEU);
  CHECK_EQ(tu::Decode<Command::ReadObject>(r, "41 02 CA FE 00", n), Error::FrameError);
  CHECK_EQ(se05x::Codec<Command::ReadObject>::Decode(tu::Hex("41 00").View(), n).error,
           Error::InvalidArgument);
}

TEST_CASE("Attested reads: TAG_5 to TAG_7, INS 22, extended; both answer formats") {
  std::array<uint8_t, 64> data{};
  std::array<uint8_t, 80> sig{};
  se05x::ReadObjectAttestedArgs a{};
  a.id = kId;
  a.attestation_key = ObjectId{0xF0000012U};
  a.algo = se05x::AttestationAlgo::EcSha256;
  for (std::size_t i = 0U; i < a.freshness.size(); ++i) {
    a.freshness[i] = static_cast<uint8_t>(i);
  }
  a.data_out = MutableByteSpan{data};
  a.signature_out = MutableByteSpan{sig};
  CHECK(tu::EncodesTo<Command::ReadObjectAttested>(
      a,
      "80 22 00 00 00 00 21 41 04 00 00 01 00 45 04 F0 00 00 12 46 01 21 47 10 00 01 02 03 04 05 "
      "06 07 08 09 0A 0B 0C 0D 0E 0F 00 00"));
  se05x::AttestedRead r{};
  const char* v2 =
      "41 82 00 02 CA FE | 42 82 00 12 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 |"
      " 43 82 00 03 A1 A2 A3 | 44 82 00 02 00 20 | 4F 82 00 0C 00 00 00 01 00 00 00 00 00 00 "
      "00 09 | 52 82 00 08 30 06 02 01 01 02 01 01";
  CHECK_EQ(tu::Decode<Command::ReadObjectAttested>(a, v2, r), Error::Ok);
  CHECK(r.format == se05x::AttestationFormat::V2);
  CHECK_EQ(r.object_size, 0x20U);
  CHECK_EQ(r.data_length, 2U);
  CHECK_EQ(r.signature_length, 8U);
  CHECK_EQ(r.unique_id[17], 0x12U);
  CHECK_EQ(r.timestamp[11], 0x09U);
  CHECK(tu::Holds(r.attributes, "A1 A2 A3"));
  const char* v1 = "41 02 CA FE | 42 03 A1 A2 A3 | 43 0C 00 00 00 01 00 00 00 00 00 00 00 09 |"
                   " 44 10 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F |"
                   " 45 12 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 | 46 03 30 01 00";
  CHECK_EQ(tu::Decode<Command::ReadObjectAttested>(a, v1, r), Error::Ok);
  CHECK(r.format == se05x::AttestationFormat::V1);
  CHECK_EQ(r.freshness[15], 0x0FU);
  CHECK_EQ(tu::Decode<Command::ReadObjectAttested>(a, "41 02 CA FE | 52 01 00", r),
           Error::FrameError);
  a.algo = se05x::AttestationAlgo::Ed25519;
  CHECK_EQ(tu::EncodeError<Command::ReadObjectAttested>(a), Error::InvalidArgument);
  a.algo = se05x::AttestationAlgo::EcSha256;
  a.length = 501U;
  CHECK_EQ(tu::EncodeError<Command::ReadObjectAttested>(a), Error::InvalidArgument);
}

TEST_CASE("ReadObjectAttributes and its attested form; ReadRsaAttested (Tables 127, 130)") {
  CHECK(tu::EncodesTo<Command::ReadObjectAttributes>(
      {kId}, "80 02 00 3B 00 00 06 41 04 00 00 01 00 00 00"));
  se05x::ObjectAttributes at{};
  CHECK_EQ(tu::Decode<Command::ReadObjectAttributes>({kId},
                                                     "43 1C 00 00 01 00 29 01 00 10 00 00 00 00 00 "
                                                     "00 08 7F FF 00 01 10 02 00 00 02 00 00 00 05",
                                                     at),
           Error::Ok);
  CHECK(at.object_class == ObjectClass::EcKeyPair);
  CHECK(at.origin == se05x::Origin::Internal);
  CHECK_EQ(at.version, 5U);
  CHECK_EQ(tu::Decode<Command::ReadObjectAttributes>({kId}, "42 01 00", at), Error::FrameError);
  std::array<uint8_t, 80> sig{};
  se05x::AttributesAttestedArgs aa{};
  aa.id = kId;
  aa.attestation_key = ObjectId{0xF0000012U};
  aa.signature_out = MutableByteSpan{sig};
  CHECK(tu::EncodesTo<Command::ReadObjectAttributesAttested>(
      aa,
      "80 22 00 3B 00 00 21 41 04 00 00 01 00 45 04 F0 00 00 12 46 01 21 47 10 00 00 00 00 00 00 "
      "00 00 00 00 00 00 00 00 00 00 00 00"));
  se05x::AttestedRead r{};
  CHECK_EQ(
      tu::Decode<Command::ReadObjectAttributesAttested>(
          aa,
          "41 01 00 42 12 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 44 02 00 20 4F 0C "
          "00 00 00 01 00 00 00 00 00 00 00 09 52 02 30 00",
          r),
      Error::BufferTooSmall); // data where none is expected
  std::array<uint8_t, 8> comp{};
  se05x::ReadRsaAttestedArgs rr{};
  rr.id = kId;
  rr.rsa_component = 1U;
  rr.attestation_key = ObjectId{0xF0000010U};
  rr.algo = se05x::AttestationAlgo::EcSha384;
  rr.data_out = MutableByteSpan{comp};
  rr.signature_out = MutableByteSpan{sig};
  CHECK(tu::EncodesTo<Command::ReadRsaAttested>(
      rr,
      "80 22 00 00 00 00 24 41 04 00 00 01 00 44 01 01 45 04 F0 00 00 10 46 01 22 47 10 00 00 00 "
      "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"));
  rr.rsa_component = 2U;
  CHECK_EQ(tu::EncodeError<Command::ReadRsaAttested>(rr), Error::InvalidArgument);
}

TEST_CASE("ReadType, ReadSize, CheckObjectExists and DeleteSecureObject (4.7.4)") {
  CHECK(tu::EncodesTo<Command::ReadType>({kId}, "80 02 00 26 06 41 04 00 00 01 00 00"));
  se05x::TypeReply t{};
  CHECK_EQ(tu::Decode<Command::ReadType>({kId}, "41 01 29 42 01 02", t), Error::Ok);
  CHECK(t.object_class == ObjectClass::EcKeyPair);
  CHECK(t.lifetime == se05x::Lifetime::TransientDeselect);
  CHECK_EQ(tu::Decode<Command::ReadType>({kId}, "41 01 2B 42 01 01", t), Error::Ok);
  CHECK(t.object_class == ObjectClass::EcPubKey);
  CHECK(t.lifetime == se05x::Lifetime::Persistent);
  CHECK_EQ(tu::Decode<Command::ReadType>({kId}, "41 01 0E 42 01 01", t), Error::FrameError);
  CHECK_EQ(tu::Decode<Command::ReadType>({kId}, "41 01 0B 42 01 03", t), Error::FrameError);
  CHECK(tu::EncodesTo<Command::ReadSize>({kId}, "80 02 00 07 06 41 04 00 00 01 00 00"));
  se05x::U32Reply s{};
  CHECK_EQ(tu::Decode<Command::ReadSize>({kId}, "41 02 01 00", s), Error::Ok);
  CHECK_EQ(s.value, 256U);
  CHECK_EQ(tu::Decode<Command::ReadSize>({kId}, "41 05 00 00 00 01 00", s), Error::FrameError);
  CHECK(tu::EncodesTo<Command::CheckObjectExists>({kId}, "80 04 00 27 06 41 04 00 00 01 00 00"));
  se05x::BoolReply b{};
  CHECK_EQ(tu::Decode<Command::CheckObjectExists>({kId}, "41 01 01", b), Error::Ok);
  CHECK(b.value);
  CHECK(tu::EncodesTo<Command::DeleteSecureObject>({kId}, "80 04 00 28 06 41 04 00 00 01 00"));
  CHECK_EQ(tu::EncodeError<Command::DeleteSecureObject>({ObjectId{0xF0000000U}}),
           Error::InvalidArgument);
  CHECK_EQ(tu::EncodeError<Command::DeleteSecureObject>({ObjectId{0U}}), Error::InvalidArgument);
}

TEST_CASE("ReadIdList: offset, filter, MoreIndicator and no truncation (Tables 142, 143)") {
  std::array<ObjectId, 2> ids{};
  se05x::ReadIdListArgs a{0U, false, ObjectClass::EcKeyPair, std::span<ObjectId>{ids}};
  CHECK(tu::EncodesTo<Command::ReadIdList>(a, "80 02 00 25 07 41 02 00 00 42 01 FF 00"));
  a.filter_by_class = true;
  a.offset = 3U;
  CHECK(tu::EncodesTo<Command::ReadIdList>(a, "80 02 00 25 07 41 02 00 03 42 01 01 00"));
  se05x::IdListReply r{};
  CHECK_EQ(tu::Decode<Command::ReadIdList>(a, "41 01 02 42 08 00 00 01 00 00 00 02 00", r),
           Error::Ok);
  CHECK_EQ(r.count, 2U);
  CHECK(r.more);
  CHECK_EQ(ids[1].value, 0x200U);
  CHECK_EQ(tu::Decode<Command::ReadIdList>(a, "41 01 01 42 00", r), Error::Ok);
  CHECK(!r.more);
  CHECK_EQ(r.count, 0U);
  CHECK_EQ(
      tu::Decode<Command::ReadIdList>(a, "41 01 01 42 0C 00 00 00 01 00 00 00 02 00 00 00 03", r),
      Error::BufferTooSmall);
  CHECK_EQ(tu::Decode<Command::ReadIdList>(a, "41 01 01 42 07 00 00 00 01 00 00 00", r),
           Error::FrameError);
  CHECK_EQ(tu::Decode<Command::ReadIdList>(a, "41 01 03 42 00", r), Error::FrameError);
}

TEST_CASE("Curves: create, parameters, id, list, delete; Ed25519 is never created (4.8)") {
  CHECK(tu::EncodesTo<Command::CreateEcCurve>({EcCurve::NistP256}, "80 01 0B 04 03 41 01 03"));
  CHECK(
      tu::EncodesTo<Command::CreateEcCurve>({EcCurve::Montgomery25519}, "80 01 0B 04 03 41 01 41"));
  CHECK_EQ(tu::EncodeError<Command::CreateEcCurve>({EcCurve::Ed25519}), Error::InvalidArgument);
  const tu::Bytes a =
      tu::Hex("FF FF FF FF 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 FF FF FF FF "
              "FF FF FF FF FF FF FF FC");
  CHECK(tu::EncodesTo<Command::SetEcCurveParam>({EcCurve::NistP256, 0x01U, a.View()},
                                                "80 01 0B 40 28 41 01 03 42 01 01 43 20 FF FF FF "
                                                "FF 00 00 00 01 00 00 00 00 00 00 00 00 00 00 "
                                                "00 00 FF FF FF FF FF FF FF FF FF FF FF FC"));
  CHECK_EQ(tu::EncodeError<Command::SetEcCurveParam>({EcCurve::NistP256, 0x03U, a.View()}),
           Error::InvalidArgument);
  CHECK_EQ(tu::EncodeError<Command::SetEcCurveParam>({EcCurve::Montgomery25519, 0x01U, a.View()}),
           Error::InvalidArgument);
  CHECK(tu::EncodesTo<Command::GetEcCurveId>({kId}, "80 02 0B 36 06 41 04 00 00 01 00 00"));
  se05x::CurveReply c{};
  CHECK_EQ(tu::Decode<Command::GetEcCurveId>({kId}, "41 01 40", c), Error::Ok);
  CHECK(c.curve == EcCurve::Ed25519);
  CHECK_EQ(tu::Decode<Command::GetEcCurveId>({kId}, "41 01 11", c), Error::Ok);
  CHECK(c.curve == EcCurve::BnP256);
  CHECK_EQ(tu::Decode<Command::GetEcCurveId>({kId}, "41 01 42", c), Error::FrameError);
  CHECK(tu::EncodesTo<Command::ReadEcCurveList>({}, "80 02 0B 25 00"));
  CHECK(tu::EncodesTo<Command::DeleteEcCurve>({EcCurve::NistP384}, "80 04 0B 28 03 41 01 04"));
}

TEST_CASE("Crypto objects: the 2-byte type of context and subtype (4.9, 4.3.39)") {
  using T = se05x::CryptoObjectType;
  CHECK(tu::EncodesTo<Command::CreateCryptoObject>({{0x0001U}, T::Digest, 2U},
                                                   "80 01 10 00 0A 41 02 00 01 42 01 01 43 01 04"));
  CHECK(tu::EncodesTo<Command::CreateCryptoObject>({{0x0002U}, T::Cipher, 9U},
                                                   "80 01 10 00 0A 41 02 00 02 42 01 02 43 01 0D"));
  CHECK(tu::EncodesTo<Command::CreateCryptoObject>({{0x0003U}, T::Mac, 4U},
                                                   "80 01 10 00 0A 41 02 00 03 42 01 03 43 01 31"));
  CHECK(tu::EncodesTo<Command::CreateCryptoObject>({{0x0004U}, T::Aead, 0U},
                                                   "80 01 10 00 0A 41 02 00 04 42 01 04 43 01 B0"));
  CHECK_EQ(tu::EncodeError<Command::CreateCryptoObject>({{0x0002U}, T::Cipher, 3U}),
           Error::Unsupported);
  CHECK_EQ(tu::EncodeError<Command::CreateCryptoObject>({{0x0002U}, T::Cipher, 14U}),
           Error::InvalidArgument);
  CHECK_EQ(tu::EncodeError<Command::CreateCryptoObject>({{0x0002U}, T::Digest, 5U}),
           Error::InvalidArgument);
  CHECK(tu::EncodesTo<Command::ReadCryptoObjectList>({}, "80 02 10 25 00"));
  se05x::SmallBlob list{};
  CHECK_EQ(tu::Decode<Command::ReadCryptoObjectList>({}, "41 04 00 01 01 04", list), Error::Ok);
  CHECK_EQ(tu::Decode<Command::ReadCryptoObjectList>({}, "41 03 00 01 01", list),
           Error::FrameError);
  CHECK(tu::EncodesTo<Command::DeleteCryptoObject>({{0x0001U}}, "80 04 10 28 04 41 02 00 01"));
}
