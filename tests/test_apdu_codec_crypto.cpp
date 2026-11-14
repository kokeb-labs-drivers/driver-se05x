/**
 * @file test_apdu_codec_crypto.cpp
 * @brief The codecs of the groups Ec, Rsa, Cipher, Aead, Mac, Digest and Kdf, byte for byte
 * against AN12543 sections 4.10 to 4.19; the EdDSA and X25519 byte order with the RFC 8032 test 3
 * and RFC 7748 section 6.1 values (vectors V1 and V2, AN12543 Figures 22 and 23).
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <array>
#include <cstdint>

#include "test_apdu_util.hpp"

namespace {

using se05x::ByteSpan;
using se05x::Command;
using se05x::Error;
using se05x::MutableByteSpan;
using se05x::ObjectId;

constexpr ObjectId kKey{0x00000100U};
constexpr const char* k32 = "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 "
                            "17 18 19 1A 1B 1C 1D 1E 1F";
constexpr const char* kP256Point = "04 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 "
                                   "14 15 16 17 18 19 1A 1B 1C 1D 1E "
                                   "1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 "
                                   "34 35 36 37 38 39 3A 3B 3C 3D 3E 3F";
constexpr const char* kDer8 = "30 06 02 01 01 02 01 01";

/// The bytes of up to three hex strings, concatenated.
tu::Bytes Cat(const char* a, const char* b, const char* c = "") {
  tu::Bytes out = tu::Hex(a);
  const tu::Bytes rest[2] = {tu::Hex(b), tu::Hex(c)};
  for (const tu::Bytes& part : rest) {
    for (std::size_t i = 0U; i < part.n; ++i) {
      out.b[out.n + i] = part.b[i];
    }
    out.n += part.n;
  }
  return out;
}

/// Encode `C` and compare with bytes.
template <Command C>
bool EncodesToBytes(const se05x::ArgsOf<C>& args, const tu::Bytes& want) {
  tu::CommandBuffer buf{};
  const auto r = se05x::Codec<C>::Encode(args, MutableByteSpan{buf});
  return r.ok() && tu::Same(ByteSpan{buf.data(), r.value}, want.View());
}

} // namespace

TEST_CASE("EcdsaSign and EcdsaVerify: digest length per algorithm, DER (4.10.1.1, 4.10.2.1)") {
  const tu::Bytes digest = tu::Hex(k32);
  std::array<uint8_t, 72> sig{};
  se05x::SignArgs s{kKey, se05x::EcSignAlgo::Sha256, digest.View(), MutableByteSpan{sig}};
  CHECK(EncodesToBytes<Command::EcdsaSign>(
      s, Cat("80 03 0C 09 2B 41 04 00 00 01 00 42 01 21 43 20", k32, "00")));
  s.algo = se05x::EcSignAlgo::Plain;
  CHECK_EQ(tu::EncodeError<Command::EcdsaSign>(s), Error::Unsupported);
  s.algo = se05x::EcSignAlgo::Ed25519Pure;
  CHECK_EQ(tu::EncodeError<Command::EcdsaSign>(s), Error::InvalidArgument);
  s.algo = se05x::EcSignAlgo::Sha384;
  CHECK_EQ(tu::EncodeError<Command::EcdsaSign>(s), Error::InvalidArgument); // 32-byte digest
  s.algo = se05x::EcSignAlgo::Sha1;
  s.input = digest.View().first(20U);
  CHECK(tu::EncodeError<Command::EcdsaSign>(s) == Error::Ok);
  se05x::LengthReply n{};
  CHECK_EQ(tu::Decode<Command::EcdsaSign>(s, "41 08 30 06 02 01 01 02 01 01", n), Error::Ok);
  CHECK_EQ(n.length, 8U);
  CHECK_EQ(tu::Decode<Command::EcdsaSign>(s, "41 08 31 06 02 01 01 02 01 01", n),
           Error::FrameError);
  const tu::Bytes der = tu::Hex(kDer8);
  const se05x::VerifyArgs v{kKey, se05x::EcSignAlgo::Sha256, digest.View(), der.View()};
  CHECK(
      EncodesToBytes<Command::EcdsaVerify>(v, Cat("80 03 0C 0A 35 41 04 00 00 01 00 42 01 21 43 20",
                                                  k32, "45 08 30 06 02 01 01 02 01 01 00")));
  se05x::BoolReply ok{};
  CHECK_EQ(tu::Decode<Command::EcdsaVerify>(v, "41 01 02", ok), Error::Ok);
  CHECK(!ok.value);
  const se05x::VerifyArgs bad{kKey, se05x::EcSignAlgo::Sha256, digest.View(), der.View().first(7U)};
  CHECK_EQ(tu::EncodeError<Command::EcdsaVerify>(bad), Error::InvalidArgument);
}

TEST_CASE("EdDSA: the message is plain, r and s are reversed each way (V1, AN12543 7.1)") {
  const tu::Bytes msg = tu::Hex("AF 82");
  std::array<uint8_t, 64> sig{};
  const se05x::SignArgs s{kKey, se05x::EcSignAlgo::Ed25519Pure, msg.View(), MutableByteSpan{sig}};
  CHECK(tu::EncodesTo<Command::EddsaSign>(
      s, "80 03 0C 09 0D 41 04 00 00 01 00 42 01 A3 43 02 AF 82 00"));
  const char* wire_sig = "AC C3 5A DB D7 80 36 5E 44 3A 74 84 A2 48 E5 0C A3 01 BE 3A 9C E6 27 48 "
                         "02 24 EC DE 57 D6 91 62 "
                         "0A C4 1E EA CE BE 27 C0 8D D2 6E 71 E9 15 7C 4A 59 C6 4D 98 60 F7 67 AE "
                         "90 F2 16 8D 53 9B FF 18";
  const char* rfc_sig = "62 91 D6 57 DE EC 24 02 48 27 E6 9C 3A BE 01 A3 0C E5 48 A2 84 74 3A 44 "
                        "5E 36 80 D7 DB 5A C3 AC "
                        "18 FF 9B 53 8D 16 F2 90 AE 67 F7 60 98 4D C6 59 4A 7C 15 E9 71 6E D2 8D "
                        "C0 27 BE CE EA 1E C4 0A";
  const tu::Bytes answer = Cat("41 40", wire_sig);
  se05x::LengthReply n{};
  CHECK(se05x::Codec<Command::EddsaSign>::Decode(s, answer.View(), n).ok());
  CHECK_EQ(n.length, 64U);
  CHECK(tu::Same(ByteSpan{sig}, tu::Hex(rfc_sig).View()));
  const tu::Bytes rfc = tu::Hex(rfc_sig);
  const se05x::VerifyArgs v{kKey, se05x::EcSignAlgo::Ed25519Pure, msg.View(), rfc.View()};
  CHECK(EncodesToBytes<Command::EddsaVerify>(
      v, Cat("80 03 0C 0A 4F 41 04 00 00 01 00 42 01 A3 43 02 AF 82 45 40", wire_sig, "00")));
  std::array<uint8_t, 941> big{};
  const se05x::SignArgs too_long{kKey, se05x::EcSignAlgo::Ed25519Pure, ByteSpan{big},
                                 MutableByteSpan{sig}};
  CHECK_EQ(tu::EncodeError<Command::EddsaSign>(too_long), Error::InvalidArgument);
  const se05x::SignArgs at_limit{kKey, se05x::EcSignAlgo::Ed25519Pure, ByteSpan{big}.first(940U),
                                 MutableByteSpan{sig}};
  CHECK(tu::EncodeError<Command::EddsaSign>(at_limit) == Error::Ok);
  const se05x::SignArgs short_sig{kKey, se05x::EcSignAlgo::Ed25519Pure, msg.View(),
                                  MutableByteSpan{sig}.first(63U)};
  CHECK_EQ(tu::EncodeError<Command::EddsaSign>(short_sig), Error::InvalidArgument);
  const se05x::VerifyArgs wrong{kKey, se05x::EcSignAlgo::Ed25519Pure, msg.View(),
                                rfc.View().first(63U)};
  CHECK_EQ(tu::EncodeError<Command::EddsaVerify>(wrong), Error::InvalidArgument);
  const se05x::VerifyArgs ecdsa{kKey, se05x::EcSignAlgo::Sha256, msg.View(), rfc.View()};
  CHECK_EQ(tu::EncodeError<Command::EddsaVerify>(ecdsa), Error::InvalidArgument);
  // AN12543 p. 104: verify takes 940 bytes outside a UserID session, as sign does (p. 103). The
  // plain APDU of a 940-byte verify is 7 + 6 + 3 + 4 + 940 + 66 + 2 = 1028 bytes, within
  // kMaxPlainCommandApdu (1033); 941 is refused by the EdDSA limit itself.
  for (const std::size_t len : {936U, 937U, 940U}) {
    const se05x::VerifyArgs v_ok{kKey, se05x::EcSignAlgo::Ed25519Pure, ByteSpan{big}.first(len),
                                 rfc.View()};
    CHECK(tu::EncodeError<Command::EddsaVerify>(v_ok) == Error::Ok);
  }
  const se05x::VerifyArgs v_long{kKey, se05x::EcSignAlgo::Ed25519Pure, ByteSpan{big}, rfc.View()};
  CHECK_EQ(tu::EncodeError<Command::EddsaVerify>(v_long), Error::InvalidArgument);
  std::array<uint8_t, se05x::kMaxPlainCommandApdu> apdu{};
  const se05x::VerifyArgs v_940{kKey, se05x::EcSignAlgo::Ed25519Pure, ByteSpan{big}.first(940U),
                                rfc.View()};
  const auto encoded = se05x::Codec<Command::EddsaVerify>::Encode(v_940, MutableByteSpan{apdu});
  CHECK(encoded.ok() && (encoded.value == 1028U));
  static_assert(se05x::wire::EddsaInputMax(true) == 919U);
  static_assert(se05x::wire::EddsaInputMax(false) == 940U);
}

TEST_CASE("EcdaaSign (applet 3.x): F4, a 32-byte digest and a 32-byte random (AN12413 Table 156)") {
  const tu::Bytes h = tu::Hex(k32);
  std::array<uint8_t, 64> sig{};
  const se05x::EcdaaSignArgs a{kKey, h.View(), h.View(), MutableByteSpan{sig}};
  const tu::Bytes head = Cat("80 03 0C 09 4D 41 04 00 00 01 00 42 01 F4 43 20", k32, "44 20");
  tu::CommandBuffer buf{};
  const auto r = se05x::Codec<Command::EcdaaSign>::Encode(a, MutableByteSpan{buf});
  REQUIRE(r.ok());
  CHECK_EQ(r.value, 5U + 0x4DU + 1U);
  CHECK(tu::Same(ByteSpan{buf}.first(head.n), head.View()));
  CHECK(tu::Same(ByteSpan{buf}.subspan(head.n, 32U), h.View()));
  CHECK_EQ(buf[head.n + 32U], 0x00U); // Le
  const se05x::EcdaaSignArgs bad{kKey, h.View(), h.View().first(31U), MutableByteSpan{sig}};
  CHECK_EQ(tu::EncodeError<Command::EcdaaSign>(bad), Error::InvalidArgument);
}

TEST_CASE("ECDH: NIST plain, SvdpDh TAG_4, X25519 reversed both ways (V2, AN12543 7.2)") {
  const tu::Bytes peer = tu::Hex(kP256Point);
  std::array<uint8_t, 32> secret{};
  se05x::EcdhArgs a{kKey, se05x::EcdhAlgo::SvdpDhPlain, peer.View(), MutableByteSpan{secret}};
  CHECK(EncodesToBytes<Command::EcdhGenerateSharedSecret>(
      a, Cat("80 03 01 0F 49 41 04 00 00 01 00 42 41", kP256Point, "00")));
  a.algo = se05x::EcdhAlgo::SvdpDh;
  CHECK(EncodesToBytes<Command::EcdhGenerateSharedSecret>(
      a, Cat("80 03 01 0F 4C 41 04 00 00 01 00 42 41", kP256Point, "44 01 01 00")));
  // RFC 7748 6.1: Bob's public key in RFC order; the wire form is its reverse.
  const tu::Bytes bob =
      tu::Hex("DE 9E DB 7D 7B 7D C1 B4 D3 5B 61 C2 EC E4 35 37 3F 83 43 C8 5B 78 67 4D "
              "AD FC 7E 14 6F 88 2B 4F");
  const se05x::EcdhArgs x{kKey, se05x::EcdhAlgo::SvdpDhPlain, bob.View(), MutableByteSpan{secret}};
  CHECK(tu::EncodesTo<Command::EcdhGenerateSharedSecret>(
      x, "80 03 01 0F 28 41 04 00 00 01 00 42 20 4F 2B 88 6F 14 7E FC AD 4D 67 78 5B C8 43 83 3F "
         "37 35 "
         "E4 EC C2 61 5B D3 B4 C1 7D 7B 7D DB 9E DE 00"));
  se05x::LengthReply n{};
  CHECK_EQ(
      tu::Decode<Command::EcdhGenerateSharedSecret>(x,
                                                    "41 20 42 17 16 1E 3C 9B F0 76 33 9E D1 47 C9 "
                                                    "21 7E E0 25 0F 35 80 F4 3B 8E 72 E1 2D CE A4 "
                                                    "5B 9D 5D 4A",
                                                    n),
      Error::Ok);
  // RFC 7748 6.1 shared secret K.
  CHECK(tu::Same(ByteSpan{secret},
                 tu::Hex("4A 5D 9D 5B A4 CE 2D E1 72 8E 3B F4 80 35 0F 25 E0 7E 21 C9 "
                         "47 D1 9E 33 76 F0 9B 3C 1E 16 17 42")
                     .View()));
  // RFC 7748 6.2: Bob's X448 public key (56 bytes) is a Montgomery key too, reversed on the wire.
  const tu::Bytes bob448 =
      tu::Hex("3E B7 A8 29 B0 CD 20 F5 BC FC 0B 59 9B 6F EC CF 6D A4 62 71 07 BD B0 D4 "
              "F3 45 B4 30 27 D8 B9 72 FC 3E 34 FB 42 32 A1 3C A7 06 DC B5 7A EC 3D AE "
              "07 BD C1 C6 7B F3 36 09");
  std::array<uint8_t, 56> secret448{};
  CHECK(tu::EncodesTo<Command::EcdhGenerateSharedSecret>(
      {kKey, se05x::EcdhAlgo::SvdpDhPlain, bob448.View(), MutableByteSpan{secret448}},
      "80 03 01 0F 40 41 04 00 00 01 00 42 38 09 36 F3 7B C6 C1 BD 07 AE 3D EC 7A B5 DC 06 A7 3C "
      "A1 32 42 "
      "FB 34 3E FC 72 B9 D8 27 30 B4 45 F3 D4 B0 BD 07 71 62 A4 6D CF EC 6F 9B 59 0B FC BC F5 20 "
      "CD B0 29 "
      "A8 B7 3E 00"));
  const tu::Bytes odd = tu::Hex("04 01 02");
  const se05x::EcdhArgs bad{kKey, se05x::EcdhAlgo::SvdpDhPlain, odd.View(),
                            MutableByteSpan{secret}};
  CHECK_EQ(tu::EncodeError<Command::EcdhGenerateSharedSecret>(bad), Error::InvalidArgument);
}

TEST_CASE("EcdhIntoObject and EC point multiplication (4.10.3.1, 4.10.4.1)") {
  const tu::Bytes peer = tu::Hex(kP256Point);
  se05x::EcdhIntoObjectArgs i{kKey, peer.View(), ObjectId{0x200U}, nullptr,
                              se05x::EcdhAlgo::SvdpDhPlain};
  CHECK(EncodesToBytes<Command::EcdhIntoObject>(
      i, Cat("80 03 01 0F 4F 41 04 00 00 01 00 42 41", kP256Point, "47 04 00 00 02 00")));
  i.target = ObjectId{};
  CHECK_EQ(tu::EncodeError<Command::EcdhIntoObject>(i), Error::InvalidArgument);
  std::array<uint8_t, 65> out{};
  const se05x::EcPointMultiplyArgs m{kKey, peer.View(), MutableByteSpan{out}};
  CHECK(EncodesToBytes<Command::EcPointMultiply>(
      m, Cat("80 03 01 62 4C 41 04 00 00 01 00 42 41", kP256Point, "44 01 06 00")));
  const tu::Bytes mont = tu::Hex(k32);
  const se05x::EcPointMultiplyArgs mm{kKey, mont.View(), MutableByteSpan{out}};
  CHECK_EQ(tu::EncodeError<Command::EcPointMultiply>(mm), Error::InvalidArgument);
  CHECK(tu::EncodesTo<Command::EcPointMultiplyInputObj>(
      {kKey, ObjectId{0x200U}, MutableByteSpan{out}},
      "80 03 01 62 0F 41 04 00 00 01 00 43 04 00 00 02 00 44 01 06 00"));
}

TEST_CASE("RSA sign, verify, encrypt and decrypt (4.11)") {
  const tu::Bytes digest = tu::Hex(k32);
  std::array<uint8_t, 256> sig{};
  const se05x::RsaSignArgs s{kKey, se05x::RsaSignAlgo::Sha256Pkcs1, digest.View(),
                             MutableByteSpan{sig}};
  CHECK(EncodesToBytes<Command::RsaSign>(
      s, Cat("80 03 0C 09 00 00 2B 41 04 00 00 01 00 42 01 28 43 20", k32, "00 00")));
  const se05x::RsaSignArgs pss{kKey, se05x::RsaSignAlgo::Sha1Pss, digest.View().first(20U),
                               MutableByteSpan{sig}.first(64U)};
  tu::CommandBuffer buf{};
  CHECK(se05x::Codec<Command::RsaSign>::Encode(pss, MutableByteSpan{buf}).ok() &&
        (buf[13] == 0x15U));
  CHECK_EQ(tu::EncodeError<Command::RsaSign>(
               {kKey, se05x::RsaSignAlgo::Sha512Pss, digest.View(), MutableByteSpan{sig}}),
           Error::InvalidArgument);
  std::array<uint8_t, 64> s64{};
  const se05x::RsaVerifyArgs v{kKey, se05x::RsaSignAlgo::Sha256Pss, digest.View(), ByteSpan{s64}};
  CHECK_EQ(se05x::Codec<Command::RsaVerify>::Encode(v, MutableByteSpan{buf}).value,
           5U + 0x6DU + 1U);
  CHECK(tu::Prefix(ByteSpan{buf}, 13U, "80 03 0C 0A 6D 41 04 00 00 01 00 42 01") &&
        (buf[13] == 0x2CU));
  const tu::Bytes data = tu::Hex("01 02 03 04");
  std::array<uint8_t, 64> out{};
  const se05x::RsaCryptArgs e{kKey, se05x::RsaCryptAlgo::Pkcs1Oaep, data.View(),
                              MutableByteSpan{out}};
  CHECK(tu::EncodesTo<Command::RsaEncrypt>(
      e, "80 03 02 37 0F 41 04 00 00 01 00 42 01 0F 43 04 01 02 03 04 00"));
  const se05x::RsaCryptArgs d{kKey, se05x::RsaCryptAlgo::NoPad, data.View(), MutableByteSpan{out}};
  CHECK(tu::EncodesTo<Command::RsaDecrypt>(
      d, "80 03 02 38 0F 41 04 00 00 01 00 42 01 0C 43 04 01 02 03 04 00"));
  se05x::LengthReply n{};
  CHECK_EQ(tu::Decode<Command::RsaDecrypt>(d, "41 02 AA BB", n), Error::Ok);
  CHECK_EQ(n.length, 2U);
}

TEST_CASE("Cipher: init with and without IV, streaming, one-shot with the mode's IV (4.12)") {
  const tu::Bytes iv = tu::Hex("A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF");
  se05x::CipherInitArgs i{{0x0002U}, kKey, iv.View(), true};
  CHECK(tu::EncodesTo<Command::CipherInit>(i, "80 03 0E 42 1C 41 04 00 00 01 00 42 02 00 02 44 10 "
                                              "A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF"));
  i = se05x::CipherInitArgs{{0x0002U}, kKey, ByteSpan{}, false};
  CHECK(tu::EncodesTo<Command::CipherInit>(i, "80 03 0E 43 0A 41 04 00 00 01 00 42 02 00 02"));
  i.iv = iv.View().first(12U);
  CHECK_EQ(tu::EncodeError<Command::CipherInit>(i), Error::InvalidArgument);
  std::array<uint8_t, 16> out{};
  const se05x::StreamArgs u{{0x0002U}, iv.View(), MutableByteSpan{out}};
  CHECK(tu::EncodesTo<Command::CipherUpdate>(
      u, "80 03 0E 0C 16 42 02 00 02 43 10 A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF 00"));
  const se05x::StreamArgs f{{0x0002U}, ByteSpan{}, MutableByteSpan{out}};
  CHECK(tu::EncodesTo<Command::CipherFinal>(f, "80 03 0E 0D 06 42 02 00 02 43 00 00"));
  CHECK_EQ(tu::EncodeError<Command::CipherUpdate>(f), Error::InvalidArgument);
  se05x::LengthReply n{};
  CHECK_EQ(tu::Decode<Command::CipherUpdate>(u, "", n), Error::Ok);
  CHECK_EQ(n.length, 0U);
  CHECK_EQ(tu::Decode<Command::CipherFinal>(f, "41 02 01 02", n), Error::Ok);
  CHECK_EQ(n.length, 2U);
  se05x::CipherOneShotArgs o{
      kKey, se05x::CipherMode::AesCbcNoPad, iv.View(), true, iv.View(), MutableByteSpan{out}};
  const tu::Bytes ob = Cat("80 03 0E 37 2D 41 04 00 00 01 00 42 01 0D 43 10",
                           "A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF",
                           "44 10 A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF 00");
  CHECK(EncodesToBytes<Command::CipherOneShot>(o, ob));
  o.mode = se05x::CipherMode::AesEcbNoPad;
  CHECK_EQ(tu::EncodeError<Command::CipherOneShot>(o), Error::InvalidArgument); // ECB with an IV
  o.iv = ByteSpan{};
  o.encrypt = false;
  tu::CommandBuffer buf{};
  CHECK(se05x::Codec<Command::CipherOneShot>::Encode(o, MutableByteSpan{buf}).ok() &&
        tu::Prefix(ByteSpan{buf}, 15U, "80 03 0E 38 1B 41 04 00 00 01 00 42 01 0E 43"));
  o.mode = se05x::CipherMode::DesCbcPkcs5;
  CHECK_EQ(tu::EncodeError<Command::CipherOneShot>(o), Error::Unsupported);
}

TEST_CASE("AEAD: GCM and CCM init, chip IV, update, final both ways (4.13.1 to 4.13.3)") {
  const tu::Bytes iv12 = tu::Hex("CA FE BA BE FA CE DB AD DE CA F8 88");
  std::array<uint8_t, 12> iv_out{};
  se05x::AeadInitArgs i{};
  i.context = {0x0003U};
  i.key = kKey;
  i.iv = iv12.View();
  i.encrypt = false;
  CHECK(tu::EncodesTo<Command::AeadInit>(
      i, "80 03 11 43 18 41 04 00 00 01 00 42 02 00 03 45 0C CA FE BA BE FA CE DB AD DE CA F8 88"));
  i.iv = ByteSpan{};
  i.iv_out = MutableByteSpan{iv_out};
  i.encrypt = true;
  CHECK(tu::EncodesTo<Command::AeadInit>(
      i, "80 03 11 42 0E 41 04 00 00 01 00 42 02 00 03 45 02 00 0C 00"));
  se05x::Empty e{};
  CHECK_EQ(tu::Decode<Command::AeadInit>(i, "43 0C 01 02 03 04 05 06 07 08 09 0A 0B 0C", e),
           Error::Ok);
  CHECK_EQ(iv_out[11], 0x0CU);
  CHECK_EQ(tu::Decode<Command::AeadInit>(i, "43 0B 01 02 03 04 05 06 07 08 09 0A 0B", e),
           Error::FrameError);
  i.encrypt = false;
  CHECK_EQ(tu::EncodeError<Command::AeadInit>(i),
           Error::InvalidArgument); // no chip IV when decrypting
  se05x::AeadInitArgs c{};
  c.context = {0x0003U};
  c.key = kKey;
  const tu::Bytes n13 = tu::Hex("00 01 02 03 04 05 06 07 08 09 0A 0B 0C");
  c.iv = n13.View();
  c.mode = se05x::AeadMode::AesCcm;
  c.aad_length = 16U;
  c.data_length = 32U;
  c.tag_length = 8U;
  CHECK(tu::EncodesTo<Command::AeadInit>(
      c,
      "80 03 11 42 25 41 04 00 00 01 00 42 02 00 03 45 0D 00 01 02 03 04 05 06 07 08 09 0A 0B 0C "
      "46 02 00 10 47 02 00 20 48 02 00 08"));
  c.tag_length = 5U;
  CHECK_EQ(tu::EncodeError<Command::AeadInit>(c), Error::InvalidArgument);
  const tu::Bytes four = tu::Hex("11 22 33 44");
  CHECK(tu::EncodesTo<Command::AeadUpdateAad>({{0x0003U}, four.View()},
                                              "80 03 11 0C 0A 42 02 00 03 44 04 11 22 33 44"));
  std::array<uint8_t, 16> out{};
  CHECK(tu::EncodesTo<Command::AeadUpdate>({{0x0003U}, four.View(), MutableByteSpan{out}},
                                           "80 03 11 0C 0A 42 02 00 03 43 04 11 22 33 44 00"));
  std::array<uint8_t, 16> tag{};
  const se05x::AeadFinalArgs fe{
      {0x0003U}, ByteSpan{}, MutableByteSpan{out}, ByteSpan{}, MutableByteSpan{tag}};
  CHECK(tu::EncodesTo<Command::AeadFinal>(fe, "80 03 11 0D 04 42 02 00 03 00"));
  se05x::LengthReply n{};
  CHECK_EQ(tu::Decode<Command::AeadFinal>(
               fe, "41 02 AA BB 42 10 36 12 D2 E7 9E 3B 07 85 56 1B E1 4A AC A2 FC CB", n),
           Error::Ok);
  CHECK_EQ(n.length, 2U);
  CHECK_EQ(tag[15], 0xCBU);
  const tu::Bytes tag_in = tu::Hex("36 12 D2 E7 9E 3B 07 85 56 1B E1 4A AC A2 FC CB");
  const se05x::AeadFinalArgs fd{
      {0x0003U}, ByteSpan{}, MutableByteSpan{out}, tag_in.View(), MutableByteSpan{}};
  CHECK(tu::EncodesTo<Command::AeadFinal>(
      fd, "80 03 11 0D 16 42 02 00 03 46 10 36 12 D2 E7 9E 3B 07 85 56 1B E1 4A AC A2 FC CB 00"));
  CHECK_EQ(tu::Decode<Command::AeadFinal>(fd, "41 02 AA BB 42 01 01", n), Error::Ok);
  CHECK_EQ(tu::Decode<Command::AeadFinal>(fd, "41 02 AA BB 42 01 02", n), Error::AuthFailed);
  CHECK_EQ(out[0], 0U); // a failed check leaves no plain text
  CHECK_EQ(tu::Decode<Command::AeadFinal>(fd, "42 01 03", n), Error::FrameError);
  const se05x::AeadFinalArgs both{
      {0x0003U}, ByteSpan{}, MutableByteSpan{out}, tag_in.View(), MutableByteSpan{tag}};
  CHECK_EQ(tu::EncodeError<Command::AeadFinal>(both), Error::InvalidArgument);
  const se05x::AeadFinalArgs with_input{
      {0x0003U}, four.View(), MutableByteSpan{out}, ByteSpan{}, MutableByteSpan{tag}};
  CHECK_EQ(tu::EncodeError<Command::AeadFinal>(with_input), Error::InvalidArgument);
}

TEST_CASE("AeadOneShot: GCM only, the tag length 16, the 888-byte rule (4.13.4)") {
  const tu::Bytes iv12 = tu::Hex("CA FE BA BE FA CE DB AD DE CA F8 88");
  const tu::Bytes four = tu::Hex("11 22 33 44");
  std::array<uint8_t, 16> out{};
  std::array<uint8_t, 16> tag{};
  se05x::AeadOneShotArgs a{
      kKey,        se05x::AeadMode::AesGcm, iv12.View(), four.View(),         true,
      four.View(), MutableByteSpan{out},    ByteSpan{},  MutableByteSpan{tag}};
  CHECK(tu::EncodesTo<Command::AeadOneShot>(a, "80 03 11 37 27 41 04 00 00 01 00 42 01 B0 43 04 11 "
                                               "22 33 44 44 04 11 22 33 44 45 0C CA FE BA "
                                               "BE FA CE DB AD DE CA F8 88 46 02 00 10 00"));
  a.mode = se05x::AeadMode::AesCcm;
  CHECK_EQ(tu::EncodeError<Command::AeadOneShot>(a), Error::Unsupported);
  a.mode = se05x::AeadMode::AesGcm;
  // Data 400, AAD 16 and a 26-byte IV: an APDU of 472 bytes, 472 + 400 + 16 = 888 exactly.
  std::array<uint8_t, 400> d400{};
  std::array<uint8_t, 16> aad16{};
  std::array<uint8_t, 27> iv27{};
  a.input = ByteSpan{d400};
  a.aad = ByteSpan{aad16};
  a.out = MutableByteSpan{d400};
  a.iv = ByteSpan{iv27}.first(26U);
  CHECK(tu::EncodeError<Command::AeadOneShot>(a) == Error::Ok);
  a.iv = ByteSpan{iv27};
  CHECK_EQ(tu::EncodeError<Command::AeadOneShot>(a), Error::InvalidArgument);
  const tu::Bytes tag_in = tu::Hex("01 02 03 04");
  const se05x::AeadOneShotArgs dec{
      kKey,        se05x::AeadMode::AesGcm, iv12.View(),   ByteSpan{},       false,
      four.View(), MutableByteSpan{out},    tag_in.View(), MutableByteSpan{}};
  CHECK(tu::EncodeError<Command::AeadOneShot>(dec) == Error::Ok);
  se05x::LengthReply n{};
  CHECK_EQ(tu::Decode<Command::AeadOneShot>(dec, "42 01 02", n), Error::AuthFailed);
  CHECK_EQ(tu::Decode<Command::AeadOneShot>(dec, "41 04 01 02 03 04 42 01 01", n), Error::Ok);
  CHECK_EQ(n.length, 4U);
  const se05x::AeadOneShotArgs short_tag{kKey,
                                         se05x::AeadMode::AesGcm,
                                         iv12.View(),
                                         ByteSpan{},
                                         false,
                                         four.View(),
                                         MutableByteSpan{out},
                                         tag_in.View().first(3U),
                                         MutableByteSpan{}};
  CHECK_EQ(tu::EncodeError<Command::AeadOneShot>(short_tag), Error::InvalidArgument);
}

TEST_CASE("MAC: init, update with the data first, final and one-shot (4.14)") {
  CHECK(tu::EncodesTo<Command::MacInit>({{0x0005U}, kKey, true},
                                        "80 03 0D 03 0A 41 04 00 00 01 00 42 02 00 05"));
  CHECK(tu::EncodesTo<Command::MacInit>({{0x0005U}, kKey, false},
                                        "80 03 0D 44 0A 41 04 00 00 01 00 42 02 00 05"));
  const tu::Bytes ab = tu::Hex("AA BB");
  CHECK(tu::EncodesTo<Command::MacUpdate>({{0x0005U}, ab.View()},
                                          "80 03 0D 0C 08 41 02 AA BB 42 02 00 05"));
  std::array<uint8_t, 16> tag{};
  const se05x::MacFinalArgs g{{0x0005U}, ab.View(), ByteSpan{}, MutableByteSpan{tag}};
  CHECK(tu::EncodesTo<Command::MacFinal>(g, "80 03 0D 0D 08 41 02 AA BB 42 02 00 05 00"));
  se05x::LengthReply n{};
  CHECK_EQ(
      tu::Decode<Command::MacFinal>(g, "41 10 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F", n),
      Error::Ok);
  CHECK_EQ(n.length, 16U);
  const tu::Bytes mac8 = tu::Hex("01 02 03 04 05 06 07 08");
  const se05x::MacFinalArgs v{{0x0005U}, ab.View(), mac8.View(), MutableByteSpan{}};
  CHECK(tu::EncodesTo<Command::MacFinal>(
      v, "80 03 0D 0D 12 41 02 AA BB 42 02 00 05 43 08 01 02 03 04 05 06 07 08 00"));
  CHECK_EQ(tu::Decode<Command::MacFinal>(v, "41 01 02", n), Error::AuthFailed);
  CHECK_EQ(tu::Decode<Command::MacFinal>(v, "41 01 01", n), Error::Ok);
  CHECK_EQ(n.length, 0U);
  const se05x::MacFinalArgs neither{{0x0005U}, ab.View(), ByteSpan{}, MutableByteSpan{}};
  CHECK_EQ(tu::EncodeError<Command::MacFinal>(neither), Error::InvalidArgument);
  const se05x::MacOneShotArgs o{kKey,       se05x::MacAlgo::HmacSha256, ab.View(), true,
                                ByteSpan{}, MutableByteSpan{tag}};
  CHECK(tu::EncodesTo<Command::MacOneShot>(
      o, "80 03 0D 45 0D 41 04 00 00 01 00 42 01 19 43 02 AA BB 00"));
  const se05x::MacOneShotArgs ov{kKey,        se05x::MacAlgo::Cmac128, ab.View(), false,
                                 mac8.View(), MutableByteSpan{}};
  CHECK(tu::EncodesTo<Command::MacOneShot>(
      ov,
      "80 03 0D 46 17 41 04 00 00 01 00 42 01 31 43 02 AA BB 45 08 01 02 03 04 05 06 07 08 00"));
  const se05x::MacOneShotArgs des{kKey,       se05x::MacAlgo::DesCmac8, ab.View(), true,
                                  ByteSpan{}, MutableByteSpan{tag}};
  CHECK_EQ(tu::EncodeError<Command::MacOneShot>(des), Error::Unsupported);
}

TEST_CASE("Digest: init, update, final, one-shot of \"abc\" (4.19)") {
  CHECK(tu::EncodesTo<Command::DigestInit>({{0x0006U}}, "80 03 00 0B 04 42 02 00 06"));
  const tu::Bytes ab = tu::Hex("AA BB");
  CHECK(tu::EncodesTo<Command::DigestUpdate>({{0x0006U}, ab.View()},
                                             "80 03 00 0C 08 42 02 00 06 43 02 AA BB"));
  CHECK_EQ(tu::EncodeError<Command::DigestUpdate>({{0x0006U}, ByteSpan{}}), Error::InvalidArgument);
  std::array<uint8_t, 32> out{};
  CHECK(tu::EncodesTo<Command::DigestFinal>({{0x0006U}, ByteSpan{}, MutableByteSpan{out}},
                                            "80 03 00 0D 06 42 02 00 06 43 00 00"));
  const tu::Bytes abc = tu::Hex("61 62 63");
  const se05x::DigestOneShotArgs o{se05x::DigestMode::Sha256, abc.View(), MutableByteSpan{out}};
  CHECK(tu::EncodesTo<Command::DigestOneShot>(o, "80 03 00 0E 08 41 01 04 42 03 61 62 63 00"));
  se05x::LengthReply n{};
  CHECK_EQ(tu::Decode<Command::DigestOneShot>(o,
                                              "41 20 BA 78 16 BF 8F 01 CF EA 41 41 40 DE 5D AE 22 "
                                              "23 B0 03 61 A3 96 17 7A 9C B4 10 FF 61 "
                                              "F2 00 15 AD",
                                              n),
           Error::Ok);
  CHECK_EQ(out[31], 0xADU);
  CHECK_EQ(tu::Decode<Command::DigestOneShot>(
               o, "41 14 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13", n),
           Error::FrameError);
  const se05x::DigestOneShotArgs small{se05x::DigestMode::Sha512, abc.View(), MutableByteSpan{out}};
  CHECK_EQ(tu::EncodeError<Command::DigestOneShot>(small), Error::InvalidArgument);
}

TEST_CASE("HKDF and PBKDF2: limits, output to the host or to an object (4.15)") {
  const tu::Bytes four = tu::Hex("01 02 03 04");
  std::array<uint8_t, 32> out{};
  se05x::HkdfArgs h{};
  h.key = kKey;
  h.salt = four.View();
  h.info = four.View();
  h.derived_length = 32U;
  h.out = MutableByteSpan{out};
  CHECK(tu::EncodesTo<Command::Hkdf>(h, "80 03 00 2D 19 41 04 00 00 01 00 42 01 04 43 04 01 02 03 "
                                        "04 44 04 01 02 03 04 45 02 00 20 00"));
  h.out = MutableByteSpan{};
  h.target = ObjectId{0x200U};
  CHECK(tu::EncodesTo<Command::Hkdf>(h, "80 03 00 2D 1F 41 04 00 00 01 00 42 01 04 43 04 01 02 03 "
                                        "04 44 04 01 02 03 04 45 02 00 20 47 04 "
                                        "00 00 02 00"));
  h.mode = se05x::HkdfMode::ExpandOnly;
  // Expand-only with a salt would be the SP 800-108 feedback KDF (TAG_3 is an IV, Table 268).
  CHECK_EQ(tu::EncodeError<Command::Hkdf>(h), Error::InvalidArgument);
  h.salt = ByteSpan{};
  h.info = ByteSpan{}; // info is optional (Table 268)
  CHECK(tu::EncodesTo<Command::Hkdf>(
      h, "80 03 00 2F 13 41 04 00 00 01 00 42 01 04 45 02 00 20 47 04 00 00 02 00"));
  h.info = four.View();
  tu::CommandBuffer buf{};
  CHECK(se05x::Codec<Command::Hkdf>::Encode(h, MutableByteSpan{buf}).ok() && (buf[3] == 0x2FU));
  h.digest = se05x::DigestMode::Sha224;
  CHECK_EQ(tu::EncodeError<Command::Hkdf>(h), Error::InvalidArgument);
  h.digest = se05x::DigestMode::Sha256;
  h.derived_length = 769U;
  CHECK_EQ(tu::EncodeError<Command::Hkdf>(h), Error::InvalidArgument);
  se05x::Pbkdf2Args p{kKey, four.View(),         1000U, se05x::DigestMode::Sha256,
                      32U,  MutableByteSpan{out}};
  CHECK(tu::EncodesTo<Command::Pbkdf2>(
      p, "80 03 00 2E 17 41 04 00 00 01 00 42 04 01 02 03 04 43 02 03 E8 44 02 00 20 45 01 19 00"));
  p.digest = se05x::DigestMode::Sha224;
  CHECK_EQ(tu::EncodeError<Command::Pbkdf2>(p), Error::InvalidArgument);
  p.digest = se05x::DigestMode::Sha1; // the default: no TAG_5, the AN12413 Table 207 form
  CHECK(tu::EncodesTo<Command::Pbkdf2>(
      p, "80 03 00 2E 14 41 04 00 00 01 00 42 04 01 02 03 04 43 02 03 E8 44 02 00 20 00"));
  p.iterations = 0x8000U;
  CHECK_EQ(tu::EncodeError<Command::Pbkdf2>(p), Error::InvalidArgument);
  p.iterations = 1U;
  p.derived_length = 33U;
  CHECK_EQ(tu::EncodeError<Command::Pbkdf2>(p), Error::InvalidArgument); // out is 32 bytes
  se05x::LengthReply n{};
  p.derived_length = 2U;
  CHECK_EQ(tu::Decode<Command::Pbkdf2>(p, "41 02 AA BB", n), Error::Ok);
  CHECK_EQ(tu::Decode<Command::Pbkdf2>(p, "41 03 AA BB CC", n), Error::FrameError);
}

TEST_CASE("TLS: random, premaster secret, PRF with the P2 of the label (4.17)") {
  std::array<uint8_t, 48> out{};
  CHECK(tu::EncodesTo<Command::TlsGenerateRandom>({MutableByteSpan{out}}, "80 03 0F 49 00"));
  CHECK_EQ(tu::EncodeError<Command::TlsGenerateRandom>({MutableByteSpan{out}.first(31U)}),
           Error::InvalidArgument);
  CHECK(tu::EncodesTo<Command::TlsCalculatePreMasterSecret>(
      {kKey, ObjectId{0x200U}, ByteSpan{}, nullptr},
      "80 03 0F 4A 0C 41 04 00 00 01 00 43 04 00 00 02 00"));
  const tu::Bytes point = tu::Hex(kP256Point);
  tu::CommandBuffer buf{};
  const se05x::TlsPmsArgs ec{kKey, ObjectId{0x200U}, point.View(), nullptr};
  CHECK(se05x::Codec<Command::TlsCalculatePreMasterSecret>::Encode(ec, MutableByteSpan{buf}).ok() &&
        tu::Prefix(ByteSpan{buf}, 19U, "80 03 0F 4A 4F 42 04 00 00 01 00 43 04 00 00 02 00 44 41"));
  const tu::Bytes master = tu::Hex("6D 61 73 74 65 72 20 73 65 63 72 65 74");
  const tu::Bytes random = tu::Hex(k32);
  se05x::TlsPrfArgs p{kKey, se05x::DigestMode::Sha256, master.View(),         random.View(),
                      48U,  MutableByteSpan{out},      se05x::TlsRole::Client};
  CHECK(EncodesToBytes<Command::TlsPerformPrf>(
      p, Cat("80 03 0F 4C 3E 41 04 00 00 01 00 42 01 04 43 0D 6D 61 73 74 65 72 20 73 65 63 72 65 "
             "74 44 20",
             k32, "45 02 00 30 00")));
  const tu::Bytes expansion = tu::Hex("6B 65 79 20 65 78 70 61 6E 73 69 6F 6E");
  p.label = expansion.View();
  CHECK(se05x::Codec<Command::TlsPerformPrf>::Encode(p, MutableByteSpan{buf}).ok() &&
        (buf[3] == 0x4EU));
  // The server role passes the client random (AN12543 4.17.3): CLI_HELLO 0x4B and CLI_RND 0x4D.
  p.role = se05x::TlsRole::Server;
  CHECK(se05x::Codec<Command::TlsPerformPrf>::Encode(p, MutableByteSpan{buf}).ok() &&
        (buf[3] == 0x4DU));
  p.label = master.View();
  CHECK(se05x::Codec<Command::TlsPerformPrf>::Encode(p, MutableByteSpan{buf}).ok() &&
        (buf[3] == 0x4BU));
  p.role = tu::NotAnEnumerator<se05x::TlsRole>(7U);
  CHECK_EQ(tu::EncodeError<Command::TlsPerformPrf>(p), Error::InvalidArgument);
  p.role = se05x::TlsRole::Server;
  const tu::Bytes both = Cat(k32, k32);
  p.random = both.View();
  CHECK(se05x::Codec<Command::TlsPerformPrf>::Encode(p, MutableByteSpan{buf}).ok() &&
        (buf[3] == 0x5AU));
  const tu::Bytes other = tu::Hex("66 6F 6F");
  p.random = random.View();
  p.label = other.View();
  CHECK_EQ(tu::EncodeError<Command::TlsPerformPrf>(p), Error::InvalidArgument);
}
