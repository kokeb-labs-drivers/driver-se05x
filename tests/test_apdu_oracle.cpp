/**
 * @file test_apdu_oracle.cpp
 * @brief The codecs against the command layouts of the vendor middleware (tests/vectors/
 * nxp_layouts.hpp, read from its source text by tools/oracle/extract_layouts.py): for each of the
 * 60 builders, the same four header bytes when the middleware's are constants, and the tags the
 * codec sends appear in the middleware's list in the same order. The codec may leave out a tag
 * the middleware always writes when the specification makes it conditional; the differences are
 * listed in the P2 report. This is a structural check, not a byte-for-byte one: the middleware was
 * not run.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "se05x_policy.hpp"
#include "test_apdu_util.hpp"
#include "vectors/nxp_layouts.hpp"

namespace {

using se05x::AppletGeneration;
using se05x::ByteSpan;
using se05x::Command;
using se05x::MutableByteSpan;
using se05x::ObjectClass;
using se05x::ObjectId;
using se05x::Rule;

/// One encoded command: the APDU and its length (0 when the codec refused).
struct Encoded {
  std::array<uint8_t, 600> bytes{};
  std::size_t length{0};
};

template <Command C>
Encoded Enc(const se05x::ArgsOf<C>& args) {
  Encoded e{};
  const auto r = se05x::Codec<C>::Encode(args, MutableByteSpan{e.bytes});
  e.length = r.ok() ? r.value : 0U;
  return e;
}

/// The TLV body of an APDU (short or extended Lc), empty for a command without data.
ByteSpan BodyOf(const Encoded& e) {
  const ByteSpan apdu{e.bytes.data(), e.length};
  if ((apdu.size() > 7U) && (apdu[4] == 0U)) {
    const std::size_t lc = (static_cast<std::size_t>(apdu[5]) << 8U) | apdu[6];
    return apdu.subspan(7U, lc);
  }
  if ((apdu.size() > 5U) && (apdu[4] != 0U)) {
    return apdu.subspan(5U, apdu[4]);
  }
  return ByteSpan{};
}

/// Whether the codec's tags are an ordered subsequence of the middleware's.
bool TagsFit(const Encoded& e, const oracle::Layout& l) {
  se05x::apdu::TlvReader reader(BodyOf(e));
  std::size_t next = 0U;
  for (std::size_t guard = 0U; (guard < 16U) && !reader.AtEnd(); ++guard) {
    const auto tlv = reader.Next();
    if (!tlv.ok()) {
      return false;
    }
    while ((next < l.tag_count) && (l.tags[next] != tlv.value.tag)) {
      ++next;
    }
    if (next == l.tag_count) {
      static_cast<void>(
          std::printf("    %s: tag %02X not in the middleware's order\n", l.name, tlv.value.tag));
      return false;
    }
    ++next;
  }
  return reader.AtEnd();
}

bool Matches(const oracle::Layout& l, const Encoded& e) {
  if (e.length == 0U) {
    static_cast<void>(std::printf("    %s: the codec refused the arguments\n", l.name));
    return false;
  }
  if (l.has_header && (std::memcmp(l.header.data(), e.bytes.data(), 4U) != 0)) {
    static_cast<void>(std::printf(
        "    %s: header %02X %02X %02X %02X, middleware %02X %02X %02X %02X\n", l.name, e.bytes[0],
        e.bytes[1], e.bytes[2], e.bytes[3], l.header[0], l.header[1], l.header[2], l.header[3]));
    return false;
  }
  return TagsFit(e, l);
}

const se05x::Policy& Policy() {
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

/// The inputs every command below shares.
struct Inputs {
  std::array<uint8_t, 512> out{};
  std::array<ObjectId, 32> ids{};
  std::array<uint8_t, 65> point{};
  tu::Bytes k16 = tu::Hex("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F");
  tu::Bytes d32 = tu::Hex("10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27 "
                          "28 29 2A 2B 2C 2D 2E 2F");
  tu::Bytes uid = tu::Hex("55 66 77 88");
  tu::Bytes der = tu::Hex("30 06 02 01 01 02 01 02");
  tu::Bytes label = tu::Hex("6D 61 73 74 65 72 20 73 65 63 72 65 74"); // "master secret"
  Inputs() {
    point[0] = 0x04U;
    for (std::size_t i = 1U; i < point.size(); ++i) {
      point[i] = static_cast<uint8_t>(i);
    }
  }
  MutableByteSpan Out(std::size_t n) {
    return MutableByteSpan{out}.first(n);
  }
};

constexpr ObjectId kKey{0x00000100U};
constexpr ObjectId kAes{0x00000102U};

Encoded Session(Inputs& in, const char* name) {
  if (std::strcmp(name, "GetVersion") == 0) {
    return Enc<Command::GetVersion>({});
  }
  if (std::strcmp(name, "ReadState") == 0) {
    return Enc<Command::ReadState>({});
  }
  if (std::strcmp(name, "GetRandom") == 0) {
    return Enc<Command::GetRandom>({in.Out(32U)});
  }
  if (std::strcmp(name, "GetFreeMemory") == 0) {
    return Enc<Command::GetFreeMemory>({se05x::MemoryType::Persistent});
  }
  if (std::strcmp(name, "CreateSession") == 0) {
    return Enc<Command::CreateSession>({ObjectId{0x7FFF0201U}});
  }
  if (std::strcmp(name, "CloseSession") == 0) {
    return Enc<Command::CloseSession>({});
  }
  if (std::strcmp(name, "VerifySessionUserID") == 0) {
    return Enc<Command::VerifySessionUserId>({in.uid.View()});
  }
  if (std::strcmp(name, "SetLockState") == 0) {
    return Enc<Command::SetLockState>({se05x::LockStateValue::Locked});
  }
  if (std::strcmp(name, "DisableObjCreation") == 0) {
    return Enc<Command::DisableObjCreation>({se05x::RestrictMode::RestrictNew});
  }
  if (std::strcmp(name, "DeleteAll") == 0) {
    return Enc<Command::DeleteAll>({});
  }
  if (std::strcmp(name, "TriggerSelfTest") == 0) {
    return Enc<Command::TriggerSelfTest>({0xF906U});
  }
  return Encoded{};
}

Encoded Writes(Inputs& in, const char* name) {
  if (std::strcmp(name, "WriteECKey_Ver") == 0) {
    se05x::WriteEcKeyArgs a{};
    a.id = kKey;
    a.policy = &Policy();
    a.public_key = ByteSpan{in.point};
    return Enc<Command::WriteEcKey>(a);
  }
  if (std::strcmp(name, "WriteSymmKey_Ver") == 0) {
    se05x::WriteSymmKeyArgs a{};
    a.id = kAes;
    a.policy = &Policy();
    a.key = in.k16.View();
    return Enc<Command::WriteSymmKey>(a);
  }
  if (std::strcmp(name, "WriteBinary_Ver") == 0) {
    se05x::WriteBinaryArgs a{};
    a.id = ObjectId{0x104U};
    a.offset = 8U;
    a.data = in.k16.View();
    return Enc<Command::WriteBinary>(a);
  }
  if (std::strcmp(name, "WriteUserID") == 0) {
    se05x::WriteUserIdArgs a{};
    a.id = ObjectId{0x106U};
    a.policy = &Policy();
    a.user_secret = in.uid.View();
    a.max_attempts = 5U;
    return Enc<Command::WriteUserId>(a);
  }
  if (std::strcmp(name, "CreateCounter") == 0) {
    se05x::WriteCounterArgs a{};
    a.id = ObjectId{0x107U};
    a.policy = &Policy();
    a.counter_bytes = 4U;
    return Enc<Command::WriteCounter>(a);
  }
  if (std::strcmp(name, "SetCounterValue") == 0) {
    se05x::WriteCounterArgs a{};
    a.id = ObjectId{0x107U};
    a.counter_bytes = 4U;
    a.set_value = true;
    a.value = 0x01020304U;
    return Enc<Command::WriteCounter>(a);
  }
  if (std::strcmp(name, "IncCounter") == 0) {
    return Enc<Command::IncrementCounter>({ObjectId{0x107U}});
  }
  if (std::strcmp(name, "WritePCR_WithType") == 0) {
    se05x::WritePcrArgs a{};
    a.id = ObjectId{0x108U};
    a.policy = &Policy();
    a.initial_value = in.d32.View();
    return Enc<Command::WritePcr>(a);
  }
  if (std::strcmp(name, "ImportObject") == 0) {
    se05x::ImportObjectArgs a{};
    a.id = kKey;
    a.serialised = in.k16.View();
    return Enc<Command::ImportObject>(a);
  }
  return Encoded{};
}

Encoded Reads(Inputs& in, const char* name) {
  if (std::strcmp(name, "ReadObject") == 0) {
    se05x::ReadObjectArgs a{};
    a.id = kKey;
    a.offset = 4U;
    a.length = 8U;
    a.out = in.Out(8U);
    return Enc<Command::ReadObject>(a);
  }
  if (std::strcmp(name, "ReadObject_W_Attst_V2") == 0) {
    se05x::ReadObjectAttestedArgs a{};
    a.id = kKey;
    a.attestation_key = ObjectId{0xF0000012U};
    a.data_out = in.Out(64U);
    a.signature_out = MutableByteSpan{in.out}.subspan(64U, 80U);
    return Enc<Command::ReadObjectAttested>(a);
  }
  if (std::strcmp(name, "ExportObject") == 0) {
    se05x::ExportObjectArgs a{};
    a.id = kKey;
    a.out = in.Out(64U);
    return Enc<Command::ExportObject>(a);
  }
  if (std::strcmp(name, "ReadType") == 0) {
    return Enc<Command::ReadType>({kKey});
  }
  if (std::strcmp(name, "ReadSize") == 0) {
    return Enc<Command::ReadSize>({kKey});
  }
  if (std::strcmp(name, "ReadIDList") == 0) {
    se05x::ReadIdListArgs a{};
    a.out = in.ids;
    return Enc<Command::ReadIdList>(a);
  }
  if (std::strcmp(name, "CheckObjectExists") == 0) {
    return Enc<Command::CheckObjectExists>({kKey});
  }
  if (std::strcmp(name, "DeleteSecureObject") == 0) {
    return Enc<Command::DeleteSecureObject>({kKey});
  }
  if (std::strcmp(name, "ReadObjectAttributes") == 0) {
    return Enc<Command::ReadObjectAttributes>({kKey});
  }
  return Encoded{};
}

Encoded Curves(const char* name) {
  if (std::strcmp(name, "CreateECCurve") == 0) {
    return Enc<Command::CreateEcCurve>({se05x::EcCurve::NistP256});
  }
  if (std::strcmp(name, "GetECCurveId") == 0) {
    return Enc<Command::GetEcCurveId>({kKey});
  }
  if (std::strcmp(name, "ReadECCurveList") == 0) {
    return Enc<Command::ReadEcCurveList>({});
  }
  if (std::strcmp(name, "DeleteECCurve") == 0) {
    return Enc<Command::DeleteEcCurve>({se05x::EcCurve::NistP256});
  }
  if (std::strcmp(name, "CreateCryptoObject") == 0) {
    se05x::CreateCryptoObjectArgs a{};
    a.context = se05x::CryptoObjectId{0x10U};
    a.type = se05x::CryptoObjectType::Cipher;
    a.algorithm = static_cast<uint8_t>(se05x::CipherMode::AesCbcNoPad);
    return Enc<Command::CreateCryptoObject>(a);
  }
  if (std::strcmp(name, "ReadCryptoObjectList") == 0) {
    return Enc<Command::ReadCryptoObjectList>({});
  }
  if (std::strcmp(name, "DeleteCryptoObject") == 0) {
    return Enc<Command::DeleteCryptoObject>({se05x::CryptoObjectId{0x10U}});
  }
  return Encoded{};
}

Encoded Asymmetric(Inputs& in, const char* name) {
  if (std::strcmp(name, "ECDSASign") == 0) {
    return Enc<Command::EcdsaSign>({kKey, se05x::EcSignAlgo::Sha256, in.d32.View(), in.Out(72U)});
  }
  if (std::strcmp(name, "ECDSAVerify") == 0) {
    return Enc<Command::EcdsaVerify>(
        {kKey, se05x::EcSignAlgo::Sha256, in.d32.View(), in.der.View()});
  }
  if (std::strcmp(name, "EdDSASign") == 0) {
    return Enc<Command::EddsaSign>(
        {kKey, se05x::EcSignAlgo::Ed25519Pure, in.k16.View(), in.Out(64U)});
  }
  if (std::strcmp(name, "ECDHGenerateSharedSecret") == 0) {
    return Enc<Command::EcdhGenerateSharedSecret>(
        {kKey, se05x::EcdhAlgo::SvdpDhPlain, ByteSpan{in.point}, in.Out(32U)});
  }
  if (std::strcmp(name, "RSASign") == 0) {
    return Enc<Command::RsaSign>(
        {kKey, se05x::RsaSignAlgo::Sha256Pss, in.d32.View(), in.Out(256U)});
  }
  if (std::strcmp(name, "RSAEncrypt") == 0) {
    return Enc<Command::RsaEncrypt>(
        {kKey, se05x::RsaCryptAlgo::Pkcs1Oaep, in.k16.View(), in.Out(256U)});
  }
  return Encoded{};
}

Encoded Symmetric(Inputs& in, const char* name) {
  const se05x::CryptoObjectId ctx{0x10U};
  if (std::strcmp(name, "CipherInit") == 0) {
    return Enc<Command::CipherInit>({ctx, kAes, in.k16.View(), true});
  }
  if (std::strcmp(name, "CipherUpdate") == 0) {
    return Enc<Command::CipherUpdate>({ctx, in.k16.View(), in.Out(32U)});
  }
  if (std::strcmp(name, "CipherFinal") == 0) {
    return Enc<Command::CipherFinal>({ctx, in.k16.View(), in.Out(32U)});
  }
  if (std::strcmp(name, "CipherOneShot") == 0) {
    return Enc<Command::CipherOneShot>(
        {kAes, se05x::CipherMode::AesCbcNoPad, in.k16.View(), true, in.k16.View(), in.Out(32U)});
  }
  if (std::strcmp(name, "MACInit") == 0) {
    se05x::MacInitArgs a{};
    a.context = ctx;
    a.key = kAes;
    return Enc<Command::MacInit>(a);
  }
  if (std::strcmp(name, "MACUpdate") == 0) {
    return Enc<Command::MacUpdate>({ctx, in.k16.View()});
  }
  if (std::strcmp(name, "MACOneShot_G") == 0) {
    se05x::MacOneShotArgs a{};
    a.key = kAes;
    a.input = in.k16.View();
    a.tag_out = in.Out(32U);
    return Enc<Command::MacOneShot>(a);
  }
  if (std::strcmp(name, "AeadOneShot") == 0) {
    se05x::AeadOneShotArgs a{};
    a.key = kAes;
    a.iv = in.k16.View().first(12U);
    a.aad = in.uid.View();
    a.input = in.k16.View();
    a.out = in.Out(16U);
    a.tag_out = MutableByteSpan{in.out}.subspan(16U, 16U);
    return Enc<Command::AeadOneShot>(a);
  }
  return Encoded{};
}

Encoded Kdf(Inputs& in, const char* name) {
  if (std::strcmp(name, "HKDF_Extended") == 0) {
    se05x::HkdfArgs a{};
    a.key = kAes;
    a.salt = in.k16.View();
    a.info = in.uid.View();
    a.derived_length = 32U;
    a.out = in.Out(32U);
    return Enc<Command::Hkdf>(a);
  }
  if (std::strcmp(name, "PBKDF2_extended") == 0) {
    se05x::Pbkdf2Args a{};
    a.key = kAes;
    a.salt = in.k16.View();
    a.iterations = 1000U;
    a.digest = se05x::DigestMode::Sha256;
    a.derived_length = 32U;
    a.out = in.Out(32U);
    return Enc<Command::Pbkdf2>(a);
  }
  if (std::strcmp(name, "DigestInit") == 0) {
    return Enc<Command::DigestInit>({se05x::CryptoObjectId{0x12U}});
  }
  if (std::strcmp(name, "DigestUpdate") == 0) {
    return Enc<Command::DigestUpdate>({se05x::CryptoObjectId{0x12U}, in.k16.View()});
  }
  if (std::strcmp(name, "DigestOneShot") == 0) {
    return Enc<Command::DigestOneShot>({se05x::DigestMode::Sha256, in.k16.View(), in.Out(32U)});
  }
  if (std::strcmp(name, "TLSGenerateRandom") == 0) {
    return Enc<Command::TlsGenerateRandom>({in.Out(32U)});
  }
  if (std::strcmp(name, "TLSPerformPRF") == 0) {
    se05x::TlsPrfArgs a{};
    a.key = kAes;
    a.label = in.label.View();
    a.random = in.d32.View();
    a.length = 48U;
    a.out = in.Out(48U);
    return Enc<Command::TlsPerformPrf>(a);
  }
  return Encoded{};
}

Encoded Desfire(Inputs& in, const char* name) {
  if (std::strcmp(name, "DFDiversifyKey") == 0) {
    return Enc<Command::DfDiversifyKey>(
        {kKey, ObjectId{0x200U}, in.uid.View().first(3U), MutableByteSpan{}});
  }
  if (std::strcmp(name, "DFKillAuthentication") == 0) {
    return Enc<Command::DfKillAuthentication>({});
  }
  if (std::strcmp(name, "DFDumpSessionKeys") == 0) {
    return Enc<Command::DfDumpSessionKeys>({ObjectId{}, ObjectId{}, ByteSpan{}, in.Out(38U)});
  }
  return Encoded{};
}

Encoded EncodeFor(Inputs& in, const char* name) {
  using Group = Encoded (*)(Inputs&, const char*);
  constexpr std::array<Group, 7> kGroups{
      &Session,    &Writes,    &Reads, [](Inputs&, const char* n) { return Curves(n); },
      &Asymmetric, &Symmetric, &Kdf};
  for (const Group g : kGroups) {
    const Encoded e = g(in, name);
    if (e.length != 0U) {
      return e;
    }
  }
  return Desfire(in, name);
}

} // namespace

TEST_CASE("Every middleware builder: same header, the codec's tags in the middleware's order") {
  Inputs in;
  std::size_t matched = 0U;
  for (const oracle::Layout& l : oracle::kLayouts) {
    const bool ok = Matches(l, EncodeFor(in, l.name));
    CHECK(ok);
    matched += ok ? 1U : 0U;
  }
  CHECK_EQ(matched, oracle::kLayouts.size());
}

TEST_CASE("The oracle check notices a wrong header and a tag out of order") {
  Inputs in;
  oracle::Layout l = oracle::kLayouts[2]; // GetRandom: 80 04 00 49, TAG_1
  REQUIRE(std::strcmp(l.name, "GetRandom") == 0);
  const Encoded e = EncodeFor(in, l.name);
  CHECK(Matches(l, e));
  l.header[3] = 0x48U;
  CHECK(!Matches(l, e));
  l = oracle::kLayouts[7]; // SetLockState: TAG_1 then TAG_2
  REQUIRE(std::strcmp(l.name, "SetLockState") == 0);
  l.tags[0] = 0x42U;
  l.tags[1] = 0x41U;
  CHECK(!Matches(l, EncodeFor(in, l.name)));
}
