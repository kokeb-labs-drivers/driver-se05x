/**
 * @file test_apdu_oracle_vectors.cpp
 * @brief The codecs byte for byte against the commands the vendor middleware built
 * (tests/vectors/nxp_oracle_vectors.hpp, recorded by tools/oracle/build_oracle.sh for applet 7.2
 * in `oracle::v7` and 3.x in `oracle::v3`) for the same inputs.
 *
 * Header and TLV body are compared byte for byte. Framing is not: the middleware frames short
 * case 4 without Le and extended commands differently (see the P2 report). Whether an Le is sent
 * is checked against what the middleware builder does (`expects_response` of
 * tests/vectors/nxp_layouts.hpp, and the recorded `has_le`, which the middleware sets only for its
 * extended case 4). Every known difference is listed in `kEntries` with its class and its
 * evidence, and is applied to that one command only, so a new difference fails the test.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "model/bytes.hpp"
#include "se05x_policy.hpp"
#include "test_apdu_util.hpp"
#include "vectors/nxp_layouts.hpp"
#include "vectors/nxp_oracle_vectors.hpp"

using se05x::testmodel::SameBytes;

namespace {

using se05x::ByteSpan;
using se05x::Command;
using se05x::MutableByteSpan;
using se05x::ObjectId;

/// One encoded command.
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

/// The parts of an APDU: header, TLV body, and whether an Le follows the body.
struct Parts {
  ByteSpan body;
  bool has_le{false};
};

Parts Split(const Encoded& e) {
  const ByteSpan a{e.bytes.data(), e.length};
  Parts p{};
  if ((a.size() > 7U) && (a[4] == 0U)) { // extended Lc
    const std::size_t lc = (static_cast<std::size_t>(a[5]) << 8U) | a[6];
    p.body = a.subspan(7U, lc);
    p.has_le = a.size() > (7U + lc);
  } else if ((a.size() > 5U) && (a[4] != 0U)) { // short Lc
    p.body = a.subspan(5U, a[4]);
    p.has_le = a.size() > (5U + a[4]);
  } else {
    p.has_le = a.size() > 4U; // case 2 (or the DeleteAll trailing 00)
  }
  return p;
}

/// The inputs of tools/oracle/oracle_capture.c, the same bytes.
struct Inputs {
  std::array<uint8_t, 1024> out{};
  std::array<ObjectId, 64> ids{};
  std::array<uint8_t, 65> point{};
  std::array<uint8_t, 300> big{};
  tu::Bytes key16 = tu::Hex("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F");
  tu::Bytes iv16 = tu::Hex("A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF");
  tu::Bytes digest32 = tu::Hex("10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 "
                               "26 27 28 29 2A 2B 2C 2D 2E 2F");
  tu::Bytes rnd16 = tu::Hex("C0 C1 C2 C3 C4 C5 C6 C7 C8 C9 CA CB CC CD CE CF");
  tu::Bytes user_id = tu::Hex("55 66 77 88");
  tu::Bytes label = tu::Hex("6D 61 73 74 65 72 20 73 65 63 72 65 74"); // "master secret"
  tu::Bytes sig8 = tu::Hex("30 06 02 01 01 02 01 02");
  /// The harness policy: one entry for every other user that grants nothing (`08 00..00`).
  se05x::Policy policy =
      se05x::PolicyBuilder<se05x::AppletGeneration::V7, se05x::ObjectClass::EcKeyPair>{}
          .ForAllOthers()
          .Build()
          .value;
  /// A policy for the commands the harness sent without one: the codec requires an explicit
  /// policy when an object is created, and the comparison removes it again (kStripPolicy).
  const se05x::Policy* create = &policy;
  Inputs() {
    for (std::size_t i = 0U; i < point.size(); ++i) {
      point[i] = static_cast<uint8_t>(i);
    }
    point[0] = 0x04U;
    for (std::size_t i = 0U; i < big.size(); ++i) {
      big[i] = static_cast<uint8_t>(i & 0xFFU);
    }
  }
  MutableByteSpan Out(std::size_t n) {
    return MutableByteSpan{out}.first(n);
  }
};

constexpr ObjectId kId100{0x100U};
constexpr ObjectId kAes{0x102U};
constexpr ObjectId kRsa{0x10AU};
constexpr se05x::CryptoObjectId kCipherCtx{0x0010U};
constexpr se05x::CryptoObjectId kMacCtx{0x0011U};
constexpr se05x::CryptoObjectId kDigestCtx{0x0012U};

using Encoder = Encoded (*)(Inputs&);

Encoded EcKeyPair(Inputs& in) {
  se05x::GenerateEcKeyArgs a{};
  a.id = kId100;
  a.policy = in.create;
  return Enc<Command::GenerateEcKey>(a);
}
Encoded EcPublic(Inputs& in) {
  se05x::WriteEcKeyArgs a{};
  a.id = ObjectId{0x101U};
  a.policy = &in.policy;
  a.public_key = ByteSpan{in.point};
  return Enc<Command::WriteEcKey>(a);
}
Encoded SymmKey(Inputs& in, se05x::Lifetime lifetime, uint32_t id) {
  se05x::WriteSymmKeyArgs a{};
  a.id = ObjectId{id};
  a.policy = in.create;
  a.key = in.key16.View();
  a.lifetime = lifetime;
  return Enc<Command::WriteSymmKey>(a);
}
Encoded Binary(Inputs& in, uint16_t offset, uint16_t file_length, ByteSpan data, uint32_t id) {
  se05x::WriteBinaryArgs a{};
  a.id = ObjectId{id};
  a.policy = (file_length != 0U) ? in.create : nullptr;
  a.offset = offset;
  a.file_length = file_length;
  a.data = data;
  return Enc<Command::WriteBinary>(a);
}
Encoded UserId(Inputs& in) {
  se05x::WriteUserIdArgs a{};
  a.id = ObjectId{0x106U};
  a.policy = in.create;
  a.user_secret = in.user_id.View();
  a.max_attempts = 5U;
  return Enc<Command::WriteUserId>(a);
}
Encoded Counter(Inputs& in, bool set) {
  se05x::WriteCounterArgs a{};
  a.id = ObjectId{0x107U};
  a.policy = set ? nullptr : in.create;
  a.counter_bytes = 4U;
  a.set_value = set;
  a.value = 0x01020304U;
  return Enc<Command::WriteCounter>(a);
}
Encoded Pcr(Inputs& in) {
  se05x::WritePcrArgs a{};
  a.id = ObjectId{0x108U};
  a.policy = in.create;
  a.initial_value = in.digest32.View();
  return Enc<Command::WritePcr>(a);
}
Encoded Read(Inputs& in, uint32_t id, uint16_t offset, uint16_t length) {
  se05x::ReadObjectArgs a{};
  a.id = ObjectId{id};
  a.offset = offset;
  a.length = length;
  a.out = in.Out((length == 0U) ? 512U : length);
  return Enc<Command::ReadObject>(a);
}
Encoded ReadAttested(Inputs& in) {
  se05x::ReadObjectAttestedArgs a{};
  a.id = kId100;
  a.attestation_key = ObjectId{0xF0000012U};
  for (std::size_t i = 0U; i < a.freshness.size(); ++i) {
    a.freshness[i] = in.rnd16.b[i];
  }
  a.data_out = in.Out(256U);
  a.signature_out = MutableByteSpan{in.out}.subspan(256U, 80U);
  return Enc<Command::ReadObjectAttested>(a);
}
Encoded Export(Inputs& in) {
  se05x::ExportObjectArgs a{};
  a.id = kId100;
  a.out = in.Out(512U);
  return Enc<Command::ExportObject>(a);
}
Encoded Import(Inputs& in) {
  se05x::ImportObjectArgs a{};
  a.id = kId100;
  a.serialised = in.key16.View();
  return Enc<Command::ImportObject>(a);
}
Encoded IdList(Inputs& in) {
  se05x::ReadIdListArgs a{};
  a.out = in.ids;
  return Enc<Command::ReadIdList>(a);
}
Encoded CryptoObject(Inputs& /*in*/) {
  se05x::CreateCryptoObjectArgs a{};
  a.context = kCipherCtx;
  a.type = se05x::CryptoObjectType::Cipher;
  a.algorithm = static_cast<uint8_t>(se05x::CipherMode::AesCbcNoPad);
  return Enc<Command::CreateCryptoObject>(a);
}
Encoded MacInit(Inputs& /*in*/) {
  se05x::MacInitArgs a{};
  a.context = kMacCtx;
  a.key = kAes;
  return Enc<Command::MacInit>(a);
}
Encoded MacOneShot(Inputs& in) {
  se05x::MacOneShotArgs a{};
  a.key = kAes;
  a.input = in.key16.View();
  a.tag_out = in.Out(32U);
  return Enc<Command::MacOneShot>(a);
}
Encoded Hkdf(Inputs& in) {
  se05x::HkdfArgs a{};
  a.key = kAes;
  a.salt = in.key16.View();
  a.info = in.rnd16.View();
  a.derived_length = 32U;
  a.out = in.Out(32U);
  return Enc<Command::Hkdf>(a);
}
Encoded Pbkdf2(Inputs& in) {
  se05x::Pbkdf2Args a{};
  a.key = kAes;
  a.salt = in.key16.View();
  a.iterations = 1000U;
  a.digest = se05x::DigestMode::Sha1; // the middleware's PBKDF2 builder sends no TAG_5
  a.derived_length = 32U;
  a.out = in.Out(32U);
  return Enc<Command::Pbkdf2>(a);
}
Encoded TlsPrf(Inputs& in) {
  se05x::TlsPrfArgs a{};
  a.key = kAes;
  a.label = in.label.View();
  a.random = in.digest32.View();
  a.length = 48U;
  a.out = in.Out(48U);
  a.role = se05x::TlsRole::Server; // the harness passed the client hello random
  return Enc<Command::TlsPerformPrf>(a);
}

// Known, classified differences, applied to one command only (bits of `Entry::fixes`).
/// No difference.
constexpr uint8_t kNone = 0U;
/// Ours carries the policy the codec requires; the harness sent none.
constexpr uint8_t kStripPolicy = 1U;
/// The 7.x builder always writes TAG_11 version 0; ours leaves it out.
constexpr uint8_t kOracleVersion0 = 2U;
/// The builder always writes TAG_2 RSAKeyComponent 0xFF.
constexpr uint8_t kOracleRsaNa = 4U;
/// A header byte differs for a reason given in the entry.
constexpr uint8_t kHeaderDiffers = 8U;
/// The Le differs from the builder for a reason given in the entry.
constexpr uint8_t kLeDiffers = 16U;

struct Entry {
  const char* name;              ///< The vector.
  const char* layout;            ///< The middleware builder (nxp_layouts.hpp).
  Encoder encode;                ///< Our command for the harness inputs.
  uint8_t fixes;                 ///< `k*` difference bits.
  std::array<uint8_t, 4> header; ///< Our header when kHeaderDiffers.
};

// clang-format off
constexpr std::array<Entry, 62> kEntries{{
    {"GetVersion", "GetVersion", [](Inputs&) { return Enc<Command::GetVersion>({}); }, kNone, {}},
    {"ReadState", "ReadState", [](Inputs&) { return Enc<Command::ReadState>({}); }, kNone, {}},
    {"GetRandom", "GetRandom", [](Inputs& in) { return Enc<Command::GetRandom>({in.Out(32U)}); },
     kNone, {}},
    {"GetFreeMemory", "GetFreeMemory",
     [](Inputs&) { return Enc<Command::GetFreeMemory>({se05x::MemoryType::Persistent}); }, kNone, {}},
    {"CreateSession", "CreateSession",
     [](Inputs&) { return Enc<Command::CreateSession>({ObjectId{0x7FFF0201U}}); }, kNone, {}},
    {"VerifyUserId", "VerifySessionUserID",
     [](Inputs& in) { return Enc<Command::VerifySessionUserId>({in.user_id.View()}); }, kNone, {}},
    {"SetLockState", "SetLockState",
     [](Inputs&) { return Enc<Command::SetLockState>({se05x::LockStateValue::Locked}); }, kNone, {}},
    {"DisableObjCreation", "DisableObjCreation",
     [](Inputs&) { return Enc<Command::DisableObjCreation>({se05x::RestrictMode::RestrictNew}); },
     kNone, {}},
    // DeleteAll: AN12543 Table 339 prints "Lc 0x00", so ours ends in 00 (spec ambiguity: as an
    // ISO 7816-4 APDU that byte reads as Le); the builder sends case 1.
    {"DeleteAll", "DeleteAll", [](Inputs&) { return Enc<Command::DeleteAll>({}); }, kLeDiffers, {}},
    {"WriteEcKeyPair", "WriteECKey_Ver", &EcKeyPair, kStripPolicy | kOracleVersion0, {}},
    {"WriteEcPublic", "WriteECKey_Ver", &EcPublic, kOracleVersion0, {}},
    {"WriteSymmKey", "WriteSymmKey_Ver",
     [](Inputs& in) { return SymmKey(in, se05x::Lifetime::Persistent, 0x102U); },
     kStripPolicy | kOracleVersion0, {}},
    {"WriteSymmKeyTransient", "WriteSymmKey_Ver",
     [](Inputs& in) { return SymmKey(in, se05x::Lifetime::TransientReset, 0x103U); },
     kStripPolicy | kOracleVersion0, {}},
    {"WriteBinaryCreate", "WriteBinary_Ver",
     [](Inputs& in) { return Binary(in, 0U, 16U, in.key16.View(), 0x104U); },
     kStripPolicy | kOracleVersion0, {}},
    {"WriteBinaryOffset", "WriteBinary_Ver",
     [](Inputs& in) { return Binary(in, 8U, 0U, in.key16.View().first(8U), 0x104U); },
     kOracleVersion0, {}},
    {"WriteBinaryLong", "WriteBinary_Ver",
     [](Inputs& in) { return Binary(in, 0U, 300U, ByteSpan{in.big}, 0x105U); },
     kStripPolicy | kOracleVersion0, {}},
    // WriteUserID: AN12543 4.7.1.5 "UserIDs must be created as Authentication Object", so INS is
    // INS_WRITE | INS_AUTH_OBJECT (0x41); the harness passed AttestationType_None (input choice).
    {"WriteUserId", "WriteUserID", &UserId, kStripPolicy | kHeaderDiffers,
     {0x80U, 0x41U, 0x07U, 0x00U}},
    {"CreateCounter", "CreateCounter", [](Inputs& in) { return Counter(in, false); }, kStripPolicy,
     {}},
    {"SetCounterValue", "SetCounterValue", [](Inputs& in) { return Counter(in, true); }, kNone, {}},
    {"IncCounter", "IncCounter",
     [](Inputs&) { return Enc<Command::IncrementCounter>({ObjectId{0x107U}}); }, kNone, {}},
    {"WritePcr", "WritePCR_WithType", &Pcr, kStripPolicy, {}},
    {"ExtendPcr", "WritePCR_WithType",
     [](Inputs& in) { return Enc<Command::ExtendPcr>({ObjectId{0x108U}, in.key16.View()}); }, kNone,
     {}},
    {"ReadObject", "ReadObject", [](Inputs& in) { return Read(in, 0x100U, 0U, 0U); }, kNone, {}},
    {"ReadObjectPart", "ReadObject", [](Inputs& in) { return Read(in, 0x104U, 4U, 8U); }, kNone, {}},
    {"ReadObjectAttested", "ReadObject_W_Attst_V2", &ReadAttested, kNone, {}},
    {"ExportObject", "ExportObject", &Export, kOracleRsaNa, {}},
    {"ImportObject", "ImportObject", &Import, kOracleRsaNa, {}},
    {"ReadType", "ReadType", [](Inputs&) { return Enc<Command::ReadType>({kId100}); }, kNone, {}},
    {"ReadSize", "ReadSize", [](Inputs&) { return Enc<Command::ReadSize>({kId100}); }, kNone, {}},
    {"ReadIdList", "ReadIDList", &IdList, kNone, {}},
    {"CheckObjectExists", "CheckObjectExists",
     [](Inputs&) { return Enc<Command::CheckObjectExists>({kId100}); }, kNone, {}},
    {"DeleteSecureObject", "DeleteSecureObject",
     [](Inputs&) { return Enc<Command::DeleteSecureObject>({kId100}); }, kNone, {}},
    {"CreateEcCurve", "CreateECCurve",
     [](Inputs&) { return Enc<Command::CreateEcCurve>({se05x::EcCurve::NistP256}); }, kNone, {}},
    {"GetEcCurveId", "GetECCurveId", [](Inputs&) { return Enc<Command::GetEcCurveId>({kId100}); },
     kNone, {}},
    {"ReadEcCurveList", "ReadECCurveList", [](Inputs&) { return Enc<Command::ReadEcCurveList>({}); },
     kNone, {}},
    {"DeleteEcCurve", "DeleteECCurve",
     [](Inputs&) { return Enc<Command::DeleteEcCurve>({se05x::EcCurve::NistP256}); }, kNone, {}},
    {"CreateCryptoObject", "CreateCryptoObject", &CryptoObject, kNone, {}},
    {"ReadCryptoObjectList", "ReadCryptoObjectList",
     [](Inputs&) { return Enc<Command::ReadCryptoObjectList>({}); }, kNone, {}},
    {"DeleteCryptoObject", "DeleteCryptoObject",
     [](Inputs&) { return Enc<Command::DeleteCryptoObject>({kCipherCtx}); }, kNone, {}},
    {"EcdsaSign", "ECDSASign",
     [](Inputs& in) {
       return Enc<Command::EcdsaSign>(
           {kId100, se05x::EcSignAlgo::Sha256, in.digest32.View(), in.Out(72U)});
     },
     kNone, {}},
    {"EcdsaVerify", "ECDSAVerify",
     [](Inputs& in) {
       return Enc<Command::EcdsaVerify>(
           {kId100, se05x::EcSignAlgo::Sha256, in.digest32.View(), in.sig8.View()});
     },
     kNone, {}},
    {"EddsaSign", "EdDSASign",
     [](Inputs& in) {
       return Enc<Command::EddsaSign>(
           {ObjectId{0x109U}, se05x::EcSignAlgo::Ed25519Pure, in.key16.View(), in.Out(64U)});
     },
     kNone, {}},
    {"Ecdh", "ECDHGenerateSharedSecret",
     [](Inputs& in) {
       return Enc<Command::EcdhGenerateSharedSecret>(
           {kId100, se05x::EcdhAlgo::SvdpDhPlain, ByteSpan{in.point}, in.Out(32U)});
     },
     kNone, {}},
    {"RsaSign", "RSASign",
     [](Inputs& in) {
       return Enc<Command::RsaSign>(
           {kRsa, se05x::RsaSignAlgo::Sha256Pss, in.digest32.View(), in.Out(512U)});
     },
     kNone, {}},
    {"RsaEncrypt", "RSAEncrypt",
     [](Inputs& in) {
       return Enc<Command::RsaEncrypt>(
           {kRsa, se05x::RsaCryptAlgo::Pkcs1Oaep, in.key16.View(), in.Out(512U)});
     },
     kNone, {}},
    // CipherInit with an IV from the host: the builder reads a response only for an IV the chip
    // generates; with an external IV it sends case 3, as ours does.
    {"CipherInit", "CipherInit",
     [](Inputs& in) { return Enc<Command::CipherInit>({kCipherCtx, kAes, in.iv16.View(), true}); },
     kLeDiffers, {}},
    {"CipherUpdate", "CipherUpdate",
     [](Inputs& in) {
       return Enc<Command::CipherUpdate>({kCipherCtx, in.key16.View(), in.Out(32U)});
     },
     kNone, {}},
    {"CipherFinal", "CipherFinal",
     [](Inputs& in) {
       return Enc<Command::CipherFinal>({kCipherCtx, in.key16.View(), in.Out(32U)});
     },
     kNone, {}},
    {"CipherOneShot", "CipherOneShot",
     [](Inputs& in) {
       return Enc<Command::CipherOneShot>({kAes, se05x::CipherMode::AesCbcNoPad, in.iv16.View(),
                                           true, in.key16.View(), in.Out(32U)});
     },
     kNone, {}},
    {"MacInit", "MACInit", &MacInit, kNone, {}},
    {"MacUpdate", "MACUpdate",
     [](Inputs& in) { return Enc<Command::MacUpdate>({kMacCtx, in.key16.View()}); }, kNone, {}},
    {"MacOneShot", "MACOneShot_G", &MacOneShot, kNone, {}},
    {"Hkdf", "HKDF_Extended", &Hkdf, kNone, {}},
    {"Pbkdf2", "PBKDF2_extended", &Pbkdf2, kNone, {}},
    {"DigestInit", "DigestInit", [](Inputs&) { return Enc<Command::DigestInit>({kDigestCtx}); },
     kNone, {}},
    {"DigestUpdate", "DigestUpdate",
     [](Inputs& in) { return Enc<Command::DigestUpdate>({kDigestCtx, in.key16.View()}); }, kNone,
     {}},
    {"DigestOneShot", "DigestOneShot",
     [](Inputs& in) {
       return Enc<Command::DigestOneShot>({se05x::DigestMode::Sha256, in.key16.View(), in.Out(32U)});
     },
     kNone, {}},
    {"TlsGenerateRandom", "TLSGenerateRandom",
     [](Inputs& in) { return Enc<Command::TlsGenerateRandom>({in.Out(32U)}); }, kNone, {}},
    // TLSPerformPRF: P2 names which random the host passes (AN12543 4.17.3). The harness passed
    // the client hello random (P2_TLS_PRF_CLI_HELLO 0x4B): the server role of `TlsPrfArgs::role`.
    {"TlsPrf", "TLSPerformPRF", &TlsPrf, kNone, {}},
    {"DfDiversify", "DFDiversifyKey",
     [](Inputs& in) {
       return Enc<Command::DfDiversifyKey>(
           {kId100, ObjectId{0x200U}, in.user_id.View().first(3U), MutableByteSpan{}});
     },
     kNone, {}},
    {"DfKill", "DFKillAuthentication", [](Inputs&) { return Enc<Command::DfKillAuthentication>({}); },
     kNone, {}},
    {"DfDump", "DFDumpSessionKeys",
     [](Inputs& in) {
       return Enc<Command::DfDumpSessionKeys>({ObjectId{}, ObjectId{}, ByteSpan{}, in.Out(38U)});
     },
     kNone, {}},
}};
// clang-format on

/// A body without the TLV with `tag` when its value is `value` (or any value when `value` is
/// empty); returns the length written to `out`.
std::size_t Without(ByteSpan body, uint8_t tag, ByteSpan value, std::span<uint8_t> out) {
  se05x::apdu::TlvReader reader(body);
  std::size_t pos = 0U;
  std::size_t n = 0U;
  for (std::size_t guard = 0U; (guard < 32U) && !reader.AtEnd(); ++guard) {
    const auto tlv = reader.Next();
    if (!tlv.ok()) {
      break;
    }
    const std::size_t next =
        static_cast<std::size_t>(tlv.value.value.data() - body.data()) + tlv.value.value.size();
    const bool drop =
        (tlv.value.tag == tag) &&
        (value.empty() || ((tlv.value.value.size() == value.size()) &&
                           (SameBytes(tlv.value.value.data(), value.data(), value.size()))));
    if (!drop) {
      for (std::size_t i = pos; i < next; ++i) {
        out[n++] = body[i];
      }
    }
    pos = next;
  }
  return n;
}

const oracle::Layout* LayoutOf(const char* name) {
  for (const oracle::Layout& l : oracle::kLayouts) {
    if (std::strcmp(l.name, name) == 0) {
      return &l;
    }
  }
  return nullptr;
}

/// Compare one entry with one recorded command; prints the first difference.
bool Same(const Entry& e, const oracle::Apdu& o, const Encoded& ours) {
  if (ours.length == 0U) {
    static_cast<void>(std::printf("    %s: the codec refused the inputs\n", e.name));
    return false;
  }
  const std::array<uint8_t, 4> want = ((e.fixes & kHeaderDiffers) != 0U) ? e.header : o.header;
  if (!SameBytes(want.data(), ours.bytes.data(), 4U)) {
    static_cast<void>(std::printf("    %s: header %02X %02X %02X %02X\n", e.name, ours.bytes[0],
                                  ours.bytes[1], ours.bytes[2], ours.bytes[3]));
    return false;
  }
  const Parts p = Split(ours);
  std::array<uint8_t, 600> a{};
  std::array<uint8_t, 600> b{};
  const std::size_t na = ((e.fixes & kStripPolicy) != 0U)
                             ? Without(p.body, se05x::apdu::kTagPolicy, ByteSpan{}, a)
                             : Without(p.body, 0x00U, ByteSpan{}, a);
  std::size_t nb = Without(o.body, 0x00U, ByteSpan{}, b);
  if ((e.fixes & kOracleVersion0) != 0U) {
    const std::array<uint8_t, 4> zero{};
    std::array<uint8_t, 600> c{};
    nb = Without(ByteSpan{b}.first(nb), se05x::apdu::kTag11, ByteSpan{zero}, c);
    b = c;
  }
  if ((e.fixes & kOracleRsaNa) != 0U) {
    const std::array<uint8_t, 1> na_component{0xFFU};
    std::array<uint8_t, 600> c{};
    nb = Without(ByteSpan{b}.first(nb), se05x::apdu::kTag2, ByteSpan{na_component}, c);
    b = c;
  }
  if ((na != nb) || (!SameBytes(a.data(), b.data(), na))) {
    static_cast<void>(std::printf("    %s: body differs (%zu vs %zu bytes)\n", e.name, na, nb));
    return false;
  }
  const oracle::Layout* l = LayoutOf(e.layout);
  const bool response = (l != nullptr) && l->expects_response;
  const bool le_ok =
      ((e.fixes & kLeDiffers) != 0U) ? (p.has_le != response) : (p.has_le == response);
  if (!le_ok || (o.has_le && !p.has_le)) {
    static_cast<void>(std::printf("    %s: Le %d, the builder reads a response: %d\n", e.name,
                                  p.has_le ? 1 : 0, response ? 1 : 0));
    return false;
  }
  return true;
}

/// The recorded command of a name in one generation, or null when that generation has none.
template <std::size_t N>
const oracle::Apdu* Find(const std::array<std::pair<const char*, const oracle::Apdu*>, N>& set,
                         const char* name) {
  for (const auto& [n, a] : set) {
    if (std::strcmp(n, name) == 0) {
      return a;
    }
  }
  return nullptr;
}

#define ORACLE_ROW(ns, x)                                                                          \
  std::pair<const char*, const oracle::Apdu*> {                                                    \
    #x, &oracle::ns::k##x                                                                          \
  }

constexpr std::array<std::pair<const char*, const oracle::Apdu*>, 62> kV7{{
    ORACLE_ROW(v7, GetVersion),
    ORACLE_ROW(v7, ReadState),
    ORACLE_ROW(v7, GetRandom),
    ORACLE_ROW(v7, GetFreeMemory),
    ORACLE_ROW(v7, CreateSession),
    ORACLE_ROW(v7, VerifyUserId),
    ORACLE_ROW(v7, SetLockState),
    ORACLE_ROW(v7, DisableObjCreation),
    ORACLE_ROW(v7, DeleteAll),
    ORACLE_ROW(v7, WriteEcKeyPair),
    ORACLE_ROW(v7, WriteEcPublic),
    ORACLE_ROW(v7, WriteSymmKey),
    ORACLE_ROW(v7, WriteSymmKeyTransient),
    ORACLE_ROW(v7, WriteBinaryCreate),
    ORACLE_ROW(v7, WriteBinaryOffset),
    ORACLE_ROW(v7, WriteBinaryLong),
    ORACLE_ROW(v7, WriteUserId),
    ORACLE_ROW(v7, CreateCounter),
    ORACLE_ROW(v7, SetCounterValue),
    ORACLE_ROW(v7, IncCounter),
    ORACLE_ROW(v7, WritePcr),
    ORACLE_ROW(v7, ExtendPcr),
    ORACLE_ROW(v7, ReadObject),
    ORACLE_ROW(v7, ReadObjectPart),
    ORACLE_ROW(v7, ReadObjectAttested),
    ORACLE_ROW(v7, ExportObject),
    ORACLE_ROW(v7, ImportObject),
    ORACLE_ROW(v7, ReadType),
    ORACLE_ROW(v7, ReadSize),
    ORACLE_ROW(v7, ReadIdList),
    ORACLE_ROW(v7, CheckObjectExists),
    ORACLE_ROW(v7, DeleteSecureObject),
    ORACLE_ROW(v7, CreateEcCurve),
    ORACLE_ROW(v7, GetEcCurveId),
    ORACLE_ROW(v7, ReadEcCurveList),
    ORACLE_ROW(v7, DeleteEcCurve),
    ORACLE_ROW(v7, CreateCryptoObject),
    ORACLE_ROW(v7, ReadCryptoObjectList),
    ORACLE_ROW(v7, DeleteCryptoObject),
    ORACLE_ROW(v7, EcdsaSign),
    ORACLE_ROW(v7, EcdsaVerify),
    ORACLE_ROW(v7, EddsaSign),
    ORACLE_ROW(v7, Ecdh),
    ORACLE_ROW(v7, RsaSign),
    ORACLE_ROW(v7, RsaEncrypt),
    ORACLE_ROW(v7, CipherInit),
    ORACLE_ROW(v7, CipherUpdate),
    ORACLE_ROW(v7, CipherFinal),
    ORACLE_ROW(v7, CipherOneShot),
    ORACLE_ROW(v7, MacInit),
    ORACLE_ROW(v7, MacUpdate),
    ORACLE_ROW(v7, MacOneShot),
    ORACLE_ROW(v7, Hkdf),
    ORACLE_ROW(v7, Pbkdf2),
    ORACLE_ROW(v7, DigestInit),
    ORACLE_ROW(v7, DigestUpdate),
    ORACLE_ROW(v7, DigestOneShot),
    ORACLE_ROW(v7, TlsGenerateRandom),
    ORACLE_ROW(v7, TlsPrf),
    ORACLE_ROW(v7, DfDiversify),
    ORACLE_ROW(v7, DfKill),
    ORACLE_ROW(v7, DfDump),
}};
// ReadState and DisableObjCreation are 7.x commands: the 3.x build has no builder for them.
constexpr std::array<std::pair<const char*, const oracle::Apdu*>, 60> kV3{{
    ORACLE_ROW(v3, GetVersion),
    ORACLE_ROW(v3, GetRandom),
    ORACLE_ROW(v3, GetFreeMemory),
    ORACLE_ROW(v3, CreateSession),
    ORACLE_ROW(v3, VerifyUserId),
    ORACLE_ROW(v3, SetLockState),
    ORACLE_ROW(v3, DeleteAll),
    ORACLE_ROW(v3, WriteEcKeyPair),
    ORACLE_ROW(v3, WriteEcPublic),
    ORACLE_ROW(v3, WriteSymmKey),
    ORACLE_ROW(v3, WriteSymmKeyTransient),
    ORACLE_ROW(v3, WriteBinaryCreate),
    ORACLE_ROW(v3, WriteBinaryOffset),
    ORACLE_ROW(v3, WriteBinaryLong),
    ORACLE_ROW(v3, WriteUserId),
    ORACLE_ROW(v3, CreateCounter),
    ORACLE_ROW(v3, SetCounterValue),
    ORACLE_ROW(v3, IncCounter),
    ORACLE_ROW(v3, WritePcr),
    ORACLE_ROW(v3, ExtendPcr),
    ORACLE_ROW(v3, ReadObject),
    ORACLE_ROW(v3, ReadObjectPart),
    ORACLE_ROW(v3, ReadObjectAttested),
    ORACLE_ROW(v3, ExportObject),
    ORACLE_ROW(v3, ImportObject),
    ORACLE_ROW(v3, ReadType),
    ORACLE_ROW(v3, ReadSize),
    ORACLE_ROW(v3, ReadIdList),
    ORACLE_ROW(v3, CheckObjectExists),
    ORACLE_ROW(v3, DeleteSecureObject),
    ORACLE_ROW(v3, CreateEcCurve),
    ORACLE_ROW(v3, GetEcCurveId),
    ORACLE_ROW(v3, ReadEcCurveList),
    ORACLE_ROW(v3, DeleteEcCurve),
    ORACLE_ROW(v3, CreateCryptoObject),
    ORACLE_ROW(v3, ReadCryptoObjectList),
    ORACLE_ROW(v3, DeleteCryptoObject),
    ORACLE_ROW(v3, EcdsaSign),
    ORACLE_ROW(v3, EcdsaVerify),
    ORACLE_ROW(v3, EddsaSign),
    ORACLE_ROW(v3, Ecdh),
    ORACLE_ROW(v3, RsaSign),
    ORACLE_ROW(v3, RsaEncrypt),
    ORACLE_ROW(v3, CipherInit),
    ORACLE_ROW(v3, CipherUpdate),
    ORACLE_ROW(v3, CipherFinal),
    ORACLE_ROW(v3, CipherOneShot),
    ORACLE_ROW(v3, MacInit),
    ORACLE_ROW(v3, MacUpdate),
    ORACLE_ROW(v3, MacOneShot),
    ORACLE_ROW(v3, Hkdf),
    ORACLE_ROW(v3, Pbkdf2),
    ORACLE_ROW(v3, DigestInit),
    ORACLE_ROW(v3, DigestUpdate),
    ORACLE_ROW(v3, DigestOneShot),
    ORACLE_ROW(v3, TlsGenerateRandom),
    ORACLE_ROW(v3, TlsPrf),
    ORACLE_ROW(v3, DfDiversify),
    ORACLE_ROW(v3, DfKill),
    ORACLE_ROW(v3, DfDump),
}};

#undef ORACLE_ROW

template <std::size_t N>
std::size_t CheckAll(const std::array<std::pair<const char*, const oracle::Apdu*>, N>& set,
                     const char* generation) {
  Inputs in;
  std::size_t compared = 0U;
  for (const Entry& e : kEntries) {
    const oracle::Apdu* o = Find(set, e.name);
    if (o == nullptr) {
      continue;
    }
    const bool ok = Same(e, *o, e.encode(in));
    if (!ok) {
      static_cast<void>(std::printf("    (%s)\n", generation));
    }
    CHECK(ok);
    compared += ok ? 1U : 0U;
  }
  return compared;
}

} // namespace

TEST_CASE("Applet 7.2: every recorded command, header and body byte for byte") {
  CHECK_EQ(CheckAll(kV7, "7.2"), kV7.size());
}

TEST_CASE("Applet 3.x: every recorded command, header and body byte for byte") {
  CHECK_EQ(CheckAll(kV3, "3.x"), kV3.size());
}

TEST_CASE("The oracle comparison catches a one-byte change of our output") {
  Inputs in;
  const Entry& e = kEntries[2]; // GetRandom: 80 04 00 49, 41 02 00 20
  REQUIRE(std::strcmp(e.name, "GetRandom") == 0);
  Encoded ours = e.encode(in);
  CHECK(Same(e, oracle::v7::kGetRandom, ours));
  ours.bytes[ours.length - 2U] ^= 0x01U; // the last byte of the TLV body
  CHECK(!Same(e, oracle::v7::kGetRandom, ours));
  ours = e.encode(in);
  ours.bytes[3] = 0x48U; // P2
  CHECK(!Same(e, oracle::v7::kGetRandom, ours));
  ours = e.encode(in);
  ours.length -= 1U; // no Le
  CHECK(!Same(e, oracle::v7::kGetRandom, ours));
}
