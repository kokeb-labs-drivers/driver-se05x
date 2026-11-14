/**
 * @file test_policy.cpp
 * @brief The generation-typed policy builder, the rule tables (AN12413 Table 11, AN12543 Table 15),
 * the header bits (AN12413 Table 50, AN12543 Table 63), the worked examples of AN12543 3.7.1.2 and
 * 3.7.1.3, the session policy (Table 62), and the read-back of policies and attributes.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <array>
#include <cstdint>
#include <utility>

#include "se05x_objects.hpp"
#include "se05x_policy.hpp"
#include "test_apdu_util.hpp"

namespace {

using se05x::AppletGeneration;
using se05x::AuthObject;
using se05x::ByteSpan;
using se05x::Error;
using se05x::ObjectClass;
using se05x::ObjectId;
using se05x::OpenReason;
using se05x::PolicyBuilder;
using se05x::Profile;
using se05x::Rule;
using se05x::RuleAllowedFor;

constexpr AppletGeneration kV3 = AppletGeneration::V3;
constexpr AppletGeneration kV7 = AppletGeneration::V7;

// The header bit of each Rule, written from AN12543 Table 63 (applet 7.x), in enumerator order.
constexpr std::array<uint32_t, 29> kV7Bits{0x20000000U,
                                           0x10000000U,
                                           0x08000000U,
                                           0x04000000U,
                                           0x02000000U,
                                           0x01000000U,
                                           0U /* Kdf: not on 7.x */,
                                           0x00400000U,
                                           0x00200000U,
                                           0x00100000U,
                                           0x00080000U,
                                           0x00040000U,
                                           0x00020000U,
                                           0x00010000U,
                                           0x00008000U,
                                           0x00004000U,
                                           0x00002000U,
                                           0x00001000U,
                                           0x00000800U,
                                           0x00000400U,
                                           0x80000000U,
                                           0x40000000U,
                                           0x00800000U,
                                           0x00000200U,
                                           0x00000100U,
                                           0x00000080U,
                                           0x00000040U,
                                           0x00000020U,
                                           0x00000010U};
// The header bit of each Rule on applet 3.x, from AN12413 Table 50 (B1b6 = 0x20000000 ...).
constexpr std::array<uint32_t, 18> kV3Bits{
    0x20000000U, 0x10000000U, 0x08000000U, 0x04000000U, 0x02000000U, 0x01000000U,
    0x00800000U, 0x00400000U, 0x00200000U, 0x00100000U, 0x00080000U, 0x00040000U,
    0x00020000U, 0x00010000U, 0x00008000U, 0x00004000U, 0x00002000U, 0x00001000U};

uint32_t Header(const se05x::Policy& p) {
  const ByteSpan b = p.Bytes();
  return (b.size() < 9U)
             ? 0U
             : ((static_cast<uint32_t>(b[5]) << 24U) | (static_cast<uint32_t>(b[6]) << 16U) |
                (static_cast<uint32_t>(b[7]) << 8U) | static_cast<uint32_t>(b[8]));
}

/// The header an Open policy with only rule R gets, or 0 when R does not exist for (G, C) or
/// needs an extension.
template <AppletGeneration G, ObjectClass C, Rule R>
uint32_t SingleRuleHeader() {
  if constexpr (RuleAllowedFor(G, C, R) && (R != Rule::RequirePcrValue) &&
                (R != Rule::DerivedInput) && (R != Rule::DesfireChangeKey)) {
    const auto p = PolicyBuilder<G, C, Profile::Open>{}
                       .ForAllOthers()
                       .template Allow<R>()
                       .WithReason(OpenReason::Laboratory)
                       .Build();
    return p.ok() ? Header(p.value) : 0xFFFFFFFFU;
  } else {
    return 0U;
  }
}

template <AppletGeneration G, ObjectClass C, std::size_t... I>
std::array<uint32_t, sizeof...(I)> AllHeaders(std::index_sequence<I...> /*unused*/) {
  return {SingleRuleHeader<G, C, static_cast<Rule>(static_cast<uint8_t>(I))>()...};
}

} // namespace

TEST_CASE("Applet 3.x rule table per class (AN12413 Table 11)") {
  CHECK(RuleAllowedFor(kV3, ObjectClass::EcKeyPair, Rule::Read));
  CHECK(RuleAllowedFor(kV3, ObjectClass::EcKeyPair, Rule::Attestation));
  CHECK(RuleAllowedFor(kV3, ObjectClass::RsaPubKey, Rule::Wrap));
  CHECK(!RuleAllowedFor(kV3, ObjectClass::EcKeyPair, Rule::ForbidDerivedOutput));
  CHECK(RuleAllowedFor(kV3, ObjectClass::AesKey, Rule::Kdf));
  CHECK(RuleAllowedFor(kV3, ObjectClass::AesKey, Rule::Gen));
  CHECK(!RuleAllowedFor(kV3, ObjectClass::AesKey, Rule::Read));
  CHECK(!RuleAllowedFor(kV3, ObjectClass::AesKey, Rule::KeyAgreement));
  CHECK(!RuleAllowedFor(kV3, ObjectClass::AesKey, Rule::Attestation));
  CHECK(RuleAllowedFor(kV3, ObjectClass::BinaryFile, Rule::Read));
  CHECK(RuleAllowedFor(kV3, ObjectClass::Counter, Rule::Write));
  CHECK(RuleAllowedFor(kV3, ObjectClass::Pcr, Rule::Delete));
  CHECK(!RuleAllowedFor(kV3, ObjectClass::Pcr, Rule::Sign));
  CHECK(RuleAllowedFor(kV3, ObjectClass::UserId, Rule::Write));
  CHECK(!RuleAllowedFor(kV3, ObjectClass::UserId, Rule::Read));
  CHECK(RuleAllowedFor(kV3, ObjectClass::UserId, Rule::RequireSecureMessaging));
  CHECK(!RuleAllowedFor(kV3, ObjectClass::Curve, Rule::Delete));
  CHECK(!RuleAllowedFor(kV3, ObjectClass::HmacKey, Rule::TlsKdf));
  CHECK(RuleAllowedFor(AppletGeneration::V6, ObjectClass::AesKey, Rule::Kdf)); // the 3.x table
  CHECK(!RuleAllowedFor(kV3, tu::NotAnEnumerator<ObjectClass>(14U), Rule::Delete));
  CHECK(!RuleAllowedFor(kV3, ObjectClass::AesKey, tu::NotAnEnumerator<Rule>(29U)));
}

TEST_CASE("Applet 7.x rule table per class (AN12543 Table 15)") {
  for (const ObjectClass c : {ObjectClass::EcKeyPair, ObjectClass::RsaPrivKey, ObjectClass::AesKey,
                              ObjectClass::BinaryFile, ObjectClass::UserId, ObjectClass::Pcr}) {
    CHECK(RuleAllowedFor(kV7, c, Rule::Read));
    CHECK(RuleAllowedFor(kV7, c, Rule::Write));
    CHECK(RuleAllowedFor(kV7, c, Rule::ForbidAll));
    CHECK(RuleAllowedFor(kV7, c, Rule::RequirePcrValue));
  }
  CHECK(RuleAllowedFor(kV7, ObjectClass::AesKey, Rule::Hkdf));
  CHECK(RuleAllowedFor(kV7, ObjectClass::HmacKey, Rule::TlsPms));
  CHECK(RuleAllowedFor(kV7, ObjectClass::DesKey, Rule::UsageAsHmacPepper));
  CHECK(!RuleAllowedFor(kV7, ObjectClass::AesKey, Rule::Kdf));
  CHECK(!RuleAllowedFor(kV7, ObjectClass::AesKey, Rule::Gen));
  CHECK(!RuleAllowedFor(kV7, ObjectClass::AesKey, Rule::KeyAgreement));
  CHECK(RuleAllowedFor(kV7, ObjectClass::EcKeyPair, Rule::Gen));
  CHECK(RuleAllowedFor(kV7, ObjectClass::EcKeyPair, Rule::KeyAgreement));
  CHECK(RuleAllowedFor(kV7, ObjectClass::EcKeyPair, Rule::ForbidDerivedOutput));
  CHECK(RuleAllowedFor(kV7, ObjectClass::EcPubKey, Rule::DerivedInput));
  CHECK(!RuleAllowedFor(kV7, ObjectClass::EcKeyPair, Rule::Wrap));
  CHECK(!RuleAllowedFor(kV7, ObjectClass::EcKeyPair, Rule::Kdf));
  CHECK(!RuleAllowedFor(kV7, ObjectClass::EcKeyPair, Rule::Hkdf));
  CHECK(!RuleAllowedFor(kV7, ObjectClass::BinaryFile, Rule::Sign));
  CHECK(!RuleAllowedFor(kV7, ObjectClass::UserId, Rule::Gen));
  CHECK(!RuleAllowedFor(kV7, ObjectClass::Curve, Rule::Read));
}

TEST_CASE("Every applet 7.x rule has the header bit of AN12543 Table 63") {
  const auto aes = AllHeaders<kV7, ObjectClass::AesKey>(std::make_index_sequence<29>{});
  const auto ec = AllHeaders<kV7, ObjectClass::EcKeyPair>(std::make_index_sequence<29>{});
  for (std::size_t i = 0U; i < kV7Bits.size(); ++i) {
    const uint32_t got = (aes[i] != 0U) ? aes[i] : ec[i];
    const bool special = (i == 13U) || (i == 23U) || (i == 24U) || (i == 6U); // extensions, Kdf
    if (!special) {
      CHECK_EQ(got, kV7Bits[i]);
    }
  }
  CHECK_EQ(aes[22], 0x00800000U); // Hkdf, ALLOW_KDF on 7.x
}

TEST_CASE("Every applet 3.x rule has the header bit of AN12413 Table 50") {
  const auto ec = AllHeaders<kV3, ObjectClass::EcKeyPair>(std::make_index_sequence<18>{});
  const auto aes = AllHeaders<kV3, ObjectClass::AesKey>(std::make_index_sequence<18>{});
  for (std::size_t i = 0U; i < kV3Bits.size(); ++i) {
    const uint32_t got = (ec[i] != 0U) ? ec[i] : aes[i];
    if (i != 13U) { // REQUIRE_PCR_VALUE needs its extension
      CHECK_EQ(got, kV3Bits[i]);
    }
  }
}

TEST_CASE("Strict needs explicit write, delete and generate refusals, and secure messaging") {
  const auto ok = PolicyBuilder<kV7, ObjectClass::EcKeyPair>{}
                      .For(AuthObject{ObjectId{0x7FFF0001U}})
                      .Allow<Rule::Sign>()
                      .RequireSecureMessaging()
                      .Forbid<Rule::Write>()
                      .Forbid<Rule::Delete>()
                      .Forbid<Rule::Gen>()
                      .Build();
  REQUIRE(ok.ok());
  CHECK(tu::Same(ok.value.Bytes(), tu::Hex("08 7F FF 00 01 10 02 00 00").View()));
  CHECK(ok.value.Generation() == kV7);
  CHECK(ok.value.GetProfile() == Profile::Strict);
  const auto no_gen = PolicyBuilder<kV7, ObjectClass::EcKeyPair>{}
                          .For(AuthObject{ObjectId{0x7FFF0001U}})
                          .Allow<Rule::Sign>()
                          .RequireSecureMessaging()
                          .Forbid<Rule::Write>()
                          .Forbid<Rule::Delete>()
                          .Build();
  CHECK_EQ(no_gen.error, Error::InvalidArgument);
  const auto no_sm = PolicyBuilder<kV7, ObjectClass::EcKeyPair>{}
                         .ForAllOthers()
                         .Allow<Rule::Sign>()
                         .Forbid<Rule::Write>()
                         .Forbid<Rule::Delete>()
                         .Forbid<Rule::Gen>()
                         .Build();
  CHECK_EQ(no_sm.error, Error::InvalidArgument);
  // A 7.x AES key has no GEN: write and delete suffice.
  const auto aes = PolicyBuilder<kV7, ObjectClass::AesKey>{}
                       .ForAllOthers()
                       .Allow<Rule::Encrypt>()
                       .RequireSecureMessaging()
                       .Forbid<Rule::Write>()
                       .Forbid<Rule::Delete>()
                       .Build();
  CHECK(aes.ok());
  const auto export_key = PolicyBuilder<kV7, ObjectClass::AesKey>{}
                              .ForAllOthers()
                              .Allow<Rule::ImportExport>()
                              .RequireSecureMessaging()
                              .Forbid<Rule::Write>()
                              .Forbid<Rule::Delete>()
                              .Build();
  CHECK_EQ(export_key.error, Error::InvalidArgument);
  // A public key needs no secure messaging; a policy that grants nothing needs no refusals.
  const auto pub = PolicyBuilder<kV7, ObjectClass::EcPubKey>{}
                       .ForAllOthers()
                       .Allow<Rule::Verify>()
                       .Forbid<Rule::Write>()
                       .Forbid<Rule::Delete>()
                       .Forbid<Rule::Gen>()
                       .Build();
  CHECK(pub.ok());
  CHECK((PolicyBuilder<kV7, ObjectClass::EcKeyPair>{}.ForAllOthers().Build().ok()));
}

TEST_CASE("Open needs a reason; contradictions and private reads are refused in any profile") {
  const auto no_reason = PolicyBuilder<kV7, ObjectClass::AesKey, Profile::Open>{}
                             .ForAllOthers()
                             .Allow<Rule::ImportExport>()
                             .Build();
  CHECK_EQ(no_reason.error, Error::InvalidArgument);
  const auto with_reason = PolicyBuilder<kV7, ObjectClass::AesKey, Profile::Open>{}
                               .ForAllOthers()
                               .Allow<Rule::ImportExport>()
                               .WithReason(OpenReason::TransientScratch)
                               .Build();
  CHECK(with_reason.ok());
  CHECK(with_reason.value.GetProfile() == Profile::Open);
  const auto both = PolicyBuilder<kV7, ObjectClass::AesKey, Profile::Open>{}
                        .ForAllOthers()
                        .Allow<Rule::Encrypt>()
                        .Forbid<Rule::Encrypt>()
                        .WithReason(OpenReason::Laboratory)
                        .Build();
  CHECK_EQ(both.error, Error::InvalidArgument);
  const auto forbid_all_and_more = PolicyBuilder<kV7, ObjectClass::AesKey, Profile::Open>{}
                                       .ForAllOthers()
                                       .Allow<Rule::ForbidAll>()
                                       .Allow<Rule::Encrypt>()
                                       .WithReason(OpenReason::Laboratory)
                                       .Build();
  CHECK_EQ(forbid_all_and_more.error, Error::InvalidArgument);
  const auto forbid_all =
      PolicyBuilder<kV7, ObjectClass::AesKey>{}.ForAllOthers().Allow<Rule::ForbidAll>().Build();
  CHECK(forbid_all.ok() &&
        tu::Same(forbid_all.value.Bytes(), tu::Hex("08 00 00 00 00 20 00 00 00").View()));
  const auto private_read = PolicyBuilder<kV3, ObjectClass::EcPrivKey, Profile::Open>{}
                                .ForAllOthers()
                                .Allow<Rule::Read>()
                                .WithReason(OpenReason::Laboratory)
                                .Build();
  CHECK_EQ(private_read.error, Error::InvalidArgument);
  const auto pair_read = PolicyBuilder<kV3, ObjectClass::EcKeyPair, Profile::Open>{}
                             .ForAllOthers()
                             .Allow<Rule::Read>()
                             .WithReason(OpenReason::Laboratory)
                             .Build();
  CHECK(pair_read.ok());
}

TEST_CASE("Policy sets: the examples of AN12543 3.7.1.2 and 3.7.1.3 byte for byte") {
  const auto two = PolicyBuilder<kV7, ObjectClass::EcPubKey, Profile::Open>{}
                       .ForAllOthers()
                       .Allow<Rule::Write>()
                       .Allow<Rule::Delete>()
                       .For(AuthObject{ObjectId{0x11111111U}})
                       .Allow<Rule::Sign>()
                       .Allow<Rule::Verify>()
                       .WithReason(OpenReason::Laboratory)
                       .Build();
  REQUIRE(two.ok());
  CHECK(tu::Same(two.value.Bytes(),
                 tu::Hex("08 00 00 00 00 00 14 00 00 08 11 11 11 11 18 00 00 00").View()));
  const tu::Bytes pcr =
      tu::Hex("00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77 "
              "88 99 AA BB CC DD EE FF");
  const auto with_pcr = PolicyBuilder<kV7, ObjectClass::BinaryFile>{}
                            .For(AuthObject{ObjectId{0x7FFF0000U}})
                            .Allow<Rule::Read>()
                            .RequirePcr(ObjectId{0x4FFFF000U}, pcr.View())
                            .Build();
  REQUIRE(with_pcr.ok());
  CHECK(tu::Same(
      with_pcr.value.Bytes(),
      tu::Hex("2C 7F FF 00 00 00 21 00 00 4F FF F0 00 00 11 22 33 44 55 66 77 88 99 AA BB CC DD "
              "EE FF 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF")
          .View()));
  const auto short_pcr = PolicyBuilder<kV7, ObjectClass::BinaryFile>{}
                             .ForAllOthers()
                             .RequirePcr(ObjectId{0x4FFFF000U}, pcr.View().first(31U))
                             .Build();
  CHECK_EQ(short_pcr.error, Error::InvalidArgument);
  const auto bare_pcr = PolicyBuilder<kV7, ObjectClass::BinaryFile>{}
                            .ForAllOthers()
                            .Allow<Rule::RequirePcrValue>()
                            .Build();
  CHECK_EQ(bare_pcr.error, Error::PolicyInvalid);
}

TEST_CASE("Chip rules: unique authentication objects, at most 8 policies, no extension rules") {
  const auto dup = PolicyBuilder<kV7, ObjectClass::BinaryFile>{}
                       .For(AuthObject{ObjectId{0x10U}})
                       .Allow<Rule::Read>()
                       .For(AuthObject{ObjectId{0x10U}})
                       .Allow<Rule::Write>()
                       .Build();
  CHECK_EQ(dup.error, Error::PolicyInvalid);
  using BinV7 = PolicyBuilder<kV7, ObjectClass::BinaryFile>;
  CHECK_EQ(BinV7{}.For(AuthObject{ObjectId{0U}}).Build().error, Error::InvalidArgument);
  CHECK_EQ(BinV7{}.Allow<Rule::Read>().Build().error, Error::InvalidArgument);
  CHECK_EQ(BinV7{}.Build().error, Error::InvalidArgument);
  BinV7 many{};
  for (uint32_t i = 1U; i <= 8U; ++i) {
    many.For(AuthObject{ObjectId{i}}).Allow<Rule::Read>();
  }
  const auto eight = many.Build();
  CHECK(eight.ok());
  CHECK_EQ(eight.value.Bytes().size(), 72U);
  many.For(AuthObject{ObjectId{9U}});
  CHECK_EQ(many.Build().error, Error::PolicyInvalid);
  const auto derived = PolicyBuilder<kV7, ObjectClass::AesKey, Profile::Open>{}
                           .ForAllOthers()
                           .Allow<Rule::DerivedInput>()
                           .WithReason(OpenReason::Laboratory)
                           .Build();
  CHECK_EQ(derived.error, Error::PolicyInvalid);
  const auto six = PolicyBuilder<AppletGeneration::V6, ObjectClass::BinaryFile>{}
                       .ForAllOthers()
                       .Allow<Rule::Read>()
                       .Build();
  CHECK_EQ(six.error, Error::Unsupported);
}

TEST_CASE("Session policies: the empty one is 02 0000, extensions in header order (Table 62)") {
  const auto empty = se05x::EncodeSessionPolicy(se05x::SessionPolicy{});
  CHECK(empty.ok() && tu::Same(empty.value.View(), tu::Hex("02 00 00").View()));
  const auto all = se05x::EncodeSessionPolicy(se05x::SessionPolicy{0x0010U, 0x003CU, true});
  CHECK(tu::Same(all.value.View(), tu::Hex("06 E0 00 00 10 00 3C").View()));
  const auto time_only = se05x::EncodeSessionPolicy(se05x::SessionPolicy{0U, 0x0102U, false});
  CHECK(tu::Same(time_only.value.View(), tu::Hex("04 40 00 01 02").View()));
  const auto refresh = se05x::EncodeSessionPolicy(se05x::SessionPolicy{0U, 0U, true});
  CHECK(tu::Same(refresh.value.View(), tu::Hex("02 20 00").View()));
}

TEST_CASE("ValidatePolicyBytes: lengths, extensions, RFU bits, duplicates, exact fill") {
  using se05x::ValidatePolicyBytes;
  struct Case {
    const char* hex;
    Error want;
  };
  const Case cases[] = {
      {"", Error::Ok},
      {"08 00 00 00 00 00 14 00 00 08 11 11 11 11 18 00 00 00", Error::Ok},
      {"07 00 00 00 00 00 14 00", Error::PolicyInvalid},
      {"08 00 00 00 00 00 01 00 00", Error::PolicyInvalid},  // PCR bit without its extension
      {"08 00 00 00 00 00 00 00 01", Error::PolicyInvalid},  // RFU bit
      {"0C 00 00 00 00 00 00 02 00 00 00 00 05", Error::Ok}, // DESFire change key + 4 bytes
      {"08 00 00 00 10 10 00 00 00 08 00 00 00 10 08 00 00 00", Error::PolicyInvalid}, // duplicate
      {"08 00 00 00 00 10 00 00 00 00", Error::PolicyInvalid}, // a trailing byte
      {"09 00 00 00 00 10 00 00 00", Error::PolicyInvalid},    // runs past the end
      {"35 00 00 00 00 00 01 00 00", Error::PolicyInvalid},    // longer than 52
  };
  for (const Case& c : cases) {
    const tu::Bytes b = tu::Hex(c.hex);
    CHECK_EQ(ValidatePolicyBytes(b.View()), c.want);
  }
}

TEST_CASE("ParseObjectAttributes: applet 7.x and 3.x layouts, attempts, malformed blocks") {
  using se05x::ParseObjectAttributes;
  const tu::Bytes v7 = tu::Hex(
      "00 00 01 00 29 01 00 10 00 00 00 00 00 00 08 7F FF 00 01 10 02 00 00 02 00 00 00 05");
  const auto a = ParseObjectAttributes(v7.View());
  REQUIRE(a.ok());
  CHECK(a.value.object_class == ObjectClass::EcKeyPair);
  CHECK(a.value.origin == se05x::Origin::Internal);
  CHECK_EQ(a.value.version, 5U);
  CHECK_EQ(a.value.policy.length, 9U);
  CHECK_EQ(a.value.max_attempts, 0U);
  const tu::Bytes v3 = tu::Hex("00 00 02 00 0C 02 00 01 7F FF 02 01 00 05 01");
  const auto b = ParseObjectAttributes(v3.View());
  REQUIRE(b.ok());
  CHECK(b.value.object_class == ObjectClass::UserId);
  CHECK(b.value.origin == se05x::Origin::External);
  CHECK_EQ(b.value.max_attempts, 5U);
  CHECK_EQ(b.value.attempts_left, 4U);
  CHECK_EQ(b.value.authentication.value, 0x7FFF0201U);
  CHECK_EQ(b.value.version, 0U);
  const tu::Bytes unlimited = tu::Hex("00 00 02 00 0C 02 00 03 00 00 00 00 00 00 01");
  CHECK_EQ(ParseObjectAttributes(unlimited.View()).value.attempts_left, 0xFFFFU);
  const tu::Bytes blocked = tu::Hex("00 00 02 00 0C 02 00 07 00 00 00 00 00 05 01");
  CHECK_EQ(ParseObjectAttributes(blocked.View()).value.attempts_left, 0U);
  for (const char* bad :
       {"00 00 02 00 0C 02 00 01 7F FF 02 01 00 05 04", // origin 4
        "00 00 02 00 0E 02 00 01 7F FF 02 01 00 05 01", // type 0E
        "00 00 02 00 0C 03 00 01 7F FF 02 01 00 05 01", // indicator 3
        "00 00 02 00 0C 02 00 01 7F FF 02 01 00", "",
        "00 00 01 00 29 01 00 10 00 00 00 00 00 00 07 7F FF 00 01 10 02 00 02 00 00 00 05"}) {
    const tu::Bytes x = tu::Hex(bad);
    CHECK_EQ(ParseObjectAttributes(x.View()).error, Error::FrameError);
  }
}
