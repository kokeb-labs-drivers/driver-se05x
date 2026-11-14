/**
 * @file test_gate.cpp
 * @brief The capability gate per variant: SE050 A, B, C, D, E, F; SE051 A, C, H, W at applet 7.2
 * and SE051 at applet 6.0; SE052F. Derivation from the version, AppletConfig (AN12543 Table 8,
 * AN12413 Table 40), the extended feature bits (AN12543 Table 9) and the OEF id (AN12436 Table 2,
 * AN12973 Table 4, SE052 data sheet); command refusals by generation, feature, state and hold.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <array>
#include <cstdint>

#include "se05x_gate.hpp"
#include "test_apdu_util.hpp"
#include "test_harness.hpp"

namespace {

using se05x::AppletInfo;
using se05x::AppletVersion;
using se05x::ByteSpan;
using se05x::Capabilities;
using se05x::Command;
using se05x::Config;
using se05x::Error;
using se05x::Family;
using se05x::gate::Check;
using se05x::gate::Derive;
using se05x::gate::ProbeResult;

// AppletConfig values written from AN12543 Table 8 / AN12413 Table 40 for the variant descriptions
// (design 1.1): A = ECC, B = RSA, C = ECC + RSA, D = A + MIFARE, F = FIPS (no plain RSA).
constexpr uint16_t kCfgA = 0x0001U | 0x0002U | 0x0004U | 0x0008U | 0x0010U | 0x0080U | 0x0100U |
                           0x0200U | 0x0400U | 0x1000U | 0x2000U;
constexpr uint16_t kCfgB =
    0x0010U | 0x0020U | 0x0040U | 0x0080U | 0x0100U | 0x0200U | 0x0400U | 0x1000U | 0x2000U;
constexpr uint16_t kCfgC = 0x3FFFU;
constexpr uint16_t kCfgD = kCfgA | 0x0800U;
constexpr uint16_t kCfgF = 0x0002U | 0x0004U | 0x0008U | 0x0010U | 0x0040U | 0x0080U | 0x0100U |
                           0x0200U | 0x0400U | 0x2000U; // FIPS_MODE_DISABLED clear
constexpr uint16_t kCfg7All = 0x3FFEU;
constexpr uint16_t kCfg052 = 0x26F2U;

/// The extended feature bytes with every operation enabled (AN12543 Table 9).
std::array<uint8_t, se05x::kExtFeatureLength> ExtAll() {
  std::array<uint8_t, se05x::kExtFeatureLength> e{};
  e[2] = 0x01U; // B3b1 RSA
  e[3] = 0x0FU; // B4b4..b1 AEAD, HMAC, DES, AES
  e[4] = 0x01U; // B5b1 HKDF
  e[5] = 0x01U; // B6b1 PBKDF
  e[6] = 0x01U; // B7b1 TLS
  e[7] = 0x01U; // B8b1 digest
  e[8] = 0x01U; // B9b1 DESFire
  return e;
}

Capabilities Caps(uint8_t major, uint8_t minor, uint16_t cfg, ByteSpan ext, uint16_t oef,
                  ProbeResult probe = ProbeResult{}) {
  const AppletInfo info{AppletVersion{major, minor, 0U}, cfg, 0x010BU};
  const auto r = Derive(info, ext, oef, probe);
  if (!r.ok()) {
    static_cast<void>(std::printf("    Derive failed: %s\n", se05x::ToString(r.error)));
  }
  return r.value;
}

bool Allows(const Capabilities& caps, Command c) {
  return Check(caps, Config{}, c) == Error::Ok;
}

} // namespace

TEST_CASE("Derive refuses an unknown applet, a wrong ext length and a contradicting OEF id") {
  const auto ext = ExtAll();
  const ProbeResult none{};
  for (const uint8_t major : {uint8_t{0U}, uint8_t{2U}, uint8_t{4U}, uint8_t{5U}, uint8_t{8U}}) {
    CHECK_EQ(
        Derive(AppletInfo{AppletVersion{major, 0U, 0U}, kCfgC, 0U}, ByteSpan{}, 0U, none).error,
        Error::DeviceIdMismatch);
  }
  const AppletInfo v7{AppletVersion{7U, 2U, 0U}, kCfg7All, 0U};
  const AppletInfo v3{AppletVersion{3U, 6U, 0U}, kCfgC, 0U};
  const AppletInfo v6{AppletVersion{6U, 0U, 0U}, kCfgC, 0U};
  CHECK_EQ(Derive(v7, ByteSpan{}, 0U, none).error, Error::InvalidArgument);
  CHECK_EQ(Derive(v7, ByteSpan{ext}.first(29U), 0U, none).error, Error::InvalidArgument);
  CHECK_EQ(Derive(v3, ByteSpan{ext}, 0U, none).error, Error::InvalidArgument);
  CHECK(Derive(v6, ByteSpan{}, 0U, none).ok());
  CHECK(Derive(v6, ByteSpan{ext}, 0U, none).ok());
  CHECK_EQ(Derive(v7, ByteSpan{ext}, 0xA204U, none).error,
           Error::DeviceIdMismatch); // SE050A is 3.x
  CHECK_EQ(Derive(v7, ByteSpan{ext}, 0xA564U, none).error, Error::DeviceIdMismatch); // SE051C 6.0
  CHECK_EQ(Derive(v3, ByteSpan{}, 0xB501U, none).error, Error::DeviceIdMismatch); // SE052F is 7.x
  const auto unknown = Derive(v7, ByteSpan{ext}, 0x1234U, none);
  CHECK(unknown.ok() && (unknown.value.family == Family::Unknown));
  CHECK(Derive(v7, ByteSpan{ext}, 0U, none).value.oef_id == 0U);
}

TEST_CASE("OEF ids name the families of AN12436 Table 2, AN12973 Table 4 and the SE052 sheet") {
  struct Row {
    uint16_t oef;
    uint8_t major;
    Family family;
  };
  const Row rows[] = {
      {0xA204U, 3U, Family::Se050A}, {0xA205U, 3U, Family::Se050A}, {0xA202U, 3U, Family::Se050B},
      {0xA203U, 3U, Family::Se050B}, {0xA200U, 3U, Family::Se050C}, {0xA201U, 3U, Family::Se050C},
      {0xA43BU, 3U, Family::Se050D}, {0xA921U, 7U, Family::Se050E}, {0xA92AU, 3U, Family::Se050F},
      {0xA77EU, 3U, Family::Se050F}, {0xA920U, 7U, Family::Se051A}, {0xA565U, 6U, Family::Se051A},
      {0xA8FAU, 7U, Family::Se051C}, {0xA564U, 6U, Family::Se051C}, {0xA739U, 7U, Family::Se051W},
      {0xB36AU, 7U, Family::Se051H}, {0xB501U, 7U, Family::Se052F}};
  const auto ext = ExtAll();
  for (const Row& r : rows) {
    const ByteSpan e = (r.major == 3U) ? ByteSpan{} : ByteSpan{ext};
    const auto caps =
        Derive(AppletInfo{AppletVersion{r.major, 2U, 0U}, kCfgC, 0U}, e, r.oef, ProbeResult{});
    CHECK(caps.ok());
    CHECK_EQ(caps.value.family, r.family);
  }
}

TEST_CASE("SE050A (3.x ECC): EdDSA, ECDAA, X25519, the ECKA key; no RSA, AEAD or DESFire") {
  const Capabilities c = Caps(3U, 6U, kCfgA, ByteSpan{}, 0xA204U);
  CHECK(c.features.eddsa && c.features.ecdaa && c.features.mont25519 && !c.features.mont448);
  CHECK(!c.features.rsa && !c.features.aes_aead && !c.features.mifare && !c.features.fips);
  CHECK(c.features.eckey_session_ecka && c.features.enable_pin && !c.features.selftest);
  CHECK(Allows(c, Command::EcdaaSign));
  CHECK(Allows(c, Command::EddsaSign));
  CHECK(Allows(c, Command::EcKeySessionGetEckaPublicKey));
  CHECK(Allows(c, Command::EcdhGenerateSharedSecret));
  CHECK(!Allows(c, Command::RsaSign));
  CHECK(!Allows(c, Command::GenerateRsaKey));
  CHECK(!Allows(c, Command::AeadOneShot));
  CHECK(!Allows(c, Command::ReadState));
  CHECK(!Allows(c, Command::ReadObjectAttributes));
  CHECK(!Allows(c, Command::DfAuthenticateFirstPart1));
  CHECK(!Allows(c, Command::EcPointMultiply));
  CHECK(!Allows(c, Command::GetExtVersion));
  CHECK(Allows(c, Command::DigestOneShot));
  CHECK(Allows(c, Command::Hkdf));
}

TEST_CASE("SE050B (RSA), C (ECC and RSA), D (DESFire), F (FIPS 140-2)") {
  const Capabilities b = Caps(3U, 6U, kCfgB, ByteSpan{}, 0xA202U);
  CHECK(b.features.rsa && b.features.rsa_plain && !b.features.eddsa);
  CHECK(Allows(b, Command::RsaSign) && Allows(b, Command::RsaEncrypt));
  CHECK(!Allows(b, Command::EcdsaSign) && !Allows(b, Command::WriteEcKey) &&
        !Allows(b, Command::CreateEcCurve));
  const Capabilities c = Caps(3U, 6U, kCfgC, ByteSpan{}, 0xA200U);
  CHECK(Allows(c, Command::RsaSign) && Allows(c, Command::EcdsaSign) &&
        Allows(c, Command::DfKillAuthentication));
  const Capabilities d = Caps(3U, 6U, kCfgD, ByteSpan{}, 0xA43BU);
  CHECK(d.features.mifare && Allows(d, Command::DfDiversifyKey));
  const Capabilities f = Caps(3U, 6U, kCfgF, ByteSpan{}, 0xA92AU);
  CHECK(f.features.fips && f.features.rsa && !f.features.rsa_plain && !f.features.rsa4096_keygen);
  CHECK_EQ(se05x::gate::CurveAllowed(f, se05x::EcCurve::NistP192), Error::Unsupported);
  CHECK_EQ(se05x::gate::CurveAllowed(f, se05x::EcCurve::Brainpool160), Error::Unsupported);
  CHECK_EQ(se05x::gate::CurveAllowed(f, se05x::EcCurve::NistP224), Error::Ok);
  CHECK_EQ(se05x::gate::CurveAllowed(c, se05x::EcCurve::NistP192), Error::Ok);
  CHECK(Caps(3U, 6U, static_cast<uint16_t>(kCfgC & 0xEFFFU), ByteSpan{}, 0U).features.fips);
}

TEST_CASE("SE050E and SE051 (7.2): AEAD, self test, X448, point multiplication; no ECDAA") {
  const auto ext = ExtAll();
  for (const uint16_t oef : {uint16_t{0xA921U}, uint16_t{0xA920U}, uint16_t{0xA8FAU},
                             uint16_t{0xA739U}, uint16_t{0xB36AU}}) {
    const Capabilities c = Caps(7U, 2U, kCfg7All, ByteSpan{ext}, oef);
    CHECK(c.features.aes_aead && c.features.selftest && c.features.mont448 && !c.features.ecdaa);
    CHECK(c.features.attestation_v2 && c.features.versioned_writes && c.features.enable_pin);
    CHECK(Allows(c, Command::AeadOneShot) && Allows(c, Command::ReadState));
    CHECK(Allows(c, Command::TriggerSelfTest) && Allows(c, Command::EcPointMultiply));
    CHECK(Allows(c, Command::DisableObjCreation) && Allows(c, Command::ReadObjectAttributes));
    CHECK(!Allows(c, Command::EcdaaSign) && !Allows(c, Command::EcKeySessionGetEckaPublicKey));
    CHECK(!c.features.free_memory_4byte && !c.features.dpd_by_sblock);
    CHECK_EQ(c.features.perso_applet, oef != 0xA921U);
    CHECK_EQ(c.features.throughput_limit, oef != 0xA921U);
  }
  auto h = ExtAll();
  h[9] = 0x80U; // a PAKE mode (B10b8)
  CHECK(Caps(7U, 2U, kCfg7All, ByteSpan{h}, 0xB36AU).features.pake);
  CHECK(!Caps(7U, 2U, kCfg7All, ByteSpan{ext}, 0xB36AU).features.pake);
}

TEST_CASE("SE052F: no EdDSA, Montgomery, DES, ECDAA or DESFire whatever AppletConfig says") {
  const auto ext = ExtAll();
  for (const uint16_t cfg : {kCfg052, uint16_t{0x3FFFU}}) {
    const Capabilities c = Caps(7U, 2U, cfg, ByteSpan{ext}, 0xB501U);
    CHECK(!c.features.eddsa && !c.features.mont25519 && !c.features.mont448);
    CHECK(!c.features.des && !c.features.ecdaa && !c.features.mifare);
    CHECK(c.features.fips && c.features.dpd_by_sblock && c.features.free_memory_4byte);
    CHECK(!c.features.enable_pin && c.features.throughput_limit && !c.features.perso_applet);
    CHECK(!Allows(c, Command::EddsaSign) && !Allows(c, Command::EddsaVerify));
    CHECK(!Allows(c, Command::DfAuthenticateFirstPart1));
    CHECK(Allows(c, Command::EcdsaSign) && Allows(c, Command::AeadOneShot) &&
          Allows(c, Command::DigestOneShot));
    CHECK_EQ(se05x::gate::CurveAllowed(c, se05x::EcCurve::Ed25519), Error::Unsupported);
    CHECK_EQ(se05x::gate::CurveAllowed(c, se05x::EcCurve::Montgomery25519), Error::Unsupported);
    CHECK_EQ(se05x::gate::CurveAllowed(c, se05x::EcCurve::NistP256), Error::Ok);
    CHECK_EQ(se05x::gate::SymmKeyAllowed(c, se05x::SymmKeyType::Des), Error::Unsupported);
    CHECK_EQ(se05x::gate::SymmKeyAllowed(c, se05x::SymmKeyType::Aes), Error::Ok);
  }
  const Capabilities c = Caps(7U, 2U, kCfg052, ByteSpan{ext}, 0xB501U);
  CHECK(Allows(c, Command::RsaSign) && Allows(c, Command::Pbkdf2) &&
        Allows(c, Command::TlsPerformPrf));
}

TEST_CASE("SE051 at applet 6.0 gets only the commands both specifications print") {
  const Capabilities c = Caps(6U, 0U, kCfgC, ByteSpan{}, 0xA565U);
  CHECK(c.generation == se05x::AppletGeneration::V6);
  CHECK(Allows(c, Command::WriteEcKey) && Allows(c, Command::EcdsaSign) &&
        Allows(c, Command::GetRandom));
  CHECK(!Allows(c, Command::GetExtVersion) && !Allows(c, Command::ReadState));
  CHECK(!Allows(c, Command::EcdaaSign) && !Allows(c, Command::EcKeySessionGetEckaPublicKey));
  CHECK(!Allows(c, Command::AeadOneShot) && !Allows(c, Command::WritePcrWithType));
  CHECK(!c.features.attestation_v2);
}

TEST_CASE("Applet 7.x needs the extended feature bit as well as AppletConfig") {
  auto ext = ExtAll();
  ext[1] = 0x02U; // EXTCFG_CRYPTO_EC_FORBID_ECDH
  ext[2] = 0x05U; // RSA on, RSA encryption forbidden
  ext[7] = 0x00U; // no digest operations
  const Capabilities c = Caps(7U, 2U, kCfg7All, ByteSpan{ext}, 0U);
  CHECK(!Allows(c, Command::EcdhGenerateSharedSecret) && !Allows(c, Command::EcdhIntoObject));
  CHECK(Allows(c, Command::RsaSign) && !Allows(c, Command::RsaEncrypt) &&
        !Allows(c, Command::RsaDecrypt));
  CHECK(!Allows(c, Command::DigestOneShot) && !Allows(c, Command::DigestInit));
  std::array<uint8_t, se05x::kExtFeatureLength> none{};
  const Capabilities n = Caps(7U, 2U, kCfg7All, ByteSpan{none}, 0U);
  CHECK(!n.features.rsa && !n.features.aes_aead && !n.features.des && !n.features.mifare);
  CHECK(!Allows(n, Command::CipherOneShot) && !Allows(n, Command::MacOneShot));
  CHECK(!Allows(n, Command::Hkdf) && !Allows(n, Command::Pbkdf2) &&
        !Allows(n, Command::TlsGenerateRandom));
  CHECK(!Allows(n, Command::WriteSymmKey));
  CHECK(Allows(n, Command::EcdsaSign) && Allows(n, Command::EddsaSign)); // EC needs no ext bit
  const ProbeResult failed{true, false, 0U};
  CHECK(!Caps(7U, 2U, kCfg7All, ByteSpan{ExtAll()}, 0U, failed).features.digest_commands);
  CHECK(!Caps(3U, 6U, kCfgC, ByteSpan{}, 0U, failed).features.digest_commands);
  const ProbeResult worked{true, true, 0U};
  CHECK(Caps(7U, 2U, kCfg7All, ByteSpan{ExtAll()}, 0U, worked).features.digest_commands);
}

TEST_CASE("Check: held commands, a locked applet, a required platform SCP, non-commands") {
  const auto ext = ExtAll();
  Capabilities c = Caps(7U, 2U, kCfg7All, ByteSpan{ext}, 0U);
  Config held{};
  held.held_commands.Add(Command::GetRandom);
  CHECK_EQ(Check(c, held, Command::GetRandom), Error::Unsupported);
  CHECK_EQ(Check(c, held, Command::GetVersion), Error::Ok);
  CHECK_EQ(Check(c, Config{}, tu::NotAnEnumerator<Command>(105U)), Error::InvalidArgument);
  c.applet_locked = true;
  for (const Command ok :
       {Command::SelectApplet, Command::GetVersion, Command::ReadState, Command::ReadObject,
        Command::GetRandom, Command::CreateSession, Command::ScpExternalAuthenticate,
        Command::EcKeySessionInternalAuthenticate, Command::SetLockState, Command::CloseSession}) {
    CHECK_EQ(Check(c, Config{}, ok), Error::Ok);
  }
  for (const Command no : {Command::EcdsaSign, Command::WriteBinary, Command::DeleteSecureObject,
                           Command::GetTimestamp}) {
    CHECK_EQ(Check(c, Config{}, no), Error::WrongState);
  }
  c.applet_locked = false;
  c.platform_scp_required = true;
  CHECK_EQ(Check(c, Config{}, Command::ReadState), Error::Ok);
  CHECK_EQ(Check(c, Config{}, Command::GetVersion), Error::Ok);
  CHECK_EQ(Check(c, Config{}, Command::GetCardIdentification), Error::Ok);
  CHECK_EQ(Check(c, Config{}, Command::GetRandom), Error::WrongState);
  CHECK_EQ(Check(c, Config{}, Command::CreateSession), Error::WrongState);
  c.platform_scp_active = true;
  CHECK_EQ(Check(c, Config{}, Command::GetRandom), Error::Ok);
  const Capabilities a = Caps(3U, 6U, kCfgA, ByteSpan{}, 0U);
  CHECK_EQ(Check(a, Config{}, Command::RsaSign), Error::Unsupported); // feature before state
}

TEST_CASE("CurveAllowed and SymmKeyAllowed follow the features") {
  const Capabilities a = Caps(3U, 6U, kCfgA, ByteSpan{}, 0U);
  using se05x::EcCurve;
  using se05x::gate::CurveAllowed;
  CHECK_EQ(CurveAllowed(a, EcCurve::Ed25519), Error::Ok);
  CHECK_EQ(CurveAllowed(a, EcCurve::Montgomery25519), Error::Ok);
  CHECK_EQ(CurveAllowed(a, EcCurve::Montgomery448), Error::Unsupported); // 7.x only
  CHECK_EQ(CurveAllowed(a, EcCurve::BnP256), Error::Ok);
  CHECK_EQ(CurveAllowed(a, tu::NotAnEnumerator<EcCurve>(20U)), Error::InvalidArgument);
  const auto ext = ExtAll();
  const Capabilities e = Caps(7U, 2U, kCfg7All, ByteSpan{ext}, 0U);
  CHECK_EQ(CurveAllowed(e, EcCurve::BnP256), Error::Unsupported);
  CHECK_EQ(CurveAllowed(e, EcCurve::Montgomery448), Error::Ok);
  const Capabilities b = Caps(3U, 6U, kCfgB, ByteSpan{}, 0U);
  CHECK_EQ(CurveAllowed(b, EcCurve::NistP256), Error::Unsupported);
  CHECK_EQ(se05x::gate::SymmKeyAllowed(b, se05x::SymmKeyType::Hmac), Error::Ok);
  CHECK_EQ(se05x::gate::SymmKeyAllowed(b, tu::NotAnEnumerator<se05x::SymmKeyType>(3U)),
           Error::InvalidArgument);
}
