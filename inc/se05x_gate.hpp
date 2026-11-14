/**
 * @file se05x_gate.hpp
 * @brief The capability gate: deriving `Capabilities` and deciding whether a command may be sent.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * The public surface below is frozen; the tables and helpers are in `se05x::gate::detail`.
 *
 * The gate refuses a command the chip's version, features, state or `Config::held_commands` do not
 * allow before anything is sent (S-11), which also avoids errata JOS.1. The inputs are what the
 * chip reports: the applet version and AppletConfig of the select response (AN12543 Table 8,
 * AN12413 Table 40), the 30 extended feature bytes of applet 7.x (AN12543 Table 9) and the OEF id
 * (AN12436 Table 2 for SE050, AN12973 Table 4 for SE051, the SE052 data sheet ordering table for
 * SE052F). A part name is never trusted: an OEF id that contradicts the applet generation is
 * `DeviceIdMismatch`.
 *
 * Command availability per generation: a command printed only in AN12543 is applet 7.x, one
 * printed only in AN12413 is applet 3.x. Applet 6.x has no specification in hand: it gets only the
 * commands both documents print (the conservative intersection).
 *
 * Per variant: SE052F has no EdDSA, no Montgomery curves, no DES, no ECDAA and no MIFARE DESFire
 * whatever AppletConfig says (SE052 data sheet; AN12543 3.13.2); SE050F refuses curves below
 * 224 bits (FIPS 140-2 configuration).
 */
#ifndef SE05X_GATE_HPP
#define SE05X_GATE_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "se05x_apdu_consts.hpp"
#include "se05x_caps.hpp"
#include "se05x_commands.hpp"
#include "se05x_device_types.hpp"
#include "se05x_status.hpp"
#include "se05x_types.hpp"

namespace se05x::gate {

/** @brief What the probes at `Open()` found (ambiguities A4, A5). */
struct ProbeResult {
  bool probed{false};         ///< Whether the probes ran.
  bool digest_works{false};   ///< `DigestOneShot` answered.
  uint32_t curves_present{0}; ///< One bit per `EcCurve` the curve list probe found.
};

namespace detail {

/// Generation bits of the command table.
inline constexpr uint8_t kGenV3 = 0x01U;
/// Applet 6.x.
inline constexpr uint8_t kGenV6 = 0x02U;
/// Applet 7.x.
inline constexpr uint8_t kGenV7 = 0x04U;
/// Every generation: printed in both specifications.
inline constexpr auto kGenAll = static_cast<uint8_t>(
    static_cast<uint32_t>(kGenV3) | static_cast<uint32_t>(kGenV6) | static_cast<uint32_t>(kGenV7));

/** @brief The feature a command needs. */
enum class Need : uint8_t {
  Always = 0,    ///< Nothing beyond the generation.
  EcAny = 1,     ///< Any EC configuration bit (key objects, curves).
  Ecdsa = 2,     ///< CONFIG_ECDSA_ECDH_ECDHE.
  Eddsa = 3,     ///< `Features::eddsa`.
  Ecdaa = 4,     ///< `Features::ecdaa`.
  Ecdh = 5,      ///< ECDH (Weierstrass or Montgomery), not forbidden by EXTCFG.
  EcPm = 6,      ///< `Features::ec_point_multiply`.
  Rsa = 7,       ///< `Features::rsa`.
  RsaCrypt = 8,  ///< RSA, encryption not forbidden by EXTCFG.
  Symm = 9,      ///< Any of AES, DES, HMAC keys.
  Cipher = 10,   ///< AES or DES operations.
  Aead = 11,     ///< `Features::aes_aead`.
  Mac = 12,      ///< HMAC, AES or DES operations.
  Digest = 13,   ///< `Features::digest_commands`.
  Hkdf = 14,     ///< HKDF.
  Pbkdf = 15,    ///< PBKDF2.
  Tls = 16,      ///< TLS handshake support.
  Mifare = 17,   ///< `Features::mifare`.
  I2cm = 18,     ///< `Features::i2cm`.
  EckaPub = 19,  ///< `Features::eckey_session_ecka`.
  SelfTest = 20, ///< `Features::selftest`.
};

/** @brief One row of the command table. */
struct CommandRule {
  uint8_t generations; ///< `kGen*` bits.
  Need need;           ///< The feature.
};

/// One row per `Command`, in enumerator order (AN12543 and AN12413 command chapters).
inline constexpr std::array<CommandRule, kCommandCount> kCommandRules{{
    {.generations = kGenAll, .need = Need::Always},   // SelectApplet
    {.generations = kGenAll, .need = Need::Always},   // GetVersion
    {.generations = kGenV7, .need = Need::Always},    // GetExtVersion
    {.generations = kGenAll, .need = Need::Always},   // GetCardIdentification
    {.generations = kGenAll, .need = Need::Always},   // GetCplc
    {.generations = kGenAll, .need = Need::Always},   // CreateSession
    {.generations = kGenAll, .need = Need::Always},   // ExchangeSessionData
    {.generations = kGenAll, .need = Need::Always},   // RefreshSession
    {.generations = kGenAll, .need = Need::Always},   // CloseSession
    {.generations = kGenAll, .need = Need::Always},   // VerifySessionUserId
    {.generations = kGenAll, .need = Need::Always},   // ScpInitializeUpdate
    {.generations = kGenAll, .need = Need::Always},   // ScpExternalAuthenticate
    {.generations = kGenAll, .need = Need::Always},   // EcKeySessionInternalAuthenticate
    {.generations = kGenV3, .need = Need::EckaPub},   // EcKeySessionGetEckaPublicKey
    {.generations = kGenAll, .need = Need::Always},   // SetLockState
    {.generations = kGenAll, .need = Need::Always},   // SetPlatformScpRequest
    {.generations = kGenAll, .need = Need::Always},   // SetAppletFeatures
    {.generations = kGenAll, .need = Need::Always},   // DeleteAll
    {.generations = kGenV7, .need = Need::Always},    // DisableObjCreation
    {.generations = kGenAll, .need = Need::Always},   // GetFreeMemory
    {.generations = kGenAll, .need = Need::Always},   // GetTimestamp
    {.generations = kGenAll, .need = Need::Always},   // GetRandom
    {.generations = kGenV7, .need = Need::Always},    // ReadState
    {.generations = kGenAll, .need = Need::Always},   // CmInvokeGarbageCollection
    {.generations = kGenV7, .need = Need::Always},    // SendCardManagerCmd
    {.generations = kGenV7, .need = Need::SelfTest},  // TriggerSelfTest
    {.generations = kGenAll, .need = Need::EcAny},    // WriteEcKey
    {.generations = kGenAll, .need = Need::EcAny},    // GenerateEcKey
    {.generations = kGenAll, .need = Need::Rsa},      // WriteRsaKey
    {.generations = kGenAll, .need = Need::Rsa},      // GenerateRsaKey
    {.generations = kGenAll, .need = Need::Symm},     // WriteSymmKey
    {.generations = kGenAll, .need = Need::Always},   // WriteBinary
    {.generations = kGenAll, .need = Need::Always},   // WriteUserId
    {.generations = kGenAll, .need = Need::Always},   // WriteCounter
    {.generations = kGenAll, .need = Need::Always},   // IncrementCounter
    {.generations = kGenAll, .need = Need::Always},   // WritePcr
    {.generations = kGenAll, .need = Need::Always},   // ExtendPcr
    {.generations = kGenAll, .need = Need::Always},   // ImportObject
    {.generations = kGenAll, .need = Need::Always},   // ExportObject
    {.generations = kGenAll, .need = Need::Always},   // ImportExternalObject
    {.generations = kGenV7, .need = Need::Always},    // WritePcrWithType
    {.generations = kGenAll, .need = Need::Always},   // ReadObject
    {.generations = kGenAll, .need = Need::Always},   // ReadObjectAttested
    {.generations = kGenV7, .need = Need::Always},    // ReadObjectAttributes
    {.generations = kGenV7, .need = Need::Always},    // ReadObjectAttributesAttested
    {.generations = kGenAll, .need = Need::Rsa},      // ReadRsaAttested
    {.generations = kGenAll, .need = Need::Always},   // ReadType
    {.generations = kGenAll, .need = Need::Always},   // ReadSize
    {.generations = kGenAll, .need = Need::Always},   // ReadIdList
    {.generations = kGenAll, .need = Need::Always},   // CheckObjectExists
    {.generations = kGenAll, .need = Need::Always},   // DeleteSecureObject
    {.generations = kGenAll, .need = Need::EcAny},    // CreateEcCurve
    {.generations = kGenAll, .need = Need::EcAny},    // SetEcCurveParam
    {.generations = kGenAll, .need = Need::EcAny},    // GetEcCurveId
    {.generations = kGenAll, .need = Need::EcAny},    // ReadEcCurveList
    {.generations = kGenAll, .need = Need::EcAny},    // DeleteEcCurve
    {.generations = kGenAll, .need = Need::Always},   // CreateCryptoObject
    {.generations = kGenAll, .need = Need::Always},   // ReadCryptoObjectList
    {.generations = kGenAll, .need = Need::Always},   // DeleteCryptoObject
    {.generations = kGenAll, .need = Need::Ecdsa},    // EcdsaSign
    {.generations = kGenAll, .need = Need::Ecdsa},    // EcdsaVerify
    {.generations = kGenAll, .need = Need::Eddsa},    // EddsaSign
    {.generations = kGenAll, .need = Need::Eddsa},    // EddsaVerify
    {.generations = kGenV3, .need = Need::Ecdaa},     // EcdaaSign
    {.generations = kGenAll, .need = Need::Ecdh},     // EcdhGenerateSharedSecret
    {.generations = kGenV7, .need = Need::Ecdh},      // EcdhIntoObject
    {.generations = kGenV7, .need = Need::EcPm},      // EcPointMultiply
    {.generations = kGenV7, .need = Need::EcPm},      // EcPointMultiplyInputObj
    {.generations = kGenAll, .need = Need::Rsa},      // RsaSign
    {.generations = kGenAll, .need = Need::Rsa},      // RsaVerify
    {.generations = kGenAll, .need = Need::RsaCrypt}, // RsaEncrypt
    {.generations = kGenAll, .need = Need::RsaCrypt}, // RsaDecrypt
    {.generations = kGenAll, .need = Need::Cipher},   // CipherInit
    {.generations = kGenAll, .need = Need::Cipher},   // CipherUpdate
    {.generations = kGenAll, .need = Need::Cipher},   // CipherFinal
    {.generations = kGenAll, .need = Need::Cipher},   // CipherOneShot
    {.generations = kGenV7, .need = Need::Aead},      // AeadInit
    {.generations = kGenV7, .need = Need::Aead},      // AeadUpdateAad
    {.generations = kGenV7, .need = Need::Aead},      // AeadUpdate
    {.generations = kGenV7, .need = Need::Aead},      // AeadFinal
    {.generations = kGenV7, .need = Need::Aead},      // AeadOneShot
    {.generations = kGenAll, .need = Need::Mac},      // MacInit
    {.generations = kGenAll, .need = Need::Mac},      // MacUpdate
    {.generations = kGenAll, .need = Need::Mac},      // MacFinal
    {.generations = kGenAll, .need = Need::Mac},      // MacOneShot
    {.generations = kGenAll, .need = Need::Digest},   // DigestInit
    {.generations = kGenAll, .need = Need::Digest},   // DigestUpdate
    {.generations = kGenAll, .need = Need::Digest},   // DigestFinal
    {.generations = kGenAll, .need = Need::Digest},   // DigestOneShot
    {.generations = kGenAll, .need = Need::Hkdf},     // Hkdf
    {.generations = kGenAll, .need = Need::Pbkdf},    // Pbkdf2
    {.generations = kGenAll, .need = Need::Tls},      // TlsGenerateRandom
    {.generations = kGenAll, .need = Need::Tls},      // TlsCalculatePreMasterSecret
    {.generations = kGenAll, .need = Need::Tls},      // TlsPerformPrf
    {.generations = kGenAll, .need = Need::Mifare},   // DfDiversifyKey
    {.generations = kGenAll, .need = Need::Mifare},   // DfAuthenticateFirstPart1
    {.generations = kGenAll, .need = Need::Mifare},   // DfAuthenticateFirstPart2
    {.generations = kGenAll, .need = Need::Mifare},   // DfAuthenticateNonFirstPart1
    {.generations = kGenAll, .need = Need::Mifare},   // DfAuthenticateNonFirstPart2
    {.generations = kGenAll, .need = Need::Mifare},   // DfDumpSessionKeys
    {.generations = kGenAll, .need = Need::Mifare},   // DfChangeKeyPart1
    {.generations = kGenAll, .need = Need::Mifare},   // DfChangeKeyPart2
    {.generations = kGenAll, .need = Need::Mifare},   // DfKillAuthentication
    {.generations = kGenAll, .need = Need::I2cm},     // I2cmExecuteCommandSet
    {.generations = kGenAll, .need = Need::I2cm},     // I2cmExecuteCommandSetAttested
}};

/** @brief One row of the OEF table. */
struct OefRow {
  uint16_t oef;                ///< The OEF id.
  Family family;               ///< The family.
  AppletGeneration generation; ///< The applet generation the variant ships with.
};

/// The known OEF ids: AN12436 Table 2 (SE050; A/C pairs are swapped between its two tables, which
/// only changes the temperature grade, not the family), AN12973 Table 4 (SE051), SE052 data sheet
/// ordering table (SE052F).
inline constexpr std::array<OefRow, 18> kOefTable{{
    {.oef = 0xA204U, .family = Family::Se050A, .generation = AppletGeneration::V3},
    {.oef = 0xA205U, .family = Family::Se050A, .generation = AppletGeneration::V3},
    {.oef = 0xA202U, .family = Family::Se050B, .generation = AppletGeneration::V3},
    {.oef = 0xA203U, .family = Family::Se050B, .generation = AppletGeneration::V3},
    {.oef = 0xA200U, .family = Family::Se050C, .generation = AppletGeneration::V3},
    {.oef = 0xA201U, .family = Family::Se050C, .generation = AppletGeneration::V3},
    {.oef = 0xA43BU, .family = Family::Se050D, .generation = AppletGeneration::V3},
    {.oef = 0xA921U, .family = Family::Se050E, .generation = AppletGeneration::V7},
    {.oef = 0xA92AU, .family = Family::Se050F, .generation = AppletGeneration::V3},
    {.oef = 0xA77EU, .family = Family::Se050F, .generation = AppletGeneration::V3},
    {.oef = 0xA920U, .family = Family::Se051A, .generation = AppletGeneration::V7},
    {.oef = 0xA565U, .family = Family::Se051A, .generation = AppletGeneration::V6},
    {.oef = 0xA8FAU, .family = Family::Se051C, .generation = AppletGeneration::V7},
    {.oef = 0xA564U, .family = Family::Se051C, .generation = AppletGeneration::V6},
    {.oef = 0xA739U, .family = Family::Se051W, .generation = AppletGeneration::V7},
    {.oef = 0xB36AU, .family = Family::Se051H, .generation = AppletGeneration::V7},
    {.oef = 0xB501U, .family = Family::Se052F, .generation = AppletGeneration::V7},
    {.oef = 0x0000U, .family = Family::Unknown, .generation = AppletGeneration::V3},
}};

/**
 * @brief The family of an OEF id, checked against the applet generation.
 * @param oef The OEF id; 0 when not read.
 * @param generation The generation from the version.
 * @param family Receives the family; `Unknown` for an id not in the table.
 * @return false when the id is known and its generation contradicts the chip's.
 */
constexpr bool FamilyOf(uint16_t oef, AppletGeneration generation, Family& family) noexcept {
  family = Family::Unknown;
  if (oef == 0U) {
    return true;
  }
  for (const OefRow& row : kOefTable) {
    if (row.oef == oef) {
      family = row.family;
      return row.generation == generation;
    }
  }
  return true;
}

/**
 * @brief Whether a bit of the extended feature bitmap is set (AN12543 Table 9: byte 1 is the
 * first, bit 8 the most significant).
 * @param ext The 30 bytes, all zero on applet 3.x.
 * @param byte The byte number, 1 to 30.
 * @param mask The bit mask.
 * @return true when set.
 */
constexpr bool ExtBit(const std::array<uint8_t, kExtFeatureLength>& ext, std::size_t byte,
                      uint8_t mask) noexcept {
  return (static_cast<uint32_t>(ext[byte - 1U]) & static_cast<uint32_t>(mask)) != 0U;
}

/** @brief The algorithm groups the command table needs, beyond `Features`. */
struct Groups {
  bool ecdsa{false};               ///< Weierstrass curves.
  bool aes{false};                 ///< AES operations.
  bool hmac{false};                ///< HMAC operations.
  bool ecdh_forbidden{false};      ///< EXTCFG_CRYPTO_EC_FORBID_ECDH.
  bool rsa_crypt_forbidden{false}; ///< EXTCFG_CRYPTO_RSA_FORBID_ENC_DEC.
  bool hkdf{false};                ///< HKDF.
  bool pbkdf{false};               ///< PBKDF2.
  bool tls{false};                 ///< TLS handshake support.
};

/**
 * @brief The algorithm groups of a chip. On applet 7.x an operation needs both its AppletConfig bit
 * and its extended feature bit (AN12543 3.4: "users need to ensure both are filled").
 * @param caps The capabilities (generation, AppletConfig, ext).
 * @return The groups.
 */
constexpr Groups GroupsOf(const Capabilities& caps) noexcept {
  const uint32_t cfg = caps.applet_config;
  const bool v7 = (caps.generation == AppletGeneration::V7);
  Groups g{};
  g.ecdsa = (cfg & apdu::kConfigEcdsa) != 0U;
  g.aes = ((cfg & apdu::kConfigAes) != 0U) && (!v7 || ExtBit(caps.ext, 4U, 0x01U));
  g.hmac = ((cfg & apdu::kConfigHmac) != 0U) && (!v7 || ExtBit(caps.ext, 4U, 0x04U));
  g.ecdh_forbidden = v7 && ExtBit(caps.ext, 2U, 0x02U);
  g.rsa_crypt_forbidden = v7 && ExtBit(caps.ext, 3U, 0x04U);
  g.hkdf = g.hmac && (!v7 || ExtBit(caps.ext, 5U, 0x01U));
  g.pbkdf = ((cfg & apdu::kConfigPbkdf) != 0U) && (!v7 || ExtBit(caps.ext, 6U, 0x01U));
  g.tls = ((cfg & apdu::kConfigTls) != 0U) && (!v7 || ExtBit(caps.ext, 7U, 0x01U));
  return g;
}

/**
 * @brief Whether a chip has the feature a command needs: the key and curve features.
 * @param need The need.
 * @param caps The capabilities.
 * @param g The groups.
 * @return true when present.
 */
constexpr bool HasKeyNeed(Need need, const Capabilities& caps, const Groups& g) noexcept {
  const Features& f = caps.features;
  switch (need) {
  case Need::EcAny:
    return g.ecdsa || f.eddsa || f.mont25519;
  case Need::Ecdsa:
    return g.ecdsa;
  case Need::Eddsa:
    return f.eddsa;
  case Need::Ecdaa:
    return f.ecdaa;
  case Need::Ecdh:
    return (g.ecdsa || f.mont25519) && !g.ecdh_forbidden;
  case Need::EcPm:
    return f.ec_point_multiply && g.ecdsa;
  case Need::Rsa:
    return f.rsa;
  case Need::RsaCrypt:
    return f.rsa && !g.rsa_crypt_forbidden;
  case Need::Symm:
    return g.aes || f.des || g.hmac;
  case Need::EckaPub:
    return f.eckey_session_ecka;
  case Need::Always:
  case Need::Cipher:
  case Need::Aead:
  case Need::Mac:
  case Need::Digest:
  case Need::Hkdf:
  case Need::Pbkdf:
  case Need::Tls:
  case Need::Mifare:
  case Need::I2cm:
  case Need::SelfTest:
  default:
    break;
  }
  return false;
}

/**
 * @brief Whether a chip has the feature a command needs.
 * @param need The need.
 * @param caps The capabilities.
 * @return true when present.
 */
constexpr bool HasNeed(Need need, const Capabilities& caps) noexcept {
  const Features& f = caps.features;
  const Groups g = GroupsOf(caps);
  switch (need) {
  case Need::Always:
    return true;
  case Need::Cipher:
    return g.aes || f.des;
  case Need::Aead:
    return f.aes_aead;
  case Need::Mac:
    return g.aes || f.des || g.hmac;
  case Need::Digest:
    return f.digest_commands;
  case Need::Hkdf:
    return g.hkdf;
  case Need::Pbkdf:
    return g.pbkdf;
  case Need::Tls:
    return g.tls;
  case Need::Mifare:
    return f.mifare;
  case Need::I2cm:
    return f.i2cm;
  case Need::SelfTest:
    return f.selftest;
  case Need::EcAny:
  case Need::Ecdsa:
  case Need::Eddsa:
  case Need::Ecdaa:
  case Need::Ecdh:
  case Need::EcPm:
  case Need::Rsa:
  case Need::RsaCrypt:
  case Need::Symm:
  case Need::EckaPub:
  default:
    break;
  }
  return HasKeyNeed(need, caps, g);
}

/**
 * @brief The generation bit of a generation.
 * @param generation The generation.
 * @return `kGenV3`, `kGenV6` or `kGenV7`.
 */
constexpr uint8_t GenBit(AppletGeneration generation) noexcept {
  if (generation == AppletGeneration::V7) {
    return kGenV7;
  }
  return (generation == AppletGeneration::V6) ? kGenV6 : kGenV3;
}

/**
 * @brief Whether an operation is on: its AppletConfig bit, and on applet 7.x its extended feature
 * bit too (AN12543 3.4: "users need to ensure both the features and extended features are filled").
 * @param caps The capabilities.
 * @param config The AppletConfig bit.
 * @param byte The extended feature byte number.
 * @param mask The extended feature bit.
 * @return true when on.
 */
constexpr bool Enabled(const Capabilities& caps, uint16_t config, std::size_t byte,
                       uint8_t mask) noexcept {
  return ((static_cast<uint32_t>(caps.applet_config) & static_cast<uint32_t>(config)) != 0U) &&
         ((caps.generation != AppletGeneration::V7) || ExtBit(caps.ext, byte, mask));
}

/**
 * @brief The RSA and symmetric features of a chip.
 * @param caps The capabilities.
 * @param f The features to fill.
 */
constexpr void SymmetricFeatures(const Capabilities& caps, Features& f) noexcept {
  const bool se052 = (caps.family == Family::Se052F);
  f.rsa =
      Enabled(caps, static_cast<uint16_t>(apdu::kConfigRsaPlain | apdu::kConfigRsaCrt), 3U, 0x01U);
  f.rsa_plain = f.rsa && ((caps.applet_config & apdu::kConfigRsaPlain) != 0U);
  f.rsa4096_keygen = f.rsa && (caps.family != Family::Se050F);
  f.aes_aead =
      (caps.generation == AppletGeneration::V7) && Enabled(caps, apdu::kConfigAes, 4U, 0x08U);
  f.des = !se052 && Enabled(caps, apdu::kConfigDes, 4U, 0x02U);
  f.mifare = !se052 && Enabled(caps, apdu::kConfigMifare, 9U, 0x01U);
}

/**
 * @brief The algorithm features of a chip: AppletConfig, the extended bits (7.x: both needed) and
 * the SE052F exclusions.
 * @param caps The capabilities with version, AppletConfig, ext and family filled.
 * @param f The features to fill.
 */
constexpr void AlgorithmFeatures(const Capabilities& caps, Features& f) noexcept {
  const uint32_t cfg = caps.applet_config;
  const bool v7 = (caps.generation == AppletGeneration::V7);
  const bool v3 = (caps.generation == AppletGeneration::V3);
  const bool se052 = (caps.family == Family::Se052F);
  f.eddsa = !se052 && ((cfg & apdu::kConfigEddsa) != 0U);
  f.mont25519 = !se052 && ((cfg & apdu::kConfigDhMont) != 0U);
  f.mont448 = f.mont25519 && v7;
  f.ecdaa = !se052 && v3 && ((cfg & apdu::kConfigEcdaa) != 0U);
  SymmetricFeatures(caps, f);
}

/**
 * @brief The features of a chip from AppletConfig, the extended bits and the family.
 * @param caps The capabilities with version, AppletConfig, ext and family filled.
 * @param probe The probe results (a digest probe that failed removes the digest commands, A5).
 * @return The features.
 */
constexpr Features FeaturesOf(const Capabilities& caps, const ProbeResult& probe) noexcept {
  const bool v7 = (caps.generation == AppletGeneration::V7);
  const bool v3 = (caps.generation == AppletGeneration::V3);
  const bool se052 = (caps.family == Family::Se052F);
  const bool se051 = (caps.family >= Family::Se051A) && (caps.family <= Family::Se051W);
  const bool fips_disabled = (caps.applet_config & apdu::kConfigFipsDisabled) != 0U;
  Features f{};
  AlgorithmFeatures(caps, f);
  f.i2cm = (caps.applet_config & apdu::kConfigI2cm) != 0U;
  f.pake = v7 && (caps.ext[9] != 0U);
  f.digest_commands = (!v7 || ExtBit(caps.ext, 8U, 0x01U)) && (!probe.probed || probe.digest_works);
  f.eckey_session_ecka = v3;
  f.selftest = v7;
  f.ec_point_multiply = v7;
  f.versioned_writes = v7;
  f.attestation_v2 = v7;
  f.fips = se052 || (caps.family == Family::Se050F) || (v3 && !fips_disabled);
  f.applet_update = se051 || se052;
  f.enable_pin = !se052;
  f.dpd_by_sblock = se052;
  f.throughput_limit = se052 || se051;
  f.free_memory_4byte = se052;
  f.perso_applet = se051;
  return f;
}

/** @brief The commands the lifecycle Inactive state allows (AN12543 Table 19), plus the select,
 * the session authentication that unlocks with RESERVED_ID_TRANSPORT and `SetLockState`. */
inline constexpr std::array<Command, 15> kWhileLocked{Command::SelectApplet,
                                                      Command::GetVersion,
                                                      Command::ReadState,
                                                      Command::ReadObject,
                                                      Command::GetRandom,
                                                      Command::CreateSession,
                                                      Command::ExchangeSessionData,
                                                      Command::RefreshSession,
                                                      Command::CloseSession,
                                                      Command::VerifySessionUserId,
                                                      Command::ScpInitializeUpdate,
                                                      Command::ScpExternalAuthenticate,
                                                      Command::EcKeySessionInternalAuthenticate,
                                                      Command::SetLockState,
                                                      Command::GetExtVersion};

/** @brief The commands the applet takes without platform SCP when it requires it (AN12543 3.14:
 * Select, GetVersion, ReadState), and the card manager commands, which the applet does not see. */
inline constexpr std::array<Command, 7> kWithoutScp{Command::SelectApplet,
                                                    Command::GetVersion,
                                                    Command::GetExtVersion,
                                                    Command::ReadState,
                                                    Command::GetCardIdentification,
                                                    Command::GetCplc,
                                                    Command::CmInvokeGarbageCollection};

/**
 * @brief Whether a command is in a list.
 * @tparam N The list length.
 * @param list The list.
 * @param command The command.
 * @return true when present.
 */
template <std::size_t N>
constexpr bool InList(const std::array<Command, N>& list, Command command) noexcept {
  bool found = false;
  for (const Command c : list) {
    found = found || (c == command);
  }
  return found;
}

/**
 * @brief The commands a chip allows: the table filtered by generation and features.
 * @param caps The capabilities.
 * @return The set.
 */
constexpr CommandSet AllowedSet(const Capabilities& caps) noexcept {
  CommandSet set{};
  const uint8_t gen = GenBit(caps.generation);
  for (std::size_t i = 0U; i < kCommandCount; ++i) {
    const CommandRule& rule = kCommandRules[i];
    if (((rule.generations & gen) != 0U) && HasNeed(rule.need, caps)) {
      static_cast<void>(set.Add(static_cast<Command>(static_cast<uint8_t>(i))));
    }
  }
  return set;
}

/**
 * @brief The size in bits of a curve's field (for the SE050F rule).
 * @param curve The curve.
 * @return The field size; 0 for a value that is not an enumerator.
 */
constexpr uint32_t CurveBits(EcCurve curve) noexcept {
  constexpr std::array<uint16_t, 20> kBits{192U, 224U, 256U, 384U, 521U, 160U, 192U,
                                           224U, 256U, 320U, 384U, 512U, 160U, 192U,
                                           224U, 256U, 256U, 255U, 255U, 448U};
  if (!se05x::detail::IsEnumerator(curve)) {
    return 0U;
  }
  return kBits[static_cast<std::size_t>(se05x::detail::ToUnderlying(curve))];
}

} // namespace detail

/**
 * @brief Derive the capabilities of a chip from what it reports.
 * @param info The select response.
 * @param ext The extended feature bits: 30 bytes on applet 7.x, empty on 3.x, either on 6.x.
 * @param oef_id The OEF id from the card identification data, 0 when not read.
 * @param probe The probe results.
 * @return The capabilities, or `DeviceIdMismatch` (an applet major version other than 3, 6 or 7,
 * or an OEF id of another generation), `InvalidArgument` (`ext` of the wrong length).
 */
constexpr Result<Capabilities> Derive(const AppletInfo& info, ByteSpan ext, uint16_t oef_id,
                                      const ProbeResult& probe) noexcept {
  const Detail where{
      .sw = 0U, .command = 0xFFU, .layer = Layer::Device, .step = 0U, .attempts_left = 0xFFU};
  const uint8_t major = info.version.major;
  if ((major != 3U) && (major != 6U) && (major != 7U)) {
    return Result<Capabilities>::Failure(Error::DeviceIdMismatch, where);
  }
  Capabilities caps{};
  caps.applet = info.version;
  caps.generation = info.version.Generation();
  const bool ext_ok = (ext.size() == kExtFeatureLength)
                          ? (caps.generation != AppletGeneration::V3)
                          : (ext.empty() && (caps.generation != AppletGeneration::V7));
  if (!ext_ok) {
    return Result<Capabilities>::Failure(Error::InvalidArgument, where);
  }
  if (!detail::FamilyOf(oef_id, caps.generation, caps.family)) {
    return Result<Capabilities>::Failure(Error::DeviceIdMismatch, where);
  }
  caps.applet_config = info.applet_config;
  caps.secure_box = info.secure_box;
  caps.oef_id = oef_id;
  for (std::size_t i = 0U; i < ext.size(); ++i) {
    caps.ext[i] = ext[i];
  }
  caps.features = detail::FeaturesOf(caps, probe);
  caps.allowed = detail::AllowedSet(caps);
  return Result<Capabilities>::Success(caps);
}

/**
 * @brief Decide whether `command` may be sent now.
 * @param caps The capabilities of the chip and its current state.
 * @param config The configuration (held commands).
 * @param command The command.
 * @return `Ok`, `InvalidArgument` (not a command), `Unsupported` (generation, feature or held),
 * `WrongState` (locked applet: AN12543 3.8 Table 19; platform SCP required and not open: 3.14).
 */
constexpr Error Check(const Capabilities& caps, const Config& config, Command command) noexcept {
  if (!se05x::detail::IsEnumerator(command)) {
    return Error::InvalidArgument;
  }
  if (config.held_commands.Contains(command) || !caps.allowed.Contains(command)) {
    return Error::Unsupported;
  }
  if (caps.applet_locked && !detail::InList(detail::kWhileLocked, command)) {
    return Error::WrongState;
  }
  if (caps.platform_scp_required && !caps.platform_scp_active &&
      !detail::InList(detail::kWithoutScp, command)) {
    return Error::WrongState;
  }
  return Error::Ok;
}

/**
 * @brief Whether a curve may be used on this chip (the argument gate of the EC commands, which
 * `Check` cannot see): Ed25519 needs EdDSA, X25519 and X448 the Montgomery configuration (X448
 * applet 7.x), BN-P256 applet 3.x, the Weierstrass curves CONFIG_ECDSA; SE050F refuses curves below
 * 224 bits.
 * @param caps The capabilities.
 * @param curve The curve.
 * @return `Ok`, `Unsupported` or `InvalidArgument` (not an enumerator).
 */
constexpr Error CurveAllowed(const Capabilities& caps, EcCurve curve) noexcept {
  if (!se05x::detail::IsEnumerator(curve)) {
    return Error::InvalidArgument;
  }
  bool ok = (caps.applet_config & apdu::kConfigEcdsa) != 0U;
  if (curve == EcCurve::Ed25519) {
    ok = caps.features.eddsa;
  } else if (curve == EcCurve::Montgomery25519) {
    ok = caps.features.mont25519;
  } else if (curve == EcCurve::Montgomery448) {
    ok = caps.features.mont448;
  } else if (curve == EcCurve::BnP256) {
    ok = ok && (caps.generation == AppletGeneration::V3);
  } else {
    ok = ok && ((caps.family != Family::Se050F) || (detail::CurveBits(curve) >= 224U));
  }
  return ok ? Error::Ok : Error::Unsupported;
}

/**
 * @brief Whether a symmetric key type may be written on this chip (SE052F has no DES; AN12543
 * 3.13.2: no DES write in FIPS 140-3 mode).
 * @param caps The capabilities.
 * @param type The key type.
 * @return `Ok`, `Unsupported` or `InvalidArgument`.
 */
constexpr Error SymmKeyAllowed(const Capabilities& caps, SymmKeyType type) noexcept {
  const detail::Groups g = detail::GroupsOf(caps);
  switch (type) {
  case SymmKeyType::Aes:
    return g.aes ? Error::Ok : Error::Unsupported;
  case SymmKeyType::Des:
    return caps.features.des ? Error::Ok : Error::Unsupported;
  case SymmKeyType::Hmac:
    return g.hmac ? Error::Ok : Error::Unsupported;
  default:
    break;
  }
  return Error::InvalidArgument;
}

} // namespace se05x::gate

#endif // SE05X_GATE_HPP
