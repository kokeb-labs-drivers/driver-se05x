/**
 * @file se05x_apdu_consts.hpp
 * @brief The numeric constants of the IoT applet APDU interface and the maps from the abstract
 * enumerations of `se05x_device_types.hpp` to their wire values.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Every number below is read from the applet specifications: AN12543 Rev 4.5
 * section 4.3 (applet 7.x; the tables are named next to each constant) and AN12413 Rev 2.12
 * section 4.3 (applet 3.x), which agree on every value used here except where a comment says
 * otherwise. A wire value never leaks into the public API: the codecs call the `*Wire()` maps.
 * A map returns `false` for a value the applet does not support (a "NOT SUPPORTED" row of the
 * specification), and the codec refuses the command before anything is sent.
 */
#ifndef SE05X_APDU_CONSTS_HPP
#define SE05X_APDU_CONSTS_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "se05x_device_types.hpp"
#include "se05x_ids.hpp"
#include "se05x_types.hpp"

namespace se05x::apdu {

/**
 * @defgroup se05x_apdu_consts APDU constants
 * @brief Classes, instructions, parameters, tags and enumeration values of the applet.
 * @{
 */

/// @name CLA bytes (AN12543 4.1.1.1)
/// @{
inline constexpr uint8_t kClaIso = 0x00U;    ///< ISO class: the GP SELECT of the applet.
inline constexpr uint8_t kClaPlain = 0x80U;  ///< No secure messaging.
inline constexpr uint8_t kClaSecure = 0x84U; ///< Proprietary secure messaging.
/// @}

/// @name INS bytes (AN12543 Tables 24, 25; GP Card Specification for the GP commands)
/// @{
inline constexpr uint8_t kInsWrite = 0x01U;                ///< INS_WRITE.
inline constexpr uint8_t kInsRead = 0x02U;                 ///< INS_READ.
inline constexpr uint8_t kInsCrypto = 0x03U;               ///< INS_CRYPTO.
inline constexpr uint8_t kInsMgmt = 0x04U;                 ///< INS_MGMT.
inline constexpr uint8_t kInsImportExternal = 0x06U;       ///< INS_IMPORT_EXTERNAL.
inline constexpr uint8_t kInsTransient = 0x80U;            ///< INS_TRANSIENT flag.
inline constexpr uint8_t kInsAuthObject = 0x40U;           ///< INS_AUTH_OBJECT flag.
inline constexpr uint8_t kInsAttest = 0x20U;               ///< INS_ATTEST flag.
inline constexpr uint8_t kInsSelect = 0xA4U;               ///< ISO SELECT.
inline constexpr uint8_t kInsGetData = 0xCAU;              ///< GP GET DATA.
inline constexpr uint8_t kInsInitializeUpdate = 0x50U;     ///< GP INITIALIZE UPDATE.
inline constexpr uint8_t kInsExternalAuthenticate = 0x82U; ///< GP EXTERNAL AUTHENTICATE.
inline constexpr uint8_t kInsInternalAuthenticate = 0x88U; ///< GP INTERNAL AUTHENTICATE.
/// @}

/// @name P1 values (AN12543 Tables 27, 28)
/// @{
inline constexpr uint8_t kP1Default = 0x00U;   ///< P1_DEFAULT.
inline constexpr uint8_t kP1KeyPair = 0x60U;   ///< P1_KEY_PAIR.
inline constexpr uint8_t kP1Private = 0x40U;   ///< P1_PRIVATE.
inline constexpr uint8_t kP1Public = 0x20U;    ///< P1_PUBLIC.
inline constexpr uint8_t kP1Ec = 0x01U;        ///< P1_EC.
inline constexpr uint8_t kP1Rsa = 0x02U;       ///< P1_RSA.
inline constexpr uint8_t kP1Aes = 0x03U;       ///< P1_AES.
inline constexpr uint8_t kP1Des = 0x04U;       ///< P1_DES.
inline constexpr uint8_t kP1Hmac = 0x05U;      ///< P1_HMAC.
inline constexpr uint8_t kP1Binary = 0x06U;    ///< P1_BINARY.
inline constexpr uint8_t kP1UserId = 0x07U;    ///< P1_USERID.
inline constexpr uint8_t kP1Counter = 0x08U;   ///< P1_COUNTER.
inline constexpr uint8_t kP1Pcr = 0x09U;       ///< P1_PCR.
inline constexpr uint8_t kP1Curve = 0x0BU;     ///< P1_CURVE.
inline constexpr uint8_t kP1Signature = 0x0CU; ///< P1_SIGNATURE.
inline constexpr uint8_t kP1Mac = 0x0DU;       ///< P1_MAC.
inline constexpr uint8_t kP1Cipher = 0x0EU;    ///< P1_CIPHER.
inline constexpr uint8_t kP1Tls = 0x0FU;       ///< P1_TLS.
inline constexpr uint8_t kP1CryptoObj = 0x10U; ///< P1_CRYPTO_OBJ.
inline constexpr uint8_t kP1Aead = 0x11U;      ///< P1_AEAD.
/// @}

/// @name P2 values (AN12543 Table 29; the DESFire values are those of Table 29, not Table 342)
/// @{
inline constexpr uint8_t kP2Default = 0x00U;           ///< P2_DEFAULT.
inline constexpr uint8_t kP2Generate = 0x03U;          ///< P2_GENERATE.
inline constexpr uint8_t kP2Create = 0x04U;            ///< P2_CREATE.
inline constexpr uint8_t kP2Size = 0x07U;              ///< P2_SIZE.
inline constexpr uint8_t kP2Sign = 0x09U;              ///< P2_SIGN.
inline constexpr uint8_t kP2Verify = 0x0AU;            ///< P2_VERIFY.
inline constexpr uint8_t kP2Init = 0x0BU;              ///< P2_INIT.
inline constexpr uint8_t kP2Update = 0x0CU;            ///< P2_UPDATE.
inline constexpr uint8_t kP2Final = 0x0DU;             ///< P2_FINAL.
inline constexpr uint8_t kP2OneShot = 0x0EU;           ///< P2_ONESHOT.
inline constexpr uint8_t kP2Dh = 0x0FU;                ///< P2_DH.
inline constexpr uint8_t kP2Diversify = 0x10U;         ///< P2_DIVERSIFY.
inline constexpr uint8_t kP2AuthFirstPart2 = 0x12U;    ///< P2_AUTH_FIRST_PART2 (Table 29).
inline constexpr uint8_t kP2AuthNonFirstPart2 = 0x13U; ///< P2_AUTH_NONFIRST_PART2 (Table 29).
inline constexpr uint8_t kP2DumpKey = 0x14U;           ///< P2_DUMP_KEY.
inline constexpr uint8_t kP2ChangeKeyPart1 = 0x15U;    ///< P2_CHANGE_KEY_PART1.
inline constexpr uint8_t kP2ChangeKeyPart2 = 0x16U;    ///< P2_CHANGE_KEY_PART2.
inline constexpr uint8_t kP2KillAuth = 0x17U;          ///< P2_KILL_AUTH.
inline constexpr uint8_t kP2Import = 0x18U;            ///< P2_IMPORT.
inline constexpr uint8_t kP2Export = 0x19U;            ///< P2_EXPORT.
inline constexpr uint8_t kP2SessionCreate = 0x1BU;     ///< P2_SESSION_CREATE.
inline constexpr uint8_t kP2SessionClose = 0x1CU;      ///< P2_SESSION_CLOSE.
inline constexpr uint8_t kP2SessionRefresh = 0x1EU;    ///< P2_SESSION_REFRESH.
inline constexpr uint8_t kP2SessionPolicy = 0x1FU;     ///< P2_SESSION_POLICY.
inline constexpr uint8_t kP2Version = 0x20U;           ///< P2_VERSION.
inline constexpr uint8_t kP2VersionExt = 0x21U;        ///< P2_VERSION_EXT.
inline constexpr uint8_t kP2Memory = 0x22U;            ///< P2_MEMORY.
inline constexpr uint8_t kP2List = 0x25U;              ///< P2_LIST.
inline constexpr uint8_t kP2Type = 0x26U;              ///< P2_TYPE.
inline constexpr uint8_t kP2Exist = 0x27U;             ///< P2_EXIST.
inline constexpr uint8_t kP2DeleteObject = 0x28U;      ///< P2_DELETE_OBJECT.
inline constexpr uint8_t kP2DeleteAll = 0x2AU;         ///< P2_DELETE_ALL.
inline constexpr uint8_t kP2SessionUserId = 0x2CU;     ///< P2_SESSION_USERID.
inline constexpr uint8_t kP2Hkdf = 0x2DU;              ///< P2_HKDF.
inline constexpr uint8_t kP2Pbkdf = 0x2EU;             ///< P2_PBKDF.
inline constexpr uint8_t kP2HkdfExpandOnly = 0x2FU;    ///< P2_HKDF_EXPAND_ONLY.
inline constexpr uint8_t kP2I2cm = 0x30U;              ///< P2_I2CM.
inline constexpr uint8_t kP2Id = 0x36U;                ///< P2_ID.
inline constexpr uint8_t kP2EncryptOneShot = 0x37U;    ///< P2_ENCRYPT_ONESHOT.
inline constexpr uint8_t kP2DecryptOneShot = 0x38U;    ///< P2_DECRYPT_ONESHOT.
inline constexpr uint8_t kP2Attributes = 0x3BU;        ///< P2_ATTRIBUTES.
inline constexpr uint8_t kP2Time = 0x3DU;              ///< P2_TIME.
inline constexpr uint8_t kP2Transport = 0x3EU;         ///< P2_TRANSPORT.
inline constexpr uint8_t kP2Variant = 0x3FU;           ///< P2_VARIANT.
inline constexpr uint8_t kP2Param = 0x40U;             ///< P2_PARAM.
inline constexpr uint8_t kP2Encrypt = 0x42U;           ///< P2_ENCRYPT.
inline constexpr uint8_t kP2Decrypt = 0x43U;           ///< P2_DECRYPT.
inline constexpr uint8_t kP2Validate = 0x44U;          ///< P2_VALIDATE.
inline constexpr uint8_t kP2GenerateOneShot = 0x45U;   ///< P2_GENERATE_ONESHOT.
inline constexpr uint8_t kP2ValidateOneShot = 0x46U;   ///< P2_VALIDATE_ONESHOT.
inline constexpr uint8_t kP2Random = 0x49U;            ///< P2_RANDOM.
inline constexpr uint8_t kP2TlsPms = 0x4AU;            ///< P2_TLS_PMS.
inline constexpr uint8_t kP2TlsPrfCliHello = 0x4BU;    ///< P2_TLS_PRF_CLI_HELLO.
inline constexpr uint8_t kP2TlsPrfSrvHello = 0x4CU;    ///< P2_TLS_PRF_SRV_HELLO.
inline constexpr uint8_t kP2TlsPrfCliRnd = 0x4DU;      ///< P2_TLS_PRF_CLI_RND.
inline constexpr uint8_t kP2TlsPrfSrvRnd = 0x4EU;      ///< P2_TLS_PRF_SRV_RND.
inline constexpr uint8_t kP2Raw = 0x4FU;               ///< P2_RAW.
inline constexpr uint8_t kP2Scp = 0x52U;               ///< P2_SCP.
inline constexpr uint8_t kP2AuthFirstPart1 = 0x53U;    ///< P2_AUTH_FIRST_PART1 (Table 29).
inline constexpr uint8_t kP2AuthNonFirstPart1 = 0x54U; ///< P2_AUTH_NONFIRST_PART1 (Table 29).
inline constexpr uint8_t kP2CmCommand = 0x55U;         ///< P2_CM_COMMAND.
inline constexpr uint8_t kP2Restrict = 0x57U;          ///< P2_RESTRICT.
inline constexpr uint8_t kP2Sanity = 0x58U;            ///< P2_SANITY.
inline constexpr uint8_t kP2PrfBoth = 0x5AU;           ///< P2_PRF_BOTH.
inline constexpr uint8_t kP2State = 0x5BU;             ///< P2_STATE.
inline constexpr uint8_t kP2Ecpm = 0x62U;              ///< P2_ECPM.
/// @}

/// @name TLV tags (AN12543 Table 33)
/// @{
inline constexpr uint8_t kTagSessionId = 0x10U;       ///< TAG_SESSION_ID.
inline constexpr uint8_t kTagPolicy = 0x11U;          ///< TAG_POLICY.
inline constexpr uint8_t kTagMaxAttempts = 0x12U;     ///< TAG_MAX_ATTEMPTS.
inline constexpr uint8_t kTagImportAuthData = 0x13U;  ///< TAG_IMPORT_AUTH_DATA.
inline constexpr uint8_t kTagImportAuthKeyId = 0x14U; ///< TAG_IMPORT_AUTH_KEY_ID.
inline constexpr uint8_t kTag1 = 0x41U;               ///< TAG_1.
inline constexpr uint8_t kTag2 = 0x42U;               ///< TAG_2.
inline constexpr uint8_t kTag3 = 0x43U;               ///< TAG_3.
inline constexpr uint8_t kTag4 = 0x44U;               ///< TAG_4.
inline constexpr uint8_t kTag5 = 0x45U;               ///< TAG_5.
inline constexpr uint8_t kTag6 = 0x46U;               ///< TAG_6.
inline constexpr uint8_t kTag7 = 0x47U;               ///< TAG_7.
inline constexpr uint8_t kTag8 = 0x48U;               ///< TAG_8.
inline constexpr uint8_t kTag9 = 0x49U;               ///< TAG_9.
inline constexpr uint8_t kTag10 = 0x4AU;              ///< TAG_10.
inline constexpr uint8_t kTag11 = 0x4BU;              ///< TAG_11.
inline constexpr uint8_t kTagTimestamp = 0x4FU;       ///< TAG_TS.
inline constexpr uint8_t kTagSignature = 0x52U;       ///< TAG_ATT_SIG.
/// @}

/// @name Small enumerations (AN12543 Tables 49 to 58)
/// @{
inline constexpr uint8_t kLockPersistent = 0x02U;     ///< PERSISTENT_LOCK.
inline constexpr uint8_t kLockLocked = 0x01U;         ///< LOCKED.
inline constexpr uint8_t kRestrictNew = 0x01U;        ///< RESTRICT_NEW.
inline constexpr uint8_t kRestrictAll = 0x02U;        ///< RESTRICT_ALL.
inline constexpr uint8_t kResultSuccess = 0x01U;      ///< RESULT_SUCCESS.
inline constexpr uint8_t kResultFailure = 0x02U;      ///< RESULT_FAILURE.
inline constexpr uint8_t kPersistent = 0x01U;         ///< TransientIndicator PERSISTENT.
inline constexpr uint8_t kTransient = 0x02U;          ///< TransientIndicator TRANSIENT.
inline constexpr uint8_t kNoMore = 0x01U;             ///< MoreIndicator NO_MORE.
inline constexpr uint8_t kMore = 0x02U;               ///< MoreIndicator MORE.
inline constexpr uint8_t kScpRequired = 0x01U;        ///< SCP_REQUIRED.
inline constexpr uint8_t kScpNotRequired = 0x02U;     ///< SCP_NOT_REQUIRED.
inline constexpr uint8_t kSigEd25519Pure = 0xA3U;     ///< SIG_ED25519PURE.
inline constexpr uint8_t kSigEcdaa = 0xF4U;           ///< SIG_ECDAA (AN12413 Table 30).
inline constexpr uint8_t kEcdhSvdpDh = 0x01U;         ///< EC_SVDP_DH (SHA-1 of X).
inline constexpr uint8_t kEcpmDhPlainXy = 0x06U;      ///< EC_SVDP_DH_PLAIN_XY.
inline constexpr uint8_t kSetIndicatorSet = 0x02U;    ///< SetIndicator SET.
inline constexpr uint8_t kSetIndicatorNotSet = 0x01U; ///< SetIndicator NOT_SET.
inline constexpr uint8_t kRsaCompMod = 0x00U;         ///< RSA_COMP_MOD.
inline constexpr uint8_t kRsaCompPubExp = 0x01U;      ///< RSA_COMP_PUB_EXP.
inline constexpr uint8_t kRsaCompLast = 0x07U;        ///< RSA_COMP_INVQ, the last component.
inline constexpr uint8_t kIdListAnyType = 0xFFU;      ///< ReadIDList filter: every type.
/// @}

/// @name AppletConfig bits (AN12543 Table 8, AN12413 Table 40)
/// @{
inline constexpr uint16_t kConfigEcdaa = 0x0001U;        ///< CONFIG_ECDAA (3.x); reserved on 7.x.
inline constexpr uint16_t kConfigEcdsa = 0x0002U;        ///< CONFIG_ECDSA_ECDH_ECDHE.
inline constexpr uint16_t kConfigEddsa = 0x0004U;        ///< CONFIG_EDDSA.
inline constexpr uint16_t kConfigDhMont = 0x0008U;       ///< CONFIG_DH_MONT.
inline constexpr uint16_t kConfigHmac = 0x0010U;         ///< CONFIG_HMAC.
inline constexpr uint16_t kConfigRsaPlain = 0x0020U;     ///< CONFIG_RSA_PLAIN.
inline constexpr uint16_t kConfigRsaCrt = 0x0040U;       ///< CONFIG_RSA_CRT.
inline constexpr uint16_t kConfigAes = 0x0080U;          ///< CONFIG_AES.
inline constexpr uint16_t kConfigDes = 0x0100U;          ///< CONFIG_DES.
inline constexpr uint16_t kConfigPbkdf = 0x0200U;        ///< CONFIG_PBKDF.
inline constexpr uint16_t kConfigTls = 0x0400U;          ///< CONFIG_TLS.
inline constexpr uint16_t kConfigMifare = 0x0800U;       ///< CONFIG_MIFARE.
inline constexpr uint16_t kConfigFipsDisabled = 0x1000U; ///< CONFIG_FIPS_MODE_DISABLED (3.x only).
inline constexpr uint16_t kConfigI2cm = 0x2000U;         ///< CONFIG_I2CM.
/// @}

/// @name Limits of the applet (AN12543 pp. 3, 43, 50, 102-105, 125, 130-133; AN13030 p. 641)
/// @{
inline constexpr std::size_t kUserIdMin = 4U;            ///< Shortest UserID value written (SE051).
inline constexpr std::size_t kUserIdMax = 16U;           ///< Longest UserID value.
inline constexpr std::size_t kI2cmCommandMax = 255U;     ///< MAX_I2CM_COMMAND_LENGTH.
inline constexpr std::size_t kHkdfSaltMax = 64U;         ///< HKDF salt (before applet 7.2.46).
inline constexpr std::size_t kHkdfInfoMax = 80U;         ///< HKDF info (applet 7.x).
inline constexpr uint16_t kHkdfOutputMax = 768U;         ///< HKDF output length.
inline constexpr std::size_t kPbkdfSaltMax = 64U;        ///< PBKDF2 salt.
inline constexpr uint16_t kPbkdfIterationsMax = 0x7FFFU; ///< PBKDF2 iteration count.
inline constexpr uint16_t kPbkdfOutputMax = 512U;        ///< PBKDF2 output length.
inline constexpr std::size_t kTlsLabelMax = 64U;         ///< TLS PRF label.
inline constexpr uint16_t kTlsPrfOutputMax = 512U;       ///< TLS PRF output length.
inline constexpr std::size_t kTlsRandom = 32U;           ///< TLS random.
inline constexpr uint16_t kBinaryFileMax = 0x7FFFU;      ///< Largest binary file.
inline constexpr std::size_t kHmacKeyMax = 256U;         ///< Longest HMAC key.
inline constexpr uint32_t kVersionMax = 0x07FFFFFFU;     ///< Largest object version (see below).
inline constexpr std::size_t kGcmIvMin = 12U;            ///< Shortest GCM IV.
inline constexpr std::size_t kGcmIvMax = 60U;            ///< Longest GCM IV.
inline constexpr std::size_t kCcmNonceMin = 7U;          ///< Shortest CCM nonce.
inline constexpr std::size_t kCcmNonceMax = 13U;         ///< Longest CCM nonce.
inline constexpr std::size_t kAeadTagMin = 4U;           ///< Shortest AEAD tag.
inline constexpr std::size_t kAeadTagMax = 16U;          ///< Longest AEAD tag (always 16 out).
inline constexpr std::size_t kDfDivInputMax = 31U;       ///< DESFire diversification input.
inline constexpr std::size_t kAttestedSignatureMax = 520U; ///< RSA-4096 signature plus margin.
/// @}

/// The applet instance AID (AN12543 Table 64).
inline constexpr std::array<uint8_t, 16> kAppletAid{0xA0U, 0x00U, 0x00U, 0x03U, 0x96U, 0x54U,
                                                    0x53U, 0x00U, 0x00U, 0x00U, 0x01U, 0x03U,
                                                    0x00U, 0x00U, 0x00U, 0x00U};

/// The self tests of `TriggerSelfTest` (AN12543 Table 57, HealthCheckMode).
inline constexpr std::array<uint16_t, 6> kHealthCheckModes{0xF906U, 0xFE01U, 0xFD02U,
                                                           0xFC03U, 0xFB04U, 0xFA05U};

// The maximum version: AN12543 4.7.1.1 prints "134217727 (or 0x7FFFFFFF)"; 134217727 is 0x07FFFFFF.
// The smaller of the two is the bound, so a value the chip may refuse is refused before sending.
static_assert(kVersionMax == 134217727U);

/** @brief The wire facts of one curve: identifier and the key lengths the applet expects. */
struct CurveInfo {
  uint8_t id{0};             ///< ECCurve identifier (AN12543 Table 44).
  uint8_t private_length{0}; ///< Private key length in bytes; 0 when the import is refused.
  uint8_t public_length{0};  ///< Public key length in bytes.
  bool weierstrass{false};   ///< A short Weierstrass curve: public key `04 || X || Y`.
  bool edwards{false};       ///< Ed25519: public key byte-reversed on the wire.
  bool montgomery{false};    ///< X25519 or X448: private and public key byte-reversed.
};

namespace detail {
/// One row per `EcCurve` enumerator, in enumerator order. Field sizes from SEC 2, RFC 5639,
/// RFC 8032 and RFC 7748. secp160k1 and secp224k1 have a 161-bit and a 225-bit order, so the
/// private key length the applet expects (field or order size) is not stated: their import is
/// refused (errata JOS.1: a wrong EC key length resets the chip); on-chip generation stays.
inline constexpr std::array<CurveInfo, 20> kCurves{{
    {.id = 0x01U,
     .private_length = 24U,
     .public_length = 49U,
     .weierstrass = true,
     .edwards = false,
     .montgomery = false}, // NIST P-192
    {.id = 0x02U,
     .private_length = 28U,
     .public_length = 57U,
     .weierstrass = true,
     .edwards = false,
     .montgomery = false}, // NIST P-224
    {.id = 0x03U,
     .private_length = 32U,
     .public_length = 65U,
     .weierstrass = true,
     .edwards = false,
     .montgomery = false}, // NIST P-256
    {.id = 0x04U,
     .private_length = 48U,
     .public_length = 97U,
     .weierstrass = true,
     .edwards = false,
     .montgomery = false}, // NIST P-384
    {.id = 0x05U,
     .private_length = 66U,
     .public_length = 133U,
     .weierstrass = true,
     .edwards = false,
     .montgomery = false}, // NIST P-521
    {.id = 0x06U,
     .private_length = 20U,
     .public_length = 41U,
     .weierstrass = true,
     .edwards = false,
     .montgomery = false}, // Brainpool P160r1
    {.id = 0x07U,
     .private_length = 24U,
     .public_length = 49U,
     .weierstrass = true,
     .edwards = false,
     .montgomery = false}, // Brainpool P192r1
    {.id = 0x08U,
     .private_length = 28U,
     .public_length = 57U,
     .weierstrass = true,
     .edwards = false,
     .montgomery = false}, // Brainpool P224r1
    {.id = 0x09U,
     .private_length = 32U,
     .public_length = 65U,
     .weierstrass = true,
     .edwards = false,
     .montgomery = false}, // Brainpool P256r1
    {.id = 0x0AU,
     .private_length = 40U,
     .public_length = 81U,
     .weierstrass = true,
     .edwards = false,
     .montgomery = false}, // Brainpool P320r1
    {.id = 0x0BU,
     .private_length = 48U,
     .public_length = 97U,
     .weierstrass = true,
     .edwards = false,
     .montgomery = false}, // Brainpool P384r1
    {.id = 0x0CU,
     .private_length = 64U,
     .public_length = 129U,
     .weierstrass = true,
     .edwards = false,
     .montgomery = false}, // Brainpool P512r1
    {.id = 0x0DU,
     .private_length = 0U,
     .public_length = 41U,
     .weierstrass = true,
     .edwards = false,
     .montgomery = false}, // secp160k1 (private import refused, see above)
    {.id = 0x0EU,
     .private_length = 24U,
     .public_length = 49U,
     .weierstrass = true,
     .edwards = false,
     .montgomery = false}, // secp192k1
    {.id = 0x0FU,
     .private_length = 0U,
     .public_length = 57U,
     .weierstrass = true,
     .edwards = false,
     .montgomery = false}, // secp224k1 (private import refused, see above)
    {.id = 0x10U,
     .private_length = 32U,
     .public_length = 65U,
     .weierstrass = true,
     .edwards = false,
     .montgomery = false}, // secp256k1
    {.id = 0x11U,
     .private_length = 32U,
     .public_length = 65U,
     .weierstrass = true,
     .edwards = false,
     .montgomery = false}, // TPM BN-P256 (applet 3.x)
    {.id = 0x40U,
     .private_length = 32U,
     .public_length = 32U,
     .weierstrass = false,
     .edwards = true,
     .montgomery = false}, // Ed25519
    {.id = 0x41U,
     .private_length = 32U,
     .public_length = 32U,
     .weierstrass = false,
     .edwards = false,
     .montgomery = true}, // Curve25519 (X25519)
    {.id = 0x43U,
     .private_length = 56U,
     .public_length = 56U,
     .weierstrass = false,
     .edwards = false,
     .montgomery = true}, // Curve448 (X448)
}};
} // namespace detail

/**
 * @brief The wire facts of a curve.
 * @param curve The curve; a value that is not an enumerator gives an all-zero row.
 * @return The row of `detail::kCurves`.
 */
constexpr CurveInfo CurveOf(EcCurve curve) noexcept {
  if (!se05x::detail::IsEnumerator(curve)) {
    return CurveInfo{};
  }
  return detail::kCurves[static_cast<std::size_t>(se05x::detail::ToUnderlying(curve))];
}

/**
 * @brief The `EcCurve` of a wire curve identifier.
 * @param id The ECCurve identifier.
 * @param curve Receives the curve.
 * @return false for an identifier this driver does not know.
 */
constexpr bool CurveFromWire(uint8_t id, EcCurve& curve) noexcept {
  for (std::size_t i = 0U; i < detail::kCurves.size(); ++i) {
    if (detail::kCurves[i].id == id) {
      curve = static_cast<EcCurve>(static_cast<uint8_t>(i));
      return true;
    }
  }
  return false;
}

/**
 * @brief The digest length of a hash.
 * @param mode The digest.
 * @return The length in bytes; 0 for a value that is not an enumerator.
 */
constexpr std::size_t DigestLength(DigestMode mode) noexcept {
  switch (mode) {
  case DigestMode::Sha1:
    return 20U;
  case DigestMode::Sha224:
    return 28U;
  case DigestMode::Sha256:
    return 32U;
  case DigestMode::Sha384:
    return 48U;
  case DigestMode::Sha512:
    return 64U;
  default:
    break;
  }
  return 0U;
}

/**
 * @brief DigestMode on the wire (AN12543 Table 42).
 * @param mode The digest.
 * @param wire Receives the value.
 * @return false for a value that is not an enumerator.
 */
constexpr bool DigestWire(DigestMode mode, uint8_t& wire) noexcept {
  constexpr std::array<uint8_t, 5> kWire{0x01U, 0x07U, 0x04U, 0x05U, 0x06U};
  if (!se05x::detail::IsEnumerator(mode)) {
    return false;
  }
  wire = kWire[static_cast<std::size_t>(se05x::detail::ToUnderlying(mode))];
  return true;
}

/**
 * @brief ECSignatureAlgo on the wire (AN12543 Table 34). `Plain` (SIG_ECDSA_PLAIN) is marked
 * NOT SUPPORTED by both specifications; `Ed25519Pure` is the EdDSA value (Table 35).
 * @param algo The algorithm.
 * @param wire Receives the value.
 * @return false for `Plain` and for a value that is not an enumerator.
 */
constexpr bool EcSignWire(EcSignAlgo algo, uint8_t& wire) noexcept {
  constexpr std::array<uint8_t, 7> kWire{0x00U, 0x11U, 0x25U, 0x21U, 0x22U, 0x26U, 0xA3U};
  if (!se05x::detail::IsEnumerator(algo) || (algo == EcSignAlgo::Plain)) {
    return false;
  }
  wire = kWire[static_cast<std::size_t>(se05x::detail::ToUnderlying(algo))];
  return true;
}

/**
 * @brief The digest length an ECDSA algorithm signs (the input length of `ECDSASign`).
 * @param algo The algorithm.
 * @return 20 to 64; 0 for `Plain`, `Ed25519Pure` and non-enumerators.
 */
constexpr std::size_t EcSignDigestLength(EcSignAlgo algo) noexcept {
  constexpr std::array<std::size_t, 7> kLength{0U, 20U, 28U, 32U, 48U, 64U, 0U};
  if (!se05x::detail::IsEnumerator(algo)) {
    return 0U;
  }
  return kLength[static_cast<std::size_t>(se05x::detail::ToUnderlying(algo))];
}

/**
 * @brief RSASignatureAlgo on the wire (AN12543 Table 38).
 * @param algo The algorithm.
 * @param wire Receives the value.
 * @return false for a value that is not an enumerator.
 */
constexpr bool RsaSignWire(RsaSignAlgo algo, uint8_t& wire) noexcept {
  constexpr std::array<uint8_t, 10> kWire{0x15U, 0x2BU, 0x2CU, 0x2DU, 0x2EU,
                                          0x0AU, 0x27U, 0x28U, 0x29U, 0x2AU};
  if (!se05x::detail::IsEnumerator(algo)) {
    return false;
  }
  wire = kWire[static_cast<std::size_t>(se05x::detail::ToUnderlying(algo))];
  return true;
}

/**
 * @brief The digest length of an RSA signature algorithm. `RSASign` takes the digest the host
 * computed (derived: the specification does not state whether TLV[TAG_3] is the digest or the
 * message; the middleware passes the digest).
 * @param algo The algorithm.
 * @return 20 to 64; 0 for a non-enumerator.
 */
constexpr std::size_t RsaSignDigestLength(RsaSignAlgo algo) noexcept {
  constexpr std::array<std::size_t, 10> kLength{20U, 28U, 32U, 48U, 64U, 20U, 28U, 32U, 48U, 64U};
  if (!se05x::detail::IsEnumerator(algo)) {
    return 0U;
  }
  return kLength[static_cast<std::size_t>(se05x::detail::ToUnderlying(algo))];
}

/**
 * @brief RSAEncryptionAlgo on the wire (AN12543 Table 39).
 * @param algo The algorithm.
 * @param wire Receives the value.
 * @return false for a value that is not an enumerator.
 */
constexpr bool RsaCryptWire(RsaCryptAlgo algo, uint8_t& wire) noexcept {
  constexpr std::array<uint8_t, 3> kWire{0x0CU, 0x0AU, 0x0FU};
  if (!se05x::detail::IsEnumerator(algo)) {
    return false;
  }
  wire = kWire[static_cast<std::size_t>(se05x::detail::ToUnderlying(algo))];
  return true;
}

/** @brief The wire value of a cipher mode and the IV it needs. */
struct CipherModeInfo {
  uint8_t wire{0};      ///< CipherMode value (AN12543 Table 46); 0 when NOT SUPPORTED.
  uint8_t iv_length{0}; ///< IV length in bytes; 0 for ECB.
};

/**
 * @brief The wire value and IV length of a cipher mode. The rows marked NOT SUPPORTED in AN12543
 * Table 46 (DES CBC PKCS5, every DES ECB padding, AES CBC PKCS5) have `wire == 0`.
 * @param mode The mode.
 * @return The row; all zero for a value that is not an enumerator.
 */
constexpr CipherModeInfo CipherModeOf(CipherMode mode) noexcept {
  constexpr std::array<CipherModeInfo, 14> kModes{{
      {.wire = 0x01U, .iv_length = 8U},  // DES CBC no padding
      {.wire = 0x02U, .iv_length = 8U},  // DES CBC ISO 9797 M1
      {.wire = 0x03U, .iv_length = 8U},  // DES CBC ISO 9797 M2
      {.wire = 0x00U, .iv_length = 0U},  // DES CBC PKCS5: NOT SUPPORTED
      {.wire = 0x05U, .iv_length = 0U},  // DES ECB no padding
      {.wire = 0x00U, .iv_length = 0U},  // DES ECB ISO 9797 M1: NOT SUPPORTED
      {.wire = 0x00U, .iv_length = 0U},  // DES ECB ISO 9797 M2: NOT SUPPORTED
      {.wire = 0x00U, .iv_length = 0U},  // DES ECB PKCS5: NOT SUPPORTED
      {.wire = 0x0EU, .iv_length = 0U},  // AES ECB no padding
      {.wire = 0x0DU, .iv_length = 16U}, // AES CBC no padding
      {.wire = 0x16U, .iv_length = 16U}, // AES CBC ISO 9797 M1
      {.wire = 0x17U, .iv_length = 16U}, // AES CBC ISO 9797 M2
      {.wire = 0x00U, .iv_length = 0U},  // AES CBC PKCS5: NOT SUPPORTED
      {.wire = 0xF0U, .iv_length = 16U}, // AES CTR
  }};
  if (!se05x::detail::IsEnumerator(mode)) {
    return CipherModeInfo{};
  }
  return kModes[static_cast<std::size_t>(se05x::detail::ToUnderlying(mode))];
}

/**
 * @brief AEADMode on the wire (AN12543 Table 47).
 * @param mode The mode.
 * @param wire Receives the value.
 * @return false for a value that is not an enumerator.
 */
constexpr bool AeadWire(AeadMode mode, uint8_t& wire) noexcept {
  switch (mode) {
  case AeadMode::AesGcm:
    wire = 0xB0U;
    return true;
  case AeadMode::AesCcm:
    wire = 0xF4U;
    return true;
  default:
    break;
  }
  return false;
}

/**
 * @brief MACAlgo on the wire (AN12543 Table 43).
 * @param algo The algorithm.
 * @param wire Receives the value.
 * @return false for a value that is not an enumerator.
 */
constexpr bool MacWire(MacAlgo algo, uint8_t& wire) noexcept {
  constexpr std::array<uint8_t, 6> kWire{0x18U, 0x19U, 0x1AU, 0x1BU, 0x31U, 0x7AU};
  if (!se05x::detail::IsEnumerator(algo)) {
    return false;
  }
  wire = kWire[static_cast<std::size_t>(se05x::detail::ToUnderlying(algo))];
  return true;
}

/**
 * @brief The HMAC MACAlgo of a digest, for PBKDF2 (AN12543 4.15.2.1 PBKDF2DeriveKey: HMAC only).
 * @param mode The digest.
 * @param wire Receives the value.
 * @return false for SHA-224 (no HMAC-SHA224 in Table 43) and non-enumerators.
 */
constexpr bool HmacOfDigest(DigestMode mode, uint8_t& wire) noexcept {
  switch (mode) {
  case DigestMode::Sha1:
    wire = 0x18U;
    return true;
  case DigestMode::Sha256:
    wire = 0x19U;
    return true;
  case DigestMode::Sha384:
    wire = 0x1AU;
    return true;
  case DigestMode::Sha512:
    wire = 0x1BU;
    return true;
  case DigestMode::Sha224:
    break;
  default:
    break;
  }
  return false;
}

/**
 * @brief AttestationAlgo on the wire: an ECSignatureAlgo or an RSASignatureAlgo (AN12543 4.3.24).
 * `EcPlain` is not supported by the applet and `Ed25519` is not an attestation algorithm.
 * @param algo The algorithm.
 * @param wire Receives the value.
 * @return false for `EcPlain`, `Ed25519` and non-enumerators.
 */
constexpr bool AttestationWire(AttestationAlgo algo, uint8_t& wire) noexcept {
  constexpr std::array<uint8_t, 13> kWire{0x00U, 0x11U, 0x25U, 0x21U, 0x22U, 0x26U, 0x00U,
                                          0x2CU, 0x2DU, 0x2EU, 0x28U, 0x29U, 0x2AU};
  if (!se05x::detail::IsEnumerator(algo)) {
    return false;
  }
  const uint8_t value = kWire[static_cast<std::size_t>(se05x::detail::ToUnderlying(algo))];
  if (value == 0U) {
    return false;
  }
  wire = value;
  return true;
}

/**
 * @brief Memory on the wire (AN12543 Table 31).
 * @param memory The memory kind.
 * @param wire Receives the value.
 * @return false for a value that is not an enumerator.
 */
constexpr bool MemoryWire(MemoryType memory, uint8_t& wire) noexcept {
  if (!se05x::detail::IsEnumerator(memory)) {
    return false;
  }
  wire = static_cast<uint8_t>(se05x::detail::ToUnderlying(memory) + 1U);
  return true;
}

/**
 * @brief CryptoContext on the wire (AN12543 Table 52); a MAC context is CC_SIGNATURE.
 * @param type The crypto object type.
 * @param wire Receives the value.
 * @return false for a value that is not an enumerator.
 */
constexpr bool CryptoContextWire(CryptoObjectType type, uint8_t& wire) noexcept {
  switch (type) {
  case CryptoObjectType::Digest:
    wire = 0x01U;
    return true;
  case CryptoObjectType::Cipher:
    wire = 0x02U;
    return true;
  case CryptoObjectType::Mac:
    wire = 0x03U;
    return true;
  case CryptoObjectType::Aead:
    wire = 0x04U;
    return true;
  default:
    break;
  }
  return false;
}

/**
 * @brief Origin from the wire (AN12543 Table 32).
 * @param wire The value.
 * @param origin Receives the origin.
 * @return false for a value outside 1 to 3.
 */
constexpr bool OriginFromWire(uint8_t wire, Origin& origin) noexcept {
  if ((wire < 1U) || (wire > 3U)) {
    return false;
  }
  origin = static_cast<Origin>(static_cast<uint8_t>(wire - 1U));
  return true;
}

/**
 * @brief The object class of a SecureObjectType (AN12543 Table 30, AN12413 Table 24). On applet
 * 7.x the EC types carry the curve (0x21 to 0x73): the low two bits give pair (01), private (10)
 * or public (11) key, and the high bits select the curve.
 * @param wire The SecureObjectType.
 * @param object_class Receives the class.
 * @return false for an unknown type.
 */
constexpr bool ClassFromWire(uint8_t wire, ObjectClass& object_class) noexcept {
  constexpr std::array<uint8_t, 16> kWire{0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U,
                                          0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0FU, 0x10U, 0x11U};
  constexpr std::array<ObjectClass, 16> kClass{
      ObjectClass::EcKeyPair,  ObjectClass::EcPrivKey,  ObjectClass::EcPubKey,
      ObjectClass::RsaKeyPair, ObjectClass::RsaKeyPair, ObjectClass::RsaPrivKey,
      ObjectClass::RsaPrivKey, ObjectClass::RsaPubKey,  ObjectClass::AesKey,
      ObjectClass::DesKey,     ObjectClass::BinaryFile, ObjectClass::UserId,
      ObjectClass::Counter,    ObjectClass::Pcr,        ObjectClass::Curve,
      ObjectClass::HmacKey};
  for (std::size_t i = 0U; i < kClass.size(); ++i) {
    if (kWire[i] == wire) {
      object_class = kClass[i];
      return true;
    }
  }
  const uint32_t low = static_cast<uint32_t>(wire) & 0x03U;
  if ((wire >= 0x21U) && (wire <= 0x73U) && (low != 0U)) {
    constexpr std::array<ObjectClass, 3> kEc{ObjectClass::EcKeyPair, ObjectClass::EcPrivKey,
                                             ObjectClass::EcPubKey};
    object_class = kEc[low - 1U];
    return true;
  }
  return false;
}

/**
 * @brief The SecureObjectType filter of `ReadIDList` for an object class (the curve-less EC
 * types and the CRT RSA types are used; derived from AN12543 Table 30, not verified on hardware).
 * @param object_class The class.
 * @param wire Receives the value.
 * @return false for a value that is not an enumerator.
 */
constexpr bool ClassFilterWire(ObjectClass object_class, uint8_t& wire) noexcept {
  constexpr std::array<uint8_t, 14> kWire{0x01U, 0x02U, 0x03U, 0x05U, 0x07U, 0x08U, 0x09U,
                                          0x0AU, 0x11U, 0x0BU, 0x0CU, 0x0DU, 0x0FU, 0x10U};
  if (!se05x::detail::IsEnumerator(object_class)) {
    return false;
  }
  wire = kWire[static_cast<std::size_t>(se05x::detail::ToUnderlying(object_class))];
  return true;
}

/** @} */

} // namespace se05x::apdu

#endif // SE05X_APDU_CONSTS_HPP
