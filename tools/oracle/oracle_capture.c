/*
 * oracle_capture.c: drives a vendor middleware checkout as a test oracle. Each call below runs one
 * middleware command builder with a transmit hook that records the APDU header, the TLV body and
 * whether an Le was asked for, and never talks to a chip. The records are printed as a C++ header
 * of constants that tests/test_apdu_oracle.cpp compares the driver's codecs against (header and
 * body only: the two frame short and extended APDUs differently, see the report).
 *
 * Built only by tools/oracle/build_oracle.sh against a pinned checkout outside the repository; no
 * middleware code is copied into the repository.
 *
 * Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sm_types.h>
#include "fsl_sss_ftr.h"
#include "se05x_tlv.h"
#include "se05x_const.h"
#include "se05x_APDU.h"

/* Logging and the case helper the middleware links against; neither matters for capture. */
void nLog(const char *comp, int level, const char *format, ...)
{
    (void)comp;
    (void)level;
    (void)format;
}

int smApduGetTxRxCase(uint8_t *apdu, size_t apduLen, size_t *data_offset, size_t *dataLen, int32_t *extendedLength)
{
    (void)apdu;
    (void)apduLen;
    (void)data_offset;
    (void)dataLen;
    (void)extendedLength;
    return 0;
}

static uint8_t g_hdr[4];
static uint8_t g_body[2048];
static size_t g_len;
static int g_hasle;
static int g_calls;

static smStatus_t Capture(struct Se05xSession *s, const tlvHeader_t *hdr, uint8_t *cmd, size_t len, uint8_t *rsp,
    size_t *rspLen, uint8_t hasle)
{
    (void)s;
    (void)rsp;
    if (g_calls == 0) {
        memcpy(g_hdr, hdr->hdr, 4);
        if (len > sizeof(g_body)) {
            len = sizeof(g_body);
        }
        memcpy(g_body, cmd, len);
        g_len   = len;
        g_hasle = hasle;
    }
    g_calls++;
    if (rspLen != NULL) {
        *rspLen = 0;
    }
    return SM_NOT_OK; /* stop the builder before it parses a reply */
}

static Se05xSession_t g_session;

static void Begin(void)
{
    memset(&g_session, 0, sizeof(g_session));
    g_session.fp_TXn = Capture;
    g_calls          = 0;
    g_len            = 0;
}

static void Emit(const char *name)
{
    size_t i;
    if (g_calls == 0) {
        printf("// %s: the middleware sent nothing\n", name);
        return;
    }
    printf("inline constexpr std::array<uint8_t, %zuU> k%sBody{", g_len, name);
    for (i = 0; i < g_len; i++) {
        printf("%s0x%02XU", (i == 0) ? "" : ", ", g_body[i]);
    }
    printf("};\n");
    printf("inline constexpr Apdu k%s{{0x%02XU, 0x%02XU, 0x%02XU, 0x%02XU}, k%sBody, %s};\n", name, g_hdr[0], g_hdr[1],
        g_hdr[2], g_hdr[3], name, g_hasle ? "true" : "false");
}

/* Applet 3.x has the same builders without the trailing version argument. */
#if SSS_HAVE_SE05X_VER_GTE_07_02
#define WRITE_EC(...) Se05x_API_WriteECKey_Ver(__VA_ARGS__, 0)
#define WRITE_SYMM(...) Se05x_API_WriteSymmKey_Ver(__VA_ARGS__, 0)
#define WRITE_BIN(...) Se05x_API_WriteBinary_Ver(__VA_ARGS__, 0)
#else
#define WRITE_EC(...) Se05x_API_WriteECKey(__VA_ARGS__)
#define WRITE_SYMM(...) Se05x_API_WriteSymmKey(__VA_ARGS__)
#define WRITE_BIN(...) Se05x_API_WriteBinary(__VA_ARGS__)
#endif

#define RUN(name, call) \
    do {                \
        Begin();        \
        (void)(call);   \
        Emit(name);     \
    } while (0)

int main(void)
{
    static uint8_t out[1024];
    static uint8_t out2[1024];
    static uint8_t out3[64];
    size_t n  = sizeof(out);
    size_t n2 = sizeof(out2);
    size_t n3 = sizeof(out3);
    uint16_t u16;
    uint32_t u32;
    uint8_t u8;
    SE05x_Result_t res;
    SE05x_SecureObjectType_t type;
    SE05x_TimeStamp_t ts;
    uint8_t policy_bytes[] = {0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    Se05xPolicy_t policy   = {policy_bytes, sizeof(policy_bytes)};
    const uint8_t key16[16]  = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F};
    uint8_t iv16[16]         = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
        0xAE, 0xAF};
    const uint8_t digest32[32] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F};
    uint8_t point65[65];
    uint8_t rnd16[16];
    uint8_t big[300];
    const uint8_t user_id[4] = {0x55, 0x66, 0x77, 0x88};
    const uint8_t label[]    = "master secret";
    const uint8_t sig8[8]    = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02};
    SE05x_CryptoModeSubType_t sub;
    size_t i;

    for (i = 0; i < sizeof(point65); i++) {
        point65[i] = (uint8_t)i;
    }
    point65[0] = 0x04;
    for (i = 0; i < sizeof(rnd16); i++) {
        rnd16[i] = (uint8_t)(0xC0U + i);
    }
    for (i = 0; i < sizeof(big); i++) {
        big[i] = (uint8_t)(i & 0xFFU);
    }

    printf("// Generated by tools/oracle/oracle_capture.c from the pinned middleware checkout named in\n");
    printf("// tests/vectors/THIRD_PARTY.md. Do not edit; regenerate with tools/oracle/build_oracle.sh.\n");

    RUN("GetVersion", Se05x_API_GetVersion(&g_session, out, &n));
#if SSS_HAVE_SE05X_VER_GTE_07_02
    RUN("ReadState", Se05x_API_ReadState(&g_session, out, &n));
#endif
    RUN("GetRandom", Se05x_API_GetRandom(&g_session, 32U, out, &n));
    RUN("GetFreeMemory", Se05x_API_GetFreeMemory(&g_session, kSE05x_MemoryType_PERSISTENT, &u32));
    RUN("CreateSession", Se05x_API_CreateSession(&g_session, 0x7FFF0201U, out, &n));
    RUN("CloseSession", Se05x_API_CloseSession(&g_session));
    RUN("VerifyUserId", Se05x_API_VerifySessionUserID(&g_session, user_id, sizeof(user_id)));
    RUN("SetLockState", Se05x_API_SetLockState(&g_session, kSE05x_LockIndicator_PERSISTENT_LOCK, kSE05x_LockState_LOCKED));
#if SSS_HAVE_SE05X_VER_GTE_07_02
    RUN("DisableObjCreation",
        Se05x_API_DisableObjCreation(&g_session, kSE05x_LockIndicator_PERSISTENT_LOCK, kSE05x_RestrictMode_RESTRICT_NEW));
#endif
    RUN("DeleteAll", Se05x_API_DeleteAll(&g_session));

    RUN("WriteEcKeyPair",
        WRITE_EC(&g_session, NULL, 0, 0x00000100U, kSE05x_ECCurve_NIST_P256, NULL, 0, NULL, 0,
            kSE05x_INS_NA, kSE05x_KeyPart_Pair));
    RUN("WriteEcPublic",
        WRITE_EC(&g_session, &policy, 0, 0x00000101U, kSE05x_ECCurve_NIST_P256, NULL, 0, point65,
            sizeof(point65), kSE05x_INS_NA, kSE05x_KeyPart_Public));
    RUN("WriteSymmKey",
        WRITE_SYMM(&g_session, NULL, 0, 0x00000102U, SE05x_KeyID_KEK_NONE, key16, sizeof(key16),
            kSE05x_INS_NA, kSE05x_SymmKeyType_AES));
    RUN("WriteSymmKeyTransient",
        WRITE_SYMM(&g_session, NULL, 0, 0x00000103U, SE05x_KeyID_KEK_NONE, key16, sizeof(key16),
            kSE05x_INS_TRANSIENT, kSE05x_SymmKeyType_AES));
    RUN("WriteBinaryCreate",
        WRITE_BIN(&g_session, NULL, 0x00000104U, 0, 16U, key16, sizeof(key16)));
    RUN("WriteBinaryOffset", WRITE_BIN(&g_session, NULL, 0x00000104U, 8U, 0, key16, 8U));
    RUN("WriteBinaryLong", WRITE_BIN(&g_session, NULL, 0x00000105U, 0, 300U, big, sizeof(big)));
    RUN("WriteUserId",
        Se05x_API_WriteUserID(&g_session, NULL, 5U, 0x00000106U, user_id, sizeof(user_id), kSE05x_AttestationType_None));
    RUN("CreateCounter", Se05x_API_CreateCounter(&g_session, NULL, 0x00000107U, 4U));
    RUN("SetCounterValue", Se05x_API_SetCounterValue(&g_session, 0x00000107U, 4U, 0x01020304U));
    RUN("IncCounter", Se05x_API_IncCounter(&g_session, 0x00000107U));
    RUN("WritePcr", Se05x_API_WritePCR(&g_session, NULL, 0x00000108U, digest32, sizeof(digest32), NULL, 0));
    RUN("ExtendPcr", Se05x_API_WritePCR(&g_session, NULL, 0x00000108U, NULL, 0, key16, sizeof(key16)));

    RUN("ReadObject", Se05x_API_ReadObject(&g_session, 0x00000100U, 0, 0, out, &n));
    RUN("ReadObjectPart", Se05x_API_ReadObject(&g_session, 0x00000104U, 4U, 8U, out, &n));
    n = sizeof(out);
    n2 = sizeof(out2);
    n3 = sizeof(out3);
#if SSS_HAVE_SE05X_VER_GTE_07_02
    RUN("ReadObjectAttested",
        Se05x_API_ReadObject_W_Attst_V2(&g_session, 0x00000100U, 0, 0, 0xF0000012U, kSE05x_AttestationAlgo_EC_SHA_256,
            rnd16, sizeof(rnd16), out, &n, out2, &n2, &ts, out3, &n3, out3, &n3, out3, &n3, out3, &n3));
#else
    RUN("ReadObjectAttested",
        Se05x_API_ReadObject_W_Attst(&g_session, 0x00000100U, 0, 0, 0xF0000012U, kSE05x_AttestationAlgo_EC_SHA_256,
            rnd16, sizeof(rnd16), out, &n, out2, &n2, &ts, out3, &n3, out3, &n3, out3, &n3));
#endif
    RUN("ExportObject", Se05x_API_ExportObject(&g_session, 0x00000100U, kSE05x_RSAKeyComponent_NA, out, &n));
    RUN("ImportObject", Se05x_API_ImportObject(&g_session, 0x00000100U, kSE05x_RSAKeyComponent_NA, key16, sizeof(key16)));
    RUN("ReadType", Se05x_API_ReadType(&g_session, 0x00000100U, &type, &u8, kSE05x_AttestationType_None));
    RUN("ReadSize", Se05x_API_ReadSize(&g_session, 0x00000100U, &u16));
    RUN("ReadIdList", Se05x_API_ReadIDList(&g_session, 0, 0xFFU, &u8, out, &n));
    RUN("CheckObjectExists", Se05x_API_CheckObjectExists(&g_session, 0x00000100U, &res));
    RUN("DeleteSecureObject", Se05x_API_DeleteSecureObject(&g_session, 0x00000100U));
    RUN("CreateEcCurve", Se05x_API_CreateECCurve(&g_session, kSE05x_ECCurve_NIST_P256));
    RUN("GetEcCurveId", Se05x_API_GetECCurveId(&g_session, 0x00000100U, &u8));
    RUN("ReadEcCurveList", Se05x_API_ReadECCurveList(&g_session, out, &n));
    RUN("DeleteEcCurve", Se05x_API_DeleteECCurve(&g_session, kSE05x_ECCurve_NIST_P256));

    memset(&sub, 0, sizeof(sub));
    sub.cipher = kSE05x_CipherMode_AES_CBC_NOPAD;
    RUN("CreateCryptoObject",
        Se05x_API_CreateCryptoObject(&g_session, (SE05x_CryptoObjectID_t)0x0010, kSE05x_CryptoContext_CIPHER, sub));
    RUN("ReadCryptoObjectList", Se05x_API_ReadCryptoObjectList(&g_session, out, &n));
    RUN("DeleteCryptoObject", Se05x_API_DeleteCryptoObject(&g_session, (SE05x_CryptoObjectID_t)0x0010));
    RUN("EcdsaSign",
        Se05x_API_ECDSASign(&g_session, 0x00000100U, kSE05x_ECSignatureAlgo_SHA_256, digest32, sizeof(digest32), out, &n));
    RUN("EcdsaVerify", Se05x_API_ECDSAVerify(&g_session, 0x00000100U, kSE05x_ECSignatureAlgo_SHA_256, digest32,
                           sizeof(digest32), sig8, sizeof(sig8), &res));
    RUN("EddsaSign", Se05x_API_EdDSASign(&g_session, 0x00000109U, kSE05x_EDSignatureAlgo_ED25519PURE_SHA_512, key16,
                         sizeof(key16), out, &n));
    RUN("Ecdh", Se05x_API_ECDHGenerateSharedSecret(&g_session, 0x00000100U, point65, sizeof(point65), out, &n));
    RUN("RsaSign", Se05x_API_RSASign(&g_session, 0x0000010AU, kSE05x_RSASignatureAlgo_SHA256_PKCS1_PSS, digest32,
                       sizeof(digest32), out, &n));
    RUN("RsaEncrypt", Se05x_API_RSAEncrypt(&g_session, 0x0000010AU, kSE05x_RSAEncryptionAlgo_PKCS1_OAEP, key16,
                          sizeof(key16), out, &n));
    RUN("CipherInit", Se05x_API_CipherInit(&g_session, 0x00000102U, (SE05x_CryptoObjectID_t)0x0010, iv16, sizeof(iv16),
                          kSE05x_Cipher_Oper_Encrypt));
    RUN("CipherUpdate",
        Se05x_API_CipherUpdate(&g_session, (SE05x_CryptoObjectID_t)0x0010, key16, sizeof(key16), out, &n));
    RUN("CipherFinal", Se05x_API_CipherFinal(&g_session, (SE05x_CryptoObjectID_t)0x0010, key16, sizeof(key16), out, &n));
    RUN("CipherOneShot", Se05x_API_CipherOneShot(&g_session, 0x00000102U, kSE05x_CipherMode_AES_CBC_NOPAD, key16,
                             sizeof(key16), iv16, sizeof(iv16), out, &n, kSE05x_Cipher_Oper_OneShot_Encrypt));
    RUN("MacInit",
        Se05x_API_MACInit(&g_session, 0x00000102U, (SE05x_CryptoObjectID_t)0x0011, kSE05x_Mac_Oper_Generate));
    RUN("MacUpdate", Se05x_API_MACUpdate(&g_session, key16, sizeof(key16), (SE05x_CryptoObjectID_t)0x0011));
    RUN("MacOneShot", Se05x_API_MACOneShot_G(&g_session, 0x00000102U, kSE05x_MACAlgo_HMAC_SHA256, key16, sizeof(key16),
                          out, &n));
    RUN("Hkdf", Se05x_API_HKDF_Extended(&g_session, 0x00000102U, kSE05x_DigestMode_SHA256, kSE05x_HkdfMode_ExtractExpand,
                    key16, sizeof(key16), 0, rnd16, sizeof(rnd16), 0, 32U, out, &n));
    RUN("Pbkdf2", Se05x_API_PBKDF2(&g_session, 0x00000102U, key16, sizeof(key16), 1000U, 32U, out, &n));
    RUN("DigestInit", Se05x_API_DigestInit(&g_session, (SE05x_CryptoObjectID_t)0x0012));
    RUN("DigestUpdate", Se05x_API_DigestUpdate(&g_session, (SE05x_CryptoObjectID_t)0x0012, key16, sizeof(key16)));
    RUN("DigestOneShot", Se05x_API_DigestOneShot(&g_session, kSE05x_DigestMode_SHA256, key16, sizeof(key16), out, &n));
    RUN("TlsGenerateRandom", Se05x_API_TLSGenerateRandom(&g_session, out, &n));
    RUN("TlsPrf", Se05x_API_TLSPerformPRF(&g_session, 0x00000102U, kSE05x_DigestMode_SHA256, label, sizeof(label) - 1U,
                      digest32, sizeof(digest32), 48U, out, &n, kSE05x_TLS_PRF_CLI_HELLO));
    RUN("DfDiversify", Se05x_API_DFDiversifyKey(&g_session, 0x00000100U, 0x00000200U, user_id, 3U));
    RUN("DfKill", Se05x_API_DFKillAuthentication(&g_session));
    RUN("DfDump", Se05x_API_DFDumpSessionKeys(&g_session, out, &n));
    return 0;
}
