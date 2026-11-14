/**
 * @file se05x_wire.hpp
 * @brief Numbers read from the specifications: the two T=1 frame flavours, the S-block codes, the
 * link defaults, the buffer sizes and the byte-order helper of the Edwards and Montgomery values
 * (frozen constants).
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Frozen: private helpers go in `src/se05x_t1.ipp`, not here.
 * Sources: UM11225 Rev 1.2 (NXP flavour, pages 5-19), GPC_SPE_172 v1.0 (GP flavour, pp. 21-39),
 * AN12543 Rev 4.5 (buffers, byte order), AN13904 p. 27 (WTX timeout). The CRC byte order of the NXP
 * flavour is not stated in UM11225; it stays the model knob `crc_swapped` (ambiguity A10). No
 * default key of any platform is in this repository.
 */
#ifndef SE05X_WIRE_HPP
#define SE05X_WIRE_HPP

#include <cstddef>
#include <cstdint>

#include "se05x_types.hpp"

namespace se05x::wire {

/** @brief The frame layout of one T=1 flavour. */
struct FrameFormat {
  uint8_t nad_host_to_se; ///< NAD of a block from the host to the chip.
  uint8_t nad_se_to_host; ///< NAD of a block from the chip to the host.
  uint8_t len_bytes;      ///< Width of the LEN field (1 or 2; two bytes are big endian).
  uint16_t max_len;       ///< Largest LEN the flavour allows.
};

/// The NXP flavour (UM11225 Tables 2 to 4): NAD 0x5A and 0xA5, one LEN byte, at most 0xFE bytes of
/// INF.
inline constexpr FrameFormat kUm11225Frame{
    .nad_host_to_se = 0x5AU, .nad_se_to_host = 0xA5U, .len_bytes = 1U, .max_len = 0xFEU};
/// The GP flavour (GPC_SPE_172 Table 4-1): NAD 0x21 and 0x12, two LEN bytes big endian, at most
/// 0x0FF9.
inline constexpr FrameFormat kGpFrame{
    .nad_host_to_se = 0x21U, .nad_se_to_host = 0x12U, .len_bytes = 2U, .max_len = 0x0FF9U};

/// CRC length in bytes, both flavours; the polynomial is the ISO 7816-3 one (CRC-16/X-25).
inline constexpr std::size_t kCrcBytes = 2U;
/// The GP example block of GPC_SPE_172 p. 33 (vector V7): NAD 21 PCB 40 LEN 000E, INF of 14 bytes,
/// CRC BDA4 (MSB first).
inline constexpr uint16_t kGpExampleCrc = 0xBDA4U;

/**
 * @name S-block request codes (PCB with bits 8 and 7 set; the response has bit 6 (0x20) set in
 * addition) Common to both flavours: UM11225 Table 9 and GPC_SPE_172 Table 4-4.
 * @{
 */
inline constexpr uint8_t kSResync = 0xC0U; ///< Resynchronise: both sequence numbers to zero.
inline constexpr uint8_t kSIfs = 0xC1U;    ///< Change the information field size.
inline constexpr uint8_t kSAbort = 0xC2U;  ///< Abort a chain.
inline constexpr uint8_t kSWtx = 0xC3U; ///< Waiting time extension; INF is the multiplier of BWT.
inline constexpr uint8_t kSInterfaceSoftReset =
    0xCFU; ///< Interface soft reset; the response carries the ATR (NXP) or CIP (GP).
inline constexpr uint8_t kSResponseBit =
    0x20U; ///< Added to a request code to get the response code.
/** @} */

/**
 * @name S-block codes that differ between the flavours
 * The same number means different things: 0xC6 is the chip reset of the NXP flavour and RELEASE of
 * the GP flavour. The link selects the code by the flavour in use.
 * @{
 */
inline constexpr uint8_t kUmEndOfApduSession =
    0xC5U; ///< NXP: end of APDU session, the chip may power down; the next block wakes it.
inline constexpr uint8_t kUmChipReset = 0xC6U; ///< NXP: the chip resets itself after the response.
inline constexpr uint8_t kUmGetAtr = 0xC7U;    ///< NXP: return the ATR without a reset.
inline constexpr uint8_t kGpCip = 0xC4U;       ///< GP: card identification (CIP) request.
inline constexpr uint8_t kGpRelease =
    0xC6U; ///< GP: release, the power-saving request (value derived from the bit table).
/** @} */

/**
 * @name Link defaults and limits
 * @{
 */
inline constexpr uint8_t kUmMaxRetransmissions =
    10U; ///< UM11225 2.4.1: ten further attempts, then an interface soft reset.
inline constexpr uint32_t kUmDefaultSegtUs =
    10U; ///< UM11225 Table 14: default guard time between two I2C accesses.
inline constexpr uint32_t kSe052DeepPowerDownUs =
    300U; ///< SE052 data sheet Table 15, p. 22 (tDPD): no access this long after a deep power-down.
inline constexpr uint32_t kUmDefaultMpotMs =
    1U; ///< UM11225 Table 14: default minimum polling time.
inline constexpr uint32_t kUmDefaultPowerWakeMs =
    5U;                                        ///< UM11225 Table 14 (DPWT): wait after power-on.
inline constexpr uint16_t kGpDefaultIfsc = 8U; ///< GPC_SPE_172: IFSC before the CIP says otherwise.
inline constexpr uint16_t kGpDefaultIfsd = 64U;   ///< GPC_SPE_172: IFSD.
inline constexpr uint32_t kGpDefaultBwtMs = 300U; ///< GPC_SPE_172: block waiting time.
inline constexpr uint32_t kGpDefaultPowerWakeMs =
    25U; ///< GPC_SPE_172 p. 31: wait after power-on (ambiguity A8).
inline constexpr uint32_t kIdleByte =
    0xFFU; ///< Read when the chip has nothing to send (both flavours).
inline constexpr uint32_t kMinWtxHostTimeoutMs =
    4000U; ///< AN13904 p. 27: the host waits at least 4 s for a WTX, in both modes.
/** @} */

/**
 * @name Buffer sizes (AN12543 pp. 3 and 125, 168-170)
 * @{
 */
inline constexpr std::size_t kApduBuffer = 270U;      ///< The applet's APDU buffer.
inline constexpr std::size_t kInternalBuffer = 1024U; ///< The applet's internal buffer.
inline constexpr std::size_t kAeadOneShotMax = 888U;  ///< Largest AEAD one-shot payload.
/// EdDSA sign and verify: the longest plain input in the default session, an AESKey or an ECKey
/// session (AN12543 4.10.1.2 p. 103 and 4.10.2.2 p. 104; platform SCP does not change it).
inline constexpr std::size_t kEddsaInputMax = 940U;
/// EdDSA sign and verify: the longest plain input inside a UserID session (same pages).
inline constexpr std::size_t kEddsaInputMaxUserId = 919U;
inline constexpr std::size_t kEddsaSignMax = kEddsaInputMax;   ///< EdDSA sign, not in UserID.
inline constexpr std::size_t kEddsaVerifyMax = kEddsaInputMax; ///< EdDSA verify, not in UserID.
/**
 * @brief The EdDSA input limit of a session.
 * @param user_id_session true inside a UserID session.
 * @return 919 inside a UserID session, 940 otherwise.
 */
[[nodiscard]] constexpr std::size_t EddsaInputMax(bool user_id_session) noexcept {
  return user_id_session ? kEddsaInputMaxUserId : kEddsaInputMax;
}
/** @} */

/**
 * @brief Reverse a byte string in place: the wire form of an Edwards or Montgomery value is the
 * byte reverse of the RFC 8032 and RFC 7748 form (public key, r, s, X25519 private and peer keys;
 * the EdDSA secret key is not reversed).
 * @param bytes The bytes to reverse.
 */
constexpr void ReverseBytes(MutableByteSpan bytes) noexcept {
  std::size_t lo = 0U;
  std::size_t hi = bytes.size();
  while ((hi > 0U) && (lo < (hi - 1U))) {
    const uint8_t tmp = bytes[lo];
    bytes[lo] = bytes[hi - 1U];
    bytes[hi - 1U] = tmp;
    ++lo;
    --hi;
  }
}

} // namespace se05x::wire

#endif // SE05X_WIRE_HPP
