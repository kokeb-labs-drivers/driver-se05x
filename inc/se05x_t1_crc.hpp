/**
 * @file se05x_t1_crc.hpp
 * @brief CRC16 of the T=1 frames.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Frozen surface: `Crc16()`. CRC-16/X-25: initial value 0xFFFF,
 * reflected polynomial 0x8408, final XOR 0xFFFF, computed over NAD, PCB, LEN and INF (UM11225
 * section 2.1.3 p. 9; GPC_SPE_172 section 4.2.5 p. 36, which keeps the two-byte CRC of ISO/IEC
 * 7816-3). The function returns the CRC as a number; the byte order on the wire is the link's
 * business:
 *
 * - GP flavour: most significant byte first (GPC_SPE_172 section 4.2 p. 33, example CRC 0xBDA4,
 *   vector V7).
 * - NXP flavour: UM11225 says only "CRC-1, CRC-2" (Figures 4 and 7, pp. 13 and 16). The link
 * accepts either order on the first valid frame of `Open()` and then keeps that order (ambiguity
 * A10); the order it tries first is least significant byte first, the order of the NXP Plug and
 * Trust middleware, which the tests use as an oracle only (never a dependency).
 */
#ifndef SE05X_T1_CRC_HPP
#define SE05X_T1_CRC_HPP

#include <cstddef>
#include <cstdint>

#include "se05x_status.hpp"
#include "se05x_types.hpp"

namespace se05x::t1 {

namespace detail {
/// Initial value of CRC-16/X-25.
inline constexpr uint16_t kCrcInit = 0xFFFFU;
/// Reflected generator polynomial of CRC-16/X-25 (x^16 + x^12 + x^5 + 1).
inline constexpr uint16_t kCrcPolyReflected = 0x8408U;
/// Final XOR of CRC-16/X-25.
inline constexpr uint16_t kCrcXorOut = 0xFFFFU;

/**
 * @brief CRC-16/X-25 of a byte string, as a plain number (no `Result`): the link's inner loop.
 * @param bytes The bytes.
 * @return The CRC; 0x0000 for an empty string.
 */
[[nodiscard]] constexpr uint16_t Crc16Raw(ByteSpan bytes) noexcept {
  uint32_t crc = kCrcInit;
  for (const uint8_t byte : bytes) {
    crc ^= static_cast<uint32_t>(byte);
    for (uint32_t bit = 0U; bit < 8U; ++bit) {
      const bool low = (crc & 1U) != 0U;
      crc >>= 1U;
      if (low) {
        crc ^= static_cast<uint32_t>(kCrcPolyReflected);
      }
    }
  }
  return static_cast<uint16_t>((crc ^ static_cast<uint32_t>(kCrcXorOut)) & 0xFFFFU);
}
} // namespace detail

/**
 * @brief The CRC16 of a byte string.
 *
 * A pure function: it never fails. `Result` is kept so that the signature matches the other
 * layers; `error` is always `Ok`.
 *
 * @param bytes The bytes: NAD through the last INF byte.
 * @return The CRC (CRC-16/X-25); 0x0000 for an empty string.
 */
constexpr Result<uint16_t> Crc16(ByteSpan bytes) noexcept {
  return Result<uint16_t>::Success(detail::Crc16Raw(bytes));
}

} // namespace se05x::t1

#endif // SE05X_T1_CRC_HPP
