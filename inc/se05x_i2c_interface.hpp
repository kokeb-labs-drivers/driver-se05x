/**
 * @file se05x_i2c_interface.hpp
 * @brief What the SE05X needs from the I2C bus, as constants.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * The bus port itself is `BusInterface` in `se05x_ports.hpp`: a port moves bytes and never frames,
 * retries or configures the chip. This leaf header holds only the requirements, so that a port and
 * a board configuration can check their settings with `static_assert`: the target address, the
 * clock ceiling and whether the chip needs a repeated start (it does not: T=1 frames are separate
 * write and read transactions, and an address-only frame is never sent, errata I2C.2).
 *
 * The clock ceiling depends on a chip-side setting: the SE050 data sheet targets 1 MHz (Fm+) and
 * 3.4 MHz with clock stretching (section 4.1.1, p. 9), and the PERSO applet note ties the two to
 * clock stretching off and on. 400 kHz is the rate of the chip's I2C controller (section 4, p. 8)
 * and the default maximum clock of the GP framing (GPC_SPE_172 Table 3-2, p. 31). The conservative
 * `kMaxClockHz` is that 400 kHz: the figure that holds for every part and setting.
 */
#ifndef SE05X_I2C_INTERFACE_HPP
#define SE05X_I2C_INTERFACE_HPP

#include <cstdint>

namespace se05x {

/**
 * @name Bus requirements
 * @{
 */
/// 7-bit I2C target address of every SE05X in its default configuration (data sheet I2C chapter).
inline constexpr uint8_t kI2cAddress = 0x48;
/// Highest SCL frequency that holds for every part and chip setting, in Hz (400 kHz fast mode).
inline constexpr uint32_t kMaxClockHz = 400000U;
/// Highest SCL frequency with the chip's clock stretching off (SE051 PERSO setting), in Hz.
inline constexpr uint32_t kMaxClockNoStretchHz = 1000000U;
/// Highest SCL frequency with the chip's clock stretching on (SE051 PERSO setting), in Hz.
inline constexpr uint32_t kMaxClockStretchHz = 3400000U;
/// The chip does not need a repeated START: a write and a read are separate transactions.
inline constexpr bool kRepeatedStart = false;
/** @} */

} // namespace se05x

#endif // SE05X_I2C_INTERFACE_HPP
