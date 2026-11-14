/**
 * @file se05x_caps.hpp
 * @brief What a chip can do: the `Capabilities` record `Device::Open()` fills from the chip.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Frozen contract. The driver never trusts a part name: `Capabilities` is derived from the applet
 * version and AppletConfig of the select response, the extended feature bits (applet 7.x), the OEF
 * id of the card identification data and, with `Config::probe_capabilities`, two probes
 * (ambiguities A4, A5). The derivation and the command gate are in `se05x_gate.hpp`; this file is
 * only the data.
 */
#ifndef SE05X_CAPS_HPP
#define SE05X_CAPS_HPP

#include <array>
#include <cstdint>

#include "se05x_commands.hpp"
#include "se05x_types.hpp"

namespace se05x {

/**
 * @defgroup se05x_caps Capabilities
 * @brief The feature flags and the `Capabilities` record.
 * @{
 */

/** @brief The feature flags that gate commands and parameters (design section 1.2). */
struct Features {
  bool eddsa{false};              ///< Ed25519 sign and verify.
  bool mont25519{false};          ///< Curve25519 key agreement.
  bool mont448{false};            ///< Curve448 key agreement (SE050E, SE051).
  bool ecdaa{false};              ///< ECDAA (applet 3.x).
  bool rsa{false};                ///< Any RSA.
  bool rsa_plain{false};          ///< RSA with the private exponent form (not CRT only).
  bool rsa4096_keygen{false};     ///< On-chip RSA-4096 key generation.
  bool aes_aead{false};           ///< AES-GCM, AES-CCM and GMAC (applet 7.x).
  bool des{false};                ///< DES and 3DES.
  bool mifare{false};             ///< MIFARE DESFire commands.
  bool i2cm{false};               ///< I2C controller commands.
  bool pake{false};               ///< PAKE (held, A6).
  bool t4t{false};                ///< NFC type 4 tag (held, A6).
  bool digest_commands{false};    ///< Digest commands as such (A5).
  bool eckey_session_ecka{false}; ///< `EcKeySessionGetEckaPublicKey` exists (applet 3.x).
  bool selftest{false};           ///< `TriggerSelfTest` and `ReadState`.
  bool ec_point_multiply{false};  ///< `EcPointMultiply`.
  bool versioned_writes{false};   ///< Versioned object updates.
  bool attestation_v2{false};     ///< Attestation format 2 (applet 7.x).
  bool fips{false}; ///< The chip is a FIPS configuration: its own claim, never the library's.
  bool applet_update{false}; ///< SEMS Lite update path present.
  bool enable_pin{false}; ///< ENA pin (SE050, SE051); false for SE052: deep power-down by S-block.
  bool dpd_by_sblock{false}; ///< Deep power-down by T=1 S-block 0xDF (SE052).
  bool throughput_limit{
      false}; ///< The chip may answer SW 0x66A6 after the APDU budget (SE052F; possible on SE051).
  bool free_memory_4byte{
      false}; ///< `GetFreeMemory` replies with 4 bytes (SE052F only); 2 bytes elsewhere.
  bool perso_applet{false}; ///< The PERSO applet exists (SE051): `perso::` is meaningful.
};

/**
 * @brief The I2C_PARAMS byte of the PERSO applet (tag 0x800E): chip-side bus and protocol settings.
 *
 * Read-only in the public surface; a write is irreversible-class (S-10) because a wrong protocol
 * leaves the chip unreachable from this host build. Settings take effect after the next chip reset.
 */
struct I2cParams {
  uint8_t raw{0}; ///< The byte as the chip reports it.

  /** @return Bit 0: the chip stretches SCL (3.4 MHz) instead of NAKing (1.0 MHz). */
  [[nodiscard]] constexpr bool ClockStretching() const noexcept {
    return (raw & 0x01U) != 0U;
  }
  /** @return Bit 1: power saving after the end-of-APDU-session response. */
  [[nodiscard]] constexpr bool PowerSaving() const noexcept {
    return (raw & 0x02U) != 0U;
  }
  /** @return Bit 4: the protocol is fixed by bit 2 (manual) instead of detected by the chip. */
  [[nodiscard]] constexpr bool ManualProtocol() const noexcept {
    return (raw & 0x10U) != 0U;
  }
  /** @return Bit 2, meaningful when `ManualProtocol()`: true GP flavour, false UM11225 flavour. */
  [[nodiscard]] constexpr bool GpFlavour() const noexcept {
    return (raw & 0x04U) != 0U;
  }
  /** @return Bit 3: blocking mode (semantics unclear without UM11225; reported only). */
  [[nodiscard]] constexpr bool BlockingMode() const noexcept {
    return (raw & 0x08U) != 0U;
  }
  /** @return Bits 7 to 5: the interface detection delay at start-up in units of 100 microseconds.
   */
  [[nodiscard]] constexpr uint32_t DetectionDelayUs() const noexcept {
    return static_cast<uint32_t>(raw >> 5U) * 100U;
  }
};

/**
 * @brief The capabilities of one chip, filled by `Device::Open()` and read-only afterwards.
 */
struct Capabilities {
  AppletVersion applet{};                            ///< Applet version from the select response.
  AppletGeneration generation{AppletGeneration::V3}; ///< Its generation, a first-class capability.
  uint16_t applet_config{0}; ///< AppletConfig bits (7 bytes select response, bytes 3 and 4).
  uint16_t secure_box{0};    ///< SecureBox bits (bytes 5 and 6).
  std::array<uint8_t, kExtFeatureLength> ext{}; ///< Extended feature bits (applet 7.x), else zero.
  Family family{Family::Unknown};               ///< The family, derived; `Unknown` is allowed.
  uint16_t oef_id{0};  ///< OEF id from card identification data; 0 when not read.
  Features features{}; ///< Feature flags.
  TransportFlavour flavour{TransportFlavour::Auto}; ///< The frame flavour in use.
  bool stretching{false};                           ///< The chip stretches SCL instead of NAKing.
  uint16_t ifsc{kDefaultIfs};                       ///< Information field size of the chip.
  uint16_t bwt_ms{kDefaultBwtMs};                   ///< Block waiting time in milliseconds.
  uint8_t max_sessions{2};                          ///< Parallel applet sessions.
  bool platform_scp_required{false};                ///< The chip demands platform SCP03.
  bool platform_scp_active{false};                  ///< A platform SCP03 channel is open.
  bool applet_locked{false};                        ///< The transport lock is set.
  bool perso_selectable{false}; ///< Probe finding: the unauthenticated PERSO applet can be selected
                                ///< (security warning).
  I2cParams i2c_params{};       ///< The PERSO I2C_PARAMS byte when read, else zero.
  CommandSet allowed;           ///< Commands the gate lets through, from the gate table.
};

/** @} */

} // namespace se05x

#endif // SE05X_CAPS_HPP
