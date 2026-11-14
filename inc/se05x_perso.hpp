/**
 * @file se05x_perso.hpp
 * @brief The PERSO applet of the SE051: read-only by default, writes and module deletion behind
 * irreversible tokens.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Written from AN13015 Rev 1.4 Appendix B (pp. 45-51): the PERSO applet (AID
 * A0000003965453000000010340000000) configures the chip's own bus behaviour: the I2C address (tag
 * 0x800D), clock stretching, power saving and the T=1 flavour (0x800E), the ATR and CIP interface
 * bytes (0x800F, 0x8015), history bytes and the deletion of optional OS modules (0x8017). It needs
 * no authentication, so while it is selectable anyone on the bus can change those settings
 * (AN13015 p. 19): `Probe()` reports that as a security finding, and `Device::Open()` copies it
 * into `Capabilities::perso_selectable`.
 *
 * The library is **read-only** on this applet. `Write()` and `DeleteModule()` exist only when
 * `kIrreversibleEnabled` and take their own confirmation token (S-10), and even then they return
 * `Unsupported` and send nothing: a wrong protocol or address leaves the chip unreachable from
 * this host build (the flavour is chip-side and not recoverable from the host), a deleted module
 * is gone for good, and no write path has been checked on a chip. `iot_base` is not in `Module`:
 * it is never offered (AN13015 Table 2 lists it as deletable after `iot_extended`). Settings take
 * effect after the next chip reset (AN13030 p. 261).
 *
 * Selecting PERSO deselects the IoT applet: every applet session and transient object is gone,
 * and the device selects the IoT applet again afterwards.
 *
 * Read: `80 02 P1 P2 01 len 00` with the tag in P1 P2 and the expected length; the answer is
 * TLV[TAG_1] (AN13015 Tables 10 to 12). SW 6700 means the expected length is shorter than the
 * value; SW 6A81 means the chip does not have the item.
 */
#ifndef SE05X_PERSO_HPP
#define SE05X_PERSO_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "se05x_caps.hpp"
#include "se05x_confirm.hpp"
#include "se05x_ports.hpp"
#include "se05x_scp03.hpp"
#include "se05x_status.hpp"
#include "se05x_types.hpp"

namespace se05x::perso {

/**
 * @defgroup se05x_perso PERSO applet
 * @brief Tags, modules and the `Perso` class.
 * @{
 */

/** @brief The PERSO tags (two bytes, 0x80xx; CLA 0x80, INS_WRITE 0x01, INS_READ 0x02). */
enum class Tag : uint16_t {
  AtsHistLen = 0x8005U,       ///< TCL_ATS_CURRENT_HISTLEN_CHARS: used length of the ATS history.
  AtsHistChars = 0x8006U,     ///< TCL_ATS_HISTCHARS: ATS historical characters (at most 20).
  AtrColdHistLen = 0x8009U,   ///< 7816_ATR_COLD_HIST_LEN_CHARS: cold-reset history length.
  AtrColdHistChars = 0x800AU, ///< 7816_ATR_COLD_HIST: cold-reset history (at most 15).
  AtrWarmHistLen = 0x800BU,   ///< 7816_ATR_WARM_HIST_LEN_CHARS: warm-reset history length.
  AtrWarmHistChars = 0x800CU, ///< 7816_ATR_WARM_HIST: warm-reset history (at most 15).
  I2cSlaveAddress =
      0x800DU,             ///< One byte: the 7-bit I2C address; changing it is irreversible-class.
  I2cParams = 0x800EU,     ///< One byte, `I2cParams`.
  AtrI2cIfBytes = 0x800FU, ///< ATR interface bytes (UM11225 flavour).
  FipsModeEnabled = 0x8014U, ///< FIPS mode flag; read only.
  CipI2cIfBytes = 0x8015U,   ///< CIP interface bytes (GP flavour).
  AtrCipHistChars = 0x8016U, ///< ATR and CIP history characters, at most 24.
  DeleteOsModule = 0x8017U,  ///< Delete an OS module: permanent.
};

/**
 * @param tag The raw tag value.
 * @return true when it is one of `Tag`.
 */
constexpr bool IsKnownTag(uint16_t tag) noexcept {
  return ((tag >= 0x8005U) && (tag <= 0x800FU) && (tag != 0x8007U) && (tag != 0x8008U)) ||
         (tag == 0x8014U) || (tag == 0x8015U) || (tag == 0x8016U) || (tag == 0x8017U);
}

/**
 * @brief Whether a tag can be written at all.
 * @param tag The tag.
 * @return false for `FipsModeEnabled`, true otherwise.
 */
constexpr bool IsWritable(Tag tag) noexcept {
  return tag != Tag::FipsModeEnabled;
}

/**
 * @brief The modules that can be deleted on SE051 variants A and C. `iot_base` is deliberately
 * absent: it must never be removed.
 */
enum class Module : uint8_t {
  IotExtended = 0, ///< Edwards and Montgomery curves (AID D276000085304A434F504D4F440B).
  RsaKeyGen = 1,   ///< On-chip RSA key generation (AID D276000085304A434F504D4F4400).
};

} // namespace se05x::perso

namespace se05x::detail {
/// Last enumerator of `perso::Module`.
template <>
struct EnumLast<perso::Module> {
  static constexpr perso::Module kValue = perso::Module::RsaKeyGen; ///< The last enumerator.
};
} // namespace se05x::detail

namespace se05x::perso {

/// The PERSO applet's instance AID (AN13015 Table 5).
inline constexpr std::array<uint8_t, 16> kPersoAid{0xA0U, 0x00U, 0x00U, 0x03U, 0x96U, 0x54U,
                                                   0x53U, 0x00U, 0x00U, 0x00U, 0x01U, 0x03U,
                                                   0x40U, 0x00U, 0x00U, 0x00U};
/// INS_READ (AN13015 Table 6).
inline constexpr uint8_t kInsRead = 0x02U;
/// INS_WRITE (AN13015 Table 6).
inline constexpr uint8_t kInsWrite = 0x01U;

/** @brief What the PERSO applet's SELECT returns. */
struct Version {
  uint8_t major{0};          ///< Major version.
  uint8_t minor{0};          ///< Minor version.
  uint8_t patch{0};          ///< Patch version.
  uint32_t config_option{0}; ///< The four-byte configuration option.
};

/**
 * @brief The PERSO applet over a lower transport.
 *
 * @tparam P A `Ports<...>` set.
 * @tparam T The lower transport (the link; PERSO runs in the clear).
 */
template <PortSet P, ApduTransport T>
class Perso {
public:
  /**
   * @brief Bind the object. No I/O.
   * @param ports The port set; it must outlive the object.
   * @param lower The lower transport; it must outlive the object.
   */
  Perso(const P& ports, T& lower) noexcept : ports_(&ports), lower_(&lower) {}

  /**
   * @brief SELECT the PERSO applet (the IoT applet is deselected).
   * @return Its version, `ObjectNotFound` (SW 6A82: the applet was deleted), `FrameError` (not 7
   * bytes), `ThroughputLimited`, `ChipSwUnknown` or a transport error.
   */
  Result<Version> Select() noexcept;

  /**
   * @brief Whether the PERSO applet can be selected: a security finding, not an error.
   * @return true when selectable (and then selected); false when it is gone (SW 6A82); otherwise
   * the error of `Select()`.
   */
  Result<bool> Probe() noexcept;

  /**
   * @brief Read one tag.
   * @param tag The tag.
   * @param out The buffer for the value (the expected length sent is its size, at most 255).
   * @return The length; `InvalidArgument` (unknown tag, empty buffer); `WrongState` (not selected
   * on this object; nothing sent); `BufferTooSmall` (SW 6700, or a value longer than `out`);
   * `Unsupported` (SW 6A81); `FrameError`; `ThroughputLimited`; `ChipSwUnknown`; a transport
   * error.
   */
  Result<std::size_t> Read(Tag tag, MutableByteSpan out) noexcept;

  /**
   * @brief Read the I2C parameters byte (tag 0x800E).
   * @return The typed byte, `FrameError` for an empty value, or the error of `Read()`
   * (`BufferTooSmall` for a value longer than one byte).
   */
  Result<I2cParams> ReadI2cParams() noexcept;

  /**
   * @brief Read the I2C target address (tag 0x800D).
   * @return The 7-bit address, `FrameError` for an empty value or one above 0x7F, or the error
   * of `Read()` (`BufferTooSmall` for a value longer than one byte).
   */
  Result<uint8_t> ReadI2cAddress() noexcept;

  /** @return true after a successful `Select()` on this object. No I/O. */
  [[nodiscard]] bool Selected() const noexcept {
    return selected_;
  }

  /**
   * @brief Write one tag; exists only with `kIrreversibleEnabled`.
   * @param tag The tag; `FipsModeEnabled` is refused with `InvalidArgument`.
   * @param value The value.
   * @param confirmation The confirmation built from `WritePersoSetting::kPhrase`.
   * @return `InvalidArgument` (read-only tag), `IrreversibleNotConfirmed`, else `Unsupported`:
   * the library does not write PERSO settings (nothing is sent).
   */
  Result<void> Write(
      Tag tag, ByteSpan value,
      irreversible::Confirmation<irreversible::WritePersoSetting> confirmation) noexcept
    requires(kIrreversibleEnabled);

  /**
   * @brief Delete an optional module for good; exists only with `kIrreversibleEnabled`.
   * @param module The module (never `iot_base`).
   * @param confirmation The confirmation built from `DeletePersoModule::kPhrase`.
   * @return `InvalidArgument` (not an enumerator), `IrreversibleNotConfirmed`, else `Unsupported`:
   * the library never deletes a module (nothing is sent).
   */
  Result<void> DeleteModule(
      Module module,
      irreversible::Confirmation<irreversible::DeletePersoModule> confirmation) noexcept
    requires(kIrreversibleEnabled);

private:
  const P* ports_;
  T* lower_;
  bool selected_{false};
};

/** @} */

} // namespace se05x::perso

// codeql::misra_deviation_next_line(MD-CPP-009)
#include "../src/se05x_perso.ipp" // IWYU pragma: export

#endif // SE05X_PERSO_HPP
