/**
 * @file se05x_gp.hpp
 * @brief The GlobalPlatform card manager: card data, key information and the platform key set.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * The card manager (the issuer security domain, AID A000000151000000) is a
 * separate applet from the IoT applet: `SelectCardManager()` replaces the selected applet, so the
 * device layer selects the IoT applet again afterwards and drops its sessions. The GET DATA calls
 * need `SelectCardManager()` first on this object (`WrongState` otherwise, nothing sent).
 *
 * Sources: GlobalPlatform Card Specification GET DATA (tags 9F7F CPLC, 00E0 key information
 * template with entries C0: key id, version, type, length); the card identification data is the
 * proprietary tag 00FE with sub-tag DF28 as the NXP GetInfo log prints it (AN12436 p. 2, AN13904
 * p. 4; the command bytes `80 CA 00 FE 02 DF 28` are not in the obtained documents: derived).
 *
 * Replacing the platform keys (`PutKeys`) is irreversible (S-10): it exists only when
 * `kIrreversibleEnabled` is true and takes a `Confirmation<ReplacePlatformKeys>`. Even then it
 * returns `Unsupported` and sends nothing: PUT KEY carries each new key encrypted under the DEK,
 * and the crypto port has no hook that encrypts one key handle under another, so the new keys
 * would have to pass through the library in the clear (S-16). A port hook for it is a contract
 * amendment.
 */
#ifndef SE05X_GP_HPP
#define SE05X_GP_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "se05x_confirm.hpp"
#include "se05x_device_types.hpp"
#include "se05x_ports.hpp"
#include "se05x_scp03.hpp"
#include "se05x_status.hpp"
#include "se05x_types.hpp"

namespace se05x::gp {

/**
 * @defgroup se05x_gp Card manager
 * @brief GET DATA, key information and PUT KEY of the platform.
 * @{
 */

/** @brief One entry of the key information template. */
struct KeyInfoEntry {
  uint8_t key_id{0};     ///< The key identifier.
  uint8_t version{0};    ///< The key version number.
  uint8_t key_type{0};   ///< The key type byte (0x88 for AES).
  uint8_t key_length{0}; ///< The key length in bytes.
};

/** @brief The key information of the card manager. */
struct KeyInformation {
  std::array<KeyInfoEntry, 8> entries{}; ///< The entries, in chip order.
  std::size_t count{0};                  ///< How many entries are valid.
};

/** @brief The platform key set to write: handles of the new keys (S-16). */
struct NewKeySet {
  scp03::StaticKeys keys{}; ///< The new ENC, MAC and DEK handles.
  uint8_t new_version{0};   ///< The version number of the new set.
};

/**
 * @brief The card manager over a lower transport.
 *
 * @tparam P A `Ports<...>` set.
 * @tparam T The lower transport, usually `t1::Link<P>` or an open SCP03 `Channel`.
 */
template <PortSet P, ApduTransport T>
class CardManager {
public:
  /**
   * @brief Bind the card manager. No I/O.
   * @param ports The port set; it must outlive the object.
   * @param lower The lower transport; it must outlive the object.
   */
  CardManager(const P& ports, T& lower) noexcept : ports_(&ports), lower_(&lower) {}

  /**
   * @brief SELECT the card manager (the applet is replaced).
   * @return `Ok`, `ThroughputLimited`, `ChipSwUnknown` (another status word, in the details) or a
   * transport error.
   */
  Result<void> SelectCardManager() noexcept;

  /**
   * @brief GET DATA 9F7F: the CPLC record (42 bytes).
   * @return The record, `WrongState` (not selected; nothing sent), `FrameError` (malformed),
   * `ChipSwUnknown`, `ThroughputLimited` or a transport error.
   */
  Result<Cplc> GetCplc() noexcept;

  /**
   * @brief GET DATA 00FE / DF28: the card identification data and its OEF id.
   * @return The data, `WrongState`, `FrameError`, `BufferTooSmall` (more than 128 bytes),
   * `ChipSwUnknown`, `ThroughputLimited` or a transport error.
   */
  Result<CardId> GetCardIdentification() noexcept;

  /**
   * @brief GET DATA 00E0: the key information template.
   * @return The entries, `WrongState`, `FrameError`, `BufferTooSmall` (more than 8 entries),
   * `ChipSwUnknown`, `ThroughputLimited` or a transport error.
   */
  Result<KeyInformation> GetKeyInformation() noexcept;

  /** @return true after a successful `SelectCardManager()` on this object. No I/O. */
  [[nodiscard]] bool Selected() const noexcept {
    return selected_;
  }
  /** @brief Forget the selection, after the caller selected another applet. No I/O. */
  void Deselect() noexcept {
    selected_ = false;
  }

  /**
   * @brief Replace the platform key set (irreversible, S-10).
   *
   * Refused with `IrreversibleNotConfirmed` unless the confirmation is valid; with a valid one it
   * still returns `Unsupported` and sends nothing (see the file comment: the port cannot wrap one
   * key handle under another).
   *
   * @param current The key set in use now.
   * @param next The new key set.
   * @param confirmation The confirmation, built from `ReplacePlatformKeys::kPhrase`.
   * @return `IrreversibleNotConfirmed` or `Unsupported`.
   */
  Result<void> PutKeys(
      const scp03::ChannelParams& current, const NewKeySet& next,
      irreversible::Confirmation<irreversible::ReplacePlatformKeys> confirmation) noexcept
    requires(kIrreversibleEnabled);

private:
  Result<std::size_t> getData(ByteSpan command, MutableByteSpan answer) noexcept;

  const P* ports_;
  T* lower_;
  bool selected_{false};
};

/** @} */

} // namespace se05x::gp

// codeql::misra_deviation_next_line(MD-CPP-009)
#include "../src/se05x_gp.ipp" // IWYU pragma: export

#endif // SE05X_GP_HPP
