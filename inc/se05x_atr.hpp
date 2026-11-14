/**
 * @file se05x_atr.hpp
 * @brief The link parameters from the ATR (UM11225 flavour) and the CIP (GP flavour).
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Frozen surface: `LinkParams`, `ParseAtr()`, `ParseCip()`. The ATR
 * and CIP replace the defaults of `kDefaultIfs` and `kDefaultBwtMs` at `Link::Open()`. Both parsers
 * are strict: every length field must fit, the structure must end exactly at the last byte, and a
 * value the link cannot use is refused with `FrameError`. They are fuzz targets (`fuzz_atr_cip`).
 *
 * ATR (UM11225 section 2.2, Tables 11 to 13, pp. 9-10): PVER (1), VID (5), DLLP length (1), DLLP
 * (BWT 2 bytes in ms, IFSC 2 bytes, extra bytes ignored), PLID (1, always 2 for I2C), PLP length
 * (1), PLP (MCF 2 bytes in kHz, configuration 1 with bit 4 = high-speed mode, MPOT 1 in ms, RFU 1,
 * RFU 2, SEGT 2 in us, WUT 2 in us; extra bytes ignored), HB length (1), HB. Multi-byte values are
 * big endian, as in the SE052 ATR of the SE052 data sheet (Table 12, p. 16). The ATR log of AN13904
 * pp. 4-5 (vector V8) has the same bytes; it comes from a chip reporting OEF A8FA, an SE051C2
 * (AN12973 Table 4, p. 4), not an SE052F.
 *
 * CIP (GPC_SPE_172 section 4.3, Tables 4-6, 4-7 and 4-9, pp. 36-38): PVER (1), IIN length (1), IIN
 * (3 or 4 bytes, BCD), PLID (1, 2 = I2C), PLP length (1), PLP (configuration 1 RFU, PWT 1 in ms,
 * MCF 2 in kHz, PST 1 in ms, MPOT 1 in units of 100 us, RWGT 2 in us; extra bytes ignored), DLLP
 * length (1), DLLP (BWT 2 in ms, IFSC 2; extra bytes ignored), HB length (1, at most 32), HB; at
 * most 64 bytes in all.
 */
#ifndef SE05X_ATR_HPP
#define SE05X_ATR_HPP

#include <cstddef>
#include <cstdint>

#include "se05x_status.hpp"
#include "se05x_types.hpp"

namespace se05x::t1 {

/** @brief What the ATR or CIP says about the link. */
struct LinkParams {
  TransportFlavour flavour{TransportFlavour::Um11225}; ///< The flavour the answer belongs to.
  uint16_t ifsc{kDefaultIfs};     ///< Information field size of the chip (IFSC).
  uint16_t ifsd{kDefaultIfs};     ///< Information field size of the host (IFSD).
  uint16_t bwt_ms{kDefaultBwtMs}; ///< Block waiting time in milliseconds.
  uint16_t max_scl_khz{1000};     ///< Highest SCL clock in kHz.
  uint16_t min_poll_us{1000};     ///< Minimum polling time in microseconds.
  uint16_t guard_us{100};         ///< Read/write guard time in microseconds (SEGT or RWGT).
  uint16_t wakeup_us{5000};       ///< Wake-up time in microseconds (WUT, or the GP PWT).
  bool stretching{false};         ///< The chip stretches SCL; neither answer reports it.
  bool high_speed{false};         ///< High-speed mode supported (ATR configuration bit 4).
};

namespace detail {

/// Largest IFSC of the NXP flavour: one LEN byte, at most 0xFE (UM11225 section 2.1.1, p. 5).
inline constexpr uint16_t kUmMaxIfs = 0xFEU;
/// Largest IFSC of the GP flavour (GPC_SPE_172 section 4.2.3, p. 35).
inline constexpr uint16_t kGpMaxIfs = 0x0FF9U;
/// IFSD the GP chip assumes until the host says otherwise (GPC_SPE_172 section 4.1, p. 32).
inline constexpr uint16_t kGpIfsd = 64U;
/// Largest CIP (GPC_SPE_172 section 4.3.1, p. 36).
inline constexpr std::size_t kMaxCipBytes = 64U;
/// Largest historical-byte field of a CIP (GPC_SPE_172 Table 4-6, p. 36).
inline constexpr std::size_t kMaxCipHistory = 32U;
/// Length of the vendor id of an ATR (UM11225 Table 11, p. 9).
inline constexpr std::size_t kAtrVidBytes = 5U;
/// Physical layer id of I2C, in both answers.
inline constexpr uint8_t kPlidI2c = 2U;
/// Smallest DLLP: BWT and IFSC (UM11225 Table 12, GPC_SPE_172 Table 4-7).
inline constexpr std::size_t kDllpBytes = 4U;
/// Largest BWT accepted from an ATR or CIP, in ms: ten times the 1 s the SE052 ATR gives (SE052
/// data sheet Table 12, p. 16); a larger value would stretch every wait the link derives from it
/// (A33).
inline constexpr uint16_t kMaxBwtMs = 10000U;
/// Smallest ATR PLP: MCF to WUT (UM11225 Table 13, p. 10).
inline constexpr std::size_t kAtrPlpBytes = 11U;
/// Smallest CIP I2C PLP: configuration to RWGT (GPC_SPE_172 Table 4-9, p. 38).
inline constexpr std::size_t kCipPlpBytes = 8U;
/// ATR configuration byte, bit 4: high-speed mode supported (UM11225 Table 13).
inline constexpr uint32_t kAtrHighSpeedBit = 0x08U;
/// Largest time in milliseconds that still fits `LinkParams` in microseconds.
inline constexpr uint32_t kMaxMsInUs16 = 65U;

/**
 * @brief A failed result of the T=1 layer.
 * @tparam T The value type.
 * @param error Why it failed.
 * @param step The rung or step number, for `Detail::step`.
 * @return `Result<T>::Failure` with the layer set to `Layer::T1`.
 */
template <typename T>
[[nodiscard]] constexpr Result<T> Fail(Error error, uint8_t step = 0U) noexcept {
  return Result<T>::Failure(error, Detail{.sw = static_cast<uint16_t>(0U),
                                          .command = static_cast<uint8_t>(0xFFU),
                                          .layer = Layer::T1,
                                          .step = step,
                                          .attempts_left = static_cast<uint8_t>(0xFFU)});
}

/** @brief A bounds-checked cursor over the bytes of an answer: no read goes past the end. */
class Cursor {
public:
  /** @param bytes The answer. */
  constexpr explicit Cursor(ByteSpan bytes) noexcept : bytes_(bytes) {}

  /** @return Whether `n` more bytes are there. */
  [[nodiscard]] constexpr bool Has(std::size_t n) const noexcept {
    return n <= (bytes_.size() - pos_);
  }
  /** @return The next byte; 0 past the end (callers check `Has()` first). */
  [[nodiscard]] constexpr uint8_t U8() noexcept {
    if (!Has(1U)) {
      ok_ = false;
      return 0U;
    }
    const uint8_t v = bytes_[pos_];
    ++pos_;
    return v;
  }
  /** @return The next two bytes, big endian; 0 past the end. */
  [[nodiscard]] constexpr uint16_t U16() noexcept {
    const auto hi = static_cast<uint32_t>(U8());
    const auto lo = static_cast<uint32_t>(U8());
    return static_cast<uint16_t>(((hi << 8U) | lo) & 0xFFFFU);
  }
  /** @brief Skip `n` bytes; past the end marks the cursor failed. */
  constexpr void Skip(std::size_t n) noexcept {
    if (Has(n)) {
      pos_ += n;
    } else {
      ok_ = false;
      pos_ = bytes_.size();
    }
  }
  /** @return Whether no read went past the end and nothing is left over. */
  [[nodiscard]] constexpr bool Complete() const noexcept {
    return ok_ && (pos_ == bytes_.size());
  }
  /** @return Whether no read went past the end. */
  [[nodiscard]] constexpr bool Ok() const noexcept {
    return ok_;
  }

private:
  ByteSpan bytes_;
  std::size_t pos_{0U};
  bool ok_{true};
};

/// A time in milliseconds as microseconds, when it fits `uint16_t`; `ok` false otherwise.
struct UsFromMs {
  uint16_t us{0U}; ///< The time in microseconds.
  bool ok{false};  ///< Whether it fits.
};

/** @return `ms` in microseconds, or not ok above 65 ms. */
[[nodiscard]] constexpr UsFromMs MsToUs16(uint32_t ms) noexcept {
  if (ms > kMaxMsInUs16) {
    return UsFromMs{};
  }
  return UsFromMs{.us = static_cast<uint16_t>(ms * 1000U), .ok = true};
}

/** @return The DLLP (BWT, IFSC) read into `p`, or false when it does not fit or is unusable. */
[[nodiscard]] constexpr bool ReadDllp(Cursor& c, uint16_t max_ifsc, LinkParams& p) noexcept {
  const std::size_t len = c.U8();
  if ((len < kDllpBytes) || !c.Has(len)) {
    return false;
  }
  p.bwt_ms = c.U16();
  p.ifsc = c.U16();
  c.Skip(len - kDllpBytes);
  return (p.bwt_ms != 0U) && (p.bwt_ms <= kMaxBwtMs) && (p.ifsc != 0U) && (p.ifsc <= max_ifsc);
}

/** @return The ATR PLP read into `p`, or false when it does not fit or is unusable. */
[[nodiscard]] constexpr bool ReadAtrPlp(Cursor& c, LinkParams& p) noexcept {
  const std::size_t len = c.U8();
  if ((len < kAtrPlpBytes) || !c.Has(len)) {
    return false;
  }
  p.max_scl_khz = c.U16();
  const auto config = static_cast<uint32_t>(c.U8());
  const UsFromMs mpot = MsToUs16(c.U8());
  c.Skip(3U); // RFU (1) and RFU (2).
  p.guard_us = c.U16();
  p.wakeup_us = c.U16();
  c.Skip(len - kAtrPlpBytes);
  p.high_speed = (config & kAtrHighSpeedBit) != 0U;
  p.stretching = false; // not in the ATR (UM11225 Table 13): set on the chip (AN13015 p. 49)
  p.min_poll_us = mpot.us;
  return mpot.ok;
}

/** @return The CIP I2C PLP read into `p`, or false when it does not fit or is unusable. */
[[nodiscard]] constexpr bool ReadCipPlp(Cursor& c, LinkParams& p) noexcept {
  const std::size_t len = c.U8();
  if ((len < kCipPlpBytes) || !c.Has(len)) {
    return false;
  }
  c.Skip(1U); // Configuration: RFU.
  const UsFromMs pwt = MsToUs16(c.U8());
  p.max_scl_khz = c.U16();
  c.Skip(1U); // PST: power saving is requested explicitly by the link.
  p.min_poll_us = static_cast<uint16_t>(static_cast<uint32_t>(c.U8()) * 100U);
  p.guard_us = c.U16();
  c.Skip(len - kCipPlpBytes);
  p.wakeup_us = pwt.us;
  return pwt.ok;
}

/** @return Whether a length-prefixed field of at most `max` bytes is there; skips it. */
[[nodiscard]] constexpr bool SkipField(Cursor& c, std::size_t max) noexcept {
  const std::size_t len = c.U8();
  if ((len > max) || !c.Has(len)) {
    return false;
  }
  c.Skip(len);
  return true;
}

} // namespace detail

/**
 * @brief Parse an ATR (UM11225 flavour).
 * @param atr The ATR bytes as received (the INF of the soft-reset or get-ATR response).
 * @return The parameters, with `ifsd` equal to `ifsc` (UM11225 section 2.1.2.1, p. 8), or
 * `FrameError`: a length that does not fit, bytes left over, PVER 0, a PLID other than 2, a BWT or
 * IFSC of 0, an IFSC above 0xFE, or an MPOT above 65 ms.
 */
constexpr Result<LinkParams> ParseAtr(ByteSpan atr) noexcept {
  detail::Cursor c(atr);
  LinkParams p{};
  p.flavour = TransportFlavour::Um11225;
  const uint8_t pver = c.U8();
  c.Skip(detail::kAtrVidBytes);
  bool ok = (pver != 0U) && detail::ReadDllp(c, detail::kUmMaxIfs, p);
  ok = ok && (c.U8() == detail::kPlidI2c);
  ok = ok && detail::ReadAtrPlp(c, p);
  ok = ok && detail::SkipField(c, atr.size());
  if (!ok || !c.Complete()) {
    return detail::Fail<LinkParams>(Error::FrameError);
  }
  p.ifsd = p.ifsc;
  return Result<LinkParams>::Success(p);
}

/**
 * @brief Parse a CIP (GP flavour).
 * @param cip The CIP bytes as received (the INF of the CIP response).
 * @return The parameters, with `ifsd` 64, the GP default the chip keeps until the host changes it
 * (GPC_SPE_172 section 4.1, p. 32), or `FrameError`: more than 64 bytes, a length that does not
 * fit, bytes left over, PVER 0, an IIN length other than 3 or 4, a PLID other than 2, a BWT or IFSC
 * of 0, an IFSC above 0x0FF9, historical bytes longer than 32, or a PWT above 65 ms.
 */
constexpr Result<LinkParams> ParseCip(ByteSpan cip) noexcept {
  detail::Cursor c(cip);
  LinkParams p{};
  p.flavour = TransportFlavour::Gp;
  const uint8_t pver = c.U8();
  const std::size_t iin = c.U8();
  c.Skip(iin);
  bool ok = (cip.size() <= detail::kMaxCipBytes) && (pver != 0U) && (iin >= 3U) && (iin <= 4U);
  ok = ok && (c.U8() == detail::kPlidI2c);
  ok = ok && detail::ReadCipPlp(c, p);
  ok = ok && detail::ReadDllp(c, detail::kGpMaxIfs, p);
  ok = ok && detail::SkipField(c, detail::kMaxCipHistory);
  if (!ok || !c.Complete()) {
    return detail::Fail<LinkParams>(Error::FrameError);
  }
  p.ifsd = detail::kGpIfsd;
  return Result<LinkParams>::Success(p);
}

} // namespace se05x::t1

#endif // SE05X_ATR_HPP
