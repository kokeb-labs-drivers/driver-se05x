/**
 * @file se05x_t1.ipp
 * @brief T=1 link implementation, included by `se05x_t1.hpp`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * detail::Block coding (UM11225 Tables 5 to 9, pp. 6-8; GPC_SPE_172 Table 4-4, p. 34): an I-block
 * has bit 8 clear, N(S) in bit 7 and M in bit 6; an R-block has bits 8-7 = 10, N(R) in bit 5 and
 * the error code in bits 2-1; an S-block has bits 8-7 = 11 and the response sets bit 6. The host is
 * the initiator of ISO/IEC 7816-3 section 11.6 as both documents require.
 */
#ifndef SE05X_T1_IPP
#define SE05X_T1_IPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

namespace se05x::t1 {

namespace detail {
/// I-block marker: bit 8 clear.
inline constexpr uint32_t kBit8 = 0x80U;
/// Bits 8 and 7, the block type.
inline constexpr uint32_t kTypeMask = 0xC0U;
/// R-block type bits.
inline constexpr uint32_t kRType = 0x80U;
/// I-block N(S) bit (bit 7).
inline constexpr uint32_t kINsShift = 6U;
/// I-block M bit (bit 6).
inline constexpr uint32_t kIMore = 0x20U;
/// I-block reserved bits 5 to 1.
inline constexpr uint32_t kIReserved = 0x1FU;
/// R-block N(R) bit (bit 5).
inline constexpr uint32_t kRNrShift = 4U;
/// R-block reserved bits 6, 4 and 3.
inline constexpr uint32_t kRReserved = 0x2CU;
/// R-block error code bits 2 and 1.
inline constexpr uint32_t kRError = 0x03U;
/// R-block error code: CRC error.
inline constexpr uint32_t kRCrcError = 0x01U;
/// R-block error code: other error.
inline constexpr uint32_t kROtherError = 0x02U;

/** @return `bit` toggled (0 or 1). */
[[nodiscard]] constexpr uint8_t Toggle(uint8_t bit) noexcept {
  return static_cast<uint8_t>((static_cast<uint32_t>(bit) ^ 1U) & 1U);
}
/** @return The smaller of two times. */
[[nodiscard]] constexpr uint64_t Earlier(uint64_t a, uint64_t b) noexcept {
  return (a < b) ? a : b;
}
} // namespace detail

// --- Time and bus ----------------------------------------------------------------------------

template <PortSet P>
uint64_t Link<P>::nowUs() const noexcept {
  return ports_->GetClock().NowUs();
}

template <PortSet P>
void Link<P>::waitUs(uint32_t us) const noexcept {
  ports_->GetClock().DelayUs(us);
}

template <PortSet P>
uint32_t Link<P>::pollUs() const noexcept {
  // POT is never below MPOT (UM11225 section 3.1.1.2, p. 14; GPC_SPE_172 section 3.2.6.1).
  return std::max(config_.poll_interval_us, static_cast<uint32_t>(params_.min_poll_us));
}

template <PortSet P>
uint32_t Link<P>::pollBudget(uint64_t deadline) const noexcept {
  // The iteration cap of every poll loop: the deadline in poll periods, plus two. A clock that does
  // not advance still ends the loop (S-05).
  const uint64_t now = nowUs();
  const uint64_t span = (deadline > now) ? (deadline - now) : 0U;
  const uint64_t polls = (span / static_cast<uint64_t>(pollUs())) + 2U;
  return static_cast<uint32_t>(std::min<uint64_t>(polls, 0xFFFF'FFFFU));
}

template <PortSet P>
void Link<P>::markAccess() noexcept {
  last_read_us_ = nowUs();
  read_done_ = true;
}

template <PortSet P>
void Link<P>::guardAfterRead() noexcept {
  // The guard time holds between any two accesses, not only before a read: SEGT (UM11225 Table 15,
  // p. 20) and RWGT (GPC_SPE_172 3.2.7, p. 28) also before a write, and before the body read that
  // follows the prologue read.
  // After a deep power-down by S-block the SE052 needs tDPD before the next access (SE052 data
  // sheet Table 15, p. 22).
  const uint64_t guard = std::max(static_cast<uint32_t>(params_.guard_us), wire::kUmDefaultSegtUs);
  const uint64_t now = nowUs();
  uint64_t until = quiet_until_us_;
  if (read_done_) {
    until = std::max(until, last_read_us_ + guard);
  }
  if (until > now) {
    waitUs(static_cast<uint32_t>(std::min<uint64_t>(until - now, 0xFFFF'FFFFU)));
  }
}

template <PortSet P>
Error Link<P>::busRead(std::size_t offset, std::size_t count, uint64_t deadline,
                       bool first) noexcept {
  const MutableByteSpan dst = MutableByteSpan{rx_}.subspan(offset, count);
  const uint32_t polls = pollBudget(deadline);
  for (uint32_t i = 0U; i < polls; ++i) {
    guardAfterRead();
    const BusRead r = ports_->GetBus().Read(config_.i2c_address, dst);
    markAccess();
    if (r.status == BusStatus::Ok) {
      if (r.count != count) {
        return Error::FrameError;
      }
      // A first byte 0xFF is the idle byte: the chip has nothing to send yet (UM11225 p. 15).
      if (!first || (static_cast<uint32_t>(dst[0]) != wire::kIdleByte)) {
        return Error::Ok;
      }
    } else if (r.status == BusStatus::BusStuck) {
      return Error::BusStuck;
    } else if (r.status != BusStatus::Nack) {
      return Error::Bus;
    } else {
      // NACK: the chip is processing; poll again after POT.
    }
    if (nowUs() >= deadline) {
      return Error::Timeout;
    }
    waitUs(pollUs());
  }
  return Error::Timeout;
}

template <PortSet P>
Error Link<P>::busWrite(std::size_t length) noexcept {
  const ByteSpan frame = ByteSpan{tx_}.first(length);
  const uint32_t polls = pollBudget(deadline_);
  Error outcome = Error::Nack;
  for (uint32_t i = 0U; i < polls; ++i) {
    // Errata I2C.1: an unread answer is read out before the next write. A NACK means the chip has
    // nothing to send now; any other failure leaves it unknown, so nothing is written this round.
    const bool probed = pending_;
    const BusStatus drained = probed ? drain() : BusStatus::Nack;
    BusStatus status = drained;
    if ((drained == BusStatus::Ok) || (drained == BusStatus::Nack)) {
      // The guard time before the write, except right after a NACKed drain probe: the chip is busy
      // with an earlier command, and a wait there would let its answer arrive just before the
      // write (errata I2C.1). A busy chip NACKs the write, and the loop probes again.
      if (!probed || (drained == BusStatus::Ok)) {
        guardAfterRead();
      }
      status = ports_->GetBus().Write(config_.i2c_address, frame);
      markAccess();
    }
    if (status == BusStatus::Ok) {
      pending_ = true;
      ++counters_.frames_sent;
      return Error::Ok;
    }
    if (status == BusStatus::BusStuck) {
      return Error::BusStuck;
    }
    const bool unread = (drained == BusStatus::BusError) || (drained == BusStatus::Timeout);
    if ((status != BusStatus::Nack) && !unread) {
      return Error::Bus;
    }
    outcome = unread ? Error::Bus : Error::Nack;
    if (nowUs() >= deadline_) {
      break;
    }
    waitUs(pollUs());
  }
  return outcome;
}

template <PortSet P>
BusStatus Link<P>::drain() noexcept {
  // Reading past the end of the chip's data returns idle bytes (UM11225 p. 15; GPC_SPE_172
  // section 3.2.7), so reads covering the largest frame either flavour allows (a GP LEN of
  // 0x0FF9) empty whatever is left, even from a chip in the other flavour. Only error paths drain;
  // a NACK ends it early (the chip has left the send state).
  BusStatus first = BusStatus::Nack;
  for (uint32_t i = 0U; i < detail::kGpDrainReads; ++i) {
    guardAfterRead();
    const BusRead r = ports_->GetBus().Read(config_.i2c_address, MutableByteSpan{rx_});
    markAccess();
    if (i == 0U) {
      first = r.status;
    }
    if (r.status != BusStatus::Ok) {
      break;
    }
  }
  if (first == BusStatus::Ok) {
    pending_ = false;
  }
  return first;
}

// --- Frames ----------------------------------------------------------------------------------

template <PortSet P>
std::size_t Link<P>::prologue() const noexcept {
  return (flavour_ == TransportFlavour::Gp) ? 4U : 3U;
}

template <PortSet P>
uint8_t Link<P>::seNad(TransportFlavour flavour) const noexcept {
  return (flavour == TransportFlavour::Gp) ? wire::kGpFrame.nad_se_to_host
                                           : wire::kUm11225Frame.nad_se_to_host;
}

template <PortSet P>
std::size_t Link<P>::buildFrame(uint8_t pcb, ByteSpan inf) noexcept {
  const bool gp = flavour_ == TransportFlavour::Gp;
  const wire::FrameFormat& fmt = gp ? wire::kGpFrame : wire::kUm11225Frame;
  const auto len = static_cast<uint32_t>(inf.size());
  tx_[0] = fmt.nad_host_to_se;
  tx_[1] = pcb;
  std::size_t pos = 2U;
  if (fmt.len_bytes == 2U) {
    tx_[pos] = static_cast<uint8_t>((len >> 8U) & 0xFFU); // GP: LEN big endian (p. 33)
    pos += 1U;
  }
  tx_[pos] = static_cast<uint8_t>(len & 0xFFU);
  pos += 1U;
  static_cast<void>(
      std::copy(inf.begin(), inf.end(), tx_.begin() + static_cast<std::ptrdiff_t>(pos)));
  pos += inf.size();
  const auto crc = static_cast<uint32_t>(detail::Crc16Raw(ByteSpan{tx_}.first(pos)));
  const bool msb_first = gp || !crc_lsb_first_;
  const auto hi = static_cast<uint8_t>((crc >> 8U) & 0xFFU);
  const auto lo = static_cast<uint8_t>(crc & 0xFFU);
  tx_[pos] = msb_first ? hi : lo;
  tx_[pos + 1U] = msb_first ? lo : hi;
  pos += wire::kCrcBytes;
  return pos;
}

template <PortSet P>
Error Link<P>::sendBlock(uint8_t pcb, ByteSpan inf) noexcept {
  return busWrite(buildFrame(pcb, inf));
}

template <PortSet P>
Error Link<P>::sendProtocol(uint8_t pcb, ByteSpan inf) noexcept {
  last_pcb_ = pcb;
  last_inf_ = inf;
  return sendBlock(pcb, inf);
}

template <PortSet P>
Error Link<P>::resendProtocol() noexcept {
  return sendBlock(last_pcb_, last_inf_);
}

template <PortSet P>
Error Link<P>::sendNak(Error why) noexcept {
  const uint32_t code = (why == Error::Crc) ? detail::kRCrcError : detail::kROtherError;
  const uint32_t pcb = detail::kRType | (static_cast<uint32_t>(nr_) << detail::kRNrShift) | code;
  ++counters_.naks_sent;
  return sendBlock(static_cast<uint8_t>(pcb), ByteSpan{});
}

template <PortSet P>
std::size_t Link<P>::rxLimit() const noexcept {
  return std::min(static_cast<std::size_t>(params_.ifsd), detail::kMaxInf);
}

template <PortSet P>
Error Link<P>::checkNad() noexcept {
  const uint8_t nad = rx_[0];
  // GPC_SPE_172 4.2.1 p. 33 only recommends the NAD values 0x21/0x12; the vendor middleware's GP
  // flavour answers with 0xA5 (docs/ambiguities.md A17). In the GP flavour both are accepted: the
  // two-byte LEN and the CRC then decide whether the block is valid.
  const bool gp_alias =
      (flavour_ == TransportFlavour::Gp) && (nad == seNad(TransportFlavour::Um11225));
  if ((nad == seNad(flavour_)) || gp_alias) {
    return Error::Ok;
  }
  const TransportFlavour other =
      (flavour_ == TransportFlavour::Gp) ? TransportFlavour::Um11225 : TransportFlavour::Gp;
  if (detect_ && (nad == seNad(other))) {
    if (adopt_) {
      setFlavour(other); // Open: a stale frame of the other flavour decides it
      return Error::Ok;
    }
    seen_other_ = true;
  }
  static_cast<void>(drain());
  return Error::FrameError;
}

template <PortSet P>
Error Link<P>::readBody(std::size_t len, uint64_t deadline) noexcept {
  return busRead(prologue(), len + wire::kCrcBytes, deadline, false);
}

template <PortSet P>
bool Link<P>::crcValid(std::size_t length) noexcept {
  const auto crc = static_cast<uint32_t>(detail::Crc16Raw(ByteSpan{rx_}.first(length)));
  const auto first = static_cast<uint32_t>(rx_[length]);
  const auto second = static_cast<uint32_t>(rx_[length + 1U]);
  const uint32_t msb = (first << 8U) | second;
  const uint32_t lsb = (second << 8U) | first;
  if (flavour_ == TransportFlavour::Gp) {
    return crc == msb; // GPC_SPE_172 section 4.2, p. 33
  }
  if (crc_fixed_) {
    return crc == (crc_lsb_first_ ? lsb : msb);
  }
  // NXP flavour before the first valid frame: UM11225 does not state the order (A10).
  if ((crc == lsb) || (crc == msb)) {
    crc_lsb_first_ = crc == lsb;
    crc_fixed_ = true;
    return true;
  }
  return false;
}

template <PortSet P>
Error Link<P>::recvBlock(detail::Block& out, uint64_t deadline, uint32_t settle_us) noexcept {
  // The host waits SEGT (UM11225 Figure 11, p. 18) or RWGT (GPC_SPE_172 section 3.2.5) after a
  // write, and longer after a soft or chip reset.
  const uint32_t guard = std::max(static_cast<uint32_t>(params_.guard_us), wire::kUmDefaultSegtUs);
  waitUs(std::max(guard, settle_us));
  Error e = busRead(0U, 3U, deadline, true);
  if (e == Error::Ok) {
    e = checkNad();
  }
  std::size_t len = rx_[2];
  if ((e == Error::Ok) && (flavour_ == TransportFlavour::Gp)) {
    e = busRead(3U, 1U, deadline, false);
    len = (len << 8U) | static_cast<std::size_t>(rx_[3]);
  }
  if (e != Error::Ok) {
    return e;
  }
  if (len > rxLimit()) { // GPC_SPE_172 section 4.2.3; the overlong-LEN class of the middleware
    static_cast<void>(drain());
    return Error::FrameError;
  }
  e = readBody(len, deadline);
  if (e != Error::Ok) {
    return e;
  }
  ++counters_.frames_received;
  if (!crcValid(prologue() + len)) {
    // A corrupted LEN makes the frame boundary unknown: bytes may be left unread, so the next write
    // reads out first (errata I2C.1).
    ++counters_.crc_errors;
    return Error::Crc;
  }
  pending_ = false;
  out.pcb = rx_[1];
  out.len = len;
  return Error::Ok;
}

// --- Blocks ----------------------------------------------------------------------------------

template <PortSet P>
uint64_t Link<P>::blockDeadline() const noexcept {
  return detail::Earlier(deadline_, nowUs() + (static_cast<uint64_t>(params_.bwt_ms) * 1000U));
}

template <PortSet P>
uint32_t Link<P>::rungMs() const noexcept {
  return config_.atr_poll_budget_ms + static_cast<uint32_t>(params_.bwt_ms);
}

template <PortSet P>
uint32_t Link<P>::bootUs() const noexcept {
  // DPWT 5 ms (UM11225 Table 14, p. 19) or PWT 25 ms (GPC_SPE_172 Table 3-2, p. 31), the wake-up
  // time of the answer, and the configured boot wait (A8): the longest of them.
  const uint32_t flavour_us = (flavour_ == TransportFlavour::Gp)
                                  ? (wire::kGpDefaultPowerWakeMs * 1000U)
                                  : (wire::kUmDefaultPowerWakeMs * 1000U);
  const uint32_t boot_us = config_.boot_wait_ms * 1000U;
  return std::max({flavour_us, boot_us, static_cast<uint32_t>(params_.wakeup_us)});
}

template <PortSet P>
bool Link<P>::hard(Error e) const noexcept {
  // Errors no retry can mend within this operation.
  if ((e == Error::BusStuck) || seen_other_ || (wtx_count_ > config_.wtx_limit)) {
    return true;
  }
  return (e != Error::Ok) && (nowUs() >= deadline_);
}

template <PortSet P>
Error Link<P>::onWtx(const detail::Block& b, uint64_t& deadline) noexcept {
  ++counters_.wtx_received;
  const std::size_t h = prologue();
  if ((b.len != 1U) || (rx_[h] == 0U)) {
    return Error::FrameError;
  }
  ++wtx_count_;
  if (wtx_count_ > config_.wtx_limit) {
    return Error::Timeout; // S-05: the WTX budget of one command
  }
  sinf_[0] = rx_[h];
  const uint32_t extension_ms =
      std::min(std::max(static_cast<uint32_t>(sinf_[0]) * static_cast<uint32_t>(params_.bwt_ms),
                        wire::kMinWtxHostTimeoutMs),
               detail::kMaxWtxWaitMs);
  // The WTX of one operation together never grant more than kMaxWtxTotalMs (S-05, A33): the
  // request that would pass it is not answered.
  if (extension_ms > (detail::kMaxWtxTotalMs - wtx_wait_ms_)) {
    return Error::Timeout;
  }
  wtx_wait_ms_ += extension_ms;
  // The response carries the request's INF (UM11225 Table 9; GPC_SPE_172 Table 4-5).
  const Error e =
      sendBlock(static_cast<uint8_t>(wire::kSWtx | wire::kSResponseBit), ByteSpan{sinf_}.first(1U));
  if (e != Error::Ok) {
    return e;
  }
  // The host then waits at least 4 s (AN13904 8.3 p. 27; UM11225 2.1.1.2.3) whatever the command
  // class: a WTX extends the command's own deadline too. The number of WTX per command bounds the
  // total wait (`Config::wtx_limit`, S-05).
  const uint64_t until = nowUs() + (static_cast<uint64_t>(extension_ms) * 1000U);
  deadline_ = std::max(deadline_, until);
  deadline = until;
  return Error::Ok;
}

template <PortSet P>
Error Link<P>::onIfs(const detail::Block& b) noexcept {
  ++ifs_count_;
  const std::size_t h = prologue();
  const bool gp = flavour_ == TransportFlavour::Gp;
  if ((ifs_count_ > detail::kMaxIfsRequests) || (b.len == 0U) || (b.len > (gp ? 2U : 1U))) {
    return Error::FrameError;
  }
  const auto hi = static_cast<uint32_t>(rx_[h]);
  const auto lo = static_cast<uint32_t>(rx_[h + 1U]);
  const uint32_t value = (b.len == 2U) ? ((hi << 8U) | lo) : hi;
  const uint32_t max = gp ? t1::detail::kGpMaxIfs : t1::detail::kUmMaxIfs;
  if ((value == 0U) || (value > max)) {
    return Error::FrameError;
  }
  sinf_[0] = rx_[h];
  sinf_[1] = rx_[h + 1U];
  const Error e = sendBlock(static_cast<uint8_t>(wire::kSIfs | wire::kSResponseBit),
                            ByteSpan{sinf_}.first(b.len));
  if (e == Error::Ok) {
    params_.ifsc = static_cast<uint16_t>(value);
    if (!gp) {
      params_.ifsd = params_.ifsc; // IFSC and IFSD stay in step (UM11225 section 2.1.2.1)
    }
  }
  return e;
}

template <PortSet P>
Error Link<P>::awaitBlock(detail::Block& out, uint64_t& deadline, uint32_t settle_us) noexcept {
  const uint32_t limit = static_cast<uint32_t>(config_.wtx_limit) + detail::kMaxIfsRequests + 1U;
  uint32_t first_wait_us = settle_us;
  for (uint32_t i = 0U; i < limit; ++i) {
    Error e = recvBlock(out, deadline, first_wait_us);
    first_wait_us = 0U;
    if (e != Error::Ok) {
      return e;
    }
    if (out.pcb == wire::kSWtx) {
      e = onWtx(out, deadline); // answered for I-block and S-block commands alike (p. 11)
    } else if (out.pcb == wire::kSIfs) {
      e = onIfs(out);
    } else {
      return Error::Ok;
    }
    if (e != Error::Ok) {
      return e;
    }
  }
  return Error::Timeout;
}

template <PortSet P>
Error Link<P>::sExchange(uint8_t request, detail::Block& out, uint32_t settle_us) noexcept {
  const auto response = static_cast<uint8_t>(request | wire::kSResponseBit);
  Error e = sendProtocol(request, ByteSpan{});
  for (uint32_t attempt = 0U; attempt <= config_.frame_retries; ++attempt) {
    if (e == Error::Ok) {
      uint64_t deadline = blockDeadline();
      e = awaitBlock(out, deadline, settle_us);
      if ((e == Error::Ok) && (out.pcb == response)) {
        return Error::Ok;
      }
      if (e == Error::Ok) {
        e = Error::FrameError; // another block: send the request again
      }
    }
    if (hard(e) || (attempt == config_.frame_retries)) {
      break;
    }
    e = resendProtocol();
  }
  return e;
}

template <PortSet P>
detail::Verdict Link<P>::judgeR(detail::Want want, uint32_t pcb) const noexcept {
  if (((pcb & detail::kRReserved) != 0U) || ((pcb & detail::kRError) == detail::kRError)) {
    return detail::Verdict::Nak;
  }
  const bool asks_again = ((pcb >> detail::kRNrShift) & 1U) == static_cast<uint32_t>(ns_);
  if (want == detail::Want::Ack) {
    if (!asks_again && ((pcb & detail::kRError) == 0U)) {
      return detail::Verdict::Accept; // R(N(R)) with N(R) the next N(S): the chained block arrived
    }
    return asks_again ? detail::Verdict::Resend : detail::Verdict::Nak;
  }
  if (want == detail::Want::FirstI) {
    return asks_again ? detail::Verdict::Resend : detail::Verdict::Nak;
  }
  return detail::Verdict::Resend; // NextI: the chip did not get the acknowledgement
}

template <PortSet P>
detail::Verdict Link<P>::judgeI(detail::Want want, const detail::Block& b) const noexcept {
  const auto pcb = static_cast<uint32_t>(b.pcb);
  const bool more = (pcb & detail::kIMore) != 0U;
  if (((pcb & detail::kIReserved) != 0U) || (more && (b.len == 0U)) ||
      (want == detail::Want::Ack)) {
    return detail::Verdict::Nak;
  }
  if (((pcb >> detail::kINsShift) & 1U) == static_cast<uint32_t>(nr_)) {
    return detail::Verdict::Accept;
  }
  // The previous block again: the acknowledgement was lost, so send it once more.
  return (want == detail::Want::NextI) ? detail::Verdict::Resend : detail::Verdict::Nak;
}

template <PortSet P>
detail::Verdict Link<P>::judge(detail::Want want, const detail::Block& b) const noexcept {
  const auto pcb = static_cast<uint32_t>(b.pcb);
  if ((pcb & detail::kBit8) == 0U) {
    return judgeI(want, b);
  }
  if ((pcb & detail::kTypeMask) == detail::kRType) {
    return judgeR(want, pcb);
  }
  return detail::Verdict::Nak; // an S-block other than WTX or IFS
}

template <PortSet P>
Error Link<P>::awaitExpected(detail::Want want, detail::Block& out, Error sent) noexcept {
  Error e = sent;
  for (uint32_t attempt = 0U; attempt <= config_.frame_retries; ++attempt) {
    detail::Verdict verdict = detail::Verdict::Nak;
    if (e == Error::Ok) {
      uint64_t deadline = blockDeadline();
      e = awaitBlock(out, deadline, 0U);
      if (e == Error::Ok) {
        verdict = judge(want, out);
        if (verdict == detail::Verdict::Accept) {
          return Error::Ok;
        }
      }
    }
    if (hard(e)) {
      return e;
    }
    if (attempt == config_.frame_retries) {
      return (e == Error::Ok) ? Error::FrameError : e;
    }
    // UM11225 section 2.4.1: an R-block, or the previous block again.
    e = (verdict == detail::Verdict::Resend) ? resendProtocol() : sendNak(e);
  }
  return Error::FrameError;
}

template <PortSet P>
Error Link<P>::sendCommand(ByteSpan command, detail::Block& first) noexcept {
  const std::size_t chunk = std::min(static_cast<std::size_t>(params_.ifsc), detail::kMaxInf);
  std::size_t pos = 0U;
  for (std::size_t blocks = 0U; blocks < command.size(); ++blocks) {
    const std::size_t n = std::min(command.size() - pos, chunk);
    const bool more = (pos + n) < command.size();
    const uint32_t pcb =
        (static_cast<uint32_t>(ns_) << detail::kINsShift) | (more ? detail::kIMore : 0U);
    Error e = sendProtocol(static_cast<uint8_t>(pcb), command.subspan(pos, n));
    e = awaitExpected(more ? detail::Want::Ack : detail::Want::FirstI, first, e);
    if (e != Error::Ok) {
      return e;
    }
    ns_ = detail::Toggle(ns_);
    if (!more) {
      return Error::Ok;
    }
    pos += n;
  }
  return Error::FrameError;
}

template <PortSet P>
Error Link<P>::collect(const detail::Block& b, MutableByteSpan response,
                       detail::Collected& got) noexcept {
  if ((got.total + b.len) > kMaxResponse) {
    return Error::FrameError; // errata APP.1: no response is longer than 1024 bytes
  }
  if (!got.overflow && ((got.total + b.len) <= response.size())) {
    const auto src = ByteSpan{rx_}.subspan(prologue(), b.len);
    static_cast<void>(std::copy(src.begin(), src.end(),
                                response.begin() + static_cast<std::ptrdiff_t>(got.total)));
    got.copied = got.total + b.len;
  } else {
    got.overflow = true;
  }
  got.total += b.len;
  return Error::Ok;
}

template <PortSet P>
Error Link<P>::receiveResponse(detail::Block first, MutableByteSpan response,
                               detail::Collected& got) noexcept {
  detail::Block b = first;
  for (std::size_t blocks = 0U; blocks <= kMaxResponse; ++blocks) {
    Error e = collect(b, response, got);
    if (e != Error::Ok) {
      return e;
    }
    nr_ = detail::Toggle(nr_);
    if ((static_cast<uint32_t>(b.pcb) & detail::kIMore) == 0U) {
      return Error::Ok;
    }
    // A chained block is acknowledged by R(N(R)), N(R) the next expected N(S) (UM11225 p. 6).
    const uint32_t ack = detail::kRType | (static_cast<uint32_t>(nr_) << detail::kRNrShift);
    e = sendProtocol(static_cast<uint8_t>(ack), ByteSpan{});
    e = awaitExpected(detail::Want::NextI, b, e);
    if (e != Error::Ok) {
      return e;
    }
  }
  return Error::FrameError;
}

template <PortSet P>
Error Link<P>::exchange(ByteSpan command, MutableByteSpan response,
                        detail::Collected& got) noexcept {
  detail::Block first{};
  const Error e = sendCommand(command, first);
  if (e != Error::Ok) {
    return e;
  }
  return receiveResponse(first, response, got);
}

template <PortSet P>
Error Link<P>::afterFailure(Error e) noexcept {
  if (e == Error::BusStuck) {
    dead_ = dead_ || !P::kHasReset;
    return P::kHasReset ? climb(Rung::PowerCycle) : Error::BusStuck;
  }
  if (((e == Error::Timeout) || (e == Error::Nack)) && hard(e)) {
    needs_resync_ = true; // the chip may still answer: the next command resynchronises first
    return Error::Timeout;
  }
  return climb(Rung::Resync);
}

template <PortSet P>
Result<std::size_t> Link<P>::finish(Error e, MutableByteSpan response,
                                    const detail::Collected& got) noexcept {
  const Error short_answer = (got.total < 2U) ? Error::FrameError : Error::Ok;
  const Error complete = got.overflow ? Error::BufferTooSmall : short_answer;
  const Error result = (e == Error::Ok) ? complete : afterFailure(e);
  if (result == Error::Ok) {
    reselect_ = false;
    return Result<std::size_t>::Success(got.total);
  }
  Zeroize(response.first(got.copied)); // S-01: no part of a failed answer stays behind
  return detail::Fail<std::size_t>(result, se05x::detail::ToUnderlying(counters_.last_rung));
}

// --- Handshake and ladder --------------------------------------------------------------------

template <PortSet P>
void Link<P>::setFlavour(TransportFlavour flavour) noexcept {
  flavour_ = flavour;
  params_ = LinkParams{};
  params_.flavour = flavour;
  if (flavour == TransportFlavour::Gp) {
    // GPC_SPE_172 section 4.1 (IFSC 8, IFSD 64), Table 3-2 and section 4.3.2 (BWT 300 ms).
    params_.ifsc = wire::kGpDefaultIfsc;
    params_.ifsd = wire::kGpDefaultIfsd;
    params_.bwt_ms = static_cast<uint16_t>(wire::kGpDefaultBwtMs);
    params_.max_scl_khz = 400U;
    params_.wakeup_us = static_cast<uint16_t>(wire::kGpDefaultPowerWakeMs * 1000U);
  } else {
    params_.wakeup_us = static_cast<uint16_t>(wire::kUmDefaultPowerWakeMs * 1000U);
  }
  params_.guard_us = static_cast<uint16_t>(wire::kUmDefaultSegtUs); // DSEGT, DRWGT: 10 us
  crc_fixed_ = flavour == TransportFlavour::Gp;
  crc_lsb_first_ = true;
  ns_ = 0U;
  nr_ = 0U;
}

template <PortSet P>
void Link<P>::startDeadline(uint32_t ms) noexcept {
  deadline_ = nowUs() + (static_cast<uint64_t>(ms) * 1000U);
}

template <PortSet P>
void Link<P>::flushStale() noexcept {
  // Errata I2C.1 workaround: read once after the host starts; answer the chip's waiting time
  // extensions of a command an earlier host left (AN13904 section 8.3), then drop its answer.
  detect_ = true;
  adopt_ = config_.flavour == TransportFlavour::Auto;
  setFlavour(adopt_ ? TransportFlavour::Um11225 : config_.flavour);
  pending_ = true;             // unknown at host start: the first write reads out whatever is left
  uint64_t deadline = nowUs(); // one look: nothing waits when nothing is there
  detail::Block b{};
  for (uint32_t i = 0U; i <= static_cast<uint32_t>(kSessionOpenWtxAllowance); ++i) {
    const Error e = recvBlock(b, deadline, 0U);
    if (e != Error::Ok) {
      break;
    }
    hint_ = true;
    adopt_ = false;
    if ((b.pcb != wire::kSWtx) || (onWtx(b, deadline) != Error::Ok)) {
      break;
    }
  }
  adopt_ = false;
  wtx_count_ = 0U;
  wtx_wait_ms_ = 0U;
}

template <PortSet P>
Error Link<P>::doSoftReset() noexcept {
  // NXP: the response carries the ATR (UM11225 Table 9, p. 8); the host keeps SDA and SCL high
  // for DMPOT. GP: S(SWR) resets N(S) and chaining (GPC_SPE_172 section 4.2.2).
  if (flavour_ != TransportFlavour::Gp) {
    // The soft reset restores the chip's largest IFS (p. 9), so its ATR may be longer than the
    // IFS agreed so far.
    params_.ifsd = static_cast<uint16_t>(detail::kMaxInf);
  }
  detail::Block b{};
  const Error e = sExchange(wire::kSInterfaceSoftReset, b, wire::kUmDefaultMpotMs * 1000U);
  if (e != Error::Ok) {
    return e;
  }
  ns_ = 0U;
  nr_ = 0U;
  if (flavour_ == TransportFlavour::Gp) {
    return Error::Ok;
  }
  const Result<LinkParams> atr = ParseAtr(ByteSpan{rx_}.subspan(prologue(), b.len));
  if (!atr.ok()) {
    return atr.error;
  }
  params_ = atr.value;
  return Error::Ok;
}

template <PortSet P>
Error Link<P>::handshake() noexcept {
  Error e = doSoftReset();
  if ((e != Error::Ok) || (flavour_ != TransportFlavour::Gp)) {
    return e;
  }
  detail::Block b{};
  e = sExchange(wire::kGpCip, b, 0U);
  if (e != Error::Ok) {
    return e;
  }
  const Result<LinkParams> cip = ParseCip(ByteSpan{rx_}.subspan(prologue(), b.len));
  if (!cip.ok()) {
    return cip.error;
  }
  params_ = cip.value;
  return Error::Ok;
}

template <PortSet P>
Error Link<P>::negotiate() noexcept {
  detect_ = true;
  seen_other_ = false;
  if (hint_ || (config_.flavour != TransportFlavour::Auto)) {
    return handshake();
  }
  // Auto (A9, A17): the NXP flavour for half of the budget, then the GP flavour. The NXP flavour
  // goes first because an SE051 locks onto the protocol of the first frame it sees (SE051 data
  // sheet 4.1.2 p. 9) and the vendor middleware speaks the NXP flavour; a GP block that answers
  // the first attempt still decides the flavour (stale-frame rule).
  const uint64_t end = deadline_;
  const uint64_t now = nowUs();
  setFlavour(TransportFlavour::Um11225);
  deadline_ = now + ((end > now) ? ((end - now) / 2U) : 0U);
  Error e = handshake();
  if ((e != Error::Ok) && (flavour_ == TransportFlavour::Um11225)) {
    seen_other_ = false;
    deadline_ = end;
    setFlavour(TransportFlavour::Gp);
    e = handshake();
  }
  return e;
}

template <PortSet P>
Error Link<P>::doResync() noexcept {
  detail::Block b{};
  const Error e = sExchange(wire::kSResync, b, 0U);
  if (e == Error::Ok) {
    ns_ = 0U; // both sequence numbers to zero (UM11225 Table 9)
    nr_ = 0U;
    ++counters_.resyncs;
  }
  return e;
}

template <PortSet P>
Error Link<P>::doChipReset() noexcept {
  // NXP flavour only: S(SE chip reset), then the chip resets itself; the host keeps the lines high
  // for DPWT (UM11225 section 2.1.1.2.3, p. 8) and starts again with the soft reset (p. 10).
  detail::Block b{};
  const Error e = sExchange(wire::kUmChipReset, b, 0U);
  if (e != Error::Ok) {
    return e;
  }
  pending_ = false;
  waitUs(bootUs());
  startDeadline(rungMs());
  return handshake();
}

template <PortSet P>
Error Link<P>::doPortReset(ResetKind kind) noexcept {
  if constexpr (P::kHasReset) {
    auto& reset = ports_->GetReset();
    const bool done = (kind == ResetKind::PowerCycle) ? reset.PowerCycle() : reset.Reset();
    if (!done) {
      return Error::Bus;
    }
    pending_ = false;
    waitUs(bootUs());
    startDeadline(rungMs());
    return handshake();
  } else {
    static_cast<void>(kind);
    return Error::Unsupported;
  }
}

template <PortSet P>
Error Link<P>::tryRung(Rung rung, Rung from) noexcept {
  startDeadline(rungMs());
  switch (rung) {
  case Rung::Resync:
    return doResync();
  case Rung::InterfaceReset:
    return doSoftReset();
  case Rung::Reselect:
    return (from == Rung::Reselect) ? Error::Ok : Error::Unsupported;
  case Rung::ChipReset:
    // 0xC6 is RELEASE in the GP flavour (GPC_SPE_172 Table 4-4): there the reset port does it.
    return (flavour_ == TransportFlavour::Gp) ? doPortReset(ResetKind::Reset) : doChipReset();
  case Rung::PowerCycle:
    return doPortReset(ResetKind::PowerCycle);
  case Rung::ResendBlock: // nothing to resend outside a command
  default:
    break;
  }
  return Error::Unsupported;
}

template <PortSet P>
Error Link<P>::climb(Rung from) noexcept {
  const auto first =
      std::max(se05x::detail::ToUnderlying(from), se05x::detail::ToUnderlying(Rung::Resync));
  const auto last = se05x::detail::ToUnderlying(Rung::PowerCycle);
  bool stuck = false;
  for (uint32_t r = first; r <= last; ++r) {
    const auto rung = static_cast<Rung>(r);
    if (stuck && (rung != Rung::PowerCycle)) {
      continue; // a stuck bus: only the power cycle clears it (errata I2C.1)
    }
    const Error e = tryRung(rung, from);
    if (e != Error::Unsupported) {
      ++counters_.recoveries;
      counters_.last_rung = std::max(counters_.last_rung, rung);
    }
    if (e == Error::Ok) {
      dead_ = false;
      log(LogLevel::Warning, Error::Ok, "t1 recovered");
      if (rung == Rung::Resync) {
        return reselect_ ? Error::NeedsReselect : Error::Resynced;
      }
      reselect_ = true;
      return Error::NeedsReselect;
    }
    stuck = stuck || (e == Error::BusStuck);
  }
  dead_ = true;
  log(LogLevel::Error, Error::TransportDead, "t1 dead");
  return Error::TransportDead;
}

template <PortSet P>
Error Link<P>::doReset(ResetKind kind) noexcept {
  switch (kind) {
  case ResetKind::Interface:
    startDeadline(rungMs());
    return doSoftReset();
  case ResetKind::Cold:
    if (flavour_ == TransportFlavour::Gp) {
      return Error::Unsupported; // no published chip-reset S-block in GPC_SPE_172
    }
    startDeadline(rungMs());
    return doChipReset();
  case ResetKind::Reset:
  case ResetKind::PowerCycle:
    return doPortReset(kind);
  default:
    break;
  }
  return Error::InvalidArgument;
}

template <PortSet P>
void Link<P>::settle() noexcept {
  if (!open_) {
    state_ = LinkState::Closed;
  } else if (dead_) {
    state_ = LinkState::Dead;
  } else if (reselect_) {
    state_ = LinkState::NeedsReselect;
  } else {
    state_ = LinkState::Idle;
  }
}

template <PortSet P>
void Link<P>::wipe() noexcept {
  Zeroize(MutableByteSpan{tx_});
  Zeroize(MutableByteSpan{rx_});
  Zeroize(MutableByteSpan{sinf_});
  last_inf_ = ByteSpan{};
}

template <PortSet P>
void Link<P>::log(LogLevel level, Error error, const char* text) const noexcept {
  ports_->Emit(LogRecord{.level = level,
                         .layer = Layer::T1,
                         .command = static_cast<uint8_t>(0xFFU),
                         .sw = static_cast<uint16_t>(0U),
                         .error = error,
                         .length = static_cast<uint16_t>(0U),
                         .text = text});
}

// --- Public ----------------------------------------------------------------------------------

template <PortSet P>
Result<void> Link<P>::Open() noexcept {
  if (state_ == LinkState::InFlight) {
    return detail::Fail<void>(Error::Busy);
  }
  if (Validate(config_) != Error::Ok) {
    return detail::Fail<void>(Error::InvalidArgument);
  }
  state_ = LinkState::InFlight;
  open_ = false;
  dead_ = false;
  reselect_ = false;
  needs_resync_ = false;
  hint_ = false;
  wtx_count_ = 0U;
  wtx_wait_ms_ = 0U;
  ifs_count_ = 0U;
  Error e = Error::Bus;
  if (ports_->GetBus().EnsureInitialized()) {
    if constexpr (P::kHasReset) {
      static_cast<void>(ports_->GetReset().SetEnable(true)); // leave an ENA deep power-down
    }
    waitUs(config_.boot_wait_ms * 1000U);
    startDeadline(config_.atr_poll_budget_ms);
    flushStale();
    e = negotiate();
  }
  detect_ = false;
  seen_other_ = false;
  crc_fixed_ = true;
  open_ = e == Error::Ok;
  log(open_ ? LogLevel::Info : LogLevel::Error, e, "t1 open");
  wipe();
  settle();
  return open_ ? Result<void>::Success() : detail::Fail<void>(e);
}

template <PortSet P>
Result<std::size_t> Link<P>::Transceive(ByteSpan command, MutableByteSpan response,
                                        CommandClass command_class) noexcept {
  Error early = Error::Ok;
  if (state_ == LinkState::Closed) {
    early = Error::NotInitialized;
  } else if (state_ == LinkState::InFlight) {
    early = Error::Busy;
  } else if (state_ == LinkState::Dead) {
    early = Error::TransportDead;
  } else if (command.empty() || (command.size() > kMaxCommandApdu) ||
             !se05x::detail::IsEnumerator(command_class)) {
    early = Error::InvalidArgument;
  } else if (response.size() < 2U) {
    early = Error::BufferTooSmall;
  } else {
    // Ready to send.
  }
  if (early != Error::Ok) {
    return detail::Fail<std::size_t>(early);
  }
  state_ = LinkState::InFlight;
  counters_.last_rung = Rung::ResendBlock;
  wtx_count_ = 0U;
  wtx_wait_ms_ = 0U;
  ifs_count_ = 0U;
  Error e = Error::Ok;
  if (needs_resync_) {
    e = climb(Rung::Resync);
    needs_resync_ = false;
    e = (e == Error::Resynced) ? Error::Ok : e;
  }
  detail::Collected got{};
  Result<std::size_t> r = detail::Fail<std::size_t>(e);
  if (e == Error::Ok) {
    startDeadline(config_.timeouts.For(command_class));
    r = finish(exchange(command, response, got), response, got);
  }
  wipe();
  settle();
  return r;
}

template <PortSet P>
Result<void> Link<P>::Close() noexcept {
  if (state_ == LinkState::Closed) {
    return Result<void>::Success();
  }
  if (state_ == LinkState::InFlight) {
    return detail::Fail<void>(Error::Busy);
  }
  state_ = LinkState::InFlight;
  wtx_count_ = 0U;
  wtx_wait_ms_ = 0U;
  startDeadline(config_.timeouts.fast_ms);
  detail::Block b{};
  // NXP: end of APDU session (UM11225 Table 9); GP: RELEASE (GPC_SPE_172 Table 4-4). Same intent,
  // and 0xC6 must never be sent in the NXP flavour for it: that code resets the chip there.
  const uint8_t code =
      (flavour_ == TransportFlavour::Gp) ? wire::kGpRelease : wire::kUmEndOfApduSession;
  const Error e = sExchange(code, b, 0U);
  open_ = false;
  dead_ = false;
  reselect_ = false;
  needs_resync_ = false;
  wipe();
  settle();
  return (e == Error::Ok) ? Result<void>::Success() : detail::Fail<void>(e);
}

template <PortSet P>
Result<void> Link<P>::DeepPowerDown() noexcept {
  if (state_ == LinkState::Closed) {
    return detail::Fail<void>(Error::NotInitialized);
  }
  if (state_ == LinkState::InFlight) {
    return detail::Fail<void>(Error::Busy);
  }
  state_ = LinkState::InFlight;
  Error e = Error::Unsupported;
  if constexpr (P::kHasReset) {
    e = ports_->GetReset().SetEnable(false) ? Error::Ok : Error::Unsupported; // ENA low
  }
  if (e != Error::Ok) {
    wtx_count_ = 0U;
    wtx_wait_ms_ = 0U;
    startDeadline(config_.timeouts.fast_ms);
    detail::Block b{};
    e = sExchange(detail::kSDeepPowerDown, b, 0U);
    e = (e == Error::FrameError) ? Error::Unsupported : e;
    if (e == Error::Ok) {
      quiet_until_us_ = nowUs() + wire::kSe052DeepPowerDownUs;
    }
  }
  if (e != Error::Unsupported) {
    open_ = false; // acts first, reports after (RD-05): the link is closed either way
  }
  wipe();
  settle();
  return (e == Error::Ok) ? Result<void>::Success() : detail::Fail<void>(e);
}

template <PortSet P>
Result<void> Link<P>::Reset(ResetKind kind) noexcept {
  if (state_ == LinkState::Closed) {
    return detail::Fail<void>(Error::NotInitialized);
  }
  if (state_ == LinkState::InFlight) {
    return detail::Fail<void>(Error::Busy);
  }
  if (!se05x::detail::IsEnumerator(kind)) {
    return detail::Fail<void>(Error::InvalidArgument);
  }
  state_ = LinkState::InFlight;
  wtx_count_ = 0U;
  wtx_wait_ms_ = 0U;
  const Error e = doReset(kind);
  if (e == Error::Ok) {
    reselect_ = true;
    dead_ = false;
    needs_resync_ = false;
  } else if (e != Error::Unsupported) {
    dead_ = true;
  } else {
    // Nothing was sent: the state stays.
  }
  wipe();
  settle();
  return (e == Error::Ok) ? Result<void>::Success() : detail::Fail<void>(e);
}

template <PortSet P>
Result<void> Link<P>::Recover(Rung from) noexcept {
  if (state_ == LinkState::Closed) {
    return detail::Fail<void>(Error::NotInitialized);
  }
  if (state_ == LinkState::InFlight) {
    return detail::Fail<void>(Error::Busy);
  }
  if (!se05x::detail::IsEnumerator(from)) {
    return detail::Fail<void>(Error::InvalidArgument);
  }
  state_ = LinkState::InFlight;
  wtx_count_ = 0U;
  wtx_wait_ms_ = 0U;
  needs_resync_ = false;
  counters_.last_rung = Rung::ResendBlock;
  const Error e = climb(from);
  wipe();
  settle();
  return detail::Fail<void>(e);
}

} // namespace se05x::t1

#endif // SE05X_T1_IPP
