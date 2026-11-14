/**
 * @file t1_target.hpp
 * @brief The T=1 stage of the test model: the chip side of T=1 over I2C in both flavours, as a bus
 * port.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Written from the documents, not from the driver (hardware-lessons rule on independent models,
 * RD-07): UM11225 Rev 1.2 (NXP flavour: Tables 1 to 14, Figures 2 to 11) and GPC_SPE_172 v1.0 (GP
 * flavour: sections 3.2 and 4). It includes no driver header but the port and model interfaces:
 * its frame coding, CRC (a table, where the driver loops over bits), NAD values, S-block codes, ATR
 * and CIP are its own. The ATR is the SE052F ATR printed in AN13904 pp. 4-5 (vector V8) with the
 * IFSC and BWT as knobs; the CIP is synthetic, laid out per GPC_SPE_172 Tables 4-6, 4-7 and 4-9.
 *
 * What it checks while the driver talks to it: a write over an unread answer (errata I2C.1), an
 * empty write (errata I2C.2), a write that is not exactly one block, and where the driver's
 * buffers live (RD-06). Faults are scheduled by the index of the frame the model makes readable.
 * The CRC order of the NXP flavour follows the middleware oracle (least significant byte first);
 * `ModelKnobs::crc_swapped` reverses it (ambiguity A10).
 */
#ifndef SE05X_TESTS_MODEL_T1_TARGET_HPP
#define SE05X_TESTS_MODEL_T1_TARGET_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>

#include "model/model_if.hpp"
#include "se05x_ports.hpp"

namespace se05x::testmodel {

/** @brief A simulated clock: time moves only when the driver waits. */
class SimClock : public ClockInterface<SimClock> {
public:
  uint64_t NowUs() noexcept {
    ++reads;
    return now_us;
  }
  void DelayUs(uint32_t us) noexcept {
    now_us += us;
    total_delay_us += us;
  }
  uint64_t now_us{0};
  uint64_t total_delay_us{0};
  uint64_t reads{0};
};

/** @brief A fault the model applies to one of the frames it sends. */
enum class Fault : uint8_t {
  None,
  CorruptCrc,  ///< Last CRC byte inverted.
  BadNad,      ///< NAD 0x00, with a matching CRC.
  OverlongLen, ///< LEN field above every IFS; the bytes stay.
  ShortLen,    ///< LEN field one less than the INF (a bit error): bytes are left unread.
  Oversize,    ///< GP only: a 2000-byte INF, far beyond IFSD (a misbehaving chip).
  RepeatPrev,  ///< The block sent before this one, again (the chip missed an acknowledgement).
  CorruptPcb,  ///< A reserved PCB bit set, with a matching CRC (a coding error, not noise).
  Drop,        ///< The frame is lost: reads NACK until the next write.
  AllIdle,     ///< The frame is lost: reads return idle bytes until the next write.
  StuckBus,    ///< From this frame on, SCL is held low until a power cycle.
};

/** @brief One scheduled fault. */
struct FaultAt {
  uint32_t frame{0};
  Fault fault{Fault::None};
};

/** @brief The knobs of the T=1 stage. */
struct T1Knobs {
  ModelKnobs base{};              ///< Flavour, CRC order, throttle.
  uint32_t process_us{300};       ///< Time from a write to the answer.
  uint32_t answer_extra_us{0};    ///< Added before the first block of each APDU answer.
  uint32_t boot_us{0};            ///< NACK time after power-on, reset and wake.
  uint16_t wtx_before_answer{0};  ///< WTX requests before each APDU answer.
  uint8_t wtx_multiplier{1};      ///< Multiplier of those requests.
  uint16_t stale_wtx{0};          ///< At start: WTX requests of an earlier host's command.
  bool stale_answer{false};       ///< At start: an unread answer of an earlier host.
  bool stretch_lock{false};       ///< Errata I2C.1: a write over an unread answer sticks the bus.
  bool ack_idle_reads{false};     ///< Reads in the receive state return idle bytes, not NACK.
  bool supports_dpd{true};        ///< Answers the deep power-down S-block 0xDF.
  bool silent_soft_reset{false};  ///< Never answers the interface soft reset.
  bool silent_resync{false};      ///< Never answers RESYNC.
  uint16_t ifsc{254};             ///< IFSC the ATR or CIP reports.
  uint16_t bwt_ms{1000};          ///< BWT the ATR or CIP reports.
  uint8_t ifs_request{0};         ///< Before each answer: S(IFS request) with this size (0: none).
  bool ignore_ifsd{false};        ///< Answer blocks of up to 200 bytes whatever the host's IFSD.
  bool idle_while_busy{false};    ///< Reads while processing return idle bytes instead of NACK.
  uint32_t lose_host_frame{0};    ///< Host write number n (from 1) is acknowledged, then lost.
  uint32_t read_cost_us{0};       ///< Time each read takes on the bus.
  uint8_t mpot_ms{1};             ///< MPOT the ATR reports.
  uint16_t segt_us{100};          ///< SEGT the ATR reports (UM11225 Table 13).
  bool ignore_foreign_nad{false}; ///< Stay silent on a block with another flavour's NAD.
  uint32_t min_gap_us{0};         ///< Count accesses closer than this to the previous one.
  bool gp_nad_a5{false}; ///< GP flavour answering with NAD 0xA5, as the vendor middleware expects.
  std::array<FaultAt, 8> faults{}; ///< Scheduled faults.
};

/**
 * @brief The chip side of T=1 over I2C. A bus port; the APDU goes to the next stage, or is echoed
 * with SW 9000 when there is none.
 */
class T1Target : public BusInterface<T1Target> {
public:
  T1Target(SimClock& clock, ApduHandler* next, const T1Knobs& knobs) noexcept
      : clock_(clock), next_(next), knobs_(knobs), gp_(knobs.base.gp_flavour),
        awake_at_(knobs.boot_us) { // power-on: NACK until booted
    buildCrcTable();
    if (knobs.stale_answer || (knobs.stale_wtx != 0U)) {
      stale_wtx_left_ = knobs.stale_wtx;
      startStale();
    }
  }

  // --- Bus port -------------------------------------------------------------------------------
  [[nodiscard]] bool EnsureInitialized() const noexcept {
    return init_ok;
  }

  BusStatus Write(uint8_t addr7, ByteSpan data) noexcept {
    ++writes;
    checkGap(true);
    note(data.data(), data.size());
    if (stuck_) {
      return BusStatus::BusStuck;
    }
    if (addr7 != kAddress) {
      return BusStatus::Nack;
    }
    if (data.empty()) {
      ++empty_writes; // errata I2C.2
      if (knobs_.stretch_lock) {
        stuck_ = true;
      }
      return BusStatus::Nack;
    }
    if (!awake()) {
      return BusStatus::Nack;
    }
    if (phase_ == Phase::Process) {
      if (clock_.now_us < ready_at_) {
        return BusStatus::Nack; // UM11225 3.1.1.2: writes are NACKed while processing
      }
      phase_ = Phase::Send;
    }
    if ((phase_ == Phase::Send) && (out_pos_ < out_len_)) {
      ++i2c1_violations; // a new block over an unread answer (errata I2C.1)
      if (knobs_.stretch_lock) {
        stuck_ = true;
        return BusStatus::BusStuck;
      }
      protocolReset(); // UM11225 2.4.2: as after an interface soft reset
    }
    phase_ = Phase::Receive;
    lost_ = Fault::None;
    ++host_writes_;
    if (host_writes_ == knobs_.lose_host_frame) {
      ++host_frames_lost; // acknowledged on the bus, never processed
      return BusStatus::Ok;
    }
    onHostFrame(data);
    return BusStatus::Ok;
  }

  BusRead Read(uint8_t addr7, MutableByteSpan out) noexcept {
    checkGap(false);
    const BusRead r = ReadChip(addr7, out);
    last_read_nacked_ = r.status == BusStatus::Nack;
    return r;
  }

  /** @brief The chip's answer to a read, without the guard-time check. */
  BusRead ReadChip(uint8_t addr7, MutableByteSpan out) noexcept {
    ++reads;
    clock_.now_us += knobs_.read_cost_us;
    note(out.data(), out.size());
    if (stuck_) {
      return BusRead{BusStatus::BusStuck, 0U};
    }
    if (bus_errors != 0U) {
      --bus_errors; // arbitration lost: nothing was transferred
      return BusRead{BusStatus::BusError, 0U};
    }
    if ((addr7 != kAddress) || !awake()) {
      return BusRead{BusStatus::Nack, 0U};
    }
    if ((phase_ == Phase::Process) && (clock_.now_us >= ready_at_)) {
      phase_ = Phase::Send;
    }
    if (phase_ == Phase::Process) {
      if (knobs_.idle_while_busy) {
        fill(out, out_len_); // past the data: idle bytes only
        return BusRead{BusStatus::Ok, out.size()};
      }
      return BusRead{BusStatus::Nack, 0U};
    }
    if (phase_ == Phase::Receive) {
      if (knobs_.ack_idle_reads || (lost_ == Fault::AllIdle)) {
        fill(out, 0U);
        return BusRead{BusStatus::Ok, out.size()};
      }
      return BusRead{BusStatus::Nack, 0U};
    }
    fill(out, out_pos_);
    std::size_t n = out.size();
    if ((short_reads != 0U) && (n > 1U)) {
      --short_reads;
      --n; // the port reports fewer bytes than asked
    }
    out_pos_ += n;
    if (out_pos_ >= out_len_) {
      afterSend();
    }
    return BusRead{BusStatus::Ok, n};
  }

  // --- Reset and power, for a test reset port -------------------------------------------------
  void HardReset() noexcept {
    ++hard_resets;
    reboot();
  }
  void PowerCycleChip() noexcept {
    ++power_cycles;
    stuck_ = false;
    reboot();
  }
  bool SetEna(bool on) noexcept {
    if (!has_ena) {
      return false;
    }
    if (!on && ena_) {
      ++dpd_entries;
      dpd_pending_ = true;
      dpd_at_ = clock_.now_us;
      asleep_ = true;
    } else if (on && !ena_) {
      reboot();
    } else {
      // No change.
    }
    ena_ = on;
    return true;
  }

  // --- Inspection -----------------------------------------------------------------------------
  /** @return How many host frames had this PCB. */
  [[nodiscard]] uint32_t Sent(uint8_t pcb) const noexcept {
    return pcb_count_[pcb];
  }
  /** @return The PCB of host frame `i`, 0xFF past the log. */
  [[nodiscard]] uint8_t HostPcb(uint32_t i) const noexcept {
    return (i < log_len_) ? log_[i] : 0xFFU;
  }
  [[nodiscard]] uint32_t HostFrames() const noexcept {
    return log_len_;
  }
  [[nodiscard]] bool BuffersWithin(const void* object, std::size_t size) const noexcept {
    const auto* base = static_cast<const uint8_t*>(object);
    const std::less<const uint8_t*> before{};
    return seen_any_ && !before(lowest_, base) && !before(base + size, highest_);
  }
  /** @return The model's own CRC-16/X-25 of a byte string (table method). */
  [[nodiscard]] uint16_t Crc(ByteSpan bytes) const noexcept {
    uint32_t crc = 0xFFFFU;
    for (const uint8_t b : bytes) {
      crc = (crc >> 8U) ^ table_[(crc ^ b) & 0xFFU];
    }
    return static_cast<uint16_t>(~crc & 0xFFFFU);
  }
  /** @return Whether the last frame the model sent is fully read. */
  [[nodiscard]] bool Drained() const noexcept {
    const bool ready =
        (phase_ == Phase::Send) || ((phase_ == Phase::Process) && (clock_.now_us >= ready_at_));
    return !ready || (out_pos_ >= out_len_);
  }
  void SetFault(uint32_t slot, uint32_t frame, Fault fault) noexcept {
    knobs_.faults[slot] = FaultAt{frame, fault};
  }
  T1Knobs& Knobs() noexcept {
    return knobs_;
  }

  /** @return When the command being processed has its answer ready (fake clock, us). */
  [[nodiscard]] uint64_t ReadyAt() const noexcept {
    return ready_at_;
  }

  bool init_ok{true};
  uint32_t bus_errors{0};  ///< Reads that fail with BusError before the next one works.
  uint32_t short_reads{0}; ///< Reads that report one byte less than asked.
  uint32_t host_frames_lost{0};
  uint32_t boot_accesses{0}; ///< Bus accesses while the chip boots after a reset.
  bool has_ena{false};
  uint32_t writes{0};
  uint32_t reads{0};
  uint32_t empty_writes{0};
  uint32_t i2c1_violations{0};
  uint32_t bad_frames{0}; ///< Host frames with a bad CRC, NAD or length.
  uint32_t apdus{0};
  uint32_t frames_out{0}; ///< Frames made readable.
  uint32_t soft_resets{0};
  uint32_t chip_resets{0};
  uint32_t hard_resets{0};
  uint32_t power_cycles{0};
  uint32_t dpd_entries{0};
  uint32_t throttled{0};
  uint32_t wtx_answered{0};
  uint64_t gap_after_dpd_us{0}; ///< Time from a deep power-down to the next access.
  uint32_t guard_violations{0}; ///< Accesses closer than `min_gap_us` to the previous one.
  uint32_t session_ends{0};
  uint32_t ifs_answered{0};

private:
  enum class Phase : uint8_t { Receive, Process, Send };
  enum class After : uint8_t { None, ChipReset, DeepPowerDown, Sleep };

  static constexpr uint8_t kAddress = 0x48U; // SE05x data sheets: 1001000b
  static constexpr std::size_t kMaxBlock = 4U + 4089U + 2U;
  static constexpr std::size_t kMaxApdu = 1200U;

  // --- CRC: table of the reflected polynomial (ISO/IEC 7816-3 CRC, X-25) ---------------------
  void buildCrcTable() noexcept {
    for (uint32_t i = 0U; i < 256U; ++i) {
      uint32_t v = i;
      for (uint32_t k = 0U; k < 8U; ++k) {
        v = ((v & 1U) != 0U) ? ((v >> 1U) ^ 0x8408U) : (v >> 1U);
      }
      table_[i] = static_cast<uint16_t>(v);
    }
  }
  [[nodiscard]] bool lsbFirst() const noexcept {
    // GP: MSB first (GPC_SPE_172 p. 33). NXP: LSB first as the oracle; the knob swaps either.
    const bool lsb = !gp_;
    return knobs_.base.crc_swapped ? !lsb : lsb;
  }
  [[nodiscard]] std::size_t hdr() const noexcept {
    return gp_ ? 4U : 3U;
  }
  [[nodiscard]] uint8_t hostNad() const noexcept {
    return gp_ ? 0x21U : 0x5AU;
  }
  [[nodiscard]] uint8_t seNad() const noexcept {
    if (gp_ && !knobs_.gp_nad_a5) {
      return 0x12U;
    }
    return 0xA5U;
  }
  [[nodiscard]] std::size_t hostIfs() const noexcept {
    return gp_ ? 64U : ifs_; // GP: the SE assumes IFSD 64 (GPC_SPE_172 4.1)
  }

  /// The guard time between two accesses (UM11225 Table 15 SEGT, GPC_SPE_172 3.2.7 RWGT).
  /// A write right after a NACKed probe read is the host's errata I2C.1 exception: not counted.
  void checkGap(bool write) noexcept {
    if (dpd_pending_) {
      dpd_pending_ = false;
      gap_after_dpd_us = clock_.now_us - dpd_at_;
    }
    const bool exempt = write && last_read_nacked_;
    last_read_nacked_ = false;
    if (accessed_ && !exempt && (knobs_.min_gap_us != 0U) &&
        ((clock_.now_us - last_access_us_) < knobs_.min_gap_us)) {
      ++guard_violations;
    }
    accessed_ = true;
    last_access_us_ = clock_.now_us;
  }
  void note(const uint8_t* p, std::size_t n) noexcept {
    if (n == 0U) {
      return;
    }
    const std::less<const uint8_t*> before{};
    if (!seen_any_ || before(p, lowest_)) {
      lowest_ = p;
    }
    if (!seen_any_ || before(highest_, p + n)) {
      highest_ = p + n;
    }
    seen_any_ = true;
  }

  [[nodiscard]] bool awake() noexcept {
    if (asleep_) {
      if (!ena_) {
        return false;
      }
      // Deep power-down: the next access wakes and boots the chip (SE052 data sheet 10.3).
      reboot();
      return false;
    }
    if (clock_.now_us < awake_at_) {
      ++boot_accesses; // UM11225 p. 8: the lines stay high for DPWT after a reset
      return false;
    }
    return true;
  }

  void reboot() noexcept {
    asleep_ = false;
    awake_at_ = clock_.now_us + knobs_.boot_us;
    phase_ = Phase::Receive;
    out_len_ = 0U;
    out_pos_ = 0U;
    lost_ = Fault::None;
    apdus_since_reset_ = 0U;
    protocolReset();
    if (next_ != nullptr) {
      next_->PowerCycle();
    }
  }

  void protocolReset() noexcept {
    host_ns_ = 0U;
    card_ns_ = 0U;
    cmd_len_ = 0U;
    resp_len_ = 0U;
    resp_pos_ = 0U;
    chaining_ = false;
    wtx_left_ = 0U;
    awaiting_wtx_ = false;
    last_len_ = 0U;
    ifs_ = knobs_.ifsc;
    ifs_sent_ = false;
  }

  void fill(MutableByteSpan out, std::size_t from) const noexcept {
    for (std::size_t i = 0U; i < out.size(); ++i) {
      const std::size_t at = from + i;
      out[i] = (at < out_len_) ? out_[at] : 0xFFU; // past the data: idle bytes
    }
  }

  void afterSend() noexcept {
    phase_ = Phase::Receive;
    const After after = after_;
    after_ = After::None;
    if (after == After::ChipReset) {
      ++chip_resets;
      reboot();
    } else if (after == After::DeepPowerDown) {
      ++dpd_entries;
      dpd_pending_ = true;
      dpd_at_ = clock_.now_us;
      asleep_ = true;
      ena_ = true;
    } else {
      // Sleep (power-down keeps the state) or nothing.
    }
  }

  // --- Building and sending blocks ------------------------------------------------------------
  void emit(uint8_t pcb, const uint8_t* inf, std::size_t len, bool remember) noexcept {
    std::size_t p = 0U;
    out_[p++] = seNad();
    out_[p++] = pcb;
    if (gp_) {
      out_[p++] = static_cast<uint8_t>((len >> 8U) & 0xFFU);
    }
    out_[p++] = static_cast<uint8_t>(len & 0xFFU);
    for (std::size_t i = 0U; i < len; ++i) {
      out_[p++] = inf[i];
    }
    const uint16_t crc = Crc(ByteSpan{out_.data(), p});
    const auto hi = static_cast<uint8_t>(crc >> 8U);
    const auto lo = static_cast<uint8_t>(crc & 0xFFU);
    out_[p++] = lsbFirst() ? lo : hi;
    out_[p++] = lsbFirst() ? hi : lo;
    out_len_ = p;
    out_pos_ = 0U;
    if (remember) {
      for (std::size_t i = 0U; i < last_len_; ++i) {
        prev_[i] = last_[i];
      }
      prev_len_ = last_len_;
      for (std::size_t i = 0U; i < p; ++i) {
        last_[i] = out_[i];
      }
      last_len_ = p;
    }
    applyFault();
    ++frames_out;
    phase_ = Phase::Process;
    ready_at_ = clock_.now_us + knobs_.process_us;
  }

  void applyFault() noexcept {
    Fault f = Fault::None;
    for (const FaultAt& fa : knobs_.faults) {
      if ((fa.fault != Fault::None) && (fa.frame == frames_out)) {
        f = fa.fault;
      }
    }
    switch (f) {
    case Fault::CorruptCrc:
      out_[out_len_ - 1U] = static_cast<uint8_t>(~out_[out_len_ - 1U]);
      break;
    case Fault::BadNad:
      out_[0] = 0x00U;
      recrc(); // a wrong NAD under a valid CRC: only the NAD check can refuse it
      break;
    case Fault::OverlongLen:
      out_[hdr() - 1U] = 0xFFU;
      if (gp_) {
        out_[2] = 0x0FU;
      }
      break;
    case Fault::CorruptPcb:
      out_[1] = static_cast<uint8_t>(out_[1] | pcbFlaw(out_[1]));
      recrc();
      break;
    case Fault::RepeatPrev:
      if (prev_len_ != 0U) {
        for (std::size_t i = 0U; i < prev_len_; ++i) {
          out_[i] = prev_[i];
        }
        out_len_ = prev_len_;
      }
      break;
    case Fault::Oversize:
      if (gp_) {
        out_[2] = 0x07U; // LEN 0x07D0
        out_[3] = 0xD0U;
        for (std::size_t i = 4U; i < (4U + 2000U + 2U); ++i) {
          out_[i] = static_cast<uint8_t>(i);
        }
        out_len_ = 4U + 2000U + 2U;
      }
      break;
    case Fault::ShortLen:
      if (out_[hdr() - 1U] != 0U) {
        out_[hdr() - 1U] = static_cast<uint8_t>(out_[hdr() - 1U] - 1U);
      }
      break;
    case Fault::Drop:
    case Fault::AllIdle:
      lost_ = f;
      out_len_ = 0U;
      phase_ = Phase::Receive;
      break;
    case Fault::StuckBus:
      stuck_ = true;
      break;
    case Fault::None:
    default:
      break;
    }
  }

  void recrc() noexcept {
    const std::size_t body = out_len_ - 2U;
    const uint16_t crc = Crc(ByteSpan{out_.data(), body});
    const auto hi = static_cast<uint8_t>(crc >> 8U);
    const auto lo = static_cast<uint8_t>(crc & 0xFFU);
    out_[body] = lsbFirst() ? lo : hi;
    out_[body + 1U] = lsbFirst() ? hi : lo;
  }

  static uint8_t pcbFlaw(uint8_t pcb) noexcept {
    if (pcb < 0x80U) {
      return 0x01U; // I-block reserved bit
    }
    return ((pcb & 0xC0U) == 0x80U) ? 0x04U : 0x10U; // R-block reserved bit, reserved S code
  }

  void resend() noexcept {
    if (last_len_ == 0U) {
      sendR(0U); // nothing sent yet: ask for the block
      return;
    }
    for (std::size_t i = 0U; i < last_len_; ++i) {
      out_[i] = last_[i];
    }
    out_len_ = last_len_;
    out_pos_ = 0U;
    applyFault();
    ++frames_out;
    phase_ = Phase::Process;
    ready_at_ = clock_.now_us + knobs_.process_us;
  }

  void sendR(uint8_t error) noexcept {
    const auto pcb = static_cast<uint8_t>(0x80U | (static_cast<uint32_t>(host_ns_) << 4U) | error);
    emit(pcb, nullptr, 0U, true);
  }

  void sendS(uint8_t pcb, const uint8_t* inf, std::size_t len) noexcept {
    emit(pcb, inf, len, true);
  }

  void sendNextAnswerBlock() noexcept {
    const std::size_t left = resp_len_ - resp_pos_;
    const std::size_t ifs = knobs_.ignore_ifsd ? 200U : hostIfs();
    const std::size_t n = (left < ifs) ? left : ifs;
    const bool more = (resp_pos_ + n) < resp_len_;
    const auto pcb =
        static_cast<uint8_t>((static_cast<uint32_t>(card_ns_) << 6U) | (more ? 0x20U : 0x00U));
    chain_ns_ = card_ns_;
    card_ns_ = static_cast<uint8_t>(card_ns_ ^ 1U);
    emit(pcb, resp_.data() + resp_pos_, n, true);
    chain_n_ = n;
    chaining_ = more;
  }

  void startAnswer() noexcept {
    if ((knobs_.ifs_request != 0U) && !ifs_sent_) {
      ifs_sent_ = true;
      ifs_req_[0] = knobs_.ifs_request;
      ifs_ = knobs_.ifs_request; // the chip's new IFSC; IFSD follows (UM11225 2.1.2.1)
      sendS(0xC1U, ifs_req_.data(), 1U);
      return;
    }
    if (wtx_left_ != 0U) {
      --wtx_left_;
      awaiting_wtx_ = true;
      wtx_inf_[0] = knobs_.wtx_multiplier;
      emit(0xC3U, wtx_inf_.data(), 1U, true);
      return;
    }
    resp_pos_ = 0U;
    sendNextAnswerBlock();
    ready_at_ += knobs_.answer_extra_us;
  }

  void startStale() noexcept {
    // An earlier host's command still pending at start (errata I2C.1 workaround test).
    resp_[0] = 0x6FU;
    resp_[1] = 0x00U;
    resp_len_ = 2U;
    if (stale_wtx_left_ != 0U) {
      --stale_wtx_left_;
      awaiting_wtx_ = true;
      stale_wtx_ = true;
      wtx_inf_[0] = 1U;
      emit(0xC3U, wtx_inf_.data(), 1U, true);
    } else {
      sendNextAnswerBlock();
    }
    phase_ = Phase::Send; // already there before the host starts
    ready_at_ = 0U;
  }

  void runApdu() noexcept {
    ++apdus;
    ++apdus_since_reset_;
    std::size_t n = 0U;
    if (knobs_.base.throttle_enabled && (apdus_since_reset_ > knobs_.base.throttle_after)) {
      ++throttled; // SW 0x66A6 until the chip is reset (AN13904 8.4)
      resp_[0] = 0x66U;
      resp_[1] = 0xA6U;
      n = 2U;
    } else if (next_ != nullptr) {
      n = next_->Handle(ByteSpan{cmd_.data(), cmd_len_},
                        MutableByteSpan{resp_.data(), resp_.size()});
    } else {
      for (std::size_t i = 0U; i < cmd_len_; ++i) {
        resp_[i] = cmd_[i];
      }
      resp_[cmd_len_] = 0x90U;
      resp_[cmd_len_ + 1U] = 0x00U;
      n = cmd_len_ + 2U;
    }
    cmd_len_ = 0U;
    if (n == 0U) {
      phase_ = Phase::Process; // dropped: the answer never comes
      ready_at_ = ~0ULL;
      return;
    }
    resp_len_ = n;
    wtx_left_ = knobs_.wtx_before_answer;
    startAnswer();
  }

  // --- Host frames ----------------------------------------------------------------------------
  void onHostFrame(ByteSpan f) noexcept {
    const std::size_t h = hdr();
    if (f.size() < (h + 2U)) {
      ++bad_frames;
      sendR(0x02U);
      return;
    }
    const uint8_t pcb = f[1];
    logPcb(pcb);
    const std::size_t len =
        gp_ ? ((static_cast<std::size_t>(f[2]) << 8U) | static_cast<std::size_t>(f[3])) : f[2];
    if (knobs_.ignore_foreign_nad && (f[0] != hostNad())) {
      ++bad_frames;
      silent(); // no answer at all to a block it cannot place
      return;
    }
    if ((f[0] != hostNad()) || (f.size() != (h + len + 2U))) {
      ++bad_frames;
      sendR(0x02U);
      return;
    }
    const uint16_t crc = Crc(f.first(h + len));
    const auto c1 = static_cast<uint32_t>(f[h + len]);
    const auto c2 = static_cast<uint32_t>(f[h + len + 1U]);
    const auto got = static_cast<uint16_t>(lsbFirst() ? ((c2 << 8U) | c1) : ((c1 << 8U) | c2));
    if (got != crc) {
      ++bad_frames;
      sendR(0x01U);
      return;
    }
    const ByteSpan inf = f.subspan(h, len);
    if ((pcb & 0x80U) == 0U) {
      onI(pcb, inf);
    } else if ((pcb & 0xC0U) == 0x80U) {
      onR(pcb);
    } else {
      onS(pcb, inf);
    }
  }

  void onI(uint8_t pcb, ByteSpan inf) noexcept {
    const auto ns = static_cast<uint8_t>((static_cast<uint32_t>(pcb) >> 6U) & 1U);
    if ((ns != host_ns_) || awaiting_wtx_ || (inf.size() > ifs_) ||
        ((cmd_len_ + inf.size()) > kMaxApdu)) {
      sendR(0x02U);
      return;
    }
    for (const uint8_t b : inf) {
      cmd_[cmd_len_++] = b;
    }
    host_ns_ = static_cast<uint8_t>(host_ns_ ^ 1U);
    chaining_ = false;
    if ((pcb & 0x20U) != 0U) {
      sendR(0x00U); // acknowledge the chained block: N(R) = next expected N(S)
      return;
    }
    runApdu();
  }

  void onR(uint8_t pcb) noexcept {
    const auto nr = static_cast<uint8_t>((static_cast<uint32_t>(pcb) >> 4U) & 1U);
    if (chaining_ && (nr != chain_ns_) && ((pcb & 0x03U) == 0U)) {
      resp_pos_ += chain_n_; // the host acknowledged the chained block: the next one
      sendNextAnswerBlock();
      return;
    }
    const uint32_t last = (last_len_ != 0U) ? static_cast<uint32_t>(last_[1]) : 0xE0U;
    const bool last_i = (last & 0x80U) == 0U;
    const bool last_r = (last & 0xC0U) == 0x80U;
    const bool last_s_request = (last & 0xE0U) == 0xC0U;
    if ((last_i && (nr == chain_ns_)) || last_r || last_s_request) {
      resend(); // the host asks for the chip's last block again
      return;
    }
    // The host asks for a block the chip never sent: the host's own block was lost, so the chip
    // asks for it (ISO/IEC 7816-3 error handling, inherited by both documents).
    sendR(0x00U);
  }

  void onS(uint8_t pcb, ByteSpan inf) noexcept {
    if (pcb == 0xE3U) {
      onWtxResponse(inf);
      return;
    }
    if (pcb == 0xE1U) { // the host's answer to the chip's IFS request
      if ((inf.size() == 1U) && (inf[0] == ifs_req_[0])) {
        ++ifs_answered;
        startAnswer();
        return;
      }
      sendR(0x02U);
      return;
    }
    if (awaiting_wtx_ && (pcb != 0xC0U)) {
      // UM11225 2.1.1.2.3: a WTX request is answered with a WTX response, never with a soft
      // reset. RESYNC is accepted: the host has given the command up.
      sendR(0x02U);
      return;
    }
    switch (pcb) {
    case 0xC0U: // RESYNC
      if (knobs_.silent_resync) {
        silent();
        return;
      }
      protocolReset();
      sendS(0xE0U, nullptr, 0U);
      return;
    case 0xC1U: // IFS request from the host
      if ((inf.size() == 1U) && (inf[0] != 0U)) {
        ifs_ = inf[0];
        sendS(0xE1U, inf.data(), 1U);
        return;
      }
      break;
    case 0xCFU: // interface soft reset (NXP) or SWR (GP)
      onSoftReset();
      return;
    case 0xDFU: // SE052 deep power-down
      if (knobs_.supports_dpd) {
        after_ = After::DeepPowerDown;
        sendS(0xFFU, nullptr, 0U);
        return;
      }
      break;
    default:
      if (gp_ ? onGpS(pcb) : onNxpS(pcb)) {
        return;
      }
      break;
    }
    sendR(0x02U);
  }

  bool onNxpS(uint8_t pcb) noexcept {
    if (pcb == 0xC5U) { // end of APDU session
      ++session_ends;
      protocolReset();
      after_ = After::Sleep;
      sendS(0xE5U, nullptr, 0U);
      return true;
    }
    if (pcb == 0xC6U) { // SE chip reset: reset after the response is read
      after_ = After::ChipReset;
      sendS(0xE6U, nullptr, 0U);
      return true;
    }
    if (pcb == 0xC7U) { // get ATR
      sendAtr(0xE7U);
      return true;
    }
    return false;
  }

  bool onGpS(uint8_t pcb) noexcept {
    if (pcb == 0xC4U) { // CIP
      sendCip();
      return true;
    }
    if (pcb == 0xC6U) { // RELEASE: power saving, the state is kept
      ++session_ends;
      after_ = After::Sleep;
      sendS(0xE6U, nullptr, 0U);
      return true;
    }
    return false;
  }

  void onWtxResponse(ByteSpan inf) noexcept {
    if (!awaiting_wtx_ || (inf.size() != 1U) || (inf[0] != wtx_inf_[0])) {
      sendR(0x02U);
      return;
    }
    ++wtx_answered;
    awaiting_wtx_ = false;
    if (stale_wtx_) {
      if (stale_wtx_left_ != 0U) {
        --stale_wtx_left_;
        awaiting_wtx_ = true;
        emit(0xC3U, wtx_inf_.data(), 1U, true);
        return;
      }
      stale_wtx_ = false;
      sendNextAnswerBlock();
      return;
    }
    startAnswer();
  }

  void onSoftReset() noexcept {
    if (knobs_.silent_soft_reset) {
      silent();
      return;
    }
    ++soft_resets;
    protocolReset();
    if (gp_) {
      sendS(0xEFU, nullptr, 0U);
    } else {
      sendAtr(0xEFU);
    }
  }

  void silent() noexcept {
    phase_ = Phase::Receive; // no answer at all
    out_len_ = 0U;
    lost_ = Fault::Drop;
  }

  void sendAtr(uint8_t pcb) noexcept {
    // AN13904 pp. 4-5 (V8), with IFSC and BWT from the knobs (UM11225 Tables 11 to 13).
    std::array<uint8_t, 35> atr{0x01U, 0xA0U, 0x00U, 0x00U, 0x03U, 0x96U, 0x04U, 0x03U, 0xE8U,
                                0x00U, 0xFEU, 0x02U, 0x0BU, 0x03U, 0xE8U, 0x00U, 0x01U, 0x00U,
                                0x00U, 0x00U, 0x00U, 0x64U, 0x13U, 0x88U, 0x0AU, 0x00U, 0x65U,
                                0x53U, 0x45U, 0x30U, 0x35U, 0x31U, 0x00U, 0x00U, 0x00U};
    atr[7] = static_cast<uint8_t>(knobs_.bwt_ms >> 8U);
    atr[8] = static_cast<uint8_t>(knobs_.bwt_ms & 0xFFU);
    atr[16] = knobs_.mpot_ms;
    atr[20] = static_cast<uint8_t>(knobs_.segt_us >> 8U);
    atr[21] = static_cast<uint8_t>(knobs_.segt_us & 0xFFU);
    atr[9] = static_cast<uint8_t>(knobs_.ifsc >> 8U);
    atr[10] = static_cast<uint8_t>(knobs_.ifsc & 0xFFU);
    sendS(pcb, atr.data(), atr.size());
  }

  void sendCip() noexcept {
    // GPC_SPE_172 Tables 4-6, 4-9, 4-7: PVER, IIN, PLID, PLP (config, PWT 25 ms, MCF 400 kHz,
    // PST FF, MPOT 10 x 100 us, RWGT 10 us), DLLP (BWT, IFSC), no historical bytes.
    std::array<uint8_t, 22> cip{0x01U, 0x04U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U, 0x08U,
                                0x00U, 0x19U, 0x01U, 0x90U, 0xFFU, 0x0AU, 0x00U, 0x0AU,
                                0x04U, 0x01U, 0x2CU, 0x00U, 0xFEU, 0x00U};
    cip[17] = static_cast<uint8_t>(knobs_.bwt_ms >> 8U);
    cip[18] = static_cast<uint8_t>(knobs_.bwt_ms & 0xFFU);
    cip[19] = static_cast<uint8_t>(knobs_.ifsc >> 8U);
    cip[20] = static_cast<uint8_t>(knobs_.ifsc & 0xFFU);
    sendS(0xE4U, cip.data(), cip.size());
  }

  void logPcb(uint8_t pcb) noexcept {
    ++pcb_count_[pcb];
    if (log_len_ < log_.size()) {
      log_[log_len_] = pcb;
      ++log_len_;
    }
  }

  SimClock& clock_;
  ApduHandler* next_;
  T1Knobs knobs_;
  bool gp_;
  bool stuck_{false};
  bool asleep_{false};
  bool ena_{true};
  uint64_t awake_at_;
  uint64_t ready_at_{0};
  uint64_t last_access_us_{0};
  bool accessed_{false};
  bool dpd_pending_{false};
  bool last_read_nacked_{false};
  uint64_t dpd_at_{0};
  Phase phase_{Phase::Receive};
  After after_{After::None};
  Fault lost_{Fault::None};
  std::array<uint16_t, 256> table_{};
  std::array<uint8_t, kMaxBlock> out_{};
  std::size_t out_len_{0};
  std::size_t out_pos_{0};
  std::array<uint8_t, kMaxBlock> last_{};
  std::size_t last_len_{0};
  std::array<uint8_t, kMaxBlock> prev_{};
  std::size_t prev_len_{0};
  uint32_t host_writes_{0};
  std::array<uint8_t, kMaxApdu> cmd_{};
  std::size_t cmd_len_{0};
  std::array<uint8_t, kMaxApdu> resp_{};
  std::size_t resp_len_{0};
  std::size_t resp_pos_{0};
  std::size_t chain_n_{0};
  uint8_t chain_ns_{0};
  bool chaining_{false};
  uint8_t host_ns_{0};
  uint8_t card_ns_{0};
  uint16_t wtx_left_{0};
  uint16_t stale_wtx_left_{0};
  bool stale_wtx_{false};
  bool awaiting_wtx_{false};
  std::array<uint8_t, 1> wtx_inf_{};
  std::array<uint8_t, 1> ifs_req_{};
  bool ifs_sent_{false};
  std::size_t ifs_{254};
  uint32_t apdus_since_reset_{0};
  std::array<uint32_t, 256> pcb_count_{};
  std::array<uint8_t, 4096> log_{};
  uint32_t log_len_{0};
  bool seen_any_{false};
  const uint8_t* lowest_{nullptr};
  const uint8_t* highest_{nullptr};
};

/** @brief A reset port wired to the model. */
class SimReset : public ResetInterface<SimReset> {
public:
  explicit SimReset(T1Target& target) noexcept : target_(target) {}
  bool Reset() noexcept {
    ++resets;
    if (reset_ok) {
      target_.HardReset();
    }
    return reset_ok;
  }
  bool PowerCycle() noexcept {
    ++cycles;
    if (reset_ok) {
      target_.PowerCycleChip();
    }
    return reset_ok;
  }
  bool SetEnable(bool on) noexcept {
    ++enables;
    return target_.SetEna(on);
  }
  bool reset_ok{true};
  uint32_t resets{0};
  uint32_t cycles{0};
  uint32_t enables{0};

private:
  T1Target& target_;
};

/** @brief A log port that counts. */
class SimLog : public LogInterface<SimLog> {
public:
  void Log(const LogRecord& record) noexcept {
    ++records;
    last = record;
  }
  uint32_t records{0};
  LogRecord last{};
};

} // namespace se05x::testmodel

#endif // SE05X_TESTS_MODEL_T1_TARGET_HPP
