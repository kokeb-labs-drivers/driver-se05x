/**
 * @file test_t1_faults.cpp
 * @brief Fault injection at every frame of the T=1 exchange, the retry budget, the recovery ladder,
 * the throughput limit (SW 0x66A6), a stuck bus, and the invariants that hold through all of it:
 * no write over an unread answer (errata I2C.1), no empty write (I2C.2), no part of a failed answer
 * left in the caller's buffer (S-01).
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>

#include "model/t1_fixture.hpp"
#include "test_harness.hpp"

namespace {

using namespace se05x;
using namespace se05x::testmodel;
using t1::LinkState;
using t1::Rung;

std::array<uint8_t, 1100>& Cmd() {
  static std::array<uint8_t, 1100> buffer{};
  return buffer;
}
std::array<uint8_t, 1100>& Resp() {
  static std::array<uint8_t, 1100> buffer{};
  return buffer;
}

template <typename B>
Result<std::size_t> Send(B& b, std::size_t n, uint8_t fill = 0U) {
  for (std::size_t i = 0U; i < Cmd().size(); ++i) {
    Cmd()[i] = static_cast<uint8_t>(i + 5U);
  }
  Resp().fill(fill);
  return b.link.Transceive(ByteSpan{Cmd()}.first(n), MutableByteSpan{Resp()});
}

template <typename B>
bool Clean(const B& b) {
  return (b.chip.i2c1_violations == 0U) && (b.chip.empty_writes == 0U) &&
         (b.link.State() != LinkState::InFlight);
}

/** @return Whether the answer arrived intact and the chip got the whole command once. */
template <typename B>
bool Intact(const B& b, const Result<std::size_t>& r, std::size_t cmd_len, uint32_t commands) {
  bool same = (b.handler.last_len == cmd_len) && (b.handler.commands == commands);
  for (std::size_t i = 0U; same && (i < cmd_len); ++i) {
    same = b.handler.last[i] == Cmd()[i];
  }
  return r.ok() && same && IsPatternAnswer(Resp(), r.value, b.handler.answer_len);
}

T1Knobs Strict(bool gp) {
  T1Knobs k = Knobs(gp);
  k.ifsc = 32U;
  k.stretch_lock = true; // any write over an unread answer would stick the bus
  return k;
}

TEST_CASE("One fault on any frame of a chained exchange is mended by the retries") {
  constexpr std::array<Fault, 7> kFaults{Fault::CorruptCrc, Fault::BadNad,     Fault::OverlongLen,
                                         Fault::ShortLen,   Fault::CorruptPcb, Fault::Drop,
                                         Fault::AllIdle};
  uint32_t failures = 0U;
  uint32_t runs = 0U;
  for (const bool gp : {false, true}) {
    for (const Fault fault : kFaults) {
      for (uint32_t k = 0U; k < 14U; ++k) {
        Bench b(Strict(gp), Patient(gp ? TransportFlavour::Gp : TransportFlavour::Um11225));
        b.handler.answer_len = 200U;
        if (!b.link.Open().ok()) {
          ++failures;
          continue;
        }
        b.chip.SetFault(0U, b.chip.frames_out + k, fault);
        const auto r = Send(b, 100U);
        failures += (Intact(b, r, 100U, 1U) && Clean(b) && (b.link.GetCounters().recoveries == 0U))
                        ? 0U
                        : 1U;
        ++runs;
      }
    }
  }
  CHECK_EQ(failures, 0U);
  CHECK_EQ(runs, 196U);
}

TEST_CASE("One fault on any frame of the start-up is mended, in Auto and in both flavours") {
  uint32_t failures = 0U;
  for (const bool gp : {false, true}) {
    for (const Fault fault : {Fault::CorruptCrc, Fault::Drop, Fault::BadNad}) {
      for (uint32_t k = 0U; k < 6U; ++k) {
        T1Knobs knobs = Strict(gp);
        knobs.faults[0] = FaultAt{k, fault};
        Config c{};
        c.atr_poll_budget_ms = 8000U;
        Bench b(knobs, c);
        const bool opened = b.link.Open().ok();
        const bool right =
            b.link.Params().flavour == (gp ? TransportFlavour::Gp : TransportFlavour::Um11225);
        failures += (opened && right && Clean(b) && Send(b, 5U).ok()) ? 0U : 1U;
      }
    }
  }
  CHECK_EQ(failures, 0U);
}

TEST_CASE("A GP frame far longer than IFSD is read out completely before the NAK") {
  Bench b(Strict(true), Patient(TransportFlavour::Gp));
  REQUIRE(b.link.Open().ok());
  b.chip.SetFault(0U, b.chip.frames_out, Fault::Oversize);
  CHECK(Intact(b, Send(b, 5U), 5U, 1U));
  CHECK_EQ(b.link.GetCounters().naks_sent, 1U);
  CHECK(Clean(b)); // stretch_lock: a write over the unread rest would have stuck the bus
}

TEST_CASE("A block longer than the host's IFS is refused, as GPC_SPE_172 section 4.2.3 says") {
  T1Knobs k = Strict(true);
  k.ignore_ifsd = true; // the chip sends 200-byte blocks; the link's IFSD is 64
  Bench b(k, Patient(TransportFlavour::Gp));
  b.handler.answer_len = 150U;
  REQUIRE(b.link.Open().ok());
  const auto r = Send(b, 5U);
  CHECK(!r.ok());
  CHECK(b.link.GetCounters().naks_sent >= 1U);
  CHECK_EQ(r.value, 0U);
  CHECK(Clean(b));
  b.chip.Knobs().ignore_ifsd = false;
  if (b.link.State() == LinkState::Dead) {
    REQUIRE(b.link.Open().ok());
  }
  // The count is read before the call: the order in which arguments are evaluated is unspecified.
  const uint32_t before = b.handler.commands;
  const auto again = Send(b, 5U);
  CHECK(Intact(b, again, 5U, before + 1U));
}

TEST_CASE("Idle bytes while the chip works are polled, never taken for a frame") {
  T1Knobs k = Strict(false);
  k.idle_while_busy = true;
  k.process_us = 5000U;
  Bench b(k, Patient(TransportFlavour::Um11225));
  b.handler.answer_len = 100U;
  REQUIRE(b.link.Open().ok());
  CHECK(Intact(b, Send(b, 40U), 40U, 1U));
  CHECK_EQ(b.link.GetCounters().naks_sent, 0U);
  CHECK_EQ(b.link.GetCounters().crc_errors, 0U);
}

TEST_CASE("A read that returns fewer bytes than asked is a frame error, not data") {
  Bench b(Strict(false), Patient(TransportFlavour::Um11225));
  REQUIRE(b.link.Open().ok());
  b.chip.short_reads = 1U;
  CHECK(Intact(b, Send(b, 5U), 5U, 1U));
  CHECK_EQ(b.link.GetCounters().naks_sent, 1U);
  CHECK_EQ(b.link.GetCounters().crc_errors, 0U);
  CHECK(Clean(b));
}

TEST_CASE("A repeated chained block (a lost acknowledgement) is not taken twice") {
  for (const bool gp : {false, true}) {
    Bench b(Strict(gp), Patient(gp ? TransportFlavour::Gp : TransportFlavour::Um11225));
    b.handler.answer_len = 120U; // blocks of 32: four
    REQUIRE(b.link.Open().ok());
    b.chip.SetFault(0U, b.chip.frames_out + 1U, Fault::RepeatPrev); // the second block is the first
    CHECK(Intact(b, Send(b, 5U), 5U, 1U));
    CHECK(Clean(b));
  }
}

TEST_CASE("A reserved PCB bit with a valid CRC is refused and the block asked for again") {
  for (const bool gp : {false, true}) {
    for (uint32_t k = 0U; k < 3U; ++k) { // the R-ack, then the two answer blocks
      Bench b(Strict(gp), Patient(gp ? TransportFlavour::Gp : TransportFlavour::Um11225));
      b.handler.answer_len = 100U; // two answer blocks in both flavours (IFSD 32 or 64)
      REQUIRE(b.link.Open().ok());
      b.chip.SetFault(0U, b.chip.frames_out + k, Fault::CorruptPcb);
      CHECK(Intact(b, Send(b, 40U), 40U, 1U));
      CHECK_EQ(b.link.GetCounters().naks_sent, 1U);
    }
  }
}

TEST_CASE("A host block lost on the wire is sent again when the chip asks for it") {
  for (const bool gp : {false, true}) {
    for (uint32_t lost = 1U; lost <= 3U; ++lost) {
      Bench b(Strict(gp), Patient(gp ? TransportFlavour::Gp : TransportFlavour::Um11225));
      REQUIRE(b.link.Open().ok());
      b.chip.Knobs().lose_host_frame = b.chip.HostFrames() + lost; // a chained block or the last
      CHECK(Intact(b, Send(b, 80U), 80U, 1U));                     // 80 bytes: three blocks of 32
      CHECK_EQ(b.chip.host_frames_lost, 1U);
      CHECK(Clean(b));
    }
  }
}

TEST_CASE("No block wait runs past the command deadline") {
  T1Knobs k = Strict(false);
  k.bwt_ms = 700U;
  Config c = WithFlavour(TransportFlavour::Um11225);
  c.timeouts.fast_ms = 2000U;
  c.frame_retries = 10U;
  Bench b(k, c);
  REQUIRE(b.link.Open().ok());
  DropFromNow(b.chip);
  const uint64_t start = b.clock.now_us;
  CHECK_EQ(Send(b, 5U).error, Error::Timeout);
  CHECK((b.clock.now_us - start) <= 2020000U);
}

TEST_CASE("Slow bus reads still end each wait at its deadline") {
  T1Knobs k = Strict(false);
  k.silent_soft_reset = true;
  k.read_cost_us = 5000U; // every read takes 5 ms on the bus
  Config c = WithFlavour(TransportFlavour::Um11225);
  Bench b(k, c);
  CHECK_EQ(b.link.Open().error, Error::Timeout);
  CHECK(b.clock.now_us <=
        (static_cast<uint64_t>(c.boot_wait_ms + c.atr_poll_budget_ms + 30U) * 1000U));
}

TEST_CASE("The poll period is never below the chip's MPOT") {
  T1Knobs k = Strict(false);
  k.mpot_ms = 5U;
  k.answer_extra_us = 100000U; // 100 ms of NACKs
  Bench b(k, Patient(TransportFlavour::Um11225));
  REQUIRE(b.link.Open().ok());
  CHECK_EQ(b.link.Params().min_poll_us, 5000U);
  const uint32_t reads = b.chip.reads;
  CHECK(Intact(b, Send(b, 5U), 5U, 1U));
  CHECK((b.chip.reads - reads) <= 25U); // about 100 ms / 5 ms, not 100 ms / 1 ms
}

TEST_CASE("Auto gives the NXP probe half the budget: a GP chip silent to it still opens") {
  T1Knobs k = Strict(true);
  k.ignore_foreign_nad = true;
  k.process_us = 5000U; // slower than the settle time: an expired budget shows
  Bench b(k);
  const Config c{};
  REQUIRE(b.link.Open().ok());
  CHECK_EQ(b.link.Params().flavour, TransportFlavour::Gp);
  CHECK(b.chip.bad_frames >= 1U);
  // The NXP probe stopped at half the ATR budget: the GP handshake followed at once.
  const uint64_t half_us =
      (static_cast<uint64_t>(c.boot_wait_ms) + (c.atr_poll_budget_ms / 2U) + 100U) * 1000U;
  CHECK(b.clock.now_us <= half_us);
  // A GP chip that boots slowly: the NXP probe polls, the GP handshake follows, and the chip opens
  // well inside the budget.
  T1Knobs slow = k;
  slow.boot_us = 800000U; // NACKs for 800 ms of the 1000 ms budget
  Bench s(slow);
  REQUIRE(s.link.Open().ok());
  CHECK_EQ(s.link.Params().flavour, TransportFlavour::Gp);
  CHECK(s.clock.now_us < 950000U);
}

TEST_CASE("A block with a wrong NAD under a valid CRC is refused and asked for again") {
  for (const bool gp : {false, true}) {
    Bench b(Strict(gp), Patient(gp ? TransportFlavour::Gp : TransportFlavour::Um11225));
    REQUIRE(b.link.Open().ok());
    b.chip.SetFault(0U, b.chip.frames_out, Fault::BadNad);
    CHECK(Intact(b, Send(b, 5U), 5U, 1U));
    CHECK_EQ(b.link.GetCounters().naks_sent, 1U);
    CHECK(Clean(b));
  }
}

TEST_CASE("A bus that sticks during a lower rung skips straight to the power cycle") {
  Bench b(Strict(false), Patient(TransportFlavour::Um11225));
  REQUIRE(b.link.Open().ok());
  b.chip.SetFault(0U, b.chip.frames_out, Fault::StuckBus); // sticks on the RESYNC answer
  const uint32_t soft = b.chip.Sent(0xCFU);
  CHECK_EQ(b.link.Recover(Rung::Resync).error, Error::NeedsReselect);
  CHECK_EQ(b.link.GetCounters().recoveries, 2U); // RESYNC, then the power cycle
  CHECK_EQ(b.reset.cycles, 1U);
  CHECK_EQ(b.chip.Sent(0xC6U), 0U);
  CHECK_EQ(b.chip.Sent(0xCFU), soft + 1U); // only the handshake after the power cycle
}

TEST_CASE("A WTX multiplier of 0 is not a waiting time: refused, never answered") {
  T1Knobs k = Strict(false);
  k.wtx_before_answer = 1U;
  k.wtx_multiplier = 0U;
  Bench b(k, Patient(TransportFlavour::Um11225));
  REQUIRE(b.link.Open().ok());
  const auto r = Send(b, 5U);
  CHECK(!r.ok());
  CHECK_EQ(b.chip.wtx_answered, 0U);
  CHECK(b.link.GetCounters().naks_sent >= 1U);
}

TEST_CASE("After a chip reset or a power cycle the bus stays quiet while the chip boots") {
  T1Knobs k = Strict(false);
  k.boot_us = 5000U; // DPWT, UM11225 Table 14
  Bench b(k, Patient(TransportFlavour::Um11225));
  REQUIRE(b.link.Open().ok());
  const uint32_t before = b.chip.boot_accesses;
  CHECK(b.link.Reset(t1::ResetKind::Cold).ok());
  CHECK(b.link.Reset(t1::ResetKind::PowerCycle).ok());
  CHECK(b.link.Reset(t1::ResetKind::Reset).ok());
  CHECK_EQ(b.link.Recover(Rung::ChipReset).error, Error::NeedsReselect);
  CHECK_EQ(b.chip.boot_accesses, before);
  CHECK(Intact(b, Send(b, 5U), 5U, 1U));
}

TEST_CASE("Retry budget: frame_retries NAKs are sent, one more error climbs to RESYNC") {
  for (const uint8_t retries : {uint8_t{1U}, uint8_t{3U}, uint8_t{7U}}) {
    Config c = Patient(TransportFlavour::Um11225);
    c.frame_retries = retries;
    Bench ok(Strict(false), c);
    REQUIRE(ok.link.Open().ok());
    for (uint32_t i = 0U; i < retries; ++i) {
      ok.chip.SetFault(i, ok.chip.frames_out + i, Fault::CorruptCrc);
    }
    const auto r = Send(ok, 5U);
    CHECK(Intact(ok, r, 5U, 1U));
    CHECK_EQ(ok.link.GetCounters().naks_sent, static_cast<uint32_t>(retries));
    CHECK_EQ(ok.chip.Sent(static_cast<uint8_t>(0x81U)), static_cast<uint32_t>(retries)); // CRC NAK
    Bench over(Strict(false), c);
    REQUIRE(over.link.Open().ok());
    for (uint32_t i = 0U; i <= retries; ++i) {
      over.chip.SetFault(i, over.chip.frames_out + i, Fault::CorruptCrc);
    }
    const auto e = Send(over, 5U);
    CHECK_EQ(e.error, Error::Resynced);
    CHECK_EQ(e.value, 0U);
    CHECK_EQ(over.handler.commands, 1U); // never repeated by the link
    CHECK_EQ(over.link.GetCounters().resyncs, 1U);
    CHECK_EQ(over.link.GetCounters().last_rung, Rung::Resync);
    CHECK_EQ(e.detail.layer, Layer::T1);
    CHECK(Clean(over));
    CHECK(Intact(over, Send(over, 6U), 6U, 2U)); // the link works again
  }
}

TEST_CASE("The ladder climbs rung by rung: RESYNC, soft reset, chip reset, power cycle") {
  // RESYNC silent: the soft reset answers.
  Bench s(Strict(false), Patient(TransportFlavour::Um11225));
  REQUIRE(s.link.Open().ok());
  s.chip.Knobs().silent_resync = true;
  DropFromNow(s.chip, 4U); // the answer and its three resends
  CHECK_EQ(Send(s, 5U).error, Error::NeedsReselect);
  CHECK_EQ(s.link.State(), LinkState::NeedsReselect);
  CHECK_EQ(s.link.GetCounters().last_rung, Rung::InterfaceReset);
  CHECK_EQ(s.chip.soft_resets, 2U);
  CHECK(Clean(s));
  // Nothing answers, no reset port: Dead after RESYNC and the soft reset; the reselect rung is the
  // layer above's and is skipped.
  PlainBench d(Strict(false), Patient(TransportFlavour::Um11225));
  REQUIRE(d.link.Open().ok());
  Silence(d.chip);
  CHECK_EQ(Send(d, 5U).error, Error::TransportDead);
  CHECK_EQ(d.link.State(), LinkState::Dead);
  CHECK(d.chip.Sent(0xC0U) >= 1U);
  CHECK(d.chip.Sent(0xCFU) >= 2U);
  // Nothing answers, a reset port: the chip reset S-block, then the power cycle, then Dead.
  Bench f(Strict(false), Patient(TransportFlavour::Um11225));
  REQUIRE(f.link.Open().ok());
  Silence(f.chip);
  CHECK_EQ(Send(f, 5U).error, Error::TransportDead);
  CHECK(f.chip.Sent(0xC6U) >= 1U);
  CHECK_EQ(f.reset.cycles, 1U);
  CHECK_EQ(f.link.GetCounters().last_rung, Rung::PowerCycle);
  CHECK(Clean(f));
}

TEST_CASE("A stuck bus goes straight to the power cycle; without a reset port it is BusStuck") {
  Bench b(Strict(false), Patient(TransportFlavour::Um11225));
  REQUIRE(b.link.Open().ok());
  b.chip.SetFault(0U, b.chip.frames_out, Fault::StuckBus);
  const auto r = Send(b, 5U);
  CHECK_EQ(r.error, Error::NeedsReselect);
  CHECK_EQ(b.reset.cycles, 1U);
  CHECK_EQ(b.chip.Sent(0xC0U), 0U); // no rung below the power cycle was tried on a stuck bus
  CHECK_EQ(b.link.GetCounters().recoveries, 1U);
  CHECK_EQ(b.link.GetCounters().last_rung, Rung::PowerCycle);
  CHECK(Intact(b, Send(b, 5U), 5U, 2U));
  PlainBench p(Strict(false), Patient(TransportFlavour::Um11225));
  REQUIRE(p.link.Open().ok());
  p.chip.SetFault(0U, p.chip.frames_out, Fault::StuckBus);
  CHECK_EQ(Send(p, 5U).error, Error::BusStuck);
  CHECK_EQ(p.link.State(), LinkState::Dead);
  CHECK_EQ(Send(p, 5U).error, Error::TransportDead);
}

TEST_CASE(
    "Throughput limit, NXP flavour: SW 0x66A6 passes through, the chip reset rung clears it") {
  T1Knobs k = Strict(false);
  k.base.throttle_enabled = true;
  k.base.throttle_after = 3U;
  PlainBench b(k); // no reset port: the S-block does it
  REQUIRE(b.link.Open().ok());
  for (uint32_t i = 0U; i < 3U; ++i) {
    CHECK(Send(b, 5U).ok());
  }
  const auto limited = Send(b, 5U);
  REQUIRE(limited.ok()); // the link carries the status word; the APDU layer maps it
  CHECK_EQ(limited.value, 2U);
  CHECK_EQ(Resp()[0], 0x66U);
  CHECK_EQ(Resp()[1], 0xA6U);
  CHECK_EQ(b.link.Recover(Rung::ChipReset).error, Error::NeedsReselect);
  CHECK_EQ(b.chip.chip_resets, 1U);
  CHECK_EQ(b.handler.power_cycles, 1U); // the stages above lost their state
  const auto after = Send(b, 5U);
  CHECK(after.ok());
  CHECK(IsPatternAnswer(Resp(), after.value, 4U));
  CHECK_EQ(b.chip.throttled, 1U);
  CHECK(Clean(b));
}

TEST_CASE("Throughput limit, GP flavour: the reset port resets the chip; without one Dead") {
  T1Knobs k = Strict(true);
  k.base.throttle_enabled = true;
  k.base.throttle_after = 1U;
  Bench b(k);
  REQUIRE(b.link.Open().ok());
  CHECK(Send(b, 5U).ok());
  CHECK_EQ(Send(b, 5U).value, 2U);
  CHECK_EQ(Resp()[0], 0x66U);
  CHECK_EQ(b.link.Recover(Rung::ChipReset).error, Error::NeedsReselect);
  CHECK_EQ(b.reset.resets, 1U);
  CHECK_EQ(b.chip.Sent(0xC6U), 0U);
  CHECK(Intact(b, Send(b, 5U), 5U, 2U));
  PlainBench p(k);
  REQUIRE(p.link.Open().ok());
  CHECK(Send(p, 5U).ok());
  CHECK_EQ(p.link.Recover(Rung::ChipReset).error, Error::TransportDead);
  CHECK_EQ(p.chip.Sent(0xC6U), 0U);
}

TEST_CASE("A timeout leaves an unread answer: it is read out before the RESYNC (errata I2C.1)") {
  T1Knobs k = Strict(false);
  k.answer_extra_us = 3000000U; // the answer comes after the 2 s deadline
  Bench b(k, WithFlavour(TransportFlavour::Um11225));
  REQUIRE(b.link.Open().ok());
  CHECK_EQ(Send(b, 5U).error, Error::Timeout);
  b.clock.now_us += 2000000U; // the chip has its answer ready now, unread
  CHECK(!b.chip.Drained());
  b.chip.Knobs().answer_extra_us = 0U;
  const auto r = Send(b, 9U);
  CHECK(Intact(b, r, 9U, 2U));
  CHECK_EQ(b.chip.Sent(0xC0U), 1U);
  CHECK(Clean(b));
}

TEST_CASE("RESYNC after a broken chained answer, with a bad CRC of its own: nothing stale left") {
  // The middleware once kept an answer in an uninitialised buffer after RESYNC and a CRC error
  // (AN13030 p. 23); here the partial answer is wiped and the call returns no length.
  Config c = Patient(TransportFlavour::Um11225);
  Bench b(Strict(false), c);
  b.handler.answer_len = 300U;
  REQUIRE(b.link.Open().ok());
  // Answer blocks of 32: frames 0 and 1 arrive, frames 2 to 5 (and their resends) are corrupt,
  // the first RESYNC answer (frame 6) is corrupt too.
  for (uint32_t i = 0U; i < 5U; ++i) {
    b.chip.SetFault(i, b.chip.frames_out + 2U + i, Fault::CorruptCrc);
  }
  const auto r = Send(b, 5U, 0xA5U);
  CHECK_EQ(r.error, Error::Resynced);
  CHECK_EQ(r.value, 0U);
  bool wiped = true;
  for (std::size_t i = 0U; i < 64U; ++i) {
    wiped = wiped && (Resp()[i] == 0U);
  }
  CHECK(wiped);
  CHECK_EQ(Resp()[64], 0xA5U); // nothing written past what had arrived
  CHECK_EQ(b.link.GetCounters().resyncs, 1U);
  CHECK(Intact(b, Send(b, 5U), 5U, 2U));
  CHECK(Clean(b));
}

TEST_CASE("A RESYNC that fails before the next command: the command is not sent") {
  T1Knobs k = Strict(false);
  k.wtx_before_answer = 3U;
  Config c = WithFlavour(TransportFlavour::Um11225);
  c.wtx_limit = 1U;
  Bench b(k, c);
  REQUIRE(b.link.Open().ok());
  CHECK_EQ(Send(b, 5U).error, Error::Timeout);
  b.chip.Knobs().silent_resync = true;
  b.chip.Knobs().wtx_before_answer = 0U;
  const uint32_t commands = b.handler.commands;
  CHECK_EQ(Send(b, 5U).error, Error::NeedsReselect); // RESYNC silent, the soft reset answered
  CHECK_EQ(b.handler.commands, commands);
  CHECK_EQ(b.link.State(), LinkState::NeedsReselect);
}

TEST_CASE("Transient bus errors are retried; the log gets records without payload") {
  Bench b(Strict(false), Patient(TransportFlavour::Um11225));
  REQUIRE(b.link.Open().ok());
  b.chip.bus_errors = 2U;
  CHECK(Intact(b, Send(b, 5U), 5U, 1U));
  b.chip.bus_errors = 1000000U; // a bus that never works again: bounded, then Dead
  const auto r = Send(b, 5U);
  CHECK_EQ(r.error, Error::TransportDead);
  CHECK_EQ(r.value, 0U);
  CHECK_EQ(b.link.GetCounters().last_rung, Rung::PowerCycle);
  b.chip.bus_errors = 0U;
  CHECK(b.link.Open().ok());
  CHECK_EQ(b.log.last.layer, Layer::T1);
  CHECK_EQ(b.log.last.length, 0U);
  CHECK(b.log.last.text != nullptr);
  CHECK(Clean(b));
  CHECK(Send(b, 5U).ok());
}

TEST_CASE("Random faults over many commands keep every invariant") {
  uint32_t seed = 12345U;
  const auto next = [&seed]() {
    seed = (seed * 1103515245U) + 12345U;
    return (seed >> 16U) & 0x7FFFU;
  };
  constexpr std::array<Fault, 7> kFaults{Fault::CorruptCrc, Fault::BadNad, Fault::OverlongLen,
                                         Fault::CorruptPcb, Fault::Drop,   Fault::AllIdle,
                                         Fault::ShortLen};
  uint32_t broken = 0U;
  uint32_t ok = 0U;
  for (const bool gp : {false, true}) {
    Bench b(Strict(gp), Patient());
    b.handler.answer_len = 120U;
    REQUIRE(b.link.Open().ok());
    for (uint32_t i = 0U; i < 60U; ++i) {
      for (uint32_t slot = 0U; slot < 3U; ++slot) {
        b.chip.SetFault(slot, b.chip.frames_out + (next() % 12U), kFaults[next() % 7U]);
      }
      const std::size_t n = 1U + (next() % 200U);
      const auto r = Send(b, n, 0xA5U);
      if (r.ok()) {
        ok += IsPatternAnswer(Resp(), r.value, 120U) ? 1U : 0U;
        broken += IsPatternAnswer(Resp(), r.value, 120U) ? 0U : 1U;
      } else {
        broken += ((r.value == 0U) && (Resp()[0] != PatternHandler::Byte(0U))) ? 0U : 1U;
        if (b.link.State() == LinkState::Dead) {
          broken += b.link.Open().ok() ? 0U : 1U;
        }
      }
      broken += Clean(b) ? 0U : 1U;
    }
  }
  CHECK_EQ(broken, 0U);
  CHECK(ok > 60U);
}

} // namespace
