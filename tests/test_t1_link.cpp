/**
 * @file test_t1_link.cpp
 * @brief The T=1 link against the independent model: start-up in both flavours, commands, waiting
 * time extensions, close, deep power-down, resets and the ladder entry points.
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
using t1::ResetKind;
using t1::Rung;

std::array<uint8_t, 1200>& Resp() {
  static std::array<uint8_t, 1200> buffer{};
  return buffer;
}

/** @brief A command of `n` bytes: 0, 1, 2, ... */
std::array<uint8_t, 1200> Command() {
  std::array<uint8_t, 1200> c{};
  for (std::size_t i = 0U; i < c.size(); ++i) {
    c[i] = static_cast<uint8_t>((i * 13U) + 1U);
  }
  return c;
}
const std::array<uint8_t, 1200> kCmd = Command();

template <typename B>
Result<std::size_t> Send(B& b, std::size_t n, CommandClass cls = CommandClass::Fast) {
  Resp().fill(0U);
  return b.link.Transceive(ByteSpan{kCmd}.first(n), MutableByteSpan{Resp()}, cls);
}

template <typename B>
bool GotCommand(const B& b, std::size_t n) {
  if (b.handler.last_len != n) {
    return false;
  }
  for (std::size_t i = 0U; i < n; ++i) {
    if (b.handler.last[i] != kCmd[i]) {
      return false;
    }
  }
  return true;
}

/** @brief A clock that never moves: every wait must still end (S-05). */
class FrozenClock : public ClockInterface<FrozenClock> {
public:
  uint64_t NowUs() noexcept {
    return 42U;
  }
  void DelayUs(uint32_t us) noexcept {
    static_cast<void>(us);
  }
};

/** @brief What a re-entrant port calls while the link is in flight. */
class Reenter {
public:
  Reenter() = default;
  Reenter(const Reenter&) = delete;
  Reenter& operator=(const Reenter&) = delete;
  virtual ~Reenter() = default;
  virtual void Call() = 0;
};

/** @brief A bus that forwards to the model and calls back into the link during one write. */
class ReentrantBus : public BusInterface<ReentrantBus> {
public:
  explicit ReentrantBus(T1Target& chip) noexcept : chip_(chip) {}
  [[nodiscard]] bool EnsureInitialized() const noexcept {
    return true;
  }
  BusStatus Write(uint8_t addr7, ByteSpan data) noexcept {
    if (hook != nullptr) {
      Reenter* h = hook;
      hook = nullptr;
      h->Call();
    }
    return chip_.Write(addr7, data);
  }
  BusRead Read(uint8_t addr7, MutableByteSpan out) noexcept {
    return chip_.Read(addr7, out);
  }
  Reenter* hook{nullptr};

private:
  T1Target& chip_;
};

using ReentrantPorts = Ports<ReentrantBus, SimClock, NoCrypto>;

/** @brief Calls every public I/O member of the link from inside a bus write. */
class CallAll : public Reenter {
public:
  explicit CallAll(t1::Link<ReentrantPorts>& link) noexcept : link_(link) {}
  void Call() override {
    std::array<uint8_t, 8> resp{};
    busy = 0U;
    busy += (link_.Transceive(ByteSpan{kCmd}.first(5U), resp).error == Error::Busy) ? 1U : 0U;
    busy += (link_.Open().error == Error::Busy) ? 1U : 0U;
    busy += (link_.Close().error == Error::Busy) ? 1U : 0U;
    busy += (link_.DeepPowerDown().error == Error::Busy) ? 1U : 0U;
    busy += (link_.Reset(ResetKind::Interface).error == Error::Busy) ? 1U : 0U;
    busy += (link_.Recover(Rung::Resync).error == Error::Busy) ? 1U : 0U;
    in_flight = link_.State() == LinkState::InFlight;
  }
  uint32_t busy{0};
  bool in_flight{false};

private:
  t1::Link<ReentrantPorts>& link_;
};

// --- Open ------------------------------------------------------------------------------------

TEST_CASE("Single flight: every call made while a transfer is in progress is Busy") {
  SimClock clock;
  PatternHandler handler;
  T1Target chip(clock, &handler, Knobs());
  ReentrantBus bus(chip);
  NoCrypto crypto;
  const ReentrantPorts ports(bus, clock, crypto);
  t1::Link<ReentrantPorts> link(ports, WithFlavour(TransportFlavour::Um11225));
  REQUIRE(link.Open().ok());
  CallAll all(link);
  bus.hook = &all;
  const uint32_t writes = chip.writes;
  std::array<uint8_t, 64> resp{};
  const auto r = link.Transceive(ByteSpan{kCmd}.first(5U), resp);
  CHECK(r.ok());
  CHECK_EQ(all.busy, 6U);
  CHECK(all.in_flight);
  CHECK_EQ(chip.writes, writes + 1U); // the nested calls wrote nothing
  CHECK_EQ(chip.i2c1_violations, 0U);
  CHECK_EQ(link.State(), LinkState::Idle);
}

TEST_CASE("Open in Auto finds the NXP flavour after the GP probe and reads the ATR") {
  T1Knobs k = Knobs(false);
  k.ifsc = 200U;
  k.bwt_ms = 700U;
  k.stretch_lock = true; // a write over an unread answer would stick the bus
  Bench b(k);
  CHECK_EQ(b.link.State(), LinkState::Closed);
  REQUIRE(b.link.Open().ok());
  CHECK_EQ(b.link.State(), LinkState::Idle);
  CHECK_EQ(b.link.Params().flavour, TransportFlavour::Um11225);
  CHECK_EQ(b.link.Params().ifsc, 200U);
  CHECK_EQ(b.link.Params().ifsd, 200U);
  CHECK_EQ(b.link.Params().bwt_ms, 700U);
  CHECK_EQ(b.chip.soft_resets, 1U);
  CHECK_EQ(b.chip.i2c1_violations, 0U);
  CHECK_EQ(b.chip.empty_writes, 0U);
  CHECK_EQ(b.reset.enables, 1U); // ENA driven high before the boot wait
  CHECK(b.log.records > 0U);
}

TEST_CASE("Open in Auto finds the GP flavour and reads the CIP") {
  T1Knobs k = Knobs(true);
  k.bwt_ms = 450U;
  k.ifsc = 100U;
  Bench b(k);
  REQUIRE(b.link.Open().ok());
  CHECK_EQ(b.link.Params().flavour, TransportFlavour::Gp);
  CHECK_EQ(b.link.Params().bwt_ms, 450U);
  CHECK_EQ(b.link.Params().ifsc, 100U);
  CHECK_EQ(b.link.Params().ifsd, 64U);
  CHECK_EQ(b.chip.Sent(0xC4U), 1U); // one CIP request
  CHECK_EQ(b.chip.bad_frames, 1U);  // the NXP probe; the GP answer to it decides the flavour
  CHECK_EQ(b.link.GetCounters().frames_sent, 3U);
}

TEST_CASE("The guard time is at least the default SEGT when the ATR gives less") {
  T1Knobs k = Knobs(false);
  k.segt_us = 0U;
  k.min_gap_us = 10U; // DSEGT (UM11225 Table 14)
  Bench b(k, WithFlavour(TransportFlavour::Um11225));
  REQUIRE(b.link.Open().ok());
  CHECK_EQ(b.link.Params().guard_us, 0U);
  CHECK(Send(b, 40U).ok());
  CHECK(Send(b, 300U).ok());
  CHECK_EQ(b.chip.guard_violations, 0U);
}

TEST_CASE("No guard wait after a NACKed probe: the answer that arrives meanwhile is read first") {
  // Errata I2C.1: a command left unanswered by a timeout; the next write probes first. The probe
  // is NACKed (the chip still works), and the chip finishes within the guard time: a wait there
  // would put the write over the new answer.
  T1Knobs k = Knobs(false);
  k.stretch_lock = true;
  Config c = WithFlavour(TransportFlavour::Um11225);
  c.timeouts.fast_ms = 2000U;
  Bench b(k, c);
  REQUIRE(b.link.Open().ok());
  b.chip.Knobs().process_us = 2500000U; // longer than the 2 s class deadline, no WTX
  CHECK(!Send(b, 5U).ok());
  REQUIRE(b.chip.ReadyAt() > b.clock.now_us);
  b.clock.now_us = b.chip.ReadyAt() - 20U; // ready within the 100 us guard of the next access
  static_cast<void>(Send(b, 5U));
  CHECK_EQ(b.chip.i2c1_violations, 0U);
}

TEST_CASE("The guard time holds between every two accesses, writes after reads included") {
  for (const bool gp : {false, true}) {
    T1Knobs k = Knobs(gp);
    k.min_gap_us = 10U; // the default SEGT before the ATR (UM11225 Table 14)
    Bench b(k, WithFlavour(gp ? TransportFlavour::Gp : TransportFlavour::Um11225));
    REQUIRE(b.link.Open().ok());
    CHECK_EQ(b.chip.guard_violations, 0U);
    b.chip.Knobs().min_gap_us = b.link.Params().guard_us; // the guard time the ATR or CIP gave
    REQUIRE(b.link.Params().guard_us >= 10U);
    for (uint8_t n = 1U; n <= 3U; ++n) {
      CHECK(Send(b, static_cast<std::size_t>(n) * 40U).ok());
    }
    CHECK_EQ(b.chip.guard_violations, 0U);
  }
}

TEST_CASE("The GP flavour accepts a chip that answers with NAD 0xA5 (A17)") {
  T1Knobs k = Knobs(true);
  k.gp_nad_a5 = true;
  Bench fixed(k, WithFlavour(TransportFlavour::Gp));
  REQUIRE(fixed.link.Open().ok());
  CHECK_EQ(fixed.link.Params().flavour, TransportFlavour::Gp);
  CHECK(Send(fixed, 5U).ok());
  Bench automatic(k);
  REQUIRE(automatic.link.Open().ok());
  CHECK_EQ(automatic.link.Params().flavour, TransportFlavour::Gp);
  CHECK(Send(automatic, 5U).ok());
}

TEST_CASE("An explicit flavour opens with its own handshake only") {
  Bench nxp(Knobs(false), WithFlavour(TransportFlavour::Um11225));
  REQUIRE(nxp.link.Open().ok());
  CHECK_EQ(nxp.link.GetCounters().frames_sent, 1U);
  CHECK_EQ(nxp.chip.bad_frames, 0U);
  Bench gp(Knobs(true), WithFlavour(TransportFlavour::Gp));
  REQUIRE(gp.link.Open().ok());
  CHECK_EQ(gp.link.GetCounters().frames_sent, 2U);
  // The wrong explicit flavour does not open.
  Bench wrong(Knobs(true), WithFlavour(TransportFlavour::Um11225));
  CHECK(!wrong.link.Open().ok());
  CHECK_EQ(wrong.link.State(), LinkState::Closed);
  CHECK_EQ(Send(wrong, 5U).error, Error::NotInitialized);
}

TEST_CASE("NXP CRC order: either order opens, then the other order is refused (A10)") {
  T1Knobs k = Knobs(false);
  k.base.crc_swapped = true; // MSB first
  Bench b(k, WithFlavour(TransportFlavour::Um11225));
  REQUIRE(b.link.Open().ok());
  const auto r = Send(b, 5U);
  CHECK(r.ok());
  CHECK(IsPatternAnswer(Resp(), r.value, b.handler.answer_len));
  CHECK(b.chip.bad_frames <= 1U); // at most the first frame, sent before the order was known
  // The chip now answers least significant byte first: the link keeps the order it fixed.
  b.chip.Knobs().base.crc_swapped = false;
  const uint32_t crc_before = b.link.GetCounters().crc_errors;
  CHECK(!Send(b, 5U).ok());
  CHECK(b.link.GetCounters().crc_errors > crc_before);
}

TEST_CASE("The GP flavour accepts the CRC most significant byte first only") {
  T1Knobs k = Knobs(true);
  k.base.crc_swapped = true;
  Bench b(k, WithFlavour(TransportFlavour::Gp));
  const auto r = b.link.Open();
  CHECK_EQ(r.error, Error::Crc);
  CHECK_EQ(b.link.State(), LinkState::Closed);
}

TEST_CASE("Open with a bad configuration or a failing bus port sends nothing") {
  Config c{};
  c.frame_retries = 0U;
  Bench b(Knobs(), c);
  CHECK_EQ(b.link.Open().error, Error::InvalidArgument);
  CHECK_EQ(b.chip.writes + b.chip.reads, 0U);
  c = Config{};
  c.wtx_limit = 0U;
  Bench w(Knobs(), c);
  CHECK_EQ(w.link.Open().error, Error::InvalidArgument);
  CHECK_EQ(w.chip.writes, 0U);
  Bench p(Knobs());
  p.chip.init_ok = false;
  CHECK_EQ(p.link.Open().error, Error::Bus);
  CHECK_EQ(p.chip.writes + p.chip.reads, 0U);
  CHECK_EQ(p.link.State(), LinkState::Closed);
}

TEST_CASE("No chip at the address: Nack within the budget; a frozen clock still ends") {
  Config c{};
  c.i2c_address = 0x49U;
  Bench b(Knobs(), c);
  CHECK_EQ(b.link.Open().error, Error::Nack);
  CHECK(b.clock.now_us <=
        (static_cast<uint64_t>(c.boot_wait_ms + c.atr_poll_budget_ms + 50U) * 1000U));
  CHECK_EQ(b.link.State(), LinkState::Closed);
  // The same with a clock that never advances: bounded by the iteration cap.
  SimClock unused;
  T1Target chip(unused, nullptr, Knobs());
  FrozenClock frozen;
  NoCrypto crypto;
  using P = Ports<T1Target, FrozenClock, NoCrypto>;
  const P ports(chip, frozen, crypto);
  t1::Link<P> link(ports, c);
  CHECK_EQ(link.Open().error, Error::Nack);
  CHECK(chip.writes < 20000U);
}

TEST_CASE("A chip that NACKs while it boots is polled until it answers") {
  T1Knobs k = Knobs(false);
  k.boot_us = 300000U; // 300 ms, longer than the boot wait
  Config c = WithFlavour(TransportFlavour::Um11225);
  c.boot_wait_ms = 0U;
  Bench b(k, c);
  REQUIRE(b.link.Open().ok());
  CHECK(b.clock.now_us >= 300000U);
}

TEST_CASE("A chip that never answers the handshake: Timeout, closed, bounded") {
  T1Knobs k = Knobs(false);
  k.silent_soft_reset = true;
  Config c = WithFlavour(TransportFlavour::Um11225);
  c.atr_poll_budget_ms = 8000U; // room for every retry at a BWT of 1 s
  Bench b(k, c);
  CHECK_EQ(b.link.Open().error, Error::Timeout);
  CHECK_EQ(b.link.State(), LinkState::Closed);
  CHECK(b.clock.now_us <= (static_cast<uint64_t>(c.boot_wait_ms + c.atr_poll_budget_ms) * 1000U));
  // The request went out once and was repeated frame_retries (3) times.
  CHECK_EQ(b.chip.Sent(0xCFU), 4U);
}

TEST_CASE("Open reads out an earlier host's answer and answers its WTX first (errata I2C.1)") {
  T1Knobs k = Knobs(false);
  k.stale_wtx = 5U;
  k.stretch_lock = true;
  Bench b(k);
  REQUIRE(b.link.Open().ok());
  CHECK_EQ(b.chip.wtx_answered, 5U);
  CHECK_EQ(b.chip.i2c1_violations, 0U);
  CHECK(Send(b, 5U).ok());
  // A stale frame of the GP flavour decides Auto at once: no NXP attempt.
  T1Knobs g = Knobs(true);
  g.stale_answer = true;
  g.stretch_lock = true;
  Bench gp(g);
  REQUIRE(gp.link.Open().ok());
  CHECK_EQ(gp.link.Params().flavour, TransportFlavour::Gp);
  CHECK_EQ(gp.chip.bad_frames, 0U);
  CHECK_EQ(gp.chip.i2c1_violations, 0U);
  // Stale WTX requests of the GP flavour while Auto starts in the NXP form: answered in GP.
  T1Knobs gw = Knobs(true);
  gw.stale_wtx = 3U;
  gw.stretch_lock = true;
  Bench gpw(gw);
  REQUIRE(gpw.link.Open().ok());
  CHECK_EQ(gpw.chip.wtx_answered, 3U);
  CHECK_EQ(gpw.link.Params().flavour, TransportFlavour::Gp);
  // A stale NXP answer: Auto opens in the NXP flavour without trying the GP probe.
  T1Knobs ns = Knobs(false);
  ns.stale_answer = true;
  Bench nxp(ns);
  REQUIRE(nxp.link.Open().ok());
  CHECK_EQ(nxp.chip.bad_frames, 0U);
  CHECK_EQ(nxp.link.GetCounters().frames_sent, 1U);
  // A stale answer whose LEN is wrong (bad CRC, unknown length) is read out before the first write.
  T1Knobs s = Knobs(false);
  s.stale_answer = true;
  s.stretch_lock = true;
  s.faults[0] = FaultAt{0U, Fault::ShortLen};
  Bench bad(s);
  REQUIRE(bad.link.Open().ok());
  CHECK_EQ(bad.chip.i2c1_violations, 0U);
  CHECK(Send(bad, 5U).ok());
}

TEST_CASE("Open from Dead and from an open link starts again") {
  Bench b(Knobs());
  REQUIRE(b.link.Open().ok());
  REQUIRE(b.link.Open().ok());
  CHECK_EQ(b.chip.soft_resets, 2U);
  CHECK_EQ(b.link.State(), LinkState::Idle);
}

// --- Transceive ------------------------------------------------------------------------------

TEST_CASE("A short command and answer in both flavours") {
  for (const bool gp : {false, true}) {
    Bench b(Knobs(gp));
    REQUIRE(b.link.Open().ok());
    const auto r = Send(b, 5U);
    REQUIRE(r.ok());
    CHECK(IsPatternAnswer(Resp(), r.value, 4U));
    CHECK(GotCommand(b, 5U));
    CHECK_EQ(b.link.State(), LinkState::Idle);
    CHECK_EQ(b.link.GetCounters().naks_sent, 0U);
    CHECK(b.chip.BuffersWithin(&b.link, sizeof(b.link))); // RD-06: member buffers only
  }
}

TEST_CASE("Chained commands and answers in both flavours, many in a row") {
  for (const bool gp : {false, true}) {
    T1Knobs k = Knobs(gp);
    k.ifsc = 32U; // many blocks
    Bench b(k);
    b.handler.answer_len = 900U;
    REQUIRE(b.link.Open().ok());
    const uint32_t bad = b.chip.bad_frames; // the GP probe of Auto, on an NXP chip
    bool all = true;
    for (std::size_t n : {1U, 31U, 32U, 33U, 64U, 65U, 600U, 1024U}) {
      const auto r = Send(b, n);
      all = all && r.ok() && IsPatternAnswer(Resp(), r.value, 900U) && GotCommand(b, n);
    }
    CHECK(all);
    CHECK_EQ(b.chip.bad_frames, bad);
    CHECK_EQ(b.chip.i2c1_violations, 0U);
    CHECK_EQ(b.link.GetCounters().naks_sent, 0U);
  }
}

TEST_CASE("Arguments: empty, oversized, a bad class or a short buffer send nothing") {
  Bench b(Knobs());
  REQUIRE(b.link.Open().ok());
  const uint32_t writes = b.chip.writes;
  const uint32_t reads = b.chip.reads;
  CHECK_EQ(Send(b, 0U).error, Error::InvalidArgument);
  CHECK_EQ(Send(b, kMaxCommandApdu + 1U).error, Error::InvalidArgument);
  CHECK_EQ(Send(b, 5U, std::bit_cast<CommandClass>(uint8_t{4U})).error, Error::InvalidArgument);
  std::array<uint8_t, 1> tiny{};
  CHECK_EQ(b.link.Transceive(ByteSpan{kCmd}.first(5U), tiny).error, Error::BufferTooSmall);
  CHECK_EQ(b.chip.writes, writes);
  CHECK_EQ(b.chip.reads, reads);
  CHECK(Send(b, kMaxCommandApdu).ok());
  std::array<uint8_t, 2> two{};
  b.handler.answer_len = 0U;
  CHECK(b.link.Transceive(ByteSpan{kCmd}.first(5U), two).ok());
}

TEST_CASE("Before Open and after Close every command call returns NotInitialized, silently") {
  Bench b(Knobs());
  CHECK_EQ(Send(b, 5U).error, Error::NotInitialized);
  CHECK_EQ(b.link.Reset(ResetKind::Interface).error, Error::NotInitialized);
  CHECK_EQ(b.link.Recover(Rung::Resync).error, Error::NotInitialized);
  CHECK_EQ(b.link.DeepPowerDown().error, Error::NotInitialized);
  CHECK_EQ(b.chip.writes + b.chip.reads, 0U);
  CHECK(b.link.Close().ok()); // closing a closed link is a no-op
  CHECK_EQ(b.chip.writes, 0U);
  REQUIRE(b.link.Open().ok());
  REQUIRE(b.link.Close().ok());
  const uint32_t writes = b.chip.writes;
  CHECK_EQ(Send(b, 5U).error, Error::NotInitialized);
  CHECK_EQ(b.chip.writes, writes);
}

TEST_CASE("An answer bigger than the buffer: BufferTooSmall, zeroed, and the link stays in step") {
  Bench b(Knobs());
  b.handler.answer_len = 600U;
  REQUIRE(b.link.Open().ok());
  std::array<uint8_t, 300> small{};
  small.fill(0xA5U);
  const auto r = b.link.Transceive(ByteSpan{kCmd}.first(5U), small);
  CHECK_EQ(r.error, Error::BufferTooSmall);
  CHECK_EQ(r.value, 0U);
  bool clean = true;
  for (std::size_t i = 0U; i < 254U; ++i) {
    clean = clean && (small[i] == 0U); // the first block was copied, then wiped
  }
  CHECK(clean);
  CHECK_EQ(small[299], 0xA5U);
  CHECK_EQ(b.link.State(), LinkState::Idle);
  CHECK_EQ(b.link.GetCounters().recoveries, 0U);
  const auto again = Send(b, 5U);
  CHECK(again.ok());
  CHECK(IsPatternAnswer(Resp(), again.value, 600U));
}

TEST_CASE("Answers over 1024 bytes and under 2 bytes are refused") {
  Bench b(Knobs());
  b.handler.answer_len = 1023U; // 1025 bytes with the status word
  REQUIRE(b.link.Open().ok());
  const auto big = Send(b, 5U);
  CHECK_EQ(big.error, Error::Resynced);
  CHECK_EQ(big.value, 0U);
  bool clean = true;
  for (const uint8_t v : Resp()) {
    clean = clean && (v == 0U);
  }
  CHECK(clean);
  b.handler.answer_len = 1022U; // exactly 1024
  CHECK(Send(b, 5U).ok());
  b.handler.only_len = 1U;
  const uint32_t recoveries = b.link.GetCounters().recoveries;
  CHECK_EQ(Send(b, 5U).error, Error::FrameError);
  CHECK_EQ(b.link.GetCounters().recoveries, recoveries); // the link itself is in step
  CHECK_EQ(Resp()[0], 0U);
}

TEST_CASE("WTX requests are answered with the same INF and counted") {
  for (const bool gp : {false, true}) {
    T1Knobs k = Knobs(gp);
    k.wtx_before_answer = 3U;
    k.wtx_multiplier = 2U;
    Bench b(k);
    REQUIRE(b.link.Open().ok());
    const auto r = Send(b, 5U);
    CHECK(r.ok());
    CHECK(IsPatternAnswer(Resp(), r.value, 4U));
    CHECK_EQ(b.chip.wtx_answered, 3U);
    CHECK_EQ(b.link.GetCounters().wtx_received, 3U);
    CHECK_EQ(b.link.GetCounters().naks_sent, 0U);
  }
}

TEST_CASE("After a WTX the link waits the multiplier times BWT, and at least 4 s") {
  T1Knobs k = Knobs(false);
  k.wtx_before_answer = 1U;
  k.wtx_multiplier = 1U;
  k.answer_extra_us = 3800000U; // 3.8 s after the WTX response; BWT is 1 s
  Config c{};
  c.timeouts.fast_ms = 20000U;
  Bench b(k, c);
  REQUIRE(b.link.Open().ok());
  CHECK(Send(b, 5U).ok());
  CHECK_EQ(b.link.GetCounters().naks_sent, 0U);
  // Multiplier 6: 6 s, beyond the 4 s floor.
  T1Knobs m = k;
  m.wtx_multiplier = 6U;
  m.answer_extra_us = 5800000U;
  Bench b6(m, c);
  REQUIRE(b6.link.Open().ok());
  CHECK(Send(b6, 5U).ok());
  CHECK_EQ(b6.link.GetCounters().naks_sent, 0U);
}

TEST_CASE("WTX budget: over wtx_limit is Timeout, and the next command resynchronises first") {
  T1Knobs k = Knobs(false);
  k.wtx_before_answer = 3U;
  Config c{};
  c.wtx_limit = 2U;
  Bench b(k, c);
  REQUIRE(b.link.Open().ok());
  CHECK_EQ(Send(b, 5U).error, Error::Timeout);
  CHECK_EQ(b.link.State(), LinkState::Idle);
  CHECK_EQ(b.chip.Sent(0xC0U), 0U);
  b.chip.Knobs().wtx_before_answer = 0U;
  const auto r = Send(b, 7U);
  CHECK(r.ok());
  CHECK(GotCommand(b, 7U));
  CHECK_EQ(b.chip.Sent(0xC0U), 1U); // RESYNC before the command
  CHECK_EQ(b.chip.i2c1_violations, 0U);
}

TEST_CASE("A WTX extends a 2 s class deadline: WTX every second for 3 s, then the answer") {
  T1Knobs k = Knobs(false);
  k.wtx_before_answer = 3U;
  k.process_us = 1000000U; // one WTX every second (AN13904 8.3 p. 27: SE052F)
  Config c = WithFlavour(TransportFlavour::Um11225);
  c.timeouts.fast_ms = 2000U;
  Bench b(k, c);
  REQUIRE(b.link.Open().ok());
  const uint64_t start = b.clock.now_us;
  CHECK(Send(b, 5U).ok());
  CHECK((b.clock.now_us - start) >= 3000000U);
  CHECK_EQ(b.chip.wtx_answered, 3U);
}

TEST_CASE("After a WTX past the class deadline every block of a chained answer is still read") {
  T1Knobs k = Knobs(false);
  k.wtx_before_answer = 3U;
  k.process_us = 1000000U;
  Config c = WithFlavour(TransportFlavour::Um11225);
  c.timeouts.fast_ms = 2000U;
  Bench b(k, c);
  b.handler.answer_len = 600U; // three blocks after the WTX: each needs the extended deadline
  REQUIRE(b.link.Open().ok());
  const auto r = Send(b, 5U);
  REQUIRE(r.ok());
  CHECK(IsPatternAnswer(Resp(), r.value, 600U));
  CHECK_EQ(b.chip.wtx_answered, 3U);
}

TEST_CASE("One WTX grants at most 30 s, and the WTX of one command at most 180 s in all") {
  T1Knobs k = Knobs(false);
  k.wtx_before_answer = 1U;
  k.wtx_multiplier = 255U; // 255 x BWT 1 s asked
  Bench b(k, WithFlavour(TransportFlavour::Um11225));
  REQUIRE(b.link.Open().ok());
  b.chip.Knobs().process_us = 1000000U;       // the WTX request after 1 s
  b.chip.Knobs().answer_extra_us = 40000000U; // then the answer 40 s later
  const uint64_t start = b.clock.now_us;
  CHECK(!Send(b, 5U).ok());
  CHECK((b.clock.now_us - start) < 41000000U); // gave up at the 30 s cap
  CHECK_EQ(b.chip.wtx_answered, 1U);

  T1Knobs many = Knobs(false);
  many.wtx_before_answer = 20U;
  many.wtx_multiplier = 255U; // each grants the 30 s cap
  Bench s(many, WithFlavour(TransportFlavour::Um11225));
  REQUIRE(s.link.Open().ok());
  s.chip.Knobs().process_us = 1000000U;
  CHECK(!Send(s, 5U).ok());
  CHECK_EQ(s.chip.wtx_answered, 6U); // 6 x 30 s = 180 s; the seventh is not answered

  // The 180 s are per command: two commands that each need 5 WTX of 30 s both complete.
  T1Knobs five = Knobs(false);
  five.wtx_before_answer = 5U;
  five.wtx_multiplier = 255U;
  Bench two(five, WithFlavour(TransportFlavour::Um11225));
  REQUIRE(two.link.Open().ok());
  two.chip.Knobs().process_us = 1000000U;
  CHECK(Send(two, 5U).ok());
  CHECK(Send(two, 5U).ok());
  CHECK_EQ(two.chip.wtx_answered, 10U);
}

// The total cap is the 40 WTX of 4 s a session open may need, plus 20 s.
static_assert(t1::detail::kMaxWtxTotalMs ==
              ((static_cast<uint32_t>(kSessionOpenWtxAllowance) * wire::kMinWtxHostTimeoutMs) +
               20000U));
static_assert(t1::detail::kMaxWtxWaitMs == 30000U);

TEST_CASE("The WTX limit bounds a WTX storm") {
  T1Knobs k = Knobs(false);
  k.wtx_before_answer = 250U;
  k.process_us = 100000U; // one WTX every 100 ms
  Config c = WithFlavour(TransportFlavour::Um11225);
  c.wtx_limit = 10U;
  c.timeouts.fast_ms = 2000U;
  Bench b(k, c);
  REQUIRE(b.link.Open().ok());
  const uint64_t start = b.clock.now_us;
  CHECK_EQ(Send(b, 5U).error, Error::Timeout);
  CHECK((b.clock.now_us - start) <= 2100000U);
  CHECK_EQ(b.chip.wtx_answered, 10U);
}

TEST_CASE("The chip's IFS request is answered and the new size is used") {
  T1Knobs k = Knobs(false);
  k.ifs_request = 32U;
  Bench b(k);
  b.handler.answer_len = 100U;
  REQUIRE(b.link.Open().ok());
  const uint32_t bad = b.chip.bad_frames;
  const auto r = Send(b, 5U);
  REQUIRE(r.ok());
  CHECK(IsPatternAnswer(Resp(), r.value, 100U));
  CHECK_EQ(b.chip.ifs_answered, 1U);
  CHECK_EQ(b.link.Params().ifsc, 32U);
  CHECK_EQ(b.link.Params().ifsd, 32U);
  const auto chained = Send(b, 100U); // 100 bytes in blocks of at most 32
  CHECK(chained.ok());
  CHECK(GotCommand(b, 100U));
  CHECK_EQ(b.chip.bad_frames, bad);
}

TEST_CASE("An IFS request above the NXP maximum 0xFE is never answered or used") {
  T1Knobs k = Knobs(false);
  k.ifs_request = 0xFFU; // UM11225: IFS 1 to 254
  Bench b(k);
  REQUIRE(b.link.Open().ok());
  const auto r = Send(b, 5U);
  CHECK(!r.ok());
  CHECK_EQ(b.chip.ifs_answered, 0U);
  CHECK(b.link.Params().ifsc <= 0xFEU);
  CHECK(b.link.Params().ifsd <= 0xFEU);
}

// --- Close, deep power-down, reset, recover --------------------------------------------------

TEST_CASE("Close sends end of APDU session (NXP) or RELEASE (GP), never the other code") {
  Bench nxp(Knobs(false));
  REQUIRE(nxp.link.Open().ok());
  CHECK(nxp.link.Close().ok());
  CHECK_EQ(nxp.chip.Sent(0xC5U), 1U);
  CHECK_EQ(nxp.chip.Sent(0xC6U), 0U); // 0xC6 resets the chip in this flavour
  CHECK_EQ(nxp.chip.chip_resets, 0U);
  CHECK_EQ(nxp.link.State(), LinkState::Closed);
  Bench gp(Knobs(true));
  REQUIRE(gp.link.Open().ok());
  CHECK(gp.link.Close().ok());
  CHECK_EQ(gp.chip.Sent(0xC6U), 1U);
  CHECK_EQ(gp.chip.Sent(0xC5U), 0U);
  CHECK_EQ(gp.chip.session_ends, 1U);
  CHECK_EQ(gp.link.State(), LinkState::Closed);
}

TEST_CASE("Close is never refused for an uncertain state (RD-05)") {
  Bench b(Knobs(false));
  REQUIRE(b.link.Open().ok());
  REQUIRE(b.link.Reset(ResetKind::Interface).ok());
  CHECK_EQ(b.link.State(), LinkState::NeedsReselect);
  CHECK(b.link.Close().ok());
  CHECK_EQ(b.chip.Sent(0xC5U), 1U);
  // Dead: no reset port, a chip that answers nothing.
  PlainBench d(Knobs(false), Patient());
  REQUIRE(d.link.Open().ok());
  Silence(d.chip);
  CHECK_EQ(Send(d, 5U).error, Error::TransportDead);
  CHECK_EQ(d.link.State(), LinkState::Dead);
  CHECK_EQ(Send(d, 5U).error, Error::TransportDead); // nothing more is tried
  const uint32_t ends = d.chip.Sent(0xC5U);
  CHECK(d.link.Close().ok());
  CHECK(d.chip.Sent(0xC5U) > ends);
  CHECK_EQ(d.link.State(), LinkState::Closed);
}

TEST_CASE("Deep power-down by ENA writes no frame; Open wakes the chip") {
  Bench b(Knobs(false));
  b.chip.has_ena = true;
  REQUIRE(b.link.Open().ok());
  const uint32_t writes = b.chip.writes;
  CHECK(b.link.DeepPowerDown().ok());
  CHECK_EQ(b.chip.writes, writes);
  CHECK_EQ(b.chip.Sent(0xDFU), 0U);
  CHECK_EQ(b.chip.dpd_entries, 1U);
  CHECK_EQ(b.link.State(), LinkState::Closed);
  CHECK_EQ(Send(b, 5U).error, Error::NotInitialized);
  REQUIRE(b.link.Open().ok());
  CHECK(Send(b, 5U).ok());
}

TEST_CASE("Deep power-down by the S-block 0xDF on a part without ENA (SE052)") {
  for (const bool gp : {false, true}) {
    Bench b(Knobs(gp));
    REQUIRE(b.link.Open().ok());
    CHECK(b.link.DeepPowerDown().ok());
    CHECK_EQ(b.chip.Sent(0xDFU), 1U);
    CHECK_EQ(b.chip.dpd_entries, 1U);
    CHECK_EQ(b.link.State(), LinkState::Closed);
    REQUIRE(b.link.Open().ok()); // the next access wakes and boots the chip
    CHECK(Send(b, 5U).ok());
  }
}

TEST_CASE("After a deep power-down by S-block nothing touches the bus for tDPD (SE052 p. 22)") {
  Config c{};
  c.boot_wait_ms = 0U; // no boot wait hides the gap
  PlainBench b(Knobs(false), c);
  REQUIRE(b.link.Open().ok());
  REQUIRE(b.link.DeepPowerDown().ok());
  REQUIRE(b.link.Open().ok());
  CHECK(b.chip.gap_after_dpd_us >= wire::kSe052DeepPowerDownUs);
}

TEST_CASE("Deep power-down: Unsupported keeps the link; from Dead it is still sent") {
  T1Knobs k = Knobs(false);
  k.supports_dpd = false;
  Bench b(k);
  REQUIRE(b.link.Open().ok());
  CHECK_EQ(b.link.DeepPowerDown().error, Error::Unsupported);
  CHECK_EQ(b.link.State(), LinkState::Idle);
  CHECK(Send(b, 5U).ok());
  PlainBench d(Knobs(false), Patient());
  REQUIRE(d.link.Open().ok());
  Silence(d.chip);
  CHECK_EQ(Send(d, 5U).error, Error::TransportDead);
  CHECK(d.link.DeepPowerDown().ok());
  CHECK(d.chip.Sent(0xDFU) >= 1U);
  CHECK_EQ(d.link.State(), LinkState::Closed);
}

TEST_CASE("Reset(Interface) leaves NeedsReselect; a command then leaves Idle") {
  for (const bool gp : {false, true}) {
    Bench b(Knobs(gp));
    REQUIRE(b.link.Open().ok());
    CHECK(b.link.Reset(ResetKind::Interface).ok());
    CHECK_EQ(b.chip.soft_resets, 2U);
    CHECK_EQ(b.link.State(), LinkState::NeedsReselect);
    CHECK(Send(b, 5U).ok()); // the layer above sends its SELECT this way
    CHECK_EQ(b.link.State(), LinkState::Idle);
  }
}

TEST_CASE("Reset(Cold) is the S-block 0xC6 in the NXP flavour and refused in the GP flavour") {
  Bench nxp(Knobs(false));
  REQUIRE(nxp.link.Open().ok());
  CHECK(nxp.link.Reset(ResetKind::Cold).ok());
  CHECK_EQ(nxp.chip.Sent(0xC6U), 1U);
  CHECK_EQ(nxp.chip.chip_resets, 1U);
  CHECK_EQ(nxp.handler.power_cycles, 1U);
  CHECK_EQ(nxp.link.State(), LinkState::NeedsReselect);
  CHECK(Send(nxp, 5U).ok());
  Bench gp(Knobs(true));
  REQUIRE(gp.link.Open().ok());
  const uint32_t writes = gp.chip.writes;
  CHECK_EQ(gp.link.Reset(ResetKind::Cold).error, Error::Unsupported);
  CHECK_EQ(gp.chip.writes, writes);
  CHECK_EQ(gp.link.State(), LinkState::Idle);
}

TEST_CASE("Reset through the reset port; without one Unsupported; a failing port is Bus") {
  Bench b(Knobs(true));
  REQUIRE(b.link.Open().ok());
  CHECK(b.link.Reset(ResetKind::Reset).ok());
  CHECK_EQ(b.reset.resets, 1U);
  CHECK_EQ(b.chip.hard_resets, 1U);
  CHECK(b.link.Reset(ResetKind::PowerCycle).ok());
  CHECK_EQ(b.reset.cycles, 1U);
  CHECK_EQ(b.link.State(), LinkState::NeedsReselect);
  CHECK_EQ(b.link.Reset(std::bit_cast<ResetKind>(uint8_t{4U})).error, Error::InvalidArgument);
  b.reset.reset_ok = false;
  CHECK_EQ(b.link.Reset(ResetKind::Reset).error, Error::Bus);
  CHECK_EQ(b.link.State(), LinkState::Dead);
  PlainBench p(Knobs(false));
  REQUIRE(p.link.Open().ok());
  CHECK_EQ(p.link.Reset(ResetKind::Reset).error, Error::Unsupported);
  CHECK_EQ(p.link.Reset(ResetKind::PowerCycle).error, Error::Unsupported);
  CHECK_EQ(p.link.State(), LinkState::Idle);
}

TEST_CASE("Recover: each starting rung does what its name says") {
  Bench b(Knobs(false));
  REQUIRE(b.link.Open().ok());
  CHECK_EQ(b.link.Recover(Rung::Resync).error, Error::Resynced);
  CHECK_EQ(b.link.Recover(Rung::ResendBlock).error, Error::Resynced);
  CHECK_EQ(b.link.GetCounters().resyncs, 2U);
  CHECK_EQ(b.link.State(), LinkState::Idle);
  const uint32_t writes = b.chip.writes;
  CHECK_EQ(b.link.Recover(Rung::Reselect).error, Error::NeedsReselect);
  CHECK_EQ(b.chip.writes, writes); // the layer above selects
  CHECK_EQ(b.link.State(), LinkState::NeedsReselect);
  CHECK_EQ(b.link.Recover(Rung::Resync).error, Error::NeedsReselect); // a reset is still pending
  CHECK_EQ(b.link.Recover(Rung::InterfaceReset).error, Error::NeedsReselect);
  CHECK_EQ(b.chip.soft_resets, 2U);
  CHECK_EQ(b.link.Recover(Rung::ChipReset).error, Error::NeedsReselect);
  CHECK_EQ(b.chip.chip_resets, 1U);
  CHECK_EQ(b.link.Recover(Rung::PowerCycle).error, Error::NeedsReselect);
  CHECK_EQ(b.reset.cycles, 1U);
  CHECK_EQ(b.link.GetCounters().last_rung, Rung::PowerCycle);
  CHECK_EQ(b.link.Recover(std::bit_cast<Rung>(uint8_t{6U})).error, Error::InvalidArgument);
}

TEST_CASE("Recover(ChipReset) in the GP flavour uses the reset port, never 0xC6") {
  Bench b(Knobs(true));
  REQUIRE(b.link.Open().ok());
  CHECK_EQ(b.link.Recover(Rung::ChipReset).error, Error::NeedsReselect);
  CHECK_EQ(b.reset.resets, 1U);
  CHECK_EQ(b.chip.Sent(0xC6U), 0U); // RELEASE in this flavour
  CHECK_EQ(b.link.GetCounters().last_rung, Rung::ChipReset);
  PlainBench p(Knobs(true));
  REQUIRE(p.link.Open().ok());
  CHECK_EQ(p.link.Recover(Rung::ChipReset).error, Error::TransportDead);
  CHECK_EQ(p.chip.Sent(0xC6U), 0U);
  CHECK_EQ(p.link.State(), LinkState::Dead);
  // From Dead, the ladder can still be climbed and Open still works.
  CHECK_EQ(p.link.Recover(Rung::Resync).error, Error::Resynced);
  CHECK_EQ(p.link.State(), LinkState::Idle);
}

} // namespace
