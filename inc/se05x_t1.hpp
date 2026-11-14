/**
 * @file se05x_t1.hpp
 * @brief The T=1 link over I2C: one command in flight, bounded waits, the recovery ladder (package
 * 1).
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * The public surface below is frozen (the compile-only test pins every signature); only private
 * members and helpers are added.
 *
 * `Link` carries one command APDU and returns one response APDU (`ApduTransport`), in either frame
 * flavour: NXP (UM11225: NAD 0x5A and 0xA5, one LEN byte) or GP (GPC_SPE_172: NAD 0x21 and 0x12,
 * two LEN bytes, CRC most significant byte first). Rules it enforces:
 *
 * - One command in flight: a response is read out completely before the next block is written
 *   (UM11225 section 2, p. 4; errata I2C.1), and `Open()` reads out whatever an earlier host left
 *   unread, answering up to `kSessionOpenWtxAllowance` waiting-time extensions of it first.
 * - One block per I2C write, never an empty write (UM11225 section 3.1.1.1, p. 13; errata I2C.2).
 *   The GP "ready to receive" probe by an address-only write (GPC_SPE_172 section 3.2.4) is never
 *   used: the link polls with reads only.
 * - Every wait has a deadline (S-05): the block waiting time from the ATR or CIP, the command class
 *   timeout of `Config::timeouts`, `Config::wtx_limit` extensions per command, and an iteration cap
 *   derived from the deadline and the poll interval, so a clock that does not advance cannot hang
 *   the link. After a waiting-time extension the link waits the multiplier times BWT and at least
 *   `wire::kMinWtxHostTimeoutMs` (AN13904 section 8.3, p. 27), never past the command deadline.
 * - Errors are retried `Config::frame_retries` times (R-block or retransmission, UM11225 section
 *   2.4.1, p. 11), then the recovery ladder climbs (S-06): resynchronisation, interface soft reset,
 *   reselect (the layer above), chip reset (the NXP S-block 0xC6; in the GP flavour, where 0xC6
 *   means RELEASE, the reset port), power cycle (reset port only), then `TransportDead`. A rung
 *   that cannot run is skipped; a stuck bus goes straight to the power cycle.
 * - A resync or reset invalidates every session above the link: `Transceive()` then returns
 *   `Resynced` or `NeedsReselect` and never a half-answer (S-07, S-15). On any failure the bytes
 *   the link wrote into the response buffer are zeroed, and the link's own frame buffers are wiped
 *   after every command (S-01).
 *
 * Not implemented: the host's own S(IFS request) (the link keeps the chip's IFSC and, in the GP
 * flavour, the default IFSD of 64 bytes), S(ABORT), and the proprietary GP cold-reset S-block of
 * the middleware (no published document defines it).
 */
#ifndef SE05X_T1_HPP
#define SE05X_T1_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "se05x_atr.hpp"
#include "se05x_ports.hpp"
#include "se05x_secret.hpp"
#include "se05x_status.hpp"
#include "se05x_t1_crc.hpp"
#include "se05x_types.hpp"
#include "se05x_wire.hpp"

namespace se05x::t1 {

/**
 * @defgroup se05x_t1 T=1 link
 * @brief Frames, blocks, chaining, waiting time extensions, resynchronisation and recovery.
 * @{
 */

/** @brief The state of the link. */
enum class LinkState : uint8_t {
  Closed = 0,        ///< `Open()` has not succeeded or `Close()` ran.
  Idle = 1,          ///< Open, no command in flight.
  InFlight = 2,      ///< A command is being exchanged.
  NeedsReselect = 3, ///< A reset happened: select the applet again before the next command.
  Dead = 4,          ///< The recovery ladder is exhausted.
};

/**
 * @brief How `Link::Reset()` resets the chip.
 *
 * `Reset` and `PowerCycle` call the reset port; what the port drives is the board's choice. On the
 * SE050 and SE051 RST_N is the ISO 7816 reset and has no effect when only I2C is enabled (SE050
 * data sheet 4.2 p. 9, SE051 p. 10): there `Reset()` must power-cycle through ENA (or the supply),
 * or the GP-flavour chip-reset rung, which uses it, resets nothing. On the SE052 RST_N resets the
 * chip (SE052 Table 14 p. 20, at least 40 us low).
 */
enum class ResetKind : uint8_t {
  Interface = 0,  ///< S-block interface soft reset: the chip keeps its state.
  Cold = 1,       ///< The NXP chip reset S-block (0xC6, UM11225); `Unsupported` in the GP flavour,
                  ///< which defines no cold reset (GPC_SPE_172).
  Reset = 2,      ///< The reset port's `Reset()`: not RST_N on an I2C-only SE050/SE051 (see above).
  PowerCycle = 3, ///< The reset port's `PowerCycle()`: supply or ENA off and on.
};

/** @brief The rungs of the recovery ladder, in order (design 5.2). */
enum class Rung : uint8_t {
  ResendBlock = 0,    ///< Resend the last block (R-block NAK), `Config::frame_retries` times.
  Resync = 1,         ///< S-block resynchronisation.
  InterfaceReset = 2, ///< Interface soft reset.
  Reselect = 3,       ///< Select the applet again (sessions are lost).
  ChipReset = 4,      ///< The T=1 chip reset (`ResetKind::Cold`; also the answer to
                      ///< `ThroughputLimited`): sessions and transient objects are lost.
  PowerCycle = 5,     ///< Power cycle through the reset port; absent without one.
};

} // namespace se05x::t1

namespace se05x::detail {
/// Last enumerator of `t1::LinkState`.
template <>
struct EnumLast<t1::LinkState> {
  static constexpr t1::LinkState kValue = t1::LinkState::Dead; ///< The last enumerator.
};
/// Last enumerator of `t1::ResetKind`.
template <>
struct EnumLast<t1::ResetKind> {
  static constexpr t1::ResetKind kValue = t1::ResetKind::PowerCycle; ///< The last enumerator.
};
/// Last enumerator of `t1::Rung`.
template <>
struct EnumLast<t1::Rung> {
  static constexpr t1::Rung kValue = t1::Rung::PowerCycle; ///< The last enumerator.
};
} // namespace se05x::detail

namespace se05x::t1 {

/** @brief Counters of what the link did; read-only diagnostics, no secrets. */
struct Counters {
  uint32_t frames_sent{0};           ///< Frames written.
  uint32_t frames_received{0};       ///< Frames read.
  uint32_t crc_errors{0};            ///< Frames with a bad CRC.
  uint32_t naks_sent{0};             ///< R-block NAKs sent.
  uint32_t resyncs{0};               ///< Resynchronisations.
  uint32_t wtx_received{0};          ///< Waiting time extensions received.
  uint32_t recoveries{0};            ///< Recovery rungs climbed.
  Rung last_rung{Rung::ResendBlock}; ///< The highest rung used for the last command.
};

namespace detail {
/// Largest INF the link sends or accepts in one block (one LEN byte of the NXP flavour, UM11225
/// section 2.1.1, p. 5; the GP flavour is held to the same size).
inline constexpr std::size_t kMaxInf = 254U;
/// Largest frame: a GP prologue (4 bytes), `kMaxInf` and the CRC.
inline constexpr std::size_t kMaxFrame = 4U + kMaxInf + wire::kCrcBytes;
/// Deep power-down request S-block of the SE052 (SE052 data sheet section 10.3, p. 7); the
/// response is the request with bit 6 set, 0xFF.
inline constexpr uint8_t kSDeepPowerDown = 0xDFU;
/// Reads of `kMaxFrame` bytes that cover the largest GP frame (4 + 0x0FF9 + 2 bytes).
inline constexpr uint32_t kGpDrainReads =
    static_cast<uint32_t>(((4U + 0x0FF9U + wire::kCrcBytes) + kMaxFrame - 1U) / kMaxFrame);
/// IFS requests from the chip answered per command before the link gives up.
inline constexpr uint32_t kMaxIfsRequests = 4U;
/// Longest wait one WTX grants, in ms (multiplier times BWT, at least 4 s; A33).
inline constexpr uint32_t kMaxWtxWaitMs = 30000U;
/// Longest total wait the WTX of one operation grant, in ms: above the 40 WTX of 4 s a session open
/// may need (`kSessionOpenWtxAllowance`; A33).
inline constexpr uint32_t kMaxWtxTotalMs = 180000U;
/// The block just read: its PCB and INF length; the INF is in the link's receive buffer after
/// the prologue.
struct Block {
  uint8_t pcb{0U};     ///< The PCB.
  std::size_t len{0U}; ///< The INF length.
};
/// What a received block means to the step that waits for it.
enum class Verdict : uint8_t { Accept, Resend, Nak };
/// What a step waits for.
enum class Want : uint8_t { Ack, FirstI, NextI };
/// Bytes of a response collected so far.
struct Collected {
  std::size_t total{0U};  ///< INF bytes received.
  std::size_t copied{0U}; ///< Bytes written into the caller's buffer.
  bool overflow{false};   ///< The response did not fit.
};
} // namespace detail

/**
 * @brief The T=1 link over the bus, clock and (optional) reset ports.
 *
 * @tparam P A `Ports<...>` set.
 */
template <PortSet P>
class Link {
public:
  /**
   * @brief Bind the link to the ports and the configuration. No I/O.
   * @param ports The port set; it must outlive the link.
   * @param config The configuration; checked at `Open()`.
   */
  Link(const P& ports, const Config& config) noexcept : ports_(&ports), config_(config) {}

  /** @brief One link per chip. */
  Link(const Link&) = delete;
  /** @brief One link per chip. */
  Link& operator=(const Link&) = delete;

  /**
   * @brief Bring the link up: drive ENA high when the set has a reset port, wait `boot_wait_ms`,
   * read out a response an earlier host left (errata I2C.1), then within `atr_poll_budget_ms`
   * exchange the interface soft reset (NXP: its response carries the ATR; GP: then the CIP
   * request) and fix the flavour, the CRC order and the parameters. `TransportFlavour::Auto`
   * tries the GP flavour for the first half of the budget, then the NXP flavour; a stale frame
   * read at the start decides it at once. Works from every state but `InFlight`.
   * @return `Ok`; `InvalidArgument` (bad `Config`; nothing sent); `Busy`; `Bus` (the bus port
   * failed, or `EnsureInitialized()` returned false); `Nack` (no write was acknowledged: no chip);
   * `BusStuck`; `Timeout`, `Crc` or `FrameError` (no valid answer within the budget). On failure
   * the link is `Closed`.
   */
  Result<void> Open() noexcept;

  /**
   * @brief Send one command APDU and read the response APDU.
   *
   * Single flight: a call while one is in flight returns `Busy`. Chains over several I-blocks,
   * answers waiting time extensions within the WTX budget, recovers within the ladder. Allowed in
   * `NeedsReselect` (the layer above sends its SELECT this way); a success then leaves `Idle`.
   *
   * @param command The command APDU, 1 to `kMaxCommandApdu` bytes.
   * @param response The buffer for the response APDU (body and status word), at least 2 bytes.
   * @param command_class Selects the timeout of `Config::timeouts`.
   * @return The response length; or, with nothing sent, `NotInitialized` (closed), `TransportDead`
   * (dead), `Busy`, `InvalidArgument` (empty or oversized command, a class that is not an
   * enumerator) or `BufferTooSmall` (response buffer under 2 bytes); or, after the exchange,
   * `BufferTooSmall` (the response did not fit; the link stays in step), `FrameError` (a response
   * under 2 bytes), `Timeout` (command deadline or WTX budget: the next call resynchronises first),
   * `Resynced`, `NeedsReselect` or `TransportDead` (the ladder ran; the command is not repeated),
   * `BusStuck` (no reset port to power-cycle). After a `Timeout` the next call resynchronises
   * first; when that needs more than the resynchronisation it returns `NeedsReselect` or
   * `TransportDead` without sending its command.
   */
  Result<std::size_t> Transceive(ByteSpan command, MutableByteSpan response,
                                 CommandClass command_class = CommandClass::Fast) noexcept;

  /**
   * @brief End the APDU session with the S-block of the flavour (NXP 0xC5 end of APDU session,
   * GP 0xC6 RELEASE); the chip may power down and wakes on the next block. Never refused for an
   * uncertain state: from `NeedsReselect` or `Dead` the S-block is still sent (RD-05). The link is
   * `Closed` afterwards whatever the chip answered.
   * @return `Ok` (also when already closed, with no I/O), `Busy`, or the error of the exchange.
   */
  Result<void> Close() noexcept;

  /**
   * @brief Enter deep power-down: the ENA pin through the reset port when the part has one
   * (SE050, SE051: `SetEnable(false)` returns true), else the S-block 0xDF (SE052 data sheet
   * section 10.3). Sessions and transient objects are lost (S-15); the link is `Closed` and the
   * next `Open()` wakes the chip. Sent from `NeedsReselect` and `Dead` too.
   * @return `Ok`; `NotInitialized` (closed); `Busy`; `Unsupported` (the chip does not answer the
   * S-block with its response; the state is kept); or the error of the exchange (the link is then
   * `Closed`).
   */
  Result<void> DeepPowerDown() noexcept;

  /**
   * @brief Reset the chip in the given way; the link ends `NeedsReselect` (S-15).
   * @param kind How to reset; `Reset` and `PowerCycle` need a reset port, `Cold` the NXP flavour.
   * @return `Ok`; `NotInitialized` (closed); `Busy`; `InvalidArgument` (not an enumerator);
   * `Unsupported` (no reset port, or `Cold` in the GP flavour; nothing sent, the state is kept);
   * `Bus` (the reset port returned false); or the error of the exchange or the handshake after
   * the reset. On every failure but `Unsupported` the link is `Dead`.
   */
  Result<void> Reset(ResetKind kind) noexcept;

  /**
   * @brief Climb the recovery ladder from `from` upwards until a rung succeeds.
   *
   * `ResendBlock` has nothing to resend outside a command and starts at `Resync`. `Reselect` is the
   * layer above's rung: called with it, the link marks `NeedsReselect` and sends nothing; climbing
   * past it from below (the soft reset failed) skips it.
   *
   * @param from The first rung to try.
   * @return `Resynced` (the resynchronisation succeeded and no reset is pending), `NeedsReselect`,
   * `TransportDead` (the link is `Dead`), `NotInitialized` (closed), `Busy` or `InvalidArgument`.
   */
  Result<void> Recover(Rung from) noexcept;

  /** @return The state of the link. No I/O. */
  [[nodiscard]] LinkState State() const noexcept {
    return state_;
  }
  /** @return The parameters in use (ATR or CIP, else the defaults). No I/O. */
  [[nodiscard]] const LinkParams& Params() const& noexcept {
    return params_;
  }
  /** @brief Not on a temporary: the reference would dangle (KB-CPP20-044). */
  void Params() const&& = delete;
  /** @return The counters. No I/O. */
  [[nodiscard]] const Counters& GetCounters() const& noexcept {
    return counters_;
  }
  /** @brief Not on a temporary: the reference would dangle (KB-CPP20-044). */
  void GetCounters() const&& = delete;

private:
  // Time and bus.
  [[nodiscard]] uint64_t nowUs() const noexcept;
  void waitUs(uint32_t us) const noexcept;
  [[nodiscard]] uint32_t pollUs() const noexcept;
  [[nodiscard]] uint32_t pollBudget(uint64_t deadline) const noexcept;
  Error busRead(std::size_t offset, std::size_t count, uint64_t deadline, bool first) noexcept;
  void guardAfterRead() noexcept;
  void markAccess() noexcept;
  Error busWrite(std::size_t length) noexcept;
  BusStatus drain() noexcept;

  // Frames.
  [[nodiscard]] std::size_t prologue() const noexcept;
  [[nodiscard]] uint8_t seNad(TransportFlavour flavour) const noexcept;
  std::size_t buildFrame(uint8_t pcb, ByteSpan inf) noexcept;
  Error sendBlock(uint8_t pcb, ByteSpan inf) noexcept;
  Error sendProtocol(uint8_t pcb, ByteSpan inf) noexcept;
  Error resendProtocol() noexcept;
  Error sendNak(Error why) noexcept;
  Error recvBlock(detail::Block& out, uint64_t deadline, uint32_t settle_us) noexcept;
  Error checkNad() noexcept;
  Error readBody(std::size_t len, uint64_t deadline) noexcept;
  bool crcValid(std::size_t length) noexcept;
  [[nodiscard]] std::size_t rxLimit() const noexcept;

  // Blocks.
  [[nodiscard]] uint64_t blockDeadline() const noexcept;
  [[nodiscard]] uint32_t rungMs() const noexcept;
  [[nodiscard]] uint32_t bootUs() const noexcept;
  [[nodiscard]] bool hard(Error e) const noexcept;
  Error awaitBlock(detail::Block& out, uint64_t& deadline, uint32_t settle_us) noexcept;
  Error onWtx(const detail::Block& b, uint64_t& deadline) noexcept;
  Error onIfs(const detail::Block& b) noexcept;
  Error sExchange(uint8_t request, detail::Block& out, uint32_t settle_us) noexcept;
  [[nodiscard]] detail::Verdict judge(detail::Want want, const detail::Block& b) const noexcept;
  [[nodiscard]] detail::Verdict judgeR(detail::Want want, uint32_t pcb) const noexcept;
  [[nodiscard]] detail::Verdict judgeI(detail::Want want, const detail::Block& b) const noexcept;
  Error awaitExpected(detail::Want want, detail::Block& out, Error sent) noexcept;
  Error sendCommand(ByteSpan command, detail::Block& first) noexcept;
  Error collect(const detail::Block& b, MutableByteSpan response, detail::Collected& got) noexcept;
  Error receiveResponse(detail::Block first, MutableByteSpan response,
                        detail::Collected& got) noexcept;
  Error exchange(ByteSpan command, MutableByteSpan response, detail::Collected& got) noexcept;
  Error afterFailure(Error e) noexcept;
  Result<std::size_t> finish(Error e, MutableByteSpan response,
                             const detail::Collected& got) noexcept;

  // Handshake and ladder.
  void setFlavour(TransportFlavour flavour) noexcept;
  void startDeadline(uint32_t ms) noexcept;
  void flushStale() noexcept;
  Error handshake() noexcept;
  Error negotiate() noexcept;
  Error doResync() noexcept;
  Error doSoftReset() noexcept;
  Error doChipReset() noexcept;
  Error doPortReset(ResetKind kind) noexcept;
  Error tryRung(Rung rung, Rung from) noexcept;
  Error climb(Rung from) noexcept;
  Error doReset(ResetKind kind) noexcept;
  void settle() noexcept;
  void wipe() noexcept;
  void log(LogLevel level, Error error, const char* text) const noexcept;

  const P* ports_;
  Config config_;
  LinkParams params_{};
  Counters counters_{};
  LinkState state_{LinkState::Closed};
  TransportFlavour flavour_{TransportFlavour::Um11225};
  bool open_{false};               ///< The link is up (not closed).
  bool dead_{false};               ///< The ladder is exhausted.
  bool reselect_{false};           ///< A reset happened since the last successful command.
  bool needs_resync_{false};       ///< The last command ended at its deadline.
  bool pending_{false};            ///< A written block may have an unread answer.
  uint64_t last_read_us_{0U};      ///< When the last bus access ended (guard time).
  bool read_done_{false};          ///< A bus access happened since the link was made.
  uint64_t quiet_until_us_{0U};    ///< No access before this time (after a deep power-down).
  bool detect_{false};             ///< Open: accept either SE NAD and either NXP CRC order.
  bool seen_other_{false};         ///< A frame of the other flavour was seen while detecting.
  bool adopt_{false};              ///< Open: switch to the flavour of a stale frame.
  bool hint_{false};               ///< Open: a stale frame fixed the flavour.
  bool crc_fixed_{false};          ///< The CRC order is fixed.
  bool crc_lsb_first_{true};       ///< NXP flavour: CRC least significant byte first.
  uint8_t ns_{0U};                 ///< N(S) of the next I-block the host sends.
  uint8_t nr_{0U};                 ///< N(S) of the next I-block the host expects.
  uint8_t last_pcb_{0U};           ///< PCB of the last protocol block (resend on R-block).
  ByteSpan last_inf_;              ///< INF of the last protocol block (caller memory or `sinf_`).
  uint16_t wtx_count_{0U};         ///< Waiting time extensions in this operation.
  uint32_t wtx_wait_ms_{0U};       ///< Time granted by those extensions, in ms.
  uint32_t ifs_count_{0U};         ///< IFS requests answered in this operation.
  uint64_t deadline_{0U};          ///< Deadline of this operation, in microseconds.
  std::array<uint8_t, 2U> sinf_{}; ///< INF of an S-block the host sends.
  std::array<uint8_t, detail::kMaxFrame> tx_{}; ///< The frame being written (RD-06: a member).
  std::array<uint8_t, detail::kMaxFrame> rx_{}; ///< The frame being read (RD-06: a member).
};

/** @} */

} // namespace se05x::t1

// codeql::misra_deviation_next_line(MD-CPP-009)
#include "../src/se05x_t1.ipp" // IWYU pragma: export

#endif // SE05X_T1_HPP
