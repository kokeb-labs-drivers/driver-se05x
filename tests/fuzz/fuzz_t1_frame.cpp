/**
 * @file fuzz_t1_frame.cpp
 * @brief Fuzz target of the T=1 link: the bus answers with bytes from the input (raw bytes, bus
 * statuses, or well-formed frames of either flavour built around fuzzed PCB and INF), and the
 * link's safety rules are checked after every call.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * Input: byte 0 configuration (flavour, retries, number of commands), byte 1 command length,
 * byte 2 response buffer size, byte 3 the extra calls; then a stream of read controls:
 * 11xxxxxx a frame (bit 5 GP, bit 4 CRC order swapped, bit 3 CRC corrupted; then PCB, LEN, INF),
 * 10nnnnnn a raw read of n + 1 bytes, otherwise a bus status (NACK, bus error, timeout, stuck).
 * Half duplex as on the wire: a frame or raw bytes start only at the beginning or after a host
 * write; until then reads return idle bytes.
 *
 * Invariants (abort on violation): every write is non-empty, one well-formed frame of a host NAD
 * with a valid CRC and at most 260 bytes (errata I2C.2, S-12); no write while a frame the bus
 * offered is partly unread (errata I2C.1); `InvalidArgument` sends nothing; a failed call returns
 * length 0; a successful one at least the status word and no more than the buffer; no call
 * returns in `InFlight`; every error is an enumerator; the number of bus calls stays bounded.
 */
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "model/t1_fixture.hpp"
#include "se05x_t1.hpp"

namespace {

using namespace se05x;

constexpr std::size_t kMaxWire = 260U;
constexpr uint64_t kMaxBusCalls = 4000000U;

uint16_t Crc(const uint8_t* p, std::size_t n) {
  uint32_t crc = 0xFFFFU;
  for (std::size_t i = 0U; i < n; ++i) {
    crc ^= p[i];
    for (int b = 0; b < 8; ++b) {
      crc = ((crc & 1U) != 0U) ? ((crc >> 1U) ^ 0x8408U) : (crc >> 1U);
    }
  }
  return static_cast<uint16_t>(~crc & 0xFFFFU);
}

void Require(bool ok) {
  if (!ok) {
    std::abort();
  }
}

/** @brief Checks one written frame: a host NAD, a consistent LEN, a valid CRC in either order. */
bool WellFormed(ByteSpan f) {
  if ((f.size() < 5U) || (f.size() > kMaxWire)) {
    return false;
  }
  const bool gp = f[0] == 0x21U;
  if (!gp && (f[0] != 0x5AU)) {
    return false;
  }
  const std::size_t h = gp ? 4U : 3U;
  if (f.size() < (h + 2U)) {
    return false;
  }
  const std::size_t len = gp ? ((static_cast<std::size_t>(f[2]) << 8U) | f[3]) : f[2];
  if (f.size() != (h + len + 2U)) {
    return false;
  }
  const uint16_t crc = Crc(f.data(), h + len);
  const auto c1 = static_cast<uint32_t>(f[h + len]);
  const auto c2 = static_cast<uint32_t>(f[h + len + 1U]);
  const auto msb = static_cast<uint16_t>((c1 << 8U) | c2);
  const auto lsb = static_cast<uint16_t>((c2 << 8U) | c1);
  return gp ? (crc == msb) : ((crc == msb) || (crc == lsb));
}

class FuzzBus : public BusInterface<FuzzBus> {
public:
  FuzzBus(const uint8_t* data, std::size_t size) : data_(data), size_(size) {}

  bool EnsureInitialized() noexcept {
    return true;
  }

  BusStatus Write(uint8_t addr7, ByteSpan data) noexcept {
    static_cast<void>(addr7);
    count();
    ++writes;
    Require(!data.empty());              // errata I2C.2
    Require(WellFormed(data));           // one block per write
    Require(queued_pos_ >= queued_len_); // errata I2C.1: nothing offered is left unread
    armed_ = true;                       // half duplex: one answer per host block
    return BusStatus::Ok;
  }

  BusRead Read(uint8_t addr7, MutableByteSpan out) noexcept {
    static_cast<void>(addr7);
    count();
    if (queued_pos_ < queued_len_) {
      serve(out);
      return BusRead{BusStatus::Ok, out.size()};
    }
    if (pos_ >= size_) {
      return BusRead{BusStatus::Nack, 0U};
    }
    const bool data = (data_[pos_] & 0x80U) != 0U;
    if (data && !armed_) {
      // The chip's answer is out: past it the chip sends idle bytes until the host writes again
      // (UM11225 p. 15; GPC_SPE_172 section 3.2.7).
      for (uint8_t& b : out) {
        b = 0xFFU;
      }
      return BusRead{BusStatus::Ok, out.size()};
    }
    const uint8_t c = data_[pos_++];
    if ((c & 0xC0U) == 0xC0U) {
      armed_ = false;
      queue(c);
      serve(out);
      return BusRead{BusStatus::Ok, out.size()};
    }
    if ((c & 0xC0U) == 0x80U) {
      armed_ = false;
      const std::size_t n = (c & 0x3FU) + 1U;
      for (std::size_t i = 0U; i < out.size(); ++i) {
        out[i] = ((i < n) && (pos_ < size_)) ? data_[pos_++] : 0xFFU;
      }
      return BusRead{BusStatus::Ok, out.size()};
    }
    switch (c & 7U) {
    case 3U:
      return BusRead{BusStatus::BusError, 0U};
    case 4U:
      return BusRead{BusStatus::Timeout, 0U};
    case 5U:
      return BusRead{((c & 0x30U) == 0x30U) ? BusStatus::BusStuck : BusStatus::Nack, 0U};
    default:
      return BusRead{BusStatus::Nack, 0U};
    }
  }

  uint64_t writes{0};

private:
  void count() {
    ++calls_;
    Require(calls_ < kMaxBusCalls); // every wait is bounded (S-05)
  }
  uint8_t next() {
    return (pos_ < size_) ? data_[pos_++] : 0U;
  }
  void queue(uint8_t c) {
    const bool gp = (c & 0x20U) != 0U;
    const bool swapped = (c & 0x10U) != 0U;
    const bool corrupt = (c & 0x08U) != 0U;
    const uint8_t pcb = next();
    const std::size_t len = next();
    std::size_t p = 0U;
    queued_[p++] = gp ? 0x12U : 0xA5U;
    queued_[p++] = pcb;
    if (gp) {
      queued_[p++] = 0U;
    }
    queued_[p++] = static_cast<uint8_t>(len);
    for (std::size_t i = 0U; i < len; ++i) {
      queued_[p++] = next();
    }
    const uint16_t crc = Crc(queued_.data(), p);
    const bool msb = gp != swapped;
    queued_[p++] = static_cast<uint8_t>(msb ? (crc >> 8U) : (crc & 0xFFU));
    queued_[p++] = static_cast<uint8_t>(msb ? (crc & 0xFFU) : (crc >> 8U));
    if (corrupt) {
      queued_[p - 1U] = static_cast<uint8_t>(~queued_[p - 1U]);
    }
    queued_len_ = p;
    queued_pos_ = 0U;
  }
  void serve(MutableByteSpan out) {
    for (uint8_t& b : out) {
      b = (queued_pos_ < queued_len_) ? queued_[queued_pos_] : 0xFFU;
      ++queued_pos_;
    }
  }

  const uint8_t* data_;
  std::size_t size_;
  std::size_t pos_{4U};
  std::array<uint8_t, 4U + 255U + 2U> queued_{};
  std::size_t queued_len_{0U};
  std::size_t queued_pos_{0U};
  uint64_t calls_{0U};
  bool armed_{true}; ///< The chip may start an answer: at start (a stale one) and after a write.
};

class FuzzReset : public ResetInterface<FuzzReset> {
public:
  bool Reset() noexcept {
    return true;
  }
  bool PowerCycle() noexcept {
    return true;
  }
  bool SetEnable(bool on) noexcept {
    static_cast<void>(on);
    return false;
  }
};

using FuzzPorts = Ports<FuzzBus, testmodel::SimClock, testmodel::NoCrypto, FuzzReset>;

void CheckError(Error e) {
  Require(std::strcmp(ToString(e), "Unknown") != 0);
}

template <typename L>
void CheckState(const L& link) {
  Require(link.State() != t1::LinkState::InFlight);
}

std::array<uint8_t, 1100>& CommandBuffer() {
  static std::array<uint8_t, 1100> buffer{};
  return buffer;
}
std::array<uint8_t, 1100>& ResponseBuffer() {
  static std::array<uint8_t, 1100> buffer{};
  return buffer;
}

template <typename L>
void RunCommand(L& link, FuzzBus& bus, std::size_t cmd_len, std::size_t resp_len, uint8_t cls) {
  const uint64_t before = bus.writes;
  const auto r = link.Transceive(ByteSpan{CommandBuffer()}.first(cmd_len),
                                 MutableByteSpan{ResponseBuffer()}.first(resp_len),
                                 static_cast<CommandClass>(cls));
  CheckError(r.error);
  CheckState(link);
  if (r.error == Error::InvalidArgument) {
    Require(bus.writes == before); // RD-04: an argument error sends nothing
  }
  if (r.ok()) {
    Require((r.value >= 2U) && (r.value <= resp_len));
  } else {
    Require(r.value == 0U);
  }
}

template <typename L>
void Extra(L& link, uint8_t op) {
  Error e = Error::Ok;
  switch (op & 7U) {
  case 0U:
    e = link.Recover(static_cast<t1::Rung>((op >> 3U) % 7U)).error;
    break;
  case 1U:
    e = link.Reset(static_cast<t1::ResetKind>((op >> 3U) % 5U)).error;
    break;
  case 2U:
    e = link.DeepPowerDown().error;
    break;
  case 3U:
    e = link.Close().error;
    break;
  default:
    break;
  }
  CheckError(e);
  CheckState(link);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
  if (size < 4U) {
    return 0;
  }
  std::array<uint8_t, 1100>& cmd = CommandBuffer();
  for (std::size_t i = 0U; i < cmd.size(); ++i) {
    cmd[i] = static_cast<uint8_t>(i);
  }
  FuzzBus bus(data, size);
  testmodel::SimClock clock;
  testmodel::NoCrypto crypto;
  FuzzReset reset;
  const FuzzPorts ports(bus, clock, crypto, reset);
  Config config{};
  const auto cfg = static_cast<uint32_t>(data[0]);
  config.flavour = static_cast<TransportFlavour>((cfg & 3U) % 3U);
  config.frame_retries = static_cast<uint8_t>(((cfg >> 2U) & 7U) + 1U);
  config.atr_poll_budget_ms = 200U;
  config.timeouts.fast_ms = 300U;
  config.wtx_limit = 8U;
  t1::Link<FuzzPorts> link(ports, config);
  const auto opened = link.Open();
  CheckError(opened.error);
  CheckState(link);
  Require(opened.ok() == (link.State() == t1::LinkState::Idle));
  const std::size_t commands = (cfg >> 5U) & 7U;
  const std::size_t cmd_len = (static_cast<std::size_t>(data[1]) * 5U) % 1030U;
  const std::size_t resp_len =
      std::min<std::size_t>((static_cast<std::size_t>(data[2]) * 5U) + 1U, 1100U);
  for (std::size_t i = 0U; i < commands; ++i) {
    RunCommand(link, bus, cmd_len, resp_len, static_cast<uint8_t>(i % 5U));
    if (((static_cast<uint32_t>(data[3]) >> i) & 1U) != 0U) {
      Extra(link, static_cast<uint8_t>(data[3] + i));
    }
  }
  CheckError(link.Close().error);
  CheckState(link);
  return 0;
}
