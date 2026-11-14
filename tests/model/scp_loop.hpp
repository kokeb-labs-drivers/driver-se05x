/**
 * @file scp_loop.hpp
 * @brief A loopback `ApduTransport` from the library to a model `ApduHandler`, with the fault
 * knobs of the secure-channel tests: a failing call, a lost response, a tampered command or
 * response byte. Plus the deterministic entropy and port set the tests share.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#ifndef SE05X_TESTS_MODEL_SCP_LOOP_HPP
#define SE05X_TESTS_MODEL_SCP_LOOP_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "model/model_if.hpp"
#include "null_ports.hpp"
#include "se05x_crypto.hpp"
#include "se05x_status.hpp"

namespace se05x::testmodel {

/** @brief The loopback transport. Indices count calls from 1; 0 disables a knob. */
class Loop {
public:
  explicit Loop(ApduHandler& handler) : handler_(&handler) {}

  uint32_t calls{0};                    ///< Transceive calls so far.
  uint32_t fail_call{0};                ///< This call returns `Timeout` and never reaches the chip.
  uint32_t lose_call{0};                ///< This call reaches the chip, then returns `Timeout`.
  uint32_t tamper_rsp_call{0};          ///< On this call, flip `tamper_mask` in response byte...
  std::size_t tamper_rsp_byte{0};       ///< ...at this index (when it exists).
  uint32_t tamper_cmd_call{0};          ///< On this call, flip `tamper_mask` in command byte...
  std::size_t tamper_cmd_byte{0};       ///< ...at this index.
  uint8_t tamper_mask{0x01U};           ///< The bits to flip.
  uint32_t truncate_rsp_call{0};        ///< On this call, drop the response's first bytes...
  std::size_t truncate_to{0};           ///< ...keeping only the last `truncate_to` bytes.
  std::array<uint8_t, 1200> last_cmd{}; ///< The last command as sent.
  std::size_t last_cmd_len{0};
  std::size_t last_rsp_len{0};

  Result<std::size_t> Transceive(ByteSpan command, MutableByteSpan response) noexcept {
    ++calls;
    if (calls == fail_call) {
      return Result<std::size_t>::Failure(Error::Timeout);
    }
    std::array<uint8_t, 1200> cmd{};
    if (command.size() > cmd.size()) {
      return Result<std::size_t>::Failure(Error::BufferTooSmall);
    }
    static_cast<void>(std::memcpy(cmd.data(), command.data(), command.size()));
    if ((calls == tamper_cmd_call) && (tamper_cmd_byte < command.size())) {
      cmd[tamper_cmd_byte] = static_cast<uint8_t>(cmd[tamper_cmd_byte] ^ tamper_mask);
    }
    static_cast<void>(std::memcpy(last_cmd.data(), cmd.data(), command.size()));
    last_cmd_len = command.size();
    std::array<uint8_t, 1200> rsp{};
    std::size_t n = handler_->Handle(ByteSpan(cmd.data(), command.size()), MutableByteSpan(rsp));
    if (calls == lose_call) {
      return Result<std::size_t>::Failure(Error::Timeout);
    }
    if ((calls == tamper_rsp_call) && (tamper_rsp_byte < n)) {
      rsp[tamper_rsp_byte] = static_cast<uint8_t>(rsp[tamper_rsp_byte] ^ tamper_mask);
    }
    std::size_t from = 0U;
    if ((calls == truncate_rsp_call) && (truncate_to < n)) {
      from = n - truncate_to;
      n = truncate_to;
    }
    last_rsp_len = n;
    if (n > response.size()) {
      return Result<std::size_t>::Failure(Error::BufferTooSmall);
    }
    static_cast<void>(std::memcpy(response.data(), rsp.data() + from, n));
    return Result<std::size_t>::Success(n);
  }

private:
  ApduHandler* handler_;
};

/** @brief A deterministic entropy source for the tests (a counter through a mixer). */
inline bool TestEntropy(MutableByteSpan out) noexcept {
  static uint32_t state = 0x1234567U;
  for (uint8_t& b : out) {
    state = (state * 1103515245U) + 12345U;
    b = static_cast<uint8_t>(state >> 16U);
  }
  return true;
}

/** @brief An entropy source that always fails. */
inline bool NoEntropy(MutableByteSpan out) noexcept {
  static_cast<void>(out);
  return false;
}

/// The port set of the secure-channel tests.
using ScpPorts = Ports<testports::NullBus, testports::NullClock, ReferenceCrypto>;

/** @brief Ports with the reference crypto and the test entropy. */
struct ScpFixture {
  testports::NullBus bus;
  testports::NullClock clock;
  ReferenceCrypto crypto{&TestEntropy};
  ScpPorts ports{bus, clock, crypto};
};

} // namespace se05x::testmodel

#endif // SE05X_TESTS_MODEL_SCP_LOOP_HPP
