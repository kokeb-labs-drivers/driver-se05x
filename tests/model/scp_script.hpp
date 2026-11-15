/**
 * @file scp_script.hpp
 * @brief A scripted transport for known-answer tests: each step names the exact command the
 * library must send and the response to give back. The bytes come from an independent derivation
 * (OpenSSL), never from the library.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#ifndef SE05X_TESTS_MODEL_SCP_SCRIPT_HPP
#define SE05X_TESTS_MODEL_SCP_SCRIPT_HPP

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>

#include "model/bytes.hpp"
#include "se05x_status.hpp"
#include "se05x_types.hpp"

namespace se05x::testmodel {

/** @brief Hex text to bytes; returns the length. */
inline std::size_t HexTo(const char* s, uint8_t* out, std::size_t cap) {
  // A table lookup: no arithmetic on character values (MISRA C++:2023 Rule 7.0.3).
  // Character values through std::bit_cast, never arithmetic on a char (MISRA C++:2023 7.0.3).
  auto nib = [](char ch) -> int {
    const auto u = static_cast<unsigned>(std::bit_cast<uint8_t>(ch));
    if ((u >= 0x30U) && (u <= 0x39U)) {
      return static_cast<int>(u - 0x30U);
    }
    if ((u >= 0x61U) && (u <= 0x66U)) {
      return static_cast<int>(u - 0x57U);
    }
    if ((u >= 0x41U) && (u <= 0x46U)) {
      return static_cast<int>(u - 0x37U);
    }
    return -1;
  };
  std::size_t n = 0U;
  int hi = -1;
  for (const char* p = s; std::bit_cast<uint8_t>(*p) != 0U; ++p) {
    const int v = nib(*p);
    if (v < 0) {
      continue;
    }
    if (hi < 0) {
      hi = v;
    } else {
      if (n < cap) {
        out[n] = static_cast<uint8_t>((static_cast<unsigned>(hi) << 4U) | static_cast<unsigned>(v));
      }
      ++n;
      hi = -1;
    }
  }
  return n;
}

/** @brief One scripted exchange. */
struct Step {
  const char* command;  ///< The exact command expected, hex.
  const char* response; ///< The response, hex.
};

/** @brief Plays a script; any other command is a mismatch (answered with 6F00). */
class Script {
public:
  Script(const Step* steps, std::size_t count) : steps_(steps), count_(count) {}

  std::size_t index{0}; ///< Steps played.
  bool mismatch{false}; ///< A command differed from the script.
  std::size_t mismatch_at{0};

  Result<std::size_t> Transceive(ByteSpan command, MutableByteSpan response) noexcept {
    if (index >= count_) {
      mismatch = true;
      return Result<std::size_t>::Failure(Error::Timeout);
    }
    std::array<uint8_t, 600> want{};
    const std::size_t n = HexTo(steps_[index].command, want.data(), want.size());
    if ((n != command.size()) || (!SameBytes(want.data(), command.data(), n))) {
      mismatch = true;
      mismatch_at = index;
      response[0] = 0x6FU;
      response[1] = 0x00U;
      ++index;
      return Result<std::size_t>::Success(2U);
    }
    const std::size_t m = HexTo(steps_[index].response, response.data(), response.size());
    ++index;
    return Result<std::size_t>::Success(m);
  }

private:
  const Step* steps_;
  std::size_t count_;
};

/** @brief Entropy that repeats 11 22 33 44 55 66 77 88: a fixed host challenge. */
inline bool FixedEntropy(MutableByteSpan out) noexcept {
  for (std::size_t i = 0U; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>(0x11U * ((i % 8U) + 1U));
  }
  return true;
}

/** @brief Entropy that never repeats within a run (a counter mixed into every byte): fresh nonces.
 */
inline bool CountingEntropy(MutableByteSpan out) noexcept {
  static uint32_t calls = 0U;
  ++calls;
  for (std::size_t i = 0U; i < out.size(); ++i) {
    out[i] =
        static_cast<uint8_t>((calls * 0x9DU) ^ (static_cast<uint32_t>(i) * 0x3BU) ^ (calls >> 8U));
  }
  return true;
}

} // namespace se05x::testmodel

#endif // SE05X_TESTS_MODEL_SCP_SCRIPT_HPP
