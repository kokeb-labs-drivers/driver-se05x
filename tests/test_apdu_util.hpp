/**
 * @file test_apdu_util.hpp
 * @brief Helpers of the APDU, policy, gate and attestation tests: hex literals, byte
 * comparison with a printed difference, and encode/decode shortcuts.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * The expected bytes of every codec test are written by hand from the tables of AN12543 and
 * AN12413 (cited in each test); they are not produced by the library, so a wrong table in the
 * library and a wrong expectation cannot cancel.
 */
#ifndef SE05X_TEST_APDU_UTIL_HPP
#define SE05X_TEST_APDU_UTIL_HPP

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <type_traits>

#include "se05x_apdu_codec.hpp"
#include "test_harness.hpp"

namespace tu {

/// A value of enumeration `E` that is none of its enumerators, for the refusal tests (a bit copy,
/// so the analyser does not take the test's deliberate out-of-range value for a mistake).
template <typename E>
constexpr E NotAnEnumerator(std::underlying_type_t<E> raw) noexcept {
  return std::bit_cast<E>(raw);
}

using se05x::ByteSpan;
using se05x::MutableByteSpan;

/** @brief Bytes held by value, built from a hex string. */
struct Bytes {
  std::array<uint8_t, 1200> b{}; ///< Storage.
  std::size_t n{0};              ///< Length.
  bool ok{true};                 ///< The hex string was well formed.
  /** @return The bytes. */
  [[nodiscard]] ByteSpan View() const noexcept {
    return ByteSpan{b.data(), n};
  }
};

/**
 * @brief The value of a hex digit.
 * @param c The character.
 * @return 0 to 15, or -1.
 */
constexpr int Nibble(char c) noexcept {
  const auto b = static_cast<int>(std::bit_cast<uint8_t>(c)); // ASCII code, no char arithmetic
  if ((b >= 0x30) && (b <= 0x39)) {
    return b - 0x30;
  }
  if ((b >= 0x61) && (b <= 0x66)) {
    return (b - 0x61) + 10;
  }
  if ((b >= 0x41) && (b <= 0x46)) {
    return (b - 0x41) + 10;
  }
  return -1;
}

/**
 * @brief Parse a hex string; spaces and `|` are ignored.
 * @param s The string.
 * @return The bytes.
 */
constexpr Bytes Hex(const char* s) noexcept {
  Bytes out{};
  int high = -1;
  for (std::size_t i = 0U; std::bit_cast<uint8_t>(s[i]) != 0U; ++i) {
    const auto code = std::bit_cast<uint8_t>(s[i]);
    if ((code == 0x20U) || (code == 0x7CU)) { // ' ' and '|'
      continue;
    }
    const int v = Nibble(s[i]);
    if ((v < 0) || (out.n >= out.b.size())) {
      out.ok = false;
      return out;
    }
    if (high < 0) {
      high = v;
    } else {
      out.b[out.n] =
          static_cast<uint8_t>((static_cast<uint32_t>(high) << 4U) | static_cast<uint32_t>(v));
      ++out.n;
      high = -1;
    }
  }
  out.ok = out.ok && (high < 0);
  return out;
}

/**
 * @brief Print two byte strings.
 * @param what The label.
 * @param got The bytes produced.
 * @param want The bytes expected.
 */
inline void Dump(const char* what, ByteSpan got, ByteSpan want) {
  static_cast<void>(std::printf("    %s\n      got  (%zu):", what, got.size()));
  for (const uint8_t v : got) {
    static_cast<void>(std::printf(" %02X", static_cast<unsigned>(v)));
  }
  static_cast<void>(std::printf("\n      want (%zu):", want.size()));
  for (const uint8_t v : want) {
    static_cast<void>(std::printf(" %02X", static_cast<unsigned>(v)));
  }
  static_cast<void>(std::printf("\n"));
}

/**
 * @brief Whether two byte strings are equal; prints both when not.
 * @param got The bytes produced.
 * @param want The bytes expected.
 * @return true when equal.
 */
inline bool Same(ByteSpan got, ByteSpan want) {
  bool same = got.size() == want.size();
  for (std::size_t i = 0U; same && (i < got.size()); ++i) {
    same = got[i] == want[i];
  }
  if (!same) {
    Dump("bytes differ", got, want);
  }
  return same;
}

/** @brief A command buffer of the largest command APDU. */
using CommandBuffer = std::array<uint8_t, se05x::kMaxCommandApdu>;

/**
 * @brief Encode command `C` and compare with a hex string.
 * @tparam C The command.
 * @param args The arguments.
 * @param hex The expected APDU.
 * @return true when equal.
 */
template <se05x::Command C>
bool EncodesTo(const se05x::ArgsOf<C>& args, const char* hex) {
  CommandBuffer buf{};
  const auto r = se05x::Codec<C>::Encode(args, MutableByteSpan{buf});
  const Bytes want = Hex(hex);
  if (!r.ok()) {
    static_cast<void>(
        std::printf("    encode of %s failed: %s\n", se05x::ToString(C), se05x::ToString(r.error)));
    return false;
  }
  return want.ok && Same(ByteSpan{buf.data(), r.value}, want.View());
}

/**
 * @brief Encode command `C` and return the error.
 * @tparam C The command.
 * @param args The arguments.
 * @return The error, `Ok` on success.
 */
template <se05x::Command C>
se05x::Error EncodeError(const se05x::ArgsOf<C>& args) {
  CommandBuffer buf{};
  const auto r = se05x::Codec<C>::Encode(args, MutableByteSpan{buf});
  bool zeroed = true;
  for (const uint8_t v : buf) {
    zeroed = zeroed && (v == 0U);
  }
  if (!r.ok() && !zeroed) {
    static_cast<void>(
        std::printf("    a failed encode of %s left bytes in the buffer\n", se05x::ToString(C)));
    return se05x::Error::Ok; // makes the caller's check fail
  }
  return r.error;
}

/**
 * @brief Decode a hex response body for command `C` (three-argument form).
 * @tparam C The command.
 * @param args The arguments.
 * @param hex The body.
 * @param reply The reply.
 * @return The error, `Ok` on success.
 */
template <se05x::Command C>
se05x::Error Decode(const se05x::ArgsOf<C>& args, const char* hex, se05x::ReplyOf<C>& reply) {
  const Bytes body = Hex(hex);
  return se05x::Codec<C>::Decode(args, body.View(), reply).error;
}

/**
 * @brief Whether a fixed reply holds the bytes of a hex string.
 * @tparam N The capacity.
 * @param got The reply.
 * @param hex The bytes.
 * @return true when equal.
 */
template <std::size_t N>
bool Holds(const se05x::FixedBytes<N>& got, const char* hex) {
  return Same(got.View(), Hex(hex).View());
}

/**
 * @brief Whether the first `n` bytes of a buffer equal a hex string.
 * @param buf The buffer.
 * @param n The length.
 * @param hex The bytes.
 * @return true when equal.
 */
inline bool Prefix(ByteSpan buf, std::size_t n, const char* hex) {
  return (n <= buf.size()) && Same(buf.first(n), Hex(hex).View());
}

} // namespace tu

#endif // SE05X_TEST_APDU_UTIL_HPP
