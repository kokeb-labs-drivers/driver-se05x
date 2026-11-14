/**
 * @file bytes.hpp
 * @brief Byte copy and compare for the tests and the chip model, safe for an empty range.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * `std::memcpy` and `std::memcmp` need valid pointers even for a length of 0, and the data
 * pointer of an empty span may be null. These helpers do nothing for an empty range, so a test
 * that moves zero bytes is defined behaviour (and quiet under UBSan).
 */
#ifndef SE05X_TESTS_MODEL_BYTES_HPP
#define SE05X_TESTS_MODEL_BYTES_HPP

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace se05x::testmodel {

/** @brief Copy `n` bytes from `from` to `to` (the ranges do not overlap); nothing when `n` is 0. */
inline void CopyBytes(uint8_t* to, const uint8_t* from, std::size_t n) noexcept {
  if (n != 0U) {
    static_cast<void>(std::copy_n(from, n, to));
  }
}

/** @return Whether the `n` bytes at `a` and `b` are equal; true when `n` is 0. */
inline bool SameBytes(const uint8_t* a, const uint8_t* b, std::size_t n) noexcept {
  bool same = true;
  for (std::size_t i = 0U; same && (i < n); ++i) {
    same = a[i] == b[i];
  }
  return same;
}

} // namespace se05x::testmodel

#endif // SE05X_TESTS_MODEL_BYTES_HPP
