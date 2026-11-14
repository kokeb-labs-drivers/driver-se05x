/**
 * @file se05x_secret.hpp
 * @brief Handling of secrets: `Zeroize()`, `SecretBuffer<N>` and the constant-time compare
 * `ct::Equal()`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * The public surface is frozen; the bodies below are small and complete so that every layer can use
 * them, and their tests and mutants cover them (compiler-barrier proof for `Zeroize`, timing-model
 * mutant for `Equal`, S-01 and S-08).
 *
 * Every secret the library holds, even for one call, lives in a `SecretBuffer` (S-01): it is wiped
 * on every exit path by its destructor. A MAC, cryptogram, receipt, freshness value or PIN-like
 * secret is compared only with `ct::Equal()`; `memcmp` is forbidden in `inc/` (S-08).
 *
 * The UserID rules of S-14 live here too, so every layer that writes or opens a UserID object
 * applies the same ones: `userid::CheckCredential()` refuses the infinite attempt counter (the
 * default, AN12543 Table 120 TAG_MAX_ATTEMPTS: 0 means unlimited) and lengths outside the
 * generation's range, and `AttemptLimiter` counts failed authentications on the host so a loop
 * cannot burn the chip's own counter.
 */
#ifndef SE05X_SECRET_HPP
#define SE05X_SECRET_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "se05x_detail.hpp"
#include "se05x_types.hpp"

namespace se05x {

/**
 * @brief Overwrite bytes with zero in a way the optimiser may not remove (S-01).
 * @param bytes The buffer to wipe.
 */
inline void Zeroize(MutableByteSpan bytes) noexcept {
  volatile uint8_t* const target = bytes.data();
  for (std::size_t i = 0U; i < bytes.size(); ++i) {
    target[i] = static_cast<uint8_t>(0U);
  }
}

/**
 * @brief Overwrite an array of unsigned words with zero, like `Zeroize()` (S-01): hash and
 * big-number state.
 * @tparam T An unsigned integer type.
 * @tparam N The number of words.
 * @param words The array to wipe.
 */
template <typename T, std::size_t N>
  requires std::is_unsigned_v<T>
inline void ZeroizeWords(std::array<T, N>& words) noexcept {
  volatile T* const target = words.data();
  for (std::size_t i = 0U; i < N; ++i) {
    target[i] = T{0};
  }
}

/**
 * @brief Up to `N` secret bytes, wiped when the object dies, is wiped, or is reused.
 *
 * Not copyable and not movable: a secret has one home. `Span()` gives the stored bytes; keep the
 * view no longer than the buffer.
 *
 * @tparam N Capacity in bytes.
 */
template <std::size_t N>
class SecretBuffer {
public:
  /** @brief An empty buffer. */
  SecretBuffer() noexcept = default;
  /** @brief A secret has one home. */
  SecretBuffer(const SecretBuffer&) = delete;
  /** @brief A secret has one home. */
  SecretBuffer& operator=(const SecretBuffer&) = delete;
  /** @brief Wipes the bytes. */
  ~SecretBuffer() noexcept {
    Wipe();
  }

  /** @brief Wipe the bytes and set the length to 0. */
  void Wipe() noexcept {
    Zeroize(MutableByteSpan{data_});
    length_ = 0U;
  }

  /**
   * @brief Take `length` writable bytes; the previous content is wiped.
   * @param length Number of bytes, at most `N`.
   * @return A writable view of `length` bytes, or an empty view when `length` exceeds `N`.
   */
  [[nodiscard]] MutableByteSpan Reserve(std::size_t length) noexcept {
    Wipe();
    if (length > N) {
      return MutableByteSpan{};
    }
    length_ = length;
    return MutableByteSpan{data_.data(), length_};
  }

  /** @return The stored bytes. */
  [[nodiscard]] ByteSpan Span() const& noexcept {
    return ByteSpan{data_.data(), length_};
  }
  /** @brief Not on a temporary: the view would dangle (KB-CPP20-044). */
  void Span() const&& = delete;

  /** @return The capacity in bytes. */
  [[nodiscard]] static constexpr std::size_t Capacity() noexcept {
    return N;
  }

private:
  std::array<uint8_t, N> data_{};
  std::size_t length_{0};
};

/** @brief Constant-time operations on secret-dependent data (S-08). */
namespace ct {

/**
 * @brief Compare two byte strings without an early exit.
 *
 * The time depends on the length only: every byte of the shorter-or-equal length is visited.
 * Strings of different lengths are unequal.
 *
 * @param a The first string.
 * @param b The second string.
 * @return true when equal.
 */
[[nodiscard]] constexpr bool Equal(ByteSpan a, ByteSpan b) noexcept {
  if (a.size() != b.size()) {
    return false;
  }
  auto difference = static_cast<uint8_t>(0U);
  for (std::size_t i = 0U; i < a.size(); ++i) {
    difference = static_cast<uint8_t>(difference | static_cast<uint8_t>(a[i] ^ b[i]));
  }
  return difference == static_cast<uint8_t>(0U);
}

} // namespace ct

/**
 * @brief Host-side count of failed authentications (S-14): after `Limit()` failures in a row the
 * owner refuses to try again without sending anything; a success resets the count.
 */
class AttemptLimiter {
public:
  /// The default limit, equal to `Config{}.auth_attempt_limit`.
  static constexpr uint8_t kDefaultLimit = 3U;

  /** @brief A limiter with the default limit. */
  constexpr AttemptLimiter() noexcept = default;
  /**
   * @brief A limiter with a given limit.
   * @param limit Failures allowed in a row; 0 is raised to 1 so that a limiter never blocks the
   * first attempt.
   */
  explicit constexpr AttemptLimiter(uint8_t limit) noexcept
      : limit_((limit == 0U) ? static_cast<uint8_t>(1U) : limit) {}

  /** @return true when no further attempt may be made. */
  [[nodiscard]] constexpr bool Exhausted() const noexcept {
    return failures_ >= limit_;
  }
  /** @return Attempts left before `Exhausted()`. */
  [[nodiscard]] constexpr uint8_t Remaining() const noexcept {
    return Exhausted() ? static_cast<uint8_t>(0U) : static_cast<uint8_t>(limit_ - failures_);
  }
  /** @return The limit. */
  [[nodiscard]] constexpr uint8_t Limit() const noexcept {
    return limit_;
  }
  /** @brief Count one failed authentication; saturates at the limit. */
  constexpr void RecordFailure() noexcept {
    if (failures_ < limit_) {
      ++failures_;
    }
  }
  /** @brief A successful authentication: the count starts again. */
  constexpr void RecordSuccess() noexcept {
    failures_ = 0U;
  }

private:
  uint8_t limit_{kDefaultLimit};
  uint8_t failures_{0};
};

/** @brief The rules for UserID authentication objects and sessions (S-14). */
namespace userid {

/// Shortest UserID value on applet 3.x (AN12413 WriteUserID: 1 to 16 bytes).
inline constexpr std::size_t kMinLengthV3 = 1U;
/// Shortest UserID value on applet 6.x and 7.x (AN12543 4.7.1.5, Table 120: 4 to 16 bytes).
inline constexpr std::size_t kMinLengthV7 = 4U;
/// Longest UserID value, every generation.
inline constexpr std::size_t kMaxLength = 16U;
/// A UserID session carries no secure messaging on the wire (AN12543 3.6.3.1): it is a plain,
/// unencrypted session. Nothing secret may travel over it unless platform SCP03 is underneath.
inline constexpr bool kCarriesSecureMessaging = false;

/**
 * @brief Check a UserID object before it is written.
 * @param generation The applet generation of the chip.
 * @param length The length of the UserID value.
 * @param max_attempts The attempt limit to store; 0 means infinite on the chip.
 * @return `Ok`; `InvalidArgument` for a length outside the generation's range; `PolicyInvalid`
 * for an infinite attempt counter, which never locks out a brute force (S-14).
 */
constexpr Error CheckCredential(AppletGeneration generation, std::size_t length,
                                uint8_t max_attempts) noexcept {
  const std::size_t min = (generation == AppletGeneration::V3) ? kMinLengthV3 : kMinLengthV7;
  if ((length < min) || (length > kMaxLength)) {
    return Error::InvalidArgument;
  }
  if (max_attempts == 0U) {
    return Error::PolicyInvalid;
  }
  return Error::Ok;
}

/**
 * @brief Check a UserID value before it is sent in `VerifySessionUserID`.
 * @param length The length of the value.
 * @return `Ok` or `InvalidArgument` outside 1 to 16 bytes (the widest range of any generation).
 */
constexpr Error CheckValue(std::size_t length) noexcept {
  return ((length >= kMinLengthV3) && (length <= kMaxLength)) ? Error::Ok : Error::InvalidArgument;
}

} // namespace userid

} // namespace se05x

#endif // SE05X_SECRET_HPP
