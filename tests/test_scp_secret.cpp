/**
 * @file test_scp_secret.cpp
 * @brief `Zeroize`, `SecretBuffer`, `ct::Equal`, `AttemptLimiter` and the UserID rules (S-01,
 * S-08, S-14).
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <type_traits>

#include "se05x_secret.hpp"
#include "test_harness.hpp"

using namespace se05x;

static_assert(!std::is_copy_constructible_v<SecretBuffer<16>>);
static_assert(!std::is_copy_assignable_v<SecretBuffer<16>>);
static_assert(ct::Equal(ByteSpan{}, ByteSpan{}));
static_assert(!userid::kCarriesSecureMessaging);

TEST_CASE("Zeroize clears every byte, and an empty span is fine") {
  std::array<uint8_t, 33> buf{};
  buf.fill(0xA5U);
  Zeroize(MutableByteSpan{buf});
  bool all_zero = true;
  for (const uint8_t b : buf) {
    all_zero = all_zero && (b == 0U);
  }
  CHECK(all_zero);
  Zeroize(MutableByteSpan{});
}

TEST_CASE("SecretBuffer wipes on Reserve, on Wipe and on destruction") {
  std::optional<SecretBuffer<16>> holder;
  holder.emplace();
  const auto raw = std::as_bytes(std::span<const SecretBuffer<16>, 1>{&*holder, 1U});
  const MutableByteSpan view = holder->Reserve(16U);
  REQUIRE(view.size() == 16U);
  for (uint8_t& b : view) {
    b = 0x5AU;
  }
  CHECK_EQ(holder->Span().size(), 16U);
  const MutableByteSpan again = holder->Reserve(4U); // previous content wiped
  CHECK_EQ(again.size(), 4U);
  CHECK_EQ(again[0], 0U);
  CHECK_EQ(view[15], 0U);
  again[0] = 0x77U;
  // The destructor is `Wipe()`; its effect is checked here on the live object, because reading
  // the storage of a destroyed object is undefined behaviour. The secret bytes come first in the
  // object; the volatile wipe cannot be removed as a dead store.
  holder->Wipe();
  bool all_zero = true;
  for (std::size_t i = 0U; i < 16U; ++i) {
    all_zero = all_zero && (raw[i] == std::byte{0U});
  }
  CHECK(all_zero);
  CHECK(holder->Span().empty());
  holder.reset();
}

TEST_CASE("SecretBuffer refuses a reservation above its capacity") {
  SecretBuffer<8> s;
  const MutableByteSpan v = s.Reserve(8U);
  v[7] = 1U;
  CHECK(s.Reserve(9U).empty());
  CHECK(s.Span().empty());
  CHECK_EQ(SecretBuffer<8>::Capacity(), 8U);
  s.Wipe();
  CHECK(s.Span().empty());
}

TEST_CASE("ct::Equal finds a difference in every byte position and refuses other lengths") {
  std::array<uint8_t, 16> a{};
  for (std::size_t i = 0U; i < a.size(); ++i) {
    a[i] = static_cast<uint8_t>(i * 17U);
  }
  CHECK(ct::Equal(ByteSpan{a}, ByteSpan{a}));
  bool all_found = true;
  for (std::size_t i = 0U; i < a.size(); ++i) {
    for (uint32_t bit = 0U; bit < 8U; ++bit) {
      auto b = a;
      b[i] = static_cast<uint8_t>(b[i] ^ (1U << bit));
      all_found = all_found && !ct::Equal(ByteSpan{a}, ByteSpan{b});
    }
  }
  CHECK(all_found);
  CHECK(!ct::Equal(ByteSpan(a.data(), 15U), ByteSpan{a}));
  CHECK(!ct::Equal(ByteSpan{a}, ByteSpan{}));
}

TEST_CASE("AttemptLimiter counts failures in a row and a success starts again") {
  AttemptLimiter limiter{3U};
  CHECK(!limiter.Exhausted());
  CHECK_EQ(limiter.Remaining(), 3U);
  limiter.RecordFailure();
  limiter.RecordFailure();
  CHECK_EQ(limiter.Remaining(), 1U);
  CHECK(!limiter.Exhausted());
  limiter.RecordFailure();
  CHECK(limiter.Exhausted());
  CHECK_EQ(limiter.Remaining(), 0U);
  limiter.RecordFailure(); // saturates
  CHECK_EQ(limiter.Remaining(), 0U);
  limiter.RecordSuccess();
  CHECK(!limiter.Exhausted());
  CHECK_EQ(limiter.Remaining(), 3U);
}

TEST_CASE("AttemptLimiter: a zero limit still allows one attempt, the default is 3") {
  AttemptLimiter zero{0U};
  CHECK_EQ(zero.Limit(), 1U);
  CHECK(!zero.Exhausted());
  zero.RecordFailure();
  CHECK(zero.Exhausted());
  const AttemptLimiter def{};
  CHECK_EQ(def.Limit(), AttemptLimiter::kDefaultLimit);
  CHECK_EQ(def.Limit(), 3U);
}

TEST_CASE("UserID: an infinite attempt counter is refused in every generation (S-14)") {
  CHECK_EQ(userid::CheckCredential(AppletGeneration::V7, 8U, 0U), Error::PolicyInvalid);
  CHECK_EQ(userid::CheckCredential(AppletGeneration::V3, 8U, 0U), Error::PolicyInvalid);
  CHECK_EQ(userid::CheckCredential(AppletGeneration::V6, 8U, 0U), Error::PolicyInvalid);
  CHECK_EQ(userid::CheckCredential(AppletGeneration::V7, 8U, 1U), Error::Ok);
  CHECK_EQ(userid::CheckCredential(AppletGeneration::V7, 8U, 255U), Error::Ok);
}

TEST_CASE("UserID: length 4 to 16 on 6.x and 7.x, 1 to 16 on 3.x") {
  CHECK_EQ(userid::CheckCredential(AppletGeneration::V7, 3U, 5U), Error::InvalidArgument);
  CHECK_EQ(userid::CheckCredential(AppletGeneration::V7, 4U, 5U), Error::Ok);
  CHECK_EQ(userid::CheckCredential(AppletGeneration::V6, 3U, 5U), Error::InvalidArgument);
  CHECK_EQ(userid::CheckCredential(AppletGeneration::V3, 1U, 5U), Error::Ok);
  CHECK_EQ(userid::CheckCredential(AppletGeneration::V3, 0U, 5U), Error::InvalidArgument);
  CHECK_EQ(userid::CheckCredential(AppletGeneration::V7, 16U, 5U), Error::Ok);
  CHECK_EQ(userid::CheckCredential(AppletGeneration::V7, 17U, 5U), Error::InvalidArgument);
  CHECK_EQ(userid::CheckCredential(AppletGeneration::V3, 17U, 5U), Error::InvalidArgument);
  CHECK_EQ(userid::CheckValue(0U), Error::InvalidArgument);
  CHECK_EQ(userid::CheckValue(1U), Error::Ok);
  CHECK_EQ(userid::CheckValue(16U), Error::Ok);
  CHECK_EQ(userid::CheckValue(17U), Error::InvalidArgument);
}
