/**
 * @file se05x_objects.hpp
 * @brief Object attribute parsing and the check of a policy set read back from the chip.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * The public surface below is frozen.
 *
 * The attribute block (AN12543 3.2.4 Tables 3 and 4, applet 7.x; AN12413 3.2.4 Table 3, applet
 * 3.x) is 14 fixed bytes, the policy set, the origin and, on 7.x only, a 4-byte version:
 *
 * | Bytes | Authentication object | Other object |
 * | --- | --- | --- |
 * | 0-3 | identifier | identifier |
 * | 4 | SecureObjectType | SecureObjectType |
 * | 5 | authentication indicator (SetIndicator) | authentication indicator |
 * | 6-7 | failed attempts counter | minimum AEAD tag length (7.x) |
 * | 8-11 | session owner | session owner |
 * | 12-13 | maximum attempts (0: unlimited) | minimum output length (7.x) |
 *
 * The block carries no generation, so the parser tells the layout by its trailer: the policy set
 * must parse exactly between byte 14 and the trailer of 5 (7.x) or 1 (3.x) bytes. The two cannot
 * both parse, because a policy is at least 9 bytes and the trailers differ by 4. The policy set is
 * the concatenation of policies `L | auth id (4) | header (4) | extensions`, `L` from 8 to 52.
 * Derived from the documents; not verified against a chip.
 */
#ifndef SE05X_OBJECTS_HPP
#define SE05X_OBJECTS_HPP

#include <cstddef>
#include <cstdint>

#include "se05x_apdu_consts.hpp"
#include "se05x_device_types.hpp"
#include "se05x_ids.hpp"
#include "se05x_policy.hpp"
#include "se05x_status.hpp"
#include "se05x_types.hpp"

namespace se05x {

namespace detail {

/// The fixed bytes before the policy set.
inline constexpr std::size_t kAttributeHead = 14U;
/// The trailer of an applet 7.x block: origin and 4-byte version.
inline constexpr std::size_t kTrailerV7 = 5U;
/// The trailer of an applet 3.x block: origin.
inline constexpr std::size_t kTrailerV3 = 1U;

/**
 * @brief A big-endian number of 2 or 4 bytes at `pos`.
 * @param b The bytes.
 * @param pos The position.
 * @param n 2 or 4.
 * @return The number.
 */
constexpr uint32_t ReadBe(ByteSpan b, std::size_t pos, std::size_t n) noexcept {
  uint32_t v = 0U;
  for (std::size_t i = 0U; i < n; ++i) {
    v = (v << 8U) | static_cast<uint32_t>(b[pos + i]);
  }
  return v;
}

} // namespace detail

namespace policy {

/**
 * @brief Whether a policy set is well formed: each policy has a length of 8 to 52, an extension
 * of exactly the length its header needs, no RFU header bit, and a distinct authentication object
 * id; the policies fill the set exactly. The empty set (default policy) is well formed.
 * @param set The policy set.
 * @return true when well formed.
 */
constexpr bool PolicySetWellFormed(ByteSpan set) noexcept {
  constexpr std::size_t kMaxPolicies = kMaxPolicyBytes / (kPolicyBase + 1U);
  std::array<uint32_t, kMaxPolicies + 1U> seen{};
  std::size_t pos = 0U;
  std::size_t n = 0U;
  while ((pos < set.size()) && (n <= kMaxPolicies)) {
    const std::size_t length = set[pos];
    if ((length < kPolicyBase) || (length > kPolicyMax) || (length > (set.size() - pos - 1U))) {
      return false;
    }
    const uint32_t auth = detail::ReadBe(set, pos + 1U, 4U);
    const uint32_t header = detail::ReadBe(set, pos + 5U, 4U);
    if (((header & kRfuBits) != 0U) || (length != (kPolicyBase + ExtensionLength(header)))) {
      return false;
    }
    for (std::size_t i = 0U; i < n; ++i) {
      if (seen[i] == auth) {
        return false;
      }
    }
    seen[n] = auth;
    ++n;
    pos += 1U + length;
  }
  return (pos == set.size()) && (set.size() <= kMaxPolicyBytes);
}

} // namespace policy

namespace detail {

/**
 * @brief Parse the block with a given trailer.
 * @param bytes The block.
 * @param trailer 5 (7.x) or 1 (3.x).
 * @param out Receives the attributes.
 * @return true when every field is valid in that layout.
 */
constexpr bool ParseAttributesAs(ByteSpan bytes, std::size_t trailer,
                                 ObjectAttributes& out) noexcept {
  if (bytes.size() < (kAttributeHead + trailer)) {
    return false;
  }
  const std::size_t policy_end = bytes.size() - trailer;
  const ByteSpan policy = bytes.subspan(kAttributeHead, policy_end - kAttributeHead);
  const uint8_t indicator = bytes[5];
  ObjectAttributes a{};
  if (!apdu::ClassFromWire(bytes[4], a.object_class) ||
      !apdu::OriginFromWire(bytes[policy_end], a.origin) ||
      ((indicator != apdu::kSetIndicatorSet) && (indicator != apdu::kSetIndicatorNotSet))) {
    return false;
  }
  if ((policy.size() > a.policy.bytes.size()) || !policy::PolicySetWellFormed(policy)) {
    return false;
  }
  a.authentication = ObjectId{ReadBe(bytes, 8U, 4U)};
  if (indicator == apdu::kSetIndicatorSet) {
    const auto failed = static_cast<uint16_t>(ReadBe(bytes, 6U, 2U));
    a.max_attempts = static_cast<uint16_t>(ReadBe(bytes, 12U, 2U));
    if (a.max_attempts == 0U) {
      a.attempts_left = 0xFFFFU; // unlimited
    } else {
      a.attempts_left =
          (failed >= a.max_attempts) ? 0U : static_cast<uint16_t>(a.max_attempts - failed);
    }
  }
  a.version = (trailer == kTrailerV7) ? ReadBe(bytes, policy_end + 1U, 4U) : 0U;
  for (std::size_t i = 0U; i < policy.size(); ++i) {
    a.policy.bytes[i] = policy[i];
  }
  a.policy.length = policy.size();
  out = a;
  return true;
}

} // namespace detail

/**
 * @brief Parse the attribute block of an object (class, authentication object, attempt counters,
 * origin, policy set; the version on applet 7.x).
 *
 * `lifetime` is not in the block and stays `Persistent` (`ReadType` tells it). For an
 * authentication object `attempts_left` is the maximum minus the failed attempts, or 0xFFFF when
 * the attempts are unlimited (maximum 0); for other objects both counters are 0.
 *
 * @param bytes The block as returned by the chip.
 * @return The attributes, or `FrameError` for a malformed block.
 */
constexpr Result<ObjectAttributes> ParseObjectAttributes(ByteSpan bytes) noexcept {
  ObjectAttributes a{};
  if (detail::ParseAttributesAs(bytes, detail::kTrailerV7, a) ||
      detail::ParseAttributesAs(bytes, detail::kTrailerV3, a)) {
    return Result<ObjectAttributes>::Success(a);
  }
  return Result<ObjectAttributes>::Failure(
      Error::FrameError,
      Detail{.sw = 0U, .command = 0xFFU, .layer = Layer::Apdu, .step = 0U, .attempts_left = 0xFFU});
}

/**
 * @brief Whether a policy set read back from the chip is well formed (lengths, extensions, header
 * RFU bits, distinct authentication objects).
 * @param policy The policy bytes.
 * @return `Ok` or `PolicyInvalid`.
 */
constexpr Error ValidatePolicyBytes(ByteSpan policy) noexcept {
  return policy::PolicySetWellFormed(policy) ? Error::Ok : Error::PolicyInvalid;
}

} // namespace se05x

#endif // SE05X_OBJECTS_HPP
