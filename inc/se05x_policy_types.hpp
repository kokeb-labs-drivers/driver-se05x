/**
 * @file se05x_policy_types.hpp
 * @brief The data types of object and session policies: rules, profiles, `Policy`, `SessionPolicy`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Frozen contract. A caller never assembles a policy from bytes: the only way to get a `Policy` is
 * `PolicyBuilder<Generation, Class, Profile>::Build()` (declared in `se05x_policy.hpp`), and
 * `Policy::Bytes()` is the only way out. The `Strict` profile is the one the facade uses (S-03): a
 * key created with the default policy would keep `ALLOW_WRITE`, `ALLOW_DELETE` and `ALLOW_GEN`, so
 * `Strict` demands that they are forbidden explicitly. `Open` needs a named `OpenReason`.
 */
#ifndef SE05X_POLICY_TYPES_HPP
#define SE05X_POLICY_TYPES_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "se05x_detail.hpp"
#include "se05x_ids.hpp"
#include "se05x_types.hpp"

namespace se05x {

/**
 * @defgroup se05x_policy_types Policy types
 * @brief Rules, profiles and the `Policy` value.
 * @{
 */

/**
 * @brief The access rules of an object policy (AN12413 policy tables; the applet 7.x additions
 * included). Which rules apply to which `ObjectClass` is the table of `se05x_policy.hpp`.
 */
enum class Rule : uint8_t {
  ForbidAll = 0,    ///< Nothing is allowed for this authentication object.
  Sign = 1,         ///< Signing.
  Verify = 2,       ///< Verification.
  KeyAgreement = 3, ///< ECDH.
  Encrypt = 4,      ///< Encryption.
  Decrypt = 5,      ///< Decryption.
  Kdf = 6,          ///< Key derivation (HMAC-based) with the object as key.
  Wrap = 7,         ///< Wrapping with the object as the key encryption key.
  Read = 8,         ///< Reading the object's value.
  Write = 9,        ///< Writing the object.
  Gen = 10,         ///< Generating the key in place.
  Delete = 11,      ///< Deleting the object.
  RequireSecureMessaging =
      12,               ///< Only inside platform SCP03 or an applet session with secure messaging.
  RequirePcrValue = 13, ///< Only while a PCR holds a given value.
  Attestation = 14,     ///< Attested reads with this object as attestation key.
  DesfireAuthentication = 15,  ///< MIFARE DESFire authentication.
  DesfireDumpSessionKeys = 16, ///< MIFARE DESFire session key dump.
  ImportExport = 17,           ///< Export and import of the serialised object.
  ForbidDerivedOutput = 18,    ///< Derived keys cannot be read out.
  KdfExtRandom = 19,           ///< KDF with external random (applet 7.x).
  TlsKdf = 20,                 ///< TLS KDF.
  TlsPms = 21,                 ///< TLS premaster secret.
  Hkdf = 22,                   ///< HKDF.
  DesfireChangeKey = 23,       ///< DESFire change key.
  DerivedInput = 24,           ///< Use as KDF input.
  Pbkdf = 25,                  ///< PBKDF2.
  DesfireKdf = 26,             ///< DESFire KDF.
  ForbidExternalIv = 27,       ///< Refuse an IV supplied by the host.
  UsageAsHmacPepper = 28,      ///< Use as an HMAC pepper.
};

/** @brief How strictly a built policy is checked (S-03). */
enum class Profile : uint8_t {
  Strict = 0, ///< Write, delete and generate are forbidden explicitly; secure messaging required
              ///< for private keys.
  Open = 1,   ///< The caller gives an `OpenReason`; refused for private-key reads even then.
};

/** @brief Why a caller needs the `Open` profile; the reason is recorded in the provisioning
 * manifest. */
enum class OpenReason : uint8_t {
  None = 0,                    ///< No reason: only valid with the `Strict` profile.
  PublicDataObject = 1,        ///< A binary file that holds public data and must stay writable.
  TransientScratch = 2,        ///< A transient object used within one session.
  FactoryProvisioning = 3,     ///< An object a factory flow rewrites until the device is released.
  InteropWithExistingKeys = 4, ///< Matching an installed base created with other rules.
  Laboratory = 5,              ///< Bring-up on a development kit.
};

namespace detail {
/// Last enumerator of `Rule`.
template <>
struct EnumLast<Rule> {
  static constexpr Rule kValue = Rule::UsageAsHmacPepper; ///< The last enumerator.
};
/// Last enumerator of `Profile`.
template <>
struct EnumLast<Profile> {
  static constexpr Profile kValue = Profile::Open; ///< The last enumerator.
};
/// Last enumerator of `OpenReason`.
template <>
struct EnumLast<OpenReason> {
  static constexpr OpenReason kValue = OpenReason::Laboratory; ///< The last enumerator.
};
} // namespace detail

/** @brief The authentication object a policy entry is for. */
struct AuthObject {
  ObjectId id{}; ///< The authentication object; `ObjectId{0}` is not valid.
};

template <AppletGeneration G, ObjectClass C, Profile P>
class PolicyBuilder;

/**
 * @brief A validated object policy set: at most `kMaxPolicyBytes` bytes in the chip's format.
 *
 * Only `PolicyBuilder::Build()` creates a non-empty one. The default value is empty and invalid
 * (`IsEmpty()`); every command that takes a policy refuses an empty one with `InvalidArgument`.
 */
class Policy {
public:
  /** @brief The empty, invalid policy. */
  constexpr Policy() noexcept = default;

  /** @return The policy in the chip's wire format: the only way out of a `Policy`. */
  [[nodiscard]] constexpr ByteSpan Bytes() const& noexcept {
    return ByteSpan{bytes_.data(), length_};
  }
  /** @brief Not on a temporary: the view would dangle (KB-CPP20-044). */
  void Bytes() const&& = delete;

  /** @return true for the default, invalid policy. */
  [[nodiscard]] constexpr bool IsEmpty() const noexcept {
    return length_ == 0U;
  }
  /**
   * @return The applet generation the policy layout is for. `Device` refuses a policy whose
   * generation differs from the chip's with `PolicyInvalid` before anything is sent.
   */
  [[nodiscard]] constexpr AppletGeneration Generation() const noexcept {
    return generation_;
  }
  /** @return The profile the policy was built with. */
  [[nodiscard]] constexpr Profile GetProfile() const noexcept {
    return profile_;
  }

private:
  template <AppletGeneration G, ObjectClass C, Profile P>
  friend class PolicyBuilder;

  constexpr Policy(const std::array<uint8_t, kMaxPolicyBytes>& bytes, std::size_t length,
                   Profile profile, AppletGeneration generation) noexcept
      : bytes_(bytes), length_(length), profile_(profile), generation_(generation) {}

  std::array<uint8_t, kMaxPolicyBytes> bytes_{};
  std::size_t length_{0};
  Profile profile_{Profile::Strict};
  AppletGeneration generation_{AppletGeneration::V3};
};

/** @brief A session policy (AN12413 session policy): how long and how often a session may be used.
 */
struct SessionPolicy {
  uint16_t max_apdus{0};     ///< Most commands in the session; 0 means no limit.
  uint16_t max_time{0};      ///< Longest session time in the chip's time unit; 0 means no limit.
  bool allow_refresh{false}; ///< Whether `RefreshSession` is allowed.
};

/** @} */

} // namespace se05x

#endif // SE05X_POLICY_TYPES_HPP
