/**
 * @file se05x_policy.hpp
 * @brief The typed policy builder.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * The public surface below is frozen; the library adds the
 * private state and the helpers in `se05x::policy`.
 *
 * A policy cannot be assembled from bytes by the caller. A rule that is invalid for the object
 * class in the applet generation fails to compile (`Allow<Rule::Sign>()` on a `BinaryFile`
 * builder). `Build()` applies the chip's own validation (AN12543 3.7.1: one policy is 9 to 53
 * bytes, a length, a 4-byte authentication object id, a 4-byte access rule header and the
 * extensions in header bit order; unique authentication object ids; at most `kMaxPolicyBytes` in
 * all) and the checks of the profile (S-03). The rule tables are AN12413 Table 11 (applet 3.x) and
 * AN12543 Table 15 (applet 7.x); the bit values are AN12413 Table 50 and AN12543 Table 63, which
 * the middleware's `se05x_const.h` agrees with.
 *
 * Applet 6.x: no document gives its policy table or bit values (the middleware dropped 6.x), so a
 * 6.x builder compiles with the 3.x rule table but `Build()` refuses it with `Unsupported`. Nothing
 * is sent to a 6.x chip with guessed policy bits.
 */
#ifndef SE05X_POLICY_HPP
#define SE05X_POLICY_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "se05x_ids.hpp"
#include "se05x_policy_types.hpp"
#include "se05x_status.hpp"
#include "se05x_types.hpp"

namespace se05x {

/**
 * @brief Whether the object class is a symmetric key (AES, DES, HMAC).
 * @param object_class The class.
 * @return true for the symmetric key classes.
 */
constexpr bool IsSymmetricClass(ObjectClass object_class) noexcept {
  return (object_class == ObjectClass::AesKey) || (object_class == ObjectClass::DesKey) ||
         (object_class == ObjectClass::HmacKey);
}

/**
 * @brief Whether the object class is an asymmetric key (EC or RSA, any form).
 * @param object_class The class.
 * @return true for the EC and RSA key classes.
 */
constexpr bool IsAsymmetricClass(ObjectClass object_class) noexcept {
  return static_cast<uint8_t>(object_class) <= static_cast<uint8_t>(ObjectClass::RsaPubKey);
}

namespace policy {

/**
 * @brief The bit of a rule.
 * @param rule The rule.
 * @return `1 << rule`.
 */
constexpr uint32_t Bit(Rule rule) noexcept {
  return uint32_t{1} << static_cast<uint32_t>(rule);
}

/// The rules every class of applet 3.x accepts (AN12413 Table 11, "All classes").
inline constexpr uint32_t kV3All = Bit(Rule::Delete) | Bit(Rule::RequireSecureMessaging) |
                                   Bit(Rule::RequirePcrValue) | Bit(Rule::ForbidAll);
/// The rules of applet 3.x symmetric keys. Table 11 notes that ENC and DEC do not apply to HMAC
/// keys and KDF only to HMAC keys, DESFire only to AES keys: the chip validates per class, so the
/// rule is accepted and has no effect.
inline constexpr uint32_t kV3Symmetric =
    Bit(Rule::Sign) | Bit(Rule::Verify) | Bit(Rule::Encrypt) | Bit(Rule::Decrypt) | Bit(Rule::Kdf) |
    Bit(Rule::Wrap) | Bit(Rule::Write) | Bit(Rule::Gen) | Bit(Rule::DesfireAuthentication) |
    Bit(Rule::DesfireDumpSessionKeys) | Bit(Rule::ImportExport);
/// The rules of applet 3.x asymmetric keys (Table 11).
inline constexpr uint32_t kV3Asymmetric =
    Bit(Rule::Sign) | Bit(Rule::Verify) | Bit(Rule::Encrypt) | Bit(Rule::Decrypt) | Bit(Rule::Kdf) |
    Bit(Rule::Wrap) | Bit(Rule::Write) | Bit(Rule::Gen) | Bit(Rule::KeyAgreement) |
    Bit(Rule::Read) | Bit(Rule::Attestation) | Bit(Rule::ImportExport);
/// The rules of applet 3.x binary files, counters and PCRs (Table 11).
inline constexpr uint32_t kV3Data = Bit(Rule::Write) | Bit(Rule::Read);
/// The rules of applet 3.x UserID objects (Table 11).
inline constexpr uint32_t kV3UserId = Bit(Rule::Write);

/// The rules every class of applet 7.x accepts (AN12543 Table 15: READ and WRITE apply to every
/// class on 7.x).
inline constexpr uint32_t kV7All = Bit(Rule::ForbidAll) | Bit(Rule::Read) | Bit(Rule::Write) |
                                   Bit(Rule::Delete) | Bit(Rule::RequireSecureMessaging) |
                                   Bit(Rule::RequirePcrValue);
/// The rules of applet 7.x symmetric keys (Table 15; the DESFire rules apply to AES keys only).
inline constexpr uint32_t kV7Symmetric =
    Bit(Rule::Sign) | Bit(Rule::Verify) | Bit(Rule::Encrypt) | Bit(Rule::Decrypt) |
    Bit(Rule::ImportExport) | Bit(Rule::DerivedInput) | Bit(Rule::ForbidDerivedOutput) |
    Bit(Rule::TlsKdf) | Bit(Rule::KdfExtRandom) | Bit(Rule::TlsPms) | Bit(Rule::Hkdf) |
    Bit(Rule::Pbkdf) | Bit(Rule::Wrap) | Bit(Rule::DesfireAuthentication) |
    Bit(Rule::DesfireDumpSessionKeys) | Bit(Rule::DesfireChangeKey) | Bit(Rule::DesfireKdf) |
    Bit(Rule::ForbidExternalIv) | Bit(Rule::UsageAsHmacPepper);
/// The rules of applet 7.x asymmetric keys (Table 15).
inline constexpr uint32_t kV7Asymmetric =
    Bit(Rule::Sign) | Bit(Rule::Verify) | Bit(Rule::Encrypt) | Bit(Rule::Decrypt) |
    Bit(Rule::ImportExport) | Bit(Rule::DerivedInput) | Bit(Rule::ForbidDerivedOutput) |
    Bit(Rule::Gen) | Bit(Rule::KeyAgreement) | Bit(Rule::Attestation);

/**
 * @brief The rules a class accepts in a generation.
 * @param generation The generation; 6.x uses the 3.x table (see the file comment).
 * @param object_class The class; a curve object has no policy.
 * @return The bit set of `Rule`s.
 */
constexpr uint32_t AllowedRules(AppletGeneration generation, ObjectClass object_class) noexcept {
  if (!detail::IsEnumerator(object_class) || (object_class == ObjectClass::Curve)) {
    return 0U;
  }
  const bool v7 = (generation == AppletGeneration::V7);
  uint32_t rules = v7 ? kV7All : kV3All;
  if (IsSymmetricClass(object_class)) {
    rules |= v7 ? kV7Symmetric : kV3Symmetric;
  } else if (IsAsymmetricClass(object_class)) {
    rules |= v7 ? kV7Asymmetric : kV3Asymmetric;
  } else if (object_class == ObjectClass::UserId) {
    rules |= v7 ? 0U : kV3UserId;
  } else {
    rules |= v7 ? 0U : kV3Data;
  }
  return rules;
}

/**
 * @brief The access rule header bit of a rule (AN12413 Table 50, AN12543 Table 63). The value
 * 0x00800000 is ALLOW_KDF on 3.x (`Rule::Kdf`) and ALLOW_KDF, formerly ALLOW_HKDF, on 7.x
 * (`Rule::Hkdf`).
 * @param rule The rule.
 * @return The bit; 0 for a value that is not an enumerator.
 */
constexpr uint32_t HeaderBit(Rule rule) noexcept {
  constexpr std::array<uint32_t, 29> kBits{
      0x20000000U, 0x10000000U, 0x08000000U, 0x04000000U, 0x02000000U, 0x01000000U,
      0x00800000U, 0x00400000U, 0x00200000U, 0x00100000U, 0x00080000U, 0x00040000U,
      0x00020000U, 0x00010000U, 0x00008000U, 0x00004000U, 0x00002000U, 0x00001000U,
      0x00000800U, 0x00000400U, 0x80000000U, 0x40000000U, 0x00800000U, 0x00000200U,
      0x00000100U, 0x00000080U, 0x00000040U, 0x00000020U, 0x00000010U};
  if (!detail::IsEnumerator(rule)) {
    return 0U;
  }
  return kBits[static_cast<std::size_t>(detail::ToUnderlying(rule))];
}

/// Header bits that need an extension (AN12543 Table 63): REQUIRE_PCR_VALUE (36 bytes),
/// ALLOW_DESFIRE_CHANGEKEY, ALLOW_DERIVED_INPUT and FORBID_EXTERNAL_INPUT_SIGN (4 bytes each).
inline constexpr uint32_t kPcrBit = 0x00010000U;
/// ALLOW_DESFIRE_CHANGEKEY.
inline constexpr uint32_t kChangeKeyBit = 0x00000200U;
/// ALLOW_DERIVED_INPUT.
inline constexpr uint32_t kDerivedInputBit = 0x00000100U;
/// FORBID_EXTERNAL_INPUT_SIGN.
inline constexpr uint32_t kInternalSignBit = 0x00000008U;
/// RFU bits of the header (AN12543 Table 63).
inline constexpr uint32_t kRfuBits = 0x00000007U;
/// Length of the PCR extension: a 4-byte PCR id and a 32-byte value.
inline constexpr std::size_t kPcrExtension = 36U;
/// A policy without extensions: authentication object id and header, after the length byte.
inline constexpr std::size_t kPolicyBase = 8U;
/// Longest policy after the length byte (AN12543 Table 12: a policy is 9 to 53 bytes).
inline constexpr std::size_t kPolicyMax = 52U;
/// Most policies one builder holds (a policy set of at most `kMaxPolicyBytes` has at most 28).
inline constexpr std::size_t kMaxEntries = 8U;

/**
 * @brief The extension length a header needs.
 * @param header The access rule header.
 * @return The number of extension bytes.
 */
constexpr std::size_t ExtensionLength(uint32_t header) noexcept {
  std::size_t n = 0U;
  n += ((header & kPcrBit) != 0U) ? kPcrExtension : 0U;
  n += ((header & kChangeKeyBit) != 0U) ? 4U : 0U;
  n += ((header & kDerivedInputBit) != 0U) ? 4U : 0U;
  n += ((header & kInternalSignBit) != 0U) ? 4U : 0U;
  return n;
}

/**
 * @brief Whether the class holds a secret the chip must keep (private and symmetric keys).
 * @param object_class The class.
 * @return true for the key classes other than public keys.
 */
constexpr bool HoldsSecret(ObjectClass object_class) noexcept {
  return IsSymmetricClass(object_class) || (object_class == ObjectClass::EcKeyPair) ||
         (object_class == ObjectClass::EcPrivKey) || (object_class == ObjectClass::RsaKeyPair) ||
         (object_class == ObjectClass::RsaPrivKey);
}

/** @brief One policy of a set, while it is built. */
struct Entry {
  uint32_t auth{0};                    ///< Authentication object id; 0 for the default session.
  uint32_t allow{0};                   ///< Allowed rules, a bit per `Rule`.
  uint32_t forbid{0};                  ///< Rules forbidden explicitly, a bit per `Rule`.
  uint32_t pcr_id{0};                  ///< PCR of REQUIRE_PCR_VALUE, or 0.
  std::array<uint8_t, 32> pcr_value{}; ///< Its expected value.
  bool pcr_set{false};                 ///< `RequirePcr` was called.
};

/**
 * @brief Check one built policy against what the chip accepts and against contradictions.
 * @param e The policy.
 * @param object_class The class.
 * @return `Ok`, `InvalidArgument` (a contradiction, a readable private key) or `PolicyInvalid`
 * (the chip would refuse it).
 */
constexpr Error CheckChipRules(const Entry& e, ObjectClass object_class) noexcept {
  const uint32_t forbid_all = Bit(Rule::ForbidAll);
  if (((e.allow & e.forbid) != 0U) ||
      (((e.allow & forbid_all) != 0U) && ((e.allow & ~forbid_all) != 0U))) {
    return Error::InvalidArgument;
  }
  if (((e.allow & Bit(Rule::Read)) != 0U) &&
      ((object_class == ObjectClass::EcPrivKey) || (object_class == ObjectClass::RsaPrivKey))) {
    return Error::InvalidArgument; // a private key is never readable (S-03)
  }
  if (((e.allow & Bit(Rule::RequirePcrValue)) != 0U) != e.pcr_set) {
    return Error::PolicyInvalid; // REQUIRE_PCR_VALUE needs its extension, and only it
  }
  if ((e.allow & (Bit(Rule::DesfireChangeKey) | Bit(Rule::DerivedInput))) != 0U) {
    return Error::PolicyInvalid; // their 4-byte extension has no argument here
  }
  return Error::Ok;
}

/**
 * @brief Check one built policy against the rules of the profile (S-03).
 * @param e The policy.
 * @param object_class The class.
 * @param available The rules the class accepts.
 * @param strict Whether the `Strict` profile applies.
 * @return `Ok`, `InvalidArgument` (a contradiction or a profile rule) or `PolicyInvalid` (the
 * chip would refuse it).
 */
constexpr Error CheckEntry(const Entry& e, ObjectClass object_class, uint32_t available,
                           bool strict) noexcept {
  const Error chip = CheckChipRules(e, object_class);
  if (chip != Error::Ok) {
    return chip;
  }
  if (!strict || (e.allow == 0U) || ((e.allow & Bit(Rule::ForbidAll)) != 0U)) {
    return Error::Ok; // a policy that grants nothing needs no explicit refusals
  }
  const uint32_t lifecycle = (Bit(Rule::Write) | Bit(Rule::Delete) | Bit(Rule::Gen)) & available;
  const bool key = IsSymmetricClass(object_class) || IsAsymmetricClass(object_class);
  if (key && ((e.forbid & lifecycle) != lifecycle)) {
    return Error::InvalidArgument; // Strict: write, delete and generate forbidden explicitly
  }
  if (HoldsSecret(object_class) && (((e.allow & Bit(Rule::RequireSecureMessaging)) == 0U) ||
                                    ((e.allow & Bit(Rule::ImportExport)) != 0U))) {
    return Error::InvalidArgument; // Strict: secure messaging, no export (S-03)
  }
  return Error::Ok;
}

/**
 * @brief Encode the policies into the chip's format.
 * @param entries The policies.
 * @param count How many.
 * @param out The buffer.
 * @param length Receives the length.
 * @return `Ok` or `PolicyInvalid` (more than `kMaxPolicyBytes`).
 */
constexpr Error EncodeEntries(const std::array<Entry, kMaxEntries>& entries, std::size_t count,
                              std::array<uint8_t, kMaxPolicyBytes>& out,
                              std::size_t& length) noexcept {
  std::size_t pos = 0U;
  for (std::size_t i = 0U; (i < count) && (i < kMaxEntries); ++i) {
    uint32_t header = 0U;
    for (uint32_t r = 0U; r <= static_cast<uint32_t>(Rule::UsageAsHmacPepper); ++r) {
      if ((entries[i].allow & (uint32_t{1} << r)) != 0U) {
        header |= HeaderBit(static_cast<Rule>(static_cast<uint8_t>(r)));
      }
    }
    const std::size_t body = kPolicyBase + ExtensionLength(header);
    if ((pos + 1U + body) > out.size()) {
      return Error::PolicyInvalid;
    }
    const std::array<uint32_t, 2> words{entries[i].auth, header};
    out[pos] = static_cast<uint8_t>(body);
    for (std::size_t w = 0U; w < words.size(); ++w) {
      for (std::size_t b = 0U; b < 4U; ++b) {
        out[pos + 1U + (4U * w) + b] = static_cast<uint8_t>((words[w] >> (24U - (8U * b))) & 0xFFU);
      }
    }
    if ((header & kPcrBit) != 0U) {
      for (std::size_t b = 0U; b < 4U; ++b) {
        out[pos + 9U + b] = static_cast<uint8_t>((entries[i].pcr_id >> (24U - (8U * b))) & 0xFFU);
      }
      for (std::size_t b = 0U; b < entries[i].pcr_value.size(); ++b) {
        out[pos + 13U + b] = entries[i].pcr_value[b];
      }
    }
    pos += 1U + body;
  }
  length = pos;
  return Error::Ok;
}

/**
 * @brief Whether a built policy grants neither `Write` nor `Delete` to any authentication object:
 * the object it protects can never change (AN12543 Table 63: the header is the 4 bytes after the
 * authentication object id of each entry `L | auth (4) | header (4) | extension`).
 * @param policy The policy.
 * @return true when no entry has ALLOW_WRITE or ALLOW_DELETE; false for an empty or malformed one.
 */
constexpr bool IsImmutable(const Policy& policy) noexcept;

/**
 * @brief Whether a policy set in the chip's format grants none of the header bits in `mask` to
 * any authentication object (AN12543 Table 63: each entry is `L | auth (4) | header (4) | ext`).
 * @param bytes The policy set, as built or as read back with `ReadObjectAttributes`.
 * @param mask Header bits (`HeaderBit()`).
 * @return true when no entry grants any of them; false for an empty or malformed set.
 */
constexpr bool GrantsNone(ByteSpan bytes, uint32_t mask) noexcept {
  std::size_t at = 0U;
  bool any = false;
  while (at < bytes.size()) {
    const std::size_t length = bytes[at];
    if ((length < 8U) || ((at + 1U + length) > bytes.size())) {
      return false;
    }
    uint32_t header = 0U;
    for (std::size_t i = 0U; i < 4U; ++i) {
      header = (header << 8U) | static_cast<uint32_t>(bytes[at + 5U + i]);
    }
    if ((header & mask) != 0U) {
      return false;
    }
    any = true;
    at += 1U + length;
  }
  return any;
}

constexpr bool IsImmutable(const Policy& policy) noexcept {
  return GrantsNone(policy.Bytes(), HeaderBit(Rule::Write) | HeaderBit(Rule::Delete));
}

} // namespace policy

/**
 * @brief Whether `rule` exists for objects of `object_class` in applet generation `generation`.
 *
 * Applet 3.x: AN12413 Table 11. Applet 7.x: AN12543 Table 15; there READ and WRITE apply to every
 * class, symmetric keys lose KDF and GEN and gain the TLS, HKDF (ALLOW_KDF), PBKDF, DESFire KDF,
 * external-IV, pepper, derived-input and derived-output rules; asymmetric keys lose KDF and WRAP
 * and gain the derived rules. A curve object has no policy. Applet 6.x uses the 3.x table and its
 * policies are refused at `Build()` (no source for its bit values).
 *
 * @param generation The applet generation.
 * @param object_class The class.
 * @param rule The rule.
 * @return true when the chip accepts the rule for the class in that generation.
 */
constexpr bool RuleAllowedFor(AppletGeneration generation, ObjectClass object_class,
                              Rule rule) noexcept {
  return detail::IsEnumerator(rule) &&
         ((policy::AllowedRules(generation, object_class) & policy::Bit(rule)) != 0U);
}

/**
 * @brief Builds the policy of one object of class `C` for applet generation `G`.
 *
 * `PolicyBuilder<AppletGeneration::V3, C>` and `PolicyBuilder<AppletGeneration::V7, C>` are
 * different types: a rule that does not exist in a generation does not compile for it. `For()` or
 * `ForAllOthers()` starts a policy (one per authentication object, at most 8); `Allow` and
 * `Forbid` act on the policy started last. A 7.x key agreement key should forbid derived output
 * (POLICY_OBJ_FORBID_DERIVED_OUTPUT, AN12543 Table 63) unless the secret is meant to leave the
 * chip.
 *
 * @code
 * constexpr auto kPolicy = PolicyBuilder<AppletGeneration::V7, ObjectClass::EcKeyPair>{}
 *     .For(AuthObject{ObjectId{0x7FFF0001U}})  // or .ForAllOthers()
 *     .Allow<Rule::Sign>().Allow<Rule::Attestation>()
 *     .RequireSecureMessaging()
 *     .Forbid<Rule::Write>().Forbid<Rule::Delete>().Forbid<Rule::Gen>()
 *     .Build();
 * @endcode
 *
 * @tparam G The applet generation the policy is for.
 * @tparam C The class of the object the policy is for.
 * @tparam P The profile; `Strict` unless the caller needs `Open` and names an `OpenReason`.
 */
template <AppletGeneration G, ObjectClass C, Profile P = Profile::Strict>
class PolicyBuilder {
public:
  /** @brief An empty builder. */
  constexpr PolicyBuilder() noexcept = default;

  /**
   * @brief Start the policy of an authentication object.
   * @param auth The authentication object; `ObjectId{0}` makes `Build()` fail (use
   * `ForAllOthers()`).
   * @return This builder.
   */
  constexpr PolicyBuilder& For(AuthObject auth) noexcept {
    if (auth.id.value == 0U) {
      fail(Error::InvalidArgument);
    }
    start(auth.id.value);
    return *this;
  }

  /**
   * @brief Start the policy of the default session, the one without an applet session, open to
   * anybody (authentication object id 0, AN12543 3.7.1.2 p. 36). An AESKey, ECKey or UserID
   * session does not inherit it: name its credential with `For()` (docs/ambiguities.md A20).
   * @return This builder.
   */
  constexpr PolicyBuilder& ForAllOthers() noexcept {
    start(0U);
    return *this;
  }

  /**
   * @brief Allow a rule; fails to compile when the class does not accept it.
   * @tparam R The rule.
   * @return This builder.
   */
  template <Rule R>
    requires(RuleAllowedFor(G, C, R))
  constexpr PolicyBuilder& Allow() noexcept {
    if (current() != nullptr) {
      current()->allow |= policy::Bit(R);
    }
    return *this;
  }

  /**
   * @brief Forbid a rule explicitly. The `Strict` profile needs `Write`, `Delete` and `Gen` (those
   * of them the class has) forbidden on every key class.
   * @tparam R The rule.
   * @return This builder.
   */
  template <Rule R>
    requires(RuleAllowedFor(G, C, R))
  constexpr PolicyBuilder& Forbid() noexcept {
    if (current() != nullptr) {
      current()->forbid |= policy::Bit(R);
    }
    return *this;
  }

  /**
   * @brief Require secure messaging (platform SCP03 or an applet session with secure messaging).
   * @return This builder.
   */
  constexpr PolicyBuilder& RequireSecureMessaging() noexcept {
    if (current() != nullptr) {
      current()->allow |= policy::Bit(Rule::RequireSecureMessaging);
    }
    return *this;
  }

  /**
   * @brief Require a PCR to hold a value (REQUIRE_PCR_VALUE with its 36-byte extension).
   * @param pcr The PCR object; 0 makes `Build()` fail.
   * @param expected The expected value, 32 bytes; another length makes `Build()` fail.
   * @return This builder.
   */
  constexpr PolicyBuilder& RequirePcr(ObjectId pcr, ByteSpan expected) noexcept {
    policy::Entry* e = current();
    if (e == nullptr) {
      return *this;
    }
    if ((pcr.value == 0U) || (expected.size() != e->pcr_value.size())) {
      fail(Error::InvalidArgument);
      return *this;
    }
    e->allow |= policy::Bit(Rule::RequirePcrValue);
    e->pcr_id = pcr.value;
    e->pcr_set = true;
    for (std::size_t i = 0U; i < e->pcr_value.size(); ++i) {
      e->pcr_value[i] = expected[i];
    }
    return *this;
  }

  /**
   * @brief Name the reason for the `Open` profile; only exists on an `Open` builder.
   * @param reason The reason; `None` makes `Build()` fail.
   * @return This builder.
   */
  constexpr PolicyBuilder& WithReason(OpenReason reason) noexcept
    requires(P == Profile::Open)
  {
    reason_ = reason;
    return *this;
  }

  /**
   * @brief Validate and encode the policy.
   * @return The `Policy`, or `Unsupported` (applet 6.x), `PolicyInvalid` (chip rules: a missing
   * extension, duplicate authentication objects, more than `kMaxPolicyBytes`) or `InvalidArgument`
   * (no policy started, a contradiction, a profile rule, an `Open` builder without a reason).
   */
  [[nodiscard]] constexpr Result<Policy> Build() const noexcept {
    const Error error = check();
    if (error != Error::Ok) {
      return Result<Policy>::Failure(error, Detail{.sw = 0U,
                                                   .command = 0xFFU,
                                                   .layer = Layer::Apdu,
                                                   .step = 0U,
                                                   .attempts_left = 0xFFU});
    }
    std::array<uint8_t, kMaxPolicyBytes> bytes{};
    std::size_t length = 0U;
    const Error encoded = policy::EncodeEntries(entries_, count_, bytes, length);
    if (encoded != Error::Ok) {
      return Result<Policy>::Failure(encoded, Detail{.sw = 0U,
                                                     .command = 0xFFU,
                                                     .layer = Layer::Apdu,
                                                     .step = 0U,
                                                     .attempts_left = 0xFFU});
    }
    return Result<Policy>::Success(Policy{bytes, length, P, G});
  }

private:
  constexpr void fail(Error error) noexcept {
    if (error_ == Error::Ok) {
      error_ = error;
    }
  }
  constexpr void start(uint32_t auth) noexcept {
    if (count_ >= policy::kMaxEntries) {
      fail(Error::PolicyInvalid);
      return;
    }
    entries_[count_] = policy::Entry{};
    entries_[count_].auth = auth;
    ++count_;
  }
  [[nodiscard]] constexpr policy::Entry* current() noexcept {
    if ((count_ == 0U) || (count_ > policy::kMaxEntries)) {
      fail(Error::InvalidArgument);
      return nullptr;
    }
    return &entries_[count_ - 1U];
  }
  [[nodiscard]] constexpr Error check() const noexcept {
    if (G == AppletGeneration::V6) {
      return Error::Unsupported;
    }
    if (error_ != Error::Ok) {
      return error_;
    }
    if ((count_ == 0U) || ((P == Profile::Open) && (reason_ == OpenReason::None))) {
      return Error::InvalidArgument;
    }
    const uint32_t available = policy::AllowedRules(G, C);
    for (std::size_t i = 0U; i < count_; ++i) {
      for (std::size_t j = 0U; j < i; ++j) {
        if (entries_[i].auth == entries_[j].auth) {
          return Error::PolicyInvalid;
        }
      }
      const Error e = policy::CheckEntry(entries_[i], C, available, P == Profile::Strict);
      if (e != Error::Ok) {
        return e;
      }
    }
    return Error::Ok;
  }

  std::array<policy::Entry, policy::kMaxEntries> entries_{};
  std::size_t count_{0};
  Error error_{Error::Ok};
  OpenReason reason_{OpenReason::None};
};

/**
 * @brief Encode a session policy (AN12543 3.7.2 and Table 62): a length, a 2-byte header
 * (MAX_APDU 0x8000, MAX_TIMEOUT 0x4000, ALLOW_REFRESH 0x2000) and the 2-byte extensions in header
 * order. The empty policy is `02 00 00`.
 * @param policy The session policy; a zero limit means no limit.
 * @return The bytes in the chip's format, 3 to 7 bytes.
 */
constexpr Result<FixedBytes<8>> EncodeSessionPolicy(const SessionPolicy& policy) noexcept {
  FixedBytes<8> out{};
  uint32_t header = 0U;
  std::size_t pos = 3U;
  const std::array<uint16_t, 2> limits{policy.max_apdus, policy.max_time};
  const std::array<uint32_t, 2> bits{0x8000U, 0x4000U};
  for (std::size_t i = 0U; i < limits.size(); ++i) {
    if (limits[i] != 0U) {
      header |= bits[i];
      out.bytes[pos] = static_cast<uint8_t>((static_cast<uint32_t>(limits[i]) >> 8U) & 0xFFU);
      out.bytes[pos + 1U] = static_cast<uint8_t>(static_cast<uint32_t>(limits[i]) & 0xFFU);
      pos += 2U;
    }
  }
  if (policy.allow_refresh) {
    header |= 0x2000U;
  }
  out.bytes[0] = static_cast<uint8_t>(pos - 1U);
  out.bytes[1] = static_cast<uint8_t>((header >> 8U) & 0xFFU);
  out.bytes[2] = static_cast<uint8_t>(header & 0xFFU);
  out.length = pos;
  return Result<FixedBytes<8>>::Success(out);
}

} // namespace se05x

#endif // SE05X_POLICY_HPP
