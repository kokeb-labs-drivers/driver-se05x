/**
 * @file chip_model.hpp
 * @brief `ChipModel`: the IoT applet behind `ScpTarget` for the device tests: version and feature
 * answers per chip profile, the lifecycle state (transport lock, platform SCP requirement,
 * restriction), a small object store (EC key pairs, binary files, counters, UserID objects), ECDSA
 * sign and verify, EdDSA length rules, attested reads (format 2) and the reserved credentials of
 * the lifecycle commands; for the facade also EC key import (key pair or
 * public key), AES key import (plain or RFC 3394 wrapped), ECDH, ReadSize and the unique id.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Written from the documents, not from the library (RD-07): AN12543 Rev 4.5 (constants Tables 23
 * to 30 pp. 50-54, TLV tags p. 55, lock behaviour Table 89 p. 74, ReadState Tables 108-109 p. 79,
 * ReadObject Tables 127-128 pp. 89-91 and the attestation signature input of 3.2.7.2 pp. 19-20,
 * reserved credentials 3.2.4.1.1 pp. 11-12, EdDSA input limits pp. 103-104; WriteECKey p. 80,
 * WriteSymmKey p. 83 with RFC 3394 unwrapping by the KEK object, ReadSize p. 93, ECDH p. 105, the
 * unique id object of Table 5 p. 10), AN12413 for the
 * applet 3.x answers. Its TLV reader and writer, its tables and its ECDSA signer are its own; the
 * only library types used are `ByteSpan` and `MutableByteSpan` through `ApduHandler`, the crypto
 * is `scp_crypto.hpp` (the model crypto, written apart from the library).
 *
 * What it does not model (tests must not rely on it): RSA, ciphers, MAC, AEAD, KDFs, DESFire,
 * I2CM, PCRs, curve objects, crypto objects, applet 3.x attestation (format 1), EdDSA signature
 * arithmetic (an EdDSA signature is 64 fixed bytes and a verification succeeds unless the
 * signature is all zero), the policy bit semantics beyond the presence of a policy and the delete
 * rule (which authentication object an entry names is not checked), and chip-side memory
 * accounting (free memory is a constant). Unknown commands answer 0x6D00.
 *
 * The throughput limiter (SW 0x66A6) is the T=1 stage's knob (`ModelKnobs::throttle_*`).
 */
#ifndef SE05X_TESTS_MODEL_CHIP_MODEL_HPP
#define SE05X_TESTS_MODEL_CHIP_MODEL_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "model/bytes.hpp"
#include "model/model_if.hpp"
#include "model/scp_crypto.hpp"
#include "model/scp_target.hpp"

namespace se05x::testmodel {

/** @brief A chip as its documents describe it. */
struct ChipProfile {
  const char* name;
  uint8_t major, minor, patch;
  uint16_t applet_config;
  uint16_t secure_box;
  uint16_t oef;      ///< Card identification OEF id.
  bool ext_version;  ///< GetExtVersion and ReadState exist (applet 7.x).
  uint8_t ext_fill;  ///< Value of each of the 30 extended feature bytes.
  bool memory_4byte; ///< GetFreeMemory answers 4 bytes (SE052F).
  bool eddsa;        ///< EdDSA present.
};

/// SE050 C2, applet 3.6 (AN12436 Table 2: C2 OEF A201).
inline constexpr ChipProfile kSe050{"se050", 3U,    6U,    0U,    0x3FFFU, 0x010BU,
                                    0xA201U, false, 0x00U, false, true};
/// SE050 E2, applet 7.2 (OEF A921).
inline constexpr ChipProfile kSe050E{"se050e", 7U,   2U,    0U,    0x3FFFU, 0x010BU,
                                     0xA921U,  true, 0xFFU, false, true};
/// SE051 A2, applet 7.2 (AN12973 Table 4: A920).
inline constexpr ChipProfile kSe051{"se051_v7", 7U,   2U,    0U,    0x3FFFU, 0x010BU,
                                    0xA920U,    true, 0xFFU, false, true};
/// SE051 C2 on an early board, applet 6.0 (AN12907 p. 13; AN12973 Table 4: A564). Applet 6.x has
/// no specification in hand: the profile answers as applet 3.x does (no GetExtVersion, no
/// ReadState), which is all the facade needs to see the generation.
inline constexpr ChipProfile kSe051V6{"se051_v6", 6U,    0U,    0U,    0x3FFFU, 0x010BU,
                                      0xA564U,    false, 0x00U, false, true};
/// SE052 F2, applet 7.2.22, AppletConfig 0x26F2, OEF B501 (SE052 data sheet), 4-byte free memory.
inline constexpr ChipProfile kSe052{"se052", 7U,   2U,    22U,  0x26F2U, 0x010BU,
                                    0xB501U, true, 0xFFU, true, false};

/** @brief How the model changes TAG_1 of one answer. */
enum class Tamper : uint8_t { None, DropLast, FlipFirst };

/** @brief Knobs of the applet model. */
struct ChipKnobs {
  bool selftest_silent{false}; ///< TriggerSelfTest: no answer at all (the chip resets itself).
  bool selftest_fails{false};  ///< TriggerSelfTest answers RESULT_FAILURE.
  uint16_t inject_sw{0};       ///< When not 0: answer this SW to the next `inject_count` commands.
  uint32_t inject_count{0};    ///< Commands that get `inject_sw` (the select excepted).
  uint32_t inject_skip{0};     ///< Commands answered normally before `inject_sw` starts.
  Tamper tamper{Tamper::None}; ///< Change TAG_1 of one answer.
  uint32_t tamper_skip{0};     ///< Answers left alone before the tampered one.
  uint32_t user_id_auth{0};    ///< The UserID credential id: EdDSA input above 919 is refused.
  bool persistent_lock{false}; ///< PERSISTENT_LOCK is LOCKED (product configuration).
  bool scp_required{false};    ///< PlatformSCPRequest is SCP_REQUIRED.
  uint8_t version_patch_after_reset{0xFF}; ///< When not 0xFF: the patch version after a reset.
  bool no_applet{false};           ///< The IoT applet is not installed: its select answers 0x6A82.
  bool attested_short_tlv{false};  ///< Attested TLVs in the shortest length form.
  bool replay_attested{false};     ///< Answer an attested read with the previous attested answer.
  bool rewind_timestamp{false};    ///< The next attested answer restarts the timestamp at 1.
  int32_t attested_size_offset{0}; ///< Added to the signed object size (TAG_4) of attested answers:
                                   ///< above 0 the value is shorter than the size it states.
  uint32_t read_truncate{0};  ///< ReadObject values of two bytes or more lose this many end bytes
                              ///< (at least one is kept); an attested answer still states the whole
                              ///< size and is signed over the bytes as returned.
  uint16_t sw_after{0};       ///< When not 0: one command is carried out, then answers this SW.
  uint32_t sw_after_skip{0};  ///< Commands answered normally before `sw_after` applies.
  bool zero_read_size{false}; ///< ReadSize answers 0 (a size no stored object has).
  uint8_t unique_id_flip{0}; ///< XOR into the plain unique-id read (an id that another chip signs).
};

/** @brief The applet model. */
class ChipModel : public ApduHandler {
public:
  static constexpr uint32_t kTransport = 0x7FFF0200U;
  static constexpr uint32_t kEcka = 0x7FFF0201U;
  static constexpr uint32_t kFeature = 0x7FFF0204U;
  static constexpr uint32_t kFactoryReset = 0x7FFF0205U;
  static constexpr uint32_t kPlatformScp = 0x7FFF0207U;
  static constexpr uint32_t kRestrict = 0x7FFF020AU;
  static constexpr uint32_t kAttestKey = 0xF0000012U;
  static constexpr uint32_t kUniqueId = 0x7FFF0206U;
  static constexpr std::size_t kMaxBinary = 2304U; // above the facade's 2048, to reach its guard

  /**
   * @brief Bind to the session stage (for `auth_id` and `via`) with a profile.
   * @param scp The SCP target this applet sits behind.
   * @param profile The chip.
   */
  ChipModel(ScpTarget& scp, const ChipProfile& profile) : scp_(scp), profile_(profile) {
    scp_.applet = this;
    scp_.oef_id = profile.oef;
    static const uint8_t kAttestPriv[32] = {0x2A, 0x51, 0x0C, 0x77, 0x18, 0x9E, 0x40, 0x03,
                                            0x61, 0x2B, 0x7C, 0x55, 0x10, 0x88, 0x3F, 0x21,
                                            0x4D, 0x6E, 0x19, 0x02, 0x73, 0x0A, 0x5B, 0x34,
                                            0x26, 0x47, 0x58, 0x69, 0x7A, 0x0B, 0x1C, 0x2D};
    Object& a = add(kAttestKey, Type::EcPair, true);
    CopyBytes(a.priv.data(), kAttestPriv, 32U);
    static_cast<void>(mc::PublicKey(a.priv.data(), a.pub.data()));
    a.attest = true;
    a.provisioned = true;
  }

  ChipKnobs knobs{};

  /** @brief The chip's ECKA key pair (RESERVED_ID_ECKEY_SESSION); also give it to `ScpTarget`. */
  void SetEcka(const uint8_t* priv32) {
    Object& o = add(kEcka, Type::EcPair, true);
    CopyBytes(o.priv.data(), priv32, 32U);
    static_cast<void>(mc::PublicKey(o.priv.data(), o.pub.data()));
    o.provisioned = true;
  }
  /** @return The attestation public key (trusted by the tests). */
  [[nodiscard]] const std::array<uint8_t, 65>& AttestPublic() const {
    return objects_[0].pub;
  }
  /** @brief Let a key sign attested reads (the model does not read POLICY_OBJ_ALLOW_ATTESTATION).
   */
  void MarkAttestation(uint32_t id) {
    Object* o = find(id);
    if (o != nullptr) {
      o->attest = true;
    }
  }
  /** @return Whether an AES key object holds `key`. */
  [[nodiscard]] bool AesKeyIs(uint32_t id, ByteSpan key) const {
    const Object* o = find(id);
    return (o != nullptr) && (o->type == Type::Aes) && (o->size == key.size()) &&
           (SameBytes(o->priv.data(), key.data(), key.size()));
  }
  /** @return Whether an object exists. */
  [[nodiscard]] bool Has(uint32_t id) const {
    return find(id) != nullptr;
  }
  /** @brief Make an existing object transient (its content is lost at deselect), as a host with
   * raw access could have created it. */
  void MakeTransient(uint32_t id) {
    Object* o = find(id);
    if (o != nullptr) {
      o->persistent = false;
    }
  }
  /** @return Whether the policy the object was created with has an entry for `auth`. */
  [[nodiscard]] bool PolicyNames(uint32_t id, uint32_t auth) const {
    const Object* o = find(id);
    if (o == nullptr) {
      return false;
    }
    for (std::size_t i = 0U; i < o->policy_entries; ++i) {
      if (o->policy_auth[i] == auth) {
        return true;
      }
    }
    return false;
  }
  /** @return A counter's value. */
  [[nodiscard]] uint64_t CounterValue(uint32_t id) const {
    const Object* o = find(id);
    return (o != nullptr) ? o->counter : 0U;
  }
  /** @return Whether the applet is locked now (Table 89). */
  [[nodiscard]] bool Locked() const {
    return knobs.persistent_lock && transient_locked_;
  }

  // Observations.
  uint32_t commands{0};
  uint32_t selects{0};
  uint32_t delete_all{0};
  uint32_t power_cycles{0};
  uint8_t last_ins{0};
  uint8_t last_p2{0};
  uint8_t restrict_mode{0};
  std::size_t last_len{0};

  std::size_t Handle(ByteSpan c, MutableByteSpan r) override {
    if ((c.size() >= 2U) && (c[0] == 0x00U) && (c[1] == 0xA4U)) {
      return select(r);
    }
    ++commands;
    last_len = c.size();
    if (c.size() < 4U) {
      return sw(r, 0U, 0x6700U);
    }
    last_ins = c[1];
    last_p2 = c[3];
    if ((knobs.inject_sw != 0U) && (knobs.inject_count != 0U)) {
      if (knobs.inject_skip != 0U) {
        --knobs.inject_skip;
      } else {
        --knobs.inject_count;
        return sw(r, 0U, knobs.inject_sw);
      }
    }
    command_ = withoutLe(c);
    Apdu a{};
    if (!parse(c, a)) {
      return sw(r, 0U, 0x6A80U);
    }
    policy_ = a.t[0x11];
    std::size_t answered = admitted(a, r);
    if ((knobs.sw_after != 0U) && (answered >= 2U)) {
      if (knobs.sw_after_skip != 0U) {
        --knobs.sw_after_skip;
      } else {
        answered = sw(r, 0U, knobs.sw_after); // the command took effect; the answer says not
        knobs.sw_after = 0U;
      }
    }
    if (knobs.tamper != Tamper::None) {
      if (knobs.tamper_skip != 0U) {
        --knobs.tamper_skip;
      } else {
        answered = tamper(r, answered);
      }
    }
    return answered;
  }

  void PowerCycle() override {
    ++power_cycles;
    deselect();
    if (knobs.version_patch_after_reset != 0xFFU) {
      patch_ = knobs.version_patch_after_reset;
    }
  }

private:
  enum class Type : uint8_t { None, EcPair, EcPub, Binary, Counter, UserId, Aes };
  struct Object {
    uint32_t id{0};
    Type type{Type::None};
    bool persistent{true};
    bool attest{false};
    bool provisioned{false};
    std::array<uint8_t, 32> priv{};
    std::array<uint8_t, 65> pub{};
    std::array<uint8_t, kMaxBinary> data{};
    std::size_t size{0};
    uint64_t counter{0};
    bool deletable{true}; ///< No policy, or a policy entry with POLICY_OBJ_ALLOW_DELETE.
    std::array<uint32_t, 4> policy_auth{}; ///< The authentication objects the policy names.
    std::size_t policy_entries{0};
    std::array<uint8_t, 64> policy{}; ///< The policy set as created (ReadObjectAttributes).
    std::size_t policy_len{0};
    bool generated{false}; ///< ORIGIN_INTERNAL: a key pair generated inside the model.
  };
  struct Tlv {
    bool present{false};
    const uint8_t* v{nullptr};
    std::size_t n{0};
  };
  struct Apdu {
    uint8_t ins{0}, p1{0}, p2{0};
    std::array<Tlv, 0x60> t{}; // indexed by tag
  };

  /// Change TAG_1 of one answer (a forged or truncated value): `DropLast` shortens it by one byte,
  /// `FlipFirst` changes its first byte. The status word stays.
  std::size_t tamper(MutableByteSpan r, std::size_t n) {
    const Tamper t = knobs.tamper;
    knobs.tamper = Tamper::None;
    if ((n < 4U) || (r[0] != 0x41U)) {
      return n;
    }
    std::size_t head = 2U;
    std::size_t len = r[1];
    if (r[1] == 0x81U) {
      head = 3U;
      len = r[2];
    } else if (r[1] == 0x82U) {
      head = 4U;
      len = (std::size_t{r[2]} << 8U) | r[3];
    } else {
      // one-byte length
    }
    if ((len == 0U) || ((head + len + 2U) > n)) {
      return n;
    }
    if (t == Tamper::FlipFirst) {
      r[head] = static_cast<uint8_t>(r[head] ^ 0x01U);
      return n;
    }
    // DropLast: one byte less; the bytes after the value move down by one.
    const std::size_t new_len = len - 1U;
    if (head == 2U) {
      r[1] = static_cast<uint8_t>(new_len);
    } else if (head == 3U) {
      r[2] = static_cast<uint8_t>(new_len);
    } else {
      r[2] = static_cast<uint8_t>(new_len >> 8U);
      r[3] = static_cast<uint8_t>(new_len & 0xFFU);
    }
    for (std::size_t i = head + len; i < n; ++i) {
      r[i - 1U] = r[i];
    }
    return n - 1U;
  }

  std::size_t admitted(const Apdu& a, MutableByteSpan r) {
    if (Locked() && !allowedLocked(a) && (scp_.auth_id != kTransport)) {
      return sw(r, 0U, 0x6985U); // AN12543 3.8 Table 19: inactive state
    }
    if (knobs.scp_required && !scp_.platform_open && !allowedWithoutScp(a)) {
      return sw(r, 0U, 0x6985U); // AN12543 3.14
    }
    return dispatch(a, r);
  }

  static std::size_t sw(MutableByteSpan r, std::size_t at, uint16_t word) {
    r[at] = static_cast<uint8_t>(word >> 8U);
    r[at + 1U] = static_cast<uint8_t>(word & 0xFFU);
    return at + 2U;
  }
  /// TLV with the three-byte length form `82 hi lo` (AN12543 4.1.3.2), as in attested answers.
  static std::size_t put82(MutableByteSpan r, std::size_t at, uint8_t tag, const uint8_t* v,
                           std::size_t n) {
    r[at] = tag;
    r[at + 1U] = 0x82U;
    r[at + 2U] = static_cast<uint8_t>(n >> 8U);
    r[at + 3U] = static_cast<uint8_t>(n & 0xFFU);
    if (n != 0U) {
      CopyBytes(&r[at + 4U], v, n);
    }
    return at + 4U + n;
  }
  /// TLV with the shortest length form.
  static std::size_t put(MutableByteSpan r, std::size_t at, uint8_t tag, const uint8_t* v,
                         std::size_t n) {
    r[at++] = tag;
    if (n < 0x80U) {
      r[at++] = static_cast<uint8_t>(n);
    } else if (n < 0x100U) {
      r[at++] = 0x81U;
      r[at++] = static_cast<uint8_t>(n);
    } else {
      r[at++] = 0x82U;
      r[at++] = static_cast<uint8_t>(n >> 8U);
      r[at++] = static_cast<uint8_t>(n & 0xFFU);
    }
    if (n != 0U) {
      CopyBytes(&r[at], v, n);
    }
    return at + n;
  }
  static uint32_t be(const Tlv& t) {
    uint32_t v = 0U;
    for (std::size_t i = 0U; i < t.n; ++i) {
      v = (v << 8U) | t.v[i];
    }
    return v;
  }

  /// The command without its Le field: what an attestation signs (AN12543 3.2.7.2).
  static ByteSpan withoutLe(ByteSpan c) {
    if (c.size() <= 5U) {
      return c.first(4U);
    }
    std::size_t lc = c[4];
    std::size_t at = 5U;
    if ((lc == 0U) && (c.size() >= 7U)) {
      lc = (std::size_t{c[5]} << 8U) | c[6];
      at = 7U;
    }
    return c.first(std::min(c.size(), at + lc));
  }
  /// ISO 7816-4 cases with short or extended Lc; the body is a list of one-byte-tag TLVs.
  static bool parse(ByteSpan c, Apdu& a) {
    a.ins = c[1];
    a.p1 = c[2];
    a.p2 = c[3];
    if (c.size() <= 5U) {
      return true;
    }
    std::size_t lc = c[4];
    std::size_t at = 5U;
    if (lc == 0U) {
      if (c.size() < 7U) {
        return true; // case 2 extended Le, or DeleteAll's Lc 0x00
      }
      lc = (std::size_t{c[5]} << 8U) | c[6];
      at = 7U;
    }
    if ((at + lc) > c.size()) {
      return false;
    }
    const std::size_t end = at + lc;
    while (at < end) {
      const uint8_t tag = c[at];
      if ((at + 2U) > end) {
        return false;
      }
      std::size_t n = c[at + 1U];
      std::size_t head = 2U;
      if ((n == 0x81U) && ((at + 3U) <= end)) {
        n = c[at + 2U];
        head = 3U;
      } else if ((n == 0x82U) && ((at + 4U) <= end)) {
        n = (std::size_t{c[at + 2U]} << 8U) | c[at + 3U];
        head = 4U;
      } else if (n > 0x80U) {
        return false;
      } else {
        // one-byte length
      }
      if ((at + head + n) > end) {
        return false;
      }
      if (tag < a.t.size()) {
        a.t[tag] = Tlv{true, c.data() + at + head, n};
      }
      at += head + n;
    }
    return true;
  }

  // --- Selection and lifecycle (AN12543 4.6, Table 89) -------------------------------------
  std::size_t select(MutableByteSpan r) {
    ++selects;
    if (knobs.no_applet) {
      return sw(r, 0U, 0x6A82U);
    }
    deselect();
    const uint8_t v[7] = {profile_.major,
                          profile_.minor,
                          patch_,
                          static_cast<uint8_t>(profile_.applet_config >> 8U),
                          static_cast<uint8_t>(profile_.applet_config & 0xFFU),
                          static_cast<uint8_t>(profile_.secure_box >> 8U),
                          static_cast<uint8_t>(profile_.secure_box & 0xFFU)};
    CopyBytes(r.data(), v, 7U);
    return sw(r, 7U, 0x9000U);
  }
  void deselect() {
    transient_locked_ = true; // the default TRANSIENT_LOCK state is LOCKED (AN12543 4.6.1)
    for (Object& o : objects_) {
      if (!o.persistent) {
        o = Object{};
      }
    }
  }
  static bool allowedLocked(const Apdu& a) {
    const uint8_t ins = a.ins & 0x0FU;
    if (ins == 0x02U) {
      return (a.p2 == 0x00U) || (a.p2 == 0x5BU); // ReadObject, ReadState
    }
    return (ins == 0x04U) && ((a.p2 == 0x20U) || (a.p2 == 0x21U) || (a.p2 == 0x49U) ||
                              (a.p2 == 0x3EU) || (a.p2 == 0x1BU));
  }
  static bool allowedWithoutScp(const Apdu& a) {
    const uint8_t ins = a.ins & 0x0FU;
    return ((ins == 0x04U) && ((a.p2 == 0x20U) || (a.p2 == 0x21U))) ||
           ((ins == 0x02U) && (a.p2 == 0x5BU));
  }

  std::size_t dispatch(const Apdu& a, MutableByteSpan r) {
    switch (a.ins & 0x0FU) {
    case 0x01U:
      return write(a, r);
    case 0x02U:
      return read(a, r);
    case 0x03U:
      return crypto(a, r);
    case 0x04U:
      return mgmt(a, r);
    default:
      break;
    }
    return sw(r, 0U, 0x6D00U);
  }

  std::size_t mgmt(const Apdu& a, MutableByteSpan r) {
    switch (a.p2) {
    case 0x20U: { // GetVersion
      const uint8_t v[7] = {profile_.major,
                            profile_.minor,
                            patch_,
                            static_cast<uint8_t>(profile_.applet_config >> 8U),
                            static_cast<uint8_t>(profile_.applet_config & 0xFFU),
                            static_cast<uint8_t>(profile_.secure_box >> 8U),
                            static_cast<uint8_t>(profile_.secure_box & 0xFFU)};
      return sw(r, put(r, 0U, 0x41U, v, 7U), 0x9000U);
    }
    case 0x21U: // GetExtVersion (applet 7.x)
      return extVersion(r);
    case 0x22U: // GetFreeMemory
      return freeMemory(a, r);
    case 0x49U: // GetRandom
      return random(a, r);
    case 0x27U: { // CheckObjectExists
      const uint8_t res = Has(be(a.t[0x41])) ? 0x01U : 0x02U;
      return sw(r, put(r, 0U, 0x41U, &res, 1U), 0x9000U);
    }
    case 0x28U: // DeleteSecureObject
      return deleteObject(a, r);
    case 0x2AU: // DeleteAll: RESERVED_ID_FACTORY_RESET session (3.2.4.1.1.5)
      return deleteAll(r);
    case 0x3EU: // SetLockState: RESERVED_ID_TRANSPORT (4.6.1)
      return lockState(a, r);
    case 0x52U: // SetPlatformSCPRequest: RESERVED_ID_PLATFORM_SCP (3.2.4.1.1.7)
      return scpRequest(a, r);
    case 0x57U: // DisableObjectCreation: RESERVED_ID_RESTRICT (4.6.3)
      return restrict(a, r);
    case 0x3FU: // SetAppletFeatures: RESERVED_ID_FEATURE (3.2.4.1.1.4)
      return sw(r, 0U, (scp_.auth_id == kFeature) ? 0x9000U : 0x6985U);
    case 0x58U: // TriggerSelfTest (4.6.6)
      return selfTest(r);
    default:
      break;
    }
    return sw(r, 0U, 0x6D00U);
  }

  [[nodiscard]] std::size_t extVersion(MutableByteSpan r) const {
    if (!profile_.ext_version) {
      return sw(r, 0U, 0x6D00U);
    }
    uint8_t v[37] = {profile_.major,
                     profile_.minor,
                     patch_,
                     static_cast<uint8_t>(profile_.applet_config >> 8U),
                     static_cast<uint8_t>(profile_.applet_config & 0xFFU),
                     static_cast<uint8_t>(profile_.secure_box >> 8U),
                     static_cast<uint8_t>(profile_.secure_box & 0xFFU)};
    static_cast<void>(std::memset(v + 7, profile_.ext_fill, 30U));
    return sw(r, put(r, 0U, 0x41U, v, 37U), 0x9000U);
  }
  [[nodiscard]] std::size_t freeMemory(const Apdu& a, MutableByteSpan r) const {
    const uint32_t type = be(a.t[0x41]);
    if ((type < 1U) || (type > 3U)) {
      return sw(r, 0U, 0x6A80U);
    }
    const uint8_t v[4] = {0x00U, 0x01U, 0x23U, 0x45U};
    if (profile_.memory_4byte) {
      return sw(r, put(r, 0U, 0x41U, v, 4U), 0x9000U);
    }
    const uint8_t v2[2] = {0x12U, 0x34U};
    return sw(r, put(r, 0U, 0x41U, v2, 2U), 0x9000U);
  }
  std::size_t random(const Apdu& a, MutableByteSpan r) {
    const uint32_t n = be(a.t[0x41]);
    if ((n == 0U) || (n > 0x200U)) {
      return sw(r, 0U, 0x6A80U);
    }
    uint8_t b[0x200];
    for (uint32_t i = 0U; i < n; ++i) {
      ++rng_;
      b[i] = static_cast<uint8_t>((rng_ * 151U) ^ (rng_ >> 3U));
    }
    return sw(r, put(r, 0U, 0x41U, b, n), 0x9000U);
  }
  std::size_t deleteObject(const Apdu& a, MutableByteSpan r) {
    Object* o = find(be(a.t[0x41]));
    if (o == nullptr) {
      return sw(r, 0U, 0x6A82U);
    }
    if (o->provisioned || !o->deletable || (restrict_mode != 0U)) {
      return sw(r, 0U, 0x6985U);
    }
    *o = Object{};
    return sw(r, 0U, 0x9000U);
  }
  std::size_t deleteAll(MutableByteSpan r) {
    if (scp_.auth_id != kFactoryReset) {
      return sw(r, 0U, 0x6985U);
    }
    ++delete_all;
    for (Object& o : objects_) {
      if (!o.provisioned) {
        o = Object{};
      }
    }
    return sw(r, 0U, 0x9000U);
  }
  std::size_t lockState(const Apdu& a, MutableByteSpan r) {
    if (scp_.auth_id != kTransport) {
      return sw(r, 0U, 0x6985U);
    }
    const uint32_t which = be(a.t[0x41]);
    const bool locked = be(a.t[0x42]) == 0x01U;
    if (which == 0x02U) {
      knobs.persistent_lock = locked;
    } else if (which == 0x01U) {
      transient_locked_ = locked;
    } else {
      return sw(r, 0U, 0x6A80U);
    }
    return sw(r, 0U, 0x9000U);
  }
  std::size_t scpRequest(const Apdu& a, MutableByteSpan r) {
    if (scp_.auth_id != kPlatformScp) {
      return sw(r, 0U, 0x6985U);
    }
    knobs.scp_required = be(a.t[0x41]) == 0x01U;
    return sw(r, 0U, 0x9000U);
  }
  std::size_t restrict(const Apdu& a, MutableByteSpan r) {
    if (scp_.auth_id != kRestrict) {
      return sw(r, 0U, 0x6985U);
    }
    restrict_mode = static_cast<uint8_t>(be(a.t[0x42]));
    return sw(r, 0U, 0x9000U);
  }
  [[nodiscard]] std::size_t selfTest(MutableByteSpan r) const {
    if (knobs.selftest_silent) {
      return 0U; // the chip resets itself and never answers
    }
    const uint8_t res = knobs.selftest_fails ? 0x02U : 0x01U;
    return sw(r, put(r, 0U, 0x41U, &res, 1U), 0x9000U);
  }

  // --- Objects (AN12543 4.7) ------------------------------------------------------------------
  std::size_t write(const Apdu& a, MutableByteSpan r) {
    const uint32_t id = be(a.t[0x41]);
    const bool transient = (a.ins & 0x80U) != 0U;
    Object* o = find(id);
    if ((o == nullptr) && (restrict_mode != 0U)) {
      return sw(r, 0U, 0x6985U);
    }
    switch (a.p1 & 0x1FU) {
    case 0x01U: // EC key
      return writeEc(a, o, id, transient, r);
    case 0x06U: // binary file
      return writeBinary(a, o, id, transient, r);
    case 0x07U: { // UserID: INS_AUTH_OBJECT is mandatory
      if (((a.ins & 0x40U) == 0U) || (o != nullptr)) {
        return sw(r, 0U, (o != nullptr) ? 0x6A89U : 0x6A80U);
      }
      static_cast<void>(add(id, Type::UserId, !transient));
      return sw(r, 0U, 0x9000U);
    }
    case 0x08U: // counter
      return writeCounter(a, o, id, transient, r);
    case 0x03U: // AES key (4.7.1.3)
      return writeAes(a, o, id, transient, r);
    default:
      break;
    }
    return sw(r, 0U, 0x6D00U);
  }
  std::size_t writeEc(const Apdu& a, Object* o, uint32_t id, bool transient, MutableByteSpan r) {
    if (o != nullptr) {
      return sw(r, 0U, 0x6A89U); // the model has no key update
    }
    if (!a.t[0x11].present || !a.t[0x42].present || (be(a.t[0x42]) != 0x03U)) {
      return sw(r, 0U, 0x6A80U); // a policy and NIST P-256 only
    }
    const Tlv& priv = a.t[0x43];
    const Tlv& pub = a.t[0x44];
    if ((priv.present && (priv.n != 32U)) ||
        (pub.present && ((pub.n != 65U) || (pub.v[0] != 4U)))) {
      return sw(r, 0U, 0x6A80U);
    }
    if (pub.present && !priv.present) { // a public key only (P1_PUBLIC)
      Object& k = add(id, Type::EcPub, !transient);
      CopyBytes(k.pub.data(), pub.v, 65U);
      return sw(r, 0U, 0x9000U);
    }
    Object& n = add(id, Type::EcPair, !transient);
    n.generated = !priv.present;
    if (priv.present) { // an imported key pair: the public key follows from the private one
      CopyBytes(n.priv.data(), priv.v, 32U);
      static_cast<void>(mc::PublicKey(n.priv.data(), n.pub.data()));
      return sw(r, 0U, 0x9000U);
    }
    for (std::size_t i = 0U; i < 32U; ++i) {
      ++rng_;
      n.priv[i] = static_cast<uint8_t>((rng_ * 97U) + (id & 0xFFU) + i);
    }
    n.priv[0] = static_cast<uint8_t>(n.priv[0] & 0x7FU); // below the group order
    static_cast<void>(mc::PublicKey(n.priv.data(), n.pub.data()));
    return sw(r, 0U, 0x9000U);
  }
  /// WriteSymmKey, AES (AN12543 p. 83): plain TAG_3, or TAG_3 wrapped (RFC 3394) under the AES
  /// key object named by TAG_2.
  std::size_t writeAes(const Apdu& a, Object* o, uint32_t id, bool transient, MutableByteSpan r) {
    if ((o != nullptr) || !a.t[0x11].present) {
      return sw(r, 0U, (o != nullptr) ? 0x6A89U : 0x6A80U);
    }
    const Tlv& k = a.t[0x43];
    uint8_t key[32] = {};
    std::size_t n = k.n;
    if (a.t[0x42].present) {
      const Object* kek = find(be(a.t[0x42]));
      if ((kek == nullptr) || (kek->type != Type::Aes) || !unwrap(*kek, k, key, n)) {
        return sw(r, 0U, 0x6A80U);
      }
    } else if ((n == 16U) || (n == 32U)) {
      CopyBytes(key, k.v, n);
    } else {
      return sw(r, 0U, 0x6A80U);
    }
    Object& x = add(id, Type::Aes, !transient);
    CopyBytes(x.priv.data(), key, n);
    x.size = n;
    return sw(r, 0U, 0x9000U);
  }
  /// RFC 3394 2.2.2 unwrap with the model's AES (one-block CBC decrypt with a zero IV is ECB).
  static bool unwrap(const Object& kek, const Tlv& in, uint8_t* out, std::size_t& n) {
    if ((in.n != 24U) && (in.n != 40U)) {
      return false;
    }
    const std::size_t blocks = (in.n / 8U) - 1U;
    uint8_t a[8];
    uint8_t rb[4][8];
    CopyBytes(a, in.v, 8U);
    for (std::size_t i = 0U; i < blocks; ++i) {
      CopyBytes(rb[i], in.v + 8U + (8U * i), 8U);
    }
    for (uint32_t step = 6U; step > 0U; --step) {
      const uint32_t j = step - 1U;
      for (std::size_t i = blocks; i >= 1U; --i) {
        const uint64_t t = (blocks * static_cast<uint64_t>(j)) + i;
        uint8_t b[16];
        CopyBytes(b, a, 8U);
        for (std::size_t q = 0U; q < 8U; ++q) {
          b[7U - q] = static_cast<uint8_t>(b[7U - q] ^ static_cast<uint8_t>(t >> (8U * q)));
        }
        CopyBytes(b + 8, rb[i - 1U], 8U);
        uint8_t iv[16] = {};
        static_cast<void>(mc::CbcDecrypt(mc::Bytes(kek.priv.data(), kek.size), iv, b, 16U));
        CopyBytes(a, b, 8U);
        CopyBytes(rb[i - 1U], b + 8, 8U);
      }
    }
    for (const uint8_t iv_byte : a) {
      if (iv_byte != 0xA6U) {
        return false; // the RFC 3394 integrity check value
      }
    }
    for (std::size_t i = 0U; i < blocks; ++i) {
      CopyBytes(out + (8U * i), rb[i], 8U);
    }
    n = 8U * blocks;
    return true;
  }
  std::size_t writeBinary(const Apdu& a, Object* o, uint32_t id, bool transient,
                          MutableByteSpan r) {
    const std::size_t offset = a.t[0x42].present ? be(a.t[0x42]) : 0U;
    if (o == nullptr) {
      const std::size_t length = be(a.t[0x43]);
      if (!a.t[0x11].present || (length == 0U) || (length > kMaxBinary)) {
        return sw(r, 0U, 0x6A80U);
      }
      o = &add(id, Type::Binary, !transient);
      o->size = length;
    } else if ((o->type != Type::Binary) || a.t[0x11].present) {
      return sw(r, 0U, 0x6A80U);
    } else {
      // an update of an existing file
    }
    const Tlv& d = a.t[0x44];
    if ((offset + d.n) > o->size) {
      return sw(r, 0U, 0x6A80U);
    }
    if (d.n != 0U) {
      CopyBytes(o->data.data() + offset, d.v, d.n);
    }
    return sw(r, 0U, 0x9000U);
  }
  std::size_t writeCounter(const Apdu& a, Object* o, uint32_t id, bool transient,
                           MutableByteSpan r) {
    if (o == nullptr) {
      if (!a.t[0x11].present) {
        return sw(r, 0U, 0x6A80U);
      }
      o = &add(id, Type::Counter, !transient);
      o->size = a.t[0x43].present ? a.t[0x43].n : be(a.t[0x42]);
      o->counter = a.t[0x43].present ? be(a.t[0x43]) : 0U;
      return sw(r, 0U, 0x9000U);
    }
    if (o->type != Type::Counter) {
      return sw(r, 0U, 0x6A80U);
    }
    if (a.t[0x43].present) {
      const uint64_t v = be(a.t[0x43]);
      if (v < o->counter) {
        return sw(r, 0U, 0x6A80U); // a counter never goes back
      }
      o->counter = v;
    } else {
      ++o->counter;
    }
    return sw(r, 0U, 0x9000U);
  }

  /// The attribute block of an object: id, SecureObjectType, SetIndicator NOT_SET, attempts 0,
  /// authentication object 0, maximum attempts 0, the policy set as created, origin, version 0.
  std::size_t attributes(const Apdu& a, MutableByteSpan r) {
    const Object* o = find(be(a.t[0x41]));
    if (o == nullptr) {
      return sw(r, 0U, 0x6A82U);
    }
    uint8_t block[14U + 64U + 5U] = {};
    for (std::size_t i = 0U; i < 4U; ++i) {
      block[i] = static_cast<uint8_t>(o->id >> (8U * (3U - i)));
    }
    constexpr uint8_t kWire[] = {0x00U, 0x01U, 0x03U, 0x0BU, 0x0DU, 0x0CU, 0x09U};
    block[4] = kWire[static_cast<std::size_t>(o->type)];
    block[5] = 0x01U; // NOT_SET
    CopyBytes(block + 14, o->policy.data(), o->policy_len);
    std::size_t n = 14U + o->policy_len;
    uint8_t origin = o->generated ? 0x02U : 0x01U; // ORIGIN_INTERNAL or ORIGIN_EXTERNAL
    if (o->provisioned) {
      origin = 0x03U; // ORIGIN_PROVISIONED
    }
    block[n] = origin;
    n += 5U;
    return sw(r, put(r, 0U, 0x43U, block, n), 0x9000U);
  }

  std::size_t read(const Apdu& a, MutableByteSpan r) {
    if (a.p2 == 0x5BU) { // ReadState (Tables 108, 109)
      if (!profile_.ext_version) {
        return sw(r, 0U, 0x6D00U);
      }
      const uint8_t v[3] = {static_cast<uint8_t>(Locked() ? 0x01U : 0x02U), restrict_mode,
                            static_cast<uint8_t>(knobs.scp_required ? 0x01U : 0x02U)};
      return sw(r, put82(r, 0U, 0x41U, v, 3U), 0x9000U);
    }
    if ((a.p1 == 0x0BU) && (a.p2 == 0x25U)) { // ReadECCurveList (4.8.4): NIST P-256 only
      uint8_t list[0x3F];
      static_cast<void>(std::memset(list, 0x01, sizeof(list))); // NOT_SET
      list[2] = 0x02U;                                          // curve id 0x03 SET
      return sw(r, put(r, 0U, 0x41U, list, sizeof(list)), 0x9000U);
    }
    if ((a.p2 == 0x00U) && (be(a.t[0x41]) == kUniqueId) && ((a.ins & 0x20U) == 0U)) {
      uint8_t uid[18];
      for (std::size_t i = 0U; i < 18U; ++i) {
        uid[i] = static_cast<uint8_t>(0xC0U + i); // the id the attested answers carry
        uid[i] = static_cast<uint8_t>(uid[i] ^ knobs.unique_id_flip);
      }
      return sw(r, put(r, 0U, 0x41U, uid, 18U), 0x9000U);
    }
    if (a.p2 == 0x26U) { // ReadType (4.7.4.1): SecureObjectType and TransientIndicator
      const Object* o = find(be(a.t[0x41]));
      if (o == nullptr) {
        return sw(r, 0U, 0x6A82U);
      }
      constexpr uint8_t kWire[] = {0x00U, 0x01U, 0x03U, 0x0BU, 0x0DU, 0x0CU, 0x09U};
      const uint8_t type[1] = {kWire[static_cast<std::size_t>(o->type)]};
      const uint8_t transient[1] = {static_cast<uint8_t>(o->persistent ? 0x01U : 0x02U)};
      std::size_t at = put(r, 0U, 0x41U, type, 1U);
      at = put(r, at, 0x42U, transient, 1U);
      return sw(r, at, 0x9000U);
    }
    if (a.p2 == 0x3BU) { // ReadObjectAttributes (4.7.4.x, applet 7.x layout: 14 + policy + 5)
      return attributes(a, r);
    }
    if (a.p2 == 0x07U) { // ReadSize (4.7.4.x): bytes of a file, a counter or a key
      const Object* s = find(be(a.t[0x41]));
      if (s == nullptr) {
        return sw(r, 0U, 0x6A82U);
      }
      std::size_t size = ((s->type == Type::Binary) || (s->type == Type::Counter)) ? s->size : 32U;
      if (knobs.zero_read_size) {
        size = 0U;
      }
      const uint8_t v[2] = {static_cast<uint8_t>(size >> 8U), static_cast<uint8_t>(size & 0xFFU)};
      return sw(r, put(r, 0U, 0x41U, v, 2U), 0x9000U);
    }
    if (a.p2 != 0x00U) {
      return sw(r, 0U, 0x6D00U);
    }
    const Object* o = find(be(a.t[0x41]));
    if (o == nullptr) {
      return sw(r, 0U, 0x6A82U);
    }
    uint8_t value[kMaxBinary];
    std::size_t n = 0U;
    if ((o->type == Type::EcPair) || (o->type == Type::EcPub)) {
      CopyBytes(value, o->pub.data(), 65U);
      n = 65U;
    } else if (o->type == Type::Binary) {
      const std::size_t off = a.t[0x42].present ? be(a.t[0x42]) : 0U;
      std::size_t len = a.t[0x43].present ? be(a.t[0x43]) : (o->size - std::min(off, o->size));
      if ((off + len) > o->size) {
        return sw(r, 0U, 0x6A80U);
      }
      CopyBytes(value, o->data.data() + off, len);
      n = len;
    } else if (o->type == Type::Counter) {
      for (std::size_t i = 0U; i < o->size; ++i) {
        value[i] = static_cast<uint8_t>(o->counter >> (8U * (o->size - 1U - i)));
      }
      n = o->size;
    } else {
      return sw(r, 0U, 0x6985U); // secrets are not read
    }
    // A faulty chip (knob) cuts the value short: the attested answer still states the whole size.
    const std::size_t whole = n;
    if ((knobs.read_truncate != 0U) && (n > 1U)) {
      n -= std::min<std::size_t>(knobs.read_truncate, n - 1U);
    }
    if ((a.ins & 0x20U) == 0U) {
      return sw(r, put(r, 0U, 0x41U, value, n), 0x9000U);
    }
    return attested(a, *o, value, n, whole, r);
  }

  /// The attested answer and its signature input (AN12543 3.2.7.2, Figure 4, Table 128).
  std::size_t attested(const Apdu& a, const Object& o, const uint8_t* value, std::size_t n,
                       std::size_t whole, MutableByteSpan r) {
    if (!profile_.ext_version) {
      return sw(r, 0U, 0x6D00U); // format 1 (applet 3.x) is not modelled
    }
    const Object* key = find(be(a.t[0x45]));
    if ((key == nullptr) || !key->attest || (be(a.t[0x46]) != 0x21U) || (a.t[0x47].n != 16U)) {
      return sw(r, 0U, 0x6985U);
    }
    uint8_t uid[18];
    for (std::size_t i = 0U; i < 18U; ++i) {
      uid[i] = static_cast<uint8_t>(0xC0U + i);
    }
    uint8_t attr[19] = {};
    for (std::size_t i = 0U; i < 4U; ++i) {
      attr[i] = static_cast<uint8_t>(o.id >> (8U * (3U - i)));
    }
    attr[4] = 0x01U;  // TYPE_EC_KEY_PAIR
    attr[5] = 0x01U;  // not an authentication object
    attr[14] = 0x01U; // ORIGIN_INTERNAL
    // The signed size, which a faulty chip (knob) states differently from the value it returns.
    const int32_t offset = knobs.attested_size_offset;
    const std::size_t stated = (offset >= 0) ? (whole + static_cast<std::size_t>(offset))
                                             : (whole - static_cast<std::size_t>(-offset));
    const uint8_t size[2] = {static_cast<uint8_t>(stated >> 8U),
                             static_cast<uint8_t>(stated & 0xFFU)};
    if (knobs.rewind_timestamp) {
      knobs.rewind_timestamp = false;
      ts_low_ = 0U;
    }
    ++ts_low_;
    uint8_t ts[12] = {0x00U, 0x00U, 0x00U, 0x07U};
    for (std::size_t i = 0U; i < 8U; ++i) {
      ts[4U + i] = static_cast<uint8_t>(ts_low_ >> (8U * (7U - i)));
    }
    // The TLVs in the `82 xx xx` form, or in the shortest form (knob): both are valid BER-TLV
    // (AN12543 4.1.3.2 p. 49); the signature covers the bytes as returned.
    const auto tlv = [this, &r](std::size_t pos, uint8_t tag, const uint8_t* v, std::size_t len) {
      return knobs.attested_short_tlv ? put(r, pos, tag, v, len) : put82(r, pos, tag, v, len);
    };
    std::size_t at = tlv(0U, 0x41U, value, n);
    at = tlv(at, 0x42U, uid, 18U);
    at = tlv(at, 0x43U, attr, 19U);
    at = tlv(at, 0x44U, size, 2U);
    at = tlv(at, 0x4FU, ts, 12U);
    // Signature input: SHA-256 of the plain command without Le, then the TLVs as returned.
    static uint8_t input[32 + 1200];
    mc::Sha256(command_, input);
    CopyBytes(input + 32, r.data(), at);
    uint8_t digest[32];
    mc::Sha256(mc::Bytes(input, 32U + at), digest);
    uint8_t der[72];
    const std::size_t dl = signDer(key->priv.data(), digest, der);
    at = put(r, at, 0x52U, der, dl);
    const std::size_t n_out = sw(r, at, 0x9000U);
    if (knobs.replay_attested && (replay_len_ != 0U)) {
      CopyBytes(r.data(), replay_.data(), replay_len_); // a bus attacker replays an old answer
      return replay_len_;
    }
    if (n_out <= replay_.size()) {
      CopyBytes(replay_.data(), r.data(), n_out);
      replay_len_ = n_out;
    }
    return n_out;
  }

  std::size_t crypto(const Apdu& a, MutableByteSpan r) {
    if ((a.p1 == 0x00U) && (a.p2 == 0x0EU)) { // DigestOneShot (4.19.4), SHA-256 only
      if (be(a.t[0x41]) != 0x04U) {
        return sw(r, 0U, 0x6A80U);
      }
      uint8_t d[32];
      mc::Sha256(mc::Bytes(a.t[0x42].v, a.t[0x42].n), d);
      return sw(r, put(r, 0U, 0x41U, d, 32U), 0x9000U);
    }
    if ((a.p1 == 0x01U) && (a.p2 == 0x0FU)) { // ECDHGenerateSharedSecret (4.10.3.1), P-256 x
      const Object* k = find(be(a.t[0x41]));
      if ((k == nullptr) || (k->type != Type::EcPair)) {
        return sw(r, 0U, 0x6A82U);
      }
      if ((a.t[0x42].n != 65U) || (a.t[0x42].v[0] != 0x04U)) {
        return sw(r, 0U, 0x6A80U);
      }
      uint8_t z[32];
      if (!mc::Ecdh(k->priv.data(), a.t[0x42].v, z)) {
        return sw(r, 0U, 0x6A80U);
      }
      return sw(r, put(r, 0U, 0x41U, z, 32U), 0x9000U);
    }
    if (a.p1 != 0x0CU) {
      return sw(r, 0U, 0x6D00U);
    }
    const Object* o = find(be(a.t[0x41]));
    if ((o == nullptr) || ((o->type != Type::EcPair) && (o->type != Type::EcPub))) {
      return sw(r, 0U, 0x6A82U);
    }
    const uint32_t algo = be(a.t[0x42]);
    if (algo == 0xA3U) {
      return eddsa(a, r);
    }
    if ((algo != 0x21U) || (a.t[0x43].n != 32U)) {
      return sw(r, 0U, 0x6A80U);
    }
    if (a.p2 == 0x09U) { // ECDSASign (4.10.1.1)
      if (o->type != Type::EcPair) {
        return sw(r, 0U, 0x6985U);
      }
      uint8_t der[72];
      const std::size_t dl = signDer(o->priv.data(), a.t[0x43].v, der);
      return sw(r, put(r, 0U, 0x41U, der, dl), 0x9000U);
    }
    if (a.p2 == 0x0AU) { // ECDSAVerify (4.10.2.1)
      uint8_t rs[64];
      const bool parsed = mc::ParseDer(mc::Bytes(a.t[0x45].v, a.t[0x45].n), rs, rs + 32);
      const bool ok = parsed && mc::Verify(o->pub.data(), a.t[0x43].v, rs, rs + 32);
      const uint8_t res = ok ? 0x01U : 0x02U;
      return sw(r, put(r, 0U, 0x41U, &res, 1U), 0x9000U);
    }
    return sw(r, 0U, 0x6D00U);
  }
  /// EdDSA input limits (AN12543 pp. 103-104): 940 bytes, 919 inside a UserID session.
  [[nodiscard]] std::size_t eddsa(const Apdu& a, MutableByteSpan r) const {
    if (!profile_.eddsa) {
      return sw(r, 0U, 0x6A80U);
    }
    const bool user_id = (knobs.user_id_auth != 0U) && (scp_.auth_id == knobs.user_id_auth);
    if (a.t[0x43].n > (user_id ? 919U : 940U)) {
      return sw(r, 0U, 0x6700U);
    }
    if (a.p2 == 0x09U) {
      uint8_t s[64];
      static_cast<void>(std::memset(s, 0x5A, sizeof(s)));
      return sw(r, put(r, 0U, 0x41U, s, 64U), 0x9000U);
    }
    bool zero = true;
    for (std::size_t i = 0U; i < a.t[0x45].n; ++i) {
      zero = zero && (a.t[0x45].v[i] == 0U);
    }
    const uint8_t res = zero ? 0x02U : 0x01U;
    return sw(r, put(r, 0U, 0x41U, &res, 1U), 0x9000U);
  }

  // --- The model's own ECDSA signer (FIPS 186-4 6.4; deterministic nonce, model only) -------
  std::size_t signDer(const uint8_t* priv, const uint8_t* digest, uint8_t* der) {
    const mc::U256& n = mc::OrderN();
    ++nonce_;
    uint8_t seed[32 + 32 + 4];
    CopyBytes(seed, priv, 32U);
    CopyBytes(seed + 32, digest, 32U);
    seed[64] = static_cast<uint8_t>(nonce_ >> 24U);
    seed[65] = static_cast<uint8_t>(nonce_ >> 16U);
    seed[66] = static_cast<uint8_t>(nonce_ >> 8U);
    seed[67] = static_cast<uint8_t>(nonce_);
    uint8_t kb[32];
    mc::Sha256(mc::Bytes(seed, sizeof(seed)), kb);
    mc::U256 k = mc::FromBe(kb);
    reduce(k);
    mc::U256 x;
    mc::U256 y;
    static_cast<void>(mc::Affine(mc::MulJ(k, mc::Base()), x, y));
    reduce(x);
    mc::U256 e = mc::FromBe(digest);
    reduce(e);
    const mc::U256 rd = mc::MulMod(x, mc::FromBe(priv), n);
    mc::U256 sum;
    const uint32_t carry = mc::AddRaw(sum, e, rd);
    if ((carry != 0U) || (mc::Cmp(sum, n) >= 0)) {
      static_cast<void>(mc::SubRaw(sum, sum, n));
    }
    const mc::U256 s = mc::MulMod(mc::InvN(k), sum, n);
    uint8_t rb[32];
    uint8_t sb[32];
    mc::ToBe(x, rb);
    mc::ToBe(s, sb);
    std::size_t at = 2U;
    at = derInt(der, at, rb);
    at = derInt(der, at, sb);
    der[0] = 0x30U;
    der[1] = static_cast<uint8_t>(at - 2U);
    return at;
  }
  static void reduce(mc::U256& v) {
    if (mc::Cmp(v, mc::OrderN()) >= 0) {
      static_cast<void>(mc::SubRaw(v, v, mc::OrderN()));
    }
  }
  static std::size_t derInt(uint8_t* der, std::size_t at, const uint8_t* v32) {
    std::size_t skip = 0U;
    while ((skip < 31U) && (v32[skip] == 0U)) {
      ++skip;
    }
    const bool pad = (v32[skip] & 0x80U) != 0U;
    const std::size_t len = (32U - skip) + (pad ? 1U : 0U);
    der[at++] = 0x02U;
    der[at++] = static_cast<uint8_t>(len);
    if (pad) {
      der[at++] = 0x00U;
    }
    CopyBytes(der + at, v32 + skip, 32U - skip);
    return at + (32U - skip);
  }

  // --- Store ----------------------------------------------------------------------------------
  Object& add(uint32_t id, Type type, bool persistent) {
    for (Object& o : objects_) {
      if (o.type == Type::None) {
        o = Object{};
        o.id = id;
        o.type = type;
        o.persistent = persistent;
        o.deletable = policyAllowsDelete();
        notePolicy(o);
        return o;
      }
    }
    return objects_.back(); // full: the tests never get here
  }
  /// Whether the policy of the command being answered lets anyone delete the object: no policy,
  /// or an entry whose header has POLICY_OBJ_ALLOW_DELETE (AN12543 Table 63, 0x00040000).
  /// Which authentication object the entry names is not checked.
  [[nodiscard]] bool policyAllowsDelete() const {
    if (!policy_.present) {
      return true;
    }
    std::size_t at = 0U;
    while ((at + 9U) <= policy_.n) {
      const uint8_t* e = policy_.v + at;
      const uint32_t header = (uint32_t{e[5]} << 24U) | (uint32_t{e[6]} << 16U) |
                              (uint32_t{e[7]} << 8U) | uint32_t{e[8]};
      if ((header & 0x00040000U) != 0U) {
        return true;
      }
      at += 1U + std::size_t{e[0]};
    }
    return false;
  }
  /// Record the authentication objects the policy of the command being answered names.
  void notePolicy(Object& o) const {
    std::size_t at = 0U;
    while (policy_.present && ((at + 9U) <= policy_.n) &&
           (o.policy_entries < o.policy_auth.size())) {
      const uint8_t* e = policy_.v + at;
      o.policy_auth[o.policy_entries] = (uint32_t{e[1]} << 24U) | (uint32_t{e[2]} << 16U) |
                                        (uint32_t{e[3]} << 8U) | uint32_t{e[4]};
      ++o.policy_entries;
      at += 1U + std::size_t{e[0]};
    }
    o.policy_len = (policy_.present && (policy_.n <= o.policy.size())) ? policy_.n : 0U;
    if (o.policy_len != 0U) {
      CopyBytes(o.policy.data(), policy_.v, o.policy_len);
    }
  }
  [[nodiscard]] Object* find(uint32_t id) {
    for (Object& o : objects_) {
      if ((o.type != Type::None) && (o.id == id)) {
        return &o;
      }
    }
    return nullptr;
  }
  [[nodiscard]] const Object* find(uint32_t id) const {
    for (const Object& o : objects_) {
      if ((o.type != Type::None) && (o.id == id)) {
        return &o;
      }
    }
    return nullptr;
  }

  ScpTarget& scp_;
  ChipProfile profile_;
  uint8_t patch_{profile_.patch};
  bool transient_locked_{true};
  uint32_t rng_{0};
  uint32_t nonce_{0};
  uint64_t ts_low_{0};
  ByteSpan command_;
  std::array<Object, 24> objects_{};
  std::array<uint8_t, 1100> replay_{};
  std::size_t replay_len_{0};
  Tlv policy_{}; ///< TAG_POLICY of the command being answered.
};

} // namespace se05x::testmodel

#endif // SE05X_TESTS_MODEL_CHIP_MODEL_HPP
