/**
 * @file scp_target.hpp
 * @brief `ScpTarget`: the chip side of platform SCP03, the applet sessions (AESKey, ECKey,
 * UserID), the card manager's GET DATA and the PERSO applet, for the host tests.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Written from the documents, not from the library (RD-07): GP Amendment D as AN12543 3.5, 3.6
 * and 4.5 apply it, AN12543 pp. 22-23 and 33-34 for the ECKey session, AN13015 Appendix B for
 * PERSO, the GetInfo logs of AN12436 p. 2 for the card identification data, errata JOS.2 for the
 * platform counter. Its crypto is `scp_crypto.hpp`, not the library's. It shares no code or table
 * with `inc/`; the only library type used is `ByteSpan` through `ApduHandler`.
 *
 * Counter semantics, chip side: platform SCP03 keeps `ctr` at 0 after EXTERNAL AUTHENTICATE and
 * increments it when a command with data arrives (JOS.2), or for every command with the knob
 * `gp_counter`; both the command and the response ICV use the current `ctr`. An applet session
 * starts at 1, uses the value for the command and the response, then increments. An error status
 * word is returned alone, without R-MAC (GP: no protection on an error).
 *
 * Plain commands that reach the IoT applet go to `applet` (an `ApduHandler`), or to the built-in
 * echo applet: it answers the command's data and 9000; INS 0x0F answers 6985; INS 0x0E answers
 * P1 * 256 + P2 pattern bytes. With an `applet`, the select of the IoT applet is answered by it too
 * (its version), `auth_id` tells it the authentication object of the session a command came in (0
 * in the default session), and a power cycle reaches it. A plain SELECT while platform SCP03 is
 * open ends the secure channel and is processed (GP Card Specification: a selection ends the
 * Secure Channel Session; AN12543 3.14 lists the select among the commands taken without SCP).
 *
 * No key in this file belongs to any real chip: the tests make their own.
 */
#ifndef SE05X_TESTS_MODEL_SCP_TARGET_HPP
#define SE05X_TESTS_MODEL_SCP_TARGET_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "model/model_if.hpp"
#include "model/scp_crypto.hpp"

namespace se05x::testmodel {

/** @brief Knobs of the SCP target for the open points and the fault tests. */
struct ScpKnobs {
  bool gp_counter{false};       ///< Platform: advance the counter for every command (not JOS.2).
  bool sequence_counter{false}; ///< INITIALIZE UPDATE answers 32 bytes (pseudo-random challenge).
  bool bad_card_cryptogram{false}; ///< Corrupt the card cryptogram.
  bool eckey_mcv_zero{false};      ///< ECKey: start the MAC chain at zero instead of KDF(08).
  bool receipt_wrong{false};       ///< ECKey: send a wrong receipt (A15).
  bool perso_present{true};        ///< The PERSO applet is still on the chip.
  bool rmac_on_errors{false};      ///< Add an R-MAC to an error status word (not GP).
  uint8_t scp_id{0x03U};           ///< The SCP identifier in INITIALIZE UPDATE's key information.
};

/** @brief The SCP target. */
class ScpTarget : public ApduHandler {
public:
  using Key = std::array<uint8_t, 32>;

  ScpKnobs knobs{};
  ApduHandler* applet{nullptr}; ///< The IoT applet behind the sessions; null: the echo applet.
  uint16_t oef_id{0xA921U};     ///< The OEF id in the card identification data (bytes 2 and 3).
  uint32_t auth_id{0};          ///< For `applet`: the session's authentication object, or 0.

  /** @brief Set the platform key set (16 or 32 bytes each) and its version. */
  void SetPlatformKeys(const uint8_t* enc, const uint8_t* mac, std::size_t len, uint8_t kvn) {
    static_cast<void>(std::memcpy(pf_enc_.data(), enc, len));
    static_cast<void>(std::memcpy(pf_mac_.data(), mac, len));
    pf_len_ = len;
    kvn_ = kvn;
  }
  /** @brief Register an AESKey authentication object. */
  void AddAesKey(uint32_t id, const uint8_t* key16) {
    Cred& c = newCred(id, 1);
    static_cast<void>(std::memcpy(c.secret.data(), key16, 16U));
    c.secret_len = 16U;
  }
  /** @brief Register an ECKey authentication object (the host's public key). */
  void AddEcKey(uint32_t id, const uint8_t* pub65) {
    Cred& c = newCred(id, 2);
    static_cast<void>(std::memcpy(c.pub.data(), pub65, 65U));
  }
  /** @brief Register a UserID object. */
  void AddUserId(uint32_t id, const uint8_t* value, std::size_t len, uint32_t max_attempts) {
    Cred& c = newCred(id, 3);
    static_cast<void>(std::memcpy(c.secret.data(), value, len));
    c.secret_len = len;
    c.max_attempts = max_attempts;
  }
  /** @brief The chip's ECKey-session key pair (RESERVED_ID_ECKEY_SESSION). */
  void SetSeKey(const uint8_t* priv32) {
    static_cast<void>(std::memcpy(se_priv_.data(), priv32, 32U));
    static_cast<void>(mc::PublicKey(se_priv_.data(), se_pub_.data()));
  }
  [[nodiscard]] const std::array<uint8_t, 65>& SePublic() const {
    return se_pub_;
  }
  /** @brief The PERSO I2C parameters byte and address. */
  uint8_t perso_i2c_params{0x11U};
  uint8_t perso_i2c_address{0x48U};

  // Observations for the tests.
  bool platform_open{false};
  uint32_t platform_ctr{0};
  uint32_t commands{0};
  uint32_t applet_commands{0};
  uint32_t mac_failures{0};
  uint32_t sessions_open{0};
  std::array<uint8_t, 1100> last_plain{}; ///< The last plain command the applet received.
  std::size_t last_plain_len{0};

  std::size_t Handle(se05x::ByteSpan command, se05x::MutableByteSpan response) override {
    ++commands;
    std::size_t n = 0U;
    if (platform_open && (command.size() >= 2U) && (command[0] == 0x80U) && (command[1] == 0x50U)) {
      platform_open = false; // GP: INITIALIZE UPDATE ends the open secure channel
    }
    if (platform_open && (command.size() >= 2U) && (command[0] == 0x00U) && (command[1] == 0xA4U)) {
      platform_open = false; // GP: a selection ends the secure channel session
    }
    if (platform_open && ((command[0] & 0x04U) != 0U) && (command.size() >= 4U) &&
        !(command[1] == 0xA4U)) {
      n = platformCommand(command, response);
    } else if (platform_open) {
      n = putSw(response, 0, 0x6982U);
    } else {
      n = plainCommand(command, response);
    }
    return n;
  }

  void PowerCycle() override {
    platform_open = false;
    pf_pending_ = Pending{};
    for (Session& s : sessions_) {
      s = Session{};
    }
    sessions_open = 0U;
    selected_ = Sel::None;
    if (applet != nullptr) {
      applet->PowerCycle();
    }
  }

private:
  enum class Sel : uint8_t { None, Isd, Iot, Perso };
  struct Cred {
    uint32_t id{0};
    int type{0}; // 1 AESKey, 2 ECKey, 3 UserID
    std::array<uint8_t, 32> secret{};
    std::size_t secret_len{0};
    std::array<uint8_t, 65> pub{};
    uint32_t max_attempts{0};
    uint32_t failures{0};
  };
  struct Sm {
    Key enc{}, mac{}, rmac{};
    std::size_t len{16};
    std::array<uint8_t, 16> mcv{};
    uint32_t ctr{0};
    uint8_t level{0};
  };
  struct Pending {
    bool active{false};
    std::array<uint8_t, 16> ctx{};
    Sm sm{};
  };
  struct Session {
    bool used{false};
    std::array<uint8_t, 8> id{};
    Cred* cred{nullptr};
    bool authenticated{false};
    bool secure{false};
    Pending pending{};
    Sm sm{};
  };

  Cred& newCred(uint32_t id, int type) {
    Cred& c = creds_[ncreds_++ % creds_.size()];
    c = Cred{};
    c.id = id;
    c.type = type;
    return c;
  }

  static std::size_t putSw(se05x::MutableByteSpan r, std::size_t at, uint16_t sw) {
    r[at] = static_cast<uint8_t>(sw >> 8);
    r[at + 1U] = static_cast<uint8_t>(sw);
    return at + 2U;
  }

  static void kdf(const uint8_t* key, std::size_t klen, uint8_t constant, const uint8_t* ctx,
                  std::size_t clen, uint8_t* out, std::size_t outlen) {
    uint8_t dd[32] = {};
    dd[11] = constant;
    const auto bits = static_cast<uint32_t>(outlen * 8U);
    dd[13] = static_cast<uint8_t>(bits >> 8);
    dd[14] = static_cast<uint8_t>(bits);
    static_cast<void>(std::memcpy(dd + 16, ctx, clen));
    for (std::size_t i = 0U; (i * 16U) < outlen; ++i) {
      dd[15] = static_cast<uint8_t>(i + 1U);
      uint8_t blk[16];
      mc::Cmac(mc::Bytes(key, klen), mc::Bytes(dd, 16U + clen), blk);
      const std::size_t take = ((outlen - (i * 16U)) < 16U) ? (outlen - (i * 16U)) : 16U;
      static_cast<void>(std::memcpy(out + (i * 16U), blk, take));
    }
  }

  // --- INITIALIZE UPDATE and EXTERNAL AUTHENTICATE, platform or AESKey session ---
  std::size_t initUpdate(se05x::ByteSpan c, se05x::MutableByteSpan r, const uint8_t* enc,
                         const uint8_t* mac, std::size_t klen, uint8_t kvn, Pending& p) {
    if ((c.size() < 13U) || (c[4] != 8U)) {
      return putSw(r, 0, 0x6700U);
    }
    if ((c[2] != 0U) && (c[2] != kvn)) {
      return putSw(r, 0, 0x6A88U);
    }
    std::array<uint8_t, 8> card{};
    ++challenge_seed_;
    for (std::size_t i = 0U; i < 8U; ++i) {
      card[i] = static_cast<uint8_t>((std::size_t{challenge_seed_} * 37U) + (i * 11U) + 5U);
    }
    static_cast<void>(std::memcpy(p.ctx.data(), &c[5], 8U));
    static_cast<void>(std::memcpy(p.ctx.data() + 8, card.data(), 8U));
    p.sm = Sm{};
    p.sm.len = klen;
    kdf(enc, klen, 0x04U, p.ctx.data(), 16U, p.sm.enc.data(), klen);
    kdf(mac, klen, 0x06U, p.ctx.data(), 16U, p.sm.mac.data(), klen);
    kdf(mac, klen, 0x07U, p.ctx.data(), 16U, p.sm.rmac.data(), klen);
    std::size_t i = 0U;
    for (int k = 0; k < 10; ++k) {
      r[i++] = static_cast<uint8_t>(0xD0 + k); // key diversification data
    }
    r[i++] = kvn;
    r[i++] = knobs.scp_id; // SCP03 unless a test says otherwise
    r[i++] = knobs.sequence_counter ? 0x10U : 0x00U;
    static_cast<void>(std::memcpy(&r[i], card.data(), 8U));
    i += 8U;
    uint8_t crypt[8];
    kdf(p.sm.mac.data(), klen, 0x00U, p.ctx.data(), 16U, crypt, 8U);
    if (knobs.bad_card_cryptogram) {
      crypt[0] = static_cast<uint8_t>(crypt[0] ^ 0x01U);
    }
    static_cast<void>(std::memcpy(&r[i], crypt, 8U));
    i += 8U;
    if (knobs.sequence_counter) {
      r[i++] = 0x00U;
      r[i++] = 0x00U;
      r[i++] = static_cast<uint8_t>(challenge_seed_);
    }
    p.active = true;
    return putSw(r, i, 0x9000U);
  }

  std::size_t extAuth(se05x::ByteSpan c, se05x::MutableByteSpan r, Pending& p, Sm& out,
                      uint32_t first_ctr) {
    if ((!p.active) || (c.size() != 21U) || (c[0] != 0x84U) || (c[4] != 0x10U)) {
      p.active = false;
      return putSw(r, 0, 0x6982U);
    }
    uint8_t host[8];
    kdf(p.sm.mac.data(), p.sm.len, 0x01U, p.ctx.data(), 16U, host, 8U);
    uint8_t buf[16 + 13] = {};
    static_cast<void>(std::memcpy(buf + 16, c.data(), 13U));
    uint8_t mac[16];
    mc::Cmac(mc::Bytes(p.sm.mac.data(), p.sm.len), mc::Bytes(buf, sizeof(buf)), mac);
    const bool ok = (std::memcmp(host, &c[5], 8U) == 0) && (std::memcmp(mac, &c[13], 8U) == 0);
    p.active = false;
    if (!ok) {
      return putSw(r, 0, 0x6300U);
    }
    out = p.sm;
    static_cast<void>(std::memcpy(out.mcv.data(), mac, 16U));
    out.level = c[2];
    out.ctr = first_ctr;
    return putSw(r, 0, 0x9000U);
  }

  // --- Command unwrap and response wrap (chip side) ---
  /// Unwrap into `plain`; returns its length, 0 on a MAC failure.
  std::size_t unwrap(se05x::ByteSpan c, Sm& sm, bool platform, uint8_t* plain) {
    if (c.size() < 13U) {
      return 0U;
    }
    std::size_t lc = c[4];
    std::size_t at = 5U;
    if (lc == 0U) {
      lc = (std::size_t{c[5]} << 8) | c[6];
      at = 7U;
    }
    if ((lc < 8U) || ((at + lc) > c.size())) {
      return 0U;
    }
    const bool has_le = c.size() > (at + lc);
    const std::size_t dlen = lc - 8U;
    static uint8_t buf[16 + 1100];
    static_cast<void>(std::memcpy(buf, sm.mcv.data(), 16U));
    static_cast<void>(std::memcpy(buf + 16, c.data(), at + dlen));
    uint8_t mac[16];
    mc::Cmac(mc::Bytes(sm.mac.data(), sm.len), mc::Bytes(buf, 16U + at + dlen), mac);
    if (std::memcmp(mac, &c[at + dlen], 8U) != 0) {
      ++mac_failures;
      return 0U;
    }
    static_cast<void>(std::memcpy(sm.mcv.data(), mac, 16U));
    if (platform && ((dlen != 0U) || knobs.gp_counter)) {
      ++sm.ctr;
    }
    uint8_t data[1100];
    static_cast<void>(std::memcpy(data, &c[at], dlen));
    std::size_t plen = dlen;
    if (((sm.level & 0x02U) != 0U) && (dlen != 0U)) {
      uint8_t iv[16] = {};
      iv[12] = static_cast<uint8_t>(sm.ctr >> 24);
      iv[13] = static_cast<uint8_t>(sm.ctr >> 16);
      iv[14] = static_cast<uint8_t>(sm.ctr >> 8);
      iv[15] = static_cast<uint8_t>(sm.ctr);
      mc::EncryptBlock(mc::Bytes(sm.enc.data(), sm.len), iv);
      if (((dlen % 16U) != 0U) ||
          !mc::CbcDecrypt(mc::Bytes(sm.enc.data(), sm.len), iv, data, dlen)) {
        return 0U;
      }
      while ((plen > 0U) && (data[plen - 1U] == 0U)) {
        --plen;
      }
      if ((plen == 0U) || (data[plen - 1U] != 0x80U)) {
        return 0U;
      }
      --plen;
    }
    std::size_t i = 0U;
    plain[i++] = static_cast<uint8_t>(c[0] & ~0x04U);
    plain[i++] = c[1];
    plain[i++] = c[2];
    plain[i++] = c[3];
    if (plen > 0U) {
      if (plen > 255U) {
        plain[i++] = 0U;
        plain[i++] = static_cast<uint8_t>(plen >> 8);
        plain[i++] = static_cast<uint8_t>(plen);
      } else {
        plain[i++] = static_cast<uint8_t>(plen);
      }
      static_cast<void>(std::memcpy(&plain[i], data, plen));
      i += plen;
    }
    if (has_le) {
      plain[i++] = 0x00U;
    }
    return i;
  }

  /// Wrap a plain response in place: `r[0, n)` is data || SW.
  std::size_t wrap(se05x::MutableByteSpan r, std::size_t n, Sm& sm) const {
    if (n < 2U) {
      return 0U; // the applet gave no answer (it reset itself): nothing to wrap, nothing sent
    }
    const auto sw = static_cast<uint16_t>((unsigned{r[n - 2U]} << 8U) | unsigned{r[n - 1U]});
    if ((sw != 0x9000U) && !knobs.rmac_on_errors) {
      return putSw(r, 0, sw);
    }
    std::size_t dlen = (sw == 0x9000U) ? (n - 2U) : 0U;
    if (((sm.level & 0x20U) != 0U) && (dlen != 0U)) {
      r[dlen++] = 0x80U;
      while ((dlen % 16U) != 0U) {
        r[dlen++] = 0x00U;
      }
      uint8_t iv[16] = {};
      iv[0] = 0x80U;
      iv[12] = static_cast<uint8_t>(sm.ctr >> 24);
      iv[13] = static_cast<uint8_t>(sm.ctr >> 16);
      iv[14] = static_cast<uint8_t>(sm.ctr >> 8);
      iv[15] = static_cast<uint8_t>(sm.ctr);
      mc::EncryptBlock(mc::Bytes(sm.enc.data(), sm.len), iv);
      static_cast<void>(mc::CbcEncrypt(mc::Bytes(sm.enc.data(), sm.len), iv, r.data(), dlen));
    }
    if ((sm.level & 0x10U) != 0U) {
      static uint8_t buf[16 + 1100];
      static_cast<void>(std::memcpy(buf, sm.mcv.data(), 16U));
      static_cast<void>(std::memcpy(buf + 16, r.data(), dlen));
      buf[16 + dlen] = static_cast<uint8_t>(sw >> 8);
      buf[17 + dlen] = static_cast<uint8_t>(sw);
      uint8_t mac[16];
      mc::Cmac(mc::Bytes(sm.rmac.data(), sm.len), mc::Bytes(buf, 18U + dlen), mac);
      static_cast<void>(std::memcpy(&r[dlen], mac, 8U));
      dlen += 8U;
    }
    return putSw(r, dlen, sw);
  }

  std::size_t platformCommand(se05x::ByteSpan c, se05x::MutableByteSpan r) {
    static uint8_t plain[1100];
    const std::size_t n = unwrap(c, pf_, true, plain);
    if (n == 0U) {
      platform_open = false; // GP: a MAC failure ends the secure channel
      return putSw(r, 0, 0x6982U);
    }
    platform_ctr = pf_.ctr;
    const std::size_t m = plainCommand(se05x::ByteSpan(plain, n), r);
    return wrap(r, m, pf_);
  }

  // --- Plain dispatch ---
  std::size_t plainCommand(se05x::ByteSpan c, se05x::MutableByteSpan r) {
    if (c.size() < 4U) {
      return putSw(r, 0, 0x6700U);
    }
    if ((c[0] == 0x00U) && (c[1] == 0xA4U)) {
      return select(c, r);
    }
    if (c[1] == 0x50U) {
      return initUpdate(c, r, pf_enc_.data(), pf_mac_.data(), pf_len_, kvn_, pf_pending_);
    }
    if (c[1] == 0x82U) {
      const std::size_t n = extAuth(c, r, pf_pending_, pf_, 0U);
      platform_open = (r[n - 2U] == 0x90U);
      platform_ctr = 0U;
      return n;
    }
    switch (selected_) {
    case Sel::Isd:
      return getData(c, r);
    case Sel::Perso:
      return perso(c, r);
    case Sel::Iot:
      return iot(c, r);
    case Sel::None:
    default:
      break;
    }
    return putSw(r, 0, 0x6D00U);
  }

  std::size_t select(se05x::ByteSpan c, se05x::MutableByteSpan r) {
    static const uint8_t kIsd[8] = {0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00};
    static const uint8_t kIotAid[16] = {0xA0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00,
                                        0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00};
    static const uint8_t kPersoAid[16] = {0xA0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00,
                                          0x00, 0x00, 0x01, 0x03, 0x40, 0x00, 0x00, 0x00};
    for (Session& s : sessions_) {
      s = Session{};
    }
    sessions_open = 0U;
    const std::size_t lc = (c.size() > 4U) ? c[4] : 0U;
    if ((c.size() < (5U + lc)) || (lc == 0U)) {
      return putSw(r, 0, 0x6700U);
    }
    const uint8_t* aid = &c[5];
    if ((lc == 8U) && (std::memcmp(aid, kIsd, 8U) == 0)) {
      selected_ = Sel::Isd;
      static const uint8_t kFci[] = {0x6F, 0x0A, 0x84, 0x08, 0xA0, 0x00,
                                     0x00, 0x01, 0x51, 0x00, 0x00, 0x00};
      static_cast<void>(std::memcpy(r.data(), kFci, sizeof(kFci)));
      return putSw(r, sizeof(kFci), 0x9000U);
    }
    if ((lc == 16U) && (std::memcmp(aid, kIotAid, 16U) == 0) && (applet != nullptr)) {
      auth_id = 0U;
      const std::size_t n = applet->Handle(c, r);
      selected_ = ((n >= 2U) && (r[n - 2U] == 0x90U)) ? Sel::Iot : Sel::None;
      return n;
    }
    if ((lc == 16U) && (std::memcmp(aid, kIotAid, 16U) == 0)) {
      selected_ = Sel::Iot;
      static const uint8_t kVer[7] = {7, 2, 0, 0x3F, 0xFF, 0x01, 0x0B};
      static_cast<void>(std::memcpy(r.data(), kVer, 7U));
      return putSw(r, 7U, 0x9000U);
    }
    if ((lc == 16U) && (std::memcmp(aid, kPersoAid, 16U) == 0) && knobs.perso_present) {
      selected_ = Sel::Perso;
      static const uint8_t kVer[7] = {1, 4, 0, 0x00, 0x00, 0x00, 0x01};
      static_cast<void>(std::memcpy(r.data(), kVer, 7U));
      return putSw(r, 7U, 0x9000U);
    }
    selected_ = Sel::None;
    return putSw(r, 0, 0x6A82U);
  }

  [[nodiscard]] std::size_t getData(se05x::ByteSpan c, se05x::MutableByteSpan r) const {
    if ((c[0] != 0x80U) || (c[1] != 0xCAU)) {
      return putSw(r, 0, 0x6D00U);
    }
    std::size_t i = 0U;
    if ((c[2] == 0x9FU) && (c[3] == 0x7FU)) {
      r[i++] = 0x9FU;
      r[i++] = 0x7FU;
      r[i++] = 0x2AU;
      for (int k = 0; k < 42; ++k) {
        r[i++] = static_cast<uint8_t>(0x40 + k);
      }
      return putSw(r, i, 0x9000U);
    }
    if ((c[2] == 0x00U) && (c[3] == 0xFEU)) {
      // Layout of the GetInfo log, AN12436 p. 2 (values here are the model's own).
      static const uint8_t kDf28[] = {
          0x01, 0x0C, 0x00, 0x05, 0xA9, 0x21, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
          0x02, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x18, 0x4A, 0x33,
          0x52, 0x33, 0x35, 0x31, 0x30, 0x32, 0x39, 0x42, 0x34, 0x31, 0x31, 0x31, 0x30, 0x30,
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x05, 0x01, 0x00, 0x07, 0x01, 0x00,
          0x08, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
      r[i++] = 0xFEU;
      r[i++] = static_cast<uint8_t>(3U + sizeof(kDf28));
      r[i++] = 0xDFU;
      r[i++] = 0x28U;
      r[i++] = static_cast<uint8_t>(sizeof(kDf28));
      static_cast<void>(std::memcpy(&r[i], kDf28, sizeof(kDf28)));
      r[i + 4U] = static_cast<uint8_t>(oef_id >> 8U);
      r[i + 5U] = static_cast<uint8_t>(oef_id & 0xFFU);
      i += sizeof(kDf28);
      return putSw(r, i, 0x9000U);
    }
    if ((c[2] == 0x00U) && (c[3] == 0xE0U)) {
      r[i++] = 0xE0U;
      r[i++] = 18U;
      for (uint8_t id = 1U; id <= 3U; ++id) {
        r[i++] = 0xC0U;
        r[i++] = 0x04U;
        r[i++] = id;
        r[i++] = kvn_;
        r[i++] = 0x88U;
        r[i++] = static_cast<uint8_t>(pf_len_);
      }
      return putSw(r, i, 0x9000U);
    }
    return putSw(r, 0, 0x6A88U);
  }

  [[nodiscard]] std::size_t perso(se05x::ByteSpan c, se05x::MutableByteSpan r) const {
    if ((c[0] != 0x80U) || (c[1] != 0x02U) || (c.size() != 7U) || (c[4] != 1U)) {
      return putSw(r, 0, 0x6D00U);
    }
    const uint32_t tag = (uint32_t{c[2]} << 8) | c[3];
    uint8_t value[32] = {};
    std::size_t len = 0U;
    if (tag == 0x800DU) {
      value[0] = perso_i2c_address;
      len = 1U;
    } else if (tag == 0x800EU) {
      value[0] = perso_i2c_params;
      len = 1U;
    } else if (tag == 0x8014U) {
      value[0] = 0x00U;
      len = 1U;
    } else if (tag == 0x8016U) {
      for (std::size_t k = 0U; k < 20U; ++k) {
        value[k] = static_cast<uint8_t>(0x30U + k);
      }
      len = 20U;
    } else {
      return putSw(r, 0, 0x6A81U);
    }
    if (c[5] < len) {
      return putSw(r, 0, 0x6700U);
    }
    r[0] = 0x41U;
    r[1] = static_cast<uint8_t>(len);
    static_cast<void>(std::memcpy(&r[2], value, len));
    return putSw(r, 2U + len, 0x9000U);
  }

  // --- IoT applet: sessions, then the applet behind ---
  std::size_t iot(se05x::ByteSpan c, se05x::MutableByteSpan r) {
    if ((c[0] == 0x80U) && (c[1] == 0x04U) && (c[3] == 0x1BU)) {
      return createSession(c, r);
    }
    if ((c[0] == 0x80U) && (c[1] == 0x05U)) {
      return process(c, r);
    }
    return appletCommand(c, r);
  }

  std::size_t appletCommand(se05x::ByteSpan c, se05x::MutableByteSpan r) {
    ++applet_commands;
    static_cast<void>(std::memcpy(last_plain.data(), c.data(), c.size()));
    last_plain_len = c.size();
    if (applet != nullptr) {
      return applet->Handle(c, r);
    }
    if (c[1] == 0x0FU) {
      return putSw(r, 0, 0x6985U);
    }
    if (c[1] == 0x0EU) {
      const std::size_t n = (std::size_t{c[2]} << 8) | c[3];
      for (std::size_t k = 0U; k < n; ++k) {
        r[k] = static_cast<uint8_t>((k * 7U) + 1U);
      }
      return putSw(r, n, 0x9000U);
    }
    // ISO 7816-4 cases: 4 bytes (no body), 5 (Le only), short Lc, extended (00 Lc1 Lc2).
    std::size_t lc = 0U;
    std::size_t at = 5U;
    if (c.size() > 5U) {
      lc = c[4];
      if ((lc == 0U) && (c.size() > 7U)) {
        lc = (std::size_t{c[5]} << 8) | c[6];
        at = 7U;
      }
    }
    if ((at + lc) > c.size()) {
      lc = 0U;
    }
    if (lc != 0U) {
      static_cast<void>(std::memcpy(r.data(), c.data() + at, lc));
    }
    return putSw(r, lc, 0x9000U);
  }

  std::size_t createSession(se05x::ByteSpan c, se05x::MutableByteSpan r) {
    if ((c.size() != 12U) || (c[5] != 0x41U) || (c[6] != 4U)) {
      return putSw(r, 0, 0x6985U);
    }
    const uint32_t id =
        (uint32_t{c[7]} << 24) | (uint32_t{c[8]} << 16) | (uint32_t{c[9]} << 8) | c[10];
    Cred* cred = nullptr;
    for (Cred& k : creds_) {
      if ((k.type != 0) && (k.id == id)) {
        cred = &k;
      }
    }
    if (cred == nullptr) {
      return putSw(r, 0, 0x6985U);
    }
    for (Session& s : sessions_) {
      if (!s.used) {
        s = Session{};
        s.used = true;
        s.cred = cred;
        ++session_seed_;
        for (std::size_t k = 0U; k < 8U; ++k) {
          s.id[k] = static_cast<uint8_t>((std::size_t{session_seed_} * 13U) + k);
        }
        ++sessions_open;
        // AN13904 p. 16 shows the 0x82 length form in this answer: use it.
        r[0] = 0x41U;
        r[1] = 0x82U;
        r[2] = 0x00U;
        r[3] = 0x08U;
        static_cast<void>(std::memcpy(&r[4], s.id.data(), 8U));
        return putSw(r, 12U, 0x9000U);
      }
    }
    return putSw(r, 0, 0x6985U);
  }

  std::size_t process(se05x::ByteSpan c, se05x::MutableByteSpan r) {
    // 80 05 00 00 Lc [ext] 10 08 id 41 L inner Le
    std::size_t at = 5U;
    std::size_t lc = c[4];
    if (lc == 0U) {
      lc = (std::size_t{c[5]} << 8) | c[6];
      at = 7U;
    }
    if ((c.size() < (at + lc)) || (lc < 12U) || (c[at] != 0x10U) || (c[at + 1U] != 8U)) {
      return putSw(r, 0, 0x6985U);
    }
    Session* s = nullptr;
    for (Session& k : sessions_) {
      if (k.used && (std::memcmp(k.id.data(), &c[at + 2U], 8U) == 0)) {
        s = &k;
      }
    }
    std::size_t p = at + 10U;
    if ((s == nullptr) || (c[p] != 0x41U)) {
      return putSw(r, 0, 0x6985U);
    }
    std::size_t ilen = c[p + 1U];
    p += 2U;
    if (ilen == 0x81U) {
      ilen = c[p++];
    } else if (ilen == 0x82U) {
      ilen = (std::size_t{c[p]} << 8) | c[p + 1U];
      p += 2U;
    } else {
      // one-byte length
    }
    if ((p + ilen) > (at + lc)) {
      return putSw(r, 0, 0x6985U);
    }
    return sessionCommand(*s, se05x::ByteSpan(&c[p], ilen), r);
  }

  void endSession(Session& s) {
    s = Session{};
    if (sessions_open > 0U) {
      --sessions_open;
    }
  }

  std::size_t sessionCommand(Session& s, se05x::ByteSpan in, se05x::MutableByteSpan r) {
    if (!s.authenticated) {
      return authenticate(s, in, r);
    }
    if (!s.secure) {
      if ((in[1] == 0x04U) && (in.size() == 4U) && (in[3] == 0x1CU)) {
        endSession(s);
        return putSw(r, 0, 0x9000U);
      }
      auth_id = s.cred->id;
      const std::size_t answered = appletCommand(in, r);
      auth_id = 0U;
      return answered;
    }
    static uint8_t plain[1100];
    const std::size_t n = unwrap(in, s.sm, false, plain);
    if (n == 0U) {
      endSession(s);
      return putSw(r, 0, 0x6982U);
    }
    std::size_t m = 0U;
    const bool close = (plain[1] == 0x04U) && (plain[3] == 0x1CU);
    if (close) {
      m = putSw(r, 0, 0x9000U);
    } else {
      auth_id = s.cred->id;
      m = appletCommand(se05x::ByteSpan(plain, n), r);
      auth_id = 0U;
    }
    const bool delete_all = (n >= 4U) && ((plain[1] & 0x0FU) == 0x04U) && (plain[3] == 0x2AU);
    if (delete_all && (m == 2U) && (r[0] == 0x90U) && (r[1] == 0x00U)) {
      endSession(s); // AN12543 4.20.5 p. 154: the session ends, the answer is not wrapped
      return m;
    }
    m = wrap(r, m, s.sm);
    ++s.sm.ctr;
    if (close) {
      endSession(s);
    }
    return m;
  }

  std::size_t authenticate(Session& s, se05x::ByteSpan in, se05x::MutableByteSpan r) {
    Cred& cred = *s.cred;
    if ((cred.type == 1) && (in[1] == 0x50U)) {
      if (in[2] != 0U) {
        return putSw(r, 0, 0x6A80U);
      }
      return initUpdate(in, r, cred.secret.data(), cred.secret.data(), 16U, 0U, s.pending);
    }
    if ((cred.type == 1) && (in[1] == 0x82U)) {
      const std::size_t n = extAuth(in, r, s.pending, s.sm, 1U);
      if (r[n - 2U] == 0x90U) {
        s.authenticated = true;
        s.secure = true;
      }
      return n;
    }
    if ((cred.type == 3) && (in[1] == 0x04U) && (in[3] == 0x2CU)) {
      return verifyUserId(s, cred, in, r);
    }
    if ((cred.type == 2) && (in[0] == 0x84U) && (in[1] == 0x88U)) {
      return ecKeyAuth(s, cred, in, r);
    }
    return putSw(r, 0, 0x6985U);
  }

  std::size_t verifyUserId(Session& s, Cred& cred, se05x::ByteSpan in, se05x::MutableByteSpan r) {
    if ((cred.max_attempts != 0U) && (cred.failures >= cred.max_attempts)) {
      return putSw(r, 0, 0x6985U);
    }
    const bool ok = (in.size() == (7U + cred.secret_len)) && (in[5] == 0x41U) &&
                    (in[6] == cred.secret_len) &&
                    (std::memcmp(&in[7], cred.secret.data(), cred.secret_len) == 0);
    if (!ok) {
      ++cred.failures;
      return putSw(r, 0, 0x6985U);
    }
    cred.failures = 0U;
    s.authenticated = true;
    s.secure = false;
    return putSw(r, 0, 0x9000U);
  }

  std::size_t ecKeyAuth(Session& s, Cred& cred, se05x::ByteSpan in, se05x::MutableByteSpan r) {
    // 84 88 00 00 Lc A6(31) 7F49(73) 5F37 len der [Le]
    // AN13904 Figure 7: the command fills its TAG_1 exactly, 5 + Lc bytes, no Le.
    if ((in.size() < (5U + 104U + 3U)) || (in.size() != (5U + std::size_t{in[4]})) ||
        (in[5] != 0xA6U) || (in[6] != 0x1DU) || (in[36] != 0x7FU) || (in[37] != 0x49U) ||
        (in[38] != 0x46U) || (in[109] != 0x5FU) || (in[110] != 0x37U)) {
      return putSw(r, 0, 0x6A80U);
    }
    const uint8_t* a6 = &in[7];
    const bool a6_ok = (a6[0] == 0x4FU) && (a6[1] == 16U) && (a6[18] == 0x90U) && (a6[19] == 3U) &&
                       (a6[20] == 0xABU) && (a6[21] == 0x01U) && (a6[22] != 0U) &&
                       (a6[23] == 0x80U) && (a6[25] == 0x88U) && (a6[26] == 0x81U) &&
                       (a6[28] == 0x10U);
    const uint8_t* k49 = &in[39];
    const bool k49_ok =
        (k49[0] == 0xB0U) && (k49[1] == 0x41U) && (k49[67] == 0xF0U) && (k49[69] == 0x03U);
    if (!a6_ok || !k49_ok) {
      return putSw(r, 0, 0x6A80U);
    }
    const uint8_t level = a6[22];
    const std::size_t der_len = in[111];
    uint8_t rs[64];
    if (((112U + der_len) > in.size()) ||
        !mc::ParseDer(mc::Bytes(&in[112], der_len), rs, rs + 32)) {
      return putSw(r, 0, 0x6A80U);
    }
    uint8_t digest[32];
    mc::Sha256(mc::Bytes(&in[5], 104U), digest);
    if (!mc::Verify(cred.pub.data(), digest, rs, rs + 32)) {
      return putSw(r, 0, 0x6985U);
    }
    uint8_t z[32];
    if (!mc::Ecdh(se_priv_.data(), &k49[2], z)) {
      return putSw(r, 0, 0x6985U);
    }
    uint8_t dr[16];
    ++challenge_seed_;
    for (std::size_t k = 0U; k < 16U; ++k) {
      dr[k] = static_cast<uint8_t>((std::size_t{challenge_seed_} * 29U) + (k * 3U));
    }
    uint8_t mk_in[4 + 32 + 16 + 4] = {0, 0, 0, 1};
    static_cast<void>(std::memcpy(mk_in + 4, z, 32U));
    static_cast<void>(std::memcpy(mk_in + 36, dr, 16U));
    mk_in[52] = 0x01U;
    mk_in[53] = level;
    mk_in[54] = 0x88U;
    mk_in[55] = 0x10U;
    uint8_t mk[32];
    mc::Sha256(mc::Bytes(mk_in, sizeof(mk_in)), mk);
    s.sm = Sm{};
    s.sm.len = 16U;
    kdf(mk, 16U, 0x04U, nullptr, 0U, s.sm.enc.data(), 16U);
    kdf(mk, 16U, 0x06U, nullptr, 0U, s.sm.mac.data(), 16U);
    kdf(mk, 16U, 0x07U, nullptr, 0U, s.sm.rmac.data(), 16U);
    if (!knobs.eckey_mcv_zero) {
      kdf(mk, 16U, 0x08U, nullptr, 0U, s.sm.mcv.data(), 16U);
    }
    s.sm.level = level;
    s.sm.ctr = 1U;
    uint8_t receipt[16];
    mc::Cmac(mc::Bytes(s.sm.rmac.data(), 16U), mc::Bytes(&in[5], 104U), receipt);
    if (knobs.receipt_wrong) {
      receipt[15] = static_cast<uint8_t>(receipt[15] ^ 0x5AU);
    }
    s.authenticated = true;
    s.secure = true;
    r[0] = 0x85U;
    r[1] = 16U;
    static_cast<void>(std::memcpy(&r[2], dr, 16U));
    r[18] = 0x86U;
    r[19] = 16U;
    static_cast<void>(std::memcpy(&r[20], receipt, 16U));
    return putSw(r, 36U, 0x9000U);
  }

  Key pf_enc_{};
  Key pf_mac_{};
  std::size_t pf_len_{16};
  uint8_t kvn_{0x0BU};
  Pending pf_pending_{};
  Sm pf_{};
  std::array<Cred, 8> creds_{};
  std::size_t ncreds_{0};
  std::array<Session, 2> sessions_{}; // MAX_NUMBER_OF_SESSIONS (AN12543 p. 50)
  std::array<uint8_t, 32> se_priv_{};
  std::array<uint8_t, 65> se_pub_{};
  Sel selected_{Sel::None};
  uint32_t challenge_seed_{0};
  uint32_t session_seed_{0};
};

} // namespace se05x::testmodel

#endif // SE05X_TESTS_MODEL_SCP_TARGET_HPP
