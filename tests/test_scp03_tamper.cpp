/**
 * @file test_scp03_tamper.cpp
 * @brief SCP03 under attack and faults: every byte of a wrapped response flipped, short and
 * truncated responses, an R-MAC on an error, lost frames and a failure at every handshake step;
 * the channel closes and releases its keys each time (S-07, S-08). And the UserID session (S-14).
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <array>
#include <cstddef>
#include <cstdint>

#include "model/bytes.hpp"
#include "model/scp_loop.hpp"
#include "model/scp_target.hpp"
#include "se05x_crypto.hpp"
#include "se05x_scp03.hpp"
#include "test_harness.hpp"

using se05x::testmodel::SameBytes;
using namespace se05x;
using testmodel::Loop;
using testmodel::ScpFixture;
using testmodel::ScpPorts;
using testmodel::ScpTarget;

namespace {

constexpr std::array<uint8_t, 16> kEnc{0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
                                       0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
constexpr std::array<uint8_t, 16> kMac{0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,
                                       0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F};

void SelectIot(Loop& loop) {
  const std::array<uint8_t, 22> select{0x00, 0xA4, 0x04, 0x00, 0x10, 0xA0, 0x00, 0x00,
                                       0x03, 0x96, 0x54, 0x53, 0x00, 0x00, 0x00, 0x01,
                                       0x03, 0x00, 0x00, 0x00, 0x00, 0x00};
  std::array<uint8_t, 32> rsp{};
  static_cast<void>(loop.Transceive(ByteSpan{select}, MutableByteSpan{rsp}));
  loop.calls = 0U;
}

struct Rig {
  ScpFixture f;
  ScpTarget chip;
  Loop loop{chip};
  scp03::Channel<ScpPorts, Loop> ch{f.ports, loop};
  scp03::ChannelParams params{};
  std::size_t static_keys{2U}; ///< ENC and MAC.

  explicit Rig(scp03::SecurityLevel level = scp03::SecurityLevel::Full) {
    chip.SetPlatformKeys(kEnc.data(), kMac.data(), 16U, 0x0BU);
    SelectIot(loop);
    static_cast<void>(f.crypto.ImportKey(KeyKind::Aes128, ByteSpan{kEnc}, params.keys.enc));
    static_cast<void>(f.crypto.ImportKey(KeyKind::Aes128, ByteSpan{kMac}, params.keys.mac));
    params.level = level;
  }
};

/// A command with data whose echo answer has data: 20 bytes in, 20 bytes out.
constexpr std::array<uint8_t, 26> kCmd{0x80, 0x20, 0x00, 0x00, 20, 1,  2,  3,   4,
                                       5,    6,    7,    8,    9,  10, 11, 12,  13,
                                       14,   15,   16,   17,   18, 19, 20, 0x00};

} // namespace

TEST_CASE("Every flipped byte of a Full response is SecureChannelError and closes the channel") {
  Rig probe;
  REQUIRE(probe.ch.Open(probe.params).ok());
  std::array<uint8_t, 64> rsp{};
  REQUIRE(probe.ch.Transceive(ByteSpan{kCmd}, MutableByteSpan{rsp}).ok());
  const std::size_t wire = probe.loop.last_rsp_len; // 32 data + 8 MAC + 2 SW
  REQUIRE(wire == 42U);
  bool all = true;
  for (std::size_t byte = 0U; byte < wire; ++byte) {
    for (const uint8_t mask : {uint8_t{0x01U}, uint8_t{0x80U}}) {
      Rig t;
      REQUIRE(t.ch.Open(t.params).ok());
      t.loop.tamper_rsp_call = t.loop.calls + 1U;
      t.loop.tamper_rsp_byte = byte;
      t.loop.tamper_mask = mask;
      const auto r = t.ch.Transceive(ByteSpan{kCmd}, MutableByteSpan{rsp});
      all = all && (r.error == Error::SecureChannelError) && (!t.ch.IsOpen()) &&
            (t.f.crypto.KeysInUse() == t.static_keys);
    }
  }
  CHECK(all);
}

TEST_CASE("Every flipped byte of a C-MAC + R-MAC response is caught, short answers included") {
  bool all = true;
  for (std::size_t byte = 0U; byte < 10U; ++byte) { // 8 MAC + 2 SW of a data-less answer
    Rig t(scp03::SecurityLevel::CMacRMac);
    REQUIRE(t.ch.Open(t.params).ok());
    t.loop.tamper_rsp_call = t.loop.calls + 1U;
    t.loop.tamper_rsp_byte = byte;
    const std::array<uint8_t, 6> cmd{0x80, 0x20, 0x00, 0x00, 0x01, 0x42};
    std::array<uint8_t, 16> rsp{};
    const auto r = t.ch.Transceive(ByteSpan(cmd.data(), 6U), MutableByteSpan{rsp});
    all = all && (r.error == Error::SecureChannelError) && !t.ch.IsOpen();
  }
  CHECK(all);
}

TEST_CASE("Without R-MAC a response is not authenticated: a flipped byte passes (documented)") {
  Rig t(scp03::SecurityLevel::CMacCDecrypt);
  REQUIRE(t.ch.Open(t.params).ok());
  t.loop.tamper_rsp_call = t.loop.calls + 1U;
  t.loop.tamper_rsp_byte = 0U;
  std::array<uint8_t, 64> rsp{};
  const auto r = t.ch.Transceive(ByteSpan{kCmd}, MutableByteSpan{rsp});
  REQUIRE(r.ok());
  CHECK_EQ(rsp[0], 0x00U); // 0x01 flipped to 0x00: levels without R-MAC protect commands only
}

TEST_CASE("Short, empty and truncated responses are refused") {
  for (const std::size_t keep : {0U, 1U, 2U, 9U, 17U}) {
    Rig t;
    REQUIRE(t.ch.Open(t.params).ok());
    t.loop.truncate_rsp_call = t.loop.calls + 1U;
    t.loop.truncate_to = keep;
    std::array<uint8_t, 64> rsp{};
    const auto r = t.ch.Transceive(ByteSpan{kCmd}, MutableByteSpan{rsp});
    CHECK_EQ(r.error, Error::SecureChannelError);
    CHECK(!t.ch.IsOpen());
  }
}

TEST_CASE("An error status word with bytes in front of it is refused (no R-MAC on errors)") {
  Rig t;
  t.chip.knobs.rmac_on_errors = true;
  REQUIRE(t.ch.Open(t.params).ok());
  const std::array<uint8_t, 4> err{0x80, 0x0F, 0x00, 0x00};
  std::array<uint8_t, 32> rsp{};
  CHECK_EQ(t.ch.Transceive(ByteSpan{err}, MutableByteSpan{rsp}).error, Error::SecureChannelError);
}

TEST_CASE("A tampered command is refused by the chip; the host sees its status word") {
  Rig t;
  REQUIRE(t.ch.Open(t.params).ok());
  t.loop.tamper_cmd_call = t.loop.calls + 1U;
  t.loop.tamper_cmd_byte = 10U;
  std::array<uint8_t, 64> rsp{};
  const auto r = t.ch.Transceive(ByteSpan{kCmd}, MutableByteSpan{rsp});
  REQUIRE(r.ok());
  CHECK((r.value == 2U) && (rsp[0] == 0x69U) && (rsp[1] == 0x82U));
  CHECK_EQ(t.chip.mac_failures, 1U);
  CHECK_EQ(t.chip.applet_commands, 0U); // nothing reached the applet
}

TEST_CASE("A lost response closes the channel and releases the keys") {
  Rig t;
  REQUIRE(t.ch.Open(t.params).ok());
  t.loop.lose_call = t.loop.calls + 1U;
  std::array<uint8_t, 64> rsp{};
  CHECK_EQ(t.ch.Transceive(ByteSpan{kCmd}, MutableByteSpan{rsp}).error, Error::Timeout);
  CHECK(!t.ch.IsOpen());
  CHECK_EQ(t.f.crypto.KeysInUse(), t.static_keys);
  CHECK_EQ(t.ch.Transceive(ByteSpan{kCmd}, MutableByteSpan{rsp}).error, Error::NotInitialized);
  REQUIRE(t.ch.Open(t.params).ok()); // a new handshake recovers
  CHECK(t.ch.Transceive(ByteSpan{kCmd}, MutableByteSpan{rsp}).ok());
}

TEST_CASE("A failure at each handshake step leaves no channel and no session key") {
  for (uint32_t call = 1U; call <= 2U; ++call) {
    for (int mode = 0; mode < 3; ++mode) {
      Rig t;
      if (mode == 0) {
        t.loop.fail_call = call;
      } else if (mode == 1) {
        t.loop.lose_call = call;
      } else {
        t.loop.tamper_rsp_call = call;
        t.loop.tamper_rsp_byte = (call == 1U) ? 22U : 0U; // card cryptogram, or the SW
      }
      const auto r = t.ch.Open(t.params);
      CHECK(!r.ok());
      CHECK(!t.ch.IsOpen());
      CHECK_EQ(t.f.crypto.KeysInUse(), t.static_keys);
    }
  }
}

TEST_CASE("A bad card cryptogram is SecureChannelError; the host stops after the limit") {
  Rig t;
  t.chip.knobs.bad_card_cryptogram = true;
  t.ch.SetAuthAttemptLimit(2U);
  const auto r1 = t.ch.Open(t.params);
  CHECK_EQ(r1.error, Error::SecureChannelError);
  CHECK_EQ(r1.detail.attempts_left, 1U);
  CHECK_EQ(t.loop.calls, 1U); // EXTERNAL AUTHENTICATE never sent
  CHECK_EQ(t.ch.Open(t.params).error, Error::SecureChannelError);
  const uint32_t calls = t.loop.calls;
  const auto r3 = t.ch.Open(t.params);
  CHECK_EQ(r3.error, Error::AuthLocked);
  CHECK_EQ(t.loop.calls, calls); // nothing sent once locked
  CHECK_EQ(r3.detail.attempts_left, 0U);
}

TEST_CASE("A wrong static key fails EXTERNAL AUTHENTICATE or the card cryptogram, counted") {
  Rig t;
  const std::array<uint8_t, 16> wrong{};
  KeyRef bad{};
  REQUIRE(t.f.crypto.ImportKey(KeyKind::Aes128, ByteSpan{wrong}, bad) == CryptoStatus::Ok);
  t.params.keys.mac = bad;
  CHECK_EQ(t.ch.Open(t.params).error, Error::SecureChannelError);
  CHECK_EQ(t.ch.Attempts().Remaining(), 2U);
  t.params.keys.mac = t.params.keys.enc; // a wrong MAC key that the card cryptogram also rejects
  CHECK(!t.ch.Open(t.params).ok());
  CHECK_EQ(t.ch.Attempts().Remaining(), 1U);
}

TEST_CASE("A response larger than the caller's buffer is dropped; the channel stays in step") {
  Rig t;
  REQUIRE(t.ch.Open(t.params).ok());
  std::array<uint8_t, 8> small{};
  const auto r = t.ch.Transceive(ByteSpan{kCmd}, MutableByteSpan{small});
  CHECK_EQ(r.error, Error::BufferTooSmall);
  CHECK(t.ch.IsOpen());
  std::array<uint8_t, 21> one_short{}; // 20 data bytes and the SW need 22
  CHECK_EQ(t.ch.Transceive(ByteSpan{kCmd}, MutableByteSpan{one_short}).error,
           Error::BufferTooSmall);
  std::array<uint8_t, 22> exact{};
  const auto fits = t.ch.Transceive(ByteSpan{kCmd}, MutableByteSpan{exact});
  CHECK(fits.ok() && (fits.value == 22U) && (exact[21] == 0x00U) && (exact[20] == 0x90U));
  std::array<uint8_t, 64> rsp{};
  CHECK(t.ch.Transceive(ByteSpan{kCmd}, MutableByteSpan{rsp}).ok());
}

TEST_CASE("A command that is not an APDU or too long is refused before anything is sent") {
  Rig t;
  REQUIRE(t.ch.Open(t.params).ok());
  const uint32_t calls = t.loop.calls;
  std::array<uint8_t, 64> rsp{};
  const std::array<uint8_t, 3> bad{0x80, 0x20, 0x00};
  CHECK_EQ(t.ch.Transceive(ByteSpan{bad}, MutableByteSpan{rsp}).error, Error::InvalidArgument);
  std::array<uint8_t, 1100> big{};
  big[0] = 0x80U;
  big[4] = 0x00U;
  big[5] = 0x04U;
  big[6] = 0x40U; // 1088 bytes of data: wrapped 4 + 3 + 1104 + 8 > kMaxCommandApdu (1108)
  CHECK_EQ(t.ch.Transceive(ByteSpan(big.data(), 7U + 1088U), MutableByteSpan{rsp}).error,
           Error::BufferTooSmall);
  CHECK_EQ(t.loop.calls, calls);
  CHECK(t.ch.IsOpen()); // nothing was sent and the chaining value is unchanged
  CHECK(t.ch.Transceive(ByteSpan{kCmd}, MutableByteSpan{rsp}).ok());
}

TEST_CASE("Close is never refused and always releases the keys (RD-05)") {
  Rig t;
  CHECK(t.ch.Close().ok()); // not open: nothing to do
  REQUIRE(t.ch.Open(t.params).ok());
  CHECK(t.f.crypto.KeysInUse() > t.static_keys);
  CHECK(t.ch.Close().ok());
  CHECK_EQ(t.f.crypto.KeysInUse(), t.static_keys);
  CHECK(!t.ch.IsOpen());
}

// --- UserID session (S-14) ---

namespace {
struct UserRig {
  ScpFixture f;
  ScpTarget chip;
  Loop loop{chip};
  session::UserIdSession<ScpPorts, Loop> s{f.ports, loop};
  std::array<uint8_t, 6> pin{0x31, 0x32, 0x33, 0x34, 0x35, 0x36};
  UserRig() {
    chip.AddUserId(0x00000777U, pin.data(), pin.size(), 5U);
    SelectIot(loop);
  }
};
static_assert(session::UserIdTransport<session::UserIdSession<ScpPorts, Loop>>);
static_assert(!session::UserIdTransport<Loop>);
static_assert(!userid::kCarriesSecureMessaging);
} // namespace

TEST_CASE("UserID session: open, commands framed in the clear, close") {
  UserRig t;
  REQUIRE(t.s.Open(ObjectId{0x777U}, ByteSpan{t.pin}).ok());
  CHECK(t.s.IsOpen());
  CHECK_EQ(t.chip.sessions_open, 1U);
  const std::array<uint8_t, 7> cmd{0x80, 0x20, 0x00, 0x00, 0x02, 0xAB, 0xCD};
  std::array<uint8_t, 16> rsp{};
  const auto r = t.s.Transceive(ByteSpan{cmd}, MutableByteSpan{rsp});
  REQUIRE(r.ok());
  CHECK((r.value == 4U) && (rsp[0] == 0xABU) && (rsp[2] == 0x90U));
  CHECK_EQ(t.loop.last_cmd[0], 0x80U); // no secure messaging bit: plain on the wire
  CHECK_EQ(t.loop.last_cmd[1], 0x05U); // ProcessSessionCmd
  CHECK(SameBytes(&t.loop.last_cmd[17], cmd.data(), cmd.size()));
  CHECK(t.s.Close().ok());
  CHECK_EQ(t.chip.sessions_open, 0U);
  CHECK_EQ(t.s.Transceive(ByteSpan{cmd}, MutableByteSpan{rsp}).error, Error::NotInitialized);
}

TEST_CASE("UserID session: wrong values are counted and the host stops at its limit") {
  UserRig t;
  t.s.SetAuthAttemptLimit(2U);
  const std::array<uint8_t, 6> wrong{0x30, 0x30, 0x30, 0x30, 0x30, 0x30};
  auto r = t.s.Open(ObjectId{0x777U}, ByteSpan{wrong});
  CHECK_EQ(r.error, Error::AuthFailed);
  CHECK_EQ(r.detail.sw, 0x6985U);
  CHECK_EQ(r.detail.attempts_left, 1U);
  CHECK(t.s.NeedsReselect());
  SelectIot(t.loop); // a reselect clears the half-open session
  CHECK_EQ(t.s.Open(ObjectId{0x777U}, ByteSpan{wrong}).error, Error::AuthFailed);
  const uint32_t calls = t.loop.calls;
  CHECK_EQ(t.s.Open(ObjectId{0x777U}, ByteSpan{t.pin}).error, Error::AuthLocked);
  CHECK_EQ(t.loop.calls, calls); // the right value is not even tried: nothing sent
}

TEST_CASE("UserID session: lengths, id 0 and a second open are refused without I/O") {
  UserRig t;
  CHECK_EQ(t.s.Open(ObjectId{0x777U}, ByteSpan{}).error, Error::InvalidArgument);
  std::array<uint8_t, 17> longer{};
  CHECK_EQ(t.s.Open(ObjectId{0x777U}, ByteSpan{longer}).error, Error::InvalidArgument);
  CHECK_EQ(t.s.Open(ObjectId{0U}, ByteSpan{t.pin}).error, Error::InvalidArgument);
  CHECK_EQ(t.loop.calls, 0U);
  REQUIRE(t.s.Open(ObjectId{0x777U}, ByteSpan{t.pin}).ok());
  CHECK_EQ(t.s.Open(ObjectId{0x777U}, ByteSpan{t.pin}).error, Error::WrongState);
  CHECK_EQ(t.s.Open(ObjectId{0x778U}, ByteSpan{t.pin}).error, Error::WrongState);
}

TEST_CASE("UserID session: an unknown object fails at CreateSession; a lost close is reported") {
  UserRig t;
  CHECK_EQ(t.s.Open(ObjectId{0x123U}, ByteSpan{t.pin}).error, Error::ConditionsNotSatisfied);
  CHECK(!t.s.NeedsReselect());
  REQUIRE(t.s.Open(ObjectId{0x777U}, ByteSpan{t.pin}).ok());
  t.loop.fail_call = t.loop.calls + 1U;
  CHECK_EQ(t.s.Close().error, Error::NeedsReselect);
  CHECK(!t.s.IsOpen());
  CHECK(t.s.NeedsReselect());
}
