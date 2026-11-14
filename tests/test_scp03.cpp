/**
 * @file test_scp03.cpp
 * @brief SCP03: known answers derived with OpenSSL (not with the library), the handshake and
 * secure messaging against the independent `ScpTarget`, every security level, AES-128 and
 * AES-256, the errata JOS.2 counter rule, the AESKey session, the applet session framing.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * The known-answer script (`kKat128`, `kKat256`) was computed step by step with OpenSSL 3.6 (AES
 * ECB/CBC and CMAC) from GP Amendment D as AN12543 applies it, with the test keys 40..4F (ENC)
 * and 60..6F (MAC), host challenge 1122334455667788, card challenge A1..A8 and key version 0x30.
 * These keys are the tests' own; no platform key of any chip is in this repository.
 */
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "model/scp_loop.hpp"
#include "model/scp_script.hpp"
#include "model/scp_target.hpp"
#include "se05x_crypto.hpp"
#include "se05x_scp03.hpp"
#include "test_harness.hpp"

using namespace se05x;
using testmodel::Loop;
using testmodel::ScpFixture;
using testmodel::ScpPorts;
using testmodel::ScpTarget;
using testmodel::Script;
using testmodel::Step;

namespace {

constexpr std::array<uint8_t, 32> kEnc{
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F};
constexpr std::array<uint8_t, 32> kMac{
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F};

constexpr std::array<Step, 8> kKat128{{
    {"8050300008112233445566778800",
     "00010203040506070809300300a1a2a3a4a5a6a7a8ff43505a8512bcb49000"},
    {"8482330010c78ff755daaf248db7b4fe740544b81b", "9000"},
    {"840e00100000183b289e533400b49f0c4d8113cfbd84b23ecac91b520b274b0000",
     "5c7afe1ce4b119b33eb1822432c0f09ae3fc751ce473e3e79000"},
    {"84200000000008cc00510cf889028f0000", "dd07fe5f6e51f4596639faa2c9f6c3f5451bba82e026a29c9000"},
    {"843000001864e8ac05a891a0f2465e315cd0b6ba004c634c38793ece49", "d5774d50b1a430169000"},
}};

constexpr std::array<Step, 8> kKat256{{
    {"8050300008112233445566778800",
     "00010203040506070809300300a1a2a3a4a5a6a7a8a844e1bee95d7f149000"},
    {"8482330010978216d882cb728eaa05324687141429", "9000"},
    {"840e001000001827b96c035076d88d4d550ad477e0a9160caa8a96d5aa969d0000",
     "6a79da4ae4b438d8a3a350fd70ac6ae5b62604c72f3b0afb9000"},
    {"842000000000081b295212fbaecedc0000", "05116379155fd5a1023a887a668aad589cd2ba8a530d396b9000"},
    {"84300000188afcf5b63b7753ace78d644e659f751f70968144e069edde", "de2a8e587efa13469000"},
}};

struct KatPorts {
  testports::NullBus bus;
  testports::NullClock clock;
  ReferenceCrypto crypto{&testmodel::FixedEntropy};
  ScpPorts ports{bus, clock, crypto};
};

scp03::ChannelParams KeysFor(ReferenceCrypto& crypto, std::size_t len) {
  scp03::ChannelParams p{};
  const KeyKind kind = (len == 32U) ? KeyKind::Aes256 : KeyKind::Aes128;
  static_cast<void>(crypto.ImportKey(kind, ByteSpan(kEnc.data(), len), p.keys.enc));
  static_cast<void>(crypto.ImportKey(kind, ByteSpan(kMac.data(), len), p.keys.mac));
  p.length = (len == 32U) ? scp03::KeyLength::Aes256 : scp03::KeyLength::Aes128;
  return p;
}

/// Run the five-step known-answer script; checks every plain answer and the counter.
void RunKat(const std::array<Step, 8>& steps, std::size_t len) {
  KatPorts k;
  Script script(steps.data(), 5U);
  scp03::Channel<ScpPorts, Script> ch(k.ports, script);
  scp03::ChannelParams p = KeysFor(k.crypto, len);
  p.key_version = 0x30U;
  const auto opened = ch.Open(p);
  REQUIRE(opened.ok());
  CHECK(!script.mismatch);
  CHECK_EQ(ch.Counter(), 1U);
  std::array<uint8_t, 64> rsp{};
  const std::array<uint8_t, 9> c1{0x80, 0x0E, 0x00, 0x10, 0x03, 0x01, 0x02, 0x03, 0x00};
  auto r = ch.Transceive(ByteSpan{c1}, MutableByteSpan{rsp});
  REQUIRE(r.ok());
  CHECK(!script.mismatch);
  REQUIRE(r.value == 6U);
  CHECK((rsp[0] == 0xCAU) && (rsp[1] == 0xFEU) && (rsp[2] == 0xBAU) && (rsp[3] == 0xBEU));
  CHECK((rsp[4] == 0x90U) && (rsp[5] == 0x00U));
  CHECK_EQ(ch.Counter(), 2U);
  const std::array<uint8_t, 5> c2{0x80, 0x20, 0x00, 0x00, 0x00};
  r = ch.Transceive(ByteSpan{c2}, MutableByteSpan{rsp});
  REQUIRE(r.ok());
  CHECK(!script.mismatch);
  REQUIRE(r.value == 4U);
  CHECK((rsp[0] == 0x01U) && (rsp[1] == 0x02U));
  CHECK_EQ(ch.Counter(), 2U); // JOS.2: no data, no advance
  const std::array<uint8_t, 7> c3{0x80, 0x30, 0x00, 0x00, 0x02, 0xAA, 0xBB};
  r = ch.Transceive(ByteSpan{c3}, MutableByteSpan{rsp});
  REQUIRE(r.ok());
  CHECK(!script.mismatch);
  CHECK_EQ(r.value, 2U);
  CHECK_EQ(ch.Counter(), 3U);
  CHECK(ch.Close().ok());
  CHECK_EQ(k.crypto.KeysInUse(), 2U); // the static keys only: the session keys are released
}

/// SELECT the IoT applet on the model (plain, before any channel).
void SelectIot(Loop& loop) {
  const std::array<uint8_t, 22> select{0x00, 0xA4, 0x04, 0x00, 0x10, 0xA0, 0x00, 0x00,
                                       0x03, 0x96, 0x54, 0x53, 0x00, 0x00, 0x00, 0x01,
                                       0x03, 0x00, 0x00, 0x00, 0x00, 0x00};
  std::array<uint8_t, 32> rsp{};
  static_cast<void>(loop.Transceive(ByteSpan{select}, MutableByteSpan{rsp}));
  loop.calls = 0U;
}

/// A platform channel against the model.
struct Platform {
  ScpFixture f;
  ScpTarget chip;
  Loop loop{chip};
  scp03::Channel<ScpPorts, Loop> ch{f.ports, loop};
  scp03::ChannelParams params{};

  explicit Platform(std::size_t len = 16U,
                    scp03::SecurityLevel level = scp03::SecurityLevel::Full) {
    chip.SetPlatformKeys(kEnc.data(), kMac.data(), len, 0x0BU);
    SelectIot(loop);
    params = KeysFor(f.crypto, len);
    params.level = level;
  }
};

/// Send `n` data bytes through the echo applet and check the plain answer.
bool Echo(scp03::Channel<ScpPorts, Loop>& ch, std::size_t n, bool with_le) {
  std::array<uint8_t, 600> cmd{};
  cmd[0] = 0x80U;
  cmd[1] = 0x20U;
  std::size_t len = 4U;
  if (n > 255U) {
    cmd[4] = 0x00U;
    cmd[5] = static_cast<uint8_t>(n >> 8U);
    cmd[6] = static_cast<uint8_t>(n & 0xFFU);
    len = 7U;
  } else if (n > 0U) {
    cmd[4] = static_cast<uint8_t>(n);
    len = 5U;
  } else {
    // no data field
  }
  for (std::size_t i = 0U; i < n; ++i) {
    cmd[len + i] = static_cast<uint8_t>(i ^ 0x5AU);
  }
  len += n;
  if (with_le) {
    cmd[len] = 0x00U;
    ++len;
    if (n > 255U) {
      cmd[len] = 0x00U;
      ++len;
    }
  }
  std::array<uint8_t, 700> rsp{};
  const auto r = ch.Transceive(ByteSpan(cmd.data(), len), MutableByteSpan{rsp});
  if ((!r.ok()) || (r.value != (n + 2U))) {
    return false;
  }
  bool same = (rsp[n] == 0x90U) && (rsp[n + 1U] == 0x00U);
  for (std::size_t i = 0U; i < n; ++i) {
    same = same && (rsp[i] == static_cast<uint8_t>(i ^ 0x5AU));
  }
  return same;
}

} // namespace

TEST_CASE("SCP03 AES-128: every byte of the handshake and three commands is the OpenSSL answer") {
  RunKat(kKat128, 16U);
}

TEST_CASE("SCP03 AES-256: every byte of the handshake and three commands is the OpenSSL answer") {
  RunKat(kKat256, 32U);
}

TEST_CASE("Without the JOS.2 rule the no-data answer of the script is refused") {
  KatPorts k;
  Script script(kKat128.data(), 5U);
  scp03::Channel<ScpPorts, Script> ch(k.ports, script);
  scp03::ChannelParams p = KeysFor(k.crypto, 16U);
  p.key_version = 0x30U;
  p.jos2_counter_rule = false;
  REQUIRE(ch.Open(p).ok());
  std::array<uint8_t, 64> rsp{};
  const std::array<uint8_t, 9> c1{0x80, 0x0E, 0x00, 0x10, 0x03, 0x01, 0x02, 0x03, 0x00};
  REQUIRE(ch.Transceive(ByteSpan{c1}, MutableByteSpan{rsp}).ok());
  const std::array<uint8_t, 5> c2{0x80, 0x20, 0x00, 0x00, 0x00};
  CHECK_EQ(ch.Transceive(ByteSpan{c2}, MutableByteSpan{rsp}).error, Error::SecureChannelError);
  CHECK(!ch.IsOpen());
  CHECK_EQ(k.crypto.KeysInUse(), 2U);
}

TEST_CASE("Every level and both key lengths talk to the model, short and extended") {
  const std::array<scp03::SecurityLevel, 4> levels{
      scp03::SecurityLevel::CMac, scp03::SecurityLevel::CMacCDecrypt,
      scp03::SecurityLevel::CMacRMac, scp03::SecurityLevel::Full};
  for (const std::size_t len : {16U, 32U}) {
    for (const auto level : levels) {
      Platform t(len, level);
      REQUIRE(t.ch.Open(t.params).ok());
      CHECK(t.chip.platform_open);
      bool ok = true;
      for (const std::size_t n : {0U, 1U, 15U, 16U, 17U, 100U, 239U, 240U, 255U, 300U, 500U}) {
        ok = ok && Echo(t.ch, n, true) && Echo(t.ch, n, false);
      }
      CHECK(ok);
      CHECK(t.ch.IsOpen());
      CHECK_EQ(t.chip.mac_failures, 0U);
      CHECK(t.ch.Close().ok());
    }
  }
}

TEST_CASE("The plain command reaches the applet byte for byte (C-DECRYPTION undone)") {
  Platform t;
  REQUIRE(t.ch.Open(t.params).ok());
  const std::array<uint8_t, 8> cmd{0x80, 0x01, 0x61, 0x00, 0x02, 0x41, 0x42, 0x00};
  std::array<uint8_t, 32> rsp{};
  REQUIRE(t.ch.Transceive(ByteSpan{cmd}, MutableByteSpan{rsp}).ok());
  REQUIRE(t.chip.last_plain_len == cmd.size());
  CHECK(std::memcmp(t.chip.last_plain.data(), cmd.data(), cmd.size()) == 0);
  // On the wire the data was encrypted and padded: the command was not sent in the clear.
  CHECK_EQ(t.loop.last_cmd[0], 0x84U);
  CHECK(std::memcmp(&t.loop.last_cmd[7], &cmd[5], 2U) != 0);
}

TEST_CASE("The counter only goes up, also across commands without data, and restarts at 1") {
  Platform t;
  REQUIRE(t.ch.Open(t.params).ok());
  uint32_t last = t.ch.Counter();
  CHECK_EQ(last, 1U);
  bool monotonic = true;
  for (std::size_t i = 0U; i < 40U; ++i) {
    REQUIRE(Echo(t.ch, i % 3U, (i % 2U) == 0U));
    const uint32_t now = t.ch.Counter();
    monotonic = monotonic && (now >= last) && (now <= (last + 1U));
    last = now;
  }
  CHECK(monotonic);
  CHECK(last > 20U);
  CHECK(t.ch.Close().ok());
  CHECK_EQ(t.ch.Counter(), 0U);
  REQUIRE(t.ch.Open(t.params).ok());
  CHECK_EQ(t.ch.Counter(), 1U);
}

TEST_CASE("A chip that follows GP (no JOS.2) needs jos2_counter_rule off") {
  // INS 0x0E asks the echo applet for P1P2 pattern bytes: a command without data whose answer
  // has data, so the response ICV matters. Eight bytes keep the padding in the first block, the
  // only block a wrong ICV garbles (CBC): SCP03 cannot see a counter mismatch in longer answers,
  // because the R-MAC covers the ciphertext, not the counter.
  const std::array<uint8_t, 5> nodata{0x80, 0x0E, 0x00, 0x08, 0x00};
  std::array<uint8_t, 64> rsp{};
  Platform t;
  t.chip.knobs.gp_counter = true;
  REQUIRE(t.ch.Open(t.params).ok());
  CHECK(Echo(t.ch, 4U, true));
  CHECK_EQ(t.ch.Transceive(ByteSpan{nodata}, MutableByteSpan{rsp}).error,
           Error::SecureChannelError); // mismatched ICV: the R-ENC padding check fails
  CHECK(!t.ch.IsOpen());
  Platform u;
  u.chip.knobs.gp_counter = true;
  u.params.jos2_counter_rule = false;
  REQUIRE(u.ch.Open(u.params).ok());
  bool ok = true;
  for (std::size_t i = 0U; i < 6U; ++i) {
    const auto r = u.ch.Transceive(ByteSpan{nodata}, MutableByteSpan{rsp});
    ok = ok && r.ok() && (r.value == 10U) && (rsp[1] == 8U) && Echo(u.ch, 5U, true);
  }
  CHECK(ok);
  // And the default chip with the default rule answers the same command.
  Platform v;
  REQUIRE(v.ch.Open(v.params).ok());
  const auto r = v.ch.Transceive(ByteSpan{nodata}, MutableByteSpan{rsp});
  CHECK(r.ok() && (r.value == 10U));
}

TEST_CASE("An error status word comes back alone and the channel stays open") {
  Platform t;
  REQUIRE(t.ch.Open(t.params).ok());
  const std::array<uint8_t, 6> cmd{0x80, 0x0F, 0x00, 0x00, 0x01, 0x00};
  std::array<uint8_t, 32> rsp{};
  const auto r = t.ch.Transceive(ByteSpan{cmd}, MutableByteSpan{rsp});
  REQUIRE(r.ok());
  CHECK_EQ(r.value, 2U);
  CHECK((rsp[0] == 0x69U) && (rsp[1] == 0x85U));
  CHECK(t.ch.IsOpen());
  CHECK(Echo(t.ch, 20U, true)); // the counters stayed in step
}

TEST_CASE("Open refuses missing keys, bad values and a second open, without I/O") {
  Platform t;
  scp03::ChannelParams p = t.params;
  p.keys.mac = KeyRef{};
  CHECK_EQ(t.ch.Open(p).error, Error::InvalidArgument);
  p = t.params;
  p.level = std::bit_cast<scp03::SecurityLevel>(uint8_t{7});
  CHECK_EQ(t.ch.Open(p).error, Error::InvalidArgument);
  p = t.params;
  p.length = std::bit_cast<scp03::KeyLength>(uint8_t{5});
  CHECK_EQ(t.ch.Open(p).error, Error::InvalidArgument);
  p = t.params;
  p.kind = std::bit_cast<scp03::ChannelKind>(uint8_t{9});
  CHECK_EQ(t.ch.Open(p).error, Error::InvalidArgument);
  CHECK_EQ(t.loop.calls, 0U);
  REQUIRE(t.ch.Open(t.params).ok());
  const uint32_t calls = t.loop.calls;
  CHECK_EQ(t.ch.Open(t.params).error, Error::WrongState);
  CHECK_EQ(t.loop.calls, calls);
  std::array<uint8_t, 8> rsp{};
  scp03::Channel<ScpPorts, Loop> closed(t.f.ports, t.loop);
  CHECK_EQ(closed.Transceive(ByteSpan{}, MutableByteSpan{rsp}).error, Error::NotInitialized);
}

TEST_CASE("A wrong key version is AuthFailed with the chip's status word") {
  Platform t;
  t.params.key_version = 0x22U;
  const auto r = t.ch.Open(t.params);
  CHECK_EQ(r.error, Error::AuthFailed);
  CHECK_EQ(r.detail.sw, 0x6A88U);
  CHECK(!t.ch.IsOpen());
  t.params.key_version = 0x0BU;
  CHECK(t.ch.Open(t.params).ok());
}

TEST_CASE("An INITIALIZE UPDATE answer for another SCP is SecureChannelError") {
  Platform t;
  t.chip.knobs.scp_id = 0x02U; // SCP02 key information
  const auto r = t.ch.Open(t.params);
  CHECK_EQ(r.error, Error::SecureChannelError);
  CHECK(!t.ch.IsOpen());
  t.chip.knobs.scp_id = 0x03U;
  CHECK(t.ch.Open(t.params).ok());
}

// The encryption counter never wraps back to a value already used with the session keys (S-16).
static_assert([] {
  uint32_t next = 0U;
  return scp03::detail::NextCounter(5U, true, next) && (next == 6U);
}());
static_assert([] {
  uint32_t next = 0U;
  return scp03::detail::NextCounter(5U, false, next) && (next == 5U);
}());
static_assert([] {
  uint32_t next = 0U;
  return scp03::detail::NextCounter(0xFFFFFFFEU, true, next) && (next == 0xFFFFFFFFU);
}());
static_assert([] {
  uint32_t next = 0U;
  return !scp03::detail::NextCounter(0xFFFFFFFFU, true, next) && (next == 0xFFFFFFFFU);
}());
static_assert([] {
  uint32_t next = 0U;
  return scp03::detail::NextCounter(0xFFFFFFFFU, false, next) && (next == 0xFFFFFFFFU);
}());

TEST_CASE("A bare 9000 is accepted once after ExpectSessionEnd, never on a later answer") {
  Platform t;
  REQUIRE(t.ch.Open(t.params).ok());
  const std::array<uint8_t, 6> cmd{0x80U, 0x20U, 0x00U, 0x00U, 0x01U, 0xA5U};
  std::array<uint8_t, 64> rsp{};
  // Expected: the bare answer of a command that ends the session is success, once.
  t.ch.ExpectSessionEnd();
  t.loop.truncate_rsp_call = t.loop.calls + 1U;
  t.loop.truncate_to = 2U; // only the status word: no R-MAC
  const auto ended = t.ch.Transceive(ByteSpan{cmd}, MutableByteSpan{rsp});
  REQUIRE(ended.ok());
  CHECK_EQ(ended.value, 2U);
  // The permission is spent by any answer: after a normal exchange a bare 9000 is refused.
  Platform u;
  REQUIRE(u.ch.Open(u.params).ok());
  u.ch.ExpectSessionEnd();
  REQUIRE(Echo(u.ch, 9U, true));
  u.loop.truncate_rsp_call = u.loop.calls + 1U;
  u.loop.truncate_to = 2U;
  CHECK_EQ(u.ch.Transceive(ByteSpan{cmd}, MutableByteSpan{rsp}).error, Error::SecureChannelError);
}

TEST_CASE("A pseudo-random challenge answer (32 bytes) is accepted") {
  Platform t;
  t.chip.knobs.sequence_counter = true;
  REQUIRE(t.ch.Open(t.params).ok());
  CHECK(Echo(t.ch, 9U, true));
}

TEST_CASE("AESKey session: CreateSession, SCP03 inside ProcessSessionCmd, CloseSession") {
  ScpFixture f;
  ScpTarget chip;
  Loop loop(chip);
  chip.AddAesKey(0x00001234U, kEnc.data());
  SelectIot(loop);
  scp03::Channel<ScpPorts, Loop> ch(f.ports, loop);
  scp03::ChannelParams p{};
  REQUIRE(f.crypto.ImportKey(KeyKind::Aes128, ByteSpan(kEnc.data(), 16U), p.keys.enc) ==
          CryptoStatus::Ok);
  p.kind = scp03::ChannelKind::AesKeySession;
  p.credential = ObjectId{0x00001234U};
  REQUIRE(ch.Open(p).ok());
  CHECK_EQ(chip.sessions_open, 1U);
  CHECK(!chip.platform_open);
  CHECK(Echo(ch, 10U, true));
  CHECK(Echo(ch, 0U, true));
  CHECK(Echo(ch, 300U, true));
  CHECK_EQ(loop.last_cmd[1], 0x05U); // ProcessSessionCmd
  CHECK(ch.Close().ok());
  CHECK_EQ(chip.sessions_open, 0U);
  CHECK(!ch.NeedsReselect());
}

TEST_CASE("AESKey session: bad parameters and an unknown credential") {
  ScpFixture f;
  ScpTarget chip;
  Loop loop(chip);
  SelectIot(loop);
  scp03::Channel<ScpPorts, Loop> ch(f.ports, loop);
  scp03::ChannelParams p{};
  REQUIRE(f.crypto.ImportKey(KeyKind::Aes128, ByteSpan(kEnc.data(), 16U), p.keys.enc) ==
          CryptoStatus::Ok);
  p.kind = scp03::ChannelKind::AesKeySession;
  CHECK_EQ(ch.Open(p).error, Error::InvalidArgument); // no credential
  p.credential = ObjectId{0x99U};
  p.length = scp03::KeyLength::Aes256;
  CHECK_EQ(ch.Open(p).error, Error::InvalidArgument); // AESKey objects are 128 bit
  p.length = scp03::KeyLength::Aes128;
  p.key_version = 1U;
  CHECK_EQ(ch.Open(p).error, Error::InvalidArgument); // KVN must be 00 (AN12543 4.5.3.1)
  p.key_version = 0U;
  const auto r = ch.Open(p);
  CHECK_EQ(r.error, Error::ConditionsNotSatisfied);
  CHECK_EQ(r.detail.sw, 0x6985U);
  CHECK(!ch.NeedsReselect()); // no session was created
}

TEST_CASE("ParseCommand splits the eight ISO 7816 forms and refuses the rest") {
  using scp03::detail::ParseCommand;
  const std::array<uint8_t, 4> c1{0x80, 0x01, 0x02, 0x03};
  auto r = ParseCommand(ByteSpan{c1});
  CHECK(r.ok() && !r.value.has_le && r.value.data.empty());
  const std::array<uint8_t, 5> c2{0x80, 0x01, 0x02, 0x03, 0x10};
  r = ParseCommand(ByteSpan{c2});
  CHECK(r.ok() && r.value.has_le && (r.value.le == 0x10U));
  const std::array<uint8_t, 7> c3{0x80, 0x01, 0x02, 0x03, 0x02, 0xAA, 0xBB};
  r = ParseCommand(ByteSpan{c3});
  CHECK(r.ok() && !r.value.has_le && (r.value.data.size() == 2U));
  const std::array<uint8_t, 8> c4{0x80, 0x01, 0x02, 0x03, 0x02, 0xAA, 0xBB, 0x00};
  r = ParseCommand(ByteSpan{c4});
  CHECK(r.ok() && r.value.has_le && (r.value.data.size() == 2U) && !r.value.extended);
  const std::array<uint8_t, 7> c2e{0x80, 0x01, 0x02, 0x03, 0x00, 0x01, 0x00};
  r = ParseCommand(ByteSpan{c2e});
  CHECK(r.ok() && r.value.has_le && r.value.extended && (r.value.le == 0x100U));
  const std::array<uint8_t, 9> c3e{0x80, 0x01, 0x02, 0x03, 0x00, 0x00, 0x02, 0xAA, 0xBB};
  r = ParseCommand(ByteSpan{c3e});
  CHECK(r.ok() && !r.value.has_le && r.value.extended && (r.value.data.size() == 2U));
  const std::array<uint8_t, 11> c4e{0x80, 0x01, 0x02, 0x03, 0x00, 0x00,
                                    0x02, 0xAA, 0xBB, 0x00, 0x00};
  r = ParseCommand(ByteSpan{c4e});
  CHECK(r.ok() && r.value.has_le && r.value.extended && (r.value.data.size() == 2U));
  const std::array<uint8_t, 6> bad1{0x80, 0x01, 0x02, 0x03, 0x02, 0xAA};
  CHECK(!ParseCommand(ByteSpan{bad1}).ok());
  const std::array<uint8_t, 3> bad2{0x80, 0x01, 0x02};
  CHECK(!ParseCommand(ByteSpan{bad2}).ok());
  const std::array<uint8_t, 8> bad3{0x80, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00};
  CHECK(!ParseCommand(ByteSpan{bad3}).ok());
  const std::array<uint8_t, 6> bad4{0x80, 0x01, 0x02, 0x03, 0x00, 0x01};
  CHECK(!ParseCommand(ByteSpan{bad4}).ok());
}

TEST_CASE("The session framer writes ProcessSessionCmd in short and extended form") {
  session::Framer framer;
  std::array<uint8_t, 600> buf{};
  const std::array<uint8_t, 4> cmd{0x80, 0x04, 0x00, 0x20};
  for (std::size_t i = 0U; i < cmd.size(); ++i) {
    buf[session::kFrameHeadroom + i] = cmd[i];
  }
  auto plain = framer.Frame(MutableByteSpan{buf}, 4U);
  REQUIRE(plain.ok());
  CHECK_EQ(plain.value.size(), 4U); // not attached: unframed
  session::Id id{1, 2, 3, 4, 5, 6, 7, 8};
  framer.Attach(id);
  auto framed = framer.Frame(MutableByteSpan{buf}, 4U);
  REQUIRE(framed.ok());
  // 80 05 00 00 10 | 10 08 id | 41 04 cmd | 00
  const std::array<uint8_t, 22> want{0x80, 0x05, 0x00, 0x00, 0x10, 0x10, 0x08, 1,
                                     2,    3,    4,    5,    6,    7,    8,    0x41,
                                     0x04, 0x80, 0x04, 0x00, 0x20, 0x00};
  REQUIRE(framed.value.size() == want.size());
  CHECK(std::memcmp(framed.value.data(), want.data(), want.size()) == 0);
  auto big = framer.Frame(MutableByteSpan{buf}, 300U);
  REQUIRE(big.ok());
  CHECK((big.value[4] == 0x00U) && (big.value[5] == 0x01U) && (big.value[6] == 0x3AU)); // 314
  CHECK((big.value[17] == 0x41U) && (big.value[18] == 0x82U) && (big.value[19] == 0x01U) &&
        (big.value[20] == 0x2CU));
  CHECK_EQ(big.value.size(), 21U + 300U + 2U);
  CHECK_EQ(framer.Frame(MutableByteSpan(buf.data(), 40U), 10U).error, Error::BufferTooSmall);
  framer.Detach();
  CHECK(!framer.Attached());
}

TEST_CASE("CreateSession reads the session id in the 1-byte and the 0x82 length forms") {
  struct Answer {
    std::array<uint8_t, 16> bytes{};
    std::size_t length{0};
    Result<std::size_t> Transceive(ByteSpan command, MutableByteSpan r) const noexcept {
      static_cast<void>(command);
      static_cast<void>(std::memcpy(r.data(), bytes.data(), length));
      return Result<std::size_t>::Success(length);
    }
  };
  Answer a;
  a.bytes = {0x41, 0x08, 9, 8, 7, 6, 5, 4, 3, 2, 0x90, 0x00};
  a.length = 12U;
  session::Id id{};
  REQUIRE(session::CreateSession(a, ObjectId{5U}, id).ok());
  CHECK((id[0] == 9U) && (id[7] == 2U));
  a.bytes = {0x41, 0x82, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x90, 0x00};
  a.length = 14U;
  REQUIRE(session::CreateSession(a, ObjectId{5U}, id).ok());
  CHECK((id[0] == 1U) && (id[7] == 8U));
  a.bytes = {0x41, 0x07, 1, 2, 3, 4, 5, 6, 7, 0x90, 0x00};
  a.length = 11U;
  CHECK_EQ(session::CreateSession(a, ObjectId{5U}, id).error, Error::FrameError);
  a.bytes = {0x66, 0xA6};
  a.length = 2U;
  CHECK_EQ(session::CreateSession(a, ObjectId{5U}, id).error, Error::ThroughputLimited);
  a.bytes = {0x6A, 0x80};
  CHECK_EQ(session::CreateSession(a, ObjectId{5U}, id).error, Error::ChipSwUnknown);
  CHECK_EQ(session::CreateSession(a, ObjectId{0U}, id).error, Error::InvalidArgument);
}

TEST_CASE("The SCP03 KDF writes the GP derivation data and refuses bad sizes") {
  ReferenceCrypto port;
  KeyRef k{};
  REQUIRE(port.ImportKey(KeyKind::Aes128, ByteSpan(kEnc.data(), 16U), k) == CryptoStatus::Ok);
  const std::array<uint8_t, 16> ctx{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8};
  std::array<uint8_t, 16> senc{};
  REQUIRE(scp03::detail::Kdf(port, k, scp03::kDdSEnc, ByteSpan{ctx}, MutableByteSpan{senc}) ==
          Error::Ok);
  // OpenSSL: CMAC(40..4F, 00*11 04 00 0080 01 || context).
  const std::array<uint8_t, 16> want{0x69, 0x98, 0xfd, 0xbe, 0xaa, 0x87, 0x02, 0xe4,
                                     0xe8, 0x28, 0xfb, 0xdb, 0xd5, 0x2c, 0xe9, 0xea};
  CHECK(senc == want);
  std::array<uint8_t, 17> odd{};
  CHECK_EQ(scp03::detail::Kdf(port, k, 4U, ByteSpan{ctx}, MutableByteSpan{odd}),
           Error::InvalidArgument);
  std::array<uint8_t, 17> long_ctx{};
  CHECK_EQ(scp03::detail::Kdf(port, k, 4U, ByteSpan{long_ctx}, MutableByteSpan{senc}),
           Error::InvalidArgument);
  CHECK_EQ(scp03::detail::Kdf(port, KeyRef{}, 4U, ByteSpan{ctx}, MutableByteSpan{senc}),
           Error::CryptoFailure);
}

TEST_CASE("LevelByte gives the GP bytes") {
  CHECK_EQ(scp03::LevelByte(scp03::SecurityLevel::CMac), 0x01U);
  CHECK_EQ(scp03::LevelByte(scp03::SecurityLevel::CMacCDecrypt), 0x03U);
  CHECK_EQ(scp03::LevelByte(scp03::SecurityLevel::CMacRMac), 0x11U);
  CHECK_EQ(scp03::LevelByte(scp03::SecurityLevel::Full), 0x33U);
  CHECK_EQ(scp03::LevelByte(std::bit_cast<scp03::SecurityLevel>(uint8_t{4})), 0x00U);
}
