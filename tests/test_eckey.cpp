/**
 * @file test_eckey.cpp
 * @brief The ECKey session: the build-flag gate, the authentication data of AN12543 Figure 14,
 * the DER signature, the KDF against the model's own derivation, the handshake against
 * `ScpTarget`, the receipt check (A15) and tampering of every byte of the chip's answer.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>

#include "model/bytes.hpp"
#include "model/scp_crypto.hpp"
#include "model/scp_loop.hpp"
#include "model/scp_target.hpp"
#include "se05x_crypto.hpp"
#include "se05x_eckey.hpp"
#include "test_harness.hpp"

using se05x::testmodel::CopyBytes;
using se05x::testmodel::SameBytes;
using namespace se05x;
using testmodel::Loop;
using testmodel::ScpFixture;
using testmodel::ScpPorts;
using testmodel::ScpTarget;

namespace {

// The host's long-term key (the RFC 6979 A.2.5 test key) and the chip's ECKA key: test values.
constexpr std::array<uint8_t, 32> kHost{
    0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93,
    0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21};
constexpr std::array<uint8_t, 32> kSe{
    0x51, 0x9b, 0x42, 0x3d, 0x71, 0x5f, 0x8b, 0x58, 0x1f, 0x4f, 0xa8, 0xee, 0x59, 0xf4, 0x77, 0x1a,
    0x5b, 0x44, 0xc8, 0x13, 0x0b, 0x4e, 0x3e, 0xac, 0xca, 0x54, 0xa5, 0x6d, 0xda, 0x72, 0xb4, 0x64};
constexpr uint32_t kCredential = 0x00002000U;

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
  eckey::detail::Engine<ScpPorts, Loop> engine{f.ports, loop};
  eckey::SessionParams params{};

  Rig() {
    std::array<uint8_t, 65> host_pub{};
    static_cast<void>(testmodel::mc::PublicKey(kHost.data(), host_pub.data()));
    chip.AddEcKey(kCredential, host_pub.data());
    chip.SetSeKey(kSe.data());
    SelectIot(loop);
    static_cast<void>(f.crypto.ImportKey(KeyKind::P256Private, ByteSpan{kHost}, params.host_key));
    params.credential = ObjectId{kCredential};
    params.se_public_key = ByteSpan{chip.SePublic()};
  }
};

bool Echo(eckey::detail::Engine<ScpPorts, Loop>& e, uint8_t seed) {
  const std::array<uint8_t, 9> cmd{0x80, 0x20, 0x00, 0x00, 0x03, seed, 2, 3, 0x00};
  std::array<uint8_t, 64> rsp{};
  const auto r = e.Transceive(ByteSpan{cmd}, MutableByteSpan{rsp});
  return r.ok() && (r.value == 5U) && (rsp[0] == seed) && (rsp[3] == 0x90U);
}

} // namespace

static_assert(!eckey::kEcKeySessionEnabled, "the ECKey session stays behind its flag by default");

TEST_CASE("Without SE05X_ENABLE_ECKEY_SESSION the session is Unsupported and sends nothing") {
  Rig t;
  eckey::Session<ScpPorts, Loop> session(t.f.ports, t.loop);
  const auto r = session.Open(t.params);
  CHECK_EQ(r.error, Error::Unsupported);
  CHECK_EQ(r.detail.layer, Layer::EcKey);
  CHECK_EQ(t.loop.calls, 0U);
  CHECK(!session.IsOpen());
  CHECK(session.Close().ok());
  std::array<uint8_t, 8> rsp{};
  CHECK_EQ(session.Transceive(ByteSpan{}, MutableByteSpan{rsp}).error, Error::NotInitialized);
}

TEST_CASE("The authentication data is the TLV layout of AN12543 Figure 14 and Table 86") {
  std::array<uint8_t, 65> pub{};
  for (std::size_t i = 0U; i < pub.size(); ++i) {
    pub[i] = static_cast<uint8_t>(i);
  }
  pub[0] = 0x04U;
  std::array<uint8_t, eckey::kAuthDataBytes> auth{};
  eckey::detail::BuildAuthData(pub, 0x33U, auth);
  const std::array<uint8_t, 31> a6{0xA6, 0x1D, 0x4F, 0x10, 0xA0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53,
                                   0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x90, 0x03,
                                   0xAB, 0x01, 0x33, 0x80, 0x01, 0x88, 0x81, 0x01, 0x10};
  CHECK(SameBytes(auth.data(), a6.data(), a6.size()));
  CHECK((auth[31] == 0x7FU) && (auth[32] == 0x49U) && (auth[33] == 0x46U));
  CHECK((auth[34] == 0xB0U) && (auth[35] == 0x41U));
  CHECK(SameBytes(&auth[36], pub.data(), 65U));
  CHECK((auth[101] == 0xF0U) && (auth[102] == 0x01U) && (auth[103] == 0x03U));
}

TEST_CASE("The DER signature strips leading zeros and pads a high bit") {
  std::array<uint8_t, 64> raw{};
  raw[0] = 0x80U; // r: high bit set, needs a 00
  raw[31] = 0x01U;
  raw[33] = 0x7FU; // s: one leading zero byte, then 0x7F
  raw[63] = 0x02U;
  std::array<uint8_t, 72> der{};
  const std::size_t n = eckey::detail::EncodeDerSignature(raw, der);
  CHECK_EQ(n, 2U + (2U + 33U) + (2U + 31U));
  CHECK((der[0] == 0x30U) && (der[1] == 68U));
  CHECK((der[2] == 0x02U) && (der[3] == 33U) && (der[4] == 0x00U) && (der[5] == 0x80U));
  CHECK((der[37] == 0x02U) && (der[38] == 31U) && (der[39] == 0x7FU));
  std::array<uint8_t, 32> r{};
  std::array<uint8_t, 32> s{};
  CHECK(testmodel::mc::ParseDer(testmodel::mc::Bytes(der.data(), n), r.data(), s.data()));
  CHECK(SameBytes(r.data(), raw.data(), 32U));
  CHECK(SameBytes(s.data(), &raw[32], 32U));
  std::array<uint8_t, 64> tiny{};
  tiny[31] = 0x05U;
  tiny[63] = 0x06U;
  CHECK_EQ(eckey::detail::EncodeDerSignature(tiny, der), 8U); // 30 06 02 01 05 02 01 06
  CHECK((der[3] == 1U) && (der[4] == 5U) && (der[6] == 1U) && (der[7] == 6U));
}

TEST_CASE("Master key and session keys match the model's own derivation of AN12543 p. 34") {
  ReferenceCrypto port;
  std::array<uint8_t, 32> z{};
  std::array<uint8_t, 16> dr{};
  for (std::size_t i = 0U; i < 32U; ++i) {
    z[i] = static_cast<uint8_t>(0xA0U + i);
  }
  for (std::size_t i = 0U; i < 16U; ++i) {
    dr[i] = static_cast<uint8_t>(i * 9U);
  }
  KeyRef mk{};
  REQUIRE(eckey::detail::DeriveMasterKey(port, z, dr, 0x33U, mk) == Error::Ok);
  scp03::detail::SessionKeys keys{};
  std::array<uint8_t, 16> mcv{};
  REQUIRE(eckey::detail::DeriveSessionKeys(port, mk, keys, mcv) == Error::Ok);
  // The model: SHA-256(00000001 || Z || DR || 01 33 88 10), first 16 bytes; CMAC(MK, 00*11 c 00
  // 0080 01).
  std::array<uint8_t, 56> in{0, 0, 0, 1};
  CopyBytes(&in[4], z.data(), 32U);
  CopyBytes(&in[36], dr.data(), 16U);
  in[52] = 0x01U;
  in[53] = 0x33U;
  in[54] = 0x88U;
  in[55] = 0x10U;
  std::array<uint8_t, 32> digest{};
  testmodel::mc::Sha256(testmodel::mc::Bytes(in), digest.data());
  const testmodel::mc::Bytes master(digest.data(), 16U);
  auto expect = [&](uint8_t constant, KeyRef handle) {
    std::array<uint8_t, 16> dd{};
    dd[11] = constant;
    dd[14] = 0x80U;
    dd[15] = 0x01U;
    std::array<uint8_t, 16> key{};
    testmodel::mc::Cmac(master, testmodel::mc::Bytes(dd), key.data());
    // Compare through the handle: the CMAC of an empty message under both keys.
    std::array<uint8_t, 16> a{};
    std::array<uint8_t, 16> b{};
    static_cast<void>(port.AesCmac(handle, ByteSpan{}, a));
    testmodel::mc::Cmac(testmodel::mc::Bytes(key), testmodel::mc::Bytes(), b.data());
    return a == b;
  };
  CHECK(expect(0x04U, keys.enc));
  CHECK(expect(0x06U, keys.mac));
  CHECK(expect(0x07U, keys.rmac));
  std::array<uint8_t, 16> dd{};
  dd[11] = 0x08U;
  dd[14] = 0x80U;
  dd[15] = 0x01U;
  std::array<uint8_t, 16> want_mcv{};
  testmodel::mc::Cmac(master, testmodel::mc::Bytes(dd), want_mcv.data());
  CHECK(mcv == want_mcv);
  CHECK_EQ(port.KeysInUse(), 4U);
}

TEST_CASE("ECKey handshake against the model, commands under the session, close") {
  Rig t;
  REQUIRE(t.engine.Open(t.params).ok());
  CHECK(t.engine.IsOpen());
  CHECK_EQ(t.chip.sessions_open, 1U);
  CHECK_EQ(t.f.crypto.KeysInUse(), 4U); // host key + S-ENC, S-MAC, S-RMAC; ephemeral released
  CHECK_EQ(t.engine.Counter(), 1U);
  // The framing of AN13904 Figure 7 (p. 16): 80 05 00 00 Lc 10 08 id 41 81 L 84 88 00 00 Lc' A6 1D.
  const auto& c = t.loop.last_cmd;
  CHECK((c[0] == 0x80U) && (c[1] == 0x05U) && (c[5] == 0x10U) && (c[6] == 0x08U));
  CHECK((c[15] == 0x41U) && (c[16] == 0x81U));
  CHECK((c[18] == 0x84U) && (c[19] == 0x88U) && (c[20] == 0x00U) && (c[21] == 0x00U));
  CHECK_EQ(std::size_t{c[17]}, 5U + std::size_t{c[22]}); // the inner command has no Le
  CHECK_EQ(std::size_t{c[4]}, 13U + std::size_t{c[17]});
  CHECK((c[23] == 0xA6U) && (c[24] == 0x1DU) && (c[25] == 0x4FU) && (c[26] == 0x10U));
  CHECK_EQ(t.loop.last_cmd_len, 5U + std::size_t{c[4]} + 1U); // outer Le 00
  bool ok = true;
  for (uint8_t i = 0U; i < 5U; ++i) {
    ok = ok && Echo(t.engine, static_cast<uint8_t>(0x10U + i));
  }
  CHECK(ok);
  CHECK_EQ(t.engine.Counter(), 6U); // an applet session advances on every command
  CHECK(t.engine.Close().ok());
  CHECK_EQ(t.chip.sessions_open, 0U);
  CHECK_EQ(t.f.crypto.KeysInUse(), 1U);
}

TEST_CASE("Each handshake uses a fresh ephemeral key") {
  Rig t;
  REQUIRE(t.engine.Open(t.params).ok());
  const std::array<uint8_t, 1200> first = t.loop.last_cmd;
  const std::size_t first_len = t.loop.last_cmd_len;
  REQUIRE(t.engine.Close().ok());
  REQUIRE(t.engine.Open(t.params).ok());
  CHECK(!SameBytes(first.data(), t.loop.last_cmd.data(), first_len));
}

TEST_CASE("A wrong receipt is SecureChannelError, counted; skipping the check opens (A15 knob)") {
  Rig t;
  t.chip.knobs.receipt_wrong = true;
  const auto r = t.engine.Open(t.params);
  CHECK_EQ(r.error, Error::SecureChannelError);
  CHECK(!t.engine.IsOpen());
  CHECK(t.engine.NeedsReselect());
  CHECK_EQ(t.f.crypto.KeysInUse(), 1U);
  CHECK_EQ(t.engine.Attempts().Remaining(), 2U);
  SelectIot(t.loop);
  t.params.verify_receipt = false;
  CHECK(t.engine.Open(t.params).ok());
}

TEST_CASE("A chip that starts the MAC chain at zero: every command is refused") {
  Rig t;
  t.chip.knobs.eckey_mcv_zero = true;
  REQUIRE(t.engine.Open(t.params).ok()); // the receipt does not depend on the chain
  const std::array<uint8_t, 6> cmd{0x80, 0x20, 0x00, 0x00, 0x01, 0x55};
  std::array<uint8_t, 16> rsp{};
  const auto r = t.engine.Transceive(ByteSpan{cmd}, MutableByteSpan{rsp});
  REQUIRE(r.ok());
  CHECK((r.value == 2U) && (rsp[0] == 0x69U) && (rsp[1] == 0x82U));
  CHECK_EQ(t.chip.mac_failures, 1U);
  CHECK_EQ(t.chip.applet_commands, 0U);
}

TEST_CASE("A host key the chip does not know is AuthFailed and counted") {
  Rig t;
  KeyRef other{};
  std::array<uint8_t, 32> d = kHost;
  d[5] = static_cast<uint8_t>(d[5] ^ 0x01U);
  REQUIRE(t.f.crypto.ImportKey(KeyKind::P256Private, ByteSpan{d}, other) == CryptoStatus::Ok);
  t.params.host_key = other;
  const auto r = t.engine.Open(t.params);
  CHECK_EQ(r.error, Error::AuthFailed);
  CHECK_EQ(r.detail.sw, 0x6985U);
  CHECK_EQ(r.detail.layer, Layer::EcKey);
  CHECK_EQ(t.f.crypto.KeysInUse(), 2U); // the two host keys; no session key, no ephemeral
}

TEST_CASE("Bad parameters are refused before anything is sent; then the host limit holds") {
  Rig t;
  eckey::SessionParams p = t.params;
  p.se_public_key = ByteSpan(t.chip.SePublic().data(), 64U);
  CHECK_EQ(t.engine.Open(p).error, Error::InvalidArgument);
  std::array<uint8_t, 65> compressed = t.chip.SePublic();
  compressed[0] = 0x02U;
  p.se_public_key = ByteSpan{compressed};
  CHECK_EQ(t.engine.Open(p).error, Error::InvalidArgument);
  p = t.params;
  p.host_key = KeyRef{};
  CHECK_EQ(t.engine.Open(p).error, Error::InvalidArgument);
  p = t.params;
  p.credential = ObjectId{};
  CHECK_EQ(t.engine.Open(p).error, Error::InvalidArgument);
  p = t.params;
  p.level = std::bit_cast<scp03::SecurityLevel>(uint8_t{4});
  CHECK_EQ(t.engine.Open(p).error, Error::InvalidArgument);
  CHECK_EQ(t.loop.calls, 0U);
  t.chip.knobs.receipt_wrong = true;
  t.engine.SetAuthAttemptLimit(1U);
  CHECK_EQ(t.engine.Open(t.params).error, Error::SecureChannelError);
  const uint32_t calls = t.loop.calls;
  CHECK_EQ(t.engine.Open(t.params).error, Error::AuthLocked);
  CHECK_EQ(t.loop.calls, calls);
}

TEST_CASE("Every flipped byte of the chip's authentication answer fails the handshake") {
  bool all = true;
  std::size_t checked = 0U;
  for (std::size_t byte = 0U; byte < 38U; ++byte) {
    Rig t;
    t.loop.tamper_rsp_call = 2U; // 1 CreateSession, 2 InternalAuthenticate
    t.loop.tamper_rsp_byte = byte;
    const auto r = t.engine.Open(t.params);
    all = all && (!r.ok()) && (!t.engine.IsOpen()) && (t.f.crypto.KeysInUse() == 1U);
    ++checked;
  }
  CHECK(all);
  CHECK_EQ(checked, 38U);
}

TEST_CASE("A lost answer at each handshake step leaves no session and no key") {
  for (uint32_t call = 1U; call <= 2U; ++call) {
    Rig t;
    t.loop.lose_call = call;
    CHECK_EQ(t.engine.Open(t.params).error, Error::Timeout);
    CHECK(!t.engine.IsOpen());
    CHECK_EQ(t.f.crypto.KeysInUse(), 1U);
  }
}

TEST_CASE("Under the session a tampered response closes it; a lost close is reported") {
  Rig t;
  REQUIRE(t.engine.Open(t.params).ok());
  t.loop.tamper_rsp_call = t.loop.calls + 1U;
  t.loop.tamper_rsp_byte = 3U;
  CHECK(!Echo(t.engine, 7U));
  CHECK(!t.engine.IsOpen());
  CHECK_EQ(t.f.crypto.KeysInUse(), 1U);
  SelectIot(t.loop);
  REQUIRE(t.engine.Open(t.params).ok());
  t.loop.fail_call = t.loop.calls + 1U;
  CHECK_EQ(t.engine.Close().error, Error::NeedsReselect);
  CHECK(!t.engine.IsOpen());
  CHECK_EQ(t.f.crypto.KeysInUse(), 1U);
}

TEST_CASE("Without entropy the ephemeral key cannot be made: CryptoFailure") {
  testports::NullBus bus;
  testports::NullClock clock;
  ReferenceCrypto crypto{&testmodel::NoEntropy};
  const ScpPorts ports(bus, clock, crypto);
  ScpTarget chip;
  Loop loop(chip);
  std::array<uint8_t, 65> host_pub{};
  static_cast<void>(testmodel::mc::PublicKey(kHost.data(), host_pub.data()));
  chip.AddEcKey(kCredential, host_pub.data());
  chip.SetSeKey(kSe.data());
  SelectIot(loop);
  eckey::detail::Engine<ScpPorts, Loop> engine(ports, loop);
  eckey::SessionParams p{};
  REQUIRE(crypto.ImportKey(KeyKind::P256Private, ByteSpan{kHost}, p.host_key) == CryptoStatus::Ok);
  p.credential = ObjectId{kCredential};
  const std::array<uint8_t, 65> se_pub = chip.SePublic();
  p.se_public_key = ByteSpan{se_pub};
  CHECK_EQ(engine.Open(p).error, Error::CryptoFailure);
  CHECK(engine.NeedsReselect()); // CreateSession ran: the half-open session needs a reselect
}
