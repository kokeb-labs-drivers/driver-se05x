/**
 * @file eckey_flag_on.cpp
 * @brief The ECKey session with `SE05X_ENABLE_ECKEY_SESSION=1`: the gate opens and the session
 * runs the handshake of `eckey::detail::Engine` against the model. Built as its own executable
 * (with test_main.cpp) so that the flag is the same in every unit of it.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <array>
#include <cstdint>

#include "model/scp_crypto.hpp"
#include "model/scp_loop.hpp"
#include "model/scp_target.hpp"
#include "se05x_crypto.hpp"
#include "se05x_eckey.hpp"
#include "test_harness.hpp"

using namespace se05x;

static_assert(eckey::kEcKeySessionEnabled, "build this unit with SE05X_ENABLE_ECKEY_SESSION=1");

TEST_CASE("With the flag on, Session::Open runs the handshake and commands go under it") {
  testmodel::ScpFixture f;
  testmodel::ScpTarget chip;
  testmodel::Loop loop(chip);
  std::array<uint8_t, 32> host{};
  std::array<uint8_t, 32> se{};
  for (std::size_t i = 0U; i < 32U; ++i) {
    host[i] = static_cast<uint8_t>(0x21U + i);
    se[i] = static_cast<uint8_t>(0x42U + (3U * i));
  }
  std::array<uint8_t, 65> host_pub{};
  static_cast<void>(testmodel::mc::PublicKey(host.data(), host_pub.data()));
  chip.AddEcKey(0x2001U, host_pub.data());
  chip.SetSeKey(se.data());
  const std::array<uint8_t, 22> select{0x00, 0xA4, 0x04, 0x00, 0x10, 0xA0, 0x00, 0x00,
                                       0x03, 0x96, 0x54, 0x53, 0x00, 0x00, 0x00, 0x01,
                                       0x03, 0x00, 0x00, 0x00, 0x00, 0x00};
  std::array<uint8_t, 64> rsp{};
  REQUIRE(loop.Transceive(ByteSpan{select}, MutableByteSpan{rsp}).ok());
  eckey::SessionParams p{};
  REQUIRE(f.crypto.ImportKey(KeyKind::P256Private, ByteSpan{host}, p.host_key) == CryptoStatus::Ok);
  p.credential = ObjectId{0x2001U};
  const std::array<uint8_t, 65> se_pub = chip.SePublic();
  p.se_public_key = ByteSpan{se_pub};
  eckey::Session<testmodel::ScpPorts, testmodel::Loop> session(f.ports, loop);
  REQUIRE(session.Open(p).ok());
  CHECK(session.IsOpen());
  const std::array<uint8_t, 7> cmd{0x80, 0x20, 0x00, 0x00, 0x02, 0x12, 0x34};
  const auto r = session.Transceive(ByteSpan{cmd}, MutableByteSpan{rsp});
  CHECK(r.ok() && (r.value == 4U) && (rsp[0] == 0x12U));
  CHECK(session.Close().ok());
  CHECK_EQ(chip.sessions_open, 0U);
}
