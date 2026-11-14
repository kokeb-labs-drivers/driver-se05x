/**
 * @file chip_bench.hpp
 * @brief The whole chain for the device tests: `Device` -> `t1::Link` -> `T1Target` ->
 * `ScpTarget` -> `ChipModel`, with a simulated clock, reset and log ports and the reference
 * crypto.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Test keys only: every key here is made up for the tests; none belongs to a real chip.
 */
#ifndef SE05X_TESTS_MODEL_CHIP_BENCH_HPP
#define SE05X_TESTS_MODEL_CHIP_BENCH_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "model/chip_model.hpp"
#include "model/scp_script.hpp"
#include "model/scp_target.hpp"
#include "model/t1_target.hpp"
#include "se05x.hpp"

namespace se05x::testmodel {

/// The port set of the bench.
using BenchPorts = Ports<T1Target, SimClock, ReferenceCrypto, SimReset, SimLog>;
/// A port set without a reset port.
using BenchPlainPorts = Ports<T1Target, SimClock, ReferenceCrypto>;

/// Test platform keys (ENC, MAC): made up for the tests.
inline constexpr std::array<uint8_t, 16> kPlatformEnc{
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F};
inline constexpr std::array<uint8_t, 16> kPlatformMac{
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F};
/// A test AESKey authentication object and its key.
inline constexpr uint32_t kAesCredential = 0x00007001U;
inline constexpr std::array<uint8_t, 16> kAesKey{0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
                                                 0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F};
/// A test UserID object and its value.
inline constexpr uint32_t kUserCredential = 0x00007002U;
inline constexpr std::array<uint8_t, 6> kUserValue{0x31, 0x32, 0x33, 0x34, 0x35, 0x36};
/// The chip's test ECKA private key.
inline constexpr std::array<uint8_t, 32> kEckaPrivate{
    0x1F, 0x2E, 0x3D, 0x4C, 0x5B, 0x6A, 0x79, 0x08, 0x17, 0x26, 0x35, 0x44, 0x53, 0x62, 0x71, 0x0E,
    0x0D, 0x1C, 0x2B, 0x3A, 0x49, 0x58, 0x67, 0x76, 0x05, 0x14, 0x23, 0x32, 0x41, 0x50, 0x6F, 0x7E};

/** @brief The chain with a reset and a log port. */
template <typename PortsT = BenchPorts>
struct ChipBenchT {
  explicit ChipBenchT(const ChipProfile& profile = kSe050E, const T1Knobs& t1_knobs = T1Knobs{},
                      const Config& config = Config{}) noexcept
      : chip(scp, profile), t1(clock, &scp, t1_knobs), reset(t1), ports(makePorts()),
        device(ports, config) {
    scp.SetPlatformKeys(kPlatformEnc.data(), kPlatformMac.data(), 16U, 0x0BU);
    scp.AddAesKey(kAesCredential, kAesKey.data());
    scp.AddUserId(kUserCredential, kUserValue.data(), kUserValue.size(), 5U);
    scp.SetSeKey(kEckaPrivate.data());
    chip.SetEcka(kEckaPrivate.data());
    chip.knobs.user_id_auth = kUserCredential;
  }
  ChipBenchT(const ChipBenchT&) = delete;
  ChipBenchT& operator=(const ChipBenchT&) = delete;

  /** @brief Give the device the platform key set (handles of the reference crypto). */
  [[nodiscard]] bool GivePlatformKeys() noexcept {
    scp03::ChannelParams p{};
    const bool ok =
        (crypto.ImportKey(KeyKind::Aes128, ByteSpan{kPlatformEnc}, p.keys.enc) ==
         CryptoStatus::Ok) &&
        (crypto.ImportKey(KeyKind::Aes128, ByteSpan{kPlatformMac}, p.keys.mac) == CryptoStatus::Ok);
    return ok && device.SetPlatformKeys(p).ok();
  }
  /** @return The AESKey session parameters with a fresh key handle. */
  [[nodiscard]] AesKeySessionParams AesParams() noexcept {
    AesKeySessionParams p{};
    p.credential = ObjectId{kAesCredential};
    static_cast<void>(crypto.ImportKey(KeyKind::Aes128, ByteSpan{kAesKey}, p.keys.enc));
    return p;
  }
  /** @return The UserID session parameters. */
  [[nodiscard]] static UserIdSessionParams UserParams() noexcept {
    return UserIdSessionParams{ObjectId{kUserCredential}, ByteSpan{kUserValue}};
  }

  SimClock clock;
  ScpTarget scp;
  ChipModel chip;
  T1Target t1;
  ReferenceCrypto crypto{&CountingEntropy};
  SimReset reset;
  SimLog log;
  PortsT ports;
  Device<PortsT> device;

private:
  PortsT makePorts() noexcept {
    if constexpr (PortsT::kHasReset) {
      return PortsT(t1, clock, crypto, reset, log);
    } else {
      return PortsT(t1, clock, crypto);
    }
  }
};

using ChipBench = ChipBenchT<BenchPorts>;
using ChipPlainBench = ChipBenchT<BenchPlainPorts>;

/** @return A test policy for the chip's generation: sign and verify for every session. */
template <AppletGeneration G>
inline Policy SignPolicy() noexcept {
  const Result<Policy> p = PolicyBuilder<G, ObjectClass::EcKeyPair, Profile::Open>{}
                               .ForAllOthers()
                               .template Allow<Rule::Sign>()
                               .template Allow<Rule::Verify>()
                               .WithReason(OpenReason::Laboratory)
                               .Build();
  return p.value;
}

} // namespace se05x::testmodel

#endif // SE05X_TESTS_MODEL_CHIP_BENCH_HPP
