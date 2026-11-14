/**
 * @file hrot_bench.hpp
 * @brief The facade on the chip model: a `ChipBench` opened with platform SCP03 (test keys) and an
 * `hrot::Device` bound to it, shared by the facade tests.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#ifndef SE05X_TESTS_HROT_BENCH_HPP
#define SE05X_TESTS_HROT_BENCH_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "model/chip_bench.hpp"

namespace se05x::testmodel {

/** @return A configuration that requires platform SCP03. */
inline Config ScpRequired() noexcept {
  Config c{};
  c.scp_policy = ScpPolicy::Require;
  return c;
}

/** @brief A bench and a facade; `Open()` opens the device (with platform SCP03 when `secure`). */
template <typename PortsT = BenchPorts>
struct HrotBenchT {
  explicit HrotBenchT(const ChipProfile& profile = kSe050E, bool secure = true) noexcept
      : bench(profile, T1Knobs{}, secure ? ScpRequired() : Config{}), facade(bench.device),
        secure_(secure) {}
  HrotBenchT(const HrotBenchT&) = delete;
  HrotBenchT& operator=(const HrotBenchT&) = delete;

  /** @return true when the device opened. */
  [[nodiscard]] bool Open() noexcept {
    if (secure_ && !bench.GivePlatformKeys()) {
      return false;
    }
    return bench.device.Open().ok();
  }
  /** @return The commands the applet model has seen. */
  [[nodiscard]] uint32_t Commands() const noexcept {
    return bench.chip.commands;
  }
  /** @return The vendor attestation key of the model, trusted. */
  [[nodiscard]] hrot::AttestationKey VendorKey() const noexcept {
    hrot::EcPublicKey pub{};
    pub.point = bench.chip.AttestPublic();
    return hrot::TrustAttestationKey(ObjectId{ChipModel::kAttestKey}, pub).value;
  }

  ChipBenchT<PortsT> bench;
  hrot::Device<PortsT> facade;

private:
  bool secure_;
};

using HrotBench = HrotBenchT<BenchPorts>;

/// SE050E with EXTCFG_CRYPTO_EC_FORBID_ECDH clear (bit 0x02 of every extended feature byte off).
inline constexpr ChipProfile kSe050EEcdh{"se050e_ecdh", 7U,   2U,    0U,    0x3FFFU, 0x010BU,
                                         0xA921U,       true, 0xFDU, false, true};

/// SE052F with EXTCFG_CRYPTO_EC_FORBID_ECDH clear: ECDH under the throughput limit.
inline constexpr ChipProfile kSe052Ecdh{"se052_ecdh", 7U,   2U,    22U,  0x26F2U, 0x010BU,
                                        0xB501U,      true, 0xFDU, true, false};

/// A SHA-256 digest of "abc" (FIPS 180-4 example), as a test digest.
inline constexpr std::array<uint8_t, 32> kDigestAbc{
    0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
    0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD};

} // namespace se05x::testmodel

#endif // SE05X_TESTS_HROT_BENCH_HPP
