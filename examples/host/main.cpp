/**
 * @file main.cpp
 * @brief The root-of-trust jobs on your PC, against the simulated chip of the host tests: open with
 * platform SCP03, read the identity, provision a key, attest it, sign and verify, keep a sealed
 * configuration and an anti-rollback counter, and show what a bus with no chip gives.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * No hardware and no SDK. The chip is the independent model in `tests/model/` (T=1, SCP03 and the
 * IoT applet written from the documents); its keys are made up for the tests. Exit code 0 when
 * every step did what the comment says.
 */
#include <array>
#include <cstdint>
#include <cstdio>

#include "model/chip_bench.hpp"
#include "null_ports.hpp"
#include "se05x.hpp"

namespace {

using se05x::Error;
namespace hrot = se05x::hrot;

/// Print one step and whether it did what was expected.
bool Step(const char* what, Error got, Error expected) {
  static_cast<void>(std::printf("%-44s %s\n", what, se05x::ToString(got)));
  return got == expected;
}

/// The SHA-256 digest of "abc" (FIPS 180-4), as the message to sign.
constexpr std::array<uint8_t, 32> kDigest{
    0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
    0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD};

bool NoChip() {
  se05x::testports::NullBus bus;
  se05x::testports::NullClock clock;
  se05x::ReferenceCrypto crypto;
  using Ports =
      se05x::Ports<se05x::testports::NullBus, se05x::testports::NullClock, se05x::ReferenceCrypto>;
  const Ports ports(bus, clock, crypto);
  se05x::Device<Ports> device(ports, se05x::Config{});
  return Step("Open with nothing on the bus", device.Open().error, Error::Nack);
}

bool Jobs() {
  se05x::Config config{};
  config.scp_policy = se05x::ScpPolicy::Require;
  se05x::testmodel::ChipBench chip(se05x::testmodel::kSe050E, se05x::testmodel::T1Knobs{}, config);
  bool ok = chip.GivePlatformKeys(); // the model's made-up platform keys, as key handles
  ok = Step("Open with platform SCP03", chip.device.Open().error, Error::Ok) && ok;
  hrot::Device<se05x::testmodel::BenchPorts> facade(chip.device);

  const auto id = facade.Identify();
  ok = Step("Identify", id.error, Error::Ok) && ok;
  static_cast<void>(std::printf("  applet %u.%u.%u, OEF id %04X\n", id.value.applet.major,
                                id.value.applet.minor, id.value.applet.patch, id.value.oef_id));

  const auto key = facade.Provision<hrot::KeyUse::Sign>(hrot::Slot::At<0>());
  ok = Step("Provision a signing key in slot 0", key.error, Error::Ok) && ok;
  ok = Step("Provision slot 0 again",
            facade.Provision<hrot::KeyUse::Sign>(hrot::Slot::At<0>()).error, Error::ObjectExists) &&
       ok;

  hrot::EcPublicKey vendor{};
  vendor.point = chip.chip.AttestPublic(); // in a product: from the verified vendor certificate
  const auto trusted =
      hrot::TrustAttestationKey(se05x::FromReserved(se05x::ReservedId::RootOfTrustKey), vendor);
  const auto attested = facade.Attest(trusted.value, hrot::Slot::At<0>());
  ok = Step("Attest the key (verified)", attested.error, Error::Ok) && ok;

  const hrot::Digest digest{kDigest};
  const auto signature = facade.Sign(key.value, digest);
  ok = Step("Sign a digest", signature.error, Error::Ok) && ok;
  ok = Step("Verify the signature on the chip",
            facade.VerifySignature(key.value, digest, signature.value.View()).error, Error::Ok) &&
       ok;

  const std::array<uint8_t, 4> config_blob{0x01U, 0x02U, 0x03U, 0x04U};
  ok = Step("Seal a configuration",
            facade
                .Store(hrot::DataSlot::At<0>(), se05x::ByteSpan{config_blob},
                       hrot::Protection::Secret)
                .error,
            Error::Ok) &&
       ok;

  ok = Step("Create the firmware floor at 3",
            facade.CreateCounter(hrot::CounterSlot::At<0>(), 3U).error, Error::Ok) &&
       ok;
  ok = Step("Boot image version 4", facade.CheckFloor(hrot::CounterSlot::At<0>(), 4U).error,
            Error::Ok) &&
       ok;
  ok = Step("Boot image version 2 (a rollback)",
            facade.CheckFloor(hrot::CounterSlot::At<0>(), 2U).error, Error::PolicyDenied) &&
       ok;

  static_cast<void>(
      std::printf("APDUs sent: %u\n", static_cast<unsigned>(facade.Budget().issued_by_device)));
  ok = Step("Close", chip.device.Close().error, Error::Ok) && ok;
  return ok;
}

} // namespace

int main() {
  static_cast<void>(
      std::printf("SE05X driver %s on the host, simulated chip\n", se05x::GetDriverVersion()));
  const bool jobs = Jobs();
  const bool absent = NoChip();
  return (jobs && absent) ? 0 : 1;
}
