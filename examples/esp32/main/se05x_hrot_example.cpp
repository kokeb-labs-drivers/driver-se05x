/**
 * @file se05x_hrot_example.cpp
 * @brief The root-of-trust facade on an ESP32: open the SE05x with platform SCP03 (keys from your
 * key store, held by the PSA crypto port), read the identity, provision the device key once,
 * attest it, sign a digest and check the firmware floor.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * Wiring: examples/esp32/README.md. The platform SCP03 keys are never in this source: fill
 * `LoadPlatformKeys()` from NVS encryption or another key store. Without them the example opens
 * without secure messaging and shows that the facade then refuses every key operation
 * (`PolicyDenied`, nothing sent). **Not verified on hardware.**
 */
#include <array>
#include <cstdint>

#include "esp_log.h"

#include "esp32_se05x_port.hpp"
#include "se05x.hpp"
#include "se05x_kconfig.hpp"
#include "se05x_psa_crypto.hpp"

namespace {

constexpr const char* kTag = "se05x_hrot";

using Ports = se05x::Ports<Esp32Se05xBus, Esp32Se05xClock, se05x::psa::PsaCrypto, Esp32Se05xReset>;

/// Import your platform SCP03 keys into the crypto port. Read them from a key store; return false
/// when the board has none. Never compile key bytes (or a vendor default key set) into the image.
bool LoadPlatformKeys(se05x::psa::PsaCrypto& /*crypto*/, se05x::scp03::ChannelParams& /*params*/) {
  return false; // read the keys, crypto.ImportKey(KeyKind::Aes128, ...) into params.keys.enc and
                // .mac
}

void Log(const char* what, se05x::Error error) {
  if (error == se05x::Error::Ok) {
    ESP_LOGI(kTag, "%s: Ok", what);
  } else {
    ESP_LOGW(kTag, "%s: %s", what, se05x::ToString(error));
  }
}

} // namespace

extern "C" void app_main(void) {
  static Esp32Se05xBus bus;
  static Esp32Se05xClock clock;
  static Esp32Se05xReset reset;
  static se05x::psa::PsaCrypto crypto;
  static const Ports ports(bus, clock, crypto, reset);
  static se05x::Device<Ports> device(ports, se05x::KconfigDefaults()); // no I/O

  se05x::scp03::ChannelParams keys{};
  if (LoadPlatformKeys(crypto, keys)) {
    Log("Platform keys", device.SetPlatformKeys(keys).error);
  } else {
    ESP_LOGW(kTag, "no platform keys: the facade will refuse key operations");
  }
  const auto opened = device.Open();
  Log("Open", opened.error);
  if (!opened.ok()) {
    return;
  }
  se05x::hrot::Device<Ports> hrot(device);

  const auto id = hrot.Identify();
  Log("Identify", id.error);
  if (id.ok()) {
    ESP_LOGI(kTag, "applet %u.%u.%u, OEF id %04X", id.value.applet.major, id.value.applet.minor,
             id.value.applet.patch, id.value.oef_id);
  }

  constexpr se05x::hrot::Slot kDeviceKey = se05x::hrot::Slot::At<0>();
  auto key = hrot.Find<se05x::hrot::KeyUse::Sign>(kDeviceKey);
  if (key.error == se05x::Error::ObjectNotFound) {
    key = hrot.Provision<se05x::hrot::KeyUse::Sign>(kDeviceKey);
  }
  Log("Device key", key.error);
  if (key.ok()) {
    const std::array<uint8_t, 32> digest{}; // the SHA-256 of what you sign
    const auto signature = hrot.Sign(key.value, se05x::hrot::Digest{digest});
    Log("Sign", signature.error);
  }

  const auto floor = hrot.CheckFloor(se05x::hrot::CounterSlot::At<0>(), 1U);
  Log("Firmware floor", floor.error);

  const se05x::hrot::ApduBudget budget = hrot.Budget();
  ESP_LOGI(kTag, "APDUs sent: %u", static_cast<unsigned>(budget.issued_by_device));
  Log("Close", device.Close().error);
}
