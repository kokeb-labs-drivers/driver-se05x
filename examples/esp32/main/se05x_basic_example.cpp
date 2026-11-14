/**
 * @file se05x_basic_example.cpp
 * @brief Open the SE05x from the menuconfig values, log what the chip is, and close it.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * Wiring: examples/esp32/README.md. Without a chip, `Open()` returns `Nack` after the bounded
 * poll; the example logs the error by name either way. **Not verified on hardware.**
 */
#include "esp_log.h"

#include "esp32_se05x_port.hpp"
#include "se05x.hpp"
#include "se05x_kconfig.hpp"

namespace {
constexpr const char* kTag = "se05x_example";
}

extern "C" void app_main(void) {
  static Esp32Se05xBus bus;
  static Esp32Se05xClock clock;
  static Esp32Se05xReset reset;
  static se05x::ReferenceCrypto
      crypto; // bring-up only (safety.md S-15): use a hardware crypto port
  using Ports =
      se05x::Ports<Esp32Se05xBus, Esp32Se05xClock, se05x::ReferenceCrypto, Esp32Se05xReset>;
  static const Ports ports(bus, clock, crypto, reset);
  static se05x::Device<Ports> device(ports, se05x::KconfigDefaults()); // no I/O

  ESP_LOGI(kTag, "SE05x driver %s", se05x::GetDriverVersion());
  const auto opened = device.Open();
  if (!opened.ok()) {
    ESP_LOGE(kTag, "Open failed: %s", se05x::ToString(opened.error));
    return;
  }
  const auto& caps = device.GetCapabilities();
  ESP_LOGI(kTag, "opened: applet %u.%u.%u, OEF id %04X", caps.applet.major, caps.applet.minor,
           caps.applet.patch, caps.oef_id);
  static_cast<void>(device.Close());
}
