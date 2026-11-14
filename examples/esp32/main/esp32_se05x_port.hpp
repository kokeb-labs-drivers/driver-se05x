/**
 * @file esp32_se05x_port.hpp
 * @brief ESP-IDF ports for the SE05x driver: i2c_master for the bus, esp_timer and esp_rom for the
 * clock, GPIO for ENA (SE050, SE051) or RST_N (SE052).
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * Start from this file for any ESP-IDF target. The pins are in Esp32Se05xPins; the defaults match
 * the wiring table in examples/esp32/README.md (ESP32-C6 DevKitC-1, SE050 or SE051 with ENA on
 * GPIO11). RST_N has no effect on an I2C-only SE050 or SE051 (SE050 data sheet 4.2, p. 9), so on
 * those the reset is a power cycle through ENA; on the SE052, set `reset_n` and leave `enable` at
 * -1 (SE052 data sheet Table 14, p. 20: RST_N low for at least 40 us). Built with ESP-IDF v5.5 for
 * esp32c6; **not verified on hardware**.
 */
#ifndef SE05X_ESP32_SE05X_PORT_HPP
#define SE05X_ESP32_SE05X_PORT_HPP

#include <cstddef>
#include <cstdint>

#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_rom_sys.h"
#include "esp_timer.h"

#include "se05x.hpp"

/// The port's default SCL clock, checked against the driver's bus requirements.
inline constexpr uint32_t kEsp32Se05xClockHz = 400'000;
static_assert(kEsp32Se05xClockHz <= se05x::kMaxClockHz, "SCL above the SE05x's maximum");
static_assert(!se05x::kRepeatedStart, "this port reads in a separate transaction");

/// Pins and bus settings of the ESP-IDF port.
struct Esp32Se05xPins {
  i2c_port_num_t port = I2C_NUM_0;
  int sda = 6;
  int scl = 7;
  int reset_n = -1; ///< RST_N, active low (SE052); -1 when not wired (SE050, SE051: tie to VSS).
  int enable = 11;  ///< ENA (SE050, SE051), with VOUT wired to VCC; -1 when tied high (SE052).
  uint32_t clock_hz = kEsp32Se05xClockHz; ///< Up to `se05x::kMaxClockHz`.
  int timeout_ms = 100;                   ///< Per transaction.
};

/// The SE05x I2C bus on ESP-IDF.
class Esp32Se05xBus : public se05x::BusInterface<Esp32Se05xBus> {
public:
  explicit Esp32Se05xBus(const Esp32Se05xPins& pins = {}) noexcept : pins_(pins) {}

  bool EnsureInitialized() noexcept {
    if (bus_ != nullptr) {
      return true;
    }
    i2c_master_bus_config_t cfg{};
    cfg.i2c_port = pins_.port;
    cfg.sda_io_num = static_cast<gpio_num_t>(pins_.sda);
    cfg.scl_io_num = static_cast<gpio_num_t>(pins_.scl);
    cfg.clk_source = I2C_CLK_SRC_DEFAULT;
    cfg.glitch_ignore_cnt = 7;
    cfg.flags.enable_internal_pullup = true;
    if (i2c_new_master_bus(&cfg, &bus_) != ESP_OK) {
      bus_ = nullptr;
      return false;
    }
    return true;
  }

  se05x::BusStatus Write(uint8_t addr7, se05x::ByteSpan data) noexcept {
    i2c_master_dev_handle_t dev = Device(addr7);
    if (dev == nullptr) {
      return se05x::BusStatus::BusError;
    }
    return Map(i2c_master_transmit(dev, data.data(), data.size(), pins_.timeout_ms));
  }

  se05x::BusRead Read(uint8_t addr7, se05x::MutableByteSpan out) noexcept {
    i2c_master_dev_handle_t dev = Device(addr7);
    if (dev == nullptr) {
      return se05x::BusRead{se05x::BusStatus::BusError, 0U};
    }
    const se05x::BusStatus status =
        Map(i2c_master_receive(dev, out.data(), out.size(), pins_.timeout_ms));
    return se05x::BusRead{status, (status == se05x::BusStatus::Ok) ? out.size() : 0U};
  }

private:
  se05x::BusStatus Map(esp_err_t err) const noexcept {
    if (err == ESP_OK) {
      return se05x::BusStatus::Ok;
    }
    // The ESP-IDF master driver answers a NACK, a lost arbitration and a held line alike
    // (ESP_ERR_INVALID_STATE or ESP_ERR_TIMEOUT), so the lines are looked at: SDA or SCL still low
    // once the transaction is over is a stuck bus (errata I2C.1), which only a power cycle clears.
    if (LineHeldLow()) {
      return se05x::BusStatus::BusStuck;
    }
    return (err == ESP_ERR_TIMEOUT) ? se05x::BusStatus::Timeout : se05x::BusStatus::Nack;
  }

  /// SDA or SCL low on three samples 10 us apart (a slow rise through the pull-ups is not stuck).
  bool LineHeldLow() const noexcept {
    for (int i = 0; i < 3; ++i) {
      if ((gpio_get_level(static_cast<gpio_num_t>(pins_.sda)) != 0) &&
          (gpio_get_level(static_cast<gpio_num_t>(pins_.scl)) != 0)) {
        return false;
      }
      esp_rom_delay_us(10U);
    }
    return true;
  }

  i2c_master_dev_handle_t Device(uint8_t addr7) noexcept {
    if ((device_ != nullptr) && (device_addr_ == addr7)) {
      return device_;
    }
    if (device_ != nullptr) {
      static_cast<void>(i2c_master_bus_rm_device(device_));
      device_ = nullptr;
    }
    i2c_device_config_t cfg{};
    cfg.dev_addr_length = I2C_ADDR_BIT_LEN_7;
    cfg.device_address = addr7;
    cfg.scl_speed_hz = pins_.clock_hz;
    if (i2c_master_bus_add_device(bus_, &cfg, &device_) != ESP_OK) {
      device_ = nullptr;
      return nullptr;
    }
    device_addr_ = addr7;
    return device_;
  }

  Esp32Se05xPins pins_;
  i2c_master_bus_handle_t bus_ = nullptr;
  i2c_master_dev_handle_t device_ = nullptr;
  uint8_t device_addr_ = 0;
};

/// The monotonic clock and the delay on ESP-IDF.
class Esp32Se05xClock : public se05x::ClockInterface<Esp32Se05xClock> {
public:
  uint64_t NowUs() noexcept {
    return static_cast<uint64_t>(esp_timer_get_time());
  }
  void DelayUs(uint32_t us) noexcept {
    esp_rom_delay_us(us);
  }
};

/// ENA and RST_N on GPIOs. The pins are driven inactive before their output is enabled, so setting
/// them up never pulses a reset (handbook KB-HW-018).
class Esp32Se05xReset : public se05x::ResetInterface<Esp32Se05xReset> {
public:
  explicit Esp32Se05xReset(const Esp32Se05xPins& pins = {}) noexcept : pins_(pins) {}

  /// A reset that really resets the chip: RST_N on the SE052, else the ENA power cycle.
  bool Reset() noexcept {
    return (pins_.reset_n >= 0) ? Pulse(pins_.reset_n) : PowerCycle();
  }
  /// ENA low for 10 us, five times tENalt (2 us typical, no minimum printed: SE050 data sheet
  /// Table 14, p. 18), then high; the driver waits the boot time after it.
  bool PowerCycle() noexcept {
    if (!SetEnable(false)) {
      return false;
    }
    esp_rom_delay_us(kEnaLowUs);
    return SetEnable(true);
  }
  bool SetEnable(bool enable) noexcept {
    return Drive(pins_.enable, enable ? 1U : 0U);
  }

private:
  static constexpr uint32_t kEnaLowUs = 10U;  ///< Five times the 2 us typical tENalt.
  static constexpr uint32_t kRstLowUs = 100U; ///< Above the SE052's 40 us minimum.

  static bool Drive(int pin, uint32_t level) noexcept {
    if (pin < 0) {
      return false;
    }
    gpio_config_t io{};
    io.pin_bit_mask = 1ULL << static_cast<unsigned>(pin);
    io.mode = GPIO_MODE_OUTPUT;
    return (gpio_set_level(static_cast<gpio_num_t>(pin), level) == ESP_OK) &&
           (gpio_config(&io) == ESP_OK);
  }
  static bool Pulse(int pin) noexcept {
    if (!Drive(pin, 0U)) {
      return false;
    }
    esp_rom_delay_us(kRstLowUs);
    return gpio_set_level(static_cast<gpio_num_t>(pin), 1U) == ESP_OK;
  }

  Esp32Se05xPins pins_;
};

#endif // SE05X_ESP32_SE05X_PORT_HPP
