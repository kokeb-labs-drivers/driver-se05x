/**
 * @file se05x_kconfig.hpp
 * @brief Optional ESP-IDF layer: a `Config` built from the `CONFIG_SE05X_*` Kconfig options (the
 * irreversible-operations flag is not a `Config` value: it is the build flag
 * `SE05X_ENABLE_IRREVERSIBLE`).
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Include this header only where you want menuconfig to choose the defaults; the driver never
 * includes it and no driver signature depends on it. Under ESP-IDF the values come from
 * `sdkconfig.h`. Without Kconfig every option falls back to the datasheet default, so
 * `KconfigDefaults()` equals `Config{}`.
 *
 * Kconfig writes a bool option set to "n" as an absent macro.
 *
 * One configuration per program: the inline function below depends on the `CONFIG_` macros, so
 * every translation unit of one program must see the same values (ESP-IDF has one `sdkconfig.h`
 * per build; each host test is its own program). No driver or library header includes this one
 * (handbook KB-CPP20-018).
 */
#ifndef SE05X_KCONFIG_HPP
#define SE05X_KCONFIG_HPP

#ifdef __has_include
#if __has_include("sdkconfig.h")
#include "sdkconfig.h"
#endif
#endif

#include "se05x_types.hpp"

#ifndef CONFIG_SE05X_BOOT_WAIT_MS
/** Wait after power-up when Kconfig does not set it: `Config{}.boot_wait_ms`. */
#define CONFIG_SE05X_BOOT_WAIT_MS 20
#endif
#ifndef CONFIG_SE05X_ATR_POLL_BUDGET_MS
/** Longest wait for the ATR when Kconfig does not set it: `Config{}.atr_poll_budget_ms`. */
#define CONFIG_SE05X_ATR_POLL_BUDGET_MS 1000
#endif
#ifndef CONFIG_SE05X_FRAME_RETRIES
/** Block resends before a resync when Kconfig does not set it: `Config{}.frame_retries`. */
#define CONFIG_SE05X_FRAME_RETRIES 3
#endif

namespace se05x {

/**
 * @brief The configuration menuconfig selected, on top of the defaults.
 * @return `Config{}` with the boot wait, ATR budget, retries, SCP03 policy and probes from Kconfig.
 */
constexpr Config KconfigDefaults() noexcept {
  Config c{};
  c.boot_wait_ms = CONFIG_SE05X_BOOT_WAIT_MS;
  c.atr_poll_budget_ms = CONFIG_SE05X_ATR_POLL_BUDGET_MS;
  c.frame_retries = CONFIG_SE05X_FRAME_RETRIES;
#ifdef CONFIG_SE05X_SCP_REQUIRE
  c.scp_policy = ScpPolicy::Require;
#elif defined(CONFIG_SE05X_SCP_OFF)
  c.scp_policy = ScpPolicy::Off;
#endif
#if defined(CONFIG_SE05X_PROBE_DISABLE)
  c.probe_capabilities = false;
#endif
  return c;
}

} // namespace se05x

#endif // SE05X_KCONFIG_HPP
