/**
 * @file test_kconfig.cpp
 * @brief KconfigDefaults(): the defaults without Kconfig, and menuconfig values when they are set.
 *
 * Built twice: without CONFIG_ macros (KCONFIG_SET undefined) and with the values an sdkconfig.h
 * would define (KCONFIG_SET=1, see tests/CMakeLists.txt).
 */
#include "se05x_kconfig.hpp"
#include "test_harness.hpp"

#ifdef KCONFIG_SET
TEST_CASE("Kconfig values reach the Config") {
  constexpr se05x::Config kC = se05x::KconfigDefaults();
  CHECK_EQ(kC.boot_wait_ms, 50U);
  CHECK_EQ(kC.atr_poll_budget_ms, 500U);
  CHECK_EQ(kC.frame_retries, 5U);
  CHECK_EQ(kC.scp_policy, se05x::ScpPolicy::Require);
  CHECK(!kC.probe_capabilities);
  CHECK_EQ(kC.flavour, se05x::TransportFlavour::Auto); // not a Kconfig option: default
  CHECK_EQ(se05x::Validate(kC), se05x::Error::Ok);
}
#else
TEST_CASE("Without Kconfig, KconfigDefaults() equals Config{}") {
  constexpr se05x::Config kC = se05x::KconfigDefaults();
  constexpr se05x::Config kD{};
  CHECK_EQ(kC.boot_wait_ms, kD.boot_wait_ms);
  CHECK_EQ(kC.atr_poll_budget_ms, kD.atr_poll_budget_ms);
  CHECK_EQ(kC.frame_retries, kD.frame_retries);
  CHECK_EQ(kC.scp_policy, kD.scp_policy);
  CHECK_EQ(kC.probe_capabilities, kD.probe_capabilities);
}
#endif
