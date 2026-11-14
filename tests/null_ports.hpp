/**
 * @file null_ports.hpp
 * @brief Minimal ports that satisfy the port concepts: for the contract test, the examples and the
 * install check. They talk to nothing; every bus read says the chip is not ready.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#ifndef SE05X_TESTS_NULL_PORTS_HPP
#define SE05X_TESTS_NULL_PORTS_HPP

#include <cstdint>

#include "se05x_crypto.hpp"
#include "se05x_ports.hpp"

namespace se05x::testports {

/** @brief A bus with nobody on it. */
class NullBus : public BusInterface<NullBus> {
public:
  bool EnsureInitialized() noexcept {
    return true;
  }
  BusStatus Write(uint8_t addr7, ByteSpan data) noexcept {
    static_cast<void>(addr7);
    static_cast<void>(data);
    return BusStatus::Nack;
  }
  BusRead Read(uint8_t addr7, MutableByteSpan out) noexcept {
    static_cast<void>(addr7);
    static_cast<void>(out);
    return BusRead{BusStatus::Nack, 0U};
  }
};

/** @brief A clock that never advances. */
class NullClock : public ClockInterface<NullClock> {
public:
  uint64_t NowUs() noexcept {
    return 0U;
  }
  void DelayUs(uint32_t us) noexcept {
    static_cast<void>(us);
  }
};

/** @brief A reset line that is not connected. */
class NullReset : public ResetInterface<NullReset> {
public:
  bool Reset() noexcept {
    return true;
  }
  bool PowerCycle() noexcept {
    return true;
  }
  bool SetEnable(bool enable) noexcept {
    static_cast<void>(enable);
    return false;
  }
};

/** @brief A log that discards. */
class NullLog : public LogInterface<NullLog> {
public:
  void Log(const LogRecord& record) noexcept {
    static_cast<void>(record);
  }
};

} // namespace se05x::testports

#endif // SE05X_TESTS_NULL_PORTS_HPP
