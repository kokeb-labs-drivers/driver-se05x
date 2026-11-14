/**
 * @file my_port.hpp
 * @brief The ports a board supplies, as shown in the quick start and the porting guide (compiled by
 * the host build so the pages cannot show code that does not compile).
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#ifndef SE05X_TESTS_DOCS_MY_PORT_HPP
#define SE05X_TESTS_DOCS_MY_PORT_HPP

#include <cstdint>

#include "se05x_ports.hpp"

// --8<-- [start:port]
class MyBus : public se05x::BusInterface<MyBus> {
public:
  bool EnsureInitialized() noexcept {
    return true; // set up the I2C controller here; return false when it cannot start
  }
  se05x::BusStatus Write(uint8_t addr7, se05x::ByteSpan data) noexcept {
    static_cast<void>(addr7);
    static_cast<void>(data);
    return se05x::BusStatus::Ok; // one I2C write transaction; Nack when the chip does not answer
  }
  se05x::BusRead Read(uint8_t addr7, se05x::MutableByteSpan out) noexcept {
    static_cast<void>(addr7);
    static_cast<void>(out);
    return se05x::BusRead{se05x::BusStatus::Nack, 0U}; // Nack while the chip is not ready
  }
};

class MyClock : public se05x::ClockInterface<MyClock> {
public:
  uint64_t NowUs() noexcept {
    return 0U; // a monotonic microsecond counter
  }
  void DelayUs(uint32_t us) noexcept {
    static_cast<void>(us); // block for at least `us` microseconds
  }
};
// --8<-- [end:port]

#endif // SE05X_TESTS_DOCS_MY_PORT_HPP
