/**
 * @file quickstart.cpp
 * @brief The quick start: build the ports, open the device, ask the chip for random bytes.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <cstdint>

#include "my_port.hpp"
#include "se05x.hpp"

namespace {

// --8<-- [start:quickstart]
using BoardPorts = se05x::Ports<MyBus, MyClock, se05x::ReferenceCrypto>;

se05x::Error RandomBytes(MyBus& bus, MyClock& clock, se05x::ReferenceCrypto& crypto,
                         se05x::MutableByteSpan out) noexcept {
  const BoardPorts ports(bus, clock, crypto);
  se05x::Device<BoardPorts> device(ports, se05x::Config{});
  if (const auto opened = device.Open(); !opened.ok()) {
    return opened.error; // for example DeviceIdMismatch: nothing answered like an SE05x
  }
  const auto random = device.GetRandom(out);
  static_cast<void>(device.Close());
  return random.error;
}
// --8<-- [end:quickstart]

// A snippet that is never linked must still be used.
[[maybe_unused]] constexpr auto kQuickstart = &RandomBytes;

} // namespace
