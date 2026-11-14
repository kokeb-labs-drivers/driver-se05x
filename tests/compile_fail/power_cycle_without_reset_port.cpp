/**
 * @file power_cycle_without_reset_port.cpp
 * @brief Must NOT compile: a port set without a reset port has no `PowerCycle()`.
 *
 * EXPECT: kHasReset
 */
#include "null_ports.hpp"
#include "se05x.hpp"

int main() {
  se05x::testports::NullBus bus;
  se05x::testports::NullClock clock;
  se05x::ReferenceCrypto crypto;
  using P =
      se05x::Ports<se05x::testports::NullBus, se05x::testports::NullClock, se05x::ReferenceCrypto>;
  const P ports(bus, clock, crypto);
  se05x::Device<P> device(ports, se05x::Config{});
  return device.PowerCycle().ok() ? 1 : 0;
}
