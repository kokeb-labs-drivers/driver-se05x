/**
 * @file hrot_slot_at_out_of_range.cpp
 * @brief Must NOT compile: `Slot::At<N>()` checks the index at compile time.
 *
 * EXPECT: kSlotCount
 */
#include <array>
#include <cstdint>

#include "null_ports.hpp"
#include "se05x.hpp"

using P =
    se05x::Ports<se05x::testports::NullBus, se05x::testports::NullClock, se05x::ReferenceCrypto>;

int main() {
  se05x::testports::NullBus bus;
  se05x::testports::NullClock clock;
  se05x::ReferenceCrypto crypto;
  const P ports(bus, clock, crypto);
  se05x::Device<P> device(ports, se05x::Config{});
  se05x::hrot::Device<P> facade(device);
  static_cast<void>(facade);
  return se05x::hrot::Slot::At<16>().Index();
}
