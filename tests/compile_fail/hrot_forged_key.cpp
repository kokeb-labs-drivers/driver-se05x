/**
 * @file hrot_forged_key.cpp
 * @brief Must NOT compile: a key handle cannot be made by hand: only the facade creates a valid
 * one.
 *
 * EXPECT: private.*Key<|Key<.*private
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
  const se05x::hrot::SignKey key{se05x::hrot::Slot::At<0>()};
  return key.IsValid() ? 1 : 0;
}
