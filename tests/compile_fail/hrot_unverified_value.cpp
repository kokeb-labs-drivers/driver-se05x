/**
 * @file hrot_unverified_value.cpp
 * @brief Must NOT compile: only the facade creates a `Verified<T>` (S-09): a value cannot be
 * declared checked.
 *
 * EXPECT: Verified.*private|private.*Verified
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
  const se05x::hrot::Verified<se05x::hrot::AttestedValue> forged{se05x::hrot::AttestedValue{}};
  return forged.IsValid() ? 1 : 0;
}
