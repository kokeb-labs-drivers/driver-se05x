/**
 * @file hrot_provision_verify_key.cpp
 * @brief Must NOT compile: a verification key is imported (`ImportPublicKey`), never generated.
 *
 * EXPECT: KeyUse::Verify
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
  return facade.Provision<se05x::hrot::KeyUse::Verify>(se05x::hrot::Slot::At<0>()).ok() ? 1 : 0;
}
