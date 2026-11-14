/**
 * @file hrot_wrong_key_use.cpp
 * @brief Must NOT compile: `Sign` takes only a `SignKey`, never a key of another use.
 *
 * EXPECT: KeyUse::Agree
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
  const std::array<uint8_t, 32> digest{};
  return facade.Sign(se05x::hrot::AgreeKey{}, se05x::hrot::Digest{digest}).ok() ? 1 : 0;
}
