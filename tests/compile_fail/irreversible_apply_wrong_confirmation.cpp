/**
 * @file irreversible_apply_wrong_confirmation.cpp
 * @brief Must NOT compile: `Apply` takes the confirmation of the plan's own operation (S-10).
 *
 * EXPECT: SetLockStatePersistent
 * FLAG_ON: built with SE05X_ENABLE_IRREVERSIBLE=1.
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
  se05x::irreversible::Operations<P> ops(device);
  const se05x::irreversible::Plan<se05x::irreversible::DeleteAllObjects> plan{};
  const se05x::irreversible::Confirmation<se05x::irreversible::SetLockStatePersistent> wrong{
      se05x::irreversible::SetLockStatePersistent::kPhrase};
  return ops.Apply(plan, wrong).ok() ? 1 : 0;
}
