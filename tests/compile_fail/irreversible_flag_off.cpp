/**
 * @file irreversible_flag_off.cpp
 * @brief Must NOT compile: without `SE05X_ENABLE_IRREVERSIBLE` the irreversible operations do not
 * exist.
 *
 * EXPECT: kIrreversibleEnabled
 * FLAG_OFF: skipped when the library is configured with SE05X_ENABLE_IRREVERSIBLE=ON.
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
  se05x::irreversible::Operations<P> operations(device);
  return operations.PlanDeleteAllObjects().ok() ? 1 : 0;
}
