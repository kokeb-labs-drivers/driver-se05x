/**
 * @file execute_irreversible_command.cpp
 * @brief Must NOT compile: `Execute<C>` is constrained to reversible commands, so `DeleteAll`
 * cannot run through it (S-10).
 *
 * EXPECT: IsIrreversible
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
  return device.Execute<se05x::Command::DeleteAll>(se05x::Empty{}).ok() ? 1 : 0;
}
