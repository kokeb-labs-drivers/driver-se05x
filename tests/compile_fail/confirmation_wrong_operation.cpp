/**
 * @file confirmation_wrong_operation.cpp
 * @brief Must NOT compile: a `Confirmation` for one operation cannot be used for another (S-10).
 *
 * EXPECT: Confirmation
 * FLAG_ON: built with SE05X_ENABLE_IRREVERSIBLE=1.
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
  const se05x::irreversible::Confirmation<se05x::irreversible::SetLockStatePersistent> wrong{
      se05x::irreversible::SetLockStatePersistent::kPhrase};
  return device.ExecuteIrreversible<se05x::Command::DeleteAll,
                                    se05x::irreversible::DeleteAllObjects>(se05x::Empty{}, wrong)
                 .ok()
             ? 1
             : 0;
}
