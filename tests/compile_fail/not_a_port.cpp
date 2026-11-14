/**
 * @file not_a_port.cpp
 * @brief Must NOT compile: a class that does not derive from `BusInterface` is not a bus port, so
 * `Ports` rejects it.
 *
 * EXPECT: BusPort
 */
#include "null_ports.hpp"
#include "se05x.hpp"

namespace {
class NotABus {};
} // namespace

int main() {
  using Bad = se05x::Ports<NotABus, se05x::testports::NullClock, se05x::ReferenceCrypto>;
  return (sizeof(Bad*) > 0U) ? 0 : 1;
}
