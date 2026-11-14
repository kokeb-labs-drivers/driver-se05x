/**
 * @file scp_over_userid.cpp
 * @brief Must NOT compile: a secure channel stacked on a UserID session (S-14: a UserID session
 * carries no secure messaging, AN12543 3.6.3.1).
 *
 * EXPECT: no secure messaging over a UserID session
 */
#include "null_ports.hpp"
#include "se05x_crypto.hpp"
#include "se05x_scp03.hpp"

namespace {
struct Link {
  se05x::Result<std::size_t> Transceive(se05x::ByteSpan, se05x::MutableByteSpan) noexcept {
    return se05x::Result<std::size_t>::Success(0U);
  }
};
using P =
    se05x::Ports<se05x::testports::NullBus, se05x::testports::NullClock, se05x::ReferenceCrypto>;
using User = se05x::session::UserIdSession<P, Link>;
} // namespace

int main() {
  se05x::testports::NullBus bus;
  se05x::testports::NullClock clock;
  se05x::ReferenceCrypto crypto;
  const P ports(bus, clock, crypto);
  Link link;
  User user(ports, link);
  se05x::scp03::Channel<P, User> channel(ports, user);
  return channel.IsOpen() ? 1 : 0;
}
