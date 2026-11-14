/**
 * @file main.cpp
 * @brief Builds the driver from the installed package only: headers, version header and .ipp.
 */
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "se05x.hpp"

namespace {

// Ports that talk to nothing: enough to instantiate the whole template stack.
class NullBus : public se05x::BusInterface<NullBus> {
public:
  bool EnsureInitialized() noexcept {
    return true;
  }
  se05x::BusStatus Write(uint8_t addr7, se05x::ByteSpan data) noexcept {
    static_cast<void>(addr7);
    static_cast<void>(data);
    return se05x::BusStatus::Nack;
  }
  se05x::BusRead Read(uint8_t addr7, se05x::MutableByteSpan out) noexcept {
    static_cast<void>(addr7);
    static_cast<void>(out);
    return se05x::BusRead{se05x::BusStatus::Nack, 0U};
  }
};

class NullClock : public se05x::ClockInterface<NullClock> {
public:
  uint64_t NowUs() noexcept {
    return 0U;
  }
  void DelayUs(uint32_t us) noexcept {
    static_cast<void>(us);
  }
};

} // namespace

int main() {
  NullBus bus;
  NullClock clock;
  se05x::ReferenceCrypto crypto;
  using Ports = se05x::Ports<NullBus, NullClock, se05x::ReferenceCrypto>;
  const Ports ports(bus, clock, crypto);
  se05x::Device<Ports> device(ports, se05x::Config{});
  // The template compiled and ran: Open() returns an error on a bus with nothing on it.
  const auto r = device.Open();
  return (!r.ok() && (std::strlen(se05x::GetDriverVersion()) > 0U)) ? 0 : 1;
}
