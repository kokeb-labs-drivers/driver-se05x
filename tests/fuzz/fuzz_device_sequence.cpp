/**
 * @file fuzz_device_sequence.cpp
 * @brief Sequence fuzzer: drives `Device` through the whole model chain (link, SCP target, chip
 * model) with a sequence of calls and faults read from the input. Invariants after every call:
 * never a second command over an unread answer (errata I2C.1), never an empty write (I2C.2), a
 * state that matches the session, no secure messaging while closed, and an error with the
 * default value on failure.
 */
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "model/chip_bench.hpp"
#include "model/t1_fixture.hpp"

namespace {

using namespace se05x;
using testmodel::ChipBench;

void Check(bool ok) {
  if (!ok) {
    std::abort();
  }
}

void Invariants(const ChipBench& b) {
  Check(b.t1.i2c1_violations == 0U);
  Check(b.t1.empty_writes == 0U);
  const DeviceState s = b.device.State();
  Check((s == DeviceState::InSession) == (b.device.Session() != SessionKind::None));
  if ((s == DeviceState::Closed) || (s == DeviceState::Dead)) {
    Check(b.device.Session() == SessionKind::None);
    Check(b.device.Role() == AuthRole::None);
  }
  if (s == DeviceState::Closed) {
    Check(!b.device.SecureMessagingActive());
  }
}

void Fault(ChipBench& b, uint8_t op) {
  switch (op % 6U) {
  case 0U:
    testmodel::DropFromNow(b.t1, 1U + (op >> 5U));
    break;
  case 1U:
    b.chip.knobs.inject_sw = ((op & 0x10U) != 0U) ? 0x6985U : 0x6D00U;
    b.chip.knobs.inject_count = 1U;
    break;
  case 2U:
    b.t1.Knobs().base.throttle_enabled = true;
    b.t1.Knobs().base.throttle_after = op >> 3U;
    break;
  case 3U:
    b.t1.Knobs().base.throttle_enabled = false;
    break;
  case 4U:
    b.chip.knobs.selftest_silent = (op & 0x08U) != 0U;
    break;
  default:
    b.t1.bus_errors = 1U;
    break;
  }
}

void Call(ChipBench& b, uint8_t op, uint8_t arg) {
  std::array<uint8_t, 32> buf{};
  std::array<uint8_t, 80> sig{};
  switch (op % 12U) {
  case 0U:
    static_cast<void>(b.device.Open());
    break;
  case 1U:
    static_cast<void>(b.device.Close());
    break;
  case 2U: {
    const auto r = b.device.GetRandom(MutableByteSpan{buf}.first(1U + (arg % 31U)));
    static_cast<void>(r);
    break;
  }
  case 3U:
    static_cast<void>(b.device.BeginUserIdSession(ChipBench::UserParams()));
    break;
  case 4U:
    static_cast<void>(b.device.BeginAesKeySession(b.AesParams()));
    break;
  case 5U:
    static_cast<void>(b.device.EndSession());
    break;
  case 6U:
    static_cast<void>(b.device.Recover());
    break;
  case 7U: {
    const Policy p = testmodel::SignPolicy<AppletGeneration::V7>();
    static_cast<void>(b.device.GenerateEcKey(ObjectId{0x1000U + (arg & 3U)}, p, EcCurve::NistP256));
    break;
  }
  case 8U: {
    const auto s = b.device.EcdsaSign(ObjectId{0x1000U + (arg & 3U)}, EcSignAlgo::Sha256,
                                      ByteSpan{buf}, MutableByteSpan{sig});
    Check(s.ok() || (s.value == 0U));
    break;
  }
  case 9U:
    static_cast<void>(b.device.TriggerSelfTest(0xFE01U, irreversible::ResetExpected{}));
    break;
  case 10U:
    static_cast<void>(b.device.PowerCycle());
    break;
  default: {
    const auto r = b.device.FreeMemory(MemoryType::Persistent);
    Check(r.ok() || (r.value == 0U));
    break;
  }
  }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
  if (size < 2U) {
    return 0;
  }
  ChipBench b(((data[0] & 1U) != 0U) ? testmodel::kSe052 : testmodel::kSe050E);
  const std::size_t steps = (size - 1U) / 2U;
  for (std::size_t i = 0U; (i < steps) && (i < 24U); ++i) {
    const uint8_t op = data[1U + (2U * i)];
    const uint8_t arg = data[2U + (2U * i)];
    if ((op & 0x80U) != 0U) {
      Fault(b, arg);
    } else {
      Call(b, op, arg);
    }
    Invariants(b);
  }
  static_cast<void>(b.device.Close());
  Invariants(b);
  Check(b.device.State() == DeviceState::Closed);
  return 0;
}
