/**
 * @file fuzz_hrot_sequence.cpp
 * @brief Sequence fuzzer of the facade: a sequence of facade calls, secure-messaging states, APDU
 * budgets and chip faults read from the input, through the whole model chain. Invariants after
 * every call: a call refused by the facade (layer `Hrot`) sent nothing; without secure messaging
 * no key, counter or secret-data call reaches the chip; a `Verified<T>` exists only on success
 * and names the chip the model is; a load never reports more than the buffer; the APDU count
 * passes the ceiling only by the recovery after a 0x66A6 answer (`kRecoveryApdus`, S-17); the
 * link keeps errata I2C.1 and I2C.2.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "hrot_bench.hpp"
#include "model/t1_fixture.hpp"

namespace {

using namespace se05x;
using testmodel::HrotBench;

void Check(bool ok) {
  if (!ok) {
    std::abort();
  }
}

/// What the device sends after a 0x66A6 answer beyond the admitted cost: the select, ReadState
/// and the two platform SCP03 handshake commands (docs/hrot-cookbook.md, S-17).
constexpr uint32_t kRecoveryApdus = 4U;

/// An admitted call ends at most `kRecoveryApdus` past the ceiling; a refused one adds nothing.
/// The count may be above the ceiling already (a `Recover()` fault is counted but not admitted),
/// and then every call is refused.
void WithinBudget(const HrotBench& t, uint32_t used_before) {
  const hrot::ApduBudget b = t.facade.Budget();
  if (b.applies) {
    const uint32_t bound = b.limit + kRecoveryApdus;
    Check(b.Used() <= ((used_before > bound) ? used_before : bound));
  }
}

/// A refusal of the facade itself sends nothing.
template <typename T>
void Refused(const HrotBench& t, const Result<T>& r, uint32_t before) {
  if (!r.ok() && (r.detail.layer == Layer::Hrot) && (r.detail.step == 1U)) {
    Check(t.Commands() == before);
  }
}

void Fault(HrotBench& t, uint8_t op) {
  switch (op % 5U) {
  case 0U:
    testmodel::DropFromNow(t.bench.t1, 1U + (op >> 5U));
    break;
  case 1U:
    if ((op & 0x20U) != 0U) {
      t.bench.chip.knobs.inject_sw = 0x66A6U; // the chip's throughput limit, whatever the count
    } else if ((op & 0x10U) != 0U) {
      t.bench.chip.knobs.inject_sw = 0x6985U;
    } else {
      t.bench.chip.knobs.inject_sw = 0x6A80U;
    }
    t.bench.chip.knobs.inject_count = 1U;
    t.bench.chip.knobs.inject_skip = static_cast<uint32_t>(op >> 6U);
    break;
  case 2U:
    t.bench.chip.knobs.unique_id_flip = static_cast<uint8_t>(op & 0x03U);
    break;
  case 3U:
    t.facade.SetWindowCount(kThroughputLimitApdus - (op >> 4U));
    break;
  default:
    static_cast<void>(t.bench.device.Recover());
    break;
  }
}

void Call(HrotBench& t, uint8_t op, uint8_t arg) {
  const uint32_t before = t.Commands();
  const uint32_t used_before = t.facade.Budget().Used();
  const bool secure = t.bench.device.SecureMessagingActive();
  const hrot::Slot slot = hrot::Slot::Make(static_cast<uint8_t>(arg & 0x03U)).value;
  const std::array<uint8_t, 32> digest{arg};
  switch (op % 9U) {
  case 0U: {
    const auto r = t.facade.Provision<hrot::KeyUse::Sign>(slot);
    Refused(t, r, before);
    Check(r.ok() == r.value.IsValid());
    Check(secure || !r.ok());
    break;
  }
  case 1U: {
    const auto k = t.facade.Find<hrot::KeyUse::Sign>(slot);
    const auto s = t.facade.Sign(k.value, hrot::Digest{digest});
    Check(k.ok() || (s.error == Error::InvalidArgument));
    Check(secure || !s.ok());
    if (s.ok()) {
      const auto v = t.facade.VerifySignature(k.value, hrot::Digest{digest}, s.value.View());
      Check(v.ok() || (v.error != Error::AttestationInvalid)); // the chip's own signature verifies
    }
    break;
  }
  case 2U: {
    const auto r = t.facade.Attest(t.VendorKey(), slot);
    Refused(t, r, before);
    Check(r.ok() == r.value.IsValid());
    if (r.ok()) {
      // The id the chip signed. The facade reads the plain id once per open and compares every
      // signed id with it, so a flip set after that first read is not seen: no check on the knob.
      Check(r.value.Get().unique_id[0] == 0xC0U);
    }
    break;
  }
  case 3U: {
    static std::array<uint8_t, 600> data{};
    data[0] = arg;
    const auto r = t.facade.Store(
        hrot::DataSlot::Make(arg & 0x01U).value, ByteSpan{data}.first(1U + (arg * 2U)),
        ((arg & 0x80U) != 0U) ? hrot::Protection::Secret : hrot::Protection::Public);
    Refused(t, r, before);
    break;
  }
  case 4U: {
    std::array<uint8_t, 256> out{};
    const auto r =
        t.facade.Load(hrot::DataSlot::Make(arg & 0x01U).value, MutableByteSpan{out},
                      ((arg & 0x80U) != 0U) ? hrot::Protection::Secret : hrot::Protection::Public);
    Refused(t, r, before);
    Check(!r.ok() || (r.value <= out.size()));
    break;
  }
  case 5U: {
    const auto r = t.facade.CreateCounter(hrot::CounterSlot::Make(arg & 0x01U).value, arg);
    Refused(t, r, before);
    Check(secure || !r.ok());
    break;
  }
  case 6U: {
    const auto r = t.facade.CheckFloor(hrot::CounterSlot::Make(arg & 0x01U).value, arg);
    Refused(t, r, before);
    Check(secure || !r.ok());
    break;
  }
  case 7U: {
    std::array<uint8_t, 64> out{};
    const auto r = t.facade.Random(MutableByteSpan{out}.first(1U + (arg & 0x3FU)));
    Refused(t, r, before);
    break;
  }
  default: {
    const auto r = t.facade.RaiseCounterTo(hrot::CounterSlot::Make(arg & 0x01U).value, arg);
    Refused(t, r, before);
    break;
  }
  }
  WithinBudget(t, used_before);
  Check(t.bench.t1.i2c1_violations == 0U);
  Check(t.bench.t1.empty_writes == 0U);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
  if (size < 2U) {
    return 0;
  }
  HrotBench t(((data[0] & 0x01U) != 0U) ? testmodel::kSe052 : testmodel::kSe050E,
              (data[0] & 0x02U) != 0U);
  if (!t.Open()) {
    return 0;
  }
  if ((data[0] & 0x04U) != 0U) {
    static_cast<void>(t.bench.device.BeginAesKeySession(t.bench.AesParams()));
  }
  constexpr std::size_t kMaxSteps = 24U;
  for (std::size_t i = 1U; ((i + 1U) < size) && (i < (2U * kMaxSteps)); i += 2U) {
    if ((data[i] & 0xE0U) == 0xE0U) {
      Fault(t, data[i + 1U]);
    } else {
      Call(t, data[i], data[i + 1U]);
    }
  }
  return 0;
}
