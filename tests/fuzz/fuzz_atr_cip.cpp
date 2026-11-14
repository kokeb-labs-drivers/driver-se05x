/**
 * @file fuzz_atr_cip.cpp
 * @brief Fuzz target of the ATR (UM11225) and CIP (GPC_SPE_172) parsers.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * Invariants (abort on violation): an accepted answer has a BWT and an IFSC the link can use (IFSC
 * 1 to 0xFE for the ATR, 1 to 0x0FF9 for the CIP), the IFSD of its flavour, a flavour tag that
 * matches the parser, at least the bytes of the fixed fields and, for the CIP, at most 64 bytes;
 * the parsers are strict, so one byte more or one byte less is refused; a refusal is `FrameError`
 * from the T=1 layer with default values; parsing twice gives the same result.
 */
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "se05x_atr.hpp"

namespace {

using namespace se05x;

void Require(bool ok) {
  if (!ok) {
    std::abort();
  }
}

bool Same(const t1::LinkParams& a, const t1::LinkParams& b) {
  return (a.flavour == b.flavour) && (a.ifsc == b.ifsc) && (a.ifsd == b.ifsd) &&
         (a.bwt_ms == b.bwt_ms) && (a.max_scl_khz == b.max_scl_khz) &&
         (a.min_poll_us == b.min_poll_us) && (a.guard_us == b.guard_us) &&
         (a.wakeup_us == b.wakeup_us) && (a.high_speed == b.high_speed) &&
         (a.stretching == b.stretching);
}

void CheckRefusal(const Result<t1::LinkParams>& r) {
  Require(r.error == Error::FrameError);
  Require(r.detail.layer == Layer::T1);
  Require(Same(r.value, t1::LinkParams{}));
}

std::array<uint8_t, 4096>& Longer() {
  static std::array<uint8_t, 4096> buffer{};
  return buffer;
}

template <typename F>
void Strict(ByteSpan in, F parse) {
  // A valid answer stays valid only at exactly its length.
  if (!in.empty()) {
    CheckRefusal(parse(in.first(in.size() - 1U)));
  }
  std::array<uint8_t, 4096>& longer = Longer();
  if (in.size() < longer.size()) {
    for (std::size_t i = 0U; i < in.size(); ++i) {
      longer[i] = in[i];
    }
    longer[in.size()] = 0x5AU;
    CheckRefusal(parse(ByteSpan{longer}.first(in.size() + 1U)));
  }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
  const ByteSpan in{data, size};
  const auto atr = t1::ParseAtr(in);
  const auto cip = t1::ParseCip(in);
  Require(Same(atr.value, t1::ParseAtr(in).value) && (atr.error == t1::ParseAtr(in).error));
  Require(Same(cip.value, t1::ParseCip(in).value) && (cip.error == t1::ParseCip(in).error));
  if (atr.ok()) {
    Require(atr.value.flavour == TransportFlavour::Um11225);
    Require((atr.value.bwt_ms != 0U) && (atr.value.ifsc != 0U) && (atr.value.ifsc <= 0xFEU));
    Require(atr.value.ifsd == atr.value.ifsc);
    Require(atr.value.min_poll_us <= 65000U);
    Require(size >= 25U); // PVER, VID, DLLP (4), PLID, PLP (11), HB length
    Strict(in, [](ByteSpan b) { return t1::ParseAtr(b); });
  } else {
    CheckRefusal(atr);
  }
  if (cip.ok()) {
    Require(cip.value.flavour == TransportFlavour::Gp);
    Require((cip.value.bwt_ms != 0U) && (cip.value.ifsc != 0U) && (cip.value.ifsc <= 0x0FF9U));
    Require(cip.value.ifsd == 64U);
    Require((size >= 21U) && (size <= 64U));
    Require(cip.value.wakeup_us <= 65000U);
    Strict(in, [](ByteSpan b) { return t1::ParseCip(b); });
  } else {
    CheckRefusal(cip);
  }
  return 0;
}
