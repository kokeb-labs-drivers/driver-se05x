/**
 * @file fuzz_pki_der.cpp
 * @brief Fuzz target of the strict DER reader and the primitive checks of the PKI layer.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * Invariants (abort on violation): the input is walked as a tree with an explicit stack of at most
 * `der::kMaxDepth` readers (the reader itself never recurses); every accepted element lies inside
 * its parent and is re-encoded by the writer to exactly the same bytes (DER is canonical: a reader
 * that accepted a non-minimal length or a long form for a short length would break this); an
 * accepted non-negative INTEGER is re-encoded from its magnitude to the same bytes; an accepted
 * BOOLEAN is 00 or FF; an accepted time is a valid calendar time; every check returns a `Reason`
 * that is an enumerator.
 */
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "se05x_pki_der.hpp"

namespace {

using namespace se05x;
using namespace se05x::pki;

void Require(bool ok) {
  if (!ok) {
    std::abort();
  }
}

/// The largest element re-encoded (libFuzzer's default inputs are at most 4096 bytes).
constexpr std::size_t kMaxOut = 8192U;

bool Inside(ByteSpan inner, ByteSpan outer) {
  return (inner.data() >= outer.data()) &&
         ((inner.data() + inner.size()) <= (outer.data() + outer.size()));
}

void CheckReencode(const der::Element& e) {
  if (e.encoded.size() > kMaxOut) {
    return;
  }
  std::array<uint8_t, kMaxOut> out{};
  der::Writer w(MutableByteSpan{out});
  if ((e.tag & der::kConstructed) != 0U) {
    w.Begin(e.tag);
    w.Raw(e.value);
    w.End();
  } else {
    w.Primitive(e.tag, e.value);
  }
  const Result<std::size_t> r = w.Finish();
  Require(r.ok());
  Require(der::SameBytes(ByteSpan{out}.first(r.value), e.encoded));
}

void CheckPrimitive(const der::Element& e) {
  ByteSpan m{};
  if ((e.tag == der::kInteger) && (e.encoded.size() <= kMaxOut) &&
      (der::ParseUnsigned(e.value, m) == Reason::Ok)) {
    std::array<uint8_t, kMaxOut> out{};
    der::Writer w(MutableByteSpan{out});
    w.Integer(m);
    const Result<std::size_t> r = w.Finish();
    Require(r.ok() && der::SameBytes(ByteSpan{out}.first(r.value), e.encoded));
  }
  bool b = false;
  if (der::ParseBoolean(e.value, b) == Reason::Ok) {
    Require((e.value[0] == 0x00U) || (e.value[0] == 0xFFU));
  }
  Time t{};
  if (der::ParseTime(e, t) == Reason::Ok) {
    Require(IsValid(t));
  }
  ByteSpan bits{};
  uint8_t unused = 0U;
  uint16_t named = 0U;
  uint32_t small = 0U;
  Require(se05x::detail::IsEnumerator(der::ParseBitString(e.value, bits, unused)));
  Require(se05x::detail::IsEnumerator(der::ParseNamedBits(e.value, named)));
  Require(se05x::detail::IsEnumerator(der::ParseSmall(e.value, 0xFFFFFFFFU, small)));
  Require(se05x::detail::IsEnumerator(der::CheckOid(e.value)));
  Require(se05x::detail::IsEnumerator(der::CheckUtf8(e.value)));
  Require(se05x::detail::IsEnumerator(der::CheckPrintable(e.value)));
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
  const ByteSpan input{data, size};
  std::array<der::Reader, der::kMaxDepth + 1U> stack{der::Reader(input)};
  std::array<ByteSpan, der::kMaxDepth + 1U> parents{input};
  std::size_t top = 0U;
  for (std::size_t steps = 0U; steps < 100000U; ++steps) {
    der::Element e{};
    if (stack[top].AtEnd() || (stack[top].Next(e) != Reason::Ok)) {
      if (top == 0U) {
        break;
      }
      --top;
      continue;
    }
    Require(Inside(e.encoded, parents[top]) && Inside(e.value, e.encoded));
    CheckReencode(e);
    if ((e.tag & der::kConstructed) == 0U) {
      CheckPrimitive(e);
    } else if (top < der::kMaxDepth) {
      der::Reader child(ByteSpan{});
      const Reason r = stack[top].Enter(e, child);
      Require((r == Reason::Ok) || (r == Reason::TooDeep));
      if (r == Reason::Ok) {
        ++top;
        stack[top] = child;
        parents[top] = e.value;
        Require(stack[top].Depth() == top);
      }
    } else {
      der::Reader child(ByteSpan{});
      Require(stack[top].Enter(e, child) == Reason::TooDeep);
    }
  }
  std::array<uint8_t, 96> raw{};
  Require(se05x::detail::IsEnumerator(der::ParseEcdsaSignature(input, 48U, MutableByteSpan{raw})));
  return 0;
}
