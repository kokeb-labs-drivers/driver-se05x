/**
 * @file fuzz_policy_parse.cpp
 * @brief Fuzz target of the parsers of what the chip says about an object: the attribute block
 * (ReadObjectAttributes) and a policy set read back from it.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * Invariants (abort on violation): an accepted attribute block carries a policy set that is
 * itself well formed and fits its buffer, never more attempts left than the limit when there is
 * one, and parses the same twice; a refusal is `FrameError` from the APDU layer with default
 * attributes; a policy set is either `Ok` or `PolicyInvalid`, and a well-formed set is no longer
 * well formed once its last byte is removed (every byte belongs to an entry).
 */
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "se05x_objects.hpp"

namespace {

using namespace se05x;

void Require(bool ok) {
  if (!ok) {
    std::abort();
  }
}

bool SameAttributes(const ObjectAttributes& a, const ObjectAttributes& b) {
  if ((a.object_class != b.object_class) || (a.origin != b.origin) || (a.lifetime != b.lifetime) ||
      (a.authentication.value != b.authentication.value) || (a.max_attempts != b.max_attempts) ||
      (a.attempts_left != b.attempts_left) || (a.version != b.version) ||
      (a.policy.length != b.policy.length)) {
    return false;
  }
  for (std::size_t i = 0U; i < a.policy.length; ++i) {
    if (a.policy.bytes[i] != b.policy.bytes[i]) {
      return false;
    }
  }
  return true;
}

void CheckAttributes(ByteSpan input) {
  const Result<ObjectAttributes> r = ParseObjectAttributes(input);
  if (!r.ok()) {
    Require(r.error == Error::FrameError);
    Require(r.detail.layer == Layer::Apdu);
    Require(SameAttributes(r.value, ObjectAttributes{}));
    return;
  }
  Require(r.value.policy.length <= r.value.policy.bytes.size());
  const ByteSpan policy{r.value.policy.bytes.data(), r.value.policy.length};
  Require(ValidatePolicyBytes(policy) == Error::Ok);
  if (r.value.max_attempts != 0U) {
    Require(r.value.attempts_left <= r.value.max_attempts);
  }
  const Result<ObjectAttributes> again = ParseObjectAttributes(input);
  Require(again.ok() && SameAttributes(r.value, again.value));
}

void CheckPolicy(ByteSpan input) {
  const Error e = ValidatePolicyBytes(input);
  Require((e == Error::Ok) || (e == Error::PolicyInvalid));
  if ((e == Error::Ok) && !input.empty()) {
    // Every entry is length-prefixed and the set is read to its last byte, so dropping that byte
    // leaves an entry short.
    Require(ValidatePolicyBytes(input.first(input.size() - 1U)) == Error::PolicyInvalid);
  }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
  const ByteSpan input{data, size};
  CheckAttributes(input);
  CheckPolicy(input);
  return 0;
}
