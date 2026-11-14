/**
 * @file lifecycle.hpp
 * @brief The lifecycle job of the getting-started page: plan, confirm and apply the persistent
 * transport lock. Exists only with `SE05X_ENABLE_IRREVERSIBLE=1`; `tests/docs/lifecycle.cpp`
 * compiles it with the flag and `tests/test_irreversible.cpp` runs it against the chip model.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#ifndef SE05X_TESTS_DOCS_LIFECYCLE_HPP
#define SE05X_TESTS_DOCS_LIFECYCLE_HPP

#include "se05x.hpp"

#if defined(SE05X_ENABLE_IRREVERSIBLE) && (SE05X_ENABLE_IRREVERSIBLE != 0)

namespace jobs {

// --8<-- [start:lifecycle]
/// Lock the transport for good. Run it from a session with the Transport credential; show the
/// plan's effect to a person; the phrase is typed by that person, not by the code that planned it.
template <se05x::PortSet P>
se05x::Error LockForGood(se05x::Device<P>& device, const se05x::irreversible::Phrase& typed,
                         void (*show)(const char* effect)) noexcept {
  using Op = se05x::irreversible::SetLockStatePersistent;
  se05x::irreversible::Operations<P> operations(device);
  const auto plan = operations.PlanSetLockStatePersistent(); // sends nothing
  if (!plan.ok()) {
    return plan.error; // ConditionsNotSatisfied: not a Transport session; WrongState: locked
  }
  show(plan.value.Effect());
  return operations.Apply(plan.value, se05x::irreversible::Confirmation<Op>{typed}).error;
}
// --8<-- [end:lifecycle]

} // namespace jobs

#endif // SE05X_ENABLE_IRREVERSIBLE

#endif // SE05X_TESTS_DOCS_LIFECYCLE_HPP
