/**
 * @file checked_config_invalid.cpp
 * @brief Must NOT compile: a CheckedConfig built from a configuration that Validate() rejects fails
 * the build, naming the error (handbook KB-CPP20-013).
 *
 * EXPECT: ConfigIsInvalid
 */
#include "se05x_types.hpp"

int main() {
  // A zero ATR poll budget is not allowed: Validate() rejects it.
  constexpr se05x::CheckedConfig kBoard{se05x::Config{.atr_poll_budget_ms = 0U}};
  return static_cast<int>(kBoard.Get().atr_poll_budget_ms);
}
