/**
 * @file slot_out_of_range.cpp
 * @brief Must NOT compile: a facade `Slot` is built only by `MakeSlot`, which checks the range.
 *
 * EXPECT: Slot
 */
#include "se05x.hpp"

int main() {
  const se05x::hrot::Slot slot{99U};
  return slot.Index();
}
