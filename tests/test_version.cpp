/**
 * @file test_version.cpp
 * @brief The version getters follow the generated se05x_version.h, so they cannot drift from
 * CMake.
 *
 * Built twice by tests/CMakeLists.txt: against the real generated header (the getters must equal
 * the CMake project version, passed as EXPECTED_*), and against a probe header generated from the
 * same template with version 9.8.7 (a getter that returns a literal instead of reading the header
 * fails there).
 */
#include <cstdio>
#include <cstring>

#include "se05x_types.hpp"

static_assert(se05x::GetDriverVersionMajor() == EXPECTED_MAJOR, "major version differs from CMake");
static_assert(se05x::GetDriverVersionMinor() == EXPECTED_MINOR, "minor version differs from CMake");
static_assert(se05x::GetDriverVersionPatch() == EXPECTED_PATCH, "patch version differs from CMake");

int main() {
  if (std::strcmp(se05x::GetDriverVersion(), EXPECTED_STRING) != 0) {
    static_cast<void>(std::printf("version string %s, expected %s\n", se05x::GetDriverVersion(),
                                  EXPECTED_STRING));
    return 1;
  }
  static_cast<void>(std::printf("version %s: PASS\n", se05x::GetDriverVersion()));
  return 0;
}
