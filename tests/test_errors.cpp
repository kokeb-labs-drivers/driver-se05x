/**
 * @file test_errors.cpp
 * @brief The error model: every enumerator has a name, the values are stable, the stub helper
 * reports the layer.
 */
#include <cstring>

#include "se05x.hpp"
#include "test_harness.hpp"

TEST_CASE("Every error has a name and the base set keeps its values") {
  CHECK_EQ(static_cast<int>(se05x::Error::Ok), 0);
  CHECK_EQ(static_cast<int>(se05x::Error::Unsupported), 9);
  CHECK_EQ(static_cast<int>(se05x::Error::BufferTooSmall), 16);
  for (int v = 0; v <= static_cast<int>(se05x::Error::ThroughputLimited); ++v) {
    if ((v > 9) && (v < 16)) {
      continue; // the gap between the base set and the chip-specific range
    }
    CHECK(std::strcmp(se05x::ToString(static_cast<se05x::Error>(v)), "Unknown") != 0);
  }
  CHECK_EQ(std::strcmp(se05x::ToString(static_cast<se05x::Error>(200)), "Unknown"), 0);
}

TEST_CASE("NotImplemented names the layer and is never ok") {
  const auto r = se05x::NotImplemented<int>(se05x::Layer::Apdu);
  CHECK(!r.ok());
  CHECK_EQ(r.error, se05x::Error::NotImplemented);
  CHECK_EQ(r.detail.layer, se05x::Layer::Apdu);
}
