/**
 * @file lifecycle.cpp
 * @brief Compiles the lifecycle job (`lifecycle.hpp`) for the quick start's board ports, with
 * `SE05X_ENABLE_IRREVERSIBLE=1` set for this file by `tests/CMakeLists.txt`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include "lifecycle.hpp"
#include "my_port.hpp"

static_assert(se05x::kIrreversibleEnabled, "tests/CMakeLists.txt builds this file with the flag");

namespace {
using BoardPorts = se05x::Ports<MyBus, MyClock, se05x::ReferenceCrypto>;
[[maybe_unused]] constexpr auto kLifecycle = &jobs::LockForGood<BoardPorts>;
} // namespace
