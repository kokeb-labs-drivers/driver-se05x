/**
 * @file pki_recipes.cpp
 * @brief Compiles every recipe of `pki_recipes.hpp` for the quick start's board ports (compiled,
 * never linked; the same templates run against the chip model in `tests/test_pki_recipes.cpp`).
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include "pki_recipes.hpp"
#include "my_port.hpp"

namespace {

using BoardPorts = se05x::Ports<MyBus, MyClock, se05x::ReferenceCrypto>;
constexpr se05x::AppletGeneration kV7 = se05x::AppletGeneration::V7;

[[maybe_unused]] constexpr auto kGenerate = &pki_recipes::GenerateDeviceKey<kV7, BoardPorts>;
[[maybe_unused]] constexpr auto kCsr = &pki_recipes::MakeCsr<BoardPorts, se05x::ReferenceCrypto>;
[[maybe_unused]] constexpr auto kImport = &pki_recipes::ImportCertificates<kV7, BoardPorts>;
[[maybe_unused]] constexpr auto kCheck =
    &pki_recipes::CheckDeviceCertificate<BoardPorts, se05x::ReferenceCrypto>;

} // namespace
