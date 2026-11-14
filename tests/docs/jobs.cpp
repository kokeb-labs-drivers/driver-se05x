/**
 * @file jobs.cpp
 * @brief Compiles every job and recipe of `jobs.hpp` for the quick start's board ports (compiled,
 * never linked; the same templates run against the chip model in `tests/test_docs_jobs.cpp`).
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include "jobs.hpp"
#include "my_port.hpp"

namespace {

using BoardPorts = se05x::Ports<MyBus, MyClock, se05x::ReferenceCrypto>;

[[maybe_unused]] constexpr auto kOpen = &jobs::OpenSecure<BoardPorts>;
[[maybe_unused]] constexpr auto kProvision = &jobs::ProvisionDeviceKey<BoardPorts>;
[[maybe_unused]] constexpr auto kAttest = &jobs::AttestDeviceKey<BoardPorts>;
[[maybe_unused]] constexpr auto kSign = &jobs::SignAndVerify<BoardPorts>;
[[maybe_unused]] constexpr auto kEcdh = &jobs::AgreeWithPeer<BoardPorts>;
[[maybe_unused]] constexpr auto kAnchor = &jobs::StoreFirmwareRoot<BoardPorts>;
[[maybe_unused]] constexpr auto kFirmware = &jobs::CheckFirmware<BoardPorts>;
[[maybe_unused]] constexpr auto kWrapped = &jobs::ImportWrappedAesKey<BoardPorts>;
[[maybe_unused]] constexpr auto kSession = &jobs::OpenAesKeySession<BoardPorts>;
[[maybe_unused]] constexpr auto kSeal = &jobs::SealConfig<BoardPorts>;
[[maybe_unused]] constexpr auto kUnseal = &jobs::UnsealConfig<BoardPorts>;
[[maybe_unused]] constexpr auto kCert = &jobs::KeepCertificate<BoardPorts>;
[[maybe_unused]] constexpr auto kBoot = &jobs::BootCheck<BoardPorts>;
[[maybe_unused]] constexpr auto kCommit = &jobs::CommitImage<BoardPorts>;
[[maybe_unused]] constexpr auto kRecord = &jobs::FactoryRecord<BoardPorts>;
[[maybe_unused]] constexpr auto kTls = &jobs::TlsSignCallback<BoardPorts>;
[[maybe_unused]] constexpr auto kNonce = &jobs::Nonce<BoardPorts>;
[[maybe_unused]] constexpr auto kBudget = &jobs::ApdusLeft<BoardPorts>;

} // namespace
