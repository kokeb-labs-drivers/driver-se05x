/**
 * @file fuzz_scp03_unwrap.cpp
 * @brief Fuzz target of the secure channel: arbitrary bytes as an SCP03 response (R-MAC, padding,
 * R-ENC), as a command to wrap, and as the session answers the library parses (CreateSession,
 * TLVs). Invariants: no out-of-range access (the hardened library traps), every error is an
 * enumerator, a forged R-MAC never passes, a response never grows, the counter never goes back.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Input layout: byte 0 picks the level (bits 0-1) and the counter rule (bit 2); byte 1 the
 * plain-command length for the wrap step; the rest is the response, then the command.
 */
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "se05x_crypto.hpp"
#include "se05x_scp03.hpp"

using namespace se05x;

namespace {

void Check(bool ok) {
  if (!ok) {
    std::abort();
  }
}

bool Known(Error e) {
  return std::strcmp(ToString(e), "Unknown") != 0;
}

struct Answer {
  ByteSpan bytes;
  Result<std::size_t> Transceive(ByteSpan command, MutableByteSpan r) const noexcept {
    static_cast<void>(command);
    const std::size_t n = (bytes.size() < r.size()) ? bytes.size() : r.size();
    static_cast<void>(std::memcpy(r.data(), bytes.data(), n));
    return Result<std::size_t>::Success(n);
  }
};

void FuzzUnwrap(uint8_t mode, ByteSpan response) {
  ReferenceCrypto crypto;
  std::array<uint8_t, 16> key{};
  scp03::detail::SessionKeys keys{};
  for (KeyRef* k : {&keys.enc, &keys.mac, &keys.rmac}) {
    key[0] = static_cast<uint8_t>(key[0] + 1U);
    Check(crypto.ImportKey(KeyKind::Aes128, ByteSpan{key}, *k) == CryptoStatus::Ok);
  }
  const std::array<uint8_t, 4> levels{0x01U, 0x03U, 0x11U, 0x33U};
  const uint8_t level = levels[mode & 3U];
  const auto rule = ((mode & 4U) != 0U) ? scp03::detail::CounterRule::DataCommandsOnly
                                        : scp03::detail::CounterRule::EveryCommand;
  scp03::detail::SecureMessaging<ReferenceCrypto> sm;
  sm.Start(crypto, keys, level, rule, std::array<uint8_t, 16>{});
  std::array<uint8_t, 16U + 1100U> buffer{};
  const std::size_t n = (response.size() > 1100U) ? 1100U : response.size();
  static_cast<void>(std::memcpy(&buffer[16], response.data(), n));
  std::array<uint8_t, 1100> out{};
  const uint32_t before = sm.Counter();
  const auto r = sm.Unwrap(MutableByteSpan{buffer}, n, MutableByteSpan{out});
  Check(Known(r.error));
  if (r.ok()) {
    Check(r.value <= n);
    Check(r.value >= 2U);
    const bool success = (n >= 2U) && (response[n - 2U] == 0x90U) && (response[n - 1U] == 0x00U);
    // With R-MAC on, a 9000 answer only passes with a valid MAC: random bytes never forge one.
    Check((!success) || ((level & 0x10U) == 0U));
  }
  Check(sm.Counter() >= before);
  sm.Stop();
  Check(crypto.KeysInUse() == 0U);
}

void FuzzWrap(ByteSpan command) {
  ReferenceCrypto crypto;
  std::array<uint8_t, 16> key{0x5AU};
  scp03::detail::SessionKeys keys{};
  for (KeyRef* k : {&keys.enc, &keys.mac, &keys.rmac}) {
    Check(crypto.ImportKey(KeyKind::Aes128, ByteSpan{key}, *k) == CryptoStatus::Ok);
  }
  scp03::detail::SecureMessaging<ReferenceCrypto> sm;
  sm.Start(crypto, keys, 0x33U, scp03::detail::CounterRule::EveryCommand,
           std::array<uint8_t, 16>{});
  std::array<uint8_t, 32U + 1100U> buffer{};
  const auto w = sm.Wrap(command, MutableByteSpan{buffer}, 32U, (command.size() % 2U) == 0U);
  Check(Known(w.error));
  const auto parsed = scp03::detail::ParseCommand(command);
  Check(w.ok() == (parsed.ok() && (w.error != Error::BufferTooSmall)));
  if (w.ok()) {
    Check(w.value <= (buffer.size() - 32U));
    Check((buffer[32] & 0x04U) != 0U);
  }
  sm.Stop();
}

void FuzzSession(ByteSpan answer) {
  Answer a{answer};
  session::Id id{};
  const auto r = session::CreateSession(a, ObjectId{1U}, id);
  Check(Known(r.error));
  std::size_t at = 0U;
  const auto tlv = scp03::detail::ReadTlv(answer, at, (answer.empty()) ? 0U : answer[0]);
  Check(Known(tlv.error));
  if (tlv.ok()) {
    Check(at <= answer.size());
    Check(tlv.value.size() <= answer.size());
  }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
  if (size < 2U) {
    return 0;
  }
  const ByteSpan input{data, size};
  const uint8_t mode = data[0];
  const std::size_t split = (static_cast<std::size_t>(data[1]) * (size - 2U)) / 255U;
  const ByteSpan response = input.subspan(2U, size - 2U - split);
  const ByteSpan command = input.subspan(size - split, split);
  FuzzUnwrap(mode, response);
  FuzzWrap(command);
  FuzzSession(response);
  return 0;
}
