/**
 * @file t1_fixture.hpp
 * @brief The test bench of the T=1 link: the model, a simulated clock, reset and log ports, a
 * crypto port that does nothing, and an APDU handler with a known answer.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#ifndef SE05X_TESTS_MODEL_T1_FIXTURE_HPP
#define SE05X_TESTS_MODEL_T1_FIXTURE_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "model/model_if.hpp"
#include "model/t1_target.hpp"
#include "se05x_t1.hpp"

namespace se05x::testmodel {

/** @brief A crypto port the link never calls: it satisfies the concept and fails every call. */
class NoCrypto : public CryptoInterface<NoCrypto> {
public:
  CryptoStatus ImportKey(KeyKind kind, ByteSpan key, KeyRef& out) noexcept {
    static_cast<void>(kind);
    static_cast<void>(key);
    static_cast<void>(out);
    return CryptoStatus::Failed;
  }
  CryptoStatus ReleaseKey(KeyRef key) noexcept {
    static_cast<void>(key);
    return CryptoStatus::Failed;
  }
  CryptoStatus AesCmac(KeyRef key, ByteSpan msg, std::span<uint8_t, 16> mac) noexcept {
    static_cast<void>(key);
    static_cast<void>(msg);
    static_cast<void>(mac);
    return CryptoStatus::Failed;
  }
  CryptoStatus AesCbc(KeyRef key, bool encrypt, std::span<uint8_t, 16> iv,
                      MutableByteSpan data) noexcept {
    static_cast<void>(key);
    static_cast<void>(encrypt);
    static_cast<void>(iv);
    static_cast<void>(data);
    return CryptoStatus::Failed;
  }
  CryptoStatus GenerateP256(KeyRef& key, std::span<uint8_t, 65> pub) noexcept {
    static_cast<void>(key);
    static_cast<void>(pub);
    return CryptoStatus::Failed;
  }
  CryptoStatus EcdhP256(KeyRef key, std::span<const uint8_t, 65> peer,
                        std::span<uint8_t, 32> secret) noexcept {
    static_cast<void>(key);
    static_cast<void>(peer);
    static_cast<void>(secret);
    return CryptoStatus::Failed;
  }
  CryptoStatus EcdsaP256Sign(KeyRef key, std::span<const uint8_t, 32> digest,
                             std::span<uint8_t, 64> sig) noexcept {
    static_cast<void>(key);
    static_cast<void>(digest);
    static_cast<void>(sig);
    return CryptoStatus::Failed;
  }
  CryptoStatus EcdsaP256Verify(std::span<const uint8_t, 65> pub,
                               std::span<const uint8_t, 32> digest,
                               std::span<const uint8_t, 64> sig) noexcept {
    static_cast<void>(pub);
    static_cast<void>(digest);
    static_cast<void>(sig);
    return CryptoStatus::Failed;
  }
  CryptoStatus Hash(HashAlg alg, ByteSpan msg, MutableByteSpan out) noexcept {
    static_cast<void>(alg);
    static_cast<void>(msg);
    static_cast<void>(out);
    return CryptoStatus::Failed;
  }
  CryptoStatus Random(MutableByteSpan out) noexcept {
    static_cast<void>(out);
    return CryptoStatus::Failed;
  }
};

/** @brief Answers every APDU with `answer_len` pattern bytes and SW 9000; records the command. */
class PatternHandler : public ApduHandler {
public:
  std::size_t Handle(ByteSpan command, MutableByteSpan response) override {
    ++commands;
    last_len = command.size();
    for (std::size_t i = 0U; (i < command.size()) && (i < last.size()); ++i) {
      last[i] = command[i];
    }
    if (drop) {
      return 0U;
    }
    if (only_len != 0U) {
      for (std::size_t i = 0U; i < only_len; ++i) {
        response[i] = Byte(i);
      }
      return only_len;
    }
    for (std::size_t i = 0U; i < answer_len; ++i) {
      response[i] = Byte(i);
    }
    response[answer_len] = 0x90U;
    response[answer_len + 1U] = 0x00U;
    return answer_len + 2U;
  }
  void PowerCycle() override {
    ++power_cycles;
  }
  /** @return Byte `i` of the answer. */
  static uint8_t Byte(std::size_t i) noexcept {
    return static_cast<uint8_t>(((i * 7U) + 3U) & 0xFFU);
  }
  std::size_t answer_len{4};
  bool drop{false};
  std::size_t only_len{0}; ///< When set: that many bytes and no status word.
  uint32_t commands{0};
  uint32_t power_cycles{0};
  std::size_t last_len{0};
  std::array<uint8_t, 1200> last{};
};

using FullPorts = Ports<T1Target, SimClock, NoCrypto, SimReset, SimLog>;
using PlainPorts = Ports<T1Target, SimClock, NoCrypto>;

/** @brief A model, its ports and a link, with a reset and a log port. */
struct Bench {
  explicit Bench(const T1Knobs& knobs, const Config& config = Config{}) noexcept
      : chip(clock, &handler, knobs), reset(chip), ports(chip, clock, crypto, reset, log),
        link(ports, config) {}
  SimClock clock;
  PatternHandler handler;
  T1Target chip;
  NoCrypto crypto;
  SimReset reset;
  SimLog log;
  FullPorts ports;
  t1::Link<FullPorts> link;
};

/** @brief A model, its ports and a link, without a reset or log port. */
struct PlainBench {
  explicit PlainBench(const T1Knobs& knobs, const Config& config = Config{}) noexcept
      : chip(clock, &handler, knobs), ports(chip, clock, crypto), link(ports, config) {}
  SimClock clock;
  PatternHandler handler;
  T1Target chip;
  NoCrypto crypto;
  PlainPorts ports;
  t1::Link<PlainPorts> link;
};

/** @return Knobs of the NXP flavour (default) or the GP flavour. */
inline T1Knobs Knobs(bool gp = false) noexcept {
  T1Knobs k{};
  k.base.gp_flavour = gp;
  return k;
}

/** @return A configuration with an explicit flavour. */
inline Config WithFlavour(TransportFlavour flavour) noexcept {
  Config c{};
  c.flavour = flavour;
  return c;
}

/** @brief Lose the next `n` frames the chip sends (at most eight). */
inline void DropFromNow(T1Target& chip, uint32_t n = 8U) noexcept {
  for (uint32_t i = 0U; (i < n) && (i < 8U); ++i) {
    chip.SetFault(i, chip.frames_out + i, Fault::Drop);
  }
}

/** @brief A chip that answers nothing more: frames lost, RESYNC and soft reset silent. */
inline void Silence(T1Target& chip) noexcept {
  chip.Knobs().silent_resync = true;
  chip.Knobs().silent_soft_reset = true;
  DropFromNow(chip);
}

/** @return A configuration with room for every retry (20 s fast class). */
inline Config Patient(TransportFlavour flavour = TransportFlavour::Auto) noexcept {
  Config c{};
  c.flavour = flavour;
  c.timeouts.fast_ms = 20000U;
  return c;
}

/** @return Whether `response[0..n)` is the pattern answer of `len` bytes and SW 9000. */
inline bool IsPatternAnswer(ByteSpan response, std::size_t n, std::size_t len) noexcept {
  if (n != (len + 2U)) {
    return false;
  }
  for (std::size_t i = 0U; i < len; ++i) {
    if (response[i] != PatternHandler::Byte(i)) {
      return false;
    }
  }
  return (response[len] == 0x90U) && (response[len + 1U] == 0x00U);
}

/** @brief A short command APDU (GET DATA style). */
inline constexpr std::array<uint8_t, 5> kShortApdu{0x80U, 0xCAU, 0x00U, 0xFEU, 0x00U};

} // namespace se05x::testmodel

#endif // SE05X_TESTS_MODEL_T1_FIXTURE_HPP
