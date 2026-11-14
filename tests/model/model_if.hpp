/**
 * @file model_if.hpp
 * @brief The shared interface of the test model chain: T1Target -> ScpTarget -> ChipModel (frozen).
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Each stage of the chain implements `ApduHandler` and may hold the next stage. The chip model
 * decodes TLV and policies with its own code, written independently of the library
 * (hardware-lessons rule on independent models). No library type crosses this interface except
 * `ByteSpan`.
 */
#ifndef SE05X_TESTS_MODEL_IF_HPP
#define SE05X_TESTS_MODEL_IF_HPP

#include <cstddef>
#include <cstdint>

#include "se05x_types.hpp"

namespace se05x::testmodel {

/**
 * @brief Knobs of the model for the points that stay open until UM11225 is sourced (design
 * ambiguities A9, A10): the T=1 stage and the chip model take them; a test sets each to both
 * values.
 */
struct ModelKnobs {
  bool crc_swapped{
      false}; ///< CRC16 bytes in the opposite order (A10): the link must reject the other order.
  bool gp_flavour{false}; ///< The chip speaks the GP flavour instead of UM11225 (A9).
  bool throttle_enabled{
      false}; ///< The chip answers SW 0x66A6 after `throttle_after` commands until reset (S-17).
  uint32_t throttle_after{0}; ///< The number of commands before the limiter trips.
};

/** @brief One stage that turns a command APDU into a response APDU. */
class ApduHandler {
public:
  ApduHandler() = default;
  ApduHandler(const ApduHandler&) = delete;
  ApduHandler& operator=(const ApduHandler&) = delete;
  virtual ~ApduHandler() = default;

  /**
   * @brief Handle one command.
   * @param command The command APDU.
   * @param response The buffer for the response APDU.
   * @return The response length, or 0 when the model drops the command (a timeout).
   */
  virtual std::size_t Handle(se05x::ByteSpan command, se05x::MutableByteSpan response) = 0;

  /** @brief Reset the stage as a power cycle would. */
  virtual void PowerCycle() = 0;
};

} // namespace se05x::testmodel

#endif // SE05X_TESTS_MODEL_IF_HPP
