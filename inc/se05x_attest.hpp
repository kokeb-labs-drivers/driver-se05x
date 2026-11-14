/**
 * @file se05x_attest.hpp
 * @brief Attestation verification, one verifier type per format.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Frozen surface; the helpers are in `se05x::attest::detail`. The two
 * formats are different types, so a format-1 rule cannot be applied to a format-2 answer (S-09):
 *
 * - `AttestationFormat::V1` (applet 3.x, AN12413 3.2.7.2 and Table 106): the answer carries data,
 * attributes, a 12-byte timestamp, the freshness echo, the 18-byte unique id and a signature over
 * the concatenated values (data, attributes, timestamp, freshness, unique id; the I2C controller
 * answer has no attributes); the echo must equal the 16-byte nonce the host sent.
 * - `AttestationFormat::V2` (applet 7.x, AN12543 3.2.7.2, Figure 4 and Tables 128, 131, 313): there
 * is no freshness echo. The signature covers `H(command) || TLV(0x41, data) || TLV(0x42, chip id)
 * || TLV(0x43, attributes) || TLV(0x44, size) || TLV(0x4F, timestamp)`, where the command is the
 * plain C-APDU as sent without its Le, `H` the digest of the attestation algorithm, and each TLV
 * as the applet returned it; an absent data or attribute TLV is left out. The nonce is bound by
 * the hashed command. The chip does not return the command (the earlier reading that it does came
 * from the middleware guide); `AttestedRead::echoed_command`, when a lower layer fills it, must
 * equal the command sent, byte for byte.
 *
 * The verifier re-encodes the TLVs of a format-2 answer with the three-byte length form `82 xx xx`:
 * the form the applet uses in attested answers, and the one the middleware's verification rebuilds
 * (AN12543 4.1.3.2 allows it for any length). A chip that answers with another form fails the
 * signature check; nothing is accepted that was not signed.
 *
 * The port verifies ECDSA with P-256 keys only, so the algorithms are the ECDSA ones: the digest
 * is the leftmost 32 bytes of the hash, or the hash padded on the left (FIPS 186-4 6.4). RSA,
 * Ed25519 and `EcPlain` are `Unsupported`.
 *
 * In both formats the 12-byte timestamp (4 bytes persistent, incremented at every session open; 8
 * bytes transient, strongly monotonic; AN12543 3.9) must not go backwards across attested reads
 * from one chip within one boot. The byte order is taken as the most significant byte first
 * (AN12543 3.9 names the "most significant 4 bytes" persistent; not stated otherwise). The nonce
 * is a fresh 16 bytes of the host's crypto port per request (`Device::ReadAttested`), never the
 * attested chip's own RNG.
 */
#ifndef SE05X_ATTEST_HPP
#define SE05X_ATTEST_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "se05x_apdu_consts.hpp"
#include "se05x_device_types.hpp"
#include "se05x_ports.hpp"
#include "se05x_status.hpp"
#include "se05x_types.hpp"

namespace se05x::attest {

/**
 * @defgroup se05x_attest Attestation
 * @brief Per-format verifier types and the timestamp order check.
 * @{
 */

/** @brief Longest command a format 2 answer echoes. */
inline constexpr std::size_t kMaxEchoedCommand = 100U;

/**
 * @brief The format an applet generation answers with.
 * @param generation The applet generation.
 * @return `V2` for 7.x, `V1` otherwise (6.x is taken as `V1` until a source is found).
 */
constexpr AttestationFormat FormatOf(AppletGeneration generation) noexcept {
  return (generation == AppletGeneration::V7) ? AttestationFormat::V2 : AttestationFormat::V1;
}

/**
 * @brief Whether timestamp `now` is not older than `last` (lexicographic over the 12 bytes).
 * @param now The timestamp of the new answer.
 * @param last The timestamp of the previous verified answer from this chip.
 * @return true when `now >= last`.
 */
constexpr bool TimestampNotBefore(const Timestamp& now, const Timestamp& last) noexcept {
  for (std::size_t i = 0U; i < kTimestampLength; ++i) {
    if (now[i] != last[i]) {
      return now[i] > last[i];
    }
  }
  return true;
}

/**
 * @brief Whether timestamp `now` is strictly later than `last`: the transient part is strongly
 * monotonic (AN12543 3.9 p. 42), so two verified answers never carry the same timestamp; an equal
 * one is a replay. A `last` of all zero (no answer verified yet) accepts any timestamp.
 * @param now The timestamp of the new answer.
 * @param last The timestamp of the previous verified answer from this chip, or all zero.
 * @return true when `now > last`, or `last` is all zero.
 */
constexpr bool TimestampAfter(const Timestamp& now, const Timestamp& last) noexcept {
  bool first = true;
  for (std::size_t i = 0U; i < kTimestampLength; ++i) {
    first = first && (last[i] == 0U);
  }
  return first || (TimestampNotBefore(now, last) && (now != last));
}

/** @brief What the host sent in an attested read (needed to check the answer). */
struct Sent {
  std::array<uint8_t, kFreshnessLength> nonce{}; ///< The nonce the host drew from its crypto port.
  ByteSpan command;                              ///< The complete command APDU the host sent.
  /// Format 2: the TLVs of the answer before the signature, byte for byte as the chip returned
  /// them. When given, the signed message is H(command) followed by these bytes (AN12543 Table
  /// 128 p. 91); when empty, the verifier rebuilds them with the `82 xx xx` length form (A21).
  ByteSpan signed_tlvs;
  AttestationAlgo algo{AttestationAlgo::EcSha256}; ///< The algorithm requested.
};

/** @brief What a verified answer contains. */
struct Checked {
  std::size_t data_length{0};                       ///< Valid bytes of the data buffer.
  Timestamp timestamp{};                            ///< The verified timestamp.
  std::array<uint8_t, kUniqueIdLength> unique_id{}; ///< The chip that signed.
  uint32_t object_size{0};                          ///< Format 2: the signed object size.
};

/**
 * @brief The verifier of format `F`.
 *
 * @tparam P A `Ports<...>` set; its crypto port performs the hash and the signature check.
 * @tparam F The attestation format.
 */
template <PortSet P, AttestationFormat F>
class Verifier {
public:
  /**
   * @brief Bind the verifier. No I/O.
   * @param ports The port set; it must outlive the verifier.
   */
  explicit Verifier(const P& ports) noexcept : ports_(&ports) {}

  /**
   * @brief Check an answer.
   *
   * @param sent What the host sent.
   * @param answer The reply the device returned (format `F` only: `answer.format` must equal `F`).
   * @param data The data the chip returned.
   * @param signature The signature.
   * @param attestation_key The chip's attestation public key, uncompressed (a P-256 point).
   * @param last The timestamp of the previous verified answer, or all zero for the first.
   * @return The checked fields, or `AttestationInvalid` (freshness, echoed command, timestamp
   * order, malformed or wrong signature), `InvalidArgument` (wrong format, sizes that do not match
   * the answer, a command that is not an APDU, a key that is not an uncompressed point),
   * `Unsupported` (an algorithm the port cannot verify), `CryptoFailure` (the port failed).
   */
  Result<Checked> Verify(const Sent& sent, const AttestedRead& answer, ByteSpan data,
                         ByteSpan signature, std::span<const uint8_t, 65> attestation_key,
                         const Timestamp& last) noexcept;

private:
  const P* ports_;
};

/** @} */

} // namespace se05x::attest

// codeql::misra_deviation_next_line(MD-CPP-009)
#include "../src/se05x_attest.ipp" // IWYU pragma: export

#endif // SE05X_ATTEST_HPP
