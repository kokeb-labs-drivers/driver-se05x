/**
 * @file se05x_codec.hpp
 * @brief The interface between the command layer and the APDU layer: `Codec<Command>`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Frozen contract, with one amendment (the three-argument `Decode`). For each
 * `Command C` the APDU layer specialises `Codec<C>` with:
 *
 * - `Encode(args, out)` writes the command APDU (header, TLVs, Lc and Le, no secure messaging) into
 *   `out` and returns its length, or `InvalidArgument` / `Unsupported` (an argument the
 *   specification refuses; every byte written is zeroed) / `BufferTooSmall`;
 * - `Decode(args, data, reply)` parses the response body (the bytes before the status word) into
 *   `reply` and copies the output of the command into the caller buffers named in `args`
 *   (`args.out`, `args.signature`, ...). It never truncates: a buffer that is too short is
 *   `BufferTooSmall`. This is the form `Device` calls for every command;
 * - `Decode(data, reply)`, the original form, for the commands that write no caller
 *   buffer (`kWritesCallerBuffers == false`); for the others it returns `InvalidArgument`, because
 *   the reply holds only lengths and the output would be lost.
 *
 * The status word is not the codec's: `Device` maps it with `apdu::StatusToError()` in the context
 * of the command, then calls `Decode` only for 0x9000. The primary template below is the stub:
 * every function returns `NotImplemented`. The APDU package writes each command's codec group by
 * group in `se05x_apdu_*.hpp` as a struct in `se05x::codecs` and selects it with an overload
 * `codecs::CodecFor(codecs::CommandTag<C>)`; the constrained `Codec<C>` below then derives from
 * it. All specialisations of `Codec` stay in this file (MISRA C++:2023 Rule 6.2.3). A command with
 * no overload keeps the stub, which is how the integration check finds a command nobody wrote.
 */
#ifndef SE05X_CODEC_HPP
#define SE05X_CODEC_HPP

#include <cstddef>

#include "se05x_commands.hpp"
#include "se05x_device_types.hpp"
#include "se05x_status.hpp"
#include "se05x_types.hpp"

namespace se05x {

/**
 * @defgroup se05x_codec Codec interface
 * @brief The encode and decode functions of each command.
 * @{
 */

namespace codecs {

/**
 * @brief The tag that names command `C` to the overloads of `CodecFor`, one per implemented
 * command, in the group headers.
 * @tparam C The command.
 */
template <Command C>
struct CommandTag {};

} // namespace codecs

namespace detail {

/**
 * @brief Whether the APDU layer declares a codec for `C`: an overload `CodecFor(CommandTag<C>)`,
 * found in `se05x::codecs` by argument-dependent lookup.
 * @tparam C The command.
 */
template <Command C>
concept HasCodec = requires { CodecFor(codecs::CommandTag<C>{}); };

} // namespace detail

/**
 * @brief Encoder and decoder of command `C`; this is the stub, for a command with no codec.
 * @tparam C The command.
 */
template <Command C>
struct Codec {
  /// True once a specialisation replaces the stub.
  static constexpr bool kImplemented = false;
  /// True when `Decode` writes into caller buffers named by the arguments.
  static constexpr bool kWritesCallerBuffers = false;

  /**
   * @brief Encode the command APDU.
   * @param args The arguments.
   * @param out The buffer for the APDU, at most `kMaxPlainCommandApdu` bytes are written.
   * @return The APDU length, or an error; the stub returns `NotImplemented`.
   */
  static constexpr Result<std::size_t> Encode(const ArgsOf<C>& args, MutableByteSpan out) noexcept {
    static_cast<void>(args);
    static_cast<void>(out);
    return NotImplemented<std::size_t>(Layer::Apdu);
  }

  /**
   * @brief Decode the response body of status 0x9000.
   * @param data The response bytes before the status word.
   * @param reply The reply to fill; it also holds the lengths written to caller buffers.
   * @return `Ok` or an error; the stub returns `NotImplemented`.
   */
  static constexpr Result<void> Decode(ByteSpan data, ReplyOf<C>& reply) noexcept {
    static_cast<void>(data);
    static_cast<void>(reply);
    return NotImplemented<void>(Layer::Apdu);
  }

  /**
   * @brief Decode the response body of status 0x9000 into the reply and the caller buffers.
   * @param args The arguments the command was encoded from (their output spans receive data).
   * @param data The response bytes before the status word.
   * @param reply The reply to fill.
   * @return `Ok` or an error; the stub returns `NotImplemented`.
   */
  static constexpr Result<void> Decode(const ArgsOf<C>& args, ByteSpan data,
                                       ReplyOf<C>& reply) noexcept {
    static_cast<void>(args);
    static_cast<void>(data);
    static_cast<void>(reply);
    return NotImplemented<void>(Layer::Apdu);
  }
};

/**
 * @brief Encoder and decoder of command `C`: the codec the group header selects with
 * `codecs::CodecFor(codecs::CommandTag<C>)`.
 * @tparam C The command.
 */
template <Command C>
  requires detail::HasCodec<C>
struct Codec<C> : decltype(CodecFor(codecs::CommandTag<C>{})){};

/** @} */

} // namespace se05x

#endif // SE05X_CODEC_HPP
