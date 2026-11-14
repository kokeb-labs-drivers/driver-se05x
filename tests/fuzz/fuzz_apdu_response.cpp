/**
 * @file fuzz_apdu_response.cpp
 * @brief Fuzz target of the response side of the APDU layer: the TLV reader, the status word split
 * and map, and the reply decoders of the commands that write into caller buffers.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * Invariants (abort on violation): every TLV value lies inside the input and the reader consumes
 * at most the input, a refused element is not consumed, so reading again gives the same refusal;
 * a split keeps all but the last two bytes; only 9000 maps to `Ok`; a decoder never reports more
 * bytes than the caller's buffer holds, never writes past it, and a decoder that refuses leaves no
 * byte of the reply in the buffer; decoding twice gives the same result.
 */
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "se05x_apdu.hpp"
#include "se05x_codec.hpp"

namespace {

using namespace se05x;

void Require(bool ok) {
  if (!ok) {
    std::abort();
  }
}

bool Defined(Error e) {
  return std::strcmp(ToString(e), "Unknown") != 0;
}

bool Inside(ByteSpan part, ByteSpan whole) {
  if (part.empty()) {
    return true;
  }
  const auto* begin = whole.data();
  const auto* end = whole.data() + whole.size();
  return (part.data() >= begin) && ((part.data() + part.size()) <= end);
}

void CheckReader(ByteSpan input) {
  apdu::TlvReader reader(input);
  std::size_t consumed = 0U;
  for (std::size_t i = 0U; i <= input.size(); ++i) {
    const Result<apdu::Tlv> tlv = reader.Next();
    if (!tlv.ok()) {
      Require(tlv.error == Error::FrameError);
      Require(reader.Next().error == Error::FrameError); // not consumed: the same refusal
      return;
    }
    Require(Inside(tlv.value.value, input));
    consumed += 2U + tlv.value.value.size();
    Require(consumed <= input.size());
  }
  Require(reader.AtEnd());
}

void CheckStatus(ByteSpan input) {
  const Result<apdu::ResponseView> split = apdu::SplitResponse(input);
  if (input.size() < 2U) {
    Require(split.error == Error::FrameError);
    return;
  }
  Require(split.ok() && (split.value.body.size() == (input.size() - 2U)));
  const auto which = static_cast<uint8_t>(input[0] % kCommandCount);
  const Error e = apdu::StatusToError(static_cast<Command>(which), split.value.sw);
  Require(Defined(e));
  Require((e == Error::Ok) == (split.value.sw == 0x9000U));
}

template <std::size_t N>
bool AllZero(const std::array<uint8_t, N>& a) {
  return std::ranges::all_of(a, [](uint8_t b) { return b == 0U; });
}

/// One decoder into a buffer of `N` bytes plus a guard band the decoder must not touch.
template <Command C, std::size_t N, typename MakeArgs>
void CheckDecoder(ByteSpan input, MakeArgs make) {
  std::array<uint8_t, N + 8U> storage{};
  const MutableByteSpan out = MutableByteSpan{storage}.first(N);
  ReplyOf<C> reply{};
  const ArgsOf<C> args = make(out);
  const Result<void> r = Codec<C>::Decode(args, input, reply);
  Require(Defined(r.error));
  for (std::size_t i = N; i < storage.size(); ++i) {
    Require(storage[i] == 0U);
  }
  if (r.ok()) {
    Require(reply.length <= N);
  } else {
    Require(AllZero(storage));
  }
  ReplyOf<C> again{};
  std::array<uint8_t, N + 8U> second{};
  const ArgsOf<C> args2 = make(MutableByteSpan{second}.first(N));
  Require(Codec<C>::Decode(args2, input, again).error == r.error);
  Require(std::memcmp(storage.data(), second.data(), storage.size()) == 0);
}

void CheckDecoders(ByteSpan input) {
  CheckDecoder<Command::GetRandom, 32U>(input, [](MutableByteSpan o) { return GetRandomArgs{o}; });
  CheckDecoder<Command::ReadObject, 64U>(input, [](MutableByteSpan o) {
    ReadObjectArgs a{};
    a.id = ObjectId{0x00000100U};
    a.out = o;
    return a;
  });
  CheckDecoder<Command::EcdsaSign, 72U>(input, [](MutableByteSpan o) {
    SignArgs a{};
    a.key = ObjectId{0x00000100U};
    a.signature = o;
    return a;
  });
  CheckDecoder<Command::EddsaSign, 64U>(input, [](MutableByteSpan o) {
    SignArgs a{};
    a.key = ObjectId{0x00000100U};
    a.algo = EcSignAlgo::Ed25519Pure;
    a.signature = o;
    return a;
  });
  CheckDecoder<Command::EcdhGenerateSharedSecret, 32U>(input, [](MutableByteSpan o) {
    EcdhArgs a{};
    a.key = ObjectId{0x00000100U};
    a.secret = o;
    return a;
  });
}

void CheckFixedReplies(ByteSpan input) {
  AppletInfo info{};
  Require(Defined(Codec<Command::GetVersion>::Decode(input, info).error));
  ObjectAttributes attrs{};
  Require(Defined(Codec<Command::ReadObjectAttributes>::Decode(input, attrs).error));
  TypeReply type{};
  Require(Defined(Codec<Command::ReadType>::Decode(input, type).error));
  U32Reply memory{};
  Require(Defined(Codec<Command::GetFreeMemory>::Decode(input, memory).error));
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
  const ByteSpan input{data, size};
  CheckReader(input);
  CheckStatus(input);
  CheckDecoders(input);
  CheckFixedReplies(input);
  return 0;
}
