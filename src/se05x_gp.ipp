/**
 * @file se05x_gp.ipp
 * @brief Card manager implementation, included by `se05x_gp.hpp`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#ifndef SE05X_GP_IPP
#define SE05X_GP_IPP

namespace se05x::gp {

namespace detail {
/// The status word of the card manager as an error.
constexpr Error CmSwError(uint16_t sw) noexcept {
  if (sw == 0x9000U) {
    return Error::Ok;
  }
  return (sw == 0x66A6U) ? Error::ThroughputLimited : Error::ChipSwUnknown;
}
} // namespace detail

template <PortSet P, ApduTransport T>
Result<std::size_t> CardManager<P, T>::getData(ByteSpan command, MutableByteSpan answer) noexcept {
  if (!selected_) {
    return Result<std::size_t>::Failure(Error::WrongState, Detail{0U, 0xFFU, Layer::Gp, 0U, 0xFFU});
  }
  const auto got = lower_->Transceive(command, answer);
  if (!got.ok()) {
    return got;
  }
  const uint16_t sw = scp03::detail::StatusWord(ByteSpan{answer.data(), got.value});
  const Error e = detail::CmSwError(sw);
  if (e != Error::Ok) {
    return Result<std::size_t>::Failure(e, Detail{sw, 0xFFU, Layer::Gp, 1U, 0xFFU});
  }
  return Result<std::size_t>::Success(got.value - 2U);
}

template <PortSet P, ApduTransport T>
Result<void> CardManager<P, T>::SelectCardManager() noexcept {
  selected_ = false;
  const std::array<uint8_t, 14> cmd{0x00U, 0xA4U, 0x04U, 0x00U, 0x08U, 0xA0U, 0x00U,
                                    0x00U, 0x01U, 0x51U, 0x00U, 0x00U, 0x00U, 0x00U};
  std::array<uint8_t, 258> rsp{};
  const auto got = lower_->Transceive(ByteSpan{cmd}, MutableByteSpan{rsp});
  if (!got.ok()) {
    return Result<void>::Failure(got.error, got.detail);
  }
  const uint16_t sw = scp03::detail::StatusWord(ByteSpan{rsp.data(), got.value});
  const Error e = detail::CmSwError(sw);
  if (e != Error::Ok) {
    return Result<void>::Failure(e, Detail{sw, 0xFFU, Layer::Gp, 0U, 0xFFU});
  }
  selected_ = true;
  return Result<void>::Success();
}

template <PortSet P, ApduTransport T>
Result<Cplc> CardManager<P, T>::GetCplc() noexcept {
  const std::array<uint8_t, 5> cmd{scp03::kClaGp, 0xCAU, 0x9FU, 0x7FU, 0x00U};
  std::array<uint8_t, 64> rsp{};
  const auto got = getData(ByteSpan{cmd}, MutableByteSpan{rsp});
  if (!got.ok()) {
    return Result<Cplc>::Failure(got.error, got.detail);
  }
  Cplc cplc{};
  // 9F 7F 2A, then 42 bytes (GP Card Specification, CPLC data).
  if ((got.value != (3U + cplc.bytes.size())) || (rsp[0] != 0x9FU) || (rsp[1] != 0x7FU) ||
      (rsp[2] != static_cast<uint8_t>(cplc.bytes.size()))) {
    return Result<Cplc>::Failure(Error::FrameError, Detail{0x9000U, 0xFFU, Layer::Gp, 2U, 0xFFU});
  }
  for (std::size_t i = 0U; i < cplc.bytes.size(); ++i) {
    cplc.bytes[i] = rsp[3U + i];
  }
  cplc.length = cplc.bytes.size();
  return Result<Cplc>::Success(cplc);
}

template <PortSet P, ApduTransport T>
Result<CardId> CardManager<P, T>::GetCardIdentification() noexcept {
  const std::array<uint8_t, 8> cmd{scp03::kClaGp, 0xCAU, 0x00U, 0xFEU, 0x02U, 0xDFU, 0x28U, 0x00U};
  std::array<uint8_t, 160> rsp{};
  const auto got = getData(ByteSpan{cmd}, MutableByteSpan{rsp});
  if (!got.ok()) {
    return Result<CardId>::Failure(got.error, got.detail);
  }
  const Detail bad{0x9000U, 0xFFU, Layer::Gp, 2U, 0xFFU};
  const ByteSpan body{rsp.data(), got.value};
  std::size_t at = 0U;
  const auto outer = scp03::detail::ReadTlv(body, at, 0xFEU);
  if ((!outer.ok()) || (at != body.size()) || (outer.value.size() < 3U) ||
      (outer.value[0] != 0xDFU)) {
    return Result<CardId>::Failure(Error::FrameError, bad);
  }
  std::size_t inner_at = 1U; // DF 28: read the second tag byte as the TLV tag
  const auto id = scp03::detail::ReadTlv(outer.value, inner_at, 0x28U);
  if ((!id.ok()) || (inner_at != outer.value.size())) {
    return Result<CardId>::Failure(Error::FrameError, bad);
  }
  CardId card{};
  if (id.value.size() > card.raw.bytes.size()) {
    return Result<CardId>::Failure(Error::BufferTooSmall, bad);
  }
  // The first sub-TLV is the configuration id: 01 0C, then 12 bytes whose bytes 2 and 3 are the
  // OEF id (AN12436 p. 2).
  std::size_t cfg_at = 0U;
  const auto cfg = scp03::detail::ReadTlv(id.value, cfg_at, 0x01U);
  if ((!cfg.ok()) || (cfg.value.size() != 12U)) {
    return Result<CardId>::Failure(Error::FrameError, bad);
  }
  card.oef_id = static_cast<uint16_t>((static_cast<uint32_t>(cfg.value[2]) << 8U) |
                                      static_cast<uint32_t>(cfg.value[3]));
  for (std::size_t i = 0U; i < id.value.size(); ++i) {
    card.raw.bytes[i] = id.value[i];
  }
  card.raw.length = id.value.size();
  return Result<CardId>::Success(card);
}

template <PortSet P, ApduTransport T>
Result<KeyInformation> CardManager<P, T>::GetKeyInformation() noexcept {
  const std::array<uint8_t, 5> cmd{scp03::kClaGp, 0xCAU, 0x00U, 0xE0U, 0x00U};
  std::array<uint8_t, 160> rsp{};
  const auto got = getData(ByteSpan{cmd}, MutableByteSpan{rsp});
  if (!got.ok()) {
    return Result<KeyInformation>::Failure(got.error, got.detail);
  }
  const Detail bad{0x9000U, 0xFFU, Layer::Gp, 2U, 0xFFU};
  const ByteSpan body{rsp.data(), got.value};
  std::size_t at = 0U;
  const auto tmpl = scp03::detail::ReadTlv(body, at, 0xE0U);
  if ((!tmpl.ok()) || (at != body.size())) {
    return Result<KeyInformation>::Failure(Error::FrameError, bad);
  }
  KeyInformation info{};
  std::size_t entry_at = 0U;
  while (entry_at < tmpl.value.size()) {
    const auto entry = scp03::detail::ReadTlv(tmpl.value, entry_at, 0xC0U);
    if ((!entry.ok()) || (entry.value.size() != 4U)) {
      return Result<KeyInformation>::Failure(Error::FrameError, bad);
    }
    if (info.count == info.entries.size()) {
      return Result<KeyInformation>::Failure(Error::BufferTooSmall, bad);
    }
    info.entries[info.count] = KeyInfoEntry{.key_id = entry.value[0],
                                            .version = entry.value[1],
                                            .key_type = entry.value[2],
                                            .key_length = entry.value[3]};
    ++info.count;
  }
  return Result<KeyInformation>::Success(info);
}

template <PortSet P, ApduTransport T>
Result<void> CardManager<P, T>::PutKeys(
    const scp03::ChannelParams& current, const NewKeySet& next,
    irreversible::Confirmation<irreversible::ReplacePlatformKeys> confirmation) noexcept
  requires(kIrreversibleEnabled)
{
  static_cast<void>(current);
  static_cast<void>(next);
  if (!confirmation.IsConfirmed()) {
    return Result<void>::Failure(Error::IrreversibleNotConfirmed);
  }
  return Result<void>::Failure(Error::Unsupported, Detail{0U, 0xFFU, Layer::Gp, 0U, 0xFFU});
}

} // namespace se05x::gp

#endif // SE05X_GP_IPP
