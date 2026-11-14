/**
 * @file se05x_perso.ipp
 * @brief PERSO applet implementation, included by `se05x_perso.hpp`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#ifndef SE05X_PERSO_IPP
#define SE05X_PERSO_IPP

namespace se05x::perso {

namespace detail {
/// The status word of the PERSO applet as an error (AN13015 Tables 8 and 11).
constexpr Error PersoSwError(uint16_t sw) noexcept {
  switch (sw) {
  case 0x9000U:
    return Error::Ok;
  case 0x6700U:
    return Error::BufferTooSmall;
  case 0x6A81U:
    return Error::Unsupported;
  case 0x6A82U:
    return Error::ObjectNotFound;
  case 0x66A6U:
    return Error::ThroughputLimited;
  default:
    break;
  }
  return Error::ChipSwUnknown;
}
} // namespace detail

template <PortSet P, ApduTransport T>
Result<Version> Perso<P, T>::Select() noexcept {
  selected_ = false;
  std::array<uint8_t, 22> cmd{0x00U, 0xA4U, 0x04U, 0x00U, static_cast<uint8_t>(kPersoAid.size())};
  for (std::size_t i = 0U; i < kPersoAid.size(); ++i) {
    cmd[5U + i] = kPersoAid[i];
  }
  cmd[21] = 0x00U; // Le
  std::array<uint8_t, 32> rsp{};
  const auto got = lower_->Transceive(ByteSpan{cmd}, MutableByteSpan{rsp});
  if (!got.ok()) {
    return Result<Version>::Failure(got.error, got.detail);
  }
  const ByteSpan answer{rsp.data(), got.value};
  const uint16_t sw = scp03::detail::StatusWord(answer);
  const Error e = detail::PersoSwError(sw);
  const Detail d{sw, 0xFFU, Layer::Gp, 0U, 0xFFU};
  if (e != Error::Ok) {
    return Result<Version>::Failure(e, d);
  }
  if (answer.size() != 9U) {
    return Result<Version>::Failure(Error::FrameError, d);
  }
  const Version v{.major = answer[0],
                  .minor = answer[1],
                  .patch = answer[2],
                  .config_option = (static_cast<uint32_t>(answer[3]) << 24U) |
                                   (static_cast<uint32_t>(answer[4]) << 16U) |
                                   (static_cast<uint32_t>(answer[5]) << 8U) |
                                   static_cast<uint32_t>(answer[6])};
  selected_ = true;
  return Result<Version>::Success(v);
}

template <PortSet P, ApduTransport T>
Result<bool> Perso<P, T>::Probe() noexcept {
  const auto selected = Select();
  if (selected.ok()) {
    return Result<bool>::Success(true);
  }
  if (selected.error == Error::ObjectNotFound) {
    return Result<bool>::Success(false);
  }
  return Result<bool>::Failure(selected.error, selected.detail);
}

template <PortSet P, ApduTransport T>
Result<std::size_t> Perso<P, T>::Read(Tag tag, MutableByteSpan out) noexcept {
  const auto raw = static_cast<uint16_t>(tag);
  if ((!IsKnownTag(raw)) || out.empty()) {
    return Result<std::size_t>::Failure(Error::InvalidArgument);
  }
  if (!selected_) {
    return Result<std::size_t>::Failure(Error::WrongState, Detail{0U, 0xFFU, Layer::Gp, 1U, 0xFFU});
  }
  const std::size_t want = (out.size() > 0xFFU) ? 0xFFU : out.size();
  const std::array<uint8_t, 7> cmd{scp03::kClaGp,
                                   kInsRead,
                                   static_cast<uint8_t>(static_cast<uint32_t>(raw) >> 8U),
                                   static_cast<uint8_t>(static_cast<uint32_t>(raw) & 0xFFU),
                                   0x01U,
                                   static_cast<uint8_t>(want),
                                   0x00U};
  std::array<uint8_t, 264> rsp{};
  const auto got = lower_->Transceive(ByteSpan{cmd}, MutableByteSpan{rsp});
  if (!got.ok()) {
    return Result<std::size_t>::Failure(got.error, got.detail);
  }
  const ByteSpan answer{rsp.data(), got.value};
  const uint16_t sw = scp03::detail::StatusWord(answer);
  const Error e = detail::PersoSwError(sw);
  const Detail d{sw, 0xFFU, Layer::Gp, 1U, 0xFFU};
  if (e != Error::Ok) {
    return Result<std::size_t>::Failure(e, d);
  }
  const ByteSpan body = answer.subspan(0U, answer.size() - 2U);
  std::size_t at = 0U;
  const auto value = scp03::detail::ReadTlv(body, at, session::kTag1);
  if ((!value.ok()) || (at != body.size())) {
    return Result<std::size_t>::Failure(Error::FrameError, d);
  }
  if (value.value.size() > out.size()) {
    return Result<std::size_t>::Failure(Error::BufferTooSmall, d);
  }
  for (std::size_t i = 0U; i < value.value.size(); ++i) {
    out[i] = value.value[i];
  }
  return Result<std::size_t>::Success(value.value.size());
}

template <PortSet P, ApduTransport T>
Result<I2cParams> Perso<P, T>::ReadI2cParams() noexcept {
  std::array<uint8_t, 1> v{};
  const auto got = Read(Tag::I2cParams, MutableByteSpan{v});
  if (!got.ok()) {
    return Result<I2cParams>::Failure(got.error, got.detail);
  }
  if (got.value != 1U) {
    return Result<I2cParams>::Failure(Error::FrameError, got.detail);
  }
  return Result<I2cParams>::Success(I2cParams{v[0]});
}

template <PortSet P, ApduTransport T>
Result<uint8_t> Perso<P, T>::ReadI2cAddress() noexcept {
  std::array<uint8_t, 1> v{};
  const auto got = Read(Tag::I2cSlaveAddress, MutableByteSpan{v});
  if (!got.ok()) {
    return Result<uint8_t>::Failure(got.error, got.detail);
  }
  if ((got.value != 1U) || (v[0] > 0x7FU)) {
    return Result<uint8_t>::Failure(Error::FrameError, got.detail);
  }
  return Result<uint8_t>::Success(v[0]);
}

template <PortSet P, ApduTransport T>
Result<void> Perso<P, T>::Write(
    Tag tag, ByteSpan value,
    irreversible::Confirmation<irreversible::WritePersoSetting> confirmation) noexcept
  requires(kIrreversibleEnabled)
{
  static_cast<void>(value);
  if ((!IsKnownTag(static_cast<uint16_t>(tag))) || (!IsWritable(tag))) {
    return Result<void>::Failure(Error::InvalidArgument);
  }
  if (!confirmation.IsConfirmed()) {
    return Result<void>::Failure(Error::IrreversibleNotConfirmed);
  }
  return Result<void>::Failure(Error::Unsupported, Detail{0U, 0xFFU, Layer::Gp, 2U, 0xFFU});
}

template <PortSet P, ApduTransport T>
Result<void> Perso<P, T>::DeleteModule(
    Module module,
    irreversible::Confirmation<irreversible::DeletePersoModule> confirmation) noexcept
  requires(kIrreversibleEnabled)
{
  if (!se05x::detail::IsEnumerator(module)) {
    return Result<void>::Failure(Error::InvalidArgument);
  }
  if (!confirmation.IsConfirmed()) {
    return Result<void>::Failure(Error::IrreversibleNotConfirmed);
  }
  return Result<void>::Failure(Error::Unsupported, Detail{0U, 0xFFU, Layer::Gp, 3U, 0xFFU});
}

} // namespace se05x::perso

#endif // SE05X_PERSO_IPP
