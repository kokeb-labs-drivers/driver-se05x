/**
 * @file se05x_scp03.ipp
 * @brief SCP03 channel, secure-messaging engine, applet session framing and UserID session,
 * included by `se05x_scp03.hpp`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Wrapped command layout (GP Amendment D 6.2.4 to 6.2.7): `CLA|04 INS P1 P2 Lc' data' C-MAC [Le]`.
 * `data'` is the data field, padded (ISO 9797-1 method 2: 0x80 then zeros to a multiple of 16,
 * always at least one byte) and AES-CBC encrypted when C-DECRYPTION is on and there is data. When
 * the plain command carries Le, the wrapped one uses the extended length form (Lc' in three bytes,
 * Le `00 00`), so a response with the R-MAC and padding still fits; this is how the middleware
 * sends it. Inside an applet session the wrapped command is carried in `ProcessSessionCmd` without
 * Le, again as the middleware does (AN12543 Table 73 names header and payload only).
 */
#ifndef SE05X_SCP03_IPP
#define SE05X_SCP03_IPP

namespace se05x::scp03::detail {

/// Big-endian 16-bit read.
constexpr uint32_t Be16(ByteSpan b, std::size_t at) noexcept {
  return (static_cast<uint32_t>(b[at]) << 8U) | static_cast<uint32_t>(b[at + 1U]);
}

constexpr Result<CommandParts> ParseCommand(ByteSpan apdu) noexcept {
  CommandParts parts{};
  const std::size_t n = apdu.size();
  if (n < 4U) {
    return Result<CommandParts>::Failure(Error::InvalidArgument);
  }
  parts.header = {apdu[0], apdu[1], apdu[2], apdu[3]};
  if (n == 4U) {
    return Result<CommandParts>::Success(parts);
  }
  const uint32_t b4 = static_cast<uint32_t>(apdu[4]);
  if (n == 5U) {
    parts.has_le = true;
    parts.le = b4;
    return Result<CommandParts>::Success(parts);
  }
  if (b4 != 0U) {
    const std::size_t lc = b4;
    parts.data = apdu.subspan(5U, (n >= (5U + lc)) ? lc : 0U);
    if (n == (5U + lc)) {
      return Result<CommandParts>::Success(parts);
    }
    if (n == (6U + lc)) {
      parts.has_le = true;
      parts.le = static_cast<uint32_t>(apdu[n - 1U]);
      return Result<CommandParts>::Success(parts);
    }
    return Result<CommandParts>::Failure(Error::InvalidArgument);
  }
  parts.extended = true;
  if (n < 7U) {
    return Result<CommandParts>::Failure(Error::InvalidArgument);
  }
  if (n == 7U) {
    parts.has_le = true;
    parts.le = Be16(apdu, 5U);
    return Result<CommandParts>::Success(parts);
  }
  const std::size_t lc = Be16(apdu, 5U);
  if (lc == 0U) {
    return Result<CommandParts>::Failure(Error::InvalidArgument);
  }
  if (n == (7U + lc)) {
    parts.data = apdu.subspan(7U, lc);
    return Result<CommandParts>::Success(parts);
  }
  if (n == (9U + lc)) {
    parts.data = apdu.subspan(7U, lc);
    parts.has_le = true;
    parts.le = Be16(apdu, n - 2U);
    return Result<CommandParts>::Success(parts);
  }
  return Result<CommandParts>::Failure(Error::InvalidArgument);
}

template <CryptoPort K>
Error Kdf(K& crypto, KeyRef key, uint8_t constant, ByteSpan context, MutableByteSpan out) noexcept {
  const std::size_t bytes = out.size();
  if ((context.size() > 16U) || (bytes == 0U) || (bytes > 32U) || ((bytes % 8U) != 0U)) {
    return Error::InvalidArgument;
  }
  const uint32_t bits = static_cast<uint32_t>(bytes) * 8U;
  std::array<uint8_t, 32> dd{};
  dd[11] = constant;
  dd[12] = 0x00U; // separation indicator
  dd[13] = static_cast<uint8_t>(bits >> 8U);
  dd[14] = static_cast<uint8_t>(bits & 0xFFU);
  for (std::size_t i = 0U; i < context.size(); ++i) {
    dd[16U + i] = context[i];
  }
  std::size_t done = 0U;
  for (uint32_t counter = 1U; done < bytes; ++counter) {
    dd[15] = static_cast<uint8_t>(counter);
    std::array<uint8_t, 16> block{};
    if (crypto.AesCmac(key, ByteSpan{dd.data(), 16U + context.size()},
                       std::span<uint8_t, 16>{block}) != CryptoStatus::Ok) {
      Zeroize(out);
      return Error::CryptoFailure;
    }
    for (std::size_t i = 0U; (i < 16U) && (done < bytes); ++i) {
      out[done] = block[i];
      ++done;
    }
    Zeroize(MutableByteSpan{block});
  }
  return Error::Ok;
}

template <CryptoPort K>
SecureMessaging<K>::~SecureMessaging() noexcept {
  Zeroize(MutableByteSpan{mcv_});
}

template <CryptoPort K>
void SecureMessaging<K>::Start(K& crypto, const SessionKeys& keys, uint8_t level, CounterRule rule,
                               const std::array<uint8_t, kMcvBytes>& mcv) noexcept {
  Stop();
  crypto_ = &crypto;
  keys_ = keys;
  level_ = level;
  rule_ = rule;
  mcv_ = mcv;
  counter_ = 1U;
  last_had_data_ = false;
  active_ = true;
}

template <CryptoPort K>
void SecureMessaging<K>::Stop() noexcept {
  expect_end_ = false;
  if (crypto_ != nullptr) {
    const std::array<KeyRef, 3> keys{keys_.enc, keys_.mac, keys_.rmac};
    for (const KeyRef key : keys) {
      if (key.IsValid()) {
        static_cast<void>(crypto_->ReleaseKey(key));
      }
    }
  }
  keys_ = SessionKeys{};
  Zeroize(MutableByteSpan{mcv_});
  counter_ = 0U;
  level_ = 0U;
  last_had_data_ = false;
  active_ = false;
}

template <CryptoPort K>
Error SecureMessaging<K>::counterIcv(bool response, std::span<uint8_t, 16> icv) noexcept {
  uint32_t value = counter_;
  if (response && (rule_ == CounterRule::DataCommandsOnly) && (!last_had_data_)) {
    value = counter_ - 1U; // JOS.2: the chip did not advance for a command without data
  }
  std::fill(icv.begin(), icv.end(), uint8_t{0U});
  icv[12] = static_cast<uint8_t>(value >> 24U);
  icv[13] = static_cast<uint8_t>((value >> 16U) & 0xFFU);
  icv[14] = static_cast<uint8_t>((value >> 8U) & 0xFFU);
  icv[15] = static_cast<uint8_t>(value & 0xFFU);
  if (response) {
    icv[0] = 0x80U;
  }
  std::array<uint8_t, 16> zero{};
  if (crypto_->AesCbc(keys_.enc, true, std::span<uint8_t, 16>{zero}, MutableByteSpan{icv}) !=
      CryptoStatus::Ok) {
    return Error::CryptoFailure;
  }
  return Error::Ok;
}

template <CryptoPort K>
Result<std::size_t> SecureMessaging<K>::encryptData(const CommandParts& parts,
                                                    MutableByteSpan field) noexcept {
  const std::size_t n = parts.data.size();
  for (std::size_t i = 0U; i < n; ++i) {
    field[i] = parts.data[i];
  }
  const bool encrypt = ((static_cast<uint32_t>(level_) & kLevelCDecrypt) != 0U) && (n != 0U);
  if (!encrypt) {
    return Result<std::size_t>::Success(n);
  }
  const std::size_t padded = ((n / 16U) + 1U) * 16U;
  field[n] = 0x80U;
  for (std::size_t i = n + 1U; i < padded; ++i) {
    field[i] = 0x00U;
  }
  std::array<uint8_t, 16> icv{};
  if ((counterIcv(false, std::span<uint8_t, 16>{icv}) != Error::Ok) ||
      (crypto_->AesCbc(keys_.enc, true, std::span<uint8_t, 16>{icv}, field.subspan(0U, padded)) !=
       CryptoStatus::Ok)) {
    Zeroize(field.subspan(0U, padded));
    return Result<std::size_t>::Failure(Error::CryptoFailure);
  }
  return Result<std::size_t>::Success(padded);
}

template <CryptoPort K>
void SecureMessaging<K>::writeHeader(const CommandParts& parts, std::size_t lc, bool extended,
                                     MutableByteSpan out) noexcept {
  out[0] = static_cast<uint8_t>(static_cast<uint32_t>(parts.header[0]) | kClaSecureMessaging);
  out[1] = parts.header[1];
  out[2] = parts.header[2];
  out[3] = parts.header[3];
  if (extended) {
    out[4] = 0x00U;
    out[5] = static_cast<uint8_t>(lc >> 8U);
    out[6] = static_cast<uint8_t>(lc & 0xFFU);
  } else {
    out[4] = static_cast<uint8_t>(lc);
  }
}

template <CryptoPort K>
Error SecureMessaging<K>::appendMac(MutableByteSpan buffer, std::size_t offset,
                                    std::size_t mac_at) noexcept {
  // C-MAC = CMAC(S-MAC, MCV || header || Lc || data); the full CMAC is the next MCV.
  for (std::size_t i = 0U; i < kMcvBytes; ++i) {
    buffer[(offset - kMcvBytes) + i] = mcv_[i];
  }
  std::array<uint8_t, 16> mac{};
  if (crypto_->AesCmac(keys_.mac, ByteSpan{buffer.subspan(offset - kMcvBytes, kMcvBytes + mac_at)},
                       std::span<uint8_t, 16>{mac}) != CryptoStatus::Ok) {
    return Error::CryptoFailure;
  }
  mcv_ = mac;
  for (std::size_t i = 0U; i < kMacBytes; ++i) {
    buffer[offset + mac_at + i] = mac[i];
  }
  return Error::Ok;
}

template <CryptoPort K>
Result<std::size_t> SecureMessaging<K>::Wrap(ByteSpan plain, MutableByteSpan buffer,
                                             std::size_t offset, bool keep_le) noexcept {
  if (!active_) {
    return Result<std::size_t>::Failure(Error::WrongState);
  }
  const auto parsed = ParseCommand(plain);
  if ((!parsed.ok()) || (offset < kHeadroom) || (offset > buffer.size())) {
    return Result<std::size_t>::Failure(Error::InvalidArgument);
  }
  const CommandParts& parts = parsed.value;
  const std::size_t worst = ((parts.data.size() / 16U) + 1U) * 16U;
  const bool extended = parts.has_le || ((worst + kMacBytes) > 255U);
  const std::size_t lc_bytes = extended ? 3U : 1U;
  const bool le = parts.has_le && keep_le;
  const std::size_t le_bytes = le ? 2U : 0U;
  if ((4U + lc_bytes + worst + kMacBytes + le_bytes) > (buffer.size() - offset)) {
    return Result<std::size_t>::Failure(Error::BufferTooSmall);
  }
  const MutableByteSpan out = buffer.subspan(offset);
  const auto field = encryptData(parts, out.subspan(4U + lc_bytes));
  if (!field.ok()) {
    return Result<std::size_t>::Failure(field.error);
  }
  const std::size_t lc = field.value + kMacBytes;
  writeHeader(parts, lc, extended, out);
  const std::size_t mac_at = 4U + lc_bytes + field.value;
  if (appendMac(buffer, offset, mac_at) != Error::Ok) {
    Zeroize(out.subspan(0U, mac_at));
    return Result<std::size_t>::Failure(Error::CryptoFailure);
  }
  std::size_t total = mac_at + kMacBytes;
  if (le) {
    out[total] = 0x00U;
    out[total + 1U] = 0x00U;
    total += 2U;
  }
  last_had_data_ = !parts.data.empty();
  return Result<std::size_t>::Success(total);
}

template <CryptoPort K>
bool SecureMessaging<K>::advance() noexcept {
  const uint32_t now = counter_;
  return NextCounter(now, (rule_ == CounterRule::EveryCommand) || last_had_data_, counter_);
}

template <CryptoPort K>
Result<std::size_t> SecureMessaging<K>::decryptData(MutableByteSpan body) noexcept {
  if ((body.empty()) || ((static_cast<uint32_t>(level_) & kLevelREncrypt) == 0U)) {
    return Result<std::size_t>::Success(body.size());
  }
  if ((body.size() % 16U) != 0U) {
    return Result<std::size_t>::Failure(Error::SecureChannelError);
  }
  std::array<uint8_t, 16> icv{};
  if ((counterIcv(true, std::span<uint8_t, 16>{icv}) != Error::Ok) ||
      (crypto_->AesCbc(keys_.enc, false, std::span<uint8_t, 16>{icv}, body) != CryptoStatus::Ok)) {
    return Result<std::size_t>::Failure(Error::CryptoFailure);
  }
  // ISO 9797-1 method 2: the last non-zero byte is 0x80, within the last block.
  std::size_t end = body.size();
  std::size_t scanned = 0U;
  while ((end > 0U) && (body[end - 1U] == 0x00U) && (scanned < 16U)) {
    --end;
    ++scanned;
  }
  if ((end == 0U) || (body[end - 1U] != 0x80U) || (scanned >= 16U)) {
    return Result<std::size_t>::Failure(Error::SecureChannelError);
  }
  return Result<std::size_t>::Success(end - 1U);
}

template <CryptoPort K>
Result<std::size_t> SecureMessaging<K>::checkRmac(MutableByteSpan buffer,
                                                  std::size_t length) noexcept {
  // R-MAC = CMAC(S-RMAC, MCV || data || SW); the MAC sits between the data and the SW.
  if (length < (2U + kMacBytes)) {
    return Result<std::size_t>::Failure(Error::SecureChannelError);
  }
  const MutableByteSpan rsp = buffer.subspan(kHeadroom, length);
  const std::size_t body = length - 2U - kMacBytes;
  std::array<uint8_t, kMacBytes> received{};
  for (std::size_t i = 0U; i < kMacBytes; ++i) {
    received[i] = rsp[body + i];
  }
  rsp[body] = rsp[length - 2U];
  rsp[body + 1U] = rsp[length - 1U];
  for (std::size_t i = 0U; i < kMcvBytes; ++i) {
    buffer[i] = mcv_[i];
  }
  std::array<uint8_t, 16> mac{};
  if (crypto_->AesCmac(keys_.rmac, ByteSpan{buffer.subspan(0U, kMcvBytes + body + 2U)},
                       std::span<uint8_t, 16>{mac}) != CryptoStatus::Ok) {
    return Result<std::size_t>::Failure(Error::CryptoFailure);
  }
  if (!ct::Equal(ByteSpan{mac.data(), kMacBytes}, ByteSpan{received})) {
    return Result<std::size_t>::Failure(Error::SecureChannelError);
  }
  return Result<std::size_t>::Success(body);
}

template <CryptoPort K>
Result<std::size_t> SecureMessaging<K>::sessionEnded(MutableByteSpan out) noexcept {
  // The applet ended its session with this command and answered without secure messaging
  // (AN12543 4.20.5 p. 154): the engine stops, the keys go with the session.
  if (out.size() < 2U) {
    return Result<std::size_t>::Failure(Error::BufferTooSmall);
  }
  out[0] = 0x90U;
  out[1] = 0x00U;
  active_ = false;
  return Result<std::size_t>::Success(std::size_t{2});
}

template <CryptoPort K>
Result<std::size_t> SecureMessaging<K>::authenticBody(MutableByteSpan buffer, std::size_t length,
                                                      bool success) noexcept {
  // At the levels with R-MAC a 9000 answer must carry a valid R-MAC, and an error status word must
  // come alone (it carries none and is not authenticated).
  if ((static_cast<uint32_t>(level_) & kLevelRMac) == 0U) {
    return Result<std::size_t>::Success(length - 2U);
  }
  if (!success) {
    return (length == 2U) ? Result<std::size_t>::Success(std::size_t{0})
                          : Result<std::size_t>::Failure(Error::SecureChannelError);
  }
  return checkRmac(buffer, length);
}

template <CryptoPort K>
Result<std::size_t> SecureMessaging<K>::Unwrap(MutableByteSpan buffer, std::size_t length,
                                               MutableByteSpan out) noexcept {
  if (!active_) {
    return Result<std::size_t>::Failure(Error::WrongState);
  }
  if ((length < 2U) || ((kHeadroom + length) > buffer.size())) {
    return Result<std::size_t>::Failure(Error::SecureChannelError);
  }
  const MutableByteSpan rsp = buffer.subspan(kHeadroom, length);
  const uint8_t sw1 = rsp[length - 2U];
  const uint8_t sw2 = rsp[length - 1U];
  const bool success = (sw1 == 0x90U) && (sw2 == 0x00U);
  const bool expect_end = expect_end_;
  expect_end_ = false;
  if (success && (length == 2U) && expect_end) {
    return sessionEnded(out);
  }
  const Result<std::size_t> body = authenticBody(buffer, length, success);
  if (!body.ok()) {
    return body;
  }
  const auto plain = success ? decryptData(rsp.subspan(0U, body.value))
                             : Result<std::size_t>::Success(std::size_t{0});
  if (!plain.ok()) {
    return Result<std::size_t>::Failure(plain.error);
  }
  if (!advance()) {
    return Result<std::size_t>::Failure(Error::SecureChannelError);
  }
  if (out.size() < (plain.value + 2U)) {
    Zeroize(rsp);
    return Result<std::size_t>::Failure(Error::BufferTooSmall);
  }
  for (std::size_t i = 0U; i < plain.value; ++i) {
    out[i] = rsp[i];
  }
  out[plain.value] = sw1;
  out[plain.value + 1U] = sw2;
  Zeroize(rsp);
  return Result<std::size_t>::Success(plain.value + 2U);
}

template <PortSet P, ApduTransport T>
Result<std::size_t> Pipe<P, T>::SendPlain(ByteSpan command, MutableByteSpan response) noexcept {
  const MutableByteSpan tx{tx_};
  if (command.size() > kMaxCommandApdu) {
    return Result<std::size_t>::Failure(Error::BufferTooSmall);
  }
  for (std::size_t i = 0U; i < command.size(); ++i) {
    tx[session::kFrameHeadroom + i] = command[i];
  }
  const auto framed = framer_.Frame(tx, command.size());
  Result<std::size_t> result = Result<std::size_t>::Failure(framed.error, framed.detail);
  if (framed.ok()) {
    result = lower_->Transceive(framed.value, response);
  }
  Zeroize(tx);
  return result;
}

template <PortSet P, ApduTransport T>
Result<std::size_t> Pipe<P, T>::SendSecure(ByteSpan command, MutableByteSpan response) noexcept {
  const MutableByteSpan tx{tx_};
  // Inside a session the wrapped command travels without its Le (see the file comment).
  const auto wrapped = sm_.Wrap(command, tx.subspan(0U, tx.size() - 3U), session::kFrameHeadroom,
                                !framer_.Attached());
  if (!wrapped.ok()) {
    Zeroize(tx);
    return Result<std::size_t>::Failure(wrapped.error, Detail{0U, 0xFFU, Layer::Scp03, 1U, 0xFFU});
  }
  const auto framed = framer_.Frame(tx, wrapped.value);
  if (!framed.ok()) {
    Zeroize(tx);
    sm_.Stop();
    return Result<std::size_t>::Failure(framed.error);
  }
  const MutableByteSpan rx{rx_};
  const auto got = lower_->Transceive(framed.value, rx.subspan(kMcvBytes, kMaxResponse + 16U));
  Zeroize(tx);
  if (!got.ok()) {
    sm_.Stop();
    Zeroize(rx);
    return got;
  }
  const auto plain = sm_.Unwrap(rx, got.value, response);
  Zeroize(rx);
  if ((!plain.ok()) && (plain.error != Error::BufferTooSmall)) {
    sm_.Stop();
    return Result<std::size_t>::Failure(plain.error, Detail{0U, 0xFFU, Layer::Scp03, 2U, 0xFFU});
  }
  return plain;
}

template <PortSet P, ApduTransport T>
void Pipe<P, T>::Reset() noexcept {
  sm_.Stop();
  framer_.Detach();
  Zeroize(MutableByteSpan{tx_});
  Zeroize(MutableByteSpan{rx_});
}

/// The TLV length field of AN12543 4.1.3.2: one byte, 0x81 n, or 0x82 hi lo.
constexpr std::size_t TlvLengthBytes(std::size_t n) noexcept {
  if (n < 0x80U) {
    return 1U;
  }
  return (n < 0x100U) ? 2U : 3U;
}

/// Write a TLV length field; returns its size.
constexpr std::size_t PutTlvLength(MutableByteSpan out, std::size_t n) noexcept {
  const std::size_t size = TlvLengthBytes(n);
  if (size == 1U) {
    out[0] = static_cast<uint8_t>(n);
  } else if (size == 2U) {
    out[0] = 0x81U;
    out[1] = static_cast<uint8_t>(n);
  } else {
    out[0] = 0x82U;
    out[1] = static_cast<uint8_t>(n >> 8U);
    out[2] = static_cast<uint8_t>(n & 0xFFU);
  }
  return size;
}

/**
 * @brief Read one TLV at `at`: the tag must be `tag`; the length is one byte, 0x81 n or 0x82 hi lo.
 * @return The value, or `FrameError`.
 */
constexpr Result<ByteSpan> ReadTlv(ByteSpan data, std::size_t& at, uint8_t tag) noexcept {
  if (((at + 2U) > data.size()) || (data[at] != tag)) {
    return Result<ByteSpan>::Failure(Error::FrameError);
  }
  std::size_t n = data[at + 1U];
  std::size_t head = 2U;
  if (n == 0x81U) {
    if ((at + 3U) > data.size()) {
      return Result<ByteSpan>::Failure(Error::FrameError);
    }
    n = data[at + 2U];
    head = 3U;
  } else if (n == 0x82U) {
    if ((at + 4U) > data.size()) {
      return Result<ByteSpan>::Failure(Error::FrameError);
    }
    n = Be16(data, at + 2U);
    head = 4U;
  } else if (n > 0x80U) {
    return Result<ByteSpan>::Failure(Error::FrameError);
  } else {
    // one-byte length
  }
  if ((at + head + n) > data.size()) {
    return Result<ByteSpan>::Failure(Error::FrameError);
  }
  const ByteSpan value = data.subspan(at + head, n);
  at += head + n;
  return Result<ByteSpan>::Success(value);
}

/// The status word at the end of a response, 0 when shorter than two bytes.
constexpr uint16_t StatusWord(ByteSpan response) noexcept {
  if (response.size() < 2U) {
    return 0U;
  }
  return static_cast<uint16_t>(Be16(response, response.size() - 2U));
}

/// The applet's throughput-limit status word (S-17).
inline constexpr uint16_t kSwThroughput = 0x66A6U;

} // namespace se05x::scp03::detail

namespace se05x::session {

inline Result<ByteSpan> Framer::Frame(MutableByteSpan buffer, std::size_t length) const noexcept {
  if ((kFrameHeadroom + length + 3U) > buffer.size()) {
    return Result<ByteSpan>::Failure(Error::BufferTooSmall);
  }
  if (!attached_) {
    return Result<ByteSpan>::Success(ByteSpan{buffer.subspan(kFrameHeadroom, length)});
  }
  const std::size_t lbytes = scp03::detail::TlvLengthBytes(length);
  const std::size_t data = 2U + kSessionIdBytes + 1U + lbytes + length;
  const bool extended = data > 255U;
  const std::size_t head = 4U + (extended ? 3U : 1U) + 2U + kSessionIdBytes + 1U + lbytes;
  if (data > 0xFFFFU) {
    return Result<ByteSpan>::Failure(Error::BufferTooSmall);
  }
  const MutableByteSpan out = buffer.subspan(kFrameHeadroom - head);
  std::size_t i = 0U;
  out[i++] = scp03::kClaGp;
  out[i++] = kInsProcess;
  out[i++] = 0x00U;
  out[i++] = 0x00U;
  if (extended) {
    out[i++] = 0x00U;
    out[i++] = static_cast<uint8_t>(data >> 8U);
    out[i++] = static_cast<uint8_t>(data & 0xFFU);
  } else {
    out[i++] = static_cast<uint8_t>(data);
  }
  out[i++] = kTagSessionId;
  out[i++] = static_cast<uint8_t>(kSessionIdBytes);
  for (const uint8_t b : id_) {
    out[i++] = b;
  }
  out[i++] = kTag1;
  i += scp03::detail::PutTlvLength(out.subspan(i), length);
  i += length;
  out[i++] = 0x00U; // Le
  if (extended) {
    out[i++] = 0x00U;
  }
  return Result<ByteSpan>::Success(ByteSpan{out.subspan(0U, i)});
}

/// Map the status word of a session command.
constexpr Error SessionSwError(uint16_t sw) noexcept {
  if (sw == 0x9000U) {
    return Error::Ok;
  }
  if (sw == scp03::detail::kSwThroughput) {
    return Error::ThroughputLimited;
  }
  if (sw == 0x6985U) {
    return Error::ConditionsNotSatisfied;
  }
  return Error::ChipSwUnknown;
}

template <ApduTransport T>
Result<void> CreateSession(T& lower, ObjectId credential, Id& id) noexcept {
  id = Id{};
  if (credential.value == 0U) {
    return Result<void>::Failure(Error::InvalidArgument);
  }
  const uint32_t v = credential.value;
  const std::array<uint8_t, 12> cmd{scp03::kClaGp,
                                    kInsMgmt,
                                    0x00U,
                                    kP2SessionCreate,
                                    0x06U,
                                    kTag1,
                                    0x04U,
                                    static_cast<uint8_t>(v >> 24U),
                                    static_cast<uint8_t>((v >> 16U) & 0xFFU),
                                    static_cast<uint8_t>((v >> 8U) & 0xFFU),
                                    static_cast<uint8_t>(v & 0xFFU),
                                    0x0CU};
  std::array<uint8_t, 32> rsp{};
  const auto got = lower.Transceive(ByteSpan{cmd}, MutableByteSpan{rsp});
  if (!got.ok()) {
    return Result<void>::Failure(got.error, got.detail);
  }
  const ByteSpan answer{rsp.data(), got.value};
  const uint16_t sw = scp03::detail::StatusWord(answer);
  const Error e = SessionSwError(sw);
  if (e != Error::Ok) {
    return Result<void>::Failure(e, Detail{sw, 0xFFU, Layer::Scp03, 0U, 0xFFU});
  }
  std::size_t at = 0U;
  const auto value = scp03::detail::ReadTlv(answer.subspan(0U, answer.size() - 2U), at, kTag1);
  if ((!value.ok()) || (value.value.size() != kSessionIdBytes) || ((at + 2U) != answer.size())) {
    return Result<void>::Failure(Error::FrameError, Detail{sw, 0xFFU, Layer::Scp03, 0U, 0xFFU});
  }
  for (std::size_t i = 0U; i < kSessionIdBytes; ++i) {
    id[i] = value.value[i];
  }
  return Result<void>::Success();
}

template <PortSet P, ApduTransport T>
Result<void> UserIdSession<P, T>::Open(ObjectId credential, ByteSpan value) noexcept {
  if (open_) {
    return Result<void>::Failure(Error::WrongState);
  }
  if ((userid::CheckValue(value.size()) != Error::Ok) || (credential.value == 0U)) {
    return Result<void>::Failure(Error::InvalidArgument);
  }
  if (attempts_.Exhausted()) {
    return Result<void>::Failure(Error::AuthLocked,
                                 Detail{0U, 0xFFU, Layer::Scp03, 0U, attempts_.Remaining()});
  }
  pipe_.Reset();
  Id id{};
  const auto created = CreateSession(pipe_.Lower(), credential, id);
  if (!created.ok()) {
    return created;
  }
  needs_reselect_ = true; // until VerifySessionUserID succeeds the session cannot be closed
  pipe_.Frame().Attach(id);
  SecretBuffer<5U + 2U + userid::kMaxLength> cmd;
  const MutableByteSpan c = cmd.Reserve(7U + value.size());
  c[0] = scp03::kClaGp;
  c[1] = kInsMgmt;
  c[2] = 0x00U;
  c[3] = kP2SessionUserId;
  c[4] = static_cast<uint8_t>(2U + value.size());
  c[5] = kTag1;
  c[6] = static_cast<uint8_t>(value.size());
  for (std::size_t i = 0U; i < value.size(); ++i) {
    c[7U + i] = value[i];
  }
  std::array<uint8_t, 8> rsp{};
  const auto got = pipe_.SendPlain(cmd.Span(), MutableByteSpan{rsp});
  if (!got.ok()) {
    pipe_.Reset();
    return Result<void>::Failure(got.error, got.detail);
  }
  const uint16_t sw = scp03::detail::StatusWord(ByteSpan{rsp.data(), got.value});
  if (sw != 0x9000U) {
    pipe_.Reset();
    const Error e =
        (sw == scp03::detail::kSwThroughput) ? Error::ThroughputLimited : Error::AuthFailed;
    if (e == Error::AuthFailed) {
      attempts_.RecordFailure();
    }
    return Result<void>::Failure(e, Detail{sw, 0xFFU, Layer::Scp03, 1U, attempts_.Remaining()});
  }
  attempts_.RecordSuccess();
  needs_reselect_ = false;
  open_ = true;
  return Result<void>::Success();
}

template <PortSet P, ApduTransport T>
Result<std::size_t> UserIdSession<P, T>::Transceive(ByteSpan command,
                                                    MutableByteSpan response) noexcept {
  if (!open_) {
    return Result<std::size_t>::Failure(Error::NotInitialized);
  }
  return pipe_.SendPlain(command, response);
}

template <PortSet P, ApduTransport T>
Result<void> UserIdSession<P, T>::Close() noexcept {
  if (!open_) {
    pipe_.Reset();
    return Result<void>::Success();
  }
  const std::array<uint8_t, 4> cmd{scp03::kClaGp, kInsMgmt, 0x00U, kP2SessionClose};
  std::array<uint8_t, 8> rsp{};
  const auto got = pipe_.SendPlain(ByteSpan{cmd}, MutableByteSpan{rsp});
  open_ = false;
  pipe_.Reset();
  if ((!got.ok()) || (scp03::detail::StatusWord(ByteSpan{rsp.data(), got.value}) != 0x9000U)) {
    needs_reselect_ = true;
    return Result<void>::Failure(Error::NeedsReselect);
  }
  return Result<void>::Success();
}

} // namespace se05x::session

namespace se05x::scp03 {

template <PortSet P, ApduTransport T>
bool Channel<P, T>::validParams(const ChannelParams& params) noexcept {
  const bool session = params.kind == ChannelKind::AesKeySession;
  const bool keys_ok = params.keys.enc.IsValid() && (session || params.keys.mac.IsValid());
  // An AESKey session: a credential, a 128-bit key and key version 00 (AN12543 4.5.3.1).
  const bool session_ok =
      (!session) || ((params.credential.value != 0U) && (params.length == KeyLength::Aes128) &&
                     (params.key_version == 0U));
  return se05x::detail::IsEnumerator(params.level) && se05x::detail::IsEnumerator(params.length) &&
         se05x::detail::IsEnumerator(params.kind) && keys_ok && session_ok;
}

template <PortSet P, ApduTransport T>
Result<void> Channel<P, T>::Open(const ChannelParams& params) noexcept {
  if (open_) {
    return Result<void>::Failure(Error::WrongState);
  }
  if (!validParams(params)) {
    return Result<void>::Failure(Error::InvalidArgument);
  }
  if (attempts_.Exhausted()) {
    return Result<void>::Failure(Error::AuthLocked,
                                 Detail{0U, 0xFFU, Layer::Scp03, 0U, attempts_.Remaining()});
  }
  pipe_.Reset();
  kind_ = params.kind;
  const auto result = handshake(params);
  if (!result.ok()) {
    pipe_.Reset();
    const bool counted =
        (result.error == Error::AuthFailed) || (result.error == Error::SecureChannelError);
    if (counted) {
      attempts_.RecordFailure();
    }
    Result<void> failed = result;
    failed.detail.attempts_left = attempts_.Remaining();
    return failed;
  }
  attempts_.RecordSuccess();
  needs_reselect_ = false;
  open_ = true;
  return Result<void>::Success();
}

template <PortSet P, ApduTransport T>
Result<void> Channel<P, T>::handshake(const ChannelParams& params) noexcept {
  if (kind_ == ChannelKind::AesKeySession) {
    session::Id id{};
    const auto created = session::CreateSession(pipe_.Lower(), params.credential, id);
    if (!created.ok()) {
      return created;
    }
    needs_reselect_ = true; // a half-open session cannot be closed (AN12543 3.6.5)
    pipe_.Frame().Attach(id);
  }
  detail::Handshake hs{};
  auto step = initializeUpdate(params, hs);
  if (step.ok()) {
    step = deriveKeys(params, hs);
  }
  if (step.ok()) {
    step = externalAuthenticate(params, hs);
  }
  return step;
}

template <PortSet P, ApduTransport T>
Result<void> Channel<P, T>::initializeUpdate(const ChannelParams& params,
                                             detail::Handshake& hs) noexcept {
  std::array<uint8_t, 14> cmd{kClaGp, kInsInitializeUpdate, params.key_version, 0x00U, 0x08U};
  const MutableByteSpan challenge{&cmd[5], kChallengeBytes};
  if (pipe_.Ports().GetCrypto().Random(challenge) != CryptoStatus::Ok) {
    return Result<void>::Failure(Error::CryptoFailure, Detail{0U, 0xFFU, Layer::Scp03, 1U, 0xFFU});
  }
  cmd[13] = 0x00U; // Le
  std::array<uint8_t, 64> rsp{};
  const auto got = pipe_.SendPlain(ByteSpan{cmd}, MutableByteSpan{rsp});
  if (!got.ok()) {
    return Result<void>::Failure(got.error, got.detail);
  }
  const ByteSpan answer{rsp.data(), got.value};
  const uint16_t sw = detail::StatusWord(answer);
  const Detail d{sw, 0xFFU, Layer::Scp03, 1U, 0xFFU};
  if (sw == detail::kSwThroughput) {
    return Result<void>::Failure(Error::ThroughputLimited, d);
  }
  if (sw != 0x9000U) {
    return Result<void>::Failure(Error::AuthFailed, d);
  }
  // Key diversification data (10), key information (3), card challenge (8), card cryptogram (8),
  // and a sequence counter (3) with a pseudo-random challenge.
  const std::size_t body = answer.size() - 2U;
  if (((body != 29U) && (body != 32U)) || (answer[11] != kScp03Id) ||
      ((params.key_version != 0U) && (answer[10] != params.key_version))) {
    return Result<void>::Failure(Error::SecureChannelError, d);
  }
  for (std::size_t i = 0U; i < kChallengeBytes; ++i) {
    hs.context[i] = cmd[5U + i];
    hs.context[kChallengeBytes + i] = answer[13U + i];
    hs.card_cryptogram[i] = answer[21U + i];
  }
  return Result<void>::Success();
}

template <PortSet P, ApduTransport T>
Result<void> Channel<P, T>::deriveKeys(const ChannelParams& params,
                                       detail::Handshake& hs) noexcept {
  auto& crypto = pipe_.Ports().GetCrypto();
  const bool wide = params.length == KeyLength::Aes256;
  const KeyKind kind = wide ? KeyKind::Aes256 : KeyKind::Aes128;
  const KeyRef mac_base = params.keys.mac.IsValid() ? params.keys.mac : params.keys.enc;
  const std::array<uint8_t, 3> constants{kDdSEnc, kDdSMac, kDdSRmac};
  const std::array<KeyRef, 3> bases{params.keys.enc, mac_base, mac_base};
  std::array<KeyRef, 3> derived{};
  const Detail d{0U, 0xFFU, Layer::Scp03, 2U, 0xFFU};
  Error e = Error::Ok;
  for (std::size_t i = 0U; (i < 3U) && (e == Error::Ok); ++i) {
    SecretBuffer<32> raw;
    const MutableByteSpan bytes = raw.Reserve(wide ? 32U : 16U);
    e = detail::Kdf(crypto, bases[i], constants[i], ByteSpan{hs.context}, bytes);
    if ((e == Error::Ok) && (crypto.ImportKey(kind, raw.Span(), derived[i]) != CryptoStatus::Ok)) {
      e = Error::CryptoFailure;
    }
  }
  hs.keys = detail::SessionKeys{.enc = derived[0], .mac = derived[1], .rmac = derived[2]};
  // The engine owns the keys from here, so `Reset()` releases them on any later failure.
  pipe_.Sm().Start(crypto, hs.keys, kLevelCMac, detail::CounterRule::EveryCommand,
                   std::array<uint8_t, kMcvBytes>{});
  if (e != Error::Ok) {
    return Result<void>::Failure(e, d);
  }
  std::array<uint8_t, kCryptogramBytes> expected{};
  e = detail::Kdf(crypto, hs.keys.mac, kDdCardCryptogram, ByteSpan{hs.context},
                  MutableByteSpan{expected});
  if (e != Error::Ok) {
    return Result<void>::Failure(e, d);
  }
  if (!ct::Equal(ByteSpan{expected}, ByteSpan{hs.card_cryptogram})) {
    return Result<void>::Failure(Error::SecureChannelError, d);
  }
  return Result<void>::Success();
}

template <PortSet P, ApduTransport T>
Result<void> Channel<P, T>::externalAuthenticate(const ChannelParams& params,
                                                 detail::Handshake& hs) noexcept {
  auto& crypto = pipe_.Ports().GetCrypto();
  const uint8_t level = LevelByte(params.level);
  std::array<uint8_t, 13> cmd{kClaGp, kInsExternalAuthenticate, level, 0x00U, 0x08U};
  const Error e = detail::Kdf(crypto, hs.keys.mac, kDdHostCryptogram, ByteSpan{hs.context},
                              MutableByteSpan{&cmd[5], kCryptogramBytes});
  if (e != Error::Ok) {
    return Result<void>::Failure(e, Detail{0U, 0xFFU, Layer::Scp03, 3U, 0xFFU});
  }
  // EXTERNAL AUTHENTICATE carries a C-MAC only and gets no R-MAC: wrap it, check the SW by hand.
  std::array<uint8_t, 8> rsp{};
  std::array<uint8_t, session::kFrameHeadroom + 32U> tx{};
  const auto wrapped =
      pipe_.Sm().Wrap(ByteSpan{cmd}, MutableByteSpan{tx}, session::kFrameHeadroom, true);
  if (!wrapped.ok()) {
    return Result<void>::Failure(wrapped.error, Detail{0U, 0xFFU, Layer::Scp03, 3U, 0xFFU});
  }
  const auto got = pipe_.SendPlain(ByteSpan{tx}.subspan(session::kFrameHeadroom, wrapped.value),
                                   MutableByteSpan{rsp});
  Zeroize(MutableByteSpan{tx});
  if (!got.ok()) {
    return Result<void>::Failure(got.error, got.detail);
  }
  const uint16_t sw = detail::StatusWord(ByteSpan{rsp.data(), got.value});
  const Detail d{sw, 0xFFU, Layer::Scp03, 3U, 0xFFU};
  if (sw == detail::kSwThroughput) {
    return Result<void>::Failure(Error::ThroughputLimited, d);
  }
  if ((sw != 0x9000U) || (got.value != 2U)) {
    return Result<void>::Failure(Error::AuthFailed, d);
  }
  const bool platform = kind_ == ChannelKind::Platform;
  pipe_.Sm().Reconfigure(level, (platform && params.jos2_counter_rule)
                                    ? detail::CounterRule::DataCommandsOnly
                                    : detail::CounterRule::EveryCommand);
  return Result<void>::Success();
}

template <PortSet P, ApduTransport T>
Result<std::size_t> Channel<P, T>::Transceive(ByteSpan command, MutableByteSpan response) noexcept {
  if (!open_) {
    return Result<std::size_t>::Failure(Error::NotInitialized);
  }
  const auto result = pipe_.SendSecure(command, response);
  if ((!result.ok()) && (!pipe_.Sm().Active())) {
    closeLocal();
  }
  return result;
}

template <PortSet P, ApduTransport T>
void Channel<P, T>::closeLocal() noexcept {
  open_ = false;
  pipe_.Reset();
}

template <PortSet P, ApduTransport T>
Result<void> Channel<P, T>::Close() noexcept {
  if ((!open_) || (kind_ == ChannelKind::Platform)) {
    closeLocal();
    return Result<void>::Success();
  }
  const std::array<uint8_t, 4> cmd{kClaGp, session::kInsMgmt, 0x00U, session::kP2SessionClose};
  std::array<uint8_t, 16> rsp{};
  const auto got = pipe_.SendSecure(ByteSpan{cmd}, MutableByteSpan{rsp});
  closeLocal();
  if ((!got.ok()) || (detail::StatusWord(ByteSpan{rsp.data(), got.value}) != 0x9000U)) {
    needs_reselect_ = true;
    return Result<void>::Failure(Error::NeedsReselect, got.detail);
  }
  return Result<void>::Success();
}

} // namespace se05x::scp03

#endif // SE05X_SCP03_IPP
