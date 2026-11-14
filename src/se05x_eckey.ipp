/**
 * @file se05x_eckey.ipp
 * @brief ECKey session implementation, included by `se05x_eckey.hpp`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#ifndef SE05X_ECKEY_IPP
#define SE05X_ECKEY_IPP

namespace se05x::eckey::detail {

constexpr void BuildAuthData(std::span<const uint8_t, 65> host_public, uint8_t level,
                             std::span<uint8_t, kAuthDataBytes> out) noexcept {
  std::size_t i = 0U;
  out[i++] = 0xA6U; // control reference template
  out[i++] = 0x1DU;
  out[i++] = 0x4FU; // applet instance AID
  out[i++] = static_cast<uint8_t>(kAppletAid.size());
  for (const uint8_t b : kAppletAid) {
    out[i++] = b;
  }
  out[i++] = 0x90U; // SCP identifier and parameters
  out[i++] = 0x03U;
  out[i++] = kScpIdEcKey;
  out[i++] = kScpParameter;
  out[i++] = level;
  out[i++] = 0x80U; // key type
  out[i++] = 0x01U;
  out[i++] = kKeyTypeAes;
  out[i++] = 0x81U; // key length
  out[i++] = 0x01U;
  out[i++] = kKeyLengthAes128;
  out[i++] = 0x7FU; // public key data object
  out[i++] = 0x49U;
  out[i++] = 0x46U;
  out[i++] = 0xB0U; // public key point
  out[i++] = 0x41U;
  for (const uint8_t b : host_public) {
    out[i++] = b;
  }
  out[i++] = 0xF0U; // key parameter reference: the curve
  out[i++] = 0x01U;
  out[i++] = kCurveNistP256;
}

/// Write one DER INTEGER of a 32-byte unsigned value; returns the bytes written.
constexpr std::size_t PutDerInteger(std::span<const uint8_t, 32> v, MutableByteSpan out) noexcept {
  std::size_t skip = 0U;
  while ((skip < 31U) && (v[skip] == 0x00U)) {
    ++skip;
  }
  const bool pad = (static_cast<uint32_t>(v[skip]) & 0x80U) != 0U;
  const std::size_t len = (32U - skip) + (pad ? 1U : 0U);
  std::size_t i = 0U;
  out[i++] = 0x02U;
  out[i++] = static_cast<uint8_t>(len);
  if (pad) {
    out[i++] = 0x00U;
  }
  for (std::size_t k = skip; k < 32U; ++k) {
    out[i++] = v[k];
  }
  return i;
}

constexpr std::size_t EncodeDerSignature(std::span<const uint8_t, 64> raw,
                                         std::span<uint8_t, 72> out) noexcept {
  std::array<uint8_t, 35> r{};
  std::array<uint8_t, 35> s{};
  const std::size_t rl =
      PutDerInteger(std::span<const uint8_t, 32>{raw.subspan(0U, 32U).data(), 32U}, r);
  const std::size_t sl =
      PutDerInteger(std::span<const uint8_t, 32>{raw.subspan(32U, 32U).data(), 32U}, s);
  std::size_t i = 0U;
  out[i++] = 0x30U;
  out[i++] = static_cast<uint8_t>(rl + sl);
  for (std::size_t k = 0U; k < rl; ++k) {
    out[i++] = r[k];
  }
  for (std::size_t k = 0U; k < sl; ++k) {
    out[i++] = s[k];
  }
  return i;
}

/// ECKeySessionInternalAuthenticate: header, the authentication data, 5F37 with the DER
/// signature (AN12543 Table 85, Figure 14). No Le: the trace of AN13904 Figure 7 (p. 16) carries
/// the command in a 182-byte TAG_1 with Lc B1, which leaves no room for one. Returns the length.
constexpr std::size_t BuildAuthCommand(std::span<const uint8_t, kAuthDataBytes> auth,
                                       std::span<const uint8_t, 64> raw,
                                       std::span<uint8_t, kAuthCommandBytes> cmd) noexcept {
  std::array<uint8_t, 72> der{};
  const std::size_t der_len = EncodeDerSignature(raw, der);
  std::size_t i = 0U;
  cmd[i++] = kClaEcKey;
  cmd[i++] = kInsInternalAuth;
  cmd[i++] = 0x00U; // key version number
  cmd[i++] = 0x00U; // key identifier
  cmd[i++] = static_cast<uint8_t>(kAuthDataBytes + 3U + der_len);
  for (const uint8_t b : auth) {
    cmd[i++] = b;
  }
  cmd[i++] = 0x5FU; // signature
  cmd[i++] = 0x37U;
  cmd[i++] = static_cast<uint8_t>(der_len);
  for (std::size_t k = 0U; k < der_len; ++k) {
    cmd[i++] = der[k];
  }
  return i;
}

/// The answer body: 85 (16-byte DR.SE) then 86 (16-byte receipt) and nothing else (Table 87).
constexpr bool ParseAuthAnswer(ByteSpan body, std::span<uint8_t, kChallengeBytes> challenge,
                               std::span<uint8_t, kReceiptBytes> receipt) noexcept {
  std::size_t at = 0U;
  const auto dr = scp03::detail::ReadTlv(body, at, kTagChallenge);
  const auto rc = scp03::detail::ReadTlv(body, at, kTagReceipt);
  if ((!dr.ok()) || (!rc.ok()) || (dr.value.size() != kChallengeBytes) ||
      (rc.value.size() != kReceiptBytes) || (at != body.size())) {
    return false;
  }
  for (std::size_t k = 0U; k < kChallengeBytes; ++k) {
    challenge[k] = dr.value[k];
    receipt[k] = rc.value[k];
  }
  return true;
}

template <CryptoPort K>
Error DeriveMasterKey(K& crypto, std::span<const uint8_t, 32> shared,
                      std::span<const uint8_t, kChallengeBytes> challenge, uint8_t level,
                      KeyRef& master) noexcept {
  master = KeyRef{};
  SecretBuffer<4U + 32U + kChallengeBytes + 4U> input;
  const MutableByteSpan in = input.Reserve(input.Capacity());
  std::size_t i = 0U;
  in[i++] = 0x00U; // the 4-byte counter 00000001
  in[i++] = 0x00U;
  in[i++] = 0x00U;
  in[i++] = 0x01U;
  for (const uint8_t b : shared) {
    in[i++] = b;
  }
  for (const uint8_t b : challenge) {
    in[i++] = b;
  }
  in[i++] = kScpParameter;
  in[i++] = level;
  in[i++] = kKeyTypeAes;
  in[i++] = kKeyLengthAes128;
  SecretBuffer<32> digest;
  const MutableByteSpan d = digest.Reserve(32U);
  if (crypto.Hash(HashAlg::Sha256, input.Span(), d) != CryptoStatus::Ok) {
    return Error::CryptoFailure;
  }
  if (crypto.ImportKey(KeyKind::Aes128, ByteSpan{d.subspan(0U, 16U)}, master) != CryptoStatus::Ok) {
    master = KeyRef{};
    return Error::CryptoFailure;
  }
  return Error::Ok;
}

template <CryptoPort K>
Error DeriveSessionKeys(K& crypto, KeyRef master, scp03::detail::SessionKeys& keys,
                        std::array<uint8_t, scp03::kMcvBytes>& mcv) noexcept {
  keys = scp03::detail::SessionKeys{};
  const std::array<uint8_t, 3> constants{scp03::kDdSEnc, scp03::kDdSMac, scp03::kDdSRmac};
  std::array<KeyRef, 3> out{};
  Error e = Error::Ok;
  for (std::size_t i = 0U; (i < 3U) && (e == Error::Ok); ++i) {
    SecretBuffer<16> raw;
    const MutableByteSpan bytes = raw.Reserve(16U);
    e = scp03::detail::Kdf(crypto, master, constants[i], ByteSpan{}, bytes);
    if ((e == Error::Ok) &&
        (crypto.ImportKey(KeyKind::Aes128, raw.Span(), out[i]) != CryptoStatus::Ok)) {
      e = Error::CryptoFailure;
    }
  }
  if (e == Error::Ok) {
    e = scp03::detail::Kdf(crypto, master, scp03::kDdInitialMcv, ByteSpan{}, MutableByteSpan{mcv});
  }
  if (e != Error::Ok) {
    for (const KeyRef k : out) {
      if (k.IsValid()) {
        static_cast<void>(crypto.ReleaseKey(k));
      }
    }
    Zeroize(MutableByteSpan{mcv});
    return e;
  }
  keys = scp03::detail::SessionKeys{.enc = out[0], .mac = out[1], .rmac = out[2]};
  return Error::Ok;
}

template <PortSet P, ApduTransport T>
Result<void> Engine<P, T>::Open(const SessionParams& params) noexcept {
  if (open_) {
    return Result<void>::Failure(Error::WrongState);
  }
  if ((params.credential.value == 0U) || (!params.host_key.IsValid()) ||
      (params.se_public_key.size() != 65U) || (params.se_public_key[0] != 0x04U) ||
      (!se05x::detail::IsEnumerator(params.level))) {
    return Result<void>::Failure(Error::InvalidArgument);
  }
  if (attempts_.Exhausted()) {
    return Result<void>::Failure(Error::AuthLocked,
                                 Detail{0U, 0xFFU, Layer::EcKey, 0U, attempts_.Remaining()});
  }
  pipe_.Reset();
  const auto result = handshake(params);
  if (!result.ok()) {
    pipe_.Reset();
    if ((result.error == Error::AuthFailed) || (result.error == Error::SecureChannelError)) {
      attempts_.RecordFailure();
    }
    Result<void> failed = result;
    failed.detail.layer = Layer::EcKey;
    failed.detail.attempts_left = attempts_.Remaining();
    return failed;
  }
  attempts_.RecordSuccess();
  needs_reselect_ = false;
  open_ = true;
  return Result<void>::Success();
}

template <PortSet P, ApduTransport T>
Result<void> Engine<P, T>::handshake(const SessionParams& params) noexcept {
  session::Id id{};
  const auto created = session::CreateSession(pipe_.Lower(), params.credential, id);
  if (!created.ok()) {
    return created;
  }
  needs_reselect_ = true; // until the handshake completes the session cannot be closed
  pipe_.Frame().Attach(id);
  auto& crypto = pipe_.Ports().GetCrypto();
  KeyRef ephemeral{};
  std::array<uint8_t, 65> host_public{};
  if (crypto.GenerateP256(ephemeral, std::span<uint8_t, 65>{host_public}) != CryptoStatus::Ok) {
    return Result<void>::Failure(Error::CryptoFailure, Detail{0U, 0xFFU, Layer::EcKey, 1U, 0xFFU});
  }
  std::array<uint8_t, kAuthDataBytes> auth{};
  std::array<uint8_t, kChallengeBytes> challenge{};
  std::array<uint8_t, kReceiptBytes> receipt{};
  auto step = authenticate(params, host_public, auth, challenge, receipt);
  if (step.ok()) {
    step = keys(params, ephemeral, auth, challenge, receipt);
  }
  static_cast<void>(crypto.ReleaseKey(ephemeral)); // ephemeral: gone after one handshake
  Zeroize(MutableByteSpan{challenge});
  return step;
}

template <PortSet P, ApduTransport T>
Result<void> Engine<P, T>::authenticate(const SessionParams& params,
                                        std::span<const uint8_t, 65> host_public,
                                        std::span<uint8_t, kAuthDataBytes> auth,
                                        std::span<uint8_t, kChallengeBytes> challenge,
                                        std::span<uint8_t, kReceiptBytes> receipt) noexcept {
  auto& crypto = pipe_.Ports().GetCrypto();
  const uint8_t level = scp03::LevelByte(params.level);
  BuildAuthData(host_public, level, auth);
  std::array<uint8_t, 32> digest{};
  std::array<uint8_t, 64> raw{};
  if ((crypto.Hash(HashAlg::Sha256, ByteSpan{auth}, MutableByteSpan{digest}) != CryptoStatus::Ok) ||
      (crypto.EcdsaP256Sign(params.host_key, std::span<const uint8_t, 32>{digest},
                            std::span<uint8_t, 64>{raw}) != CryptoStatus::Ok)) {
    return Result<void>::Failure(Error::CryptoFailure, Detail{0U, 0xFFU, Layer::EcKey, 2U, 0xFFU});
  }
  std::array<uint8_t, kAuthCommandBytes> cmd{};
  const std::size_t length = BuildAuthCommand(auth, raw, cmd);
  std::array<uint8_t, 64> rsp{};
  const auto got = pipe_.SendPlain(ByteSpan{cmd.data(), length}, MutableByteSpan{rsp});
  if (!got.ok()) {
    return Result<void>::Failure(got.error, got.detail);
  }
  const ByteSpan answer{rsp.data(), got.value};
  const uint16_t sw = scp03::detail::StatusWord(answer);
  const Detail d{sw, 0xFFU, Layer::EcKey, 3U, 0xFFU};
  if (sw == scp03::detail::kSwThroughput) {
    return Result<void>::Failure(Error::ThroughputLimited, d);
  }
  if (sw != 0x9000U) {
    return Result<void>::Failure(Error::AuthFailed, d);
  }
  if (!ParseAuthAnswer(answer.subspan(0U, answer.size() - 2U), challenge, receipt)) {
    return Result<void>::Failure(Error::SecureChannelError, d);
  }
  return Result<void>::Success();
}

template <PortSet P, ApduTransport T>
Result<void> Engine<P, T>::keys(const SessionParams& params, KeyRef ephemeral,
                                std::span<const uint8_t, kAuthDataBytes> auth,
                                std::span<const uint8_t, kChallengeBytes> challenge,
                                std::span<const uint8_t, kReceiptBytes> receipt) noexcept {
  auto& crypto = pipe_.Ports().GetCrypto();
  const uint8_t level = scp03::LevelByte(params.level);
  const Detail d{0U, 0xFFU, Layer::EcKey, 4U, 0xFFU};
  SecretBuffer<32> shared;
  const MutableByteSpan z = shared.Reserve(32U);
  if (crypto.EcdhP256(ephemeral, std::span<const uint8_t, 65>{params.se_public_key.data(), 65U},
                      std::span<uint8_t, 32>{z.data(), 32U}) != CryptoStatus::Ok) {
    return Result<void>::Failure(Error::CryptoFailure, d);
  }
  KeyRef master{};
  Error e = DeriveMasterKey(crypto, std::span<const uint8_t, 32>{z.data(), 32U}, challenge, level,
                            master);
  shared.Wipe();
  scp03::detail::SessionKeys session_keys{};
  std::array<uint8_t, scp03::kMcvBytes> mcv{};
  if (e == Error::Ok) {
    e = DeriveSessionKeys(crypto, master, session_keys, mcv);
  }
  if (master.IsValid()) {
    static_cast<void>(crypto.ReleaseKey(master));
  }
  if (e != Error::Ok) {
    return Result<void>::Failure(e, d);
  }
  // The engine owns the keys from here: a failed receipt check releases them through Reset().
  pipe_.Sm().Start(crypto, session_keys, level, scp03::detail::CounterRule::EveryCommand, mcv);
  Zeroize(MutableByteSpan{mcv});
  if (params.verify_receipt) {
    std::array<uint8_t, 16> expected{};
    if (crypto.AesCmac(session_keys.rmac, ByteSpan{auth}, std::span<uint8_t, 16>{expected}) !=
        CryptoStatus::Ok) {
      return Result<void>::Failure(Error::CryptoFailure, d);
    }
    if (!ct::Equal(ByteSpan{expected}, ByteSpan{receipt})) {
      return Result<void>::Failure(Error::SecureChannelError, d);
    }
  }
  return Result<void>::Success();
}

template <PortSet P, ApduTransport T>
Result<std::size_t> Engine<P, T>::Transceive(ByteSpan command, MutableByteSpan response) noexcept {
  if (!open_) {
    return Result<std::size_t>::Failure(Error::NotInitialized);
  }
  const auto result = pipe_.SendSecure(command, response);
  if ((!result.ok()) && (!pipe_.Sm().Active())) {
    open_ = false;
    pipe_.Reset();
  }
  return result;
}

template <PortSet P, ApduTransport T>
Result<void> Engine<P, T>::Close() noexcept {
  if (!open_) {
    pipe_.Reset();
    return Result<void>::Success();
  }
  const std::array<uint8_t, 4> cmd{scp03::kClaGp, session::kInsMgmt, 0x00U,
                                   session::kP2SessionClose};
  std::array<uint8_t, 16> rsp{};
  const auto got = pipe_.SendSecure(ByteSpan{cmd}, MutableByteSpan{rsp});
  open_ = false;
  pipe_.Reset();
  if ((!got.ok()) || (scp03::detail::StatusWord(ByteSpan{rsp.data(), got.value}) != 0x9000U)) {
    needs_reselect_ = true;
    return Result<void>::Failure(Error::NeedsReselect, got.detail);
  }
  return Result<void>::Success();
}

} // namespace se05x::eckey::detail

#endif // SE05X_ECKEY_IPP
