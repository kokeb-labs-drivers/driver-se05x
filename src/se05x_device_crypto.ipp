/**
 * @file se05x_device_crypto.ipp
 * @brief Device sessions (UserID, AESKey, ECKey), the verified ECKA key, the self test, raw
 * access, transactions and the crypto and management wrappers, included by `se05x_device.hpp`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#ifndef SE05X_DEVICE_CRYPTO_IPP
#define SE05X_DEVICE_CRYPTO_IPP

namespace se05x {

namespace detail {
/// INS_MGMT without its characteristics bits (AN12543 Tables 23, 25).
inline constexpr uint8_t kInsMgmtLow = 0x04U;
/// INS_PROCESS (session framing).
inline constexpr uint8_t kInsProcessLow = 0x05U;
/// The P2 values of INS_MGMT that `ReadRaw` refuses: the session commands (P2_SESSION_CREATE,
/// _CLOSE, _REFRESH, _POLICY, _USERID) and the irreversible ones (P2_DELETE_ALL, P2_TRANSPORT,
/// P2_VARIANT, P2_SCP, P2_RESTRICT) (AN12543 Table 29).
inline constexpr std::array<uint8_t, 10> kRawRefusedP2{0x1BU, 0x1CU, 0x1EU, 0x1FU, 0x2CU,
                                                       0x2AU, 0x3EU, 0x3FU, 0x52U, 0x57U};
/// Whether a raw APDU would change what the device knows of the chip (S-10).
constexpr bool RawRefused(ByteSpan command) noexcept {
  if (command.size() < 4U) {
    return false;
  }
  const uint32_t ins = static_cast<uint32_t>(command[1]) & 0x0FU;
  if ((command[0] == 0x00U) && (command[1] == 0xA4U)) {
    return true; // SELECT
  }
  if (ins == kInsProcessLow) {
    return true;
  }
  bool refused = false;
  if (ins == kInsMgmtLow) {
    for (const uint8_t p2 : kRawRefusedP2) {
      refused = refused || (command[3] == p2);
    }
  }
  return refused;
}
} // namespace detail

// --- Sessions --------------------------------------------------------------------------------

template <PortSet P>
Error Device<P>::sessionReady() const noexcept {
  if (state_ == DeviceState::Closed) {
    return Error::NotInitialized;
  }
  if (state_ == DeviceState::Dead) {
    return Error::TransportDead;
  }
  if ((state_ != DeviceState::Ready) || (session_ != SessionKind::None)) {
    return Error::WrongState;
  }
  return gate::Check(caps_, config_, Command::CreateSession);
}

template <PortSet P>
Result<void> Device<P>::afterSessionOpen(Result<void> opened, SessionKind kind, ObjectId credential,
                                         uint32_t sent_before) noexcept {
  // Every APDU the handshake handed down, whatever the session kind: UserID 2, AESKey 3
  // (CreateSession, INITIALIZE UPDATE, EXTERNAL AUTHENTICATE), ECKey its own number (S-17).
  countApdus(applet_.Sent() - sent_before);
  const bool early = (opened.error == Error::InvalidArgument) ||
                     (opened.error == Error::AuthLocked) || (opened.error == Error::WrongState) ||
                     (opened.error == Error::Unsupported);
  last_detail_ = opened.detail;
  if (opened.ok()) {
    session_ = kind;
    role_ = RoleOf(credential);
    session_credential_ = credential;
    state_ = DeviceState::InSession;
    last_detail_ = Detail{};
    return opened;
  }
  if (early) {
    return opened; // refused before anything was sent
  }
  if (opened.error == Error::ThroughputLimited) {
    static_cast<void>(onThroughput(Command::CreateSession));
    return Result<void>::Failure(Error::ThroughputLimited, last_detail_);
  }
  // A failed handshake after CreateSession leaves a session the chip cannot close (AN12543
  // 3.6.5, errata APP.2), and a lost frame leaves the stack out of step: select the applet again
  // now, which also ends any chip-side session (S-07).
  teardown();
  if (link_.State() == t1::LinkState::Dead) {
    state_ = DeviceState::Dead;
    return opened;
  }
  state_ = reselect().ok() ? DeviceState::Ready : DeviceState::NeedsReopen;
  if (link_.State() == t1::LinkState::Dead) {
    state_ = DeviceState::Dead;
  }
  return opened;
}

template <PortSet P>
Result<void> Device<P>::BeginUserIdSession(const UserIdSessionParams& params) noexcept {
  const Error ready = sessionReady();
  if (ready != Error::Ok) {
    return refuse<void>(Command::CreateSession, ready);
  }
  if ((userid::CheckValue(params.pin.size()) != Error::Ok) || (params.credential.value == 0U)) {
    return refuse<void>(Command::VerifySessionUserId, Error::InvalidArgument);
  }
  wire_.SetClass(CommandClass::Fast);
  const uint32_t before = applet_.Sent();
  return afterSessionOpen(userid_.Open(params.credential, params.pin), SessionKind::UserId,
                          params.credential, before);
}

template <PortSet P>
Result<void> Device<P>::BeginAesKeySession(const AesKeySessionParams& params) noexcept {
  const Error ready = sessionReady();
  if (ready != Error::Ok) {
    return refuse<void>(Command::CreateSession, ready);
  }
  scp03::ChannelParams p{};
  p.keys = params.keys;
  p.level = params.level;
  p.length = scp03::KeyLength::Aes128;
  p.jos2_counter_rule = false; // applet sessions advance the counter on every command
  p.kind = scp03::ChannelKind::AesKeySession;
  p.credential = params.credential;
  wire_.SetClass(CommandClass::Fast);
  const uint32_t before = applet_.Sent();
  return afterSessionOpen(aes_.Open(p), SessionKind::AesKey, params.credential, before);
}

template <PortSet P>
Result<void> Device<P>::BeginEcKeySession(const eckey::SessionParams& params) noexcept {
  const Error ready = sessionReady();
  if (ready != Error::Ok) {
    return refuse<void>(Command::CreateSession, ready);
  }
  // The chip's ECKA key must be the one verified by attestation in this open (AN12543 3.6.3.3).
  bool same = ecka_verified_ && (params.se_public_key.size() == ecka_.size());
  for (std::size_t i = 0U; same && (i < ecka_.size()); ++i) {
    same = params.se_public_key[i] == ecka_[i];
  }
  if (!same) {
    return refuse<void>(Command::EcKeySessionInternalAuthenticate, Error::WrongState);
  }
  eckey::SessionParams p = params;
  p.verify_receipt = detail::VerifyReceipt(config_.verify_eckey_receipt, params.verify_receipt);
  wire_.SetClass(CommandClass::Fast);
  const uint32_t before = applet_.Sent();
  return afterSessionOpen(eckey_.Open(p), SessionKind::EcKey, params.credential, before);
}

template <PortSet P>
Result<void> Device<P>::EndSession() noexcept {
  if (state_ == DeviceState::Closed) {
    return refuse<void>(Command::CloseSession, Error::NotInitialized);
  }
  Result<void> closed = Result<void>::Success();
  switch (session_) {
  case SessionKind::UserId:
    closed = userid_.Close();
    break;
  case SessionKind::AesKey:
    closed = aes_.Close();
    break;
  case SessionKind::EcKey:
    closed = eckey_.Close();
    break;
  case SessionKind::None:
  default:
    return Result<void>::Success(); // never CloseSession without a session (errata APP.2)
  }
  countApdus(1U);
  session_ = SessionKind::None;
  role_ = AuthRole::None;
  session_credential_ = ObjectId{};
  state_ = DeviceState::Ready;
  if (closed.ok()) {
    return closed;
  }
  // Not confirmed: the session may be half open. Select the applet again (S-07).
  teardown();
  const Result<void> back = reselect();
  state_ = back.ok() ? DeviceState::Ready : DeviceState::NeedsReopen;
  if (link_.State() == t1::LinkState::Dead) {
    state_ = DeviceState::Dead;
  }
  return back;
}

template <PortSet P>
Result<void> Device<P>::RefreshSession() noexcept {
  if ((state_ == DeviceState::InSession) && (session_ != SessionKind::None)) {
    const Error admitted = admit(Command::RefreshSession, nullptr);
    if (admitted != Error::Ok) {
      return refuse<void>(Command::RefreshSession, admitted);
    }
    const auto r = run<Command::RefreshSession>(RefreshSessionArgs{});
    return r.ok() ? Result<void>::Success() : Result<void>::Failure(r.error, r.detail);
  }
  return refuse<void>(Command::RefreshSession,
                      (state_ == DeviceState::Closed) ? Error::NotInitialized : Error::WrongState);
}

template <PortSet P>
Result<attest::Checked> Device<P>::verifyAttested(const attest::Sent& sent,
                                                  const AttestedRead& answer, ByteSpan data,
                                                  ByteSpan signature,
                                                  std::span<const uint8_t, 65> key) noexcept {
  if (caps_.generation == AppletGeneration::V7) {
    attest::Verifier<P, AttestationFormat::V2> v(*ports_);
    return v.Verify(sent, answer, data, signature, key, last_timestamp_);
  }
  attest::Verifier<P, AttestationFormat::V1> v(*ports_);
  return v.Verify(sent, answer, data, signature, key, last_timestamp_);
}

template <PortSet P>
Result<attest::Checked> Device<P>::ReadVerified(
    const ReadObjectAttestedArgs& args, std::span<const uint8_t, 65> attestation_public) noexcept {
  const Result<AttestedRead> read = ReadAttested(args);
  if (!read.ok()) {
    return Result<attest::Checked>::Failure(read.error, read.detail);
  }
  attest::Sent sent{};
  sent.command =
      ByteSpan{sent_.data(), (sent_length_ < sent_.size()) ? sent_length_ : sent_.size()};
  // Under secure messaging the applet hashes the command as the channel hands it over after
  // unwrapping: header, the shortest Lc form and the data (docs/ambiguities.md, "Attested read
  // under secure messaging"; not verified on a chip). The rewritten command is kept in the
  // answer's `echoed_command`, which the device filled with the command it encoded.
  AttestedRead answer = read.value;
  if (SecureMessagingActive()) {
    MutableByteSpan echoed{answer.echoed_command.bytes};
    const ByteSpan shortest = detail::ShortestLcForm(sent.command, echoed);
    const std::size_t n = (shortest.size() < echoed.size()) ? shortest.size() : echoed.size();
    for (std::size_t i = 0U; i < n; ++i) {
      echoed[i] = shortest[i];
    }
    answer.echoed_command.length = n;
    sent.command = ByteSpan{answer.echoed_command.bytes.data(), n};
  }
  sent.algo = args.algo;
  sent.signed_tlvs = ByteSpan{signed_.data(), signed_length_};
  sent.nonce = last_nonce_; // the nonce the device drew from the crypto port for this read
  const bool sizes = (read.value.data_length <= args.data_out.size()) &&
                     (read.value.signature_length <= args.signature_out.size());
  if (!sizes) {
    return Result<attest::Checked>::Failure(
        Error::FrameError, detail::DeviceDetail(Command::ReadObjectAttested, last_sw_, 9U));
  }
  const ByteSpan data{args.data_out.data(), read.value.data_length};
  const ByteSpan sig{args.signature_out.data(), read.value.signature_length};
  const Result<attest::Checked> checked =
      verifyAttested(sent, answer, data, sig, attestation_public);
  if (!checked.ok()) {
    return Result<attest::Checked>::Failure(
        checked.error, detail::DeviceDetail(Command::ReadObjectAttested, last_sw_, 8U));
  }
  last_timestamp_ = checked.value.timestamp;
  return checked;
}

template <PortSet P>
Result<void> Device<P>::ReadEckaPublicKey(ObjectId attestation_key,
                                          std::span<const uint8_t, 65> attestation_public,
                                          std::span<uint8_t, 65> out) noexcept {
  std::array<uint8_t, 65> point{};
  std::array<uint8_t, 80> signature{};
  ReadObjectAttestedArgs args{};
  args.id = FromReserved(ReservedId::EcKeySession);
  args.attestation_key = attestation_key;
  args.algo = AttestationAlgo::EcSha256;
  args.data_out = MutableByteSpan{point};
  args.signature_out = MutableByteSpan{signature};
  const Result<attest::Checked> checked = ReadVerified(args, attestation_public);
  if (!checked.ok()) {
    return Result<void>::Failure(checked.error, checked.detail);
  }
  if ((checked.value.data_length != 65U) || (point[0] != 0x04U)) {
    return Result<void>::Failure(Error::FrameError,
                                 detail::DeviceDetail(Command::ReadObjectAttested, last_sw_, 9U));
  }
  ecka_ = point;
  ecka_verified_ = true;
  for (std::size_t i = 0U; i < out.size(); ++i) {
    out[i] = point[i];
  }
  return Result<void>::Success();
}

// --- Self test, raw access, transactions -----------------------------------------------------

template <PortSet P>
Result<bool> Device<P>::TriggerSelfTest(uint16_t test,
                                        irreversible::ResetExpected acknowledgement) noexcept {
  static_cast<void>(acknowledgement);
  const Error admitted = admit(Command::TriggerSelfTest, nullptr);
  if (admitted != Error::Ok) {
    return refuse<bool>(Command::TriggerSelfTest, admitted);
  }
  const auto r = run<Command::TriggerSelfTest>(SelfTestArgs{test});
  if (r.ok()) {
    return Result<bool>::Success(r.value.passed);
  }
  if ((r.error == Error::Timeout) || (r.error == Error::Resynced) ||
      (r.error == Error::NeedsReselect)) {
    // No answer: the chip reset itself (AN12543 4.6.6). Bring the stack back and say so.
    const Result<void> back = Recover();
    if (!back.ok()) {
      return Result<bool>::Failure(back.error, back.detail);
    }
    return Result<bool>::Failure(Error::Resynced,
                                 detail::DeviceDetail(Command::TriggerSelfTest, 0U, 10U));
  }
  return Result<bool>::Failure(r.error, r.detail);
}

template <PortSet P>
Error Device<P>::rawCheck(ByteSpan command, MutableByteSpan response) const noexcept {
  if (!config_.allow_lab_override) {
    return Error::Unsupported;
  }
  if (!IsOpen()) {
    return Error::NotInitialized;
  }
  if (state_ == DeviceState::NeedsReopen) {
    return Error::NeedsReselect;
  }
  if (detail::RawRefused(command)) {
    return Error::Unsupported;
  }
  if (command.empty() || (command.size() > tx_.size()) || (response.size() < 2U)) {
    return Error::InvalidArgument;
  }
  return Error::Ok;
}

template <PortSet P>
Result<std::size_t> Device<P>::ReadRaw(ByteSpan command, MutableByteSpan response) noexcept {
  const Error checked = rawCheck(command, response);
  if (checked != Error::Ok) {
    return refuse<std::size_t>(Command::SendCardManagerCmd, checked);
  }
  for (std::size_t i = 0U; i < command.size(); ++i) {
    tx_[i] = command[i];
  }
  const Result<ByteSpan> body = exchange(Command::SendCardManagerCmd, command.size());
  const bool answered =
      body.ok() || ((last_detail_.sw != 0U) && (body.error != Error::ThroughputLimited) &&
                    (body.error != Error::NeedsReselect));
  if (!answered) {
    return Result<std::size_t>::Failure(body.error, body.detail);
  }
  const std::size_t n = body.ok() ? (body.value.size() + 2U) : 2U;
  if (response.size() < n) {
    Zeroize(MutableByteSpan{rx_});
    return refuse<std::size_t>(Command::SendCardManagerCmd, Error::BufferTooSmall);
  }
  for (std::size_t i = 0U; (i + 2U) < n; ++i) {
    response[i] = rx_[i];
  }
  response[n - 2U] = static_cast<uint8_t>(static_cast<uint32_t>(last_sw_) >> 8U);
  response[n - 1U] = static_cast<uint8_t>(static_cast<uint32_t>(last_sw_) & 0xFFU);
  Zeroize(MutableByteSpan{rx_});
  return Result<std::size_t>::Success(n);
}

template <PortSet P>
Result<void> Device<P>::BeginTransaction() noexcept {
  if (!IsOpen()) {
    return refuse<void>(Command::SelectApplet, Error::NotInitialized);
  }
  if (in_transaction_) {
    return refuse<void>(Command::SelectApplet, Error::Busy);
  }
  in_transaction_ = true;
  return Result<void>::Success();
}

template <PortSet P>
Result<void> Device<P>::EndTransaction() noexcept {
  in_transaction_ = false;
  return Result<void>::Success();
}

// --- Management and crypto wrappers ----------------------------------------------------------

template <PortSet P>
Result<AppletInfo> Device<P>::GetVersion() noexcept {
  return Execute<Command::GetVersion>(Empty{});
}

template <PortSet P>
Result<uint32_t> Device<P>::FreeMemory(MemoryType memory) noexcept {
  const auto r = Execute<Command::GetFreeMemory>(FreeMemoryArgs{memory});
  return r.ok() ? Result<uint32_t>::Success(r.value.value)
                : Result<uint32_t>::Failure(r.error, r.detail);
}

template <PortSet P>
Result<void> Device<P>::GetRandom(MutableByteSpan out) noexcept {
  const auto r = Execute<Command::GetRandom>(GetRandomArgs{out});
  return r.ok() ? Result<void>::Success() : Result<void>::Failure(r.error, r.detail);
}

template <PortSet P>
Result<std::size_t> Device<P>::EcdsaSign(ObjectId key, EcSignAlgo algo, ByteSpan digest,
                                         MutableByteSpan signature) noexcept {
  const auto r = Execute<Command::EcdsaSign>(SignArgs{key, algo, digest, signature});
  return r.ok() ? Result<std::size_t>::Success(r.value.length)
                : Result<std::size_t>::Failure(r.error, r.detail);
}

template <PortSet P>
Result<bool> Device<P>::EcdsaVerify(ObjectId key, EcSignAlgo algo, ByteSpan digest,
                                    ByteSpan signature) noexcept {
  const auto r = Execute<Command::EcdsaVerify>(VerifyArgs{key, algo, digest, signature});
  return r.ok() ? Result<bool>::Success(r.value.value) : Result<bool>::Failure(r.error, r.detail);
}

} // namespace se05x

#endif // SE05X_DEVICE_CRYPTO_IPP
