/**
 * @file se05x_device_core.ipp
 * @brief Device lifecycle: open, close, recovery, power, the transport stack and the exchange of
 * one command, included by `se05x_device.hpp`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#ifndef SE05X_DEVICE_CORE_IPP
#define SE05X_DEVICE_CORE_IPP

namespace se05x {

namespace detail {
/// The detail of an error of the device layer.
constexpr Detail DeviceDetail(Command command, uint16_t sw, uint8_t step) noexcept {
  return Detail{.sw = sw,
                .command = static_cast<uint8_t>(ToUnderlying(command)),
                .layer = Layer::Device,
                .step = step,
                .attempts_left = 0xFFU};
}
/// SW 0x66A6: the applet refuses every command until it is reset (AN14028 2.3.1, S-17).
inline constexpr uint16_t kSwThroughputLimited = 0x66A6U;
/// SW 0x6A82: no such object, or no such applet at a select.
inline constexpr uint16_t kSwNotFound = 0x6A82U;
/// One bit per `EcCurve` whose SetIndicator in a ReadECCurveList answer is SET (AN12543 4.8.4:
/// one byte per curve id below 0x40, SET is 0x02).
inline uint32_t CurvesPresent(ByteSpan list) noexcept {
  uint32_t bits = 0U;
  for (std::size_t i = 0U; (i < list.size()) && (i < 0x3FU); ++i) {
    EcCurve curve{};
    if ((list[i] == 0x02U) && apdu::CurveFromWire(static_cast<uint8_t>(i + 1U), curve)) {
      bits |= uint32_t{1} << static_cast<uint32_t>(ToUnderlying(curve));
    }
  }
  return bits;
}
/// The lifecycle values of ReadState (AN12543 Table 109; LockState LOCKED, SCP_REQUIRED).
inline constexpr uint8_t kStateLocked = 0x01U;
inline constexpr uint8_t kStateScpRequired = 0x01U;
} // namespace detail

// --- Configuration ---------------------------------------------------------------------------

template <PortSet P>
Result<void> Device<P>::SetPlatformKeys(const scp03::ChannelParams& params) noexcept {
  if (IsOpen()) {
    return Result<void>::Failure(Error::WrongState,
                                 detail::DeviceDetail(Command::SelectApplet, 0U, 0U));
  }
  if ((params.kind != scp03::ChannelKind::Platform) || !params.keys.enc.IsValid() ||
      !params.keys.mac.IsValid()) {
    return Result<void>::Failure(Error::InvalidArgument,
                                 detail::DeviceDetail(Command::SelectApplet, 0U, 0U));
  }
  platform_params_ = params;
  platform_keys_ = true;
  return Result<void>::Success();
}

// --- Open, close, recovery -------------------------------------------------------------------

template <PortSet P>
Result<void> Device<P>::Open() noexcept {
  if (IsOpen()) {
    return Result<void>::Failure(Error::WrongState,
                                 detail::DeviceDetail(Command::SelectApplet, 0U, 0U));
  }
  if (Validate(config_) != Error::Ok) {
    return Result<void>::Failure(Error::InvalidArgument,
                                 detail::DeviceDetail(Command::SelectApplet, 0U, 0U));
  }
  const Result<void> link = link_.Open();
  if (!link.ok()) {
    state_ = DeviceState::Closed;
    return link;
  }
  return bringUp();
}

template <PortSet P>
Result<void> Device<P>::bringUp() noexcept {
  // `apdu_count_` is never reset: the throughput window of the chip spans every open (S-17).
  ++opens_;
  caps_ = Capabilities{};
  ecka_verified_ = false;
  // `last_timestamp_` survives a reopen: the persistent part of the chip timestamp grows with every
  // session open (AN12543 3.9 p. 42), so an older answer stays refused across a reset (S-09).
  applet_.RequirePlatform(false);
  const auto limit = config_.auth_attempt_limit;
  platform_.SetAuthAttemptLimit(limit);
  aes_.SetAuthAttemptLimit(limit);
  eckey_.SetAuthAttemptLimit(limit);
  userid_.SetAuthAttemptLimit(limit);
  AppletInfo info{};
  std::array<uint8_t, kExtFeatureLength> ext{};
  bool has_ext = false;
  uint16_t oef = 0U;
  Result<void> r = identify(info, ext, has_ext, oef);
  if (r.ok()) {
    r = probeAndDerive(info, has_ext ? ByteSpan{ext} : ByteSpan{}, oef);
  }
  if (!r.ok()) {
    teardown();
    static_cast<void>(link_.Close());
    state_ = DeviceState::Closed;
    caps_ = Capabilities{};
    wipeBuffers();
  }
  return r;
}

template <PortSet P>
Result<void> Device<P>::identify(AppletInfo& info, std::array<uint8_t, kExtFeatureLength>& ext,
                                 bool& has_ext, uint16_t& oef) noexcept {
  // The OEF id from the card manager (AN12543 Table 8 note; AN13030 pp. 227-228). A card manager
  // that does not answer leaves it 0 ("not read"); a transport failure ends the open.
  gp::CardManager<P, Wire> cm(*ports_, wire_);
  const Result<void> cm_selected = cm.SelectCardManager();
  countApdus(1U);
  if (cm_selected.ok()) {
    const Result<CardId> card = cm.GetCardIdentification();
    countApdus(1U);
    if (card.ok()) {
      oef = card.value.oef_id;
    } else if ((card.error != Error::ChipSwUnknown) && (card.error != Error::FrameError)) {
      return Result<void>::Failure(card.error, card.detail);
    } else {
      oef = 0U;
    }
  } else if (cm_selected.error != Error::ChipSwUnknown) {
    return cm_selected;
  } else {
    oef = 0U;
  }
  const Result<AppletInfo> sel = selectApplet();
  if (!sel.ok()) {
    return Result<void>::Failure(sel.error, sel.detail);
  }
  info = sel.value;
  if (info.version.Generation() != AppletGeneration::V3) {
    const Result<ExtFeatures> e = plain<Command::GetExtVersion>(Empty{});
    if (e.ok() && (e.value.length == kExtFeatureLength)) {
      for (std::size_t i = 0U; i < kExtFeatureLength; ++i) {
        ext[i] = e.value.bytes[i];
      }
      has_ext = true;
    } else if (info.version.Generation() == AppletGeneration::V7) {
      return Result<void>::Failure(e.ok() ? Error::FrameError : e.error, e.detail);
    } else {
      has_ext = false; // applet 6.x: either form (gate::Derive)
    }
  }
  return Result<void>::Success();
}

template <PortSet P>
Result<void> Device<P>::probeAndDerive(const AppletInfo& info, ByteSpan ext,
                                       uint16_t oef) noexcept {
  Result<Capabilities> derived = gate::Derive(info, ext, oef, gate::ProbeResult{});
  if (!derived.ok()) {
    return Result<void>::Failure(derived.error, derived.detail);
  }
  caps_ = derived.value;
  const t1::LinkParams& lp = link_.Params();
  caps_.flavour = lp.flavour;
  caps_.ifsc = lp.ifsc;
  caps_.bwt_ms = lp.bwt_ms;
  caps_.stretching = lp.stretching;
  Result<void> r = readLifecycle();
  if (r.ok()) {
    r = openPlatform();
  }
  if (!r.ok() || !config_.probe_capabilities) {
    state_ = r.ok() ? DeviceState::Ready : state_;
    return r;
  }
  state_ = DeviceState::Ready;
  const Result<gate::ProbeResult> probe = runProbes();
  if (!probe.ok()) {
    return Result<void>::Failure(probe.error, probe.detail);
  }
  const Capabilities state = caps_;
  derived = gate::Derive(info, ext, oef, probe.value);
  if (!derived.ok()) {
    return Result<void>::Failure(derived.error, derived.detail);
  }
  caps_ = derived.value;
  caps_.flavour = state.flavour;
  caps_.ifsc = state.ifsc;
  caps_.bwt_ms = state.bwt_ms;
  caps_.stretching = state.stretching;
  caps_.applet_locked = state.applet_locked;
  caps_.platform_scp_required = state.platform_scp_required;
  caps_.platform_scp_active = state.platform_scp_active;
  return Result<void>::Success();
}

template <PortSet P>
Result<gate::ProbeResult> Device<P>::runProbes() noexcept {
  // The probes (A4, A5) run as the commands they are, under platform SCP03 when it is open. A
  // refusal by the chip means "absent"; a transport failure ends the open.
  probing_ = true;
  gate::ProbeResult probe{};
  probe.probed = true;
  Result<gate::ProbeResult> out = Result<gate::ProbeResult>::Success(probe);
  if (caps_.allowed.Contains(Command::DigestOneShot)) {
    constexpr std::array<uint8_t, 1> kOne{0x00U};
    std::array<uint8_t, 64> digest{};
    const auto d = Execute<Command::DigestOneShot>(
        DigestOneShotArgs{DigestMode::Sha256, ByteSpan{kOne}, MutableByteSpan{digest}});
    out.value.digest_works = d.ok();
    if (!d.ok() && (state_ != DeviceState::Ready)) {
      out = Result<gate::ProbeResult>::Failure(d.error, d.detail);
    }
  }
  if (out.ok() && caps_.allowed.Contains(Command::ReadEcCurveList)) {
    const auto list = Execute<Command::ReadEcCurveList>(Empty{});
    if (list.ok()) {
      out.value.curves_present = detail::CurvesPresent(list.value.View());
    } else if (state_ != DeviceState::Ready) {
      out = Result<gate::ProbeResult>::Failure(list.error, list.detail);
    } else {
      // Absent: no curve list.
    }
  }
  probing_ = false;
  return out;
}

template <PortSet P>
Result<void> Device<P>::readLifecycle() noexcept {
  if (caps_.generation != AppletGeneration::V7) {
    // Applet 3.x has no ReadState: SE050F makes platform SCP03 mandatory (FIPS 140-2 build).
    caps_.platform_scp_required = caps_.family == Family::Se050F;
    caps_.applet_locked = false;
    return Result<void>::Success();
  }
  // ReadState is answered without platform SCP03 and while locked (AN12543 4.6.7).
  const Result<SmallBlob> st = plain<Command::ReadState>(Empty{});
  if (!st.ok()) {
    return Result<void>::Failure(st.error, st.detail);
  }
  if (st.value.length < 3U) {
    return Result<void>::Failure(Error::FrameError,
                                 detail::DeviceDetail(Command::ReadState, last_sw_, 0U));
  }
  caps_.applet_locked = st.value.bytes[0] == detail::kStateLocked;
  caps_.platform_scp_required = st.value.bytes[2] == detail::kStateScpRequired;
  return Result<void>::Success();
}

template <PortSet P>
Result<void> Device<P>::openPlatform() noexcept {
  const bool wanted = (config_.scp_policy == ScpPolicy::Require) ||
                      ((config_.scp_policy == ScpPolicy::Auto) && caps_.platform_scp_required);
  if (!wanted) {
    if (caps_.platform_scp_required) {
      return Result<void>::Failure(Error::WrongState,
                                   detail::DeviceDetail(Command::SelectApplet, 0U, 1U));
    }
    return Result<void>::Success(); // a plain bus: `platform_scp_active` stays false (S-13)
  }
  if (!platform_keys_) {
    return Result<void>::Failure(Error::WrongState,
                                 detail::DeviceDetail(Command::SelectApplet, 0U, 2U));
  }
  wire_.SetClass(CommandClass::Fast);
  countApdus(2U);
  const Result<void> opened = platform_.Open(platform_params_);
  if (!opened.ok()) {
    return opened;
  }
  applet_.RequirePlatform(true);
  caps_.platform_scp_active = true;
  return Result<void>::Success();
}

template <PortSet P>
Result<AppletInfo> Device<P>::selectApplet() noexcept {
  const Result<AppletInfo> sel = plain<Command::SelectApplet>(Empty{});
  if ((!sel.ok()) && (last_sw_ == detail::kSwNotFound)) {
    return Result<AppletInfo>::Failure(Error::Counterfeit, sel.detail); // no IoT applet
  }
  return sel;
}

template <PortSet P>
Result<void> Device<P>::Close() noexcept {
  if (state_ == DeviceState::Closed) {
    wipeBuffers();
    return Result<void>::Success();
  }
  if ((state_ == DeviceState::InSession) && (link_.State() == t1::LinkState::Idle)) {
    static_cast<void>(EndSession()); // best effort; keys are released either way
  }
  teardown();
  const Result<void> closed = link_.Close(); // sent from every state (RD-05)
  finishClose();
  return closed;
}

template <PortSet P>
void Device<P>::finishClose() noexcept {
  applet_.RequirePlatform(false);
  state_ = DeviceState::Closed;
  caps_.platform_scp_active = false;
  ecka_verified_ = false;
  ecka_ = std::array<uint8_t, 65>{};
  in_transaction_ = false;
  wipeBuffers();
}

template <PortSet P>
Result<void> Device<P>::Recover() noexcept {
  if (state_ == DeviceState::Closed) {
    return Result<void>::Failure(Error::NotInitialized,
                                 detail::DeviceDetail(Command::SelectApplet, 0U, 0U));
  }
  if ((state_ == DeviceState::Dead) || (link_.State() == t1::LinkState::Dead)) {
    state_ = DeviceState::Dead;
    return Result<void>::Failure(Error::TransportDead,
                                 detail::DeviceDetail(Command::SelectApplet, 0U, 0U));
  }
  teardown();
  Result<void> r = reselect();
  const bool transport = !r.ok() && (r.error != Error::DeviceIdMismatch) &&
                         (r.error != Error::ThroughputLimited) && (r.error != Error::Counterfeit) &&
                         (r.detail.sw == 0U);
  if (transport) {
    // One climb of the link's ladder from the resynchronisation, then one more select.
    const Result<void> climbed = link_.Recover(t1::Rung::Resync);
    if (climbed.error == Error::TransportDead) {
      state_ = DeviceState::Dead;
      return climbed;
    }
    r = reselect();
  }
  state_ = r.ok() ? DeviceState::Ready : DeviceState::NeedsReopen;
  if (link_.State() == t1::LinkState::Dead) {
    state_ = DeviceState::Dead;
  }
  return r;
}

template <PortSet P>
Result<void> Device<P>::reselect() noexcept {
  const Result<AppletInfo> sel = selectApplet();
  if (!sel.ok()) {
    return Result<void>::Failure(sel.error, sel.detail);
  }
  if ((sel.value.version.Packed() != caps_.applet.Packed()) ||
      (sel.value.applet_config != caps_.applet_config)) {
    return Result<void>::Failure(Error::DeviceIdMismatch,
                                 detail::DeviceDetail(Command::SelectApplet, last_sw_, 1U));
  }
  const Result<void> lifecycle = readLifecycle();
  if (!lifecycle.ok()) {
    return lifecycle;
  }
  if (!applet_.PlatformRequired()) {
    return Result<void>::Success();
  }
  wire_.SetClass(CommandClass::Fast);
  countApdus(2U);
  const Result<void> opened = platform_.Open(platform_params_);
  caps_.platform_scp_active = opened.ok();
  return opened;
}

template <PortSet P>
void Device<P>::teardown() noexcept {
  // Release every session key and forget every session without a byte on the wire: the blocked
  // stage refuses the best-effort CloseSession of each (errata APP.2).
  applet_.Block(true);
  static_cast<void>(userid_.Close());
  static_cast<void>(aes_.Close());
  static_cast<void>(eckey_.Close());
  applet_.Block(false);
  static_cast<void>(platform_.Close()); // platform kind: local only
  caps_.platform_scp_active = false;
  session_ = SessionKind::None;
  role_ = AuthRole::None;
  session_credential_ = ObjectId{};
  if (state_ == DeviceState::InSession) {
    state_ = DeviceState::Ready;
  }
}

template <PortSet P>
void Device<P>::wipeBuffers() noexcept {
  Zeroize(MutableByteSpan{tx_});
  Zeroize(MutableByteSpan{rx_});
}

template <PortSet P>
Result<void> Device<P>::PowerCycle() noexcept
  requires(P::kHasReset)
{
  teardown();
  if ((state_ == DeviceState::Closed) || (link_.State() == t1::LinkState::Closed)) {
    finishClose();
    if (!ports_->GetReset().PowerCycle()) {
      return Result<void>::Failure(Error::Bus, detail::DeviceDetail(Command::SelectApplet, 0U, 0U));
    }
    return Open();
  }
  const Result<void> reset = link_.Reset(t1::ResetKind::PowerCycle);
  if (!reset.ok()) {
    finishClose();
    static_cast<void>(link_.Close());
    return reset;
  }
  return bringUp();
}

template <PortSet P>
Result<void> Device<P>::DeepPowerDown() noexcept {
  if (state_ == DeviceState::Closed) {
    return Result<void>::Failure(Error::NotInitialized,
                                 detail::DeviceDetail(Command::SelectApplet, 0U, 0U));
  }
  teardown();
  const Result<void> down = link_.DeepPowerDown();
  if (down.error == Error::Unsupported) {
    return down; // the chip did not enter it; the link and the device stay as they were
  }
  finishClose();
  return down;
}

// --- Admission and exchange ------------------------------------------------------------------

template <PortSet P>
Error Device<P>::admit(Command command, const Policy* policy) const noexcept {
  if ((state_ == DeviceState::Closed)) {
    return Error::NotInitialized;
  }
  if (state_ == DeviceState::Dead) {
    return Error::TransportDead;
  }
  if (state_ == DeviceState::NeedsReopen) {
    return Error::NeedsReselect;
  }
  const Error gated = gate::Check(caps_, config_, command);
  if (gated != Error::Ok) {
    return gated;
  }
  const AuthRole needed = RequiredRole(command);
  if ((needed != AuthRole::None) && (role_ != needed)) {
    return Error::ConditionsNotSatisfied; // the chip would refuse it: nothing is sent
  }
  if ((policy != nullptr) && !policy->IsEmpty() && (policy->Generation() != caps_.generation)) {
    return Error::PolicyInvalid;
  }
  return Error::Ok;
}

template <PortSet P>
template <typename T>
Result<T> Device<P>::refuse(Command command, Error error) noexcept {
  last_detail_ = detail::DeviceDetail(command, 0U, 0U);
  return Result<T>::Failure(error, last_detail_);
}

template <PortSet P>
Result<std::size_t> Device<P>::transmit(ByteSpan command) noexcept {
  countApdus(1U);
  const MutableByteSpan rsp{rx_};
  switch (session_) {
  case SessionKind::UserId:
    return userid_.Transceive(command, rsp);
  case SessionKind::AesKey:
    return aes_.Transceive(command, rsp);
  case SessionKind::EcKey:
    return eckey_.Transceive(command, rsp);
  case SessionKind::None:
  default:
    break;
  }
  return applet_.Transceive(command, rsp);
}

template <PortSet P>
Result<ByteSpan> Device<P>::exchange(Command command, std::size_t length) noexcept {
  wire_.SetClass(detail::ClassOf(command));
  // The reply comes unwrapped (AN12543 4.20.5 p. 154): only the session now open accepts it.
  if (ReplyEndsSession(command) && (session_ == SessionKind::AesKey)) {
    aes_.ExpectSessionEnd();
  } else if (ReplyEndsSession(command) && (session_ == SessionKind::EcKey)) {
    eckey_.ExpectSessionEnd();
  } else {
    // Any other command, or no secure-messaging session: answers are unwrapped as usual.
  }
  const Result<std::size_t> got = transmit(ByteSpan{tx_.data(), length});
  Zeroize(MutableByteSpan{tx_}.first(length)); // the command may carry a secret (S-01)
  if (!got.ok()) {
    return afterTransport(command, got);
  }
  const Result<apdu::ResponseView> split = apdu::SplitResponse(ByteSpan{rx_.data(), got.value});
  if (!split.ok()) {
    last_detail_ = detail::DeviceDetail(command, 0U, 2U);
    return Result<ByteSpan>::Failure(Error::FrameError, last_detail_);
  }
  last_sw_ = split.value.sw;
  if (last_sw_ == detail::kSwThroughputLimited) {
    return onThroughput(command);
  }
  const Error mapped = apdu::StatusToError(command, last_sw_);
  if (mapped != Error::Ok) {
    if ((mapped == Error::NeedsReselect) && !probing_) {
      teardown();
      state_ = DeviceState::NeedsReopen; // the applet is no longer selected
    }
    last_detail_ = detail::DeviceDetail(command, last_sw_, 3U);
    return Result<ByteSpan>::Failure(mapped, last_detail_);
  }
  last_detail_ = Detail{};
  return Result<ByteSpan>::Success(split.value.body);
}

template <PortSet P>
Result<ByteSpan> Device<P>::afterTransport(Command command, Result<std::size_t> failed) noexcept {
  last_detail_ = failed.detail;
  last_detail_.command = static_cast<uint8_t>(detail::ToUnderlying(command));
  const bool secured = (session_ != SessionKind::None) || applet_.PlatformRequired();
  if ((failed.error == Error::BufferTooSmall) && secured) {
    return Result<ByteSpan>::Failure(failed.error, last_detail_); // checked and dropped; open
  }
  if ((failed.error == Error::TransportDead) || (link_.State() == t1::LinkState::Dead)) {
    teardown();
    state_ = DeviceState::Dead;
  } else if (secured || (failed.error == Error::NeedsReselect) ||
             (link_.State() == t1::LinkState::NeedsReselect)) {
    // Every layer above the link is gone or out of step (S-07, S-15).
    teardown();
    state_ = DeviceState::NeedsReopen;
  } else {
    // A plain command without a session: the link resynchronises before the next one.
  }
  return Result<ByteSpan>::Failure(failed.error, last_detail_);
}

template <PortSet P>
Result<ByteSpan> Device<P>::onThroughput(Command command) noexcept {
  // S-17: drop the sessions, reset the chip once (the ChipReset rung), select the applet again;
  // the command is not repeated.
  teardown();
  last_detail_ = detail::DeviceDetail(command, detail::kSwThroughputLimited, 4U);
  const Result<void> reset = link_.Recover(t1::Rung::ChipReset);
  if ((reset.error == Error::TransportDead) || (link_.State() == t1::LinkState::Dead)) {
    state_ = DeviceState::Dead;
    return Result<ByteSpan>::Failure(Error::ThroughputLimited, last_detail_);
  }
  const Result<void> back = reselect();
  state_ = back.ok() ? DeviceState::Ready : DeviceState::NeedsReopen;
  last_sw_ = detail::kSwThroughputLimited;
  last_detail_.step = back.ok() ? 5U : 6U;
  return Result<ByteSpan>::Failure(Error::ThroughputLimited, last_detail_);
}

template <PortSet P>
template <Command C>
Result<ReplyOf<C>> Device<P>::plain(const ArgsOf<C>& args) noexcept {
  // A command straight on the link (select, ReadState, GetExtVersion): never under SCP03.
  const Result<std::size_t> enc = Codec<C>::Encode(args, MutableByteSpan{tx_});
  if (!enc.ok()) {
    return Result<ReplyOf<C>>::Failure(enc.error, detail::DeviceDetail(C, 0U, 0U));
  }
  wire_.SetClass(CommandClass::Fast);
  countApdus(1U);
  const Result<std::size_t> got =
      wire_.Transceive(ByteSpan{tx_.data(), enc.value}, MutableByteSpan{rx_});
  Zeroize(MutableByteSpan{tx_});
  if (!got.ok()) {
    last_sw_ = 0U;
    return Result<ReplyOf<C>>::Failure(got.error, got.detail);
  }
  const Result<apdu::ResponseView> split = apdu::SplitResponse(ByteSpan{rx_.data(), got.value});
  last_sw_ = split.ok() ? split.value.sw : 0U;
  const Error mapped = split.ok() ? apdu::StatusToError(C, last_sw_) : Error::FrameError;
  if (mapped != Error::Ok) {
    Zeroize(MutableByteSpan{rx_});
    return Result<ReplyOf<C>>::Failure(mapped, detail::DeviceDetail(C, last_sw_, 1U));
  }
  ReplyOf<C> reply{};
  const Result<void> dec = Codec<C>::Decode(args, split.value.body, reply);
  Zeroize(MutableByteSpan{rx_});
  if (!dec.ok()) {
    return Result<ReplyOf<C>>::Failure(dec.error, detail::DeviceDetail(C, last_sw_, 2U));
  }
  return Result<ReplyOf<C>>::Success(reply);
}

} // namespace se05x

#endif // SE05X_DEVICE_CORE_IPP
