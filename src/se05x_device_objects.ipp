/**
 * @file se05x_device_objects.ipp
 * @brief Device execution (`Execute`, `ExecuteIrreversible`, the card manager route, the argument
 * checks) and the object and counter wrappers, included by `se05x_device.hpp`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#ifndef SE05X_DEVICE_OBJECTS_IPP
#define SE05X_DEVICE_OBJECTS_IPP

namespace se05x {

namespace detail {
/// A codec that splits one command into several APDUs (`WriteRsaKey`).
template <Command C>
concept MultiStepCodec = requires(const ArgsOf<C>& args, std::size_t step, MutableByteSpan out) {
  { Codec<C>::Steps(args) } -> std::convertible_to<std::size_t>;
  { Codec<C>::Step(args, step, out) } -> std::same_as<Result<std::size_t>>;
};
/// The persistent-lock indicator of `SetLockState` and `DisableObjCreation` (AN12543 Table 51).
inline constexpr uint8_t kPersistentLock = 0x02U;
} // namespace detail

template <PortSet P>
template <Command C>
Error Device<P>::checkArgs(const ArgsOf<C>& args, bool irreversible) const noexcept {
  // Only the creating commands below read `irreversible`; for every other command it is ignored.
  static_cast<void>(irreversible);
  if constexpr ((C == Command::EddsaSign) || (C == Command::EddsaVerify)) {
    // 940 bytes in the default, AESKey and ECKey sessions, 919 in a UserID session (AN12543
    // 4.10.1.2 p. 103, 4.10.2.2 p. 104); the codec knows only the first.
    if (args.input.size() > wire::EddsaInputMax(session_ == SessionKind::UserId)) {
      return Error::InvalidArgument;
    }
  } else if constexpr (C == Command::WriteUserId) {
    // Every UserID object has a finite attempt counter (S-14) and locks for good when it runs
    // out: it is created only by `irreversible::Operations::PlanCreateFiniteAuthObject`.
    const Error credential =
        userid::CheckCredential(caps_.generation, args.user_secret.size(), args.max_attempts);
    if (credential != Error::Ok) {
      return credential;
    }
    return irreversible ? Error::Ok : Error::IrreversibleNotConfirmed;
  } else if constexpr (C == Command::WriteBinary) {
    // A binary file whose policy grants neither write nor delete can never change: it is created
    // only by `irreversible::Operations::PlanCreateImmutableObject`.
    const bool creates = (args.policy != nullptr) && (args.file_length != 0U);
    if (creates && !irreversible && policy::IsImmutable(*args.policy)) {
      return Error::IrreversibleNotConfirmed;
    }
  } else if constexpr ((C == Command::GenerateEcKey) || (C == Command::WriteEcKey)) {
    return gate::CurveAllowed(caps_, args.curve);
  } else if constexpr (C == Command::WriteSymmKey) {
    return gate::SymmKeyAllowed(caps_, args.type);
  } else {
    static_cast<void>(args);
  }
  return Error::Ok;
}

template <PortSet P>
template <Command C>
  requires(!IsIrreversible(C) && !detail::IsDeviceOwned(C))
Result<ReplyOf<C>> Device<P>::Execute(const ArgsOf<C>& args) noexcept {
  const Error admitted = admit(C, detail::PolicyOf(args));
  if (admitted != Error::Ok) {
    return refuse<ReplyOf<C>>(C, admitted);
  }
  const Error checked = checkArgs<C>(args, false);
  if (checked != Error::Ok) {
    return refuse<ReplyOf<C>>(C, checked);
  }
  if constexpr (detail::IsCardManagerCommand(C)) {
    return runCardManager<C>(args);
  } else {
    return run<C>(args);
  }
}

template <PortSet P>
template <Command C>
  requires((C == Command::WriteBinary) || (C == Command::WriteUserId))
Result<ReplyOf<C>> Device<P>::createIrreversible(const ArgsOf<C>& args) noexcept {
  const Error admitted = admit(C, detail::PolicyOf(args));
  if (admitted != Error::Ok) {
    return refuse<ReplyOf<C>>(C, admitted);
  }
  const Error checked = checkArgs<C>(args, true);
  if (checked != Error::Ok) {
    return refuse<ReplyOf<C>>(C, checked);
  }
  return run<C>(args);
}

template <PortSet P>
template <Command C>
Result<ByteSpan> Device<P>::send(const ArgsOf<C>& args) noexcept {
  if constexpr (detail::MultiStepCodec<C>) {
    Result<ByteSpan> body = Result<ByteSpan>::Success(ByteSpan{});
    const std::size_t steps = Codec<C>::Steps(args);
    for (std::size_t i = 0U; (i < steps) && body.ok(); ++i) {
      const Result<std::size_t> enc = Codec<C>::Step(args, i, MutableByteSpan{tx_});
      body = enc.ok() ? exchange(C, enc.value) : refuse<ByteSpan>(C, enc.error);
    }
    return body;
  } else {
    const Result<std::size_t> enc = Codec<C>::Encode(args, MutableByteSpan{tx_});
    if (!enc.ok()) {
      Zeroize(MutableByteSpan{tx_});
      return refuse<ByteSpan>(C, enc.error);
    }
    if constexpr (std::same_as<ReplyOf<C>, AttestedRead>) {
      sent_length_ = enc.value; // kept (public bytes) for `echoed_command`
      for (std::size_t i = 0U; (i < enc.value) && (i < sent_.size()); ++i) {
        sent_[i] = tx_[i];
      }
    }
    return exchange(C, enc.value);
  }
}

template <PortSet P>
template <Command C>
Result<ReplyOf<C>> Device<P>::run(const ArgsOf<C>& args) noexcept {
  const Result<ByteSpan> body = send<C>(args);
  if (!body.ok()) {
    return Result<ReplyOf<C>>::Failure(body.error, body.detail);
  }
  ReplyOf<C> reply{};
  const Result<void> dec = Codec<C>::Decode(args, body.value, reply);
  if constexpr (std::same_as<ReplyOf<C>, AttestedRead>) {
    // The signed TLVs as returned (A21): kept (public bytes) for the verifier.
    const ByteSpan signed_tlvs = detail::SignedTlvs(body.value);
    signed_length_ = (signed_tlvs.size() <= signed_.size()) ? signed_tlvs.size() : 0U;
    for (std::size_t i = 0U; i < signed_length_; ++i) {
      signed_[i] = signed_tlvs[i];
    }
  }
  Zeroize(MutableByteSpan{rx_});
  if (ReplyEndsSession(C)) {
    // DeleteAll ends the session with its answer (AN13030): drop it, select the applet again.
    teardown();
    if (!reselect().ok()) {
      state_ =
          (link_.State() == t1::LinkState::Dead) ? DeviceState::Dead : DeviceState::NeedsReopen;
    }
  }
  if (!dec.ok()) {
    last_detail_ = detail::DeviceDetail(C, last_sw_, 7U);
    return Result<ReplyOf<C>>::Failure(dec.error, last_detail_);
  }
  if constexpr (std::same_as<ReplyOf<C>, AttestedRead>) {
    const std::size_t n = (sent_length_ < reply.echoed_command.bytes.size())
                              ? sent_length_
                              : reply.echoed_command.bytes.size();
    for (std::size_t i = 0U; i < n; ++i) {
      reply.echoed_command.bytes[i] = sent_[i];
    }
    reply.echoed_command.length = n;
  }
  return Result<ReplyOf<C>>::Success(reply);
}

template <PortSet P>
template <Command C>
Result<ReplyOf<C>> Device<P>::runCardManager(const ArgsOf<C>& args) noexcept {
  // The card manager answers GET DATA only while selected: that replaces the IoT applet and ends
  // platform SCP03 and every session, so it runs only from `Ready` on a plain bus.
  if ((session_ != SessionKind::None) || applet_.PlatformRequired()) {
    return refuse<ReplyOf<C>>(C, Error::WrongState);
  }
  gp::CardManager<P, Wire> cm(*ports_, wire_);
  wire_.SetClass(CommandClass::Fast);
  countApdus(1U);
  const Result<void> selected = cm.SelectCardManager();
  Result<ReplyOf<C>> out = Result<ReplyOf<C>>::Failure(selected.error, selected.detail);
  if (selected.ok()) {
    out = run<C>(args);
  }
  const Result<void> back = reselect();
  if (!back.ok()) {
    state_ = (link_.State() == t1::LinkState::Dead) ? DeviceState::Dead : DeviceState::NeedsReopen;
    return Result<ReplyOf<C>>::Failure(back.error, back.detail);
  }
  return out;
}

template <PortSet P>
template <Command C, typename Op>
  requires(kIrreversibleEnabled && IsIrreversible(C) && (Op::kCommand == C))
Result<ReplyOf<C>> Device<P>::ExecuteIrreversible(
    const ArgsOf<C>& args, irreversible::Confirmation<Op> confirmation) noexcept {
  if (!confirmation.IsConfirmed()) {
    return refuse<ReplyOf<C>>(C, Error::IrreversibleNotConfirmed);
  }
  const Error admitted = admit(C, detail::PolicyOf(args));
  if (admitted != Error::Ok) {
    return refuse<ReplyOf<C>>(C, admitted);
  }
  // Typed state checks: a request the chip is already in is refused, not repeated.
  if constexpr (C == Command::SetPlatformScpRequest) {
    if ((args.requirement == ScpRequirement::Required) && caps_.platform_scp_required) {
      return refuse<ReplyOf<C>>(C, Error::WrongState);
    }
  } else if constexpr (C == Command::SetLockState) {
    if ((args.state == LockStateValue::Locked) && caps_.applet_locked) {
      return refuse<ReplyOf<C>>(C, Error::WrongState);
    }
  } else {
    static_cast<void>(args);
  }
  const Result<ReplyOf<C>> r = run<C>(args);
  if (r.ok()) {
    if constexpr (C == Command::SetPlatformScpRequest) {
      caps_.platform_scp_required = args.requirement == ScpRequirement::Required;
    } else if constexpr (C == Command::SetLockState) {
      caps_.applet_locked = args.state == LockStateValue::Locked;
    } else {
      // DeleteAll, SetAppletFeatures and DisableObjCreation change nothing the gate reads now.
    }
  }
  return r;
}

// --- Object wrappers -------------------------------------------------------------------------

template <PortSet P>
Result<void> Device<P>::GenerateEcKey(ObjectId id, const Policy& policy, EcCurve curve) noexcept {
  GenerateEcKeyArgs args{};
  args.id = id;
  args.policy = &policy;
  args.curve = curve;
  const auto r = Execute<Command::GenerateEcKey>(args);
  return r.ok() ? Result<void>::Success() : Result<void>::Failure(r.error, r.detail);
}

template <PortSet P>
Result<std::size_t> Device<P>::ReadObject(ObjectId id, uint16_t offset,
                                          MutableByteSpan out) noexcept {
  ReadObjectArgs args{};
  args.id = id;
  args.offset = offset;
  args.out = out;
  const auto r = Execute<Command::ReadObject>(args);
  return r.ok() ? Result<std::size_t>::Success(r.value.length)
                : Result<std::size_t>::Failure(r.error, r.detail);
}

template <PortSet P>
Result<void> Device<P>::WriteBinary(ObjectId id, const Policy& policy, uint16_t offset,
                                    ByteSpan data, uint16_t file_length) noexcept {
  WriteBinaryArgs args{};
  args.id = id;
  args.policy = (file_length != 0U) ? &policy : nullptr;
  args.offset = offset;
  args.data = data;
  args.file_length = file_length;
  const auto r = Execute<Command::WriteBinary>(args);
  return r.ok() ? Result<void>::Success() : Result<void>::Failure(r.error, r.detail);
}

template <PortSet P>
Result<bool> Device<P>::ObjectExists(ObjectId id) noexcept {
  const auto r = Execute<Command::CheckObjectExists>(IdArgs{id});
  return r.ok() ? Result<bool>::Success(r.value.value) : Result<bool>::Failure(r.error, r.detail);
}

template <PortSet P>
Result<void> Device<P>::DeleteObject(ObjectId id) noexcept {
  const auto r = Execute<Command::DeleteSecureObject>(IdArgs{id});
  return r.ok() ? Result<void>::Success() : Result<void>::Failure(r.error, r.detail);
}

template <PortSet P>
Result<AttestedRead> Device<P>::ReadAttested(const ReadObjectAttestedArgs& args) noexcept {
  const Error admitted = admit(Command::ReadObjectAttested, nullptr);
  if (admitted != Error::Ok) {
    return refuse<AttestedRead>(Command::ReadObjectAttested, admitted);
  }
  // A fresh nonce from the host's crypto port for every request (AN12543 3.2.7.2: the user
  // supplies the freshness; S-09). Never from the attested chip: over an unauthenticated bus its
  // RNG answer can be replayed together with an old attested answer.
  ReadObjectAttestedArgs fresh = args;
  if (ports_->GetCrypto().Random(MutableByteSpan{fresh.freshness}) != CryptoStatus::Ok) {
    Zeroize(MutableByteSpan{fresh.freshness});
    return refuse<AttestedRead>(Command::ReadObjectAttested, Error::CryptoFailure);
  }
  last_nonce_ = fresh.freshness;
  return Execute<Command::ReadObjectAttested>(fresh);
}

template <PortSet P>
Result<void> Device<P>::IncrementCounter(ObjectId id) noexcept {
  const auto r = Execute<Command::IncrementCounter>(IdArgs{id});
  return r.ok() ? Result<void>::Success() : Result<void>::Failure(r.error, r.detail);
}

} // namespace se05x

#endif // SE05X_DEVICE_OBJECTS_IPP
