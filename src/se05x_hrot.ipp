/**
 * @file se05x_hrot.ipp
 * @brief Facade implementation, included by `se05x_hrot.hpp`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Every call first runs `admit()`: the device is open, the APDU budget allows the call's cost
 * (S-17), and secure messaging is active when the call uses a key, a counter or secret data
 * (S-14). A refusal sends nothing. The costs are the APDUs each call sends.
 */
#ifndef SE05X_HROT_IPP
#define SE05X_HROT_IPP

namespace se05x::hrot {

namespace detail {

/// The facade's step numbers in `Detail::step` for its own refusals.
enum class Step : uint8_t {
  Admit = 1,     ///< `admit()`: closed, budget or secure messaging.
  Argument = 2,  ///< An argument check.
  Floor = 3,     ///< `CheckFloor`: below the floor.
  Signature = 4, ///< `VerifySignature`: the signature does not verify.
  Identity = 5,  ///< `Attest`: another chip signed.
};

/**
 * @brief The detail of a facade refusal.
 * @param step The step.
 * @return The detail, layer `Hrot`.
 */
constexpr Detail HrotDetail(Step step) noexcept {
  return Detail{.sw = 0U,
                .command = 0xFFU,
                .layer = Layer::Hrot,
                .step = static_cast<uint8_t>(step),
                .attempts_left = 0xFFU};
}

/// The last byte of a stored object: written after every data chunk, so a store cut short is
/// never read back as data.
inline constexpr uint8_t kStoreComplete = 0xA5U;

/**
 * @brief Remove the completion marker of `Store` from an attested stored object: the size and the
 * value are reported without it. The whole object must have been read (format 2 gives its size,
 * AN12543 Table 131): a partial read cannot show the marker, so it is refused, and a read longer
 * than the signed size is refused too (docs/ambiguities.md A36). The length is checked before the
 * marker byte is read, so a signed size above the buffer never reads past it.
 * @param value The attested value; changed in place.
 * @return false when the object is too small, was not read whole, or ends without the marker.
 */
constexpr bool WithoutStoreMarker(AttestedValue& value) noexcept {
  const auto whole = static_cast<std::size_t>(value.object_size);
  if ((whole < 2U) || (value.data.length != whole) ||
      (value.data.bytes[whole - 1U] != kStoreComplete)) {
    return false;
  }
  value.object_size -= 1U;
  value.data.length = whole - 1U;
  return true;
}

/// The chunks needed for `bytes` bytes.
constexpr uint32_t Chunks(std::size_t bytes) noexcept {
  return static_cast<uint32_t>((bytes + (kChunkBytes - 1U)) / kChunkBytes);
}

/**
 * @brief The rules of one entry of a facade key policy of use `U` (S-03): the use's rule, read of
 * the public part, secure messaging; write, delete and generate forbidden.
 * @tparam B The builder type.
 * @tparam U The use.
 * @param b The builder, an entry started.
 */
template <KeyUse U, typename B>
constexpr void KeyRules(B& b) noexcept {
  static_cast<void>(b.template Allow<Rule::Read>().RequireSecureMessaging());
  if constexpr (U == KeyUse::Verify) {
    static_cast<void>(b.template Allow<Rule::Verify>());
  } else if constexpr (U == KeyUse::Attest) {
    static_cast<void>(b.template Allow<Rule::Attestation>());
  } else if constexpr (U == KeyUse::Agree) {
    static_cast<void>(b.template Allow<Rule::KeyAgreement>());
  } else {
    static_cast<void>(b.template Allow<Rule::Sign>().template Allow<Rule::Verify>());
  }
  static_cast<void>(b.template Forbid<Rule::Write>()
                        .template Forbid<Rule::Delete>()
                        .template Forbid<Rule::Gen>());
}

/**
 * @brief The strict policy of a facade key of use `U`. Authentication object 0 is the default
 * session only (AN12543 3.7.1.2 p. 36), not every session: the policy names the applet session the
 * facade runs in as well, when there is one, and is refused by the chip in any other session
 * (fail closed, docs/ambiguities.md A20).
 * @tparam G The applet generation.
 * @tparam U The use.
 * @param session The credential of the applet session now open, or 0.
 * @return The policy or the builder's error.
 */
template <AppletGeneration G, KeyUse U>
constexpr Result<Policy> KeyPolicyOf(uint32_t session) noexcept {
  constexpr ObjectClass kClass =
      (U == KeyUse::Verify) ? ObjectClass::EcPubKey : ObjectClass::EcKeyPair;
  PolicyBuilder<G, kClass, Profile::Strict> b{};
  KeyRules<U>(b.ForAllOthers());
  if (session != 0U) {
    KeyRules<U>(b.For(AuthObject{ObjectId{session}}));
  }
  return b.Build();
}

/**
 * @brief The rules of one entry of a facade binary object or counter policy.
 * @tparam B The builder type.
 * @param b The builder, an entry started.
 * @param secure Whether secure messaging is required.
 * @param deletable Whether the object may be deleted.
 */
template <typename B>
constexpr void DataRules(B& b, bool secure, bool deletable) noexcept {
  static_cast<void>(b.template Allow<Rule::Read>().template Allow<Rule::Write>());
  if (deletable) {
    static_cast<void>(b.template Allow<Rule::Delete>());
  }
  if (secure) {
    static_cast<void>(b.RequireSecureMessaging());
  }
}

/**
 * @brief The policy of a facade binary object or counter: read and write (and delete when
 * `deletable`) for the default session and the applet session now open, under secure messaging
 * when `secure`.
 * @tparam G The applet generation.
 * @tparam C The class (binary file or counter).
 * @param secure Whether secure messaging is required.
 * @param deletable Whether the object may be deleted (never a counter: a floor that could be
 * deleted could be created again lower).
 * @param session The credential of the applet session now open, or 0.
 * @return The policy or the builder's error.
 */
template <AppletGeneration G, ObjectClass C>
constexpr Result<Policy> DataPolicyOf(bool secure, bool deletable, uint32_t session) noexcept {
  PolicyBuilder<G, C, Profile::Strict> b{};
  DataRules(b.ForAllOthers(), secure, deletable);
  if (session != 0U) {
    DataRules(b.For(AuthObject{ObjectId{session}}), secure, deletable);
  }
  return b.Build();
}

/**
 * @brief Pick the generation at run time.
 * @tparam U The use.
 * @param generation The chip's generation.
 * @param session The credential of the applet session now open, or 0.
 * @return The key policy, `Unsupported` for 6.x.
 */
template <KeyUse U>
constexpr Result<Policy> KeyPolicyFor(AppletGeneration generation, uint32_t session) noexcept {
  if (generation == AppletGeneration::V7) {
    return KeyPolicyOf<AppletGeneration::V7, U>(session);
  }
  if (generation == AppletGeneration::V3) {
    return KeyPolicyOf<AppletGeneration::V3, U>(session);
  }
  return Result<Policy>::Failure(Error::Unsupported, HrotDetail(Step::Argument));
}

/**
 * @brief The key policy of a run-time use.
 * @param generation The chip's generation.
 * @param use The use.
 * @param session The credential of the applet session now open, or 0.
 * @return The policy or the error.
 */
constexpr Result<Policy> KeyPolicyForUse(AppletGeneration generation, KeyUse use,
                                         uint32_t session) noexcept {
  switch (use) {
  case KeyUse::Sign:
    return KeyPolicyFor<KeyUse::Sign>(generation, session);
  case KeyUse::Attest:
    return KeyPolicyFor<KeyUse::Attest>(generation, session);
  case KeyUse::Agree:
    return KeyPolicyFor<KeyUse::Agree>(generation, session);
  case KeyUse::TlsClient:
    return KeyPolicyFor<KeyUse::TlsClient>(generation, session);
  case KeyUse::Verify:
    return KeyPolicyFor<KeyUse::Verify>(generation, session);
  default:
    break;
  }
  return Result<Policy>::Failure(Error::InvalidArgument, HrotDetail(Step::Argument));
}

/**
 * @brief Read a big-endian number.
 * @param bytes 1 to 4 bytes.
 * @return The value.
 */
constexpr uint32_t BigEndian32(ByteSpan bytes) noexcept {
  uint32_t v = 0U;
  for (std::size_t i = 0U; (i < bytes.size()) && (i < 4U); ++i) {
    v = (v << 8U) | static_cast<uint32_t>(bytes[i]);
  }
  return v;
}

} // namespace detail

// --- Admission ---------------------------------------------------------------------------------

template <PortSet P>
Error Device<P>::admit(uint32_t cost, detail::Need need) noexcept {
  if (!device_->IsOpen()) {
    return Error::NotInitialized;
  }
  // The facade is for applet 7.x: on 3.x (SE050 A to D, F) there is no plain attribute read
  // (AN12413), so a key or counter could be made but never adopted again after a reboot, and 6.x
  // (early SE051) has no specification in hand. Refused before anything is sent, so no
  // half-usable state is ever created.
  if (device_->GetCapabilities().generation != AppletGeneration::V7) {
    return Error::Unsupported;
  }
  syncOpen();
  if (!Budget().Allows(cost)) {
    return Error::ThroughputLimited; // the facade refuses before the chip would (S-17)
  }
  // A secure-messaging layer counts only at the level the call needs (S-14): authenticated
  // answers for results the caller acts on, and encryption both ways for secrets.
  if ((need == detail::Need::Authentic) && !device_->AnswersAuthenticated()) {
    return Error::PolicyDenied;
  }
  if ((need == detail::Need::Confidential) && !device_->TrafficConfidential()) {
    return Error::PolicyDenied;
  }
  return Error::Ok;
}

template <PortSet P>
void Device<P>::syncOpen() noexcept {
  // A new open may be another chip or a reset one: the unique id is read again before the next
  // attestation compares against it.
  if (device_->OpenCount() != seen_open_) {
    seen_open_ = device_->OpenCount();
    id_known_ = false;
  }
}

template <PortSet P>
uint32_t Device<P>::sessionCredential() const noexcept {
  return device_->SessionCredential().value;
}

template <PortSet P>
template <typename T>
Result<T> Device<P>::refuse(Error error) noexcept {
  return Result<T>::Failure(error, detail::HrotDetail(detail::Step::Admit));
}

template <PortSet P>
ApduBudget Device<P>::Budget() const noexcept {
  ApduBudget budget{};
  budget.issued_by_device = device_->ApduCount();
  budget.applies = device_->GetCapabilities().features.throughput_limit;
  budget.persistent_counter_known = window_known_;
  budget.issued_in_window = se05x::detail::SaturatingAdd(window_base_, budget.issued_by_device);
  return budget;
}

template <PortSet P>
void Device<P>::SetWindowCount(uint32_t issued_in_window) noexcept {
  const uint32_t sent = device_->ApduCount();
  window_base_ = (issued_in_window > sent) ? (issued_in_window - sent) : 0U;
  window_known_ = true;
}

// --- Identity ----------------------------------------------------------------------------------

template <PortSet P>
Result<void> Device<P>::uniqueId() noexcept {
  std::array<uint8_t, kUniqueIdLength> id{};
  ReadObjectArgs args{};
  args.id = FromReserved(ReservedId::UniqueId);
  args.out = MutableByteSpan{id};
  const auto r = device_->template Execute<Command::ReadObject>(args);
  if (!r.ok()) {
    return Result<void>::Failure(r.error, r.detail);
  }
  if (r.value.length != kUniqueIdLength) {
    return Result<void>::Failure(Error::FrameError, detail::HrotDetail(detail::Step::Identity));
  }
  unique_id_ = id;
  id_known_ = true;
  return Result<void>::Success();
}

template <PortSet P>
Result<Identity> Device<P>::Identify() noexcept {
  const Error admitted = admit(cost::kIdentify, detail::Need::None);
  if (admitted != Error::Ok) {
    return refuse<Identity>(admitted);
  }
  const Result<void> read = uniqueId();
  if (!read.ok()) {
    return Result<Identity>::Failure(read.error, read.detail);
  }
  const Capabilities& caps = device_->GetCapabilities();
  Identity identity{};
  identity.unique_id = unique_id_;
  identity.family = caps.family;
  identity.applet = caps.applet;
  identity.oef_id = caps.oef_id;
  return Result<Identity>::Success(identity);
}

// --- Keys --------------------------------------------------------------------------------------

template <PortSet P>
Result<void> Device<P>::CheckPlan(std::span<const SlotPlan> plans) const noexcept {
  if (!device_->IsOpen()) {
    return Result<void>::Failure(Error::NotInitialized, detail::HrotDetail(detail::Step::Admit));
  }
  if (plans.empty() || (plans.size() > kSlotCount)) {
    return Result<void>::Failure(Error::InvalidArgument,
                                 detail::HrotDetail(detail::Step::Argument));
  }
  const Capabilities& caps = device_->GetCapabilities();
  if (caps.generation != AppletGeneration::V7) {
    return Result<void>::Failure(Error::Unsupported, detail::HrotDetail(detail::Step::Admit));
  }
  if (gate::CurveAllowed(caps, EcCurve::NistP256) != Error::Ok) {
    return Result<void>::Failure(Error::Unsupported, detail::HrotDetail(detail::Step::Argument));
  }
  for (std::size_t i = 0U; i < plans.size(); ++i) {
    for (std::size_t j = 0U; j < i; ++j) {
      if (plans[i].slot == plans[j].slot) {
        return Result<void>::Failure(Error::InvalidArgument,
                                     detail::HrotDetail(detail::Step::Argument));
      }
    }
    const Result<Policy> policy =
        detail::KeyPolicyForUse(caps.generation, plans[i].use, sessionCredential());
    if (!policy.ok()) {
      return Result<void>::Failure(policy.error, policy.detail);
    }
  }
  return Result<void>::Success();
}

template <PortSet P>
template <KeyUse U>
Result<Policy> Device<P>::keyPolicy() const noexcept {
  return detail::KeyPolicyFor<U>(device_->GetCapabilities().generation, sessionCredential());
}

template <PortSet P>
Result<void> Device<P>::createKey(ObjectId id, const Policy& policy) noexcept {
  const Result<bool> exists = device_->ObjectExists(id);
  if (!exists.ok()) {
    return Result<void>::Failure(exists.error, exists.detail);
  }
  if (exists.value) {
    return Result<void>::Failure(Error::ObjectExists, detail::HrotDetail(detail::Step::Argument));
  }
  return device_->GenerateEcKey(id, policy, EcCurve::NistP256);
}

template <PortSet P>
template <KeyUse U>
  requires(U != KeyUse::Verify)
Result<Key<U>> Device<P>::Provision(Slot slot) noexcept {
  const Error admitted = admit(cost::kProvision, detail::Need::Authentic);
  if (admitted != Error::Ok) {
    return refuse<Key<U>>(admitted);
  }
  const Result<Policy> policy = keyPolicy<U>();
  if (!policy.ok()) {
    return Result<Key<U>>::Failure(policy.error, policy.detail);
  }
  const Result<void> created = createKey(slot.Object(), policy.value);
  if (!created.ok()) {
    return Result<Key<U>>::Failure(created.error, created.detail);
  }
  return Result<Key<U>>::Success(Key<U>{slot});
}

template <PortSet P>
template <KeyUse U>
Result<Key<U>> Device<P>::Find(Slot slot) noexcept {
  const Error admitted = admit(cost::kFind, detail::Need::Authentic);
  if (admitted != Error::Ok) {
    return refuse<Key<U>>(admitted);
  }
  const Result<bool> exists = device_->ObjectExists(slot.Object());
  if (!exists.ok()) {
    return Result<Key<U>>::Failure(exists.error, exists.detail);
  }
  if (!exists.value) {
    return Result<Key<U>>::Failure(Error::ObjectNotFound,
                                   detail::HrotDetail(detail::Step::Argument));
  }
  // Only a key the facade itself could have made for this use is adopted: a persistent EC key of
  // the right class and origin whose policy is, byte for byte, the policy the facade builds for
  // this use in this session (S-03; docs/ambiguities.md A34).
  const Result<Policy> expected = keyPolicy<U>();
  if (!expected.ok()) {
    return Result<Key<U>>::Failure(expected.error, expected.detail);
  }
  const ObjectClass cls = (U == KeyUse::Verify) ? ObjectClass::EcPubKey : ObjectClass::EcKeyPair;
  const Origin origin = (U == KeyUse::Verify) ? Origin::External : Origin::Internal;
  const Result<void> adopt = adoptable(slot.Object(), cls, origin, expected.value);
  if (!adopt.ok()) {
    return Result<Key<U>>::Failure(adopt.error, adopt.detail);
  }
  return Result<Key<U>>::Success(Key<U>{slot});
}

template <PortSet P>
Result<void> Device<P>::adoptable(ObjectId id, ObjectClass object_class, Origin origin,
                                  const Policy& expected) noexcept {
  const auto attributes = device_->template Execute<Command::ReadObjectAttributes>(IdArgs{id});
  if (!attributes.ok()) {
    return Result<void>::Failure(attributes.error, attributes.detail);
  }
  const ObjectAttributes& a = attributes.value;
  const bool same_policy = ct::Equal(a.policy.View(), expected.Bytes());
  if ((a.object_class != object_class) || (a.origin != origin) || !same_policy) {
    return Result<void>::Failure(Error::PolicyDenied, detail::HrotDetail(detail::Step::Argument));
  }
  // The attributes carry no lifetime (AN12543 Table 4); ReadType does. A transient object loses
  // its content at deselect (AN12543 3.2.1.7): a transient counter would reset the floor to 0.
  const auto type = device_->template Execute<Command::ReadType>(IdArgs{id});
  if (!type.ok()) {
    return Result<void>::Failure(type.error, type.detail);
  }
  if (type.value.lifetime != Lifetime::Persistent) {
    return Result<void>::Failure(Error::PolicyDenied, detail::HrotDetail(detail::Step::Argument));
  }
  return Result<void>::Success();
}

template <PortSet P>
template <KeyUse U>
Result<EcPublicKey> Device<P>::GetPublicKey(const Key<U>& key) noexcept {
  if (!key.IsValid()) {
    return Result<EcPublicKey>::Failure(Error::InvalidArgument,
                                        detail::HrotDetail(detail::Step::Argument));
  }
  const Error admitted = admit(cost::kGetPublicKey, detail::Need::Authentic);
  if (admitted != Error::Ok) {
    return refuse<EcPublicKey>(admitted);
  }
  EcPublicKey out{};
  const Result<std::size_t> read = device_->ReadObject(key.Id(), 0U, MutableByteSpan{out.point});
  if (!read.ok()) {
    return Result<EcPublicKey>::Failure(read.error, read.detail);
  }
  if ((read.value != kPointLength) || (out.point[0] != 0x04U)) {
    return Result<EcPublicKey>::Failure(Error::FrameError,
                                        detail::HrotDetail(detail::Step::Argument));
  }
  return Result<EcPublicKey>::Success(out);
}

template <PortSet P>
Result<VerifyKey> Device<P>::ImportPublicKey(Slot slot, const EcPublicKey& trusted) noexcept {
  if (!refcrypto::P256OnCurve(std::span<const uint8_t, 65>{trusted.point})) {
    return Result<VerifyKey>::Failure(Error::InvalidArgument,
                                      detail::HrotDetail(detail::Step::Argument));
  }
  const Error admitted = admit(cost::kImportPublicKey, detail::Need::Authentic);
  if (admitted != Error::Ok) {
    return refuse<VerifyKey>(admitted);
  }
  const Result<Policy> policy = keyPolicy<KeyUse::Verify>();
  if (!policy.ok()) {
    return Result<VerifyKey>::Failure(policy.error, policy.detail);
  }
  const Result<bool> exists = device_->ObjectExists(slot.Object());
  if (!exists.ok()) {
    return Result<VerifyKey>::Failure(exists.error, exists.detail);
  }
  if (exists.value) {
    return Result<VerifyKey>::Failure(Error::ObjectExists,
                                      detail::HrotDetail(detail::Step::Argument));
  }
  WriteEcKeyArgs args{};
  args.id = slot.Object();
  args.policy = &policy.value;
  args.curve = EcCurve::NistP256;
  args.public_key = trusted.View();
  const auto written = device_->template Execute<Command::WriteEcKey>(args);
  if (!written.ok()) {
    return Result<VerifyKey>::Failure(written.error, written.detail);
  }
  return Result<VerifyKey>::Success(VerifyKey{slot});
}

template <PortSet P>
Result<Signature> Device<P>::signDigest(ObjectId id, Digest digest) noexcept {
  const Error admitted = admit(cost::kSign, detail::Need::Authentic);
  if (admitted != Error::Ok) {
    return refuse<Signature>(admitted);
  }
  Signature signature{};
  const Result<std::size_t> r = device_->EcdsaSign(id, EcSignAlgo::Sha256, ByteSpan{digest},
                                                   MutableByteSpan{signature.bytes});
  if (!r.ok()) {
    return Result<Signature>::Failure(r.error, r.detail);
  }
  signature.length = r.value;
  return Result<Signature>::Success(signature);
}

template <PortSet P>
Result<Signature> Device<P>::Sign(const Key<KeyUse::Sign>& key, Digest digest) noexcept {
  if (!key.IsValid()) {
    return Result<Signature>::Failure(Error::InvalidArgument,
                                      detail::HrotDetail(detail::Step::Argument));
  }
  return signDigest(key.Id(), digest);
}

template <PortSet P>
Result<Signature> Device<P>::TlsSign(const Key<KeyUse::TlsClient>& key, Digest digest) noexcept {
  if (!key.IsValid()) {
    return Result<Signature>::Failure(Error::InvalidArgument,
                                      detail::HrotDetail(detail::Step::Argument));
  }
  return signDigest(key.Id(), digest);
}

template <PortSet P>
template <KeyUse U>
  requires((U == KeyUse::Sign) || (U == KeyUse::TlsClient) || (U == KeyUse::Verify))
Result<void> Device<P>::VerifySignature(const Key<U>& key, Digest digest,
                                        ByteSpan signature) noexcept {
  if (!key.IsValid() || signature.empty() || (signature.size() > kMaxSignatureLength)) {
    return Result<void>::Failure(Error::InvalidArgument,
                                 detail::HrotDetail(detail::Step::Argument));
  }
  const Error admitted = admit(cost::kVerifySignature, detail::Need::Authentic);
  if (admitted != Error::Ok) {
    return refuse<void>(admitted);
  }
  const Result<bool> r =
      device_->EcdsaVerify(key.Id(), EcSignAlgo::Sha256, ByteSpan{digest}, signature);
  if (!r.ok()) {
    return Result<void>::Failure(r.error, r.detail);
  }
  if (!r.value) {
    return Result<void>::Failure(Error::AttestationInvalid,
                                 detail::HrotDetail(detail::Step::Signature));
  }
  return Result<void>::Success();
}

template <PortSet P>
Result<void> Device<P>::Agree(const Key<KeyUse::Agree>& key, const EcPublicKey& peer,
                              SecretBuffer<32>& shared) noexcept {
  shared.Wipe();
  // The peer must be a point of NIST P-256 (prefix 04, coordinates below p, on the curve): an
  // invalid point is refused here, before anything is sent, since AN12543 4.10.3.1 does not say
  // that the chip validates it.
  if (!key.IsValid() || !refcrypto::P256OnCurve(std::span<const uint8_t, 65>{peer.point})) {
    return Result<void>::Failure(Error::InvalidArgument,
                                 detail::HrotDetail(detail::Step::Argument));
  }
  const Error admitted = admit(cost::kAgree, detail::Need::Confidential);
  if (admitted != Error::Ok) {
    return refuse<void>(admitted);
  }
  EcdhArgs args{};
  args.key = key.Id();
  args.algo = EcdhAlgo::SvdpDhPlain;
  args.peer_public = peer.View();
  args.secret = shared.Reserve(32U);
  const auto r = device_->template Execute<Command::EcdhGenerateSharedSecret>(args);
  if (!r.ok() || (r.value.length != 32U)) {
    shared.Wipe();
    return r.ok() ? Result<void>::Failure(Error::FrameError,
                                          detail::HrotDetail(detail::Step::Argument))
                  : Result<void>::Failure(r.error, r.detail);
  }
  return Result<void>::Success();
}

// --- Attestation -------------------------------------------------------------------------------

template <PortSet P>
template <SlotKind K>
Result<Verified<AttestedValue>> Device<P>::Attest(const AttestationKey& key,
                                                  SlotOf<K> slot) noexcept {
  using Out = Result<Verified<AttestedValue>>;
  if (!key.IsValid()) {
    return Out::Failure(Error::InvalidArgument, detail::HrotDetail(detail::Step::Argument));
  }
  const Error admitted =
      admit(id_known_ ? (cost::kAttest - 1U) : cost::kAttest, detail::Need::None);
  if (admitted != Error::Ok) {
    return refuse<Verified<AttestedValue>>(admitted);
  }
  if (!id_known_) {
    const Result<void> read = uniqueId();
    if (!read.ok()) {
      return Out::Failure(read.error, read.detail);
    }
  }
  AttestedValue value{};
  std::array<uint8_t, kMaxSignatureLength + 8U> signature{};
  ReadObjectAttestedArgs args{};
  args.id = slot.Object();
  args.attestation_key = key.Id();
  args.algo = AttestationAlgo::EcSha256;
  args.data_out = MutableByteSpan{value.data.bytes};
  args.signature_out = MutableByteSpan{signature};
  const Result<attest::Checked> checked =
      device_->ReadVerified(args, std::span<const uint8_t, kPointLength>{key.Public().point});
  if (!checked.ok()) {
    return Out::Failure(checked.error, checked.detail);
  }
  if (!ct::Equal(ByteSpan{checked.value.unique_id}, ByteSpan{unique_id_})) {
    return Out::Failure(Error::Counterfeit, detail::HrotDetail(detail::Step::Identity));
  }
  value.data.length = checked.value.data_length;
  value.timestamp = checked.value.timestamp;
  value.unique_id = checked.value.unique_id;
  value.object_size = checked.value.object_size;
  if constexpr ((K == SlotKind::Data) || (K == SlotKind::Certificate)) {
    if (!detail::WithoutStoreMarker(value)) {
      return Out::Failure(Error::FrameError, detail::HrotDetail(detail::Step::Argument));
    }
  }
  return Out::Success(Verified<AttestedValue>{value});
}

// --- Stored data and certificates --------------------------------------------------------------

template <PortSet P>
Result<Policy> Device<P>::dataPolicy(Protection protection) const noexcept {
  const bool secure = (protection == Protection::Secret);
  const AppletGeneration g = device_->GetCapabilities().generation;
  if (g == AppletGeneration::V7) {
    return detail::DataPolicyOf<AppletGeneration::V7, ObjectClass::BinaryFile>(secure, true,
                                                                               sessionCredential());
  }
  if (g == AppletGeneration::V3) {
    return detail::DataPolicyOf<AppletGeneration::V3, ObjectClass::BinaryFile>(secure, true,
                                                                               sessionCredential());
  }
  return Result<Policy>::Failure(Error::Unsupported, detail::HrotDetail(detail::Step::Argument));
}

template <PortSet P>
Result<Policy> Device<P>::counterPolicy() const noexcept {
  const AppletGeneration g = device_->GetCapabilities().generation;
  if (g == AppletGeneration::V7) {
    return detail::DataPolicyOf<AppletGeneration::V7, ObjectClass::Counter>(true, false,
                                                                            sessionCredential());
  }
  if (g == AppletGeneration::V3) {
    return detail::DataPolicyOf<AppletGeneration::V3, ObjectClass::Counter>(true, false,
                                                                            sessionCredential());
  }
  return Result<Policy>::Failure(Error::Unsupported, detail::HrotDetail(detail::Step::Argument));
}

template <PortSet P>
void Device<P>::dropUnfinished(ObjectId id, const Result<void>& written) noexcept {
  // A partly written object is not left behind (its policy allows delete): no `Load` returns a
  // zero-filled tail as data, and a retry finds the slot free. A failed first chunk may have
  // created the object too, so the delete is sent then as well. Best effort: the chip may be
  // unreachable now, then `Load` and `Erase` still work on the object. After SW 0x66A6 no delete
  // is sent: the chip refuses work, the device has already reset it and selected the applet again
  // (S-17), and one more APDU would only pass the admitted cost. The object stays without its
  // marker, so `Load` refuses it; `Erase` removes it once the window allows.
  if ((!written.ok()) && (written.error != Error::ThroughputLimited)) {
    static_cast<void>(device_->DeleteObject(id));
  }
}

template <PortSet P>
Result<void> Device<P>::storeBytes(ObjectId id, ByteSpan data, Protection protection) noexcept {
  if (data.empty() || (data.size() > kMaxStoredBytes)) {
    return Result<void>::Failure(Error::InvalidArgument,
                                 detail::HrotDetail(detail::Step::Argument));
  }
  const Error admitted =
      admit(cost::kStoreBase + detail::Chunks(data.size()),
            (protection == Protection::Secret) ? detail::Need::Confidential : detail::Need::None);
  if (admitted != Error::Ok) {
    return refuse<void>(admitted);
  }
  const Result<Policy> policy = dataPolicy(protection);
  if (!policy.ok()) {
    return Result<void>::Failure(policy.error, policy.detail);
  }
  const Result<bool> exists = device_->ObjectExists(id);
  if (!exists.ok()) {
    return Result<void>::Failure(exists.error, exists.detail);
  }
  if (exists.value) {
    return Result<void>::Failure(Error::ObjectExists, detail::HrotDetail(detail::Step::Argument));
  }
  // The object is one byte longer than the data: the last byte is the completion marker, written
  // by its own command after every data chunk. A store cut short (a power loss between chunks)
  // leaves the marker unwritten, and `Load` refuses the object instead of returning a partial
  // value (docs/ambiguities.md A35).
  const auto total = static_cast<uint16_t>(data.size() + 1U);
  Result<void> written = Result<void>::Success();
  for (std::size_t at = 0U; (at < data.size()) && written.ok(); at += kChunkBytes) {
    const std::size_t n = ((data.size() - at) < kChunkBytes) ? (data.size() - at) : kChunkBytes;
    const bool first = (at == 0U);
    written = device_->WriteBinary(id, policy.value, static_cast<uint16_t>(at), data.subspan(at, n),
                                   first ? total : uint16_t{0U});
    dropUnfinished(id, written);
  }
  if (written.ok()) {
    const std::array<uint8_t, 1> marker{detail::kStoreComplete};
    written = device_->WriteBinary(id, policy.value, static_cast<uint16_t>(data.size()),
                                   ByteSpan{marker}, uint16_t{0U});
    dropUnfinished(id, written);
  }
  return written;
}

template <PortSet P>
Result<std::size_t> Device<P>::loadBytes(ObjectId id, MutableByteSpan out,
                                         detail::Need need) noexcept {
  const std::size_t most = (out.size() < kMaxStoredBytes) ? out.size() : kMaxStoredBytes;
  const Error admitted = admit(cost::kLoadBase + detail::Chunks(most), need);
  if (admitted != Error::Ok) {
    return refuse<std::size_t>(admitted);
  }
  const auto size = device_->template Execute<Command::ReadSize>(IdArgs{id});
  if (!size.ok()) {
    return Result<std::size_t>::Failure(size.error, size.detail);
  }
  // The object holds the data and the completion marker (see `storeBytes`).
  if ((size.value.value < 2U) || (size.value.value > (kMaxStoredBytes + 1U))) {
    return Result<std::size_t>::Failure(Error::FrameError,
                                        detail::HrotDetail(detail::Step::Argument));
  }
  const std::size_t total = size.value.value - 1U;
  std::array<uint8_t, 1> marker{};
  ReadObjectArgs last{};
  last.id = id;
  last.offset = static_cast<uint16_t>(total);
  last.length = 1U;
  last.out = MutableByteSpan{marker};
  const auto end = device_->template Execute<Command::ReadObject>(last);
  if (!end.ok()) {
    return Result<std::size_t>::Failure(end.error, end.detail);
  }
  if ((end.value.length != 1U) || (marker[0] != detail::kStoreComplete)) {
    return Result<std::size_t>::Failure(Error::FrameError,
                                        detail::HrotDetail(detail::Step::Argument));
  }
  if (total > out.size()) {
    return Result<std::size_t>::Failure(Error::BufferTooSmall,
                                        detail::HrotDetail(detail::Step::Argument));
  }
  for (std::size_t at = 0U; at < total; at += kChunkBytes) {
    const std::size_t n = ((total - at) < kChunkBytes) ? (total - at) : kChunkBytes;
    ReadObjectArgs args{};
    args.id = id;
    args.offset = static_cast<uint16_t>(at);
    args.length = static_cast<uint16_t>(n);
    args.out = out.subspan(at, n);
    const auto r = device_->template Execute<Command::ReadObject>(args);
    if (!r.ok()) {
      Zeroize(out.first(total));
      return Result<std::size_t>::Failure(r.error, r.detail);
    }
    if (r.value.length != n) {
      Zeroize(out.first(total));
      return Result<std::size_t>::Failure(Error::FrameError,
                                          detail::HrotDetail(detail::Step::Argument));
    }
  }
  return Result<std::size_t>::Success(total);
}

template <PortSet P>
Result<void> Device<P>::eraseObject(ObjectId id) noexcept {
  const Error admitted = admit(cost::kErase, detail::Need::None);
  if (admitted != Error::Ok) {
    return refuse<void>(admitted);
  }
  return device_->DeleteObject(id);
}

template <PortSet P>
Result<void> Device<P>::Store(SlotOf<SlotKind::Data> slot, ByteSpan data,
                              Protection protection) noexcept {
  return storeBytes(slot.Object(), data, protection);
}

template <PortSet P>
Result<std::size_t> Device<P>::Load(SlotOf<SlotKind::Data> slot, MutableByteSpan out,
                                    Protection protection) noexcept {
  return loadBytes(
      slot.Object(), out,
      (protection == Protection::Secret) ? detail::Need::Confidential : detail::Need::None);
}

template <PortSet P>
Result<void> Device<P>::Erase(SlotOf<SlotKind::Data> slot) noexcept {
  return eraseObject(slot.Object());
}

template <PortSet P>
Result<void> Device<P>::StoreCertificate(SlotOf<SlotKind::Certificate> slot,
                                         ByteSpan der) noexcept {
  return storeBytes(slot.Object(), der, Protection::Public);
}

template <PortSet P>
Result<std::size_t> Device<P>::LoadCertificate(SlotOf<SlotKind::Certificate> slot,
                                               MutableByteSpan out) noexcept {
  return loadBytes(slot.Object(), out, detail::Need::None);
}

template <PortSet P>
Result<void> Device<P>::EraseCertificate(SlotOf<SlotKind::Certificate> slot) noexcept {
  return eraseObject(slot.Object());
}

// --- Counters ----------------------------------------------------------------------------------

template <PortSet P>
Result<void> Device<P>::CreateCounter(SlotOf<SlotKind::Counter> slot, uint32_t initial) noexcept {
  const Error admitted = admit(cost::kCreateCounter, detail::Need::Authentic);
  if (admitted != Error::Ok) {
    return refuse<void>(admitted);
  }
  const Result<Policy> policy = counterPolicy();
  if (!policy.ok()) {
    return Result<void>::Failure(policy.error, policy.detail);
  }
  const Result<bool> exists = device_->ObjectExists(slot.Object());
  if (!exists.ok()) {
    return Result<void>::Failure(exists.error, exists.detail);
  }
  if (exists.value) {
    // Only a counter the facade made is adopted (a counter whose policy grants delete to nobody);
    // anything else in the slot is refused. An adopted counter is never trusted to be the floor
    // asked for: it is raised to `initial` when lower, then the slot is reported as existing, so
    // a floor is never left lower than the caller asked.
    const Result<void> adopt =
        adoptable(slot.Object(), ObjectClass::Counter, Origin::External, policy.value);
    if (!adopt.ok()) {
      return adopt;
    }
    const Result<uint32_t> current = CounterValue(slot);
    if (!current.ok()) {
      return Result<void>::Failure(current.error, current.detail);
    }
    if (current.value < initial) {
      const Result<void> raised = RaiseCounterTo(slot, initial);
      if (!raised.ok()) {
        return raised;
      }
    }
    return Result<void>::Failure(Error::ObjectExists, detail::HrotDetail(detail::Step::Argument));
  }
  // One command creates the counter with its start value (AN12543 4.7.1.6: TAG_3 at creation), so
  // no torn state can leave a floor of 0 behind.
  WriteCounterArgs args{};
  args.id = slot.Object();
  args.policy = &policy.value;
  args.counter_bytes = kCounterBytes;
  args.value = initial;
  args.set_value = true;
  const auto created = device_->template Execute<Command::WriteCounter>(args);
  return created.ok() ? Result<void>::Success()
                      : Result<void>::Failure(created.error, created.detail);
}

template <PortSet P>
Result<uint32_t> Device<P>::CounterValue(SlotOf<SlotKind::Counter> slot) noexcept {
  const Error admitted = admit(cost::kCounterValue, detail::Need::Authentic);
  if (admitted != Error::Ok) {
    return refuse<uint32_t>(admitted);
  }
  std::array<uint8_t, 8> raw{};
  const Result<std::size_t> r = device_->ReadObject(slot.Object(), 0U, MutableByteSpan{raw});
  if (!r.ok()) {
    return Result<uint32_t>::Failure(r.error, r.detail);
  }
  if (r.value != kCounterBytes) {
    return Result<uint32_t>::Failure(Error::FrameError, detail::HrotDetail(detail::Step::Argument));
  }
  return Result<uint32_t>::Success(detail::BigEndian32(ByteSpan{raw}.first(r.value)));
}

template <PortSet P>
Result<uint32_t> Device<P>::CounterIncrement(SlotOf<SlotKind::Counter> slot) noexcept {
  const Error admitted = admit(cost::kCounterIncrement, detail::Need::Authentic);
  if (admitted != Error::Ok) {
    return refuse<uint32_t>(admitted);
  }
  const Result<void> r = device_->IncrementCounter(slot.Object());
  if (!r.ok()) {
    return Result<uint32_t>::Failure(r.error, r.detail);
  }
  return CounterValue(slot);
}

template <PortSet P>
Result<void> Device<P>::RaiseCounterTo(SlotOf<SlotKind::Counter> slot, uint32_t value) noexcept {
  const Error admitted = admit(cost::kRaiseCounterTo, detail::Need::Authentic);
  if (admitted != Error::Ok) {
    return refuse<void>(admitted);
  }
  WriteCounterArgs set{};
  set.id = slot.Object();
  set.counter_bytes = kCounterBytes;
  set.value = value;
  set.set_value = true;
  const auto r = device_->template Execute<Command::WriteCounter>(set);
  return r.ok() ? Result<void>::Success() : Result<void>::Failure(r.error, r.detail);
}

template <PortSet P>
Result<void> Device<P>::CheckFloor(SlotOf<SlotKind::Counter> floor, uint32_t version) noexcept {
  const Result<uint32_t> value = CounterValue(floor);
  if (!value.ok()) {
    return Result<void>::Failure(value.error, value.detail);
  }
  if (version < value.value) {
    return Result<void>::Failure(Error::PolicyDenied, detail::HrotDetail(detail::Step::Floor));
  }
  return Result<void>::Success();
}

// --- Random ------------------------------------------------------------------------------------

template <PortSet P>
Result<void> Device<P>::Random(MutableByteSpan out) noexcept {
  if (out.empty() || (out.size() > kMaxApduPayload)) {
    return Result<void>::Failure(Error::InvalidArgument,
                                 detail::HrotDetail(detail::Step::Argument));
  }
  constexpr std::size_t kPerApdu = 512U;
  const auto apdus =
      cost::kRandomPer512 * static_cast<uint32_t>((out.size() + (kPerApdu - 1U)) / kPerApdu);
  const Error admitted = admit(apdus, detail::Need::None);
  if (admitted != Error::Ok) {
    return refuse<void>(admitted);
  }
  for (std::size_t at = 0U; at < out.size(); at += kPerApdu) {
    const std::size_t n = ((out.size() - at) < kPerApdu) ? (out.size() - at) : kPerApdu;
    const Result<void> r = device_->GetRandom(out.subspan(at, n));
    if (!r.ok()) {
      return r;
    }
  }
  return Result<void>::Success();
}

} // namespace se05x::hrot

#endif // SE05X_HROT_IPP
