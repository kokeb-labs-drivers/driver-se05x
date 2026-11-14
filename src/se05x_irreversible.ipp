/**
 * @file se05x_irreversible.ipp
 * @brief Irreversible operations, included by `se05x_irreversible.hpp`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#ifndef SE05X_IRREVERSIBLE_IPP
#define SE05X_IRREVERSIBLE_IPP

namespace se05x::irreversible {

namespace detail {

/// The effects shown to the operator (static text, S-02: no data).
inline constexpr const char* kLockEffect =
    "Locks the applet: only the transport credential is accepted until it unlocks";
/// The effect of `RequirePlatformScp`.
inline constexpr const char* kScpEffect =
    "Every command must run inside platform SCP03 from now on; lost keys lose the chip";
/// The effect of `ChangeAppletFeatures`.
inline constexpr const char* kFeaturesEffect =
    "Changes the applet's feature set; features turned off may not come back";
/// The effect of `DeleteAllObjects`.
inline constexpr const char* kDeleteAllEffect =
    "Deletes every key and object that NXP did not provision; they cannot be recovered";
/// The effect of `DisableObjectCreation`.
inline constexpr const char* kRestrictEffect = "No new objects can be created on this chip";
/// The effect of `CreateImmutableObject`.
inline constexpr const char* kImmutableEffect =
    "Creates an object that can never be changed or deleted";
/// The effect of `CreateFiniteAuthObject`.
inline constexpr const char* kFiniteEffect =
    "Creates an authentication object that locks for good when its attempts run out";

} // namespace detail

template <typename P>
template <typename Op>
Result<Plan<Op>> Operations<P>::prepare(Command command, const Policy* policy, ObjectId target,
                                        const char* effect,
                                        const typename Op::Args& args) const noexcept {
  const Error admitted = device_->admit(command, policy);
  if (admitted != Error::Ok) {
    return Result<Plan<Op>>::Failure(admitted, se05x::detail::DeviceDetail(command, 0U, 0U));
  }
  return Result<Plan<Op>>::Success(
      Plan<Op>{target, effect, args, static_cast<const void*>(device_)});
}

template <typename P>
template <typename Op>
Result<Plan<Op>> Operations<P>::unsupported() noexcept {
  return Result<Plan<Op>>::Failure(
      Error::Unsupported,
      Detail{
          .sw = 0U, .command = 0xFFU, .layer = Layer::Device, .step = 0U, .attempts_left = 0xFFU});
}

template <typename P>
Result<Plan<SetLockStatePersistent>> Operations<P>::PlanSetLockStatePersistent() noexcept
  requires(kIrreversibleEnabled)
{
  if (device_->IsOpen() && device_->GetCapabilities().applet_locked) {
    return Result<Plan<SetLockStatePersistent>>::Failure(Error::WrongState);
  }
  return prepare<SetLockStatePersistent>(Command::SetLockState, nullptr, ObjectId{},
                                         detail::kLockEffect, NoArgs{});
}

template <typename P>
Result<Plan<RequirePlatformScp>> Operations<P>::PlanRequirePlatformScp() noexcept
  requires(kIrreversibleEnabled)
{
  if (device_->IsOpen() && device_->GetCapabilities().platform_scp_required) {
    return Result<Plan<RequirePlatformScp>>::Failure(Error::WrongState);
  }
  return prepare<RequirePlatformScp>(Command::SetPlatformScpRequest, nullptr, ObjectId{},
                                     detail::kScpEffect, NoArgs{});
}

template <typename P>
Result<Plan<ReplacePlatformKeys>> Operations<P>::PlanReplacePlatformKeys() noexcept
  requires(kIrreversibleEnabled)
{
  return unsupported<ReplacePlatformKeys>();
}

template <typename P>
Result<Plan<ChangeAppletFeatures>> Operations<P>::PlanChangeAppletFeatures(
    const SetAppletFeaturesArgs& args) noexcept
  requires(kIrreversibleEnabled)
{
  bool ext_set = false;
  for (const uint8_t b : args.ext) {
    ext_set = ext_set || (b != 0U);
  }
  if ((args.applet_config == 0U) && !(args.has_ext && ext_set)) {
    return Result<Plan<ChangeAppletFeatures>>::Failure(Error::InvalidArgument);
  }
  return prepare<ChangeAppletFeatures>(Command::SetAppletFeatures, nullptr, ObjectId{},
                                       detail::kFeaturesEffect, args);
}

template <typename P>
Result<Plan<DeleteAllObjects>> Operations<P>::PlanDeleteAllObjects() noexcept
  requires(kIrreversibleEnabled)
{
  return prepare<DeleteAllObjects>(Command::DeleteAll, nullptr, ObjectId{},
                                   detail::kDeleteAllEffect, NoArgs{});
}

template <typename P>
Result<Plan<DisableObjectCreation>> Operations<P>::PlanDisableObjectCreation(
    RestrictMode mode) noexcept
  requires(kIrreversibleEnabled)
{
  if (!se05x::detail::IsEnumerator(mode)) {
    return Result<Plan<DisableObjectCreation>>::Failure(Error::InvalidArgument);
  }
  return prepare<DisableObjectCreation>(Command::DisableObjCreation, nullptr, ObjectId{},
                                        detail::kRestrictEffect, DisableObjCreationArgs{mode});
}

template <typename P>
Result<Plan<CreateImmutableObject>> Operations<P>::PlanCreateImmutableObject(ObjectId id,
                                                                             const Policy& policy,
                                                                             ByteSpan data) noexcept
  requires(kIrreversibleEnabled)
{
  if (!MakeUserObject(id.value).ok() || data.empty() || (data.size() > kMaxImmutableBytes) ||
      !policy::IsImmutable(policy)) {
    return Result<Plan<CreateImmutableObject>>::Failure(Error::InvalidArgument);
  }
  return prepare<CreateImmutableObject>(Command::WriteBinary, &policy, id, detail::kImmutableEffect,
                                        ImmutableObjectArgs{id, policy, data});
}

template <typename P>
Result<Plan<CreateFiniteAuthObject>> Operations<P>::PlanCreateFiniteAuthObject(
    ObjectId id, const Policy& policy, ByteSpan secret, uint8_t max_attempts) noexcept
  requires(kIrreversibleEnabled)
{
  if (!MakeUserObject(id.value).ok() || policy.IsEmpty()) {
    return Result<Plan<CreateFiniteAuthObject>>::Failure(Error::InvalidArgument);
  }
  const Error credential =
      userid::CheckCredential(device_->GetCapabilities().generation, secret.size(), max_attempts);
  if (credential != Error::Ok) {
    return Result<Plan<CreateFiniteAuthObject>>::Failure(credential);
  }
  return prepare<CreateFiniteAuthObject>(Command::WriteUserId, &policy, id, detail::kFiniteEffect,
                                         FiniteAuthArgs{id, policy, secret, max_attempts});
}

template <typename P>
Result<Plan<ChangeI2cAddress>> Operations<P>::PlanChangeI2cAddress() noexcept
  requires(kIrreversibleEnabled)
{
  return unsupported<ChangeI2cAddress>();
}

template <typename P>
Result<Plan<ApplyAppletUpdate>> Operations<P>::PlanApplyAppletUpdate() noexcept
  requires(kIrreversibleEnabled)
{
  return unsupported<ApplyAppletUpdate>();
}

template <typename P>
Result<Plan<ReplaceEcKeyCredential>> Operations<P>::PlanReplaceEcKeyCredential() noexcept
  requires(kIrreversibleEnabled)
{
  return unsupported<ReplaceEcKeyCredential>();
}

template <typename P>
template <Command C, typename Op>
Result<void> Operations<P>::run(const ArgsOf<C>& args, Confirmation<Op> confirmation) noexcept {
  const auto r = device_->template ExecuteIrreversible<C, Op>(args, confirmation);
  return r.ok() ? Result<void>::Success() : Result<void>::Failure(r.error, r.detail);
}

template <typename P>
template <typename Op>
Result<void> Operations<P>::Apply(const Plan<Op>& plan, Confirmation<Op> confirmation) noexcept
  requires(kIrreversibleEnabled)
{
  if (!plan.IsPrepared() || !confirmation.IsConfirmed() ||
      (plan.owner_ != static_cast<const void*>(device_))) {
    return Result<void>::Failure(Error::IrreversibleNotConfirmed);
  }
  if constexpr (std::same_as<Op, SetLockStatePersistent>) {
    return run<Command::SetLockState>(SetLockStateArgs{LockStateValue::Locked}, confirmation);
  } else if constexpr (std::same_as<Op, RequirePlatformScp>) {
    return run<Command::SetPlatformScpRequest>(SetPlatformScpRequestArgs{ScpRequirement::Required},
                                               confirmation);
  } else if constexpr (std::same_as<Op, ChangeAppletFeatures>) {
    return run<Command::SetAppletFeatures>(plan.Arguments(), confirmation);
  } else if constexpr (std::same_as<Op, DeleteAllObjects>) {
    return run<Command::DeleteAll>(Empty{}, confirmation);
  } else if constexpr (std::same_as<Op, DisableObjectCreation>) {
    return run<Command::DisableObjCreation>(plan.Arguments(), confirmation);
  } else if constexpr (std::same_as<Op, CreateImmutableObject>) {
    const ImmutableObjectArgs& args = plan.Arguments();
    WriteBinaryArgs write{};
    write.id = args.id;
    write.policy = &args.policy;
    write.data = args.data;
    write.file_length = static_cast<uint16_t>(args.data.size());
    const auto r = device_->template createIrreversible<Command::WriteBinary>(write);
    return r.ok() ? Result<void>::Success() : Result<void>::Failure(r.error, r.detail);
  } else if constexpr (std::same_as<Op, CreateFiniteAuthObject>) {
    const FiniteAuthArgs& args = plan.Arguments();
    WriteUserIdArgs write{};
    write.id = args.id;
    write.policy = &args.policy;
    write.user_secret = args.secret;
    write.max_attempts = args.max_attempts;
    const auto r = device_->template createIrreversible<Command::WriteUserId>(write);
    return r.ok() ? Result<void>::Success() : Result<void>::Failure(r.error, r.detail);
  } else {
    return Result<void>::Failure(Error::Unsupported); // no plan of these is ever prepared
  }
}

} // namespace se05x::irreversible

#endif // SE05X_IRREVERSIBLE_IPP
