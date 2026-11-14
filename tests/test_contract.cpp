/**
 * @file test_contract.cpp
 * @brief The frozen contract: every header included, the public surface pinned with static_asserts.
 *
 * Built twice (tests/CMakeLists.txt): with `SE05X_ENABLE_IRREVERSIBLE` unset and with it set to 1
 * (`CONTRACT_IRREVERSIBLE_ON`). A builder who changes a frozen signature breaks this file; the
 * change is then a contract amendment (docs/builders.md). The run-time cases check what each layer
 * answers with ports that talk to nothing: refusals, never a crash or a hang.
 */
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "null_ports.hpp"
#include "se05x.hpp"
#include "se05x_kconfig.hpp"
#include "test_harness.hpp"

namespace {

using namespace se05x;
using testports::NullBus;
using testports::NullClock;
using testports::NullLog;
using testports::NullReset;

using Plain = Ports<NullBus, NullClock, ReferenceCrypto>;
using Full = Ports<NullBus, NullClock, ReferenceCrypto, NullReset, NullLog>;

// --- Error model ---------------------------------------------------------------------------------
static_assert(static_cast<uint8_t>(Error::Ok) == 0U);
static_assert(static_cast<uint8_t>(Error::Unsupported) == 9U);
static_assert(static_cast<uint8_t>(Error::BufferTooSmall) == 16U);
static_assert(static_cast<uint8_t>(Error::CryptoFailure) == 37U);
static_assert(static_cast<uint8_t>(Error::NotImplemented) == 38U);
static_assert(static_cast<uint8_t>(Error::ThroughputLimited) == 39U);
static_assert(std::is_trivially_copyable_v<Detail>);
static_assert(sizeof(Result<void>) <= 16U);

// --- Commands
// -------------------------------------------------------------------------------------
static_assert(kCommandCount == 105U);
static_assert(IsIrreversible(Command::SetLockState));
static_assert(IsIrreversible(Command::SetPlatformScpRequest));
static_assert(IsIrreversible(Command::SetAppletFeatures));
static_assert(IsIrreversible(Command::DeleteAll));
static_assert(IsIrreversible(Command::DisableObjCreation));
static_assert(!IsIrreversible(Command::GetRandom));
static_assert(!IsIrreversible(Command::DeleteSecureObject));
static_assert(!IsIrreversible(static_cast<Command>(250U)));
static_assert(std::same_as<ReplyOf<Command::GetRandom>, LengthReply>);
static_assert(std::same_as<ArgsOf<Command::EcdsaSign>, SignArgs>);
static_assert(std::same_as<ReplyOf<Command::I2cmExecuteCommandSetAttested>, AttestedRead>);

// --- Ports
// ----------------------------------------------------------------------------------------
static_assert(BusPort<NullBus>);
static_assert(ClockPort<NullClock>);
static_assert(CryptoPort<ReferenceCrypto>);
static_assert(ResetPort<NullReset>);
static_assert(LogPort<NullLog>);
static_assert(!BusPort<NullClock>);
static_assert(!CryptoPort<NullBus>);
static_assert(PortSet<Plain>);
static_assert(PortSet<Full>);
static_assert(!Plain::kHasReset);
static_assert(Full::kHasReset && Full::kHasLog);

// --- Types
// ----------------------------------------------------------------------------------------
static_assert(kI2cAddress == 0x48U);
static_assert(kUniqueIdLength == 18U);
static_assert(!kRepeatedStart && (kMaxClockHz == 400000U) &&
              (kMaxClockStretchHz > kMaxClockNoStretchHz));
static_assert(detail::DeviceHasRawAccess<Plain>);
static_assert(kFreshnessLength == 16U);
static_assert(Validate(Config{}) == Error::Ok);
static_assert(Validate(Config{.atr_poll_budget_ms = 0U}) != Error::Ok);
// The poll interval is at least the default MPOT of 1 ms (UM11225 Table 14, p. 19).
static_assert(Validate(Config{.poll_interval_us = 999U}) != Error::Ok);
static_assert(Validate(Config{.poll_interval_us = 1000U}) == Error::Ok);
static_assert(!Config{}.allow_lab_override);
static_assert(Config{}.verify_eckey_receipt);

// --- Object ids
// -----------------------------------------------------------------------------------
static_assert(!MakeUserObject(0U).ok());
static_assert(!MakeUserObject(0x7FFF0200U).ok());
static_assert(!MakeUserObject(0xF0000012U).ok());
static_assert(MakeUserObject(0x00001000U).ok());
static_assert(IsNxpOwned(ReservedId::RootOfTrustKey));
static_assert(!IsNxpOwned(ReservedId::Transport));

// --- Irreversible operations
// ----------------------------------------------------------------------
static_assert(irreversible::kOperationCount == 13U);
static_assert(!std::same_as<irreversible::Confirmation<irreversible::DeleteAllObjects>,
                            irreversible::Confirmation<irreversible::SetLockStatePersistent>>);
static_assert(
    !std::is_convertible_v<irreversible::Confirmation<irreversible::DeleteAllObjects>,
                           irreversible::Confirmation<irreversible::SetLockStatePersistent>>);
static_assert(!std::is_constructible_v<irreversible::Plan<irreversible::DeleteAllObjects>, ObjectId,
                                       const char*>);
#if defined(SE05X_ENABLE_IRREVERSIBLE) && (SE05X_ENABLE_IRREVERSIBLE != 0)
static_assert(kIrreversibleEnabled);
#else
static_assert(!kIrreversibleEnabled);
#endif

// Execute<C> exists only for reversible commands; ExecuteIrreversible only with the flag.
template <typename D, Command C>
concept CanExecute = requires(D& d, const ArgsOf<C>& a) { d.template Execute<C>(a); };
template <typename D, Command C, typename Op>
concept CanExecuteIrreversible =
    requires(D& d, const ArgsOf<C>& a, irreversible::Confirmation<Op> c) {
      d.template ExecuteIrreversible<C, Op>(a, c);
    };
static_assert(CanExecute<Device<Plain>, Command::GetRandom>);
static_assert(!CanExecute<Device<Plain>, Command::DeleteAll>);
static_assert(!CanExecute<Device<Plain>, Command::SetLockState>);
static_assert(
    CanExecuteIrreversible<Device<Plain>, Command::DeleteAll, irreversible::DeleteAllObjects> ==
    kIrreversibleEnabled);
static_assert(
    !CanExecuteIrreversible<Device<Plain>, Command::GetRandom, irreversible::DeleteAllObjects>);
static_assert(!CanExecuteIrreversible<Device<Plain>, Command::DeleteAll,
                                      irreversible::SetLockStatePersistent>);

template <typename D>
concept CanPowerCycle = requires(D& d) { d.PowerCycle(); };
static_assert(!CanPowerCycle<Device<Plain>>);
static_assert(CanPowerCycle<Device<Full>>);

template <typename O>
concept CanPlanDeleteAll = requires(O& o) { o.PlanDeleteAllObjects(); };
static_assert(CanPlanDeleteAll<irreversible::Operations<Plain>> == kIrreversibleEnabled);

template <typename G>
concept CanPutKeys = requires(G& g, const scp03::ChannelParams& p, const gp::NewKeySet& n) {
  g.PutKeys(p, n,
            irreversible::Confirmation<irreversible::ReplacePlatformKeys>{
                irreversible::ReplacePlatformKeys::kPhrase});
};
static_assert(CanPutKeys<gp::CardManager<Plain, t1::Link<Plain>>> == kIrreversibleEnabled);

// --- Layer signatures
// -----------------------------------------------------------------------------
static_assert(ApduTransport<t1::Link<Plain>>);
static_assert(ApduTransport<scp03::Channel<Plain, t1::Link<Plain>>>);
static_assert(ApduTransport<eckey::Session<Plain, t1::Link<Plain>>>);
static_assert(std::same_as<decltype(std::declval<t1::Link<Plain>&>().Open()), Result<void>>);
static_assert(std::same_as<decltype(std::declval<Device<Plain>&>().Open()), Result<void>>);
static_assert(
    std::same_as<decltype(std::declval<Device<Plain>&>().GetCapabilities()), const Capabilities&>);
static_assert(std::same_as<decltype(std::declval<hrot::Device<Plain>&>().Identify()),
                           Result<hrot::Identity>>);
static_assert(!std::is_copy_constructible_v<Device<Plain>>);
static_assert(!std::is_copy_constructible_v<scp03::Channel<Plain, t1::Link<Plain>>>);
static_assert(!hrot::MakeSlot(16U).ok());
static_assert(hrot::MakeSlot(15U).ok());

// The facade cannot reach an irreversible operation.
template <typename D>
concept FacadeHasIrreversible = requires(D& d) { d.PlanDeleteAllObjects(); };
static_assert(!FacadeHasIrreversible<hrot::Device<Plain>>);

// --- Policy
// ---------------------------------------------------------------------------------------
static_assert(RuleAllowedFor(AppletGeneration::V7, ObjectClass::EcKeyPair,
                             Rule::ForbidDerivedOutput));
static_assert(!RuleAllowedFor(AppletGeneration::V3, ObjectClass::EcKeyPair,
                              Rule::ForbidDerivedOutput));
static_assert(!RuleAllowedFor(AppletGeneration::V7, ObjectClass::AesKey, Rule::Kdf));
static_assert(RuleAllowedFor(AppletGeneration::V3, ObjectClass::AesKey, Rule::Kdf));
static_assert(RuleAllowedFor(AppletGeneration::V7, ObjectClass::AesKey, Rule::Hkdf));
// AN12543 Table 15: on 7.x READ applies to every class; 0x00800000 is HKDF there, KDF on 3.x.
static_assert(RuleAllowedFor(AppletGeneration::V7, ObjectClass::EcKeyPair, Rule::Read));
static_assert(!RuleAllowedFor(AppletGeneration::V7, ObjectClass::EcKeyPair, Rule::Hkdf));
static_assert(AppletVersion{7U, 2U, 0U}.Generation() == AppletGeneration::V7);
static_assert(AppletVersion{6U, 0U, 0U}.Generation() == AppletGeneration::V6);
static_assert(AppletVersion{3U, 6U, 0U}.Generation() == AppletGeneration::V3);

// --- Attestation formats are different types ---------------------------------------------------
static_assert(!std::same_as<attest::Verifier<Plain, AttestationFormat::V1>,
                            attest::Verifier<Plain, AttestationFormat::V2>>);
static_assert(attest::FormatOf(AppletGeneration::V7) == AttestationFormat::V2);
static_assert(attest::FormatOf(AppletGeneration::V3) == AttestationFormat::V1);
static_assert(attest::TimestampNotBefore(Timestamp{}, Timestamp{}));

// --- Lifecycle preconditions, PERSO, rungs ------------------------------------------------------
static_assert(RequiredRole(Command::SetLockState) == AuthRole::Transport);
static_assert(ReplyEndsSession(Command::DeleteAll));
static_assert(MayResetWithoutReply(Command::TriggerSelfTest));
static_assert(perso::IsKnownTag(0x800DU) && !perso::IsKnownTag(0x8007U) &&
              !perso::IsWritable(perso::Tag::FipsModeEnabled));
static_assert(I2cParams{0x14U}.ManualProtocol() && I2cParams{0x14U}.GpFlavour() &&
              !I2cParams{0x14U}.ClockStretching());
static_assert(I2cParams{0x20U}.DetectionDelayUs() == 100U);
static_assert((static_cast<uint8_t>(t1::Rung::ChipReset) + 1U) ==
              static_cast<uint8_t>(t1::Rung::PowerCycle));
static_assert((kSessionOpenWtxAllowance == 40U) && (kThroughputLimitApdus == 1000000U) &&
              (kThroughputWindowDays == 34U));
static_assert(kMaxAttestedBinaryRead == 500U);
static_assert(std::same_as<ReplyOf<Command::ImportExternalObject>, ExternalImportReceipt>);

template <typename P2>
concept CanReadPerso = requires(P2& p, perso::Tag t, MutableByteSpan o) { p.Read(t, o); };
template <typename P2>
concept CanWritePerso = requires(P2& p, perso::Tag t, ByteSpan v) {
  p.Write(t, v,
          irreversible::Confirmation<irreversible::WritePersoSetting>{
              irreversible::WritePersoSetting::kPhrase});
};
template <typename P2>
concept CanDeleteModule = requires(P2& p) {
  p.DeleteModule(perso::Module::IotExtended,
                 irreversible::Confirmation<irreversible::DeletePersoModule>{
                     irreversible::DeletePersoModule::kPhrase});
};
static_assert(CanReadPerso<perso::Perso<Plain, t1::Link<Plain>>>);
static_assert(CanWritePerso<perso::Perso<Plain, t1::Link<Plain>>> == kIrreversibleEnabled);
static_assert(CanDeleteModule<perso::Perso<Plain, t1::Link<Plain>>> == kIrreversibleEnabled);

struct Fixture {
  NullBus bus;
  NullClock clock;
  ReferenceCrypto crypto;
  NullReset reset;
  NullLog log;
};

} // namespace

TEST_CASE("With nobody on the bus the Device stays closed and refuses commands") {
  Fixture f;
  const Full ports(f.bus, f.clock, f.crypto, f.reset, f.log);
  Device<Full> device(ports, Config{});
  CHECK_EQ(device.Open().error, Error::Nack); // the link finds no chip
  CHECK(!device.IsOpen());
  CHECK_EQ(device.State(), DeviceState::Closed);
  CHECK_EQ(device.GetRandom(MutableByteSpan{}).error, Error::NotInitialized);
  CHECK_EQ(device.Execute<Command::GetRandom>(GetRandomArgs{}).error, Error::NotInitialized);
  CHECK(!device.PowerCycle().ok());
  CHECK_EQ(device.State(), DeviceState::Closed);
}

TEST_CASE("The facade on a closed device: NotInitialized, arguments checked first") {
  Fixture f;
  const Plain ports(f.bus, f.clock, f.crypto);
  Device<Plain> device(ports, Config{});
  hrot::Device<Plain> facade(device);
  CHECK_EQ(facade.Identify().error, Error::NotInitialized);
  CHECK_EQ(facade.Random(MutableByteSpan{}).error, Error::InvalidArgument);
}

TEST_CASE("The link finds nobody, the channel refuses empty keys, the codecs exist") {
  Fixture f;
  const Plain ports(f.bus, f.clock, f.crypto);
  t1::Link<Plain> link(ports, Config{});
  CHECK_EQ(link.Open().error, Error::Nack); // every address phase is refused
  CHECK_EQ(link.State(), t1::LinkState::Closed);
  scp03::Channel<Plain, t1::Link<Plain>> channel(ports, link);
  CHECK_EQ(channel.Open(scp03::ChannelParams{}).error, Error::InvalidArgument); // no static keys
  CHECK(!channel.IsOpen());
  CHECK(Codec<Command::GetRandom>::kImplemented);
  // CRC-16/X-25 (UM11225 2.1.3 p. 9): init 0xFFFF, final XOR 0xFFFF; no input gives 0x0000.
  CHECK(t1::Crc16(ByteSpan{}).ok());
  CHECK_EQ(t1::Crc16(ByteSpan{}).value, 0x0000U);
}

TEST_CASE("The self test needs the acknowledgement and the budget starts at zero") {
  Fixture f;
  const Plain ports(f.bus, f.clock, f.crypto);
  Device<Plain> device(ports, Config{});
  CHECK_EQ(device.TriggerSelfTest(0U, irreversible::ResetExpected{}).error, Error::NotInitialized);
  hrot::Device<Plain> facade(device);
  CHECK_EQ(facade.Budget().issued_by_device, 0U);
  CHECK_EQ(facade.Budget().limit, 1000000U);
  CHECK_EQ(device.Role(), AuthRole::None);
  CHECK(!device.SecureMessagingActive());
}

TEST_CASE("The format 2 verifier refuses a format 1 answer and a missing command") {
  Fixture f;
  const Plain ports(f.bus, f.clock, f.crypto);
  attest::Verifier<Plain, AttestationFormat::V2> v2(ports);
  std::array<uint8_t, 65> key{};
  key[0] = 0x04U; // an uncompressed point, so only the checked field is wrong
  const Timestamp last{};
  const std::array<uint8_t, 4> case1{0x80U, 0x04U, 0x00U, 0x00U};
  attest::Sent sent{};
  sent.command = ByteSpan{case1};
  AttestedRead answer{}; // format 1 by default
  CHECK_EQ(v2.Verify(sent, answer, ByteSpan{}, ByteSpan{}, key, last).error,
           Error::InvalidArgument);
  answer.format = AttestationFormat::V2;
  CHECK_EQ(v2.Verify(attest::Sent{}, answer, ByteSpan{}, ByteSpan{}, key, last).error,
           Error::InvalidArgument);
  // The shape is accepted; the empty signature is then not a valid DER signature.
  CHECK_EQ(v2.Verify(sent, answer, ByteSpan{}, ByteSpan{}, key, last).error,
           Error::AttestationInvalid);
}

static_assert((wire::kUm11225Frame.nad_host_to_se == 0x5AU) &&
              (wire::kUm11225Frame.nad_se_to_host == 0xA5U));
static_assert((wire::kGpFrame.nad_host_to_se == 0x21U) && (wire::kGpFrame.nad_se_to_host == 0x12U));
static_assert((wire::kUm11225Frame.len_bytes == 1U) && (wire::kGpFrame.len_bytes == 2U));
static_assert((wire::kSWtx | wire::kSResponseBit) == 0xE3U);
static_assert(wire::kUmChipReset == wire::kGpRelease,
              "the same code, two meanings: select by flavour");
static_assert(wire::kUmMaxRetransmissions == kMaxFrameRetries);
static_assert((wire::kApduBuffer == 270U) && (wire::kInternalBuffer == 1024U) &&
              (wire::kAeadOneShotMax == 888U));
static_assert(kMaxApduPayload == wire::kInternalBuffer);
// A 940-byte EdDSA verify is a 1028-byte plain APDU; the wire limit has room for two
// secure-messaging layers and the session framing (se05x_device_stage.hpp).
static_assert((kMaxPlainCommandApdu == 1033U) && (kMaxCommandApdu == 1108U));
static_assert(!CanExecute<Device<Plain>, Command::CreateSession>);
static_assert(!CanExecute<Device<Plain>, Command::TriggerSelfTest>);
static_assert((wire::kEddsaSignMax == 940U) && (wire::kEddsaVerifyMax == 940U) &&
              (wire::kEddsaInputMaxUserId == 919U));

TEST_CASE("ReverseBytes gives the wire form of an Edwards or Montgomery value") {
  // RFC 7748 Alice private key, first and last bytes of the wire form of the AN12543 vector V2.
  uint8_t key[4] = {0x01U, 0x02U, 0x03U, 0x04U};
  wire::ReverseBytes(MutableByteSpan(key, 4U));
  CHECK_EQ(key[0], 0x04U);
  CHECK_EQ(key[3], 0x01U);
  uint8_t odd[3] = {0xAAU, 0xBBU, 0xCCU};
  wire::ReverseBytes(MutableByteSpan(odd, 3U));
  CHECK_EQ(odd[1], 0xBBU);
  CHECK_EQ(odd[0], 0xCCU);
  wire::ReverseBytes(MutableByteSpan{});
}

TEST_CASE("Confirmation binds to one operation and its phrase") {
  using irreversible::Confirmation;
  using irreversible::DeleteAllObjects;
  using irreversible::SetLockStatePersistent;
  CHECK(Confirmation<DeleteAllObjects>{DeleteAllObjects::kPhrase}.IsConfirmed());
  CHECK(!Confirmation<DeleteAllObjects>{SetLockStatePersistent::kPhrase}.IsConfirmed());
  CHECK(!irreversible::Plan<DeleteAllObjects>{}.IsPrepared());
}

#ifdef CONTRACT_IRREVERSIBLE_ON
TEST_CASE("With the flag on, an irreversible call without a valid confirmation is refused") {
  Fixture f;
  const Plain ports(f.bus, f.clock, f.crypto);
  Device<Plain> device(ports, Config{});
  const irreversible::Confirmation<irreversible::DeleteAllObjects> wrong{
      irreversible::SetLockStatePersistent::kPhrase};
  const auto r = device.ExecuteIrreversible<Command::DeleteAll, irreversible::DeleteAllObjects>(
      Empty{}, wrong);
  CHECK_EQ(r.error, Error::IrreversibleNotConfirmed);
  const auto closed =
      device.ExecuteIrreversible<Command::DeleteAll, irreversible::DeleteAllObjects>(
          Empty{}, irreversible::Confirmation<irreversible::DeleteAllObjects>{
                       irreversible::DeleteAllObjects::kPhrase});
  CHECK_EQ(closed.error, Error::NotInitialized);
  irreversible::Operations<Plain> ops(device);
  CHECK_EQ(ops.PlanDeleteAllObjects().error, Error::NotInitialized); // closed: nothing planned
  CHECK_EQ(ops.Apply(irreversible::Plan<irreversible::DeleteAllObjects>{},
                     irreversible::Confirmation<irreversible::DeleteAllObjects>{
                         irreversible::DeleteAllObjects::kPhrase})
               .error,
           Error::IrreversibleNotConfirmed);
}
#endif
