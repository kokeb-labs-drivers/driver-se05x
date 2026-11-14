/**
 * @file jobs.hpp
 * @brief The job paths of the getting-started page and the recipes of the HRoT cookbook, as
 * templates over the port set: `tests/docs/jobs.cpp` compiles them for the board ports of the
 * quick start, and `tests/test_docs_jobs.cpp` runs every one against the chip model.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#ifndef SE05X_TESTS_DOCS_JOBS_HPP
#define SE05X_TESTS_DOCS_JOBS_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "se05x.hpp"

namespace jobs {

using namespace se05x;

// --8<-- [start:open-secure]
/// Open the chip with platform SCP03. The keys are handles in your crypto port: never compile key
/// bytes into the image, and never use a vendor default key set in a product.
template <PortSet P>
Error OpenSecure(se05x::Device<P>& device, KeyRef platform_enc, KeyRef platform_mac) noexcept {
  scp03::ChannelParams keys{};
  keys.keys.enc = platform_enc;
  keys.keys.mac = platform_mac;
  if (const auto given = device.SetPlatformKeys(keys); !given.ok()) {
    return given.error;
  }
  return device.Open().error; // Config::scp_policy = ScpPolicy::Require when the device was built
}
// --8<-- [end:open-secure]

// --8<-- [start:provision]
/// Generate the device key in slot 0 and read its public half.
template <PortSet P>
Error ProvisionDeviceKey(hrot::Device<P>& hrot, hrot::EcPublicKey& public_key) noexcept {
  constexpr hrot::Slot kDeviceKey = hrot::Slot::At<0>();
  const std::array<hrot::SlotPlan, 1> plan{hrot::SlotPlan{kDeviceKey, hrot::KeyUse::Sign}};
  if (const auto checked = hrot.CheckPlan(plan); !checked.ok()) {
    return checked.error; // nothing was sent
  }
  const auto key = hrot.template Provision<hrot::KeyUse::Sign>(kDeviceKey);
  if (!key.ok()) {
    return key.error; // ObjectExists: the slot was provisioned before; use Find()
  }
  const auto pub = hrot.GetPublicKey(key.value);
  public_key = pub.value;
  return pub.error;
}
// --8<-- [end:provision]

// --8<-- [start:attest]
/// Prove that the key in slot 0 lives in this chip. `vendor_public` must come from a verified
/// certificate (the se05x::pki layer) or your factory record, never from the same chip.
template <PortSet P>
Error AttestDeviceKey(hrot::Device<P>& hrot, const hrot::EcPublicKey& vendor_public,
                      hrot::EcPublicKey& attested_key) noexcept {
  const auto trusted =
      hrot::TrustAttestationKey(FromReserved(ReservedId::RootOfTrustKey), vendor_public);
  if (!trusted.ok()) {
    return trusted.error;
  }
  const auto value = hrot.Attest(trusted.value, hrot::Slot::At<0>());
  if (!value.ok()) {
    return value.error; // AttestationInvalid, Counterfeit: do not trust this chip
  }
  const hrot::AttestedValue& checked = value.value.Get(); // a Verified<T> exists only if checked
  if (checked.data.length != attested_key.point.size()) {
    return Error::FrameError; // not an uncompressed P-256 point
  }
  for (std::size_t i = 0U; i < attested_key.point.size(); ++i) {
    attested_key.point[i] = checked.data.bytes[i];
  }
  return Error::Ok;
}
// --8<-- [end:attest]

// --8<-- [start:sign]
/// Sign a SHA-256 digest with the device key and check the signature on the chip.
template <PortSet P>
Error SignAndVerify(hrot::Device<P>& hrot, hrot::Digest digest, hrot::Signature& out) noexcept {
  const auto key = hrot.template Find<hrot::KeyUse::Sign>(hrot::Slot::At<0>());
  if (!key.ok()) {
    return key.error;
  }
  const auto signature = hrot.Sign(key.value, digest);
  if (!signature.ok()) {
    return signature.error; // PolicyDenied: no secure messaging
  }
  out = signature.value;
  return hrot.VerifySignature(key.value, digest, out.View()).error; // Ok only when valid
}
// --8<-- [end:sign]

// --8<-- [start:ecdh]
/// Agree a secret with a peer. The key lives in slot 1; the secret is wiped when `shared` goes.
template <PortSet P>
Error AgreeWithPeer(hrot::Device<P>& hrot, const hrot::EcPublicKey& peer,
                    SecretBuffer<32>& shared) noexcept {
  auto key = hrot.template Find<hrot::KeyUse::Agree>(hrot::Slot::At<1>());
  if (key.error == Error::ObjectNotFound) {
    key = hrot.template Provision<hrot::KeyUse::Agree>(hrot::Slot::At<1>());
  }
  if (!key.ok()) {
    return key.error;
  }
  return hrot.Agree(key.value, peer, shared).error;
}
// --8<-- [end:ecdh]

// --8<-- [start:import-anchor]
/// Keep the firmware-signing root in the chip: it verifies, and nobody can replace it.
template <PortSet P>
Error StoreFirmwareRoot(hrot::Device<P>& hrot, const hrot::EcPublicKey& root) noexcept {
  return hrot.ImportPublicKey(hrot::Slot::At<2>(), root).error;
}

/// Verify a firmware image's signature with that root.
template <PortSet P>
Error CheckFirmware(hrot::Device<P>& hrot, hrot::Digest image_digest, ByteSpan signature) noexcept {
  const auto root = hrot.template Find<hrot::KeyUse::Verify>(hrot::Slot::At<2>());
  if (!root.ok()) {
    return root.error;
  }
  return hrot.VerifySignature(root.value, image_digest, signature).error;
}
// --8<-- [end:import-anchor]

// --8<-- [start:import-wrapped]
/// Import an AES key wrapped (RFC 3394) under a key-encryption key already in the chip: the plain
/// key never exists on the host. This is the device layer: the facade has no symmetric keys.
template <PortSet P>
Error ImportWrappedAesKey(se05x::Device<P>& device, ObjectId kek, ObjectId target,
                          ByteSpan wrapped) noexcept {
  const auto policy = PolicyBuilder<AppletGeneration::V7, ObjectClass::AesKey, Profile::Strict>{}
                          .ForAllOthers()
                          .template Allow<Rule::Encrypt>()
                          .template Allow<Rule::Decrypt>()
                          .RequireSecureMessaging()
                          .template Forbid<Rule::Write>()
                          .template Forbid<Rule::Delete>()
                          .Build();
  if (!policy.ok()) {
    return policy.error;
  }
  WriteSymmKeyArgs args{};
  args.id = target;
  args.policy = &policy.value;
  args.type = SymmKeyType::Aes;
  args.key = wrapped; // 24 or 40 bytes: an AES-128 or AES-256 key wrapped
  args.kek = kek;
  return device.template Execute<Command::WriteSymmKey>(args).error;
}
// --8<-- [end:import-wrapped]

// --8<-- [start:aeskey-session]
/// Open an AESKey session with an authentication object of the chip. `key` is a handle in your
/// crypto port; the session ends with EndSession() or Close().
template <PortSet P>
Error OpenAesKeySession(se05x::Device<P>& device, ObjectId credential, KeyRef key) noexcept {
  AesKeySessionParams params{};
  params.credential = credential;
  params.keys.enc = key;
  const auto opened = device.BeginAesKeySession(params);
  if (opened.error == Error::NeedsReselect) {
    return device.Recover().error; // a lost frame under a session: recover, then open it again
  }
  return opened.error;
}
// --8<-- [end:aeskey-session]

// --8<-- [start:storage]
/// Keep a configuration blob that only a host with secure messaging reads back.
template <PortSet P>
Error SealConfig(hrot::Device<P>& hrot, ByteSpan config) noexcept {
  return hrot.Store(hrot::DataSlot::At<0>(), config, hrot::Protection::Secret).error;
}

/// Read it back; the length comes from the chip.
template <PortSet P>
Result<std::size_t> UnsealConfig(hrot::Device<P>& hrot, MutableByteSpan out) noexcept {
  return hrot.Load(hrot::DataSlot::At<0>(), out, hrot::Protection::Secret);
}
// --8<-- [end:storage]

// --8<-- [start:certificates]
/// Store the device certificate your CA issued, and read it back for the TLS stack. The bytes are
/// not parsed here: building and checking X.509 is the se05x::pki layer.
template <PortSet P>
Error KeepCertificate(hrot::Device<P>& hrot, ByteSpan der, MutableByteSpan out) noexcept {
  constexpr hrot::CertSlot kDeviceCert = hrot::CertSlot::At<0>();
  if (const auto stored = hrot.StoreCertificate(kDeviceCert, der); !stored.ok()) {
    return stored.error; // ObjectExists: EraseCertificate() first to replace it
  }
  return hrot.LoadCertificate(kDeviceCert, out).error;
}
// --8<-- [end:certificates]

// --8<-- [start:counters]
/// The anti-rollback check at boot: refuse an image older than one that ran before.
template <PortSet P>
Error BootCheck(hrot::Device<P>& hrot, uint32_t image_version) noexcept {
  constexpr hrot::CounterSlot kFloor = hrot::CounterSlot::At<0>();
  return hrot.CheckFloor(kFloor, image_version).error; // Ok only when not below the floor
}

/// After the new image booted and passed its self test: raise the floor in one command.
template <PortSet P>
Error CommitImage(hrot::Device<P>& hrot, uint32_t image_version) noexcept {
  return hrot.RaiseCounterTo(hrot::CounterSlot::At<0>(), image_version).error;
}
// --8<-- [end:counters]

// --8<-- [start:identity]
/// The factory record: the chip identity and the device public key.
template <PortSet P>
Error FactoryRecord(hrot::Device<P>& hrot, hrot::Identity& identity,
                    hrot::EcPublicKey& public_key) noexcept {
  const auto id = hrot.Identify();
  if (!id.ok()) {
    return id.error;
  }
  identity = id.value;
  return ProvisionDeviceKey(hrot, public_key); // then attest it and send both to your CA
}
// --8<-- [end:identity]

// --8<-- [start:tls]
/// At start-up, once: find the TLS client key (three APDUs), and keep the handle.
template <PortSet P>
Result<hrot::TlsKey> FindTlsKey(hrot::Device<P>& hrot) noexcept {
  return hrot.template Find<hrot::KeyUse::TlsClient>(hrot::Slot::At<3>());
}

/// The private-key callback of a TLS stack: sign the handshake digest with the kept key, one
/// APDU per handshake.
template <PortSet P>
Error TlsSignCallback(hrot::Device<P>& hrot, const hrot::TlsKey& key, hrot::Digest handshake_digest,
                      hrot::Signature& out) noexcept {
  const auto signature = hrot.TlsSign(key, handshake_digest);
  out = signature.value;
  return signature.error;
}
// --8<-- [end:tls]

// --8<-- [start:random]
/// A nonce from the chip's random number generator.
template <PortSet P>
Error Nonce(hrot::Device<P>& hrot, std::array<uint8_t, 16>& nonce) noexcept {
  return hrot.Random(MutableByteSpan{nonce}).error;
}
// --8<-- [end:random]

// --8<-- [start:budget]
/// At boot, give the facade the APDU count your application persisted for the last 34 days; it
/// refuses a call that would pass the chip's ceiling (ThroughputLimited, nothing sent).
template <PortSet P>
uint32_t ApdusLeft(hrot::Device<P>& hrot, uint32_t persisted_count) noexcept {
  hrot.SetWindowCount(persisted_count);
  const hrot::ApduBudget budget = hrot.Budget();
  if (!budget.applies) {
    return budget.limit;
  }
  return (budget.Used() < budget.limit) ? (budget.limit - budget.Used()) : 0U;
}
// --8<-- [end:budget]
// --8<-- [start:wifi]
/// Keep the Wi-Fi passphrase (or a cloud token) in the chip, written once at provisioning: it
/// crosses the bus only encrypted, and the slot refuses a second write (`ObjectExists`).
template <PortSet P>
Error SaveWifiPassphrase(hrot::Device<P>& hrot, ByteSpan passphrase) noexcept {
  return hrot.Store(hrot::DataSlot::At<1>(), passphrase, hrot::Protection::Secret).error;
}

/// Read it back at boot into a buffer that wipes itself; nothing else holds a copy.
template <PortSet P>
Error LoadWifiPassphrase(hrot::Device<P>& hrot, SecretBuffer<64>& passphrase) noexcept {
  std::array<uint8_t, 64> raw{};
  const auto n = hrot.Load(hrot::DataSlot::At<1>(), MutableByteSpan{raw}, hrot::Protection::Secret);
  if (n.ok()) {
    const MutableByteSpan kept = passphrase.Reserve(n.value);
    for (std::size_t i = 0U; i < n.value; ++i) {
      kept[i] = raw[i];
    }
  }
  Zeroize(MutableByteSpan{raw});
  return n.error; // PolicyDenied without encrypted traffic: open platform SCP03 at Full first
}
// --8<-- [end:wifi]

} // namespace jobs

#endif // SE05X_TESTS_DOCS_JOBS_HPP
