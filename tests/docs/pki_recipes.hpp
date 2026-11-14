/**
 * @file pki_recipes.hpp
 * @brief The provisioning recipes of the PKI page as templates over the port set:
 * `tests/docs/pki_recipes.cpp` compiles them for the board ports of the quick start, and
 * `tests/test_pki_recipes.cpp` runs every one against the chip model.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#ifndef SE05X_TESTS_DOCS_PKI_RECIPES_HPP
#define SE05X_TESTS_DOCS_PKI_RECIPES_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "se05x.hpp"
#include "se05x_pki.hpp"

namespace pki_recipes {

using namespace se05x;

// --8<-- [start:generate]
/// Step 1: generate the device key inside the chip and read its public half. The policy lets
/// anybody sign with it under secure messaging and nobody write, delete or regenerate it.
template <AppletGeneration G, PortSet P>
Result<pki::PublicKey> GenerateDeviceKey(se05x::Device<P>& device, ObjectId key,
                                         std::span<uint8_t, 65> public_key) noexcept {
  const Result<Policy> policy = PolicyBuilder<G, ObjectClass::EcKeyPair, Profile::Strict>{}
                                    .ForAllOthers()
                                    .template Allow<Rule::Sign>()
                                    .template Forbid<Rule::Write>()
                                    .template Forbid<Rule::Delete>()
                                    .template Forbid<Rule::Gen>()
                                    .RequireSecureMessaging()
                                    .Build();
  if (!policy.ok()) {
    return Result<pki::PublicKey>::Failure(policy.error, policy.detail);
  }
  if (const auto made = device.GenerateEcKey(key, policy.value, EcCurve::NistP256); !made.ok()) {
    return Result<pki::PublicKey>::Failure(made.error, made.detail);
  }
  return pki::ReadPublicKey(device, key, pki::KeyType::EcP256, MutableByteSpan{public_key});
}
// --8<-- [end:generate]

// --8<-- [start:csr]
/// Step 2: a certification request for that key, signed by the chip, with the chip's unique id
/// as the subject's serialNumber. The request is checked against its own key before it leaves.
template <PortSet P, typename Crypto>
Result<std::size_t> MakeCsr(se05x::Device<P>& device, Crypto& crypto, ObjectId key,
                            const pki::PublicKey& public_key, ByteSpan unique_id,
                            MutableByteSpan csr) noexcept {
  constexpr std::array<uint8_t, 6> kOrganization{0x44U, 0x65U, 0x76U, 0x69U, 0x63U, 0x65U};
  pki::Name subject{};
  static_cast<void>(subject.Add(pki::Attribute::Organization, ByteSpan{kOrganization})
                        .AddHex(pki::Attribute::SerialNumber, unique_id));
  const pki::CsrRequest request{&subject, public_key, nullptr, pki::key_usage::kDigitalSignature};
  pki::DeviceSigner<P> signer(device, key, pki::KeyType::EcP256);
  const Result<std::size_t> built = pki::BuildCsr(request, signer, crypto, csr);
  if (!built.ok()) {
    return built;
  }
  pki::PortVerifier<Crypto> verifier(crypto);
  const auto checked = pki::VerifyCsr(ByteSpan{csr}.first(built.value), verifier, crypto);
  return checked.ok() ? built : Result<std::size_t>::Failure(checked.error, checked.detail);
}
// --8<-- [end:csr]

// --8<-- [start:import]
/// Step 3: store the certificate the CA issued, and the CA's certificate as the trust anchor,
/// each in a new binary object nobody can write; `admin` may delete them to rotate.
template <AppletGeneration G, PortSet P>
Result<void> ImportCertificates(se05x::Device<P>& device, ObjectId certificate, ByteSpan issued,
                                ObjectId anchor, ByteSpan ca_certificate,
                                AuthObject admin) noexcept {
  const Result<Policy> policy = pki::CertificatePolicy<G>(admin);
  if (!policy.ok()) {
    return Result<void>::Failure(policy.error, policy.detail);
  }
  std::array<uint8_t, 1024> scratch{};
  const auto stored_anchor =
      pki::StoreCertificate(device, anchor, ca_certificate, policy.value, scratch);
  if (!stored_anchor.ok()) {
    return stored_anchor;
  }
  return pki::StoreCertificate(device, certificate, issued, policy.value, scratch);
}
// --8<-- [end:import]

// --8<-- [start:check]
/// At every boot: read the certificate and the anchor back and verify the chain at `now` (Unix
/// seconds from a clock you trust). The verified key is the one the chip signs with.
template <PortSet P, typename Crypto>
Error CheckDeviceCertificate(se05x::Device<P>& device, Crypto& crypto, ObjectId certificate,
                             ObjectId anchor, uint64_t now) noexcept {
  std::array<uint8_t, 1024> anchor_bytes{};
  std::array<uint8_t, 1024> cert_bytes{};
  const auto trusted = pki::LoadTrustAnchor(device, anchor, anchor_bytes);
  const auto cert = pki::ReadCertificate(device, certificate, cert_bytes);
  if (!trusted.ok() || !cert.ok()) {
    return trusted.ok() ? cert.error : trusted.error;
  }
  const std::array<ByteSpan, 1> chain{cert.value.der};
  const std::array<pki::TrustAnchor, 1> anchors{trusted.value};
  pki::PortVerifier<Crypto> verifier(crypto);
  const pki::VerifyOptions options{now, pki::key_usage::kDigitalSignature, false};
  const auto verified =
      pki::VerifyChain(std::span<const ByteSpan>{chain}, std::span<const pki::TrustAnchor>{anchors},
                       options, verifier, crypto);
  return verified.error; // AttestationInvalid: pki::ReasonOf(verified.detail) says why
}
// --8<-- [end:check]

} // namespace pki_recipes

#endif // SE05X_TESTS_DOCS_PKI_RECIPES_HPP
