/**
 * @file test_pki_recipes.cpp
 * @brief The PKI page's provisioning recipes (`tests/docs/pki_recipes.hpp`), run against the chip
 * model: the documentation shows code that works, not only code that compiles.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <array>
#include <cstddef>
#include <cstdint>

#include "docs/pki_recipes.hpp"
#include "model/chip_bench.hpp"
#include "pki_test_util.hpp"
#include "test_harness.hpp"
#include "vectors/pki_vectors.hpp"

using namespace se05x;
using testmodel::BenchPorts;
using testmodel::ChipBench;

namespace {

constexpr ObjectId kKey{0x00003001U};
constexpr ObjectId kCert{0x00003002U};
constexpr ObjectId kAnchor{0x00003003U};
constexpr AuthObject kAdmin{ObjectId{testmodel::kAesCredential}};
constexpr AppletGeneration kV7 = AppletGeneration::V7;
constexpr std::array<uint8_t, 18> kUniqueId{0x04U, 0x00U, 0x50U, 0x01U, 0x23U, 0x45U,
                                            0x67U, 0x89U, 0xABU, 0xCDU, 0xEFU, 0x10U,
                                            0x32U, 0x54U, 0x76U, 0x98U, 0xBAU, 0xDCU};

/// The CA's side, for the test only: issue a certificate for the key in the request.
struct TestCa {
  pkitest::TestIssuer issuer;
  std::array<uint8_t, 64> name{};
  std::array<uint8_t, 600> ca{};
  std::array<uint8_t, 600> leaf{};
  std::size_t ca_size{0};
  std::size_t leaf_size{0};

  bool Issue(const pki::CsrInfo& request) {
    constexpr std::array<uint8_t, 7> kCaName{0x54U, 0x65U, 0x73U, 0x74U, 0x20U, 0x43U, 0x41U};
    pki::Name n{};
    static_cast<void>(n.Add(pki::Attribute::CommonName, ByteSpan{kCaName}));
    pkitest::CertSpec spec{};
    spec.issuer = pkitest::EncodeName(n, name);
    spec.subject = spec.issuer;
    spec.key = issuer.Key();
    spec.ca = true;
    spec.key_usage = pki::key_usage::kKeyCertSign;
    ca_size = issuer.Issue(spec, MutableByteSpan{ca});
    spec.subject = request.subject;
    spec.key = request.key;
    spec.ca = false;
    spec.key_usage = pki::key_usage::kDigitalSignature;
    spec.serial = 7U;
    leaf_size = issuer.Issue(spec, MutableByteSpan{leaf});
    return (ca_size != 0U) && (leaf_size != 0U);
  }
};

} // namespace

TEST_CASE("PKI recipes: generate, request, import, check, as the PKI page shows them") {
  ChipBench b;
  REQUIRE(b.device.Open().ok());
  std::array<uint8_t, 65> pub{};
  const Result<pki::PublicKey> key =
      pki_recipes::GenerateDeviceKey<kV7>(b.device, kKey, std::span<uint8_t, 65>{pub});
  REQUIRE(key.ok());
  std::array<uint8_t, 400> csr{};
  const Result<std::size_t> request = pki_recipes::MakeCsr(
      b.device, b.crypto, kKey, key.value, ByteSpan{kUniqueId}, MutableByteSpan{csr});
  REQUIRE(request.ok());
  pki::PortVerifier<ReferenceCrypto> verifier(b.crypto);
  const Result<pki::CsrInfo> info =
      pki::VerifyCsr(ByteSpan{csr}.first(request.value), verifier, b.crypto);
  REQUIRE(info.ok());
  TestCa ca;
  REQUIRE(ca.Issue(info.value));
  REQUIRE(pki_recipes::ImportCertificates<kV7>(b.device, kCert,
                                               ByteSpan{ca.leaf}.first(ca.leaf_size), kAnchor,
                                               ByteSpan{ca.ca}.first(ca.ca_size), kAdmin)
              .ok());
  CHECK_EQ(pki_recipes::CheckDeviceCertificate(b.device, b.crypto, kCert, kAnchor, pkitest::Now()),
           Error::Ok);
  // Expired by the clock: the check says so and why.
  const uint64_t late = pki::ToUnixSeconds(pki::Time{2046U, 1U, 1U, 0U, 0U, 0U});
  CHECK_EQ(pki_recipes::CheckDeviceCertificate(b.device, b.crypto, kCert, kAnchor, late),
           Error::AttestationInvalid);
  // Importing again does not overwrite.
  CHECK_EQ(
      pki_recipes::ImportCertificates<kV7>(b.device, kCert, ByteSpan{ca.leaf}.first(ca.leaf_size),
                                           kAnchor, ByteSpan{ca.ca}.first(ca.ca_size), kAdmin)
          .error,
      Error::ObjectExists);
}

TEST_CASE("PKI recipes: failures come back with the layer's error") {
  ChipBench b;
  std::array<uint8_t, 65> pub{};
  CHECK_EQ(pki_recipes::GenerateDeviceKey<kV7>(b.device, kKey, std::span<uint8_t, 65>{pub}).error,
           Error::NotInitialized);
  REQUIRE(b.device.Open().ok());
  CHECK_EQ(pki_recipes::CheckDeviceCertificate(b.device, b.crypto, kCert, kAnchor, pkitest::Now()),
           Error::ObjectNotFound);
  const pki::PublicKey wrong{pki::KeyType::EcP256, ByteSpan{pub}};
  std::array<uint8_t, 400> csr{};
  CHECK_EQ(pki_recipes::MakeCsr(b.device, b.crypto, kKey, wrong, ByteSpan{kUniqueId},
                                MutableByteSpan{csr})
               .error,
           Error::InvalidArgument); // an all-zero key is not a point: refused before signing
  const Result<pki::PublicKey> key =
      pki_recipes::GenerateDeviceKey<kV7>(b.device, kKey, std::span<uint8_t, 65>{pub});
  REQUIRE(key.ok());
  const Result<pki::Certificate> other = pki::ParseCertificate(ByteSpan{testvec::kLeafP256});
  REQUIRE(other.ok());
  const pki::PublicKey mismatched = other.value.public_key; // a valid key, not the chip's
  CHECK_EQ(pki_recipes::MakeCsr(b.device, b.crypto, kKey, mismatched, ByteSpan{kUniqueId},
                                MutableByteSpan{csr})
               .error,
           Error::AttestationInvalid); // the self check: the chip's key is not that one
}
