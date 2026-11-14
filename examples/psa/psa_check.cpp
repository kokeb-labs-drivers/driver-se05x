/**
 * @file psa_check.cpp
 * @brief The PSA crypto port against known answers and against the reference port, then the whole
 * stack with it: platform SCP03, an AESKey session and the facade's provision, attest and sign
 * against the chip model of the host tests. Built when `SE05X_BUILD_PSA_EXAMPLE` is on and CMake
 * finds MbedTLS 3 (CTest `se05x_psa_check`).
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <array>
#include <cstddef>
#include <cstdint>

#include "model/chip_bench.hpp"
#include "model/scp_crypto.hpp"
#include "se05x.hpp"
#include "se05x_psa_crypto.hpp"
#include "test_harness.hpp"

using namespace se05x;
using testmodel::ChipModel;
using testmodel::ScpTarget;
using testmodel::SimClock;
using testmodel::T1Target;

namespace {

using PsaPorts = Ports<T1Target, SimClock, psa::PsaCrypto>;

/// The chain of the host tests with the PSA port in place of the reference crypto.
struct PsaBench {
  explicit PsaBench(const Config& config) noexcept
      : chip(scp, testmodel::kSe050E), t1(clock, &scp, testmodel::T1Knobs{}),
        ports(t1, clock, crypto), device(ports, config) {
    scp.SetPlatformKeys(testmodel::kPlatformEnc.data(), testmodel::kPlatformMac.data(), 16U, 0x0BU);
    scp.AddAesKey(testmodel::kAesCredential, testmodel::kAesKey.data());
  }
  SimClock clock;
  ScpTarget scp;
  ChipModel chip;
  T1Target t1;
  psa::PsaCrypto crypto;
  PsaPorts ports;
  Device<PsaPorts> device;
};

// RFC 4493 example 2: AES-128 key, a 16-byte message.
constexpr std::array<uint8_t, 16> kCmacKey{0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                                           0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
constexpr std::array<uint8_t, 16> kCmacMsg{0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
                                           0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A};
constexpr std::array<uint8_t, 16> kCmacTag{0x07, 0x0A, 0x16, 0xB4, 0x6B, 0x4D, 0x41, 0x44,
                                           0xF7, 0x9B, 0xDD, 0x9D, 0xD0, 0x4A, 0x28, 0x7C};

} // namespace

TEST_CASE("PSA port: CMAC and CBC match the known answers and the reference port") {
  psa::PsaCrypto p;
  ReferenceCrypto r;
  KeyRef pk{};
  KeyRef rk{};
  REQUIRE(p.ImportKey(KeyKind::Aes128, ByteSpan{kCmacKey}, pk) == CryptoStatus::Ok);
  REQUIRE(r.ImportKey(KeyKind::Aes128, ByteSpan{kCmacKey}, rk) == CryptoStatus::Ok);
  std::array<uint8_t, 16> tag{};
  REQUIRE(p.AesCmac(pk, ByteSpan{kCmacMsg}, tag) == CryptoStatus::Ok);
  CHECK(tag == kCmacTag);
  std::array<uint8_t, 48> a{};
  for (std::size_t i = 0U; i < a.size(); ++i) {
    a[i] = static_cast<uint8_t>(i * 13U);
  }
  std::array<uint8_t, 48> b = a;
  std::array<uint8_t, 16> iva{0x01U};
  std::array<uint8_t, 16> ivb{0x01U};
  REQUIRE(p.AesCbc(pk, true, iva, MutableByteSpan{a}) == CryptoStatus::Ok);
  REQUIRE(r.AesCbc(rk, true, ivb, MutableByteSpan{b}) == CryptoStatus::Ok);
  CHECK(a == b);
  CHECK(iva == ivb);
  REQUIRE(p.AesCbc(pk, false, iva, MutableByteSpan{a}.first(16U)) == CryptoStatus::Ok);
  CHECK(p.KeysInUse() == 1U);
  CHECK(p.ReleaseKey(pk) == CryptoStatus::Ok);
  CHECK(p.ReleaseKey(pk) == CryptoStatus::InvalidKey); // a stale handle
  CHECK(p.AesCmac(pk, ByteSpan{kCmacMsg}, tag) == CryptoStatus::InvalidKey);
}

TEST_CASE("PSA port: P-256 sign, verify and ECDH agree with the reference port") {
  psa::PsaCrypto p;
  ReferenceCrypto r(&testmodel::FixedEntropy);
  const std::array<uint8_t, 32> d{0x1F, 0x2E, 0x3D, 0x4C, 0x5B, 0x6A, 0x79, 0x08, 0x17, 0x26, 0x35,
                                  0x44, 0x53, 0x62, 0x71, 0x0E, 0x0D, 0x1C, 0x2B, 0x3A, 0x49, 0x58,
                                  0x67, 0x76, 0x05, 0x14, 0x23, 0x32, 0x41, 0x50, 0x6F, 0x7E};
  std::array<uint8_t, 65> pub{};
  REQUIRE(testmodel::mc::PublicKey(d.data(), pub.data())); // the model's own P-256
  KeyRef pk{};
  REQUIRE(p.ImportKey(KeyKind::P256Private, ByteSpan{d}, pk) == CryptoStatus::Ok);
  std::array<uint8_t, 32> digest{};
  std::array<uint8_t, 32> ref_digest{};
  REQUIRE(p.Hash(HashAlg::Sha256, ByteSpan{d}, MutableByteSpan{digest}) == CryptoStatus::Ok);
  REQUIRE(r.Hash(HashAlg::Sha256, ByteSpan{d}, MutableByteSpan{ref_digest}) == CryptoStatus::Ok);
  CHECK(digest == ref_digest);
  std::array<uint8_t, 64> sig{};
  REQUIRE(p.EcdsaP256Sign(pk, digest, sig) == CryptoStatus::Ok);
  CHECK(r.EcdsaP256Verify(pub, digest, sig) == CryptoStatus::Ok);
  CHECK(p.EcdsaP256Verify(pub, digest, sig) == CryptoStatus::Ok);
  sig[63] = static_cast<uint8_t>(sig[63] ^ 0x01U);
  CHECK(p.EcdsaP256Verify(pub, digest, sig) == CryptoStatus::Mismatch);
  CHECK(p.EcdsaP256Verify(std::array<uint8_t, 65>{}, digest, sig) == CryptoStatus::InvalidKey);
  // ECDH: an ephemeral PSA key and a reference key derive the same secret.
  KeyRef eph{};
  std::array<uint8_t, 65> eph_pub{};
  REQUIRE(p.GenerateP256(eph, eph_pub) == CryptoStatus::Ok);
  CHECK(p.EcdsaP256Sign(eph, digest, sig) == CryptoStatus::InvalidKey); // derive only
  KeyRef rk{};
  REQUIRE(r.ImportKey(KeyKind::P256Private, ByteSpan{d}, rk) == CryptoStatus::Ok);
  std::array<uint8_t, 32> s1{};
  std::array<uint8_t, 32> s2{};
  REQUIRE(p.EcdhP256(eph, pub, s1) == CryptoStatus::Ok);
  REQUIRE(r.EcdhP256(rk, eph_pub, s2) == CryptoStatus::Ok);
  CHECK(s1 == s2);
  REQUIRE(p.EcdhP256(pk, eph_pub, s1) == CryptoStatus::Ok);
  CHECK(s1 == s2);
  CHECK(p.KeysInUse() == 2U);
}

TEST_CASE("PSA port: the whole stack opens platform SCP03 and runs the facade jobs") {
  Config config{};
  config.scp_policy = ScpPolicy::Require;
  PsaBench b(config);
  scp03::ChannelParams keys{};
  REQUIRE(b.crypto.ImportKey(KeyKind::Aes128, ByteSpan{testmodel::kPlatformEnc}, keys.keys.enc) ==
          CryptoStatus::Ok);
  REQUIRE(b.crypto.ImportKey(KeyKind::Aes128, ByteSpan{testmodel::kPlatformMac}, keys.keys.mac) ==
          CryptoStatus::Ok);
  REQUIRE(b.device.SetPlatformKeys(keys).ok());
  REQUIRE(b.device.Open().ok());
  CHECK(b.scp.platform_open);
  hrot::Device<PsaPorts> facade(b.device);
  const auto key = facade.Provision<hrot::KeyUse::Sign>(hrot::Slot::At<0>());
  REQUIRE(key.ok());
  hrot::EcPublicKey vendor{};
  vendor.point = b.chip.AttestPublic();
  const auto trusted = hrot::TrustAttestationKey(FromReserved(ReservedId::RootOfTrustKey), vendor);
  REQUIRE(trusted.ok());
  const auto attested = facade.Attest(trusted.value, hrot::Slot::At<0>()); // PSA verifies it
  REQUIRE(attested.ok());
  CHECK(attested.value.IsValid());
  std::array<uint8_t, 32> digest{};
  const auto sig = facade.Sign(key.value, hrot::Digest{digest});
  REQUIRE(sig.ok());
  CHECK(facade.VerifySignature(key.value, hrot::Digest{digest}, sig.value.View()).ok());
  AesKeySessionParams session{};
  session.credential = ObjectId{testmodel::kAesCredential};
  REQUIRE(b.crypto.ImportKey(KeyKind::Aes128, ByteSpan{testmodel::kAesKey}, session.keys.enc) ==
          CryptoStatus::Ok);
  REQUIRE(b.device.BeginAesKeySession(session).ok());
  std::array<uint8_t, 16> rnd{};
  CHECK(facade.Random(MutableByteSpan{rnd}).ok());
  REQUIRE(b.device.Close().ok());
  CHECK(!b.device.IsOpen());
  CHECK(b.crypto.KeysInUse() == 3U); // the caller's three handles: every session key released
}
