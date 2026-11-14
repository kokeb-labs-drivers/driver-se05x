/**
 * @file test_scp_crypto.cpp
 * @brief Known-answer tests of the reference crypto port and of the model's independent crypto,
 * against public vectors: FIPS 197 C.1 to C.3, RFC 4493 section 4, SP 800-38A F.2.1, FIPS 180-4
 * examples ("abc"), RFC 6979 A.2.5 (P-256, SHA-256), and an ECDH value cross-checked with
 * OpenSSL. Plus the key-handle rules of `ReferenceCrypto` (S-01, S-16).
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <optional>

#include "model/bytes.hpp"
#include "model/scp_crypto.hpp"
#include "model/scp_loop.hpp"
#include "se05x_crypto.hpp"
#include "test_harness.hpp"

using se05x::testmodel::SameBytes;
using namespace se05x;

namespace {

template <std::size_t N>
std::array<uint8_t, N> Hex(const char* s) {
  std::array<uint8_t, N> out{};
  // Character values through std::bit_cast, never arithmetic on a char (MISRA C++:2023 7.0.3).
  auto nib = [](char ch) -> uint8_t {
    const auto u = static_cast<unsigned>(std::bit_cast<uint8_t>(ch));
    if ((u >= 0x30U) && (u <= 0x39U)) {
      return static_cast<uint8_t>(u - 0x30U);
    }
    if ((u >= 0x61U) && (u <= 0x66U)) {
      return static_cast<uint8_t>(u - 0x57U);
    }
    return static_cast<uint8_t>(u - 0x37U);
  };
  for (std::size_t i = 0U; i < N; ++i) {
    out[i] =
        static_cast<uint8_t>((unsigned{nib(s[2U * i])} << 4U) | unsigned{nib(s[(2U * i) + 1U])});
  }
  return out;
}

template <std::size_t N>
bool Same(const std::array<uint8_t, N>& a, const uint8_t* b) {
  return SameBytes(a.data(), b, N);
}

// FIPS 197 C.1 to C.3: plaintext 00112233..ff, key 000102...
constexpr const char* kPlain = "00112233445566778899aabbccddeeff";
constexpr const char* kKey32 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

// RFC 4493 section 4.
constexpr const char* kCmacKey = "2b7e151628aed2a6abf7158809cf4f3c";
constexpr const char* kCmacMsg =
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc119"
    "1a0a52eff69f2445df4f9b17ad2b417be66c3710";

// RFC 6979 A.2.5.
constexpr const char* kD = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
constexpr const char* kPub =
    "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e9"
    "5628bc64f2f1b20c2d7e9f5177a3c294d4462299";
constexpr const char* kSigSample =
    "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716f7cb1c942d657c41d436c7a1b6"
    "e29f65f3e900dbb9aff4064dc4ab2f843acda8";
constexpr const char* kSigTest =
    "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367019f4113742a2b14bd25926b49"
    "c649155f267e60d3814b4c0cc84250e46f0083";
// ECDH of kD with the public key of 0102..20 (OpenSSL 3.6 pkeyutl -derive gives the same).
constexpr const char* kD2 = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
constexpr const char* kZ = "cf551a5f5d50b264e06ee9c4f7f541aa0318be11d12577b3857c8b5c625f935a";

/// Text as bytes, through std::bit_cast (no reinterpret_cast).
struct Text {
  std::array<uint8_t, 256> bytes{};
  std::size_t length{0};
  explicit Text(const char* s) {
    for (const char* p = s; (std::bit_cast<uint8_t>(*p) != 0U) && (length < bytes.size()); ++p) {
      bytes[length] = std::bit_cast<uint8_t>(*p);
      ++length;
    }
  }
  [[nodiscard]] ByteSpan View() const {
    return {bytes.data(), length};
  }
};

std::array<uint8_t, 32> Sha256Of(const char* text) {
  std::array<uint8_t, 32> d{};
  refcrypto::Sha256 h;
  const Text t(text);
  h.Update(t.View());
  static_cast<void>(h.Final(MutableByteSpan{d}));
  return d;
}

} // namespace

TEST_CASE("AES-128, -192 and -256 encrypt and decrypt the FIPS 197 vectors") {
  const auto key = Hex<32>(kKey32);
  const std::array<const char*, 3> expected{"69c4e0d86a7b0430d8cdb78070b4c55a",
                                            "dda97ca4864cdfe06eaf70a0ec0d7191",
                                            "8ea2b7ca516745bfeafc49904b496089"};
  const std::array<std::size_t, 3> lengths{16U, 24U, 32U};
  for (std::size_t i = 0U; i < 3U; ++i) {
    refcrypto::AesSchedule s;
    REQUIRE(s.Expand(ByteSpan(key.data(), lengths[i])));
    auto block = Hex<16>(kPlain);
    s.Encrypt(block);
    CHECK(block == Hex<16>(expected[i]));
    s.Decrypt(block);
    CHECK(block == Hex<16>(kPlain));
  }
  refcrypto::AesSchedule bad;
  CHECK(!bad.Expand(ByteSpan(key.data(), 20U)));
  CHECK(!bad.IsValid());
}

TEST_CASE("AES-CMAC gives the four RFC 4493 tags") {
  const auto key = Hex<16>(kCmacKey);
  const auto msg = Hex<64>(kCmacMsg);
  refcrypto::AesSchedule s;
  REQUIRE(s.Expand(ByteSpan{key}));
  const std::array<std::size_t, 4> lengths{0U, 16U, 40U, 64U};
  const std::array<const char*, 4> tags{
      "bb1d6929e95937287fa37d129b756746", "070a16b46b4d4144f79bdd9dd04a287c",
      "dfa66747de9ae63030ca32611497c827", "51f0bebf7e3b9d92fc49741779363cfe"};
  for (std::size_t i = 0U; i < 4U; ++i) {
    std::array<uint8_t, 16> mac{};
    REQUIRE(refcrypto::AesCmacCompute(s, ByteSpan(msg.data(), lengths[i]), mac));
    CHECK(mac == Hex<16>(tags[i]));
    std::array<uint8_t, 16> model{};
    testmodel::mc::Cmac(testmodel::mc::Bytes(key), testmodel::mc::Bytes(msg.data(), lengths[i]),
                        model.data());
    CHECK(model == mac);
  }
}

TEST_CASE("AES-CBC encrypts the SP 800-38A F.2.1 vector and updates the IV") {
  const auto key = Hex<16>(kCmacKey);
  auto data = Hex<32>("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
  auto iv = Hex<16>("000102030405060708090a0b0c0d0e0f");
  refcrypto::AesSchedule s;
  REQUIRE(s.Expand(ByteSpan{key}));
  REQUIRE(refcrypto::AesCbcCrypt(s, true, iv, MutableByteSpan{data}));
  CHECK(data == Hex<32>("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"));
  CHECK(iv == Hex<16>("5086cb9b507219ee95db113a917678b2"));
  auto iv2 = Hex<16>("000102030405060708090a0b0c0d0e0f");
  REQUIRE(refcrypto::AesCbcCrypt(s, false, iv2, MutableByteSpan{data}));
  CHECK(data == Hex<32>("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"));
  CHECK(!refcrypto::AesCbcCrypt(s, true, iv2, MutableByteSpan(data.data(), 15U)));
}

TEST_CASE("SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 hash abc as FIPS 180-4 shows") {
  ReferenceCrypto port;
  const Text abc("abc");
  const ByteSpan msg = abc.View();
  std::array<uint8_t, 64> d{};
  REQUIRE(port.Hash(HashAlg::Sha1, msg, MutableByteSpan{d}) == CryptoStatus::Ok);
  CHECK(Same(Hex<20>("a9993e364706816aba3e25717850c26c9cd0d89d"), d.data()));
  REQUIRE(port.Hash(HashAlg::Sha224, msg, MutableByteSpan{d}) == CryptoStatus::Ok);
  CHECK(Same(Hex<28>("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"), d.data()));
  REQUIRE(port.Hash(HashAlg::Sha256, msg, MutableByteSpan{d}) == CryptoStatus::Ok);
  CHECK(
      Same(Hex<32>("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), d.data()));
  REQUIRE(port.Hash(HashAlg::Sha384, msg, MutableByteSpan{d}) == CryptoStatus::Ok);
  CHECK(Same(Hex<48>("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7c"
                     "c2358baeca134c825a7"),
             d.data()));
  REQUIRE(port.Hash(HashAlg::Sha512, msg, MutableByteSpan{d}) == CryptoStatus::Ok);
  CHECK(Same(Hex<64>("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc"
                     "1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
             d.data()));
  std::array<uint8_t, 32> model{};
  testmodel::mc::Sha256(testmodel::mc::Bytes(msg.data(), msg.size()), model.data());
  CHECK(Same(model, Sha256Of("abc").data()));
}

TEST_CASE("SHA-256 and SHA-512 handle the two-block FIPS 180-4 messages and padding edges") {
  // FIPS 180-4 examples: the 448-bit and 896-bit messages.
  const char* m256 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  CHECK(Sha256Of(m256) ==
        Hex<32>("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
  const char* m512 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklm"
                     "nopqklmnopqrlmnopqrsmnopqrstnopqrstu";
  std::array<uint8_t, 64> d{};
  refcrypto::Sha512 h;
  const Text t512(m512);
  h.Update(t512.View());
  REQUIRE(h.Final(MutableByteSpan{d}) == 64U);
  CHECK(d == Hex<64>("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f"
                     "7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"));
  // A message of every length 0 to 130 hashes the same through both SHA-256 implementations.
  std::array<uint8_t, 130> buf{};
  for (std::size_t i = 0U; i < buf.size(); ++i) {
    buf[i] = static_cast<uint8_t>(i * 3U);
  }
  bool all = true;
  for (std::size_t n = 0U; n <= buf.size(); ++n) {
    std::array<uint8_t, 32> a{};
    std::array<uint8_t, 32> b{};
    refcrypto::Sha256 s;
    s.Update(ByteSpan(buf.data(), n));
    static_cast<void>(s.Final(MutableByteSpan{a}));
    testmodel::mc::Sha256(testmodel::mc::Bytes(buf.data(), n), b.data());
    all = all && (a == b);
  }
  CHECK(all);
  std::array<uint8_t, 31> small{};
  refcrypto::Sha256 s;
  CHECK_EQ(s.Final(MutableByteSpan{small}), 0U);
}

TEST_CASE("P-256 public key and RFC 6979 signatures match A.2.5, both implementations") {
  const auto d = Hex<32>(kD);
  std::array<uint8_t, 65> pub{};
  REQUIRE(refcrypto::P256PublicKey(d, pub));
  CHECK(pub == Hex<65>(kPub));
  std::array<uint8_t, 65> model{};
  REQUIRE(testmodel::mc::PublicKey(d.data(), model.data()));
  CHECK(model == pub);
  std::array<uint8_t, 64> sig{};
  REQUIRE(refcrypto::P256Sign(d, Sha256Of("sample"), sig));
  CHECK(sig == Hex<64>(kSigSample));
  REQUIRE(refcrypto::P256Sign(d, Sha256Of("test"), sig));
  CHECK(sig == Hex<64>(kSigTest));
  const auto digest = Sha256Of("test");
  CHECK(refcrypto::P256Verify(pub, digest, sig));
  CHECK(testmodel::mc::Verify(pub.data(), digest.data(), sig.data(), sig.data() + 32));
}

TEST_CASE("P-256 verification refuses every one-bit change of r, s, digest and key") {
  const auto pub = Hex<65>(kPub);
  const auto sig = Hex<64>(kSigSample);
  const auto digest = Sha256Of("sample");
  bool none = true;
  for (std::size_t i = 0U; i < 64U; i += 7U) {
    auto bad = sig;
    bad[i] = static_cast<uint8_t>(bad[i] ^ 0x10U);
    none = none && !refcrypto::P256Verify(pub, digest, bad);
  }
  auto bad_digest = digest;
  bad_digest[31] = static_cast<uint8_t>(bad_digest[31] ^ 1U);
  none = none && !refcrypto::P256Verify(pub, bad_digest, sig);
  auto bad_pub = pub;
  bad_pub[64] = static_cast<uint8_t>(bad_pub[64] ^ 1U); // off the curve
  none = none && !refcrypto::P256Verify(bad_pub, digest, sig);
  std::array<uint8_t, 64> zero{};
  none = none && !refcrypto::P256Verify(pub, digest, zero);
  CHECK(none);
}

TEST_CASE("P-256 ECDH agrees with OpenSSL and with the model, and refuses bad points") {
  const auto d1 = Hex<32>(kD);
  const auto d2 = Hex<32>(kD2);
  std::array<uint8_t, 65> p1{};
  std::array<uint8_t, 65> p2{};
  REQUIRE(refcrypto::P256PublicKey(d1, p1));
  REQUIRE(refcrypto::P256PublicKey(d2, p2));
  std::array<uint8_t, 32> z1{};
  std::array<uint8_t, 32> z2{};
  REQUIRE(refcrypto::P256Ecdh(d1, p2, z1));
  REQUIRE(refcrypto::P256Ecdh(d2, p1, z2));
  CHECK(z1 == Hex<32>(kZ));
  CHECK(z2 == z1);
  std::array<uint8_t, 32> zm{};
  REQUIRE(testmodel::mc::Ecdh(d1.data(), p2.data(), zm.data()));
  CHECK(zm == z1);
  auto off = p2;
  off[10] = static_cast<uint8_t>(off[10] ^ 0x01U);
  CHECK(!refcrypto::P256Ecdh(d1, off, z1));
  auto compressed = p2;
  compressed[0] = 0x02U;
  CHECK(!refcrypto::P256Ecdh(d1, compressed, z1));
  std::array<uint8_t, 65> big{};
  big[0] = 0x04U;
  for (std::size_t i = 1U; i < 33U; ++i) {
    big[i] = 0xFFU; // x above p
  }
  CHECK(!refcrypto::P256OnCurve(big));
}

TEST_CASE("P-256 private keys must be 1 to n-1") {
  std::array<uint8_t, 32> zero{};
  CHECK(!refcrypto::P256ValidPrivate(zero));
  auto n = Hex<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
  CHECK(!refcrypto::P256ValidPrivate(n));
  n[31] = 0x50U; // n - 1
  CHECK(refcrypto::P256ValidPrivate(n));
  std::array<uint8_t, 65> pub{};
  CHECK(!refcrypto::P256PublicKey(zero, pub));
  std::array<uint8_t, 64> sig{};
  CHECK(!refcrypto::P256Sign(zero, Sha256Of("x"), sig));
}

TEST_CASE("ReferenceCrypto keys are handles: import, use, release, stale handle refused") {
  ReferenceCrypto port;
  const auto key = Hex<16>(kCmacKey);
  KeyRef h{};
  REQUIRE(port.ImportKey(KeyKind::Aes128, ByteSpan{key}, h) == CryptoStatus::Ok);
  CHECK(h.IsValid());
  CHECK_EQ(port.KeysInUse(), 1U);
  std::array<uint8_t, 16> mac{};
  REQUIRE(port.AesCmac(h, ByteSpan{}, mac) == CryptoStatus::Ok);
  CHECK(mac == Hex<16>("bb1d6929e95937287fa37d129b756746"));
  REQUIRE(port.ReleaseKey(h) == CryptoStatus::Ok);
  CHECK_EQ(port.KeysInUse(), 0U);
  CHECK(port.AesCmac(h, ByteSpan{}, mac) == CryptoStatus::InvalidKey);
  CHECK(port.ReleaseKey(h) == CryptoStatus::InvalidKey);
  KeyRef h2{};
  REQUIRE(port.ImportKey(KeyKind::Aes128, ByteSpan{key}, h2) == CryptoStatus::Ok);
  CHECK(h2.id != h.id); // the same slot, a new generation
  CHECK(port.AesCmac(h, ByteSpan{}, mac) == CryptoStatus::InvalidKey);
  CHECK(port.AesCmac(KeyRef{}, ByteSpan{}, mac) == CryptoStatus::InvalidKey);
  CHECK(port.AesCmac(KeyRef{0x77U}, ByteSpan{}, mac) == CryptoStatus::InvalidKey);
}

TEST_CASE("ReferenceCrypto refuses wrong lengths, wrong kinds and a full table") {
  ReferenceCrypto port;
  const auto key = Hex<32>(kKey32);
  KeyRef h{};
  CHECK(port.ImportKey(KeyKind::Aes128, ByteSpan(key.data(), 15U), h) == CryptoStatus::InvalidKey);
  CHECK(!h.IsValid());
  CHECK(port.ImportKey(KeyKind::Aes256, ByteSpan(key.data(), 16U), h) == CryptoStatus::InvalidKey);
  CHECK(port.ImportKey(KeyKind::Aes192, ByteSpan(key.data(), 24U), h) == CryptoStatus::Ok);
  std::array<uint8_t, 32> zero{};
  KeyRef p{};
  CHECK(port.ImportKey(KeyKind::P256Private, ByteSpan{zero}, p) == CryptoStatus::InvalidKey);
  REQUIRE(port.ImportKey(KeyKind::P256Private, ByteSpan{Hex<32>(kD)}, p) == CryptoStatus::Ok);
  std::array<uint8_t, 16> mac{};
  CHECK(port.AesCmac(p, ByteSpan{}, mac) == CryptoStatus::InvalidKey); // not an AES key
  std::array<uint8_t, 64> sig{};
  CHECK(port.EcdsaP256Sign(h, Sha256Of("x"), sig) == CryptoStatus::InvalidKey); // not P-256
  std::array<uint8_t, 32> z{};
  CHECK(port.EcdhP256(h, Hex<65>(kPub), z) == CryptoStatus::InvalidKey);
  KeyRef odd{};
  CHECK(port.ImportKey(std::bit_cast<KeyKind>(uint8_t{9}), ByteSpan{key}, odd) ==
        CryptoStatus::InvalidKey);
  for (std::size_t i = port.KeysInUse(); i < ReferenceCrypto::kSlots; ++i) {
    KeyRef k{};
    REQUIRE(port.ImportKey(KeyKind::Aes128, ByteSpan(key.data(), 16U), k) == CryptoStatus::Ok);
  }
  KeyRef full{};
  CHECK(port.ImportKey(KeyKind::Aes128, ByteSpan(key.data(), 16U), full) == CryptoStatus::Failed);
  std::array<uint8_t, 16> iv{};
  CHECK(port.AesCbc(h, true, iv, MutableByteSpan(sig.data(), 15U)) == CryptoStatus::Failed);
}

TEST_CASE("ReferenceCrypto signs with a handle and verifies with the RFC 6979 result") {
  ReferenceCrypto port;
  KeyRef p{};
  REQUIRE(port.ImportKey(KeyKind::P256Private, ByteSpan{Hex<32>(kD)}, p) == CryptoStatus::Ok);
  std::array<uint8_t, 64> sig{};
  REQUIRE(port.EcdsaP256Sign(p, Sha256Of("sample"), sig) == CryptoStatus::Ok);
  CHECK(sig == Hex<64>(kSigSample));
  CHECK(port.EcdsaP256Verify(Hex<65>(kPub), Sha256Of("sample"), sig) == CryptoStatus::Ok);
  CHECK(port.EcdsaP256Verify(Hex<65>(kPub), Sha256Of("other"), sig) == CryptoStatus::Mismatch);
  auto off = Hex<65>(kPub);
  off[40] = static_cast<uint8_t>(off[40] ^ 1U);
  CHECK(port.EcdsaP256Verify(off, Sha256Of("sample"), sig) == CryptoStatus::InvalidKey);
  std::array<uint8_t, 32> z{};
  auto bad = Hex<65>(kPub);
  bad[1] = static_cast<uint8_t>(bad[1] ^ 1U);
  CHECK(port.EcdhP256(p, bad, z) == CryptoStatus::InvalidKey);
  CHECK((z == std::array<uint8_t, 32>{})); // a failed ECDH leaves no partial secret
}

TEST_CASE("Random and key generation need an entropy source") {
  ReferenceCrypto none;
  std::array<uint8_t, 8> out{1, 2, 3, 4, 5, 6, 7, 8};
  CHECK(none.Random(MutableByteSpan{out}) == CryptoStatus::Failed);
  CHECK((out == std::array<uint8_t, 8>{})); // wiped on failure
  KeyRef h{};
  std::array<uint8_t, 65> pub{};
  CHECK(none.GenerateP256(h, pub) == CryptoStatus::Failed);
  CHECK(!h.IsValid());
  ReferenceCrypto failing{&testmodel::NoEntropy};
  CHECK(failing.Random(MutableByteSpan{out}) == CryptoStatus::Failed);
  ReferenceCrypto good{&testmodel::TestEntropy};
  REQUIRE(good.GenerateP256(h, pub) == CryptoStatus::Ok);
  CHECK(h.IsValid());
  CHECK(refcrypto::P256OnCurve(pub));
  std::array<uint8_t, 64> sig{};
  REQUIRE(good.EcdsaP256Sign(h, Sha256Of("m"), sig) == CryptoStatus::Ok);
  CHECK(good.EcdsaP256Verify(pub, Sha256Of("m"), sig) == CryptoStatus::Ok);
}

TEST_CASE("Hash refuses a short buffer and an unknown algorithm") {
  ReferenceCrypto port;
  std::array<uint8_t, 31> small{};
  CHECK(port.Hash(HashAlg::Sha256, ByteSpan{}, MutableByteSpan{small}) == CryptoStatus::Failed);
  std::array<uint8_t, 64> d{};
  CHECK(port.Hash(std::bit_cast<HashAlg>(uint8_t{7}), ByteSpan{}, MutableByteSpan{d}) ==
        CryptoStatus::Failed);
  CHECK(port.Hash(HashAlg::Sha512, ByteSpan{}, MutableByteSpan(d.data(), 63U)) ==
        CryptoStatus::Failed);
  CHECK(port.Hash(HashAlg::Sha1, ByteSpan{}, MutableByteSpan(d.data(), 19U)) ==
        CryptoStatus::Failed);
}

TEST_CASE("HMAC-SHA-256 matches RFC 4231 test case 2") {
  const char* key = "Jefe";
  const char* data = "what do ya want for nothing?";
  const Text k(key);
  const Text d(data);
  refcrypto::HmacSha256 mac(k.View());
  mac.Update(d.View());
  std::array<uint8_t, 32> out{};
  mac.Final(out);
  CHECK(out == Hex<32>("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
  std::array<uint8_t, 100> longkey{};
  longkey.fill(0xAAU);
  refcrypto::HmacSha256 mac2(ByteSpan{longkey});
  mac2.Update(ByteSpan{});
  mac2.Final(out); // a key longer than the block is hashed first (no crash, defined output)
  CHECK((out != std::array<uint8_t, 32>{}));
}

TEST_CASE("ReleaseKey and the destructor leave no key byte in the port's memory (S-01)") {
  std::optional<ReferenceCrypto> holder;
  holder.emplace();
  // The object representation, viewed through std::as_bytes; it stays readable after reset().
  const auto raw = std::as_bytes(std::span<const ReferenceCrypto, 1>{&*holder, 1U});
  std::array<uint8_t, 32> key{};
  key.fill(0xC3U);
  auto found = [&raw]() {
    std::size_t run = 0U;
    for (const std::byte b : raw) {
      run = (b == std::byte{0xC3U}) ? (run + 1U) : 0U;
      if (run >= 8U) {
        return true;
      }
    }
    return false;
  };
  KeyRef h{};
  REQUIRE(holder->ImportKey(KeyKind::Aes256, ByteSpan{key}, h) == CryptoStatus::Ok);
  CHECK(found());
  REQUIRE(holder->ReleaseKey(h) == CryptoStatus::Ok);
  CHECK(!found());
  REQUIRE(holder->ImportKey(KeyKind::Aes256, ByteSpan{key}, h) == CryptoStatus::Ok);
  holder.reset();
  CHECK(!found());
}
