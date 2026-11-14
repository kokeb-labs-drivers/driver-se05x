/**
 * @file se05x_crypto.hpp
 * @brief `ReferenceCrypto`: the crypto port for tests and for bring-up on platforms without a
 * crypto library.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * `ReferenceCrypto` satisfies `CryptoPort`: AES-128,
 * -192 and -256 (FIPS 197), AES-CBC (SP 800-38A), AES-CMAC (SP 800-38B), SHA-1 and SHA-2 (FIPS
 * 180-4), and NIST P-256 key generation, ECDH and ECDSA with RFC 6979 nonces. It holds keys in a
 * fixed table of `kSlots` entries behind `KeyRef` handles; `ReleaseKey` and the destructor wipe
 * them (S-01). The building blocks live in `se05x::refcrypto` so the known-answer tests can reach
 * them.
 *
 * **Bring-up only (S-15).** The table lookups of AES are masked scans and the P-256 ladder has no
 * branch on a secret bit, but nothing here is hardened against power analysis or fault injection,
 * and the key table is ordinary RAM. Do not provision a real key with it: a production port wraps
 * a hardware engine or a vetted library (mbedTLS, PSA) behind the same hooks. `Random()` needs an
 * entropy source given at construction; without one it fails and so does `GenerateP256()`.
 *
 * Owner decision 5 (ship it in the library or keep it test-only) is recorded as an assumption:
 * it ships, behind its own header, and nothing else in the library includes it.
 */
#ifndef SE05X_CRYPTO_HPP
#define SE05X_CRYPTO_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "se05x_ports.hpp"
#include "se05x_secret.hpp"
#include "se05x_types.hpp"

/** @brief The building blocks of `ReferenceCrypto`; not a general crypto library. */
namespace se05x::refcrypto {

/// AES block size in bytes.
inline constexpr std::size_t kAesBlock = 16U;
/// Bytes of an expanded AES-256 key schedule (15 round keys).
inline constexpr std::size_t kAesScheduleBytes = 240U;

/** @brief An expanded AES key (FIPS 197 5.2), wiped when destroyed. */
class AesSchedule {
public:
  /** @brief An empty schedule; `IsValid()` is false. */
  AesSchedule() noexcept = default;
  /** @brief A key schedule has one home. */
  AesSchedule(const AesSchedule&) = delete;
  /** @brief A key schedule has one home. */
  AesSchedule& operator=(const AesSchedule&) = delete;
  /** @brief Wipes the round keys. */
  ~AesSchedule() noexcept;
  /**
   * @brief Expand a key.
   * @param key 16, 24 or 32 bytes.
   * @return false for another length (the schedule is then empty).
   */
  bool Expand(ByteSpan key) noexcept;
  /** @return true after a successful `Expand()`. */
  [[nodiscard]] bool IsValid() const noexcept {
    return rounds_ != 0U;
  }
  /** @brief Encrypt one block in place. @param block The block. */
  void Encrypt(std::span<uint8_t, kAesBlock> block) const noexcept;
  /** @brief Decrypt one block in place. @param block The block. */
  void Decrypt(std::span<uint8_t, kAesBlock> block) const noexcept;

private:
  std::array<uint8_t, kAesScheduleBytes> round_keys_{};
  uint8_t rounds_{0};
};

/**
 * @brief AES-CBC in place.
 * @param schedule The key.
 * @param encrypt Direction.
 * @param iv The IV; replaced by the last ciphertext block.
 * @param data A multiple of 16 bytes.
 * @return false for an empty schedule or a length that is not a multiple of 16.
 */
bool AesCbcCrypt(const AesSchedule& schedule, bool encrypt, std::span<uint8_t, kAesBlock> iv,
                 MutableByteSpan data) noexcept;

/**
 * @brief AES-CMAC (SP 800-38B).
 * @param schedule The key.
 * @param message The message, any length.
 * @param mac The 16-byte tag.
 * @return false for an empty schedule.
 */
bool AesCmacCompute(const AesSchedule& schedule, ByteSpan message,
                    std::span<uint8_t, kAesBlock> mac) noexcept;

/** @brief SHA-256, or SHA-224 (FIPS 180-4 6.2, 6.3); wiped when destroyed. */
class Sha256 {
public:
  /** @brief A fresh hash. @param sha224 true for SHA-224. */
  explicit Sha256(bool sha224 = false) noexcept {
    Reset(sha224);
  }
  /** @brief Hash state has one home. */
  Sha256(const Sha256&) = delete;
  /** @brief Hash state has one home. */
  Sha256& operator=(const Sha256&) = delete;
  /** @brief Wipes the state. */
  ~Sha256() noexcept;
  /** @brief Start again. @param sha224 true for SHA-224. */
  void Reset(bool sha224) noexcept;
  /** @brief Absorb bytes. @param data The bytes. */
  void Update(ByteSpan data) noexcept;
  /**
   * @brief Finish and start again.
   * @param digest At least 32 (28) bytes.
   * @return The digest length, or 0 when `digest` is too small (nothing is finished).
   */
  std::size_t Final(MutableByteSpan digest) noexcept;

private:
  void compress() noexcept;
  std::array<uint32_t, 8> h_{};
  std::array<uint8_t, 64> buffer_{};
  std::size_t used_{0};
  uint64_t total_{0};
  bool is224_{false};
};

/** @brief SHA-512, or SHA-384 (FIPS 180-4 6.4, 6.5); wiped when destroyed. */
class Sha512 {
public:
  /** @brief A fresh hash. @param sha384 true for SHA-384. */
  explicit Sha512(bool sha384 = false) noexcept {
    Reset(sha384);
  }
  /** @brief Hash state has one home. */
  Sha512(const Sha512&) = delete;
  /** @brief Hash state has one home. */
  Sha512& operator=(const Sha512&) = delete;
  /** @brief Wipes the state. */
  ~Sha512() noexcept;
  /** @brief Start again. @param sha384 true for SHA-384. */
  void Reset(bool sha384) noexcept;
  /** @brief Absorb bytes. @param data The bytes. */
  void Update(ByteSpan data) noexcept;
  /**
   * @brief Finish and start again.
   * @param digest At least 64 (48) bytes.
   * @return The digest length, or 0 when `digest` is too small.
   */
  std::size_t Final(MutableByteSpan digest) noexcept;

private:
  void compress() noexcept;
  std::array<uint64_t, 8> h_{};
  std::array<uint8_t, 128> buffer_{};
  std::size_t used_{0};
  uint64_t total_{0};
  bool is384_{false};
};

/** @brief SHA-1 (FIPS 180-4 6.1), for pre-hashing public data only. */
class Sha1 {
public:
  /** @brief A fresh hash. */
  Sha1() noexcept {
    Reset();
  }
  /** @brief Hash state has one home. */
  Sha1(const Sha1&) = delete;
  /** @brief Hash state has one home. */
  Sha1& operator=(const Sha1&) = delete;
  /** @brief Wipes the state. */
  ~Sha1() noexcept;
  /** @brief Start again. */
  void Reset() noexcept;
  /** @brief Absorb bytes. @param data The bytes. */
  void Update(ByteSpan data) noexcept;
  /**
   * @brief Finish and start again.
   * @param digest At least 20 bytes.
   * @return 20, or 0 when `digest` is too small.
   */
  std::size_t Final(MutableByteSpan digest) noexcept;

private:
  void compress() noexcept;
  std::array<uint32_t, 5> h_{};
  std::array<uint8_t, 64> buffer_{};
  std::size_t used_{0};
  uint64_t total_{0};
};

/** @brief HMAC-SHA-256 (FIPS 198-1), single use: construct, `Update`, `Final` once. */
class HmacSha256 {
public:
  /** @brief Key the MAC. @param key The key, any length. */
  explicit HmacSha256(ByteSpan key) noexcept;
  /** @brief MAC state has one home. */
  HmacSha256(const HmacSha256&) = delete;
  /** @brief MAC state has one home. */
  HmacSha256& operator=(const HmacSha256&) = delete;
  /** @brief Wipes the key pad. */
  ~HmacSha256() noexcept;
  /** @brief Absorb bytes. @param data The bytes. */
  void Update(ByteSpan data) noexcept;
  /** @brief Finish. @param mac The 32-byte tag. */
  void Final(std::span<uint8_t, 32> mac) noexcept;

private:
  Sha256 inner_;
  std::array<uint8_t, 64> pad_{};
};

/**
 * @param d A private key, 32 bytes big endian.
 * @return true when 1 <= d < n.
 */
bool P256ValidPrivate(std::span<const uint8_t, 32> d) noexcept;
/**
 * @brief The public point of a private key.
 * @param d The private key.
 * @param pub The uncompressed point 04 || x || y.
 * @return false for an invalid private key.
 */
bool P256PublicKey(std::span<const uint8_t, 32> d, std::span<uint8_t, 65> pub) noexcept;
/**
 * @param pub An uncompressed point.
 * @return true when it starts with 04, both coordinates are below p and it lies on the curve.
 */
bool P256OnCurve(std::span<const uint8_t, 65> pub) noexcept;
/**
 * @brief ECDH: the x coordinate of d * peer.
 * @param d The private key.
 * @param peer The peer's uncompressed point; checked to lie on the curve.
 * @param secret The 32-byte shared secret.
 * @return false for an invalid key or point, or a result at infinity.
 */
bool P256Ecdh(std::span<const uint8_t, 32> d, std::span<const uint8_t, 65> peer,
              std::span<uint8_t, 32> secret) noexcept;
/**
 * @brief ECDSA over a 32-byte digest with the RFC 6979 nonce (HMAC-SHA-256).
 * @param d The private key.
 * @param digest The digest.
 * @param signature r || s, 64 bytes.
 * @return false for an invalid private key.
 */
bool P256Sign(std::span<const uint8_t, 32> d, std::span<const uint8_t, 32> digest,
              std::span<uint8_t, 64> signature) noexcept;
/**
 * @brief ECDSA verification.
 * @param pub The uncompressed public point.
 * @param digest The 32-byte digest.
 * @param signature r || s.
 * @return true when valid.
 */
bool P256Verify(std::span<const uint8_t, 65> pub, std::span<const uint8_t, 32> digest,
                std::span<const uint8_t, 64> signature) noexcept;

} // namespace se05x::refcrypto

namespace se05x {

/**
 * @brief The reference crypto port. Keys live in a fixed table inside the object; `ReleaseKey`
 * wipes the slot. Bring-up and tests only (S-15).
 */
class ReferenceCrypto : public CryptoInterface<ReferenceCrypto> {
public:
  /// An entropy source: fills the span with unpredictable bytes, false when it cannot.
  using EntropySource = bool (*)(MutableByteSpan out) noexcept;
  /// Number of key slots: an applet session inside platform SCP03 holds two static keys and six
  /// session keys, with room for the KDF's short-lived handles and the caller's own keys.
  static constexpr std::size_t kSlots = 16U;

  /** @brief An empty key table without entropy: `Random()` fails. */
  ReferenceCrypto() noexcept = default;
  /** @brief An empty key table. @param entropy The entropy source of `Random()`. */
  explicit ReferenceCrypto(EntropySource entropy) noexcept : entropy_(entropy) {}

  /**
   * @brief Store a key and return its handle.
   * @param kind What the key is; its length must be 16, 24 or 32 bytes (AES) or 32 bytes with
   * 1 <= d < n (P-256).
   * @param key The key bytes; the caller wipes its copy.
   * @param out The handle.
   * @return `Ok`, `InvalidKey` (length, value or kind) or `Failed` (table full).
   */
  CryptoStatus ImportKey(KeyKind kind, ByteSpan key, KeyRef& out) noexcept;
  /**
   * @brief Free a handle and wipe the key.
   * @param key The handle.
   * @return `Ok`, or `InvalidKey` for a handle that is not in use.
   */
  CryptoStatus ReleaseKey(KeyRef key) noexcept;
  /**
   * @brief AES-CMAC (NIST SP 800-38B, RFC 4493) over `message`.
   * @param key An AES key handle.
   * @param message The message.
   * @param mac The 16-byte tag.
   * @return `Ok` or `InvalidKey`.
   */
  CryptoStatus AesCmac(KeyRef key, ByteSpan message, std::span<uint8_t, 16> mac) noexcept;
  /**
   * @brief AES-CBC in place; `data` is a multiple of 16 bytes; `iv` is updated.
   * @param key An AES key handle.
   * @param encrypt Direction.
   * @param iv The 16-byte IV, replaced by the last ciphertext block.
   * @param data The data.
   * @return `Ok`, `InvalidKey`, or `Failed` for a length that is not a multiple of 16.
   */
  CryptoStatus AesCbc(KeyRef key, bool encrypt, std::span<uint8_t, 16> iv,
                      MutableByteSpan data) noexcept;
  /**
   * @brief Generate an ephemeral P-256 key pair.
   * @param priv The handle of the private key.
   * @param pub The uncompressed public point.
   * @return `Ok`, or `Failed` (no entropy, table full).
   */
  CryptoStatus GenerateP256(KeyRef& priv, std::span<uint8_t, 65> pub) noexcept;
  /**
   * @brief ECDH on P-256.
   * @param priv The private key handle.
   * @param peer The peer's uncompressed public point.
   * @param secret The 32-byte shared secret (secret).
   * @return `Ok`, `InvalidKey` (handle or a point not on the curve) or `Failed`.
   */
  CryptoStatus EcdhP256(KeyRef priv, std::span<const uint8_t, 65> peer,
                        std::span<uint8_t, 32> secret) noexcept;
  /**
   * @brief ECDSA P-256 signature over a digest (RFC 6979 nonce).
   * @param priv The private key handle.
   * @param digest The 32-byte digest.
   * @param signature The raw r and s, 64 bytes.
   * @return `Ok` or `InvalidKey`.
   */
  CryptoStatus EcdsaP256Sign(KeyRef priv, std::span<const uint8_t, 32> digest,
                             std::span<uint8_t, 64> signature) noexcept;
  /**
   * @brief ECDSA P-256 verification.
   * @param pub The uncompressed public point.
   * @param digest The 32-byte digest.
   * @param signature The raw r and s.
   * @return `Ok` valid, `Mismatch` invalid, `InvalidKey` for a point not on the curve.
   */
  CryptoStatus EcdsaP256Verify(std::span<const uint8_t, 65> pub,
                               std::span<const uint8_t, 32> digest,
                               std::span<const uint8_t, 64> signature) noexcept;
  /**
   * @brief Hash data.
   * @param alg The algorithm.
   * @param message The data.
   * @param digest The output buffer, at least the digest size; the digest is written to its start.
   * @return `Ok`, or `Failed` for a buffer that is too small or an algorithm that is not an
   * enumerator.
   */
  CryptoStatus Hash(HashAlg alg, ByteSpan message, MutableByteSpan digest) noexcept;
  /**
   * @brief Random bytes from the entropy source.
   * @param out The buffer to fill.
   * @return `Ok`, or `Failed` without a source or when the source fails (the buffer is then
   * wiped).
   */
  CryptoStatus Random(MutableByteSpan out) noexcept;

  /** @return The number of key slots in use. No I/O (tests check that channels release keys). */
  [[nodiscard]] std::size_t KeysInUse() const noexcept;

private:
  struct Slot {
    SecretBuffer<32> key;
    KeyKind kind{KeyKind::Aes128};
    bool used{false};
    uint32_t generation{0};
  };
  Slot* find(KeyRef ref) noexcept;
  Slot* findAes(KeyRef ref) noexcept;
  CryptoStatus store(KeyKind kind, ByteSpan key, KeyRef& out) noexcept;

  std::array<Slot, kSlots> slots_{};
  EntropySource entropy_{nullptr};
};

} // namespace se05x

// codeql::misra_deviation_next_line(MD-CPP-009)
#include "../src/se05x_crypto_aes.ipp" // IWYU pragma: export
// codeql::misra_deviation_next_line(MD-CPP-009)
#include "../src/se05x_crypto_sha.ipp" // IWYU pragma: export
// codeql::misra_deviation_next_line(MD-CPP-009)
#include "../src/se05x_crypto_p256.ipp" // IWYU pragma: export
// codeql::misra_deviation_next_line(MD-CPP-009)
#include "../src/se05x_crypto.ipp" // IWYU pragma: export

namespace se05x {
static_assert(CryptoPort<ReferenceCrypto>);
} // namespace se05x

#endif // SE05X_CRYPTO_HPP
