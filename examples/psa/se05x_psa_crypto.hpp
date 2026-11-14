/**
 * @file se05x_psa_crypto.hpp
 * @brief An optional crypto port over the PSA Crypto API (mbedTLS 3.x, the ESP-IDF mbedtls
 * component, TF-M): the production replacement for `ReferenceCrypto` (S-15).
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Header-only and outside the library: include it only in a build that links a PSA Crypto
 * implementation (the driver never depends on one, and nothing here is vendored). Every key the
 * driver hands over goes into PSA as a volatile key and stays there; the driver holds only the
 * `KeyRef` handle (S-16). A PSA key has one permitted algorithm, so an AES key is imported twice
 * (CMAC, and CBC without padding) and a P-256 private key twice (ECDSA, ECDH); `ReleaseKey`
 * destroys both. A generated P-256 key (the ephemeral key of an ECKey session) can only derive.
 *
 * `psa_crypto_init()` is called on first use; it is idempotent. The port is not thread safe: use
 * one per device, from one task, as the device itself (S-11).
 *
 * Built and run on the host when CMake finds MbedTLS 3 and `SE05X_BUILD_PSA_EXAMPLE` is on
 * (`examples/psa/psa_check.cpp`, CTest `se05x_psa_check`); the ESP-IDF example uses it on target.
 * Without `psa/crypto.h` on the include path the header declares nothing, so a lint of the header
 * alone stays clean.
 */
#ifndef SE05X_EXAMPLES_PSA_CRYPTO_HPP
#define SE05X_EXAMPLES_PSA_CRYPTO_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#if __has_include("psa/crypto.h")
#include "psa/crypto.h"

#include "se05x_ports.hpp"
#include "se05x_types.hpp"

namespace se05x::psa {

/** @brief A `CryptoPort` over PSA Crypto. */
class PsaCrypto : public CryptoInterface<PsaCrypto> {
public:
  /// Key handles the port holds at a time (platform keys, session keys, ECKey keys).
  static constexpr std::size_t kSlots = 16U;

  PsaCrypto() noexcept = default;
  /** @brief Destroys every key still held. */
  ~PsaCrypto() noexcept {
    for (Slot& s : slots_) {
      destroy(s);
    }
  }
  PsaCrypto(const PsaCrypto&) = delete;
  PsaCrypto& operator=(const PsaCrypto&) = delete;

  /**
   * @brief Import a key into PSA.
   * @param kind The kind.
   * @param key The bytes; the caller wipes its copy.
   * @param out The handle.
   * @return `Ok`, `InvalidKey` (length or value) or `Failed` (table full, PSA error).
   */
  CryptoStatus ImportKey(KeyKind kind, ByteSpan key, KeyRef& out) noexcept {
    out = KeyRef{};
    std::size_t bits = key.size() * 8U;
    bool aes = true;
    switch (kind) {
    case KeyKind::Aes128:
      aes = (key.size() == 16U);
      break;
    case KeyKind::Aes192:
      aes = (key.size() == 24U);
      break;
    case KeyKind::Aes256:
      aes = (key.size() == 32U);
      break;
    case KeyKind::P256Private:
      aes = false;
      bits = 256U;
      if (key.size() != 32U) {
        return CryptoStatus::InvalidKey;
      }
      break;
    default:
      return CryptoStatus::InvalidKey;
    }
    if ((kind != KeyKind::P256Private) && !aes) {
      return CryptoStatus::InvalidKey;
    }
    Slot* s = freeSlot();
    if ((s == nullptr) || !ready()) {
      return CryptoStatus::Failed;
    }
    const bool is_aes = (kind != KeyKind::P256Private);
    const psa_key_type_t type =
        is_aes ? PSA_KEY_TYPE_AES : PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
    const psa_algorithm_t first = is_aes ? PSA_ALG_CMAC : PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    const psa_algorithm_t second = is_aes ? PSA_ALG_CBC_NO_PADDING : PSA_ALG_ECDH;
    const psa_key_usage_t first_use = is_aes ? PSA_KEY_USAGE_SIGN_MESSAGE : PSA_KEY_USAGE_SIGN_HASH;
    const psa_key_usage_t second_use =
        is_aes ? (PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT) : PSA_KEY_USAGE_DERIVE;
    if (!import(type, bits, first, first_use, key, s->a) ||
        !import(type, bits, second, second_use, key, s->b)) {
      destroy(*s);
      return is_aes ? CryptoStatus::Failed : CryptoStatus::InvalidKey;
    }
    return take(*s, kind, out);
  }

  /** @brief Destroy a key. @param key The handle. @return `Ok` or `InvalidKey`. */
  CryptoStatus ReleaseKey(KeyRef key) noexcept {
    Slot* s = find(key);
    if (s == nullptr) {
      return CryptoStatus::InvalidKey;
    }
    destroy(*s);
    return CryptoStatus::Ok;
  }

  /**
   * @brief AES-CMAC.
   * @param key An AES handle.
   * @param message The message.
   * @param mac The tag.
   * @return `Ok`, `InvalidKey` or `Failed`.
   */
  CryptoStatus AesCmac(KeyRef key, ByteSpan message, std::span<uint8_t, 16> mac) noexcept {
    const Slot* s = find(key);
    if ((s == nullptr) || (s->kind == KeyKind::P256Private)) {
      return CryptoStatus::InvalidKey;
    }
    std::size_t length = 0U;
    const psa_status_t st = psa_mac_compute(s->a, PSA_ALG_CMAC, message.data(), message.size(),
                                            mac.data(), mac.size(), &length);
    return ((st == PSA_SUCCESS) && (length == mac.size())) ? CryptoStatus::Ok
                                                           : CryptoStatus::Failed;
  }

  /**
   * @brief AES-CBC in place with the given IV; the IV becomes the last ciphertext block.
   * @param key An AES handle.
   * @param encrypt Direction.
   * @param iv The IV.
   * @param data A multiple of 16 bytes.
   * @return `Ok`, `InvalidKey` or `Failed`.
   */
  CryptoStatus AesCbc(KeyRef key, bool encrypt, std::span<uint8_t, 16> iv,
                      MutableByteSpan data) noexcept {
    const Slot* s = find(key);
    if ((s == nullptr) || (s->kind == KeyKind::P256Private)) {
      return CryptoStatus::InvalidKey;
    }
    if ((data.size() % 16U) != 0U) {
      return CryptoStatus::Failed;
    }
    if (data.empty()) {
      return CryptoStatus::Ok;
    }
    std::array<uint8_t, 16> next{};
    const std::size_t last = data.size() - 16U;
    if (!encrypt) {
      for (std::size_t i = 0U; i < 16U; ++i) {
        next[i] = data[last + i];
      }
    }
    psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
    psa_status_t st = encrypt ? psa_cipher_encrypt_setup(&op, s->b, PSA_ALG_CBC_NO_PADDING)
                              : psa_cipher_decrypt_setup(&op, s->b, PSA_ALG_CBC_NO_PADDING);
    std::size_t out = 0U;
    std::size_t tail = 0U;
    if (st == PSA_SUCCESS) {
      st = psa_cipher_set_iv(&op, iv.data(), iv.size());
    }
    // PSA allows the output to alias the input for a block cipher mode.
    if (st == PSA_SUCCESS) {
      st = psa_cipher_update(&op, data.data(), data.size(), data.data(), data.size(), &out);
    }
    if (st == PSA_SUCCESS) {
      st = psa_cipher_finish(&op, data.data() + out, data.size() - out, &tail);
    }
    static_cast<void>(psa_cipher_abort(&op));
    if ((st != PSA_SUCCESS) || ((out + tail) != data.size())) {
      return CryptoStatus::Failed;
    }
    for (std::size_t i = 0U; i < 16U; ++i) {
      iv[i] = encrypt ? data[last + i] : next[i];
    }
    return CryptoStatus::Ok;
  }

  /**
   * @brief Generate an ephemeral P-256 key pair (derive only).
   * @param priv The handle.
   * @param pub The public point.
   * @return `Ok` or `Failed`.
   */
  CryptoStatus GenerateP256(KeyRef& priv, std::span<uint8_t, 65> pub) noexcept {
    priv = KeyRef{};
    Slot* s = freeSlot();
    if ((s == nullptr) || !ready()) {
      return CryptoStatus::Failed;
    }
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256U);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    std::size_t length = 0U;
    const bool ok = (psa_generate_key(&attr, &s->b) == PSA_SUCCESS) &&
                    (psa_export_public_key(s->b, pub.data(), pub.size(), &length) == PSA_SUCCESS) &&
                    (length == pub.size());
    psa_reset_key_attributes(&attr);
    if (!ok) {
      destroy(*s);
      return CryptoStatus::Failed;
    }
    s->derive_only = true;
    return take(*s, KeyKind::P256Private, priv);
  }

  /**
   * @brief ECDH on P-256: the x coordinate.
   * @param priv The handle.
   * @param peer The peer's point.
   * @param secret The secret.
   * @return `Ok`, `InvalidKey` or `Failed`.
   */
  CryptoStatus EcdhP256(KeyRef priv, std::span<const uint8_t, 65> peer,
                        std::span<uint8_t, 32> secret) noexcept {
    const Slot* s = find(priv);
    if ((s == nullptr) || (s->kind != KeyKind::P256Private)) {
      return CryptoStatus::InvalidKey;
    }
    std::size_t length = 0U;
    const psa_status_t st = psa_raw_key_agreement(PSA_ALG_ECDH, s->b, peer.data(), peer.size(),
                                                  secret.data(), secret.size(), &length);
    if (st == PSA_ERROR_INVALID_ARGUMENT) {
      return CryptoStatus::InvalidKey; // a point not on the curve
    }
    return ((st == PSA_SUCCESS) && (length == secret.size())) ? CryptoStatus::Ok
                                                              : CryptoStatus::Failed;
  }

  /**
   * @brief ECDSA P-256 over a digest: raw r and s.
   * @param priv The handle (an imported key).
   * @param digest The digest.
   * @param signature The 64 bytes.
   * @return `Ok`, `InvalidKey` or `Failed`.
   */
  CryptoStatus EcdsaP256Sign(KeyRef priv, std::span<const uint8_t, 32> digest,
                             std::span<uint8_t, 64> signature) noexcept {
    const Slot* s = find(priv);
    if ((s == nullptr) || (s->kind != KeyKind::P256Private) || s->derive_only) {
      return CryptoStatus::InvalidKey;
    }
    std::size_t length = 0U;
    const psa_status_t st =
        psa_sign_hash(s->a, PSA_ALG_ECDSA(PSA_ALG_SHA_256), digest.data(), digest.size(),
                      signature.data(), signature.size(), &length);
    return ((st == PSA_SUCCESS) && (length == signature.size())) ? CryptoStatus::Ok
                                                                 : CryptoStatus::Failed;
  }

  /**
   * @brief ECDSA P-256 verification.
   * @param pub The public point.
   * @param digest The digest.
   * @param signature Raw r and s.
   * @return `Ok`, `Mismatch`, `InvalidKey` or `Failed`.
   */
  CryptoStatus EcdsaP256Verify(std::span<const uint8_t, 65> pub,
                               std::span<const uint8_t, 32> digest,
                               std::span<const uint8_t, 64> signature) noexcept {
    if (!ready()) {
      return CryptoStatus::Failed;
    }
    psa_key_id_t id = PSA_KEY_ID_NULL;
    if (!import(PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1), 256U,
                PSA_ALG_ECDSA(PSA_ALG_SHA_256), PSA_KEY_USAGE_VERIFY_HASH, ByteSpan{pub}, id)) {
      return CryptoStatus::InvalidKey;
    }
    const psa_status_t st = psa_verify_hash(id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), digest.data(),
                                            digest.size(), signature.data(), signature.size());
    static_cast<void>(psa_destroy_key(id));
    if (st == PSA_SUCCESS) {
      return CryptoStatus::Ok;
    }
    return (st == PSA_ERROR_INVALID_SIGNATURE) ? CryptoStatus::Mismatch : CryptoStatus::Failed;
  }

  /**
   * @brief Hash.
   * @param alg The algorithm.
   * @param message The data.
   * @param digest The output, at least the digest size.
   * @return `Ok` or `Failed`.
   */
  CryptoStatus Hash(HashAlg alg, ByteSpan message, MutableByteSpan digest) noexcept {
    psa_algorithm_t a = PSA_ALG_SHA_256;
    switch (alg) {
    case HashAlg::Sha1:
      a = PSA_ALG_SHA_1;
      break;
    case HashAlg::Sha224:
      a = PSA_ALG_SHA_224;
      break;
    case HashAlg::Sha256:
      a = PSA_ALG_SHA_256;
      break;
    case HashAlg::Sha384:
      a = PSA_ALG_SHA_384;
      break;
    case HashAlg::Sha512:
      a = PSA_ALG_SHA_512;
      break;
    default:
      return CryptoStatus::Failed;
    }
    std::size_t length = 0U;
    if (!ready() || (digest.size() < PSA_HASH_LENGTH(a))) {
      return CryptoStatus::Failed;
    }
    return (psa_hash_compute(a, message.data(), message.size(), digest.data(), digest.size(),
                             &length) == PSA_SUCCESS)
               ? CryptoStatus::Ok
               : CryptoStatus::Failed;
  }

  /** @brief Random bytes. @param out The buffer. @return `Ok` or `Failed` (wiped). */
  CryptoStatus Random(MutableByteSpan out) noexcept {
    if (ready() && (psa_generate_random(out.data(), out.size()) == PSA_SUCCESS)) {
      return CryptoStatus::Ok;
    }
    for (uint8_t& b : out) {
      b = 0U;
    }
    return CryptoStatus::Failed;
  }

  /** @return The handles in use (a channel must release what it took). */
  [[nodiscard]] std::size_t KeysInUse() const noexcept {
    std::size_t n = 0U;
    for (const Slot& s : slots_) {
      n += s.used ? 1U : 0U;
    }
    return n;
  }

private:
  struct Slot {
    bool used{false};
    bool derive_only{false};
    KeyKind kind{KeyKind::Aes128};
    uint8_t generation{0};
    psa_key_id_t a{PSA_KEY_ID_NULL}; ///< CMAC or ECDSA.
    psa_key_id_t b{PSA_KEY_ID_NULL}; ///< CBC or ECDH.
  };

  bool ready() noexcept {
    if (!initialised_) {
      initialised_ = (psa_crypto_init() == PSA_SUCCESS);
    }
    return initialised_;
  }
  static bool import(psa_key_type_t type, std::size_t bits, psa_algorithm_t alg,
                     psa_key_usage_t usage, ByteSpan key, psa_key_id_t& id) noexcept {
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, type);
    psa_set_key_bits(&attr, bits);
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_algorithm(&attr, alg);
    const psa_status_t st = psa_import_key(&attr, key.data(), key.size(), &id);
    psa_reset_key_attributes(&attr);
    return st == PSA_SUCCESS;
  }
  Slot* freeSlot() noexcept {
    for (Slot& s : slots_) {
      if (!s.used) {
        return &s;
      }
    }
    return nullptr;
  }
  CryptoStatus take(Slot& s, KeyKind kind, KeyRef& out) noexcept {
    s.used = true;
    s.kind = kind;
    s.generation = static_cast<uint8_t>(s.generation + 1U);
    const auto index = static_cast<uint32_t>(&s - slots_.data());
    out = KeyRef{(static_cast<uint32_t>(s.generation) << 8U) | (index + 1U)};
    return CryptoStatus::Ok;
  }
  Slot* find(KeyRef key) noexcept {
    const uint32_t index = (key.id & 0xFFU);
    if ((index == 0U) || (index > kSlots)) {
      return nullptr;
    }
    Slot& s = slots_[index - 1U];
    return (s.used && ((key.id >> 8U) == s.generation)) ? &s : nullptr;
  }
  static void destroy(Slot& s) noexcept {
    if (s.a != PSA_KEY_ID_NULL) {
      static_cast<void>(psa_destroy_key(s.a));
    }
    if (s.b != PSA_KEY_ID_NULL) {
      static_cast<void>(psa_destroy_key(s.b));
    }
    s.a = PSA_KEY_ID_NULL;
    s.b = PSA_KEY_ID_NULL;
    s.used = false;
    s.derive_only = false;
  }

  std::array<Slot, kSlots> slots_{};
  bool initialised_{false};
};

static_assert(CryptoPort<PsaCrypto>);

} // namespace se05x::psa

#endif // __has_include("psa/crypto.h")

#endif // SE05X_EXAMPLES_PSA_CRYPTO_HPP
