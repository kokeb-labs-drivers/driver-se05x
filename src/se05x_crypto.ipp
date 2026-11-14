/**
 * @file se05x_crypto.ipp
 * @brief `ReferenceCrypto` hooks, included by `se05x_crypto.hpp`.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * A handle is `generation << 8 | (slot + 1)`: a released handle no longer matches its slot, so a
 * use after `ReleaseKey` fails with `InvalidKey` instead of reaching the next key stored there.
 */
#ifndef SE05X_CRYPTO_IPP
#define SE05X_CRYPTO_IPP

namespace se05x {

namespace refcrypto::port_detail {
/// The key length of an AES kind, 0 for another kind.
constexpr std::size_t AesLength(KeyKind kind) noexcept {
  switch (kind) {
  case KeyKind::Aes128:
    return 16U;
  case KeyKind::Aes192:
    return 24U;
  case KeyKind::Aes256:
    return 32U;
  case KeyKind::P256Private:
    return 0U;
  default:
    break;
  }
  return 0U;
}
} // namespace refcrypto::port_detail

inline ReferenceCrypto::Slot* ReferenceCrypto::find(KeyRef ref) noexcept {
  const uint32_t index = ref.id & 0xFFU;
  if ((index == 0U) || (index > kSlots)) {
    return nullptr;
  }
  Slot& slot = slots_[index - 1U];
  if ((!slot.used) || (slot.generation != (ref.id >> 8U))) {
    return nullptr;
  }
  return &slot;
}

inline ReferenceCrypto::Slot* ReferenceCrypto::findAes(KeyRef ref) noexcept {
  Slot* const slot = find(ref);
  if ((slot == nullptr) || (refcrypto::port_detail::AesLength(slot->kind) == 0U)) {
    return nullptr;
  }
  return slot;
}

inline CryptoStatus ReferenceCrypto::store(KeyKind kind, ByteSpan key, KeyRef& out) noexcept {
  for (std::size_t i = 0U; i < kSlots; ++i) {
    Slot& slot = slots_[i];
    if (!slot.used) {
      const MutableByteSpan dst = slot.key.Reserve(key.size());
      for (std::size_t j = 0U; j < key.size(); ++j) {
        dst[j] = key[j];
      }
      slot.kind = kind;
      slot.used = true;
      out = KeyRef{(slot.generation << 8U) | static_cast<uint32_t>(i + 1U)};
      return CryptoStatus::Ok;
    }
  }
  return CryptoStatus::Failed;
}

inline CryptoStatus ReferenceCrypto::ImportKey(KeyKind kind, ByteSpan key, KeyRef& out) noexcept {
  out = KeyRef{};
  const std::size_t aes = refcrypto::port_detail::AesLength(kind);
  bool valid = false;
  if (kind == KeyKind::P256Private) {
    valid = (key.size() == 32U) &&
            refcrypto::P256ValidPrivate(std::span<const uint8_t, 32>{key.data(), 32U});
  } else {
    valid = (aes != 0U) && (key.size() == aes);
  }
  if (!valid) {
    return CryptoStatus::InvalidKey;
  }
  return store(kind, key, out);
}

inline CryptoStatus ReferenceCrypto::ReleaseKey(KeyRef key) noexcept {
  Slot* const slot = find(key);
  if (slot == nullptr) {
    return CryptoStatus::InvalidKey;
  }
  slot->key.Wipe();
  slot->used = false;
  slot->generation = (slot->generation + 1U) & 0x00FFFFFFU;
  return CryptoStatus::Ok;
}

inline CryptoStatus ReferenceCrypto::AesCmac(KeyRef key, ByteSpan message,
                                             std::span<uint8_t, 16> mac) noexcept {
  const Slot* const slot = findAes(key);
  if (slot == nullptr) {
    return CryptoStatus::InvalidKey;
  }
  refcrypto::AesSchedule schedule;
  if (!schedule.Expand(slot->key.Span())) {
    return CryptoStatus::InvalidKey;
  }
  return refcrypto::AesCmacCompute(schedule, message, mac) ? CryptoStatus::Ok
                                                           : CryptoStatus::Failed;
}

inline CryptoStatus ReferenceCrypto::AesCbc(KeyRef key, bool encrypt, std::span<uint8_t, 16> iv,
                                            MutableByteSpan data) noexcept {
  const Slot* const slot = findAes(key);
  if (slot == nullptr) {
    return CryptoStatus::InvalidKey;
  }
  refcrypto::AesSchedule schedule;
  if (!schedule.Expand(slot->key.Span())) {
    return CryptoStatus::InvalidKey;
  }
  return refcrypto::AesCbcCrypt(schedule, encrypt, iv, data) ? CryptoStatus::Ok
                                                             : CryptoStatus::Failed;
}

inline CryptoStatus ReferenceCrypto::GenerateP256(KeyRef& priv,
                                                  std::span<uint8_t, 65> pub) noexcept {
  priv = KeyRef{};
  SecretBuffer<32> d;
  const MutableByteSpan bytes = d.Reserve(32U);
  bool found = false;
  for (uint32_t attempt = 0U; (attempt < 16U) && (!found); ++attempt) {
    if (Random(bytes) != CryptoStatus::Ok) {
      return CryptoStatus::Failed;
    }
    found = refcrypto::P256ValidPrivate(std::span<const uint8_t, 32>{bytes.data(), 32U});
  }
  if ((!found) ||
      (!refcrypto::P256PublicKey(std::span<const uint8_t, 32>{bytes.data(), 32U}, pub))) {
    return CryptoStatus::Failed;
  }
  return store(KeyKind::P256Private, d.Span(), priv);
}

inline CryptoStatus ReferenceCrypto::EcdhP256(KeyRef priv, std::span<const uint8_t, 65> peer,
                                              std::span<uint8_t, 32> secret) noexcept {
  const Slot* const slot = find(priv);
  if ((slot == nullptr) || (slot->kind != KeyKind::P256Private)) {
    return CryptoStatus::InvalidKey;
  }
  if (!refcrypto::P256Ecdh(std::span<const uint8_t, 32>{slot->key.Span().data(), 32U}, peer,
                           secret)) {
    Zeroize(MutableByteSpan{secret});
    return CryptoStatus::InvalidKey;
  }
  return CryptoStatus::Ok;
}

inline CryptoStatus ReferenceCrypto::EcdsaP256Sign(KeyRef priv, std::span<const uint8_t, 32> digest,
                                                   std::span<uint8_t, 64> signature) noexcept {
  const Slot* const slot = find(priv);
  if ((slot == nullptr) || (slot->kind != KeyKind::P256Private)) {
    return CryptoStatus::InvalidKey;
  }
  return refcrypto::P256Sign(std::span<const uint8_t, 32>{slot->key.Span().data(), 32U}, digest,
                             signature)
             ? CryptoStatus::Ok
             : CryptoStatus::Failed;
}

inline CryptoStatus ReferenceCrypto::EcdsaP256Verify(
    std::span<const uint8_t, 65> pub, std::span<const uint8_t, 32> digest,
    std::span<const uint8_t, 64> signature) noexcept {
  if (!refcrypto::P256OnCurve(pub)) {
    return CryptoStatus::InvalidKey;
  }
  return refcrypto::P256Verify(pub, digest, signature) ? CryptoStatus::Ok : CryptoStatus::Mismatch;
}

inline CryptoStatus ReferenceCrypto::Hash(HashAlg alg, ByteSpan message,
                                          MutableByteSpan digest) noexcept {
  std::size_t written = 0U;
  switch (alg) {
  case HashAlg::Sha1: {
    refcrypto::Sha1 h;
    h.Update(message);
    written = h.Final(digest);
    break;
  }
  case HashAlg::Sha224:
  case HashAlg::Sha256: {
    refcrypto::Sha256 h(alg == HashAlg::Sha224);
    h.Update(message);
    written = h.Final(digest);
    break;
  }
  case HashAlg::Sha384:
  case HashAlg::Sha512: {
    refcrypto::Sha512 h(alg == HashAlg::Sha384);
    h.Update(message);
    written = h.Final(digest);
    break;
  }
  default:
    break;
  }
  return (written != 0U) ? CryptoStatus::Ok : CryptoStatus::Failed;
}

inline CryptoStatus ReferenceCrypto::Random(MutableByteSpan out) noexcept {
  if ((entropy_ == nullptr) || (!entropy_(out))) {
    Zeroize(out);
    return CryptoStatus::Failed;
  }
  return CryptoStatus::Ok;
}

inline std::size_t ReferenceCrypto::KeysInUse() const noexcept {
  return static_cast<std::size_t>(std::count_if(
      slots_.begin(), slots_.end(), [](const Slot& slot) noexcept { return slot.used; }));
}

} // namespace se05x

#endif // SE05X_CRYPTO_IPP
