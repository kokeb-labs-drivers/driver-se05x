/**
 * @file fuzz_pki_x509.cpp
 * @brief Fuzz target of the X.509 parser, the chain walk and the CSR parser of the PKI layer.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * Invariants (abort on violation): a refusal is a `Layer::Pki` failure whose reason is an
 * enumerator; an accepted certificate points only into the input, its TBSCertificate lies inside
 * it, its names pass `CheckName`, its times are valid and ordered, its key has the length of its
 * type, a path length is only on a CA, and parsing it again gives the same views; the chain walk
 * over the input (as a one-certificate chain, with an anchor named by its issuer and a verifier
 * that accepts everything) ends in `Ok` or a reason, never in a crash, and never accepts a
 * certificate the parser refuses; the CSR parser behaves the same way.
 */
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "se05x_crypto.hpp"
#include "se05x_pki_csr.hpp"
#include "se05x_pki_verify.hpp"
#include "se05x_pki_x509.hpp"

namespace {

using namespace se05x;
using namespace se05x::pki;

void Require(bool ok) {
  if (!ok) {
    std::abort();
  }
}

bool Inside(ByteSpan inner, ByteSpan outer) {
  return inner.empty() || ((inner.data() >= outer.data()) &&
                           ((inner.data() + inner.size()) <= (outer.data() + outer.size())));
}

/// A verifier that accepts every signature: the walk's other checks still apply.
struct AcceptAll {
  [[nodiscard]] bool Supports(KeyType type) const noexcept {
    return type != KeyType::Ed25519;
  }
  CryptoStatus VerifySignature(KeyType type, ByteSpan key, ByteSpan digest, ByteSpan raw) noexcept {
    Require((type != KeyType::Ed25519) && (key.size() == PublicKeyLength(type)) &&
            (digest.size() == DigestLength(AlgorithmFor(type))) &&
            (raw.size() == (2U * DigestLength(AlgorithmFor(type)))));
    return CryptoStatus::Ok;
  }
};

bool Entropy(MutableByteSpan out) noexcept {
  for (uint8_t& b : out) {
    b = 0x5AU;
  }
  return true;
}

void CheckRefusal(const Detail& d) {
  Require((d.layer == Layer::Pki) && (ReasonOf(d) != Reason::Ok));
}

void CheckCertificate(ByteSpan input, const Certificate& c) {
  for (const ByteSpan s :
       {c.der, c.tbs, c.serial, c.issuer, c.subject, c.signature, c.public_key.bytes,
        c.subject_alt_names, c.ext_key_usage, c.subject_key_id, c.authority_key_id}) {
    Require(Inside(s, input));
  }
  Require(Inside(c.tbs, c.der) && (c.tbs.size() < c.der.size()));
  bool empty = false;
  Require(CheckName(c.issuer, empty) == Reason::Ok);
  Require(!empty);
  Require(CheckName(c.subject, empty) == Reason::Ok);
  Require(IsValid(c.not_before) && IsValid(c.not_after));
  Require(Compare(c.not_before, c.not_after) <= 0);
  Require(c.public_key.bytes.size() == PublicKeyLength(c.public_key.type));
  Require(c.is_ca || (c.path_length == kNoPathLength));
  Require(c.has_key_usage || (c.key_usage == 0U));
  const Result<Certificate> again = ParseCertificate(input);
  Require(again.ok() && der::SameBytes(again.value.tbs, c.tbs) &&
          der::SameBytes(again.value.subject, c.subject) && (again.value.is_ca == c.is_ca));
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
  const ByteSpan input{data, size};
  const Result<Certificate> parsed = ParseCertificate(input);
  if (parsed.ok()) {
    CheckCertificate(input, parsed.value);
  } else {
    CheckRefusal(parsed.detail);
  }
  ReferenceCrypto crypto{&Entropy};
  AcceptAll verifier{};
  std::array<uint8_t, 65> key{};
  key[0] = 0x04U;
  const TrustAnchor anchor{parsed.ok() ? parsed.value.issuer : ByteSpan{},
                           PublicKey{KeyType::EcP256, ByteSpan{key}}, kNoPathLength};
  const std::array<TrustAnchor, 1> anchors{anchor};
  const std::array<ByteSpan, 1> chain{input};
  const VerifyOptions options{ToUnixSeconds(Time{2030U, 1U, 1U, 0U, 0U, 0U}), 0U, true};
  const Result<VerifiedChain> v =
      VerifyChain(std::span<const ByteSpan>{chain}, std::span<const TrustAnchor>{anchors}, options,
                  verifier, crypto);
  if (v.ok()) {
    Require(parsed.ok() && der::SameBytes(v.value.leaf_key.bytes, parsed.value.public_key.bytes));
  } else {
    CheckRefusal(v.detail);
  }
  const Result<CsrInfo> csr = VerifyCsr(input, verifier, crypto);
  if (csr.ok()) {
    Require(Inside(csr.value.subject, input) && Inside(csr.value.key.bytes, input) &&
            Inside(csr.value.attributes, input));
  } else {
    CheckRefusal(csr.detail);
  }
  return 0;
}
