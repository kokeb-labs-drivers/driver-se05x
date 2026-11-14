/**
 * @file test_attest.cpp
 * @brief The attestation verifiers of both formats, from the chip's answer through the codec to
 * the verdict: freshness (S-09), the hashed command of format 2 (AN12543 3.2.7.2), the timestamp
 * order, the DER signature, and every refusal.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <array>
#include <cstdint>

#include "null_ports.hpp"
#include "se05x_attest.hpp"
#include "test_apdu_util.hpp"
#include "test_attest_crypto.hpp"
#include "vectors/attest_vectors.hpp"

namespace {

using attesttest::VectorCrypto;
using se05x::AttestationAlgo;
using se05x::AttestationFormat;
using se05x::AttestedRead;
using se05x::ByteSpan;
using se05x::Command;
using se05x::Error;
using se05x::MutableByteSpan;
using se05x::testports::NullBus;
using se05x::testports::NullClock;

using TestPorts = se05x::Ports<NullBus, NullClock, VectorCrypto>;
using V1 = se05x::attest::Verifier<TestPorts, AttestationFormat::V1>;
using V2 = se05x::attest::Verifier<TestPorts, AttestationFormat::V2>;

constexpr const char* kUid = "01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12";
constexpr const char* kTs = "00 00 00 01 00 00 00 00 00 00 00 09";

/// Append a TLV with the three-byte length form, as the chip answers.
void Put(tu::Bytes& out, uint8_t tag, ByteSpan value) {
  out.b[out.n] = tag;
  out.b[out.n + 1U] = 0x82U;
  out.b[out.n + 2U] = static_cast<uint8_t>(value.size() >> 8U);
  out.b[out.n + 3U] = static_cast<uint8_t>(value.size() & 0xFFU);
  for (std::size_t i = 0U; i < value.size(); ++i) {
    out.b[out.n + 4U + i] = value[i];
  }
  out.n += 4U + value.size();
}

/// A format 2 answer with the data, chip id, attributes (unless left out), size, timestamp and a
/// signature.
tu::Bytes AnswerV2(ByteSpan signature, bool with_attributes = true) {
  tu::Bytes out{};
  Put(out, 0x41U, tu::Hex("CA FE").View());
  Put(out, 0x42U, tu::Hex(kUid).View());
  if (with_attributes) {
    Put(out, 0x43U, tu::Hex("A1 A2 A3").View());
  }
  Put(out, 0x44U, tu::Hex("00 20").View());
  Put(out, 0x4FU, tu::Hex(kTs).View());
  Put(out, 0x52U, signature);
  return out;
}

/// A format 1 answer: data, attributes, timestamp, freshness 00..0F, chip id, signature.
tu::Bytes AnswerV1(ByteSpan signature, uint8_t first_freshness_byte) {
  tu::Bytes fresh = tu::Hex("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F");
  fresh.b[0] = first_freshness_byte;
  tu::Bytes out{};
  Put(out, 0x41U, tu::Hex("CA FE").View());
  Put(out, 0x42U, tu::Hex("A1 A2 A3").View());
  Put(out, 0x43U, tu::Hex(kTs).View());
  Put(out, 0x44U, fresh.View());
  Put(out, 0x45U, tu::Hex(kUid).View());
  Put(out, 0x46U, signature);
  return out;
}

struct Fixture {
  NullBus bus;
  NullClock clock;
  VectorCrypto crypto;
  TestPorts ports{bus, clock, crypto};
  std::array<uint8_t, 64> data{};
  std::array<uint8_t, 80> sig{};
  AttestedRead answer{};
  se05x::attest::Sent sent{};

  Fixture() {
    for (std::size_t i = 0U; i < sent.nonce.size(); ++i) {
      sent.nonce[i] = static_cast<uint8_t>(i);
    }
    crypto.want_key = vectors::kAttestationPublicKey;
  }
  /// Decode an answer through the codec of ReadObjectAttested.
  Error Decode(const tu::Bytes& body) {
    se05x::ReadObjectAttestedArgs a{};
    a.data_out = MutableByteSpan{data};
    a.signature_out = MutableByteSpan{sig};
    return se05x::Codec<Command::ReadObjectAttested>::Decode(a, body.View(), answer).error;
  }
  [[nodiscard]] ByteSpan Data() const {
    return ByteSpan{data}.first(answer.data_length);
  }
  [[nodiscard]] ByteSpan Signature() const {
    return ByteSpan{sig}.first(answer.signature_length);
  }
};

template <typename V>
Error Verify(Fixture& f, const se05x::Timestamp& last = se05x::Timestamp{}) {
  V v(f.ports);
  return v.Verify(f.sent, f.answer, f.Data(), f.Signature(), vectors::kAttestationPublicKey, last)
      .error;
}

void SetUpV2(Fixture& f) {
  f.crypto.want_input = vectors::kV2Digest;
  f.crypto.want_sig = vectors::kV2Raw;
  f.sent.command = ByteSpan{vectors::kV2Command};
  f.sent.algo = AttestationAlgo::EcSha256;
}

} // namespace

TEST_CASE("Format 2: the signature over H(command without Le) and the TLVs verifies") {
  Fixture f;
  SetUpV2(f);
  REQUIRE(f.Decode(AnswerV2(ByteSpan{vectors::kV2Signature})) == Error::Ok);
  V2 v(f.ports);
  const auto r = v.Verify(f.sent, f.answer, f.Data(), f.Signature(), vectors::kAttestationPublicKey,
                          se05x::Timestamp{});
  CHECK_EQ(r.error, Error::Ok);
  CHECK_EQ(r.value.data_length, 2U);
  CHECK_EQ(r.value.object_size, 0x20U);
  CHECK_EQ(r.value.timestamp[11], 0x09U);
  CHECK_EQ(r.value.unique_id[0], 0x01U);
  CHECK_EQ(f.crypto.hashes, 2);
  CHECK(f.crypto.last_hash == se05x::HashAlg::Sha256);
}

TEST_CASE("Format 2 without attributes: TAG_3 is absent from the answer and the signed message") {
  Fixture f;
  SetUpV2(f);
  f.crypto.want_input = vectors::kV2NoAttributesDigest;
  f.crypto.want_sig = vectors::kV2NoAttributesRaw;
  REQUIRE(f.Decode(AnswerV2(ByteSpan{vectors::kV2NoAttributesSignature}, false)) == Error::Ok);
  CHECK_EQ(f.answer.attributes.length, 0U);
  CHECK_EQ(Verify<V2>(f), Error::Ok);
  // The signature over the message with attributes does not verify an answer without them.
  REQUIRE(f.Decode(AnswerV2(ByteSpan{vectors::kV2Signature}, false)) == Error::Ok);
  CHECK_EQ(Verify<V2>(f), Error::AttestationInvalid);
}

TEST_CASE("Format 2 with SHA-384: both hashes are SHA-384, the P-256 input its leftmost 32 bytes") {
  Fixture f;
  f.crypto.want_input = vectors::kV2Sha384Digest;
  f.crypto.want_sig = vectors::kV2Sha384Raw;
  f.sent.command = ByteSpan{vectors::kV2Sha384Command};
  f.sent.algo = AttestationAlgo::EcSha384;
  REQUIRE(f.Decode(AnswerV2(ByteSpan{vectors::kV2Sha384Signature})) == Error::Ok);
  CHECK_EQ(Verify<V2>(f), Error::Ok);
  CHECK(f.crypto.last_hash == se05x::HashAlg::Sha384);
}

TEST_CASE("Format 2 refuses a changed command, data, timestamp order or echoed command") {
  Fixture f;
  SetUpV2(f);
  REQUIRE(f.Decode(AnswerV2(ByteSpan{vectors::kV2Signature})) == Error::Ok);
  std::array<uint8_t, 42> other_nonce = vectors::kV2Command;
  other_nonce[30] ^= 0x01U; // a nonce byte: not the command the chip signed
  f.sent.command = ByteSpan{other_nonce};
  CHECK_EQ(Verify<V2>(f), Error::AttestationInvalid);
  f.sent.command = ByteSpan{vectors::kV2Command};
  f.data[1] ^= 0x01U;
  CHECK_EQ(Verify<V2>(f), Error::AttestationInvalid);
  f.data[1] ^= 0x01U;
  CHECK_EQ(Verify<V2>(f), Error::Ok);
  se05x::Timestamp later{};
  later[3] = 0x02U; // a later boot: the persistent part is the most significant
  CHECK_EQ(Verify<V2>(f, later), Error::AttestationInvalid);
  se05x::Timestamp same{};
  same[3] = 0x01U;
  same[11] = 0x08U;
  CHECK_EQ(Verify<V2>(f, same), Error::Ok);
  same[11] = 0x09U; // the answer's own timestamp: a replay (AN12543 3.9: strongly monotonic)
  CHECK_EQ(Verify<V2>(f, same), Error::AttestationInvalid);
  same[11] = 0x0AU;
  CHECK_EQ(Verify<V2>(f, same), Error::AttestationInvalid);
  f.answer.echoed_command.length = vectors::kV2Command.size();
  for (std::size_t i = 0U; i < vectors::kV2Command.size(); ++i) {
    f.answer.echoed_command.bytes[i] = vectors::kV2Command[i];
  }
  CHECK_EQ(Verify<V2>(f), Error::Ok);
  f.answer.echoed_command.bytes[0] = 0x84U;
  CHECK_EQ(Verify<V2>(f), Error::AttestationInvalid);
}

TEST_CASE("Format 1: the echo must equal the nonce; the signature covers the values") {
  Fixture f;
  f.crypto.want_input = vectors::kV1Digest;
  f.crypto.want_sig = vectors::kV1Raw;
  f.sent.algo = AttestationAlgo::EcSha256;
  REQUIRE(f.Decode(AnswerV1(ByteSpan{vectors::kV1Signature}, 0x00U)) == Error::Ok);
  CHECK(f.answer.format == AttestationFormat::V1);
  CHECK_EQ(Verify<V1>(f), Error::Ok);
  CHECK_EQ(f.crypto.hashes, 1);
  REQUIRE(f.Decode(AnswerV1(ByteSpan{vectors::kV1Signature}, 0x80U)) == Error::Ok);
  CHECK_EQ(Verify<V1>(f), Error::AttestationInvalid); // stale or foreign echo
  REQUIRE(f.Decode(AnswerV1(ByteSpan{vectors::kV1Signature}, 0x00U)) == Error::Ok);
  f.sent.nonce[15] = 0xFFU;
  CHECK_EQ(Verify<V1>(f), Error::AttestationInvalid);
}

TEST_CASE("A verifier refuses the other format, mismatched sizes, a bad key and a bad command") {
  Fixture f;
  SetUpV2(f);
  REQUIRE(f.Decode(AnswerV2(ByteSpan{vectors::kV2Signature})) == Error::Ok);
  CHECK_EQ(Verify<V1>(f), Error::InvalidArgument); // a format 2 answer to a format 1 verifier
  V2 v(f.ports);
  CHECK_EQ(v.Verify(f.sent, f.answer, f.Data().first(1U), f.Signature(),
                    vectors::kAttestationPublicKey, se05x::Timestamp{})
               .error,
           Error::InvalidArgument);
  CHECK_EQ(v.Verify(f.sent, f.answer, f.Data(), f.Signature().first(10U),
                    vectors::kAttestationPublicKey, se05x::Timestamp{})
               .error,
           Error::InvalidArgument);
  std::array<uint8_t, 65> compressed = vectors::kAttestationPublicKey;
  compressed[0] = 0x02U;
  CHECK_EQ(
      v.Verify(f.sent, f.answer, f.Data(), f.Signature(), compressed, se05x::Timestamp{}).error,
      Error::InvalidArgument);
  f.sent.command = ByteSpan{vectors::kV2Command}.first(41U); // half an Le
  CHECK_EQ(Verify<V2>(f), Error::InvalidArgument);
  f.sent.command = ByteSpan{};
  CHECK_EQ(Verify<V2>(f), Error::InvalidArgument);
}

TEST_CASE("Algorithms the port cannot verify, port failures and malformed signatures") {
  Fixture f;
  SetUpV2(f);
  REQUIRE(f.Decode(AnswerV2(ByteSpan{vectors::kV2Signature})) == Error::Ok);
  for (const AttestationAlgo a : {AttestationAlgo::RsaSha256Pss, AttestationAlgo::RsaSha512Pkcs1,
                                  AttestationAlgo::Ed25519, AttestationAlgo::EcPlain}) {
    f.sent.algo = a;
    CHECK_EQ(Verify<V2>(f), Error::Unsupported);
  }
  f.sent.algo = AttestationAlgo::EcSha1;
  CHECK_EQ(Verify<V2>(f), Error::CryptoFailure); // the test port has no SHA-1
  CHECK(f.crypto.last_hash == se05x::HashAlg::Sha1);
  f.sent.algo = AttestationAlgo::EcSha256;
  f.crypto.fail_hash = true;
  CHECK_EQ(Verify<V2>(f), Error::CryptoFailure);
  f.crypto.fail_hash = false;
  f.crypto.verify_status = se05x::CryptoStatus::InvalidKey;
  CHECK_EQ(Verify<V2>(f), Error::CryptoFailure);
  f.crypto.verify_status = se05x::CryptoStatus::Ok;
  f.sig[0] = 0x31U; // not a SEQUENCE
  CHECK_EQ(Verify<V2>(f), Error::AttestationInvalid);
}

TEST_CASE("DER signatures: strict integers of at most 32 significant bytes") {
  using se05x::attest::detail::DerToRaw;
  std::array<uint8_t, 64> raw{};
  struct Case {
    const char* der;
    bool ok;
  };
  const Case cases[] = {
      {"30 06 02 01 01 02 01 02", true},
      {"30 07 02 02 00 80 02 01 02", true},  // a needed sign byte
      {"30 07 02 02 00 01 02 01 02", false}, // a sign byte that is not needed
      {"30 06 02 01 81 02 01 02", false},    // negative
      {"30 07 02 01 01 02 01 02 00", false}, // a trailing byte inside the sequence
      {"30 06 02 01 01 02 01 02 00", false}, // a trailing byte after it
      {"30 05 02 00 02 01 02", false},       // an empty integer
      {"30 06 03 01 01 02 01 02", false},    // not an INTEGER
  };
  for (const Case& c : cases) {
    const tu::Bytes b = tu::Hex(c.der);
    CHECK_EQ(DerToRaw(b.View(), std::span<uint8_t, 64>{raw}), c.ok);
  }
  const tu::Bytes ok = tu::Hex("30 07 02 02 00 80 02 01 02");
  CHECK(DerToRaw(ok.View(), std::span<uint8_t, 64>{raw}));
  CHECK_EQ(raw[31], 0x80U);
  CHECK_EQ(raw[30], 0x00U);
  CHECK_EQ(raw[63], 0x02U);
  std::array<uint8_t, 72> long_r{};
  long_r[0] = 0x30U;
  long_r[1] = 0x26U;
  long_r[2] = 0x02U;
  long_r[3] = 0x21U; // 33 bytes, first not zero
  long_r[4] = 0x01U;
  long_r[37] = 0x02U;
  long_r[38] = 0x01U;
  long_r[39] = 0x01U;
  CHECK(!DerToRaw(ByteSpan{long_r}.first(40U), std::span<uint8_t, 64>{raw}));
}

TEST_CASE("The command without Le: ISO 7816-4 cases 1 to 4, short and extended") {
  using se05x::attest::detail::WithoutLe;
  struct Case {
    const char* apdu;
    int kept; // -1: malformed
  };
  const Case cases[] = {
      {"80 04 00 1C", 4},
      {"80 04 00 20 00", 4},
      {"80 04 00 20 00 00 00", 4},
      {"80 04 00 28 01 AA", 6},
      {"80 04 00 28 01 AA 00", 6},
      {"80 04 00 28 00 00 01 AA", 8},
      {"80 04 00 28 00 00 01 AA 00 00", 8},
      {"80 04 00", -1},
      {"80 04 00 20 00 00", -1},
      {"80 04 00 28 02 AA", -1},
      {"80 04 00 28 01 AA 00 00", -1},
      {"80 04 00 28 00 00 00 AA", -1},
      {"80 04 00 28 00 00 01 AA 00", -1},
  };
  for (const Case& c : cases) {
    const tu::Bytes b = tu::Hex(c.apdu);
    ByteSpan plain{};
    const bool ok = WithoutLe(b.View(), plain);
    CHECK_EQ(ok, c.kept >= 0);
    if (ok) {
      CHECK_EQ(plain.size(), static_cast<std::size_t>(c.kept));
    }
  }
}

TEST_CASE("Timestamps compare most significant byte first and allow equality") {
  using se05x::attest::TimestampNotBefore;
  se05x::Timestamp a{};
  se05x::Timestamp b{};
  CHECK(TimestampNotBefore(a, b));
  a[11] = 1U;
  CHECK(TimestampNotBefore(a, b));
  CHECK(!TimestampNotBefore(b, a));
  b[0] = 1U;
  CHECK(!TimestampNotBefore(a, b));
  CHECK(TimestampNotBefore(b, a));
  CHECK(se05x::attest::FormatOf(se05x::AppletGeneration::V6) == AttestationFormat::V1);
}
