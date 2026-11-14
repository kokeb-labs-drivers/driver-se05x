#!/usr/bin/env python3
"""Build the attestation verification vectors of tests/vectors/attest_vectors.hpp.

Each vector is an attested answer as a chip would send it, signed over the message that AN12413
(format 1: the concatenated values) and AN12543 3.2.7.2 Figure 4 (format 2: the digest of the
command without Le, then the TLVs with three-byte lengths) define. The message is assembled here,
independently of the C++ verifier; openssl signs it with a P-256 key made for this run and then
deleted, and verifies the signature before the header is written. Only the public key, the
message digest and the signature reach the header: no private key is ever written.

    python3 -I tools/oracle/attest_vectors.py OUT_HEADER WORK_DIR
"""

import hashlib
import subprocess
import sys
from pathlib import Path

UID = bytes(range(1, 19))
TIMESTAMP = bytes.fromhex("000000010000000000000009")
NONCE = bytes(range(16))
DATA = bytes.fromhex("cafe")
ATTRIBUTES = bytes.fromhex("a1a2a3")


def tlv3(tag: int, value: bytes) -> bytes:
    """A TLV with the three-byte length form 82 xx xx."""
    return bytes([tag, 0x82, len(value) >> 8, len(value) & 0xFF]) + value


def command(algo: int) -> bytes:
    """ReadObjectAttested of object 0x100 by key 0xF0000012, as the codec encodes it (with Le)."""
    body = (bytes.fromhex("410400000100") + bytes.fromhex("4504f0000012") + bytes([0x46, 0x01, algo])
            + bytes([0x47, 0x10]) + NONCE)
    return bytes.fromhex("80220000") + bytes([0, len(body) >> 8, len(body) & 0xFF]) + body + b"\x00\x00"


def run(*args: str, data: bytes | None = None) -> bytes:
    return subprocess.run(list(args), input=data, check=True, capture_output=True).stdout


def der_to_raw(der: bytes) -> bytes:
    assert der[0] == 0x30 and der[1] == len(der) - 2
    pos, out = 2, b""
    for _ in range(2):
        assert der[pos] == 0x02
        n = der[pos + 1]
        v = der[pos + 2:pos + 2 + n].lstrip(b"\x00")
        out += v.rjust(32, b"\x00")
        pos += 2 + n
    return out


def sign(work: Path, message: bytes, hash_name: str) -> bytes:
    key = work / "key.pem"
    msg = work / "msg.bin"
    sig = work / "sig.der"
    pub = work / "pub.pem"
    msg.write_bytes(message)
    run("openssl", "dgst", f"-{hash_name}", "-sign", str(key), "-out", str(sig), str(msg))
    run("openssl", "ec", "-in", str(key), "-pubout", "-out", str(pub))
    run("openssl", "dgst", f"-{hash_name}", "-verify", str(pub), "-signature", str(sig), str(msg))
    return sig.read_bytes()


def c_array(name: str, data: bytes) -> str:
    rows = [", ".join(f"0x{b:02X}U" for b in data[i:i + 12]) for i in range(0, len(data), 12)]
    body = ",\n    ".join(rows)
    return f"inline constexpr std::array<uint8_t, {len(data)}> {name}{{\n    {body}}};\n"


def main() -> int:
    out, work = Path(sys.argv[1]), Path(sys.argv[2])
    work.mkdir(parents=True, exist_ok=True)
    key = work / "key.pem"
    run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key))
    pub_der = run("openssl", "ec", "-in", str(key), "-pubout", "-outform", "DER")
    public = pub_der[-65:]
    assert public[0] == 0x04

    parts = []
    # Format 2, SHA-256 (AttestationAlgo 0x21).
    cmd = command(0x21)
    msg2 = (hashlib.sha256(cmd[:-2]).digest() + tlv3(0x41, DATA) + tlv3(0x42, UID) + tlv3(0x43, ATTRIBUTES)
            + tlv3(0x44, bytes.fromhex("0020")) + tlv3(0x4F, TIMESTAMP))
    sig2 = sign(work, msg2, "sha256")
    parts += [c_array("kV2Command", cmd), c_array("kV2Signature", sig2),
              c_array("kV2Digest", hashlib.sha256(msg2).digest()), c_array("kV2Raw", der_to_raw(sig2))]
    # Format 2, SHA-256, an answer without attributes: TAG_3 is left out of the message too.
    msg2n = (hashlib.sha256(cmd[:-2]).digest() + tlv3(0x41, DATA) + tlv3(0x42, UID)
             + tlv3(0x44, bytes.fromhex("0020")) + tlv3(0x4F, TIMESTAMP))
    sig2n = sign(work, msg2n, "sha256")
    parts += [c_array("kV2NoAttributesSignature", sig2n),
              c_array("kV2NoAttributesDigest", hashlib.sha256(msg2n).digest()),
              c_array("kV2NoAttributesRaw", der_to_raw(sig2n))]
    # Format 2, SHA-384 (0x22): the digest is truncated to the leftmost 32 bytes for P-256.
    cmd384 = command(0x22)
    msg384 = (hashlib.sha384(cmd384[:-2]).digest() + tlv3(0x41, DATA) + tlv3(0x42, UID)
              + tlv3(0x43, ATTRIBUTES) + tlv3(0x44, bytes.fromhex("0020")) + tlv3(0x4F, TIMESTAMP))
    sig384 = sign(work, msg384, "sha384")
    parts += [c_array("kV2Sha384Command", cmd384), c_array("kV2Sha384Signature", sig384),
              c_array("kV2Sha384Digest", hashlib.sha384(msg384).digest()[:32]),
              c_array("kV2Sha384Raw", der_to_raw(sig384))]
    # Format 1, SHA-256: data, attributes, timestamp, freshness, chip id concatenated.
    msg1 = DATA + ATTRIBUTES + TIMESTAMP + NONCE + UID
    sig1 = sign(work, msg1, "sha256")
    parts += [c_array("kV1Signature", sig1), c_array("kV1Digest", hashlib.sha256(msg1).digest()),
              c_array("kV1Raw", der_to_raw(sig1))]
    key.unlink()

    header = (
        "/**\n * @file attest_vectors.hpp\n"
        " * @brief Attestation verification vectors, generated by tools/oracle/attest_vectors.py.\n"
        " * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT\n *\n"
        " * @details\n"
        " * Signed with a P-256 key made for the run and deleted; only its public key is here. The data,\n"
        " * attributes, chip id (01..12), timestamp and freshness (00..0F) are the ones of the script.\n"
        " */\n#ifndef SE05X_TEST_ATTEST_VECTORS_HPP\n#define SE05X_TEST_ATTEST_VECTORS_HPP\n\n"
        "#include <array>\n#include <cstdint>\n\nnamespace vectors {\n\n"
        + c_array("kAttestationPublicKey", public) + "\n" + "\n".join(parts)
        + "\n} // namespace vectors\n\n#endif // SE05X_TEST_ATTEST_VECTORS_HPP\n")
    out.write_text(header)
    return 0


if __name__ == "__main__":
    sys.exit(main())
