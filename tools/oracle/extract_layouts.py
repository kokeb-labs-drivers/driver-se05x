#!/usr/bin/env python3
"""Static oracle: the command layouts of the vendor middleware, read as text (nothing is compiled
or run). For each command builder named below it records the four header bytes (when they are
constants) and the TLV tags the builder can send, in order, and writes tests/vectors/nxp_layouts.hpp.

    python3 -I tools/oracle/extract_layouts.py <plug-and-trust checkout> <output header>

Only header constants and tag numbers are written: no code, keys or other data of the checkout.
The checkout and its licence are named in tests/vectors/THIRD_PARTY.md.
Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
"""

import re
import sys
from pathlib import Path

# Middleware builder -> the name used in the test. 3.x and 7.x builders that differ only by a
# trailing version argument share a layout; the 7.x one is used where both exist.
BUILDERS = [
    "GetVersion", "ReadState", "GetRandom", "GetFreeMemory", "CreateSession", "CloseSession",
    "VerifySessionUserID", "SetLockState", "DisableObjCreation", "DeleteAll", "WriteECKey_Ver",
    "WriteSymmKey_Ver", "WriteBinary_Ver", "WriteUserID", "CreateCounter", "SetCounterValue",
    "IncCounter", "WritePCR_WithType", "ReadObject", "ReadObject_W_Attst_V2", "ExportObject",
    "ImportObject", "ReadType", "ReadSize", "ReadIDList", "CheckObjectExists", "DeleteSecureObject",
    "CreateECCurve", "GetECCurveId", "ReadECCurveList", "DeleteECCurve", "CreateCryptoObject",
    "ReadCryptoObjectList", "DeleteCryptoObject", "ECDSASign", "ECDSAVerify", "EdDSASign",
    "ECDHGenerateSharedSecret", "RSASign", "RSAEncrypt", "CipherInit", "CipherUpdate", "CipherFinal",
    "CipherOneShot", "MACInit", "MACUpdate", "MACOneShot_G", "HKDF_Extended", "PBKDF2_extended",
    "DigestInit", "DigestUpdate", "DigestOneShot", "TLSGenerateRandom", "TLSPerformPRF",
    "DFDiversifyKey", "DFKillAuthentication", "DFDumpSessionKeys", "AeadOneShot", "TriggerSelfTest",
    "ReadObjectAttributes",
]


def constants(root: Path) -> dict[str, int]:
    """Every `kSE05x_NAME = 0x..` and `#define kSE05x_NAME 0x..` of the enum and constant headers."""
    values: dict[str, int] = {}
    for name in ("se05x_enums.h", "se05x_const.h", "se05x_tlv.h"):
        text = (root / "hostlib/hostLib/inc" / name).read_text(errors="replace")
        for m in re.finditer(r"\b(kSE05x_\w+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)\b", text):
            values.setdefault(m.group(1), int(m.group(2), 0))
        for m in re.finditer(r"^#define\s+(kSE05x_\w+)\s+\(?(0x[0-9A-Fa-f]+|\d+)\)?\s*$", text, re.M):
            values.setdefault(m.group(1), int(m.group(2), 0))
    return values


def body_of(src: str, start: int) -> str:
    i = src.index("{", start)
    depth = 0
    for j in range(i, len(src)):
        depth += {"{": 1, "}": -1}.get(src[j], 0)
        if depth == 0:
            return src[i:j]
    return src[i:]


def main() -> int:
    root, out = Path(sys.argv[1]), Path(sys.argv[2])
    values = constants(root)
    sources = [root / "hostlib/hostLib/se05x_03_xx_xx" / n
               for n in ("se05x_04_xx_APDU_impl.h", "se05x_APDU_impl.h")]
    found: dict[str, tuple[list[int] | None, list[int], bool]] = {}
    for path in sources:
        src = path.read_text(errors="replace")
        for m in re.finditer(r"^smStatus_t Se05x_API_(\w+)\(", src, re.M):
            name = m.group(1)
            if name not in BUILDERS or name in found:
                continue
            body = body_of(src, m.end())
            hdr = re.search(r"hdr\s*=\s*\{\{([^}]*)\}\}", body)
            header = None
            if hdr:
                parts = [p.strip() for p in hdr.group(1).split(",")]
                if all(p in values for p in parts):
                    header = [values[p] for p in parts]
            tags = []
            for t in re.findall(r"TLVSET_\w+\(\s*\"[^\"]*\",\s*&pCmdbuf,\s*&cmdbufLen,\s*(kSE05x_TAG_\w+)",
                                body):
                v = values[t]
                if v not in tags:
                    tags.append(v)
            # A builder that reads a response calls one of the DoAPDUTxRx_* helpers.
            found[name] = (header, tags, "DoAPDUTxRx" in body)
    missing = [b for b in BUILDERS if b not in found]
    if missing:
        print("not found:", ", ".join(missing), file=sys.stderr)
        return 1
    lines = [
        "/**",
        " * @file nxp_layouts.hpp",
        " * @brief Command layouts of the vendor middleware (an oracle, see THIRD_PARTY.md): per builder",
        " * the header bytes when they are constants, the TLV tags it can send, in order, and whether it",
        " * reads response data. Generated",
        " * by tools/oracle/extract_layouts.py from the source text; do not edit.",
        " * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT",
        " */",
        "#ifndef SE05X_TEST_NXP_LAYOUTS_HPP",
        "#define SE05X_TEST_NXP_LAYOUTS_HPP",
        "",
        "#include <array>",
        "#include <cstdint>",
        "",
        "namespace oracle {",
        "",
        "/// One builder: its header (when constant) and its tags in order (at most 8).",
        "struct Layout {",
        "  const char* name;              ///< The middleware builder.",
        "  bool has_header;               ///< Whether all four header bytes are constants.",
        "  std::array<uint8_t, 4> header; ///< CLA INS P1 P2.",
        "  uint8_t tag_count;             ///< Number of tags.",
        "  std::array<uint8_t, 8> tags;   ///< The tags, in the order the builder writes them.",
        "  bool expects_response;         ///< Whether the builder reads response data.",
        "};",
        "",
        f"inline constexpr std::array<Layout, {len(BUILDERS)}> kLayouts{{{{",
    ]
    for name in BUILDERS:
        header, tags, response = found[name]
        h = ", ".join(f"0x{b:02X}U" for b in (header or [0, 0, 0, 0]))
        t = ", ".join(f"0x{b:02X}U" for b in tags)
        lines.append(f'    {{"{name}", {"true" if header else "false"}, {{{h}}}, {len(tags)}U, {{{t}}}, {"true" if response else "false"}}},')
    lines += ["}};", "", "} // namespace oracle", "", "#endif // SE05X_TEST_NXP_LAYOUTS_HPP", ""]
    out.write_text("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
