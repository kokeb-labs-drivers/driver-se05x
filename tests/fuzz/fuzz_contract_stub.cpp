/**
 * @file fuzz_contract_stub.cpp
 * @brief Fuzz target of the frozen surface: the byte parsers every layer shares must accept any
 * input without crashing and return an `Error` the enum defines.
 *
 * The package fuzz targets (`fuzz_t1_frame`, `fuzz_atr_cip`, `fuzz_apdu_response`,
 * `fuzz_policy_parse`, `fuzz_scp03_unwrap`, `fuzz_sequence`) are added by their owners
 * (design/se05x-builders.md); this one keeps the build wiring honest until then. Built two ways
 * (tests/fuzz/CMakeLists.txt): libFuzzer on Clang, and a corpus replay as a CTest on any compiler.
 */
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "se05x.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
  const se05x::ByteSpan input{data, size};
  const auto atr = se05x::t1::ParseAtr(input);
  const auto cip = se05x::t1::ParseCip(input);
  const auto response = se05x::apdu::SplitResponse(input);
  const auto crc = se05x::t1::Crc16(input);
  se05x::apdu::TlvReader reader(input);
  const auto tlv = reader.Next();
  // Every result is either a success or a defined error; a stub says NotImplemented.
  const se05x::Error errors[] = {atr.error, cip.error, response.error, crc.error, tlv.error};
  for (const se05x::Error e : errors) {
    if (std::strcmp(se05x::ToString(e), "Unknown") == 0) { // a value outside the enum
      std::abort();
    }
  }
  return 0;
}
