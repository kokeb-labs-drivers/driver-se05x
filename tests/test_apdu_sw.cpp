/**
 * @file test_apdu_sw.cpp
 * @brief The status word map in the context of a command (AN12543 Table 21 and the per-command
 * SW lists; design section 9).
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <cstdint>

#include "se05x_apdu.hpp"
#include "test_harness.hpp"

namespace {

using se05x::Command;
using se05x::Error;
using se05x::apdu::StatusToError;

struct Row {
  uint16_t sw;
  Error error;
};

// Written from AN12543 Table 21 and the ISO 7816-4 meanings, independently of the library table.
constexpr Row kGeneric[] = {
    {0x9000U, Error::Ok},
    {0x66A6U, Error::ThroughputLimited},
    {0x6700U, Error::BufferTooSmall},
    {0x6982U, Error::PolicyDenied},
    {0x6983U, Error::AuthLocked},
    {0x6984U, Error::PolicyInvalid},
    {0x6985U, Error::ConditionsNotSatisfied},
    {0x6986U, Error::PolicyDenied},
    {0x6987U, Error::SecureChannelError},
    {0x6988U, Error::SecureChannelError},
    {0x6A80U, Error::ConditionsNotSatisfied},
    {0x6A81U, Error::Unsupported},
    {0x6A82U, Error::ObjectNotFound},
    {0x6A84U, Error::MemoryFull},
    {0x6A86U, Error::Unsupported},
    {0x6A89U, Error::ObjectExists},
    {0x6B00U, Error::Unsupported},
    {0x6D00U, Error::NeedsReselect},
    {0x6E00U, Error::NeedsReselect},
    {0x6F00U, Error::DeviceFault},
    {0x6A83U, Error::ChipSwUnknown},
    {0x6F01U, Error::ChipSwUnknown},
    {0x9001U, Error::ChipSwUnknown},
    {0x0000U, Error::ChipSwUnknown},
    {0xFFFFU, Error::ChipSwUnknown},
};

} // namespace

TEST_CASE("Generic status words map to their errors for a command without special cases") {
  for (const Row& row : kGeneric) {
    CHECK_EQ(StatusToError(Command::ReadType, row.sw), row.error);
    CHECK_EQ(StatusToError(Command::EcdsaSign, row.sw), row.error);
  }
}

TEST_CASE("Any status word but 9000 after CloseSession is NeedsReselect (AN12543 4.5.1.5)") {
  CHECK_EQ(StatusToError(Command::CloseSession, 0x9000U), Error::Ok);
  for (const uint16_t sw : {uint16_t{0x6985U}, uint16_t{0x6A80U}, uint16_t{0x66A6U},
                            uint16_t{0x6F00U}, uint16_t{0x1234U}}) {
    CHECK_EQ(StatusToError(Command::CloseSession, sw), Error::NeedsReselect);
  }
}

TEST_CASE("SW 6985 is AuthFailed after VerifySessionUserId and PolicyInvalid on a session policy") {
  CHECK_EQ(StatusToError(Command::VerifySessionUserId, 0x6985U), Error::AuthFailed);
  CHECK_EQ(StatusToError(Command::ExchangeSessionData, 0x6985U), Error::PolicyInvalid);
  CHECK_EQ(StatusToError(Command::RefreshSession, 0x6985U), Error::PolicyInvalid);
  CHECK_EQ(StatusToError(Command::CreateSession, 0x6985U), Error::ConditionsNotSatisfied);
  CHECK_EQ(StatusToError(Command::WriteEcKey, 0x6985U), Error::ConditionsNotSatisfied);
}

TEST_CASE("SW 6A80 is PolicyInvalid on every object write and AuthFailed on DESFire part 2") {
  for (uint32_t c = 0U; c < se05x::kCommandCount; ++c) {
    const auto command = static_cast<Command>(static_cast<uint8_t>(c));
    const bool write = se05x::GroupOf(command) == se05x::Group::ObjectWrite;
    Error want = Error::ConditionsNotSatisfied;
    if (write) {
      want = Error::PolicyInvalid;
    } else if (command == Command::DfAuthenticateNonFirstPart2) {
      want = Error::AuthFailed;
    } else if (command == Command::CloseSession) {
      want = Error::NeedsReselect;
    } else {
      want = Error::ConditionsNotSatisfied;
    }
    CHECK_EQ(StatusToError(command, 0x6A80U), want);
  }
}

TEST_CASE("SW 6982 and 63Cx are AuthFailed on an authentication step") {
  for (const Command c :
       {Command::ScpExternalAuthenticate, Command::EcKeySessionInternalAuthenticate,
        Command::VerifySessionUserId, Command::DfAuthenticateFirstPart2,
        Command::DfAuthenticateNonFirstPart2}) {
    CHECK_EQ(StatusToError(c, 0x6982U), Error::AuthFailed);
  }
  CHECK_EQ(StatusToError(Command::DfAuthenticateFirstPart1, 0x6982U), Error::PolicyDenied);
  CHECK_EQ(StatusToError(Command::ReadObject, 0x6982U), Error::PolicyDenied);
  for (const uint16_t sw : {uint16_t{0x63C0U}, uint16_t{0x63C3U}, uint16_t{0x63CFU}}) {
    CHECK_EQ(StatusToError(Command::ReadObject, sw), Error::AuthFailed);
  }
  CHECK_EQ(StatusToError(Command::ReadObject, 0x63B0U), Error::ChipSwUnknown);
  CHECK_EQ(StatusToError(Command::ReadObject, 0x6BC0U), Error::ChipSwUnknown);
}

TEST_CASE("The throughput limit 66A6 maps the same on every command but CloseSession") {
  for (uint32_t c = 0U; c < se05x::kCommandCount; ++c) {
    const auto command = static_cast<Command>(static_cast<uint8_t>(c));
    const Error want =
        (command == Command::CloseSession) ? Error::NeedsReselect : Error::ThroughputLimited;
    CHECK_EQ(StatusToError(command, 0x66A6U), want);
  }
}
