/**
 * @file test_apdu_codec_identity.cpp
 * @brief The codecs of the groups Identity, Session and Management, byte for byte against the
 * tables of AN12543 (section 4.4 to 4.6, 4.20) and AN12413; answers include the published
 * samples AN13904 p. 16 (V9, V10) and AN13030 pp. 227-228, 259, 262.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <array>
#include <cstdint>

#include "test_apdu_util.hpp"

namespace {

using se05x::ByteSpan;
using se05x::Command;
using se05x::Error;
using se05x::MutableByteSpan;

} // namespace

TEST_CASE("SelectApplet and GetVersion: the AID, the 7-byte VersionInfo (V9)") {
  CHECK(tu::EncodesTo<Command::SelectApplet>(
      {}, "00 A4 04 00 10 A0 00 00 03 96 54 53 00 00 00 01 03 00 00 00 00 00"));
  se05x::AppletInfo info{};
  CHECK_EQ(tu::Decode<Command::SelectApplet>({}, "03 01 00 3F FF 01 0B", info), Error::Ok);
  CHECK_EQ(info.version.major, 3U);
  CHECK_EQ(info.version.minor, 1U);
  CHECK_EQ(info.applet_config, 0x3FFFU);
  CHECK_EQ(info.secure_box, 0x010BU);
  CHECK_EQ(tu::Decode<Command::SelectApplet>({}, "03 01 00 3F FF 01", info), Error::FrameError);
  CHECK(tu::EncodesTo<Command::GetVersion>({}, "80 04 00 20 00"));
  CHECK_EQ(tu::Decode<Command::GetVersion>({}, "41 82 00 07 07 02 00 3F FF 01 0B", info),
           Error::Ok);
  CHECK_EQ(info.version.major, 7U);
  CHECK_EQ(info.version.minor, 2U);
  CHECK_EQ(tu::Decode<Command::GetVersion>({}, "41 07 07 02 00 3F FF 01 0B 00", info),
           Error::FrameError);
}

TEST_CASE("GetExtVersion keeps the 30 extended feature bytes") {
  CHECK(tu::EncodesTo<Command::GetExtVersion>({}, "80 04 00 21 00"));
  se05x::ExtFeatures ext{};
  CHECK_EQ(tu::Decode<Command::GetExtVersion>(
               {},
               "41 25 07 02 00 3F FF 01 0B | 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 "
               "12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E",
               ext),
           Error::Ok);
  CHECK_EQ(ext.length, 30U);
  CHECK_EQ(ext.bytes[0], 0x01U);
  CHECK_EQ(ext.bytes[29], 0x1EU);
  CHECK_EQ(tu::Decode<Command::GetExtVersion>({}, "41 07 07 02 00 3F FF 01 0B", ext),
           Error::FrameError);
}

TEST_CASE("GetCardIdentification parses the AN13030 sample and its OEF id") {
  CHECK(tu::EncodesTo<Command::GetCardIdentification>({}, "80 CA 00 FE 02 DF 28 00"));
  se05x::CardId id{};
  const char* sample =
      "FE 45 DF 28 42 | 01 0C 00 01 A8 78 80 10 29 0E F3 33 19 C1 | 02 08 00 00 00 00 00 00 00 00 |"
      " 03 18 4A 33 52 33 35 31 30 32 39 42 34 31 31 31 30 30 30 30 30 30 30 30 30 30 |"
      " 05 01 00 | 07 01 01 | 08 08 52 4F 4D 5F 5F 5F 49 44";
  CHECK_EQ(tu::Decode<Command::GetCardIdentification>({}, sample, id), Error::Ok);
  CHECK_EQ(id.oef_id, 0xA878U);
  CHECK_EQ(id.raw.length, 0x42U);
  CHECK_EQ(id.raw.bytes[0], 0x01U);
  CHECK_EQ(tu::Decode<Command::GetCardIdentification>({}, "FE 05 DF 28 02 01 00", id),
           Error::FrameError); // configuration id of 0 bytes
  CHECK_EQ(tu::Decode<Command::GetCardIdentification>({}, "FE 06 DF 29 03 01 01 00", id),
           Error::FrameError); // wrong inner tag
  CHECK_EQ(tu::Decode<Command::GetCardIdentification>(
               {}, "FE 13 DF 28 10 01 0C 00 01 A8 78 80 10 29 0E F3 33 19 C1 02", id),
           Error::FrameError); // a truncated sub-TLV after the configuration id
}

TEST_CASE("GetCplc wants exactly the 42 bytes of tag 9F7F") {
  CHECK(tu::EncodesTo<Command::GetCplc>({}, "80 CA 9F 7F 00"));
  se05x::Cplc cplc{};
  const char* ok = "9F 7F 2A 47 90 D3 21 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
                   "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 11";
  CHECK_EQ(tu::Decode<Command::GetCplc>({}, ok, cplc), Error::Ok);
  CHECK_EQ(cplc.length, 42U);
  CHECK_EQ(cplc.bytes[41], 0x11U);
  CHECK_EQ(tu::Decode<Command::GetCplc>({}, "9F 7F 01 00", cplc), Error::FrameError);
  CHECK_EQ(tu::Decode<Command::GetCplc>({}, "9F 7E 01 00", cplc), Error::FrameError);
}

TEST_CASE("CreateSession encodes the authentication object and decodes V10's session id") {
  CHECK(tu::EncodesTo<Command::CreateSession>({se05x::ObjectId{0x7FFF0201U}},
                                              "80 04 00 1B 06 41 04 7F FF 02 01 00"));
  CHECK_EQ(tu::EncodeError<Command::CreateSession>({se05x::ObjectId{0U}}), Error::InvalidArgument);
  se05x::SessionId id{};
  CHECK_EQ(tu::Decode<Command::CreateSession>({}, "41 82 00 08 01 68 27 0C A6 5D CF D7", id),
           Error::Ok);
  CHECK(tu::Holds(id, "01 68 27 0C A6 5D CF D7"));
  CHECK_EQ(tu::Decode<Command::CreateSession>({}, "41 07 01 68 27 0C A6 5D CF", id),
           Error::FrameError);
}

TEST_CASE("Session policies: ExchangeSessionData and RefreshSession (AN12543 Table 62)") {
  CHECK(tu::EncodesTo<Command::ExchangeSessionData>({}, "80 04 00 1F 05 41 03 02 00 00 00"));
  se05x::ExchangeSessionDataArgs a{};
  a.policy = se05x::SessionPolicy{0x0010U, 0U, true};
  CHECK(tu::EncodesTo<Command::ExchangeSessionData>(a, "80 04 00 1F 07 41 05 04 A0 00 00 10 00"));
  CHECK(tu::EncodesTo<Command::RefreshSession>({}, "80 04 00 1E"));
  se05x::RefreshSessionArgs r{};
  r.has_policy = true;
  r.policy = se05x::SessionPolicy{0U, 0x003CU, false};
  CHECK(tu::EncodesTo<Command::RefreshSession>(r, "80 04 00 1E 07 11 05 04 40 00 00 3C"));
  se05x::Empty e{};
  CHECK_EQ(tu::Decode<Command::ExchangeSessionData>({}, "", e), Error::Ok);
  CHECK_EQ(tu::Decode<Command::ExchangeSessionData>({}, "00", e), Error::FrameError);
}

TEST_CASE("CloseSession and DeleteAll have no body; DeleteAll sends the Lc 00 of Table 339") {
  CHECK(tu::EncodesTo<Command::CloseSession>({}, "80 04 00 1C"));
  CHECK(tu::EncodesTo<Command::DeleteAll>({}, "80 04 00 2A 00"));
  se05x::Empty e{};
  CHECK_EQ(tu::Decode<Command::CloseSession>({}, "41 00", e), Error::FrameError);
}

TEST_CASE("VerifySessionUserId takes 1 to 16 bytes") {
  const tu::Bytes secret = tu::Hex("01 02 03 04");
  CHECK(tu::EncodesTo<Command::VerifySessionUserId>({secret.View()},
                                                    "80 04 00 2C 06 41 04 01 02 03 04"));
  CHECK_EQ(tu::EncodeError<Command::VerifySessionUserId>({ByteSpan{}}), Error::InvalidArgument);
  const tu::Bytes seventeen = tu::Hex("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10");
  CHECK_EQ(tu::EncodeError<Command::VerifySessionUserId>({seventeen.View()}),
           Error::InvalidArgument);
  CHECK(tu::EncodeError<Command::VerifySessionUserId>({seventeen.View().first(16U)}) == Error::Ok);
}

TEST_CASE("AESKey session: INITIALIZE UPDATE and EXTERNAL AUTHENTICATE (GP SCP03)") {
  const tu::Bytes challenge = tu::Hex("11 22 33 44 55 66 77 88");
  CHECK(tu::EncodesTo<Command::ScpInitializeUpdate>({challenge.View()},
                                                    "80 50 00 00 08 11 22 33 44 55 66 77 88 00"));
  CHECK_EQ(tu::EncodeError<Command::ScpInitializeUpdate>({challenge.View().first(7U)}),
           Error::InvalidArgument);
  se05x::SmallBlob blob{};
  const tu::Bytes s8 = tu::Hex("00 01 02 03 04 05 06 07 08 09 FF 03 00 "
                               "A1 A2 A3 A4 A5 A6 A7 A8 C1 C2 C3 C4 C5 C6 C7 C8");
  CHECK(se05x::Codec<Command::ScpInitializeUpdate>::Decode(s8.View(), blob).ok());
  CHECK_EQ(blob.length, 29U);
  CHECK_EQ(se05x::Codec<Command::ScpInitializeUpdate>::Decode(s8.View().first(28U), blob).error,
           Error::FrameError);
  CHECK(tu::EncodesTo<Command::ScpExternalAuthenticate>({challenge.View()},
                                                        "84 82 33 00 08 11 22 33 44 55 66 77 88"));
  CHECK_EQ(tu::EncodeError<Command::ScpExternalAuthenticate>({ByteSpan{}}), Error::InvalidArgument);
}

TEST_CASE("ECKey session: INTERNAL AUTHENTICATE and the 3.x ECKA public key") {
  const tu::Bytes host = tu::Hex("A6 03 01 02 03");
  CHECK(tu::EncodesTo<Command::EcKeySessionInternalAuthenticate>(
      {host.View()}, "84 88 00 00 05 A6 03 01 02 03 00"));
  const tu::Bytes not_a6 = tu::Hex("7F 49 00");
  CHECK_EQ(tu::EncodeError<Command::EcKeySessionInternalAuthenticate>({not_a6.View()}),
           Error::InvalidArgument);
  se05x::SmallBlob blob{};
  const char* answer = "85 10 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F "
                       "86 10 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F";
  CHECK_EQ(tu::Decode<Command::EcKeySessionInternalAuthenticate>({}, answer, blob), Error::Ok);
  CHECK_EQ(blob.length, 36U);
  CHECK_EQ(tu::Decode<Command::EcKeySessionInternalAuthenticate>({}, "85 10 00", blob),
           Error::FrameError);
  CHECK(tu::EncodesTo<Command::EcKeySessionGetEckaPublicKey>(
      {}, "84 CA BF 21 06 A6 04 83 02 00 00 00"));
  CHECK_EQ(
      tu::Decode<Command::EcKeySessionGetEckaPublicKey>({}, "7F 49 03 B0 01 04 5F 37 01 00", blob),
      Error::Ok);
  CHECK_EQ(tu::Decode<Command::EcKeySessionGetEckaPublicKey>({}, "5F 37 01 00", blob),
           Error::FrameError);
}

TEST_CASE("Lifecycle commands: lock, SCP requirement, features, object creation") {
  CHECK(tu::EncodesTo<Command::SetLockState>({}, "80 04 00 3E 06 41 01 02 42 01 01"));
  CHECK_EQ(tu::EncodeError<Command::SetLockState>({tu::NotAnEnumerator<se05x::LockStateValue>(1U)}),
           Error::InvalidArgument);
  CHECK(tu::EncodesTo<Command::SetPlatformScpRequest>({se05x::ScpRequirement::Required},
                                                      "80 04 00 52 03 41 01 01"));
  CHECK(tu::EncodesTo<Command::SetPlatformScpRequest>({se05x::ScpRequirement::NotRequired},
                                                      "80 04 00 52 03 41 01 02"));
  CHECK(tu::EncodesTo<Command::SetAppletFeatures>({0x3FFFU, {}, false},
                                                  "80 04 00 3F 04 41 02 3F FF"));
  se05x::SetAppletFeaturesArgs f{0x26F2U, {}, true};
  f.ext[0] = 0xAAU;
  f.ext[29] = 0x55U;
  CHECK(tu::EncodesTo<Command::SetAppletFeatures>(
      f, "80 04 00 3F 22 41 20 26 F2 AA 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
         "00 00 00 00 00 00 00 00 00 55"));
  CHECK(tu::EncodesTo<Command::DisableObjCreation>({se05x::RestrictMode::RestrictAll},
                                                   "80 04 00 57 06 41 01 02 42 01 02"));
  CHECK(tu::EncodesTo<Command::DisableObjCreation>({se05x::RestrictMode::RestrictNew},
                                                   "80 04 00 57 06 41 01 02 42 01 01"));
}

TEST_CASE("GetFreeMemory takes 2 or 4 bytes; GetTimestamp 12 bytes") {
  CHECK(tu::EncodesTo<Command::GetFreeMemory>({se05x::MemoryType::Persistent},
                                              "80 04 00 22 03 41 01 01 00"));
  CHECK(tu::EncodesTo<Command::GetFreeMemory>({se05x::MemoryType::TransientDeselect},
                                              "80 04 00 22 03 41 01 03 00"));
  CHECK_EQ(tu::EncodeError<Command::GetFreeMemory>({tu::NotAnEnumerator<se05x::MemoryType>(3U)}),
           Error::InvalidArgument);
  se05x::U32Reply m{};
  CHECK_EQ(tu::Decode<Command::GetFreeMemory>({}, "41 02 7F FF", m), Error::Ok);
  CHECK_EQ(m.value, 0x7FFFU);
  CHECK_EQ(tu::Decode<Command::GetFreeMemory>({}, "41 04 00 01 00 00", m), Error::Ok);
  CHECK_EQ(m.value, 0x10000U);
  CHECK_EQ(tu::Decode<Command::GetFreeMemory>({}, "41 03 00 01 00", m), Error::FrameError);
  CHECK(tu::EncodesTo<Command::GetTimestamp>({}, "80 04 00 3D 00"));
  se05x::Timestamp ts{};
  CHECK_EQ(tu::Decode<Command::GetTimestamp>({}, "41 0C 00 00 00 05 00 00 00 00 00 00 01 02", ts),
           Error::Ok);
  CHECK_EQ(ts[3], 0x05U);
  CHECK_EQ(ts[11], 0x02U);
  CHECK_EQ(tu::Decode<Command::GetTimestamp>({}, "41 0B 00 00 00 05 00 00 00 00 00 00 01", ts),
           Error::FrameError);
}

TEST_CASE("GetRandom asks for out.size() bytes, extended above 252, and wants exactly them") {
  std::array<uint8_t, 16> out{};
  CHECK(tu::EncodesTo<Command::GetRandom>({MutableByteSpan{out}}, "80 04 00 49 04 41 02 00 10 00"));
  std::array<uint8_t, 300> big{};
  CHECK(tu::EncodesTo<Command::GetRandom>({MutableByteSpan{big}},
                                          "80 04 00 49 00 00 04 41 02 01 2C 00 00"));
  CHECK_EQ(tu::EncodeError<Command::GetRandom>({MutableByteSpan{}}), Error::InvalidArgument);
  std::array<uint8_t, 1019> huge{};
  CHECK_EQ(tu::EncodeError<Command::GetRandom>({MutableByteSpan{huge}}), Error::InvalidArgument);
  CHECK(tu::EncodeError<Command::GetRandom>({MutableByteSpan{huge}.first(1018U)}) == Error::Ok);
  se05x::LengthReply n{};
  const se05x::GetRandomArgs args{MutableByteSpan{out}};
  CHECK_EQ(tu::Decode<Command::GetRandom>(
               args, "41 10 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F", n),
           Error::Ok);
  CHECK_EQ(n.length, 16U);
  CHECK_EQ(out[15], 0x0FU);
  CHECK_EQ(
      tu::Decode<Command::GetRandom>(args, "41 0F 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E", n),
      Error::FrameError);
  CHECK_EQ(se05x::Codec<Command::GetRandom>::Decode(tu::Hex("41 01 00").View(), n).error,
           Error::InvalidArgument);
}

TEST_CASE("ReadState, the card manager commands and TriggerSelfTest") {
  CHECK(tu::EncodesTo<Command::ReadState>({}, "80 02 00 5B 00"));
  se05x::SmallBlob state{};
  CHECK_EQ(tu::Decode<Command::ReadState>({}, "41 82 00 03 02 00 02", state), Error::Ok);
  CHECK(tu::Holds(state, "02 00 02"));
  CHECK_EQ(tu::Decode<Command::ReadState>({}, "41 02 02 00", state), Error::FrameError);
  CHECK(tu::EncodesTo<Command::CmInvokeGarbageCollection>({}, "80 CA 00 FE 02 DF 25 00"));
  se05x::Empty e{};
  CHECK_EQ(tu::Decode<Command::CmInvokeGarbageCollection>({}, "FE 03 DF 25 00", e), Error::Ok);
  CHECK_EQ(tu::Decode<Command::CmInvokeGarbageCollection>({}, "FE 03 DF 28 00", e),
           Error::FrameError);
  std::array<uint8_t, 32> cm{};
  const tu::Bytes inner = tu::Hex("80 CA 00 66 00");
  CHECK(tu::EncodesTo<Command::SendCardManagerCmd>({inner.View(), MutableByteSpan{cm}},
                                                   "80 04 00 55 07 41 05 80 CA 00 66 00 00"));
  CHECK_EQ(
      tu::EncodeError<Command::SendCardManagerCmd>({inner.View().first(3U), MutableByteSpan{cm}}),
      Error::InvalidArgument);
  CHECK(tu::EncodesTo<Command::TriggerSelfTest>({0xF906U}, "80 04 00 58 04 41 02 F9 06 00"));
  CHECK_EQ(tu::EncodeError<Command::TriggerSelfTest>({0x1234U}), Error::InvalidArgument);
  se05x::SelfTestReply st{};
  CHECK_EQ(tu::Decode<Command::TriggerSelfTest>({}, "41 01 01", st), Error::Ok);
  CHECK(st.passed);
  CHECK_EQ(tu::Decode<Command::TriggerSelfTest>({}, "41 01 02", st), Error::Ok);
  CHECK(!st.passed);
  CHECK_EQ(tu::Decode<Command::TriggerSelfTest>({}, "41 01 03", st), Error::FrameError);
}
