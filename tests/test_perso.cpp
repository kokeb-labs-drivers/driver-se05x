/**
 * @file test_perso.cpp
 * @brief The PERSO applet (read-only; AN13015 Appendix B) and the card manager GET DATA calls.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 */
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "model/scp_loop.hpp"
#include "model/scp_target.hpp"
#include "se05x_crypto.hpp"
#include "se05x_gp.hpp"
#include "se05x_perso.hpp"
#include "test_harness.hpp"

using namespace se05x;
using testmodel::Loop;
using testmodel::ScpFixture;
using testmodel::ScpPorts;
using testmodel::ScpTarget;

namespace {

/// A transport that answers one fixed response, for malformed answers.
struct Fixed {
  std::array<uint8_t, 300> bytes{};
  std::size_t length{0};
  uint32_t calls{0};
  Result<std::size_t> Transceive(ByteSpan command, MutableByteSpan r) noexcept {
    static_cast<void>(command);
    ++calls;
    static_cast<void>(std::memcpy(r.data(), bytes.data(), length));
    return Result<std::size_t>::Success(length);
  }
};

struct PersoRig {
  ScpFixture f;
  ScpTarget chip;
  Loop loop{chip};
  perso::Perso<ScpPorts, Loop> perso{f.ports, loop};
};

} // namespace

static_assert(perso::IsKnownTag(0x8005U) && perso::IsKnownTag(0x800FU) &&
              perso::IsKnownTag(0x8014U) && perso::IsKnownTag(0x8017U));
static_assert(!perso::IsKnownTag(0x8004U) && !perso::IsKnownTag(0x8007U) &&
              !perso::IsKnownTag(0x8008U) && !perso::IsKnownTag(0x8010U) &&
              !perso::IsKnownTag(0x8013U) && !perso::IsKnownTag(0x8018U));
static_assert(!perso::IsWritable(perso::Tag::FipsModeEnabled) &&
              perso::IsWritable(perso::Tag::I2cSlaveAddress));
static_assert(static_cast<uint8_t>(se05x::detail::EnumLast<perso::Module>::kValue) == 1U,
              "two modules only: iot_base is never offered");

TEST_CASE("PERSO: Select sends the AN13015 Table 7 command and reads the version") {
  PersoRig t;
  const auto v = t.perso.Select();
  REQUIRE(v.ok());
  CHECK((v.value.major == 1U) && (v.value.minor == 4U) && (v.value.config_option == 1U));
  const std::array<uint8_t, 22> want{0x00, 0xA4, 0x04, 0x00, 0x10, 0xA0, 0x00, 0x00,
                                     0x03, 0x96, 0x54, 0x53, 0x00, 0x00, 0x00, 0x01,
                                     0x03, 0x40, 0x00, 0x00, 0x00, 0x00};
  REQUIRE(t.loop.last_cmd_len == want.size());
  CHECK(std::memcmp(t.loop.last_cmd.data(), want.data(), want.size()) == 0);
  CHECK(t.perso.Selected());
}

TEST_CASE("PERSO: Probe is a finding while the applet is there, false once deleted") {
  PersoRig t;
  auto p = t.perso.Probe();
  CHECK(p.ok() && p.value);
  t.chip.knobs.perso_present = false;
  p = t.perso.Probe();
  CHECK(p.ok() && !p.value);
  CHECK(!t.perso.Selected());
  CHECK_EQ(t.perso.Select().error, Error::ObjectNotFound);
}

TEST_CASE("PERSO: the I2C address and parameters are read with Table 10 and 12") {
  PersoRig t;
  t.chip.perso_i2c_params = 0x15U; // stretching, manual protocol, GP flavour
  REQUIRE(t.perso.Select().ok());
  const auto a = t.perso.ReadI2cAddress();
  REQUIRE(a.ok());
  CHECK_EQ(a.value, 0x48U);
  const std::array<uint8_t, 7> want{0x80, 0x02, 0x80, 0x0D, 0x01, 0x01, 0x00};
  CHECK(std::memcmp(t.loop.last_cmd.data(), want.data(), want.size()) == 0);
  const auto p = t.perso.ReadI2cParams();
  REQUIRE(p.ok());
  CHECK(p.value.ClockStretching());
  CHECK(p.value.ManualProtocol());
  CHECK(p.value.GpFlavour());
  CHECK(!p.value.PowerSaving());
}

TEST_CASE("PERSO: reads before Select, of unknown tags or into no buffer send nothing") {
  PersoRig t;
  std::array<uint8_t, 4> out{};
  CHECK_EQ(t.perso.Read(perso::Tag::I2cParams, MutableByteSpan{out}).error, Error::WrongState);
  CHECK_EQ(t.loop.calls, 0U);
  REQUIRE(t.perso.Select().ok());
  const uint32_t calls = t.loop.calls;
  CHECK_EQ(t.perso.Read(std::bit_cast<perso::Tag>(uint16_t{0x8007U}), MutableByteSpan{out}).error,
           Error::InvalidArgument);
  CHECK_EQ(t.perso.Read(perso::Tag::I2cParams, MutableByteSpan{}).error, Error::InvalidArgument);
  CHECK_EQ(t.loop.calls, calls);
}

TEST_CASE("PERSO: SW 6700 is BufferTooSmall, SW 6A81 Unsupported, long values fit or fail") {
  PersoRig t;
  REQUIRE(t.perso.Select().ok());
  std::array<uint8_t, 8> small{};
  CHECK_EQ(t.perso.Read(perso::Tag::AtrCipHistChars, MutableByteSpan{small}).error,
           Error::BufferTooSmall); // 20 bytes, 8 asked: the chip answers 6700
  std::array<uint8_t, 25> big{};
  const auto r = t.perso.Read(perso::Tag::AtrCipHistChars, MutableByteSpan{big});
  REQUIRE(r.ok());
  CHECK_EQ(r.value, 20U);
  CHECK_EQ(t.perso.Read(perso::Tag::AtsHistChars, MutableByteSpan{big}).error, Error::Unsupported);
  std::array<uint8_t, 1> fips{};
  const auto f = t.perso.Read(perso::Tag::FipsModeEnabled, MutableByteSpan{fips});
  CHECK(f.ok() && (fips[0] == 0x00U));
}

TEST_CASE("PERSO: malformed answers are FrameError") {
  ScpFixture f;
  Fixed fixed;
  perso::Perso<ScpPorts, Fixed> p(f.ports, fixed);
  fixed.bytes = {1, 4, 0, 0, 0, 0, 1, 0x90, 0x00};
  fixed.length = 9U;
  REQUIRE(p.Select().ok());
  fixed.bytes = {0x42, 0x01, 0x11, 0x90, 0x00}; // wrong tag
  fixed.length = 5U;
  std::array<uint8_t, 4> out{};
  CHECK_EQ(p.Read(perso::Tag::I2cParams, MutableByteSpan{out}).error, Error::FrameError);
  fixed.bytes = {0x41, 0x02, 0x11, 0x22, 0x90, 0x00}; // two bytes for a one-byte item
  fixed.length = 6U;
  CHECK_EQ(p.ReadI2cParams().error, Error::BufferTooSmall);
  fixed.bytes = {0x41, 0x00, 0x90, 0x00}; // an empty item
  fixed.length = 4U;
  CHECK_EQ(p.ReadI2cParams().error, Error::FrameError);
  fixed.bytes = {0x41, 0x01, 0x90, 0x90, 0x00}; // an address above 0x7F
  fixed.length = 5U;
  CHECK_EQ(p.ReadI2cAddress().error, Error::FrameError);
  fixed.bytes = {0x41, 0x05, 0x11, 0x90, 0x00}; // length beyond the answer
  CHECK_EQ(p.Read(perso::Tag::I2cParams, MutableByteSpan{out}).error, Error::FrameError);
  fixed.bytes = {1, 4, 0x90, 0x00}; // a short version
  fixed.length = 4U;
  CHECK_EQ(p.Select().error, Error::FrameError);
  fixed.bytes = {0x66, 0xA6};
  fixed.length = 2U;
  CHECK_EQ(p.Select().error, Error::ThroughputLimited);
}

#if defined(SE05X_ENABLE_IRREVERSIBLE) && (SE05X_ENABLE_IRREVERSIBLE != 0)
TEST_CASE("PERSO writes and module deletion are never sent, even confirmed") {
  PersoRig t;
  REQUIRE(t.perso.Select().ok());
  const uint32_t calls = t.loop.calls;
  const std::array<uint8_t, 1> addr{0x49U};
  using irreversible::Confirmation;
  using irreversible::DeletePersoModule;
  using irreversible::WritePersoSetting;
  CHECK_EQ(t.perso
               .Write(perso::Tag::I2cSlaveAddress, ByteSpan{addr},
                      Confirmation<WritePersoSetting>{WritePersoSetting::kPhrase})
               .error,
           Error::Unsupported);
  CHECK_EQ(t.perso
               .Write(perso::Tag::FipsModeEnabled, ByteSpan{addr},
                      Confirmation<WritePersoSetting>{WritePersoSetting::kPhrase})
               .error,
           Error::InvalidArgument);
  CHECK_EQ(t.perso
               .Write(perso::Tag::I2cParams, ByteSpan{addr},
                      Confirmation<WritePersoSetting>{DeletePersoModule::kPhrase})
               .error,
           Error::IrreversibleNotConfirmed);
  CHECK_EQ(t.perso
               .DeleteModule(perso::Module::RsaKeyGen,
                             Confirmation<DeletePersoModule>{DeletePersoModule::kPhrase})
               .error,
           Error::Unsupported);
  CHECK_EQ(t.perso
               .DeleteModule(std::bit_cast<perso::Module>(uint8_t{2}),
                             Confirmation<DeletePersoModule>{DeletePersoModule::kPhrase})
               .error,
           Error::InvalidArgument);
  CHECK_EQ(t.loop.calls, calls);
}
#endif

// --- Card manager ---

namespace {
struct CmRig {
  ScpFixture f;
  ScpTarget chip;
  Loop loop{chip};
  gp::CardManager<ScpPorts, Loop> cm{f.ports, loop};
  CmRig() {
    const std::array<uint8_t, 16> k{};
    chip.SetPlatformKeys(k.data(), k.data(), 16U, 0x0BU);
  }
};
} // namespace

TEST_CASE("Card manager: SELECT of the ISD, then CPLC, card identification and key info") {
  CmRig t;
  REQUIRE(t.cm.SelectCardManager().ok());
  const std::array<uint8_t, 14> select{0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00,
                                       0x00, 0x01, 0x51, 0x00, 0x00, 0x00, 0x00};
  CHECK(std::memcmp(t.loop.last_cmd.data(), select.data(), select.size()) == 0);
  const auto cplc = t.cm.GetCplc();
  REQUIRE(cplc.ok());
  CHECK_EQ(cplc.value.length, 42U);
  CHECK((cplc.value.bytes[0] == 0x40U) && (cplc.value.bytes[41] == 0x69U));
  const auto id = t.cm.GetCardIdentification();
  REQUIRE(id.ok());
  CHECK_EQ(id.value.oef_id, 0xA921U);
  CHECK_EQ(id.value.raw.length, 66U);
  const std::array<uint8_t, 8> want{0x80, 0xCA, 0x00, 0xFE, 0x02, 0xDF, 0x28, 0x00};
  CHECK(std::memcmp(t.loop.last_cmd.data(), want.data(), want.size()) == 0);
  const auto keys = t.cm.GetKeyInformation();
  REQUIRE(keys.ok());
  CHECK_EQ(keys.value.count, 3U);
  CHECK((keys.value.entries[0].key_id == 1U) && (keys.value.entries[0].version == 0x0BU) &&
        (keys.value.entries[0].key_type == 0x88U) && (keys.value.entries[0].key_length == 16U));
  CHECK_EQ(keys.value.entries[2].key_id, 3U);
}

TEST_CASE("Card manager: GET DATA needs the selection first; nothing is sent without it") {
  CmRig t;
  CHECK_EQ(t.cm.GetCplc().error, Error::WrongState);
  CHECK_EQ(t.cm.GetCardIdentification().error, Error::WrongState);
  CHECK_EQ(t.cm.GetKeyInformation().error, Error::WrongState);
  CHECK_EQ(t.loop.calls, 0U);
  REQUIRE(t.cm.SelectCardManager().ok());
  CHECK(t.cm.Selected());
  t.cm.Deselect();
  CHECK_EQ(t.cm.GetCplc().error, Error::WrongState);
}

TEST_CASE("Card manager: malformed and refused answers") {
  ScpFixture f;
  Fixed fixed;
  gp::CardManager<ScpPorts, Fixed> cm(f.ports, fixed);
  fixed.bytes = {0x6A, 0x82};
  fixed.length = 2U;
  const auto sel = cm.SelectCardManager();
  CHECK_EQ(sel.error, Error::ChipSwUnknown);
  CHECK_EQ(sel.detail.sw, 0x6A82U);
  fixed.bytes = {0x90, 0x00};
  REQUIRE(cm.SelectCardManager().ok());
  fixed.bytes = {0x9F, 0x7F, 0x29, 0x90, 0x00}; // wrong CPLC length
  fixed.length = 5U;
  CHECK_EQ(cm.GetCplc().error, Error::FrameError);
  fixed.bytes = {0xE0, 0x07, 0xC0, 0x04, 1, 2, 3, 4, 0x90, 0x00}; // template runs past the end
  fixed.length = 10U;
  CHECK_EQ(cm.GetKeyInformation().error, Error::FrameError);
  fixed.bytes = {0xE0, 0x05, 0xC0, 0x03, 1, 2, 3, 0x90, 0x00}; // entry of 3 bytes
  fixed.length = 9U;
  CHECK_EQ(cm.GetKeyInformation().error, Error::FrameError);
  // Nine entries: more than the 8 the type holds.
  std::size_t i = 0U;
  fixed.bytes[i++] = 0xE0U;
  fixed.bytes[i++] = 54U;
  for (uint8_t e = 0U; e < 9U; ++e) {
    fixed.bytes[i++] = 0xC0U;
    fixed.bytes[i++] = 4U;
    fixed.bytes[i++] = e;
    fixed.bytes[i++] = 1U;
    fixed.bytes[i++] = 0x88U;
    fixed.bytes[i++] = 16U;
  }
  fixed.bytes[i++] = 0x90U;
  fixed.bytes[i++] = 0x00U;
  fixed.length = i;
  CHECK_EQ(cm.GetKeyInformation().error, Error::BufferTooSmall);
  fixed.bytes = {0xFE, 0x05, 0xDF, 0x28, 0x02, 0x01, 0x00, 0x90, 0x00}; // config id too short
  fixed.length = 9U;
  CHECK_EQ(cm.GetCardIdentification().error, Error::FrameError);
  fixed.bytes = {0x66, 0xA6};
  fixed.length = 2U;
  CHECK_EQ(cm.GetCplc().error, Error::ThroughputLimited);
}

#if defined(SE05X_ENABLE_IRREVERSIBLE) && (SE05X_ENABLE_IRREVERSIBLE != 0)
TEST_CASE("PUT KEY is never sent: confirmed it is Unsupported, unconfirmed refused") {
  CmRig t;
  using irreversible::Confirmation;
  using irreversible::ReplacePlatformKeys;
  CHECK_EQ(t.cm.PutKeys(scp03::ChannelParams{}, gp::NewKeySet{},
                        Confirmation<ReplacePlatformKeys>{ReplacePlatformKeys::kPhrase})
               .error,
           Error::Unsupported);
  CHECK_EQ(t.cm.PutKeys(scp03::ChannelParams{}, gp::NewKeySet{},
                        Confirmation<ReplacePlatformKeys>{irreversible::DeletePersoModule::kPhrase})
               .error,
           Error::IrreversibleNotConfirmed);
  CHECK_EQ(t.loop.calls, 0U);
}
#endif
