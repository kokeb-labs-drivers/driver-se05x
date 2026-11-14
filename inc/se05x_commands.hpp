/**
 * @file se05x_commands.hpp
 * @brief The commands of the IoT applet: one enumerator per command, its group, its name and the
 * `CommandSet` bitset.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Frozen contract. The enumerators are contiguous from 0 (`EnumLast<Command>`), so a table indexed
 * by `Command` is checked with `static_assert` against `kCommandCount`. The order is the order of
 * `docs/datasheet.md` (applet specification AN12413 section 4, applet 7.x commands appended to
 * their group). The GlobalPlatform card manager commands are not in this list: they live in `gp::`.
 * PAKE and T4T are held (ambiguity A6): they have no enumerator until their byte layout is sourced.
 *
 * This file was generated once from a table and is maintained by hand
 * afterwards: a new command is a contract amendment (an enumerator, a name, a group, a
 * `CommandTypes` entry in `se05x_device_types.hpp` and a `Codec` specialisation).
 */
#ifndef SE05X_COMMANDS_HPP
#define SE05X_COMMANDS_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "se05x_detail.hpp"

namespace se05x {

/**
 * @defgroup se05x_commands Command set
 * @brief The commands, their groups and the `CommandSet` bitset.
 * @{
 */

/** @brief The command groups of the applet specification. */
enum class Group : uint8_t {
  Identity = 0,
  Session = 1,
  Management = 2,
  ObjectWrite = 3,
  ObjectRead = 4,
  Curve = 5,
  CryptoObject = 6,
  Ec = 7,
  Rsa = 8,
  Cipher = 9,
  Aead = 10,
  Mac = 11,
  Digest = 12,
  Kdf = 13,
  Desfire = 14,
  I2cm = 15,
};

/** @brief One enumerator per applet command; the gate, the codec and the model are keyed by it. */
enum class Command : uint8_t {
  SelectApplet = 0,  ///< Select the IoT applet; returns its version, AppletConfig and SecureBox.
  GetVersion = 1,    ///< Applet version, AppletConfig and SecureBox.
  GetExtVersion = 2, ///< Extended feature bits (applet 7.x).
  GetCardIdentification = 3,    ///< GP GET DATA tag DF28: OEF id and platform build id.
  GetCplc = 4,                  ///< GP GET DATA tag 9F7F: card production life cycle data.
  CreateSession = 5,            ///< Create an applet session bound to an authentication object.
  ExchangeSessionData = 6,      ///< Set the session policy.
  RefreshSession = 7,           ///< Refresh the session policy counters.
  CloseSession = 8,             ///< Close the applet session (never without one: errata APP.2).
  VerifySessionUserId = 9,      ///< Present a UserID secret to the session.
  ScpInitializeUpdate = 10,     ///< AESKey session: INITIALIZE UPDATE.
  ScpExternalAuthenticate = 11, ///< AESKey session: EXTERNAL AUTHENTICATE.
  EcKeySessionInternalAuthenticate = 12, ///< ECKey session: INTERNAL AUTHENTICATE.
  EcKeySessionGetEckaPublicKey =
      13,                     ///< ECKey session: the chip's ephemeral public key (applet 3.x).
  SetLockState = 14,          ///< Transport lock state; irreversible.
  SetPlatformScpRequest = 15, ///< Require platform SCP03; irreversible.
  SetAppletFeatures = 16,     ///< Permanently change the feature set; irreversible.
  DeleteAll = 17,             ///< Delete every user object; irreversible.
  DisableObjCreation = 18,    ///< Stop object creation (applet 7.x); irreversible.
  GetFreeMemory = 19,         ///< Free persistent or transient memory in bytes.
  GetTimestamp = 20,          ///< The chip's monotonic timestamp.
  GetRandom = 21,             ///< Random bytes from the chip DRG.4 generator.
  ReadState = 22,             ///< Applet state; the reply uses a two-byte BER length (applet 7.x).
  CmInvokeGarbageCollection =
      23, ///< Card manager garbage collection; closes the session; wears the memory.
  SendCardManagerCmd = 24, ///< Tunnel a card manager command through the applet.
  TriggerSelfTest = 25,    ///< Run a self test (applet 7.x).
  WriteEcKey = 26,         ///< Import an EC key pair, private or public key.
  GenerateEcKey = 27,      ///< Generate an EC key pair inside the chip.
  WriteRsaKey = 28,        ///< Import an RSA key.
  GenerateRsaKey = 29,     ///< Generate an RSA key pair inside the chip.
  WriteSymmKey = 30,       ///< Import an AES, DES or HMAC key, optionally wrapped by a key object.
  WriteBinary = 31,        ///< Create or write a binary file.
  WriteUserId = 32,        ///< Create a UserID authentication object.
  WriteCounter = 33,       ///< Create a counter or set its value.
  IncrementCounter = 34,   ///< Increment a counter by one.
  WritePcr = 35,           ///< Create a PCR.
  ExtendPcr = 36,          ///< Extend a PCR with data.
  ImportObject = 37,       ///< Import a serialised object.
  ExportObject = 38,       ///< Export a serialised object.
  ImportExternalObject =
      39, ///< Import an object under an ECKey import envelope (SCP id 0xAB, receipt).
  WritePcrWithType = 40,             ///< Create a persistent or transient PCR (applet 7.x).
  ReadObject = 41,                   ///< Read public object data.
  ReadObjectAttested = 42,           ///< Read object data with an attestation signature.
  ReadObjectAttributes = 43,         ///< Class, origin, policy, authentication object.
  ReadObjectAttributesAttested = 44, ///< The attribute block with an attestation signature.
  ReadRsaAttested = 45,              ///< One RSA component with an attestation signature.
  ReadType = 46,                     ///< Object class and lifetime.
  ReadSize = 47,                     ///< Object size in bytes.
  ReadIdList = 48,                   ///< List object ids.
  CheckObjectExists = 49,            ///< Whether an object exists.
  DeleteSecureObject = 50,           ///< Delete an object.
  CreateEcCurve = 51,                ///< Create a curve object.
  SetEcCurveParam = 52,              ///< Set one curve parameter.
  GetEcCurveId = 53,                 ///< The curve of an EC key.
  ReadEcCurveList = 54,              ///< Curves that exist in the chip.
  DeleteEcCurve = 55,                ///< Delete a curve object.
  CreateCryptoObject = 56,           ///< Create a digest, cipher, MAC or AEAD context.
  ReadCryptoObjectList = 57,         ///< List crypto objects.
  DeleteCryptoObject = 58,           ///< Delete a crypto object.
  EcdsaSign = 59,                    ///< ECDSA signature (DER) over a digest or message.
  EcdsaVerify = 60,                  ///< ECDSA verification with a chip key.
  EddsaSign = 61,                    ///< EdDSA signature.
  EddsaVerify = 62,                  ///< EdDSA verification.
  EcdaaSign = 63,                    ///< ECDAA signature (applet 3.x).
  EcdhGenerateSharedSecret = 64,     ///< ECDH shared secret returned to the host.
  EcdhIntoObject = 65,               ///< ECDH shared secret kept in a chip object.
  EcPointMultiply = 66,              ///< EC point multiplication (applet 7.x).
  EcPointMultiplyInputObj =
      67,                 ///< EC point multiplication with the point in an object (applet 7.x).
  RsaSign = 68,           ///< RSA signature.
  RsaVerify = 69,         ///< RSA verification.
  RsaEncrypt = 70,        ///< RSA encryption with a chip key.
  RsaDecrypt = 71,        ///< RSA decryption.
  CipherInit = 72,        ///< Start a streaming cipher.
  CipherUpdate = 73,      ///< Feed a streaming cipher.
  CipherFinal = 74,       ///< Finish a streaming cipher.
  CipherOneShot = 75,     ///< Encrypt or decrypt in one command.
  AeadInit = 76,          ///< Start AES-GCM or AES-CCM (applet 7.x).
  AeadUpdateAad = 77,     ///< Feed associated data.
  AeadUpdate = 78,        ///< Feed AEAD data.
  AeadFinal = 79,         ///< Finish AEAD, produce or check the tag.
  AeadOneShot = 80,       ///< AEAD in one command.
  MacInit = 81,           ///< Start a streaming MAC.
  MacUpdate = 82,         ///< Feed a streaming MAC.
  MacFinal = 83,          ///< Finish a streaming MAC.
  MacOneShot = 84,        ///< MAC in one command.
  DigestInit = 85,        ///< Start a streaming digest.
  DigestUpdate = 86,      ///< Feed a streaming digest.
  DigestFinal = 87,       ///< Finish a streaming digest.
  DigestOneShot = 88,     ///< Digest in one command.
  Hkdf = 89,              ///< HKDF with a chip key.
  Pbkdf2 = 90,            ///< PBKDF2 with a chip key.
  TlsGenerateRandom = 91, ///< TLS random.
  TlsCalculatePreMasterSecret = 92,    ///< TLS premaster secret into a chip object.
  TlsPerformPrf = 93,                  ///< TLS PRF.
  DfDiversifyKey = 94,                 ///< MIFARE DESFire key diversification.
  DfAuthenticateFirstPart1 = 95,       ///< DESFire authenticate first, part 1.
  DfAuthenticateFirstPart2 = 96,       ///< DESFire authenticate first, part 2.
  DfAuthenticateNonFirstPart1 = 97,    ///< DESFire authenticate non-first, part 1.
  DfAuthenticateNonFirstPart2 = 98,    ///< DESFire authenticate non-first, part 2.
  DfDumpSessionKeys = 99,              ///< DESFire dump session keys.
  DfChangeKeyPart1 = 100,              ///< DESFire change key, part 1.
  DfChangeKeyPart2 = 101,              ///< DESFire change key, part 2.
  DfKillAuthentication = 102,          ///< DESFire kill authentication.
  I2cmExecuteCommandSet = 103,         ///< Run an I2C controller command set.
  I2cmExecuteCommandSetAttested = 104, ///< Run an I2C controller command set with attestation.
};

/// Number of commands: the size of every table indexed by `Command`.
inline constexpr std::size_t kCommandCount = 105U;

namespace detail {
/// Last enumerator of `Group`.
template <>
struct EnumLast<Group> {
  static constexpr Group kValue = Group::I2cm; ///< The last enumerator.
};
/// Last enumerator of `Command`.
template <>
struct EnumLast<Command> {
  static constexpr Command kValue =
      Command::I2cmExecuteCommandSetAttested; ///< The last enumerator.
};

/// The names of the commands, in enumerator order.
inline constexpr std::array<const char*, kCommandCount> kCommandNames{
    "SelectApplet",
    "GetVersion",
    "GetExtVersion",
    "GetCardIdentification",
    "GetCplc",
    "CreateSession",
    "ExchangeSessionData",
    "RefreshSession",
    "CloseSession",
    "VerifySessionUserId",
    "ScpInitializeUpdate",
    "ScpExternalAuthenticate",
    "EcKeySessionInternalAuthenticate",
    "EcKeySessionGetEckaPublicKey",
    "SetLockState",
    "SetPlatformScpRequest",
    "SetAppletFeatures",
    "DeleteAll",
    "DisableObjCreation",
    "GetFreeMemory",
    "GetTimestamp",
    "GetRandom",
    "ReadState",
    "CmInvokeGarbageCollection",
    "SendCardManagerCmd",
    "TriggerSelfTest",
    "WriteEcKey",
    "GenerateEcKey",
    "WriteRsaKey",
    "GenerateRsaKey",
    "WriteSymmKey",
    "WriteBinary",
    "WriteUserId",
    "WriteCounter",
    "IncrementCounter",
    "WritePcr",
    "ExtendPcr",
    "ImportObject",
    "ExportObject",
    "ImportExternalObject",
    "WritePcrWithType",
    "ReadObject",
    "ReadObjectAttested",
    "ReadObjectAttributes",
    "ReadObjectAttributesAttested",
    "ReadRsaAttested",
    "ReadType",
    "ReadSize",
    "ReadIdList",
    "CheckObjectExists",
    "DeleteSecureObject",
    "CreateEcCurve",
    "SetEcCurveParam",
    "GetEcCurveId",
    "ReadEcCurveList",
    "DeleteEcCurve",
    "CreateCryptoObject",
    "ReadCryptoObjectList",
    "DeleteCryptoObject",
    "EcdsaSign",
    "EcdsaVerify",
    "EddsaSign",
    "EddsaVerify",
    "EcdaaSign",
    "EcdhGenerateSharedSecret",
    "EcdhIntoObject",
    "EcPointMultiply",
    "EcPointMultiplyInputObj",
    "RsaSign",
    "RsaVerify",
    "RsaEncrypt",
    "RsaDecrypt",
    "CipherInit",
    "CipherUpdate",
    "CipherFinal",
    "CipherOneShot",
    "AeadInit",
    "AeadUpdateAad",
    "AeadUpdate",
    "AeadFinal",
    "AeadOneShot",
    "MacInit",
    "MacUpdate",
    "MacFinal",
    "MacOneShot",
    "DigestInit",
    "DigestUpdate",
    "DigestFinal",
    "DigestOneShot",
    "Hkdf",
    "Pbkdf2",
    "TlsGenerateRandom",
    "TlsCalculatePreMasterSecret",
    "TlsPerformPrf",
    "DfDiversifyKey",
    "DfAuthenticateFirstPart1",
    "DfAuthenticateFirstPart2",
    "DfAuthenticateNonFirstPart1",
    "DfAuthenticateNonFirstPart2",
    "DfDumpSessionKeys",
    "DfChangeKeyPart1",
    "DfChangeKeyPart2",
    "DfKillAuthentication",
    "I2cmExecuteCommandSet",
    "I2cmExecuteCommandSetAttested",
};

/// The group of each command, in enumerator order.
inline constexpr std::array<Group, kCommandCount> kCommandGroups{
    Group::Identity,     Group::Identity,     Group::Identity,     Group::Identity,
    Group::Identity,     Group::Session,      Group::Session,      Group::Session,
    Group::Session,      Group::Session,      Group::Session,      Group::Session,
    Group::Session,      Group::Session,      Group::Management,   Group::Management,
    Group::Management,   Group::Management,   Group::Management,   Group::Management,
    Group::Management,   Group::Management,   Group::Management,   Group::Management,
    Group::Management,   Group::Management,   Group::ObjectWrite,  Group::ObjectWrite,
    Group::ObjectWrite,  Group::ObjectWrite,  Group::ObjectWrite,  Group::ObjectWrite,
    Group::ObjectWrite,  Group::ObjectWrite,  Group::ObjectWrite,  Group::ObjectWrite,
    Group::ObjectWrite,  Group::ObjectWrite,  Group::ObjectWrite,  Group::ObjectWrite,
    Group::ObjectWrite,  Group::ObjectRead,   Group::ObjectRead,   Group::ObjectRead,
    Group::ObjectRead,   Group::ObjectRead,   Group::ObjectRead,   Group::ObjectRead,
    Group::ObjectRead,   Group::ObjectRead,   Group::ObjectRead,   Group::Curve,
    Group::Curve,        Group::Curve,        Group::Curve,        Group::Curve,
    Group::CryptoObject, Group::CryptoObject, Group::CryptoObject, Group::Ec,
    Group::Ec,           Group::Ec,           Group::Ec,           Group::Ec,
    Group::Ec,           Group::Ec,           Group::Ec,           Group::Ec,
    Group::Rsa,          Group::Rsa,          Group::Rsa,          Group::Rsa,
    Group::Cipher,       Group::Cipher,       Group::Cipher,       Group::Cipher,
    Group::Aead,         Group::Aead,         Group::Aead,         Group::Aead,
    Group::Aead,         Group::Mac,          Group::Mac,          Group::Mac,
    Group::Mac,          Group::Digest,       Group::Digest,       Group::Digest,
    Group::Digest,       Group::Kdf,          Group::Kdf,          Group::Kdf,
    Group::Kdf,          Group::Kdf,          Group::Desfire,      Group::Desfire,
    Group::Desfire,      Group::Desfire,      Group::Desfire,      Group::Desfire,
    Group::Desfire,      Group::Desfire,      Group::Desfire,      Group::I2cm,
    Group::I2cm,
};

/// Whether each command is irreversible (S-10), in enumerator order.
inline constexpr std::array<bool, kCommandCount> kCommandIrreversible{
    false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, true,  true,  true,  true,  true,  false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false,
};
} // namespace detail

/**
 * @brief The name of a command, for logs and the redaction table.
 * @param command The command.
 * @return A static string such as `"EcdsaSign"`; `"Unknown"` for a value that is not an enumerator.
 */
constexpr const char* ToString(Command command) noexcept {
  return detail::IsEnumerator(command)
             ? detail::kCommandNames[static_cast<std::size_t>(detail::ToUnderlying(command))]
             : "Unknown";
}

/**
 * @brief The group of a command.
 * @param command The command.
 * @return Its group; `Group::Identity` for a value that is not an enumerator.
 */
constexpr Group GroupOf(Command command) noexcept {
  return detail::IsEnumerator(command)
             ? detail::kCommandGroups[static_cast<std::size_t>(detail::ToUnderlying(command))]
             : Group::Identity;
}

/**
 * @brief Whether a command cannot be undone (S-10): lifecycle locks, feature changes, `DeleteAll`.
 *
 * `Device::Execute<>` refuses these at compile time; they run only through `irreversible::` with a
 * confirmation, and only when the library is built with `SE05X_ENABLE_IRREVERSIBLE`.
 *
 * @param command The command.
 * @return true for an irreversible command; false for anything else, a non-enumerator included.
 */
constexpr bool IsIrreversible(Command command) noexcept {
  return detail::IsEnumerator(command) &&
         detail::kCommandIrreversible[static_cast<std::size_t>(detail::ToUnderlying(command))];
}

/**
 * @brief A set of commands: the held list (`Config::held_commands`), the commands a chip allows.
 *
 * A fixed bitset over `Command`; no heap, `constexpr`.
 */
class CommandSet {
public:
  /** @brief The empty set. */
  constexpr CommandSet() noexcept = default;

  /**
   * @brief Add a command.
   * @param command The command; a non-enumerator is ignored.
   * @return This set.
   */
  constexpr CommandSet& Add(Command command) noexcept {
    if (detail::IsEnumerator(command)) {
      const auto index = static_cast<std::size_t>(detail::ToUnderlying(command));
      words_[index / kWordBits] |= (uint32_t{1} << (index % kWordBits));
    }
    return *this;
  }

  /**
   * @brief Whether a command is in the set.
   * @param command The command.
   * @return true when present; false for a non-enumerator.
   */
  [[nodiscard]] constexpr bool Contains(Command command) const noexcept {
    if (!detail::IsEnumerator(command)) {
      return false;
    }
    const auto index = static_cast<std::size_t>(detail::ToUnderlying(command));
    return ((words_[index / kWordBits] >> (index % kWordBits)) & 1U) != 0U;
  }

private:
  static constexpr std::size_t kWordBits = 32U;
  static constexpr std::size_t kWords = (kCommandCount + kWordBits - 1U) / kWordBits;
  std::array<uint32_t, kWords> words_{};
};

static_assert(detail::kCommandNames.size() == kCommandCount);
static_assert((detail::ToUnderlying(detail::EnumLast<Command>::kValue) + 1U) == kCommandCount);
static_assert(IsIrreversible(Command::DeleteAll) && !IsIrreversible(Command::GetRandom));
static_assert(CommandSet{}.Add(Command::EcdsaSign).Contains(Command::EcdsaSign));

/** @} */

} // namespace se05x

#endif // SE05X_COMMANDS_HPP
