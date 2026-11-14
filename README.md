# SE05X Driver

<!-- generated: chip-summary -->
The **SE05x** is a family of secure elements (SE050, SE051, SE052) that hold keys and credentials isolated from the
host, sign, agree keys and attest with them inside the chip, and talk to the host over I2C with T=1 framing and an
encrypted SCP03 channel (SE050 1 Introduction, p. 1).
<!-- /generated -->

C++20 driver and hardware root-of-trust facade for the NXP EdgeLock SE050, SE051 and SE052 secure elements over I2C
(T=1, GlobalPlatform SCP03, IoT applet), with the transport, crypto and timing behind ports.

[![CI](https://github.com/kokeb-labs-drivers/driver-se05x/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/kokeb-labs-drivers/driver-se05x/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-informational)](docs/installation.md#requirements)

**Documentation: [`docs/`](docs/index.md)**, with the API reference built by Doxygen ([how](docs/api-reference.md)).
The site at <https://kokeb-labs-drivers.github.io/driver-se05x/> opens when the repository is public.

The three chips differ in package, applet, memory and certification: [Where to use it](docs/variants.md) helps you
choose and draws the SE052's HVQFN20 package; the figures below show the HX2QFN20 of the SE050 and SE051.

<!-- figure: chip-hero -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/chip-hero.dark.svg">
  <img src="docs/diagrams/chip-hero.svg"
    alt="Overview of the SE05x, a family of secure elements (SE050, SE051, SE052) that hold keys and
    credentials isolated from the host, sign, agree keys and attest with them inside the chip, and talk
    to the host over I2C with T=1 framing and an encrypted SCP03 channel. A MCU talks to it over I2C,
    T=1; it drives Sensor or actuator. Headline figures: EAL 6+ Common Criteria, hardware and OS (SE051
    2.2, p. 3; SE052 3.1, p. 3); 0x48 I2C target address, T=1 framing (SE052: Table 12, p. 18); 1.62 to
    3.6 V VIN and VCC, SE050 and SE051; 3 x 3 mm HX2QFN20, SE050 and SE051; 4 x 4 mm HVQFN20, SE052.">
</picture>
<!-- /figure -->

## What it does

<!-- figure: chip-capabilities -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/chip-capabilities.dark.svg">
  <img src="docs/diagrams/chip-capabilities.svg"
    alt="Capability map of the SE05x: Key generation (supported): Generates EC key pairs inside the chip
    under a policy; the private key never leaves it; Signatures and key agreement (supported): ECDSA
    signatures and verification and ECDH shared secrets with keys held in the chip; Attestation
    (supported): Proves a key or a value comes from this chip: a signed, fresh read with the chip's
    unique ID; Secure storage (supported): Binary objects for secrets such as a Wi-Fi passphrase or a
    token, read only as their policy allows; Certificates and CSR (supported): Stores and reads
    certificates, builds a certificate request for a chip key and checks a chain; Monotonic counters
    (supported): Counters that only count up, for an anti-rollback floor on the firmware version; Secure
    channels (supported): Platform SCP03 encrypts the bus; AESKey, ECKey and UserID sessions
    authenticate the caller; Lifecycle and locks (guarded): Transport lock, a platform SCP03 requirement
    and factory reset: one-way changes to the chip; Contactless and ISO 7816 (not covered): The ISO
    14443 antenna and ISO 7816 interfaces; the host cannot reach them over I2C.">
</picture>
<!-- /figure -->

## Where it is used

<!-- generated: chip-uses -->
- Secure connection to public and private clouds and edge platforms
- Device-to-device authentication
- Protection of data such as sensor data (SE050 1 Introduction, p. 1)
- Wi-Fi credential protection: a device key for WPA-EAP-TLS (AN12661 2 Wi-Fi credential protection, p. 4)
- Secure commissioning, key storage and credential provisioning
- Ecosystem protection
- Smart industry, smart home, smart cities and smart supply chains (SE050 1.2 SE050 target applications, p. 2)
- Healthcare (SE052) (SE052 1.2 Applications, p. 1)

Uses named by the datasheet (SE050 1.1 SE050 use cases, p. 1).
<!-- /generated -->

## Inside the chip

<!-- figure: chip-blocks -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/chip-blocks.dark.svg">
  <img src="docs/diagrams/chip-blocks.svg"
    alt="Block diagram of the SE05x: its function blocks, how they connect and which package pins reach each
    block.">
</picture>
<!-- /figure -->

The block diagram is drawn from the functional description of the SE050 data sheet (sections 3 to 5), which has no
block diagram of its own. It and the pinout and wiring figures below show the SE050 and SE051 in HX2QFN20, though
their titles name the family. The SE052 has no ENA pin (SE052 Table 2, p. 4), so the power-switch block does not
apply to it; [SE052](docs/se052.md) draws its own pins and wiring.

## Pins and wiring

<!-- figure: chip-pinout -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/chip-pinout.dark.svg">
  <img src="docs/diagrams/chip-pinout.svg"
    alt="Pinout of the SE05x in HX2QFN20, top view: 20 pins and an exposed pad, each with its name, its
    electrical type as a colour and the driver hook that uses it.">
</picture>
<!-- /figure -->

<!-- figure: chip-wiring-typical -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/chip-wiring-typical.dark.svg">
  <img src="docs/diagrams/chip-wiring-typical.svg"
    alt="Wiring of the SE05x for the Recommended application (SE050, SE051): MCU I2C SDA to SDA (Write() /
    Read()); MCU I2C SCL to SCL (Write() / Read()); MCU GPIO to ENA (SetEnable() / PowerCycle()).
    Supplies, grounds and the support parts are listed under the drawing.">
</picture>
<!-- /figure -->

| MCU | SE050, SE051 | SE052 | Notes |
| --- | --- | --- | --- |
| I2C SDA | SDA, pin 9 | SDA, pin 11 | Pull-up to the bus supply; the vendor kit fits 3.3 kΩ |
| I2C SCL | SCL, pin 10 | SCL, pin 10 | Pull-up to the bus supply |
| GPIO | ENA, pin 11 | RST_N, pin 14 | The reset port: ENA power cycle, or SE052 reset |
| 3.3 V | VIN | VIN | 1.62 V to 3.6 V (SE052 VIN: 1.65 V) |
| | VOUT to VCC | VOUT to VDD | Lets deep power-down switch the core off |
| | RST_N to VSS | | ISO 7816 reset: no effect with I2C alone |
| GND | VSS | VSS | |

Both I2C lines must be high when the chip powers up. Per-chip guides: [SE050](docs/se050.md), [SE051](docs/se051.md),
[SE052](docs/se052.md).

<!-- figure: chip-frame-t1-rblock -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/chip-frame-t1-rblock.dark.svg">
  <img src="docs/diagrams/chip-frame-t1-rblock.svg"
    alt="T=1 R-block (acknowledgement) of the SE05x, 40 bits, most significant bit first. Host to chip: DAD
    (bits 39 to 36), SAD (bits 35 to 32), PCB (bits 31 to 24), LEN 0x00 (bits 23 to 16), CRC16 (bits 15
    to 0); Chip to host: DAD (bits 39 to 36), SAD (bits 35 to 32), PCB (bits 31 to 24), LEN 0x00 (bits
    23 to 16), CRC16 (bits 15 to 0). The PCB field of the Host to chip row: bit 7 1 (R-block), bit 6 0
    (R-block), bit 5 0 (reserved), bit 4 N(R), bit 3 0 (reserved), bit 2 0 (reserved), bit 1 error code,
    high, bit 0 error code, low.">
</picture>
<!-- /figure -->

<!-- figure: chip-outline -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/chip-outline.dark.svg">
  <img src="docs/diagrams/chip-outline.svg"
    alt="Outline of the SE05x in HX2QFN20 drawn to scale from above: body 3.0 x 3.0 x 0.32 mm, pitch 0.4 mm,
    20 pins and an exposed pad.">
</picture>
<!-- /figure -->

<!-- generated: chip-card -->
| | | Datasheet |
| --- | --- | --- |
| **Package** | HX2QFN20, exposed pad | Table 5 Pin description HX2QFN20, p. 11 |
| **Pins** | 20 | Table 5 Pin description HX2QFN20, p. 11 |
| **Body size** | 3.0 x 3.0 x 0.32 mm | 8, p. 12 |
| **Pin pitch** | 0.4 mm | 8, p. 12 |
| **Variants** | `hvqfn20` (below) | Table 2 Pin description for SE052, p. 4 |
| **Supply VIN** | 1.62 V to 3.6 V | Table 9 Recommended operating conditions, p. 13 |
| **Supply VCC** | 1.62 V to 3.6 V | Table 9 Recommended operating conditions, p. 13 |

Also sold as:

| Variant | Package | Pins | Size | Ordering | Note | Datasheet |
| --- | --- | --- | --- | --- | --- | --- |
| `hvqfn20` | HVQFN20 | 20 | 4.0 x 4.0 x 0.85 mm | SE052 | 0.5 mm pitch; no ENA pin; SCL on pin 10, SDA on pin 11, VDD on pin 18; the data sheet names SOT917-7 (section 6, p. 5), AN14028 SOT917-6 (ambiguity A2) | Table 2 Pin description for SE052, p. 4 |

From [`docs/hardware.yml`](docs/hardware.yml); pins, circuits and the block diagram: [Hardware](docs/hardware.md).
<!-- /generated -->

## Quick start

**1. Wire it** as in [Pins and wiring](#pins-and-wiring).

**2. Write the ports**: a bus class with `EnsureInitialized()` (bring the bus up), `Write()` and `Read()` (one I2C
transaction each) and a clock class with `NowUs()` and `DelayUs()`, about 30 lines on most SDKs. A reset class (ENA,
or RST_N on the SE052) is optional and adds the power-cycle rung of the recovery ladder. [Porting](docs/porting.md)
has the contract.

**3. Open the device:**

<!-- generated: quickstart-code -->
```cpp
using BoardPorts = se05x::Ports<MyBus, MyClock, se05x::ReferenceCrypto>;

se05x::Error RandomBytes(MyBus& bus, MyClock& clock, se05x::ReferenceCrypto& crypto,
                         se05x::MutableByteSpan out) noexcept {
  const BoardPorts ports(bus, clock, crypto);
  se05x::Device<BoardPorts> device(ports, se05x::Config{});
  if (const auto opened = device.Open(); !opened.ok()) {
    return opened.error; // for example DeviceIdMismatch: nothing answered like an SE05x
  }
  const auto random = device.GetRandom(out);
  static_cast<void>(device.Close());
  return random.error;
}
```
<!-- /generated -->

`Open()` is the only call that starts the chip. Every other call returns `Error::NotInitialized` until it has succeeded.

## Driver coverage

<!-- generated: chip-coverage -->
| Capability | What the chip does | Driver API | Registers | Status | Datasheet |
| --- | --- | --- | --- | --- | --- |
| [Key generation](docs/tasks/provisioning.md) | Generates EC key pairs inside the chip under a policy; the private key never leaves it (the facade needs applet 7.x; Device also serves 3.x (AN12413 4.7.1.1, p. 58)) | `Provision`, `GenerateEcKey`, `Execute` | `WriteECKey` (`WriteEcKey`), `WriteSymmKey` | Supported | AN12543 4.7.1.1 WriteECKey, p. 80 |
| [Signatures and key agreement](docs/getting-started.md#sign-and-verify) | ECDSA signatures and verification and ECDH shared secrets with keys held in the chip | `Sign`, `TlsSign`, `VerifySignature`, `Agree`, `EcdsaSign`, `EcdsaVerify` | `ECDSASign` (`EcdsaSign`), `ECDSAVerify` (`EcdsaVerify`), `ECDHGenerateSharedSecret` (`EcdhGenerateSharedSecret`) | Supported | AN12543 4.10 Crypto operations EC, p. 101 |
| [Attestation](docs/tasks/attestation.md) | Proves a key or a value comes from this chip: a signed, fresh read with the chip's unique ID (the facade needs applet 7.x; Device also serves 3.x (AN12413 3.2.7.2, p. 13)) | `Attest`, `ReadAttested` | `ReadObject with attestation` (`ReadObjectAttested`) | Supported | AN12543 3.2.7.2 Reading with attestation, p. 19 |
| [Secure storage](docs/tasks/secret-storage.md) | Binary objects for secrets such as a Wi-Fi passphrase or a token, read only as their policy allows (the facade needs applet 7.x; Device also serves 3.x (AN12413 4.7.1.4, p. 61)) | `Store`, `Load`, `WriteBinary`, `ReadObject` | `WriteBinary`, `ReadObject` | Supported | AN12543 4.7.1.4 WriteBinary, p. 84 |
| [Certificates and CSR](docs/pki.md) | Stores and reads certificates, builds a certificate request for a chip key and checks a chain (requests and chains in the optional PKI layer) | `StoreCertificate`, `LoadCertificate`, `BuildCsr`, `VerifyChain` | `WriteBinary`, `ReadObject` | Supported | AN12543 4.7.1.4 WriteBinary, p. 84 |
| [Monotonic counters](docs/tasks/anti-rollback.md) | Counters that only count up, for an anti-rollback floor on the firmware version (the facade needs applet 7.x; Device also serves 3.x (AN12413 3.2.1.7, p. 8)) | `CreateCounter`, `RaiseCounterTo`, `CheckFloor`, `IncrementCounter` | `WriteCounter` | Supported | AN12543 3.2.1.7 Counter, p. 7 |
| [Secure channels](docs/secure-channels.md) | Platform SCP03 encrypts the bus; AESKey, ECKey and UserID sessions authenticate the caller (ECKey sessions behind a build flag) | `Open`, `BeginAesKeySession`, `BeginEcKeySession`, `BeginUserIdSession`, `EndSession` | `CreateSession`, `SCPInitializeUpdate` (`ScpInitializeUpdate`), `VerifySessionUserID` (`VerifySessionUserId`) | Supported | AN12543 3.5 Secure Channel Protocols, p. 27 |
| [Lifecycle and locks](docs/irreversible.md) | Transport lock, a platform SCP03 requirement and factory reset: one-way changes to the chip (compiled out by default; each needs a plan and a typed confirmation) | `ExecuteIrreversible`, `Operations` | `SetLockState`, `SetPlatformSCPRequest` (`SetPlatformScpRequest`), `DeleteAll` | Guarded | AN12543 3.8 Lifecycle management, p. 42 |
| [Contactless and ISO 7816](docs/limitations.md) | The ISO 14443 antenna and ISO 7816 interfaces; the host cannot reach them over I2C | - | - | Not covered | SE050 4.2 ISO7816 and ISO14443 interface, p. 9 |

**Supported**: the driver covers it and a host test checks it; **Guarded**: covered, behind an explicit acknowledgement
because a wrong value can do harm; **Not covered**: the chip has it and the driver leaves it alone.

From [`docs/hardware.yml`](docs/hardware.yml); `kokeb-docs hardware --check` confirms that every API name is in
`inc/se05x_hrot.hpp`, `inc/se05x_device.hpp`, `inc/se05x_pki_csr.hpp`, `inc/se05x_pki_verify.hpp`,
`inc/se05x_pki_device.hpp`, `inc/se05x_irreversible.hpp` and every register (the header constant in brackets, where the
header spells it otherwise) in `inc/se05x_commands.hpp`.
<!-- /generated -->

This driver is a native implementation of the chip's protocol (T=1 over I2C, GlobalPlatform SCP03, the IoT applet), with
the transport, crypto and timing behind ports. The NXP Plug & Trust middleware is only a test oracle and is never a
dependency. A small facade (`hrot::Device`) turns the chip into a hardware root of trust with a few calls: device
identity, TLS keys, anti-rollback, sealed configuration ([HRoT cookbook](docs/hrot-cookbook.md)); each job has its
own guide ([Choose your job](docs/jobs.md)).

| | |
| --- | --- |
| **Chips** | NXP EdgeLock SE050, SE051 and SE052; VIN 1.62 V to 3.6 V on the SE050 and SE051 (SE050 Table 9, p. 13), 1.65 V to 3.6 V on the SE052 (SE052 Table 13, p. 18) |
| **Bus** | I2C target at 7-bit address `0x48` (`kI2cAddress`), up to 400 kHz in this driver; T=1 framing |
| **Layers** | T=1 link, APDU and TLV, SCP03, capability gate, typed objects and policies, device commands, HRoT facade |
| **Facade** | `hrot::Device` needs applet 7.x (SE050E, SE051, SE052): on applet 3.x (SE050 A to D, F) and 6.x (SE051 on early boards) every facade call returns `Unsupported` and sends nothing, after its argument checks (an invalid key, an off-curve point or an empty buffer is `InvalidArgument` first); `se05x::Device` serves those chips |
| **Safety** | Irreversible operations are separate types behind named confirmations, compiled out by default |
| **Driver** | Header-only C++20; no heap, exceptions, RTTI or virtual calls; every call returns `Result<T>` |
| **Runs on** | Any MCU with I2C and a C++20 compiler; the host example runs on any PC ([Platforms](docs/platforms.md)) |
| **Status** | 0.1.0, not yet verified on hardware: every layer, the facade (`hrot`) and the irreversible operations are built and tested against an independent chip model ([Limitations](docs/limitations.md)) |

- Opens the chip: boot wait, ATR or CIP, T=1 resynchronisation, applet select and version, capabilities.
- Gates every command on what the chip is (generation, applet version, features), so a command the chip lacks never
  reaches the bus.
- Builds objects and policies as typed values (policy bits differ between applet generations V3, V6 and V7).
- Opens SCP03 sessions and checks attestations against freshness.
- Recovers from a lost frame, a stuck bus and the chip's throughput limit by a ladder that ends in a power cycle.
- Returns `Result<T>` with an `Error` from every call: no exceptions, no heap, no RTTI, no virtual calls.

## Documentation

| Page | Read it when you want to |
| --- | --- |
| [Quickstart](docs/quickstart.md) | Go from a bare chip to an opened device on your MCU |
| [Choose your job](docs/jobs.md) | What the chip does for your firmware, with a guide per job: secrets, identity, certificates, mutual TLS, ECDH, secure channel, anti-rollback, attestation, provisioning |
| [The first 15 minutes](docs/first-15-minutes.md) | From the host example to a wired chip running the ESP32 example |
| [Getting started by job](docs/getting-started.md) | Provision, attest, sign, ECDH, import, channels, storage, certificates, counters, lock |
| [Where to use it](docs/variants.md) | SE050, SE051 or SE052: where each fits, the configuration, the applet and the authentication, with the package figures |
| [Hardware](docs/hardware.md) | Wire it, check the bus settings, the timing and the power; per-chip guides |
| [Security model](docs/security-model.md) | Know what the chip protects, what it does not and where the trust boundaries are |
| [HRoT cookbook](docs/hrot-cookbook.md) | Device identity, TLS keys, anti-rollback, sealed configuration, host binding |
| [Irreversible operations](docs/irreversible.md) | Lock, require SCP03, factory reset: the warnings and the confirmation flow |
| [Transport](docs/transport.md) | Understand T=1 over I2C, both flavours and the recovery ladder |
| [Secure channels](docs/secure-channels.md) | Choose and open platform SCP03, AESKey, ECKey or UserID sessions |
| [Porting](docs/porting.md), [ESP-IDF](docs/porting-esp-idf.md) | Write the port classes for your MCU's SDK |
| [API guide](docs/api-guide.md) | Use each layer: open, sessions, objects, commands, the facade, errors |
| [Troubleshooting](docs/troubleshooting.md) | Bus lock-up, the throughput limit, flavour mismatch, any error |
| [Errors and status words](docs/status-words.md) | Look up an `Error` or a status word and what to do |
| [Contract](docs/contract.md) | Know exactly what the driver promises, needs and returns |
| [Ambiguities](docs/ambiguities.md), [Limitations](docs/limitations.md) | See what the sources leave open and what is not supported |
| [Datasheet map](docs/datasheet.md) | Find the datasheet section behind each part of the driver |
| [API reference](docs/api-reference.md) | Look up a class or member (Doxygen; built by CI and locally) |

## Datasheet

<!-- generated: datasheet-card -->
| Document | Revision | Get it |
| --- | --- | --- |
| Datasheet: SE050 Plug & Trust Secure Element product data sheet (doc 504938) (NXP SE050-DATASHEET) | Rev. 3.8, revision date 2023-10-18 | [vendor page](https://www.nxp.com/docs/en/data-sheet/SE050-DATASHEET.pdf) |
| Datasheet: SE051 Plug & Trust Secure Element product data sheet (doc 577320) (NXP SE051) | Rev. 2.0, revision date 2024-07-08 | [vendor page](https://www.nxp.com/docs/en/data-sheet/SE051.pdf) |
| Datasheet: SE052 EdgeLock family product data sheet (doc 789115) (NXP SE052) | Rev. 1.5, revision date 2024-06-03 | [vendor page](https://www.nxp.com/docs/en/data-sheet/SE052.pdf) |
| Errata (datasheet set): SE050 Errata sheet (doc 640310) (NXP SE050_Erratasheet) | Rev. 1.0, revision date 2020-10-14 | [vendor page](https://www.nxp.com/docs/en/errata/SE050_Erratasheet.pdf) |
| User manual (datasheet set): UM11225 NXP SE05x T=1 Over I2C Specification (NXP UM11225) | Rev. 1.2, revision date 2020-12-10 | [vendor page](https://www.nxp.com/webapp/Download?colCode=UM11225) |
| Specification (datasheet set): GPC_SPE_172 APDU Transport over SPI / I2C, public release (GlobalPlatform GPC_SPE_172) | v1.0, 2020-01 | [vendor page](https://globalplatform.org/specs-library/apdu-transport-over-spi-i2c-v1-0-gpc_spe_172) |
| Application note (datasheet set): AN12543 SE05x IoT applet APDU Specification (applet 7.x) (NXP AN12543) | Rev. 4.5, revision date 2024-03-27 | [vendor page](https://www.nxp.com/docs/en/application-note/AN12543.pdf) |
| Application note (datasheet set): AN12413 SE050A/B/C/D/F APDU Specification (applet 3.x) (NXP AN12413) | Rev. 2.12, revision date 2021-03-24 | [vendor page](https://www.nxp.com/docs/en/application-note/AN12413.pdf) |
| Application note (datasheet set): AN12436 SE050 configurations (NXP AN12436) | Rev. 2.4, revision date 2024-07-08 | [vendor page](https://www.nxp.com/docs/en/application-note/AN12436.pdf) |
| Application note (datasheet set): AN12973 SE051 configurations (NXP AN12973) | Rev. 2.0, revision date 2024-07-08 | [vendor page](https://www.nxp.com/) |
| Application note (datasheet set): AN14277 SE052 Configuration Details (NXP AN14277) | Rev. 1.0, revision date 2024-03-25 | [vendor page](https://www.nxp.com/docs/en/application-note/AN14277.pdf) |
| Application note (datasheet set): AN13014 Moving from SE050 to SE050E or SE051 (NXP AN13014) | Rev. 1.2, revision date 2022-04-11 | [vendor page](https://www.nxp.com/docs/en/application-note/AN13014.pdf) |
| Application note (datasheet set): AN14028 Moving from SE050F to SE052F (NXP AN14028) | Rev. 1.0, revision date 2024-04-02 | [vendor page](https://www.nxp.com/docs/en/application-note/AN14028.pdf) |
| Application note (datasheet set): AN12514 SE050 User Guidelines (NXP AN12514) | Rev. 1.4, revision date 2021-11-21 | [vendor page](https://www.nxp.com/) |
| Application note (datasheet set): AN13483 SE050E User Guidelines (NXP AN13483) | Rev. 1.2, revision date 2022-08-22 | [vendor page](https://www.nxp.com/) |
| Application note (datasheet set): AN13904 SE052F User Guidelines (NXP AN13904) | Rev. 1.0, revision date 2024-03-27 | [vendor page](https://www.nxp.com/) |
| Application note (datasheet set): AN13254 Secure attestation with EdgeLock SE05x (NXP AN13254) | Rev. 1.1, revision date 2023-07-26 | [vendor page](https://www.nxp.com/docs/en/application-note/AN13254.pdf) |
| Application note (datasheet set): AN12907 Secure update of EdgeLock SE051 IoT applet (SEMS Lite) (NXP AN12907) | Rev. 1.2, revision date 2023-11-23 | [vendor page](https://www.nxp.com/) |
| Application note (datasheet set): AN13015 How to use EdgeLock SE051 PERSO applet (NXP AN13015) | Rev. 1.4, revision date 2026-01-09 | [vendor page](https://www.nxp.com/) |
| Application note (datasheet set): AN13030 Plug & Trust MW Documentation (a user guide; not a T=1 or APDU specification) (NXP AN13030) | Rev. 2.7, revision date 2026-07-09 | [vendor page](https://www.nxp.com/) |
| Application note (datasheet set): AN13539 OM-SE05xARD hardware overview (NXP AN13539) | Rev. 1.2, revision date 2022-11-08 | [vendor page](https://www.nxp.com/) |
| Application note (datasheet set): AN12448 Plug & Trust MW porting guidelines (NXP AN12448) | Rev. 1.1, revision date 2020-12-07 | [vendor page](https://www.nxp.com/docs/en/application-note/AN12448.pdf) |
| Application note (datasheet set): AN12662 Binding a host device to SE05x (NXP AN12662) | Rev. 1.1, revision date 2020-12-07 | [vendor page](https://www.nxp.com/docs/en/application-note/AN12662.pdf) |
| Application note (datasheet set): AN13013 Get started with SE05x support package (NXP AN13013) | Rev. 1.5, revision date 2024-07-25 | [vendor page](https://www.nxp.com/docs/en/application-note/AN13013.pdf) |
| Application note (datasheet set): AN12396 EdgeLock SE05x quick start guide with FRDM-K64F (NXP AN12396) | Rev. 3.3, revision date 2022-08-04 | [vendor page](https://www.nxp.com/) |
| Application note (datasheet set): AN12450 SE05x quick start guide with i.MX RT1060 and RT1170 (NXP AN12450) | Rev. 4.2, revision date 2022-08-04 | [vendor page](https://www.nxp.com/) |
| Application note (datasheet set): AN13027 SE05x quick start guide with i.MX 8M (NXP AN13027) | Rev. 1.3, revision date 2022-09-12 | [vendor page](https://www.nxp.com/) |
| Application note (datasheet set): AN12570 SE05x quick start with Raspberry Pi (NXP AN12570) | Rev. 1.5, revision date 2022-08-03 | [vendor page](https://www.nxp.com/docs/en/application-note/AN12570.pdf) |
| Application note (datasheet set): AN12398 SE05x quick start with Visual Studio (NXP AN12398) | Rev. 2.5, revision date 2022-09-12 | [vendor page](https://www.nxp.com/docs/en/application-note/AN12398.pdf) |
| Application note (datasheet set): AN12399 SE05x device-to-device authentication (NXP AN12399) | Rev. 1.3, revision date 2022-03-28 | [vendor page](https://www.nxp.com/docs/en/application-note/AN12399.pdf) |
| Application note (datasheet set): AN12449 Sensor data protection with SE05x (NXP AN12449) | Rev. 1.3, 2021-07 | [vendor page](https://www.nxp.com/docs/en/application-note/AN12449.pdf) |
| Application note (datasheet set): AN12663 SE05x TPM-like functionality (NXP AN12663) | Rev. 1.0, revision date 2021-04-13 | [vendor page](https://www.nxp.com/docs/en/application-note/AN12663.pdf) |
| Application note (datasheet set): AN13086 SE05x to enhance MCU boot sequence security (NXP AN13086) | Rev. 1.0, revision date 2021-04-13 | [vendor page](https://www.nxp.com/docs/en/application-note/AN13086.pdf) |
| Application note (datasheet set): AN12404 SE05x secure connection to AWS IoT Core (NXP AN12404) | Rev. 1.6, revision date 2021-01-15 | [vendor page](https://www.nxp.com/docs/en/application-note/AN12404.pdf) |
| Application note (datasheet set): AN12400 SE05x secure connection to OEM cloud (NXP AN12400) | Rev. 1.3, revision date 2020-12-07 | [vendor page](https://www.nxp.com/docs/en/application-note/AN12400.pdf) |
| Application note (datasheet set): AN12402 EdgeLock SE05x for secure connection to Azure IoT Hub (NXP AN12402) | Rev. 2.1, revision date 2020-12-07 | [vendor page](https://www.nxp.com/) |
| Application note (datasheet set): AN12569 SE05x secure access control in IIoT (NXP AN12569) | Rev. 1.2, revision date 2020-12-07 | [vendor page](https://www.nxp.com/docs/en/application-note/AN12569.pdf) |
| Application note (datasheet set): AN12660 Ease ISA/IEC 62443 compliance with SE05x (NXP AN12660) | Rev. 1.1, revision date 2020-12-07 | [vendor page](https://www.nxp.com/docs/en/application-note/AN12660.pdf) |
| Application note (datasheet set): AN12661 EdgeLock SE05x for Wi-Fi credential protection (NXP AN12661) | Rev. 1.2, revision date 2020-12-07 | [vendor page](https://www.nxp.com/) |
| Application note (datasheet set): AN12664 EdgeLock SE05x for NFC late-stage configuration (NXP AN12664) | Rev. 1.1, revision date 2020-12-07 | [vendor page](https://www.nxp.com/) |
| Application note (datasheet set): AN12665 EdgeLock SE05x for Blockchain ID (NXP AN12665) | Rev. 1.1, revision date 2022-08-22 | [vendor page](https://www.nxp.com/) |
| Application note (datasheet set): AN13445 Matter with SE05x/A5000 (NXP AN13445) | Rev. 1.1, revision date 2023-02-10 | [vendor page](https://www.nxp.com/docs/en/application-note/AN13445.pdf) |
| Application note (datasheet set): AN13645 Smart and secure EV charging with NXP secure solutions (NXP AN13645) | Rev. 1.0, revision date 2022-11-28 | [vendor page](https://www.nxp.com/) |
| Application note (datasheet set): AN13742 Secure smart metering with NXP secure solutions (NXP AN13742) | Rev. 1.0, revision date 2024-06-07 | [vendor page](https://www.nxp.com/) |
| Application note (datasheet set): AN14252 Secure medical IoT application with NXP secure devices (NXP AN14252) | Rev. 2.1, revision date 2025-12-19 | [vendor page](https://www.nxp.com/) |
| Application note (datasheet set): AN14671 Ease CRA compliance with EdgeLock discrete portfolio (NXP AN14671) | Rev. 1.0, revision date 2025-10-13 | [vendor page](https://www.nxp.com/) |
| Fact sheet (datasheet set): SE051 fact sheet (NXP FS-SE051) | n/a, n/a | [vendor page](https://www.nxp.com/docs/en/fact-sheet/FS-SE051.pdf) |
| Fact sheet (datasheet set): SE051H fact sheet (Matter, NFC) (NXP SE051HFS) | n/a, n/a | [vendor page](https://www.nxp.com/docs/en/fact-sheet/SE051HFS.pdf) |
| Fact sheet (datasheet set): SE051W block diagram page (UWB) (NXP SE051W-block-diagram) | n/a, revision date 2026-02-18 | [vendor page](https://www.nxp.com/assets/block-diagram/en/SE051W.pdf) |
| Fact sheet (datasheet set): SE052F fact sheet (NXP ELSE052FFSA4) | n/a, n/a | [vendor page](https://www.nxp.com/docs/en/fact-sheet/ELSE052FFSA4.pdf) |
| Source (test oracle only; not a datasheet): Plug and Trust middleware, mini package (NXP plug-and-trust) | v04.08.02, commit 7102413e0457d3dfa4fc4be686ca8ec50bd9f5e2, revision date 2026-09-24 | [vendor page](https://github.com/NXP/plug-and-trust) |

Written against these revisions; the SHA-256 of each file is in [`docs/datasheets.yml`](docs/datasheets.yml). Where each
part of the driver is in the datasheet: [Datasheet map](docs/datasheet.md).
<!-- /generated -->

## Try it on your PC

No hardware needed: [`examples/host`](examples/host/README.md) runs the root-of-trust jobs against the simulated chip
of the tests (platform SCP03, identity, a key, attestation, a signature, a sealed configuration, the firmware floor),
then opens a bus with nothing on it. You need git, CMake 3.16+ and a C++20 compiler (GCC 10+, Clang 13+ or MSVC 2022).

1. Get the source:

   ```bash
   git clone https://github.com/kokeb-labs-drivers/driver-se05x.git && cd driver-se05x
   ```

2. Build and run the example:

   ```bash
   cmake -S examples/host -B build-example
   cmake --build build-example
   ./build-example/se05x_host_example
   ```

3. You should see:

   ```text
   SE05X driver 0.1.0 on the host, simulated chip
   Open with platform SCP03                     Ok
   Identify                                     Ok
     applet 7.2.0, OEF id A921
   Provision a signing key in slot 0            Ok
   Provision slot 0 again                       ObjectExists
   Attest the key (verified)                    Ok
   Sign a digest                                Ok
   Verify the signature on the chip             Ok
   Seal a configuration                         Ok
   Create the firmware floor at 3               Ok
   Boot image version 4                         Ok
   Boot image version 2 (a rollback)            PolicyDenied
   APDUs sent: 23
   Close                                        Ok
   Open with nothing on the bus                 Nack
   ```

To run the whole test suite instead: `cmake -S . -B build -DSE05X_BUILD_TESTS=ON && cmake --build build && ctest
--test-dir build`.

## Add it to your project

Pick the row that matches your build; each is a few steps, and [Installation](docs/installation.md) has the
details.

| Your build | Steps below |
| --- | --- |
| Plain CMake: STM32 (CubeMX), RP2040 (Pico SDK), nRF Connect, a host app | [A](#a-cmake-any-mcu) |
| ESP-IDF | [B](#b-esp-idf) |
| An SDK or OS image that installs libraries | [C](#c-installed-package) |

### A. CMake, any MCU

1. Add the driver as a submodule, pinned to the version you chose:

   ```bash
   git submodule add https://github.com/kokeb-labs-drivers/driver-se05x.git external/driver-se05x
   ```

2. In your `CMakeLists.txt`, after `project()`:

   ```cmake
   add_subdirectory(external/driver-se05x)
   target_link_libraries(my_app PRIVATE se05x::se05x)   # brings the headers and C++20
   ```

3. In your code, `#include "se05x.hpp"`, write the port ([Porting](docs/porting.md)) and build. A first build
   that compiles the quickstart above is the check that the driver is wired in.

### B. ESP-IDF

1. Add the driver under your project's `components/`; ESP-IDF finds it there and names it after the folder:

   ```bash
   git submodule add https://github.com/kokeb-labs-drivers/driver-se05x.git components/se05x
   ```

2. In `main/CMakeLists.txt`, list it: `idf_component_register(SRCS "main.cpp" REQUIRES se05x)`.
3. `idf.py menuconfig` now has a **SE05X secure element** menu (boot wait, ATR poll budget, frame retries, secure messaging),
   and `idf.py build` builds the driver with your app. [`examples/esp32`](examples/esp32) is a complete
   project with a port for the board.

### C. Installed package

1. Install it once into a prefix:

   ```bash
   cmake -S external/driver-se05x -B build-se05x && cmake --install build-se05x --prefix /opt/sdk
   ```

2. In your project, with `CMAKE_PREFIX_PATH=/opt/sdk`:

   ```cmake
   find_package(se05x 0.1 REQUIRED)
   target_link_libraries(my_app PRIVATE se05x::se05x)
   ```

The target is `se05x::se05x` every way, so switching later changes nothing else.

## Tests and quality

```bash
cmake -S . -B build -DSE05X_BUILD_TESTS=ON && cmake --build build && ctest --test-dir build
```

The host tests run the driver against an independent model of the chip built from the documents, with vectors from the
specifications and the pinned NXP middleware (an oracle, never a dependency). Fuzzers corrupt what the chip sends back and
check the driver's promises after every call. CI also builds for Cortex-M and gates coverage, complexity, sanitizers,
fuzzing, clang-tidy, cppcheck and the handbook rules (`.kokeb/handbook.yml`). See [Testing and CI](docs/testing.md),
which lists every gate and its limit.

## License

MIT. See [LICENSE](LICENSE).
