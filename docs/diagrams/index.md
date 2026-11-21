# Figures

<!-- Written by kokeb-docs figures from docs/diagrams/figures/*.py. Do not edit by hand. -->

Every figure on this site is drawn by a Python module from facts extracted from the code, so it is rebuilt,
not redrawn, when the code changes. CI runs `kokeb-docs figures --check` and fails when a
committed figure no longer matches the code. Each figure below lists the files it is drawn from.

## ECDH key agreement

<!-- figure: agree-call -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="agree-call.dark.svg">
  <img src="agree-call.svg"
    alt="ECDH key agreement: the firmware provisions an agreement key once, receives the peer's public key,
    and Agree has the chip compute the shared secret under encryption both ways and return it in a
    SecretBuffer that wipes itself.">
</picture>
<!-- /figure -->

Hardware description: [`docs/model/agree-call.seq.yml`](../model/agree-call.seq.yml)

Drawn from:

- [`docs/model/agree-call.seq.yml`](../model/agree-call.seq.yml)

## An attested read

<!-- figure: attest-call -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="attest-call.dark.svg">
  <img src="attest-call.svg"
    alt="An attested read: the facade draws a fresh nonce, asks the chip to read the object with attestation,
    and checks the command hash, the signature, a later timestamp and the unique id on the host before
    it returns a Verified result.">
</picture>
<!-- /figure -->

Hardware description: [`docs/model/attest-call.seq.yml`](../model/attest-call.seq.yml)

Drawn from:

- [`docs/model/attest-call.seq.yml`](../model/attest-call.seq.yml)

## Inside the SE05x

<!-- figure: chip-blocks -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="chip-blocks.dark.svg">
  <img src="chip-blocks.svg"
    alt="Block diagram of the SE05x: its function blocks, how they connect and which package pins reach each
    block.">
</picture>
<!-- /figure -->

Hardware description: [`docs/hardware.yml`](../hardware.yml)

Drawn from:

- [`docs/hardware.yml`](../hardware.yml)
- [`inc/se05x_ports.hpp`](../../inc/se05x_ports.hpp)

## What the SE05x does

<!-- figure: chip-capabilities -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="chip-capabilities.dark.svg">
  <img src="chip-capabilities.svg"
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

Hardware description: [`docs/hardware.yml`](../hardware.yml)

Drawn from:

- [`docs/hardware.yml`](../hardware.yml)
- [`inc/se05x_ports.hpp`](../../inc/se05x_ports.hpp)

## SE05x: Minimal application, no power cycle (SE050, SE051)

<!-- figure: chip-circuit-minimal -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="chip-circuit-minimal.dark.svg">
  <img src="chip-circuit-minimal.svg"
    alt="Schematic of the SE05x minimal application, no power cycle (se050, se051): the chip with U2 MCU, C1
    capacitor 100 nF, R1 resistor 3.3 kΩ, R2 resistor 3.3 kΩ; the MCU wires carry the port hooks
    SetEnable() / PowerCycle(), Write() / Read().">
</picture>
<!-- /figure -->

Hardware description: [`docs/hardware.yml`](../hardware.yml)

Drawn from:

- [`docs/hardware.yml`](../hardware.yml)
- [`inc/se05x_ports.hpp`](../../inc/se05x_ports.hpp)

## SE05x: Recommended application (SE050, SE051)

<!-- figure: chip-circuit-typical -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="chip-circuit-typical.dark.svg">
  <img src="chip-circuit-typical.svg"
    alt="Schematic of the SE05x recommended application (se050, se051): the chip with U2 MCU, C1 capacitor
    100 nF, R1 resistor 3.3 kΩ, R2 resistor 3.3 kΩ; the MCU wires carry the port hooks SetEnable() /
    PowerCycle(), Write() / Read().">
</picture>
<!-- /figure -->

Hardware description: [`docs/hardware.yml`](../hardware.yml)

Drawn from:

- [`docs/hardware.yml`](../hardware.yml)
- [`inc/se05x_ports.hpp`](../../inc/se05x_ports.hpp)

## SE05x: T=1 R-block (acknowledgement)

<!-- figure: chip-frame-t1-rblock -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="chip-frame-t1-rblock.dark.svg">
  <img src="chip-frame-t1-rblock.svg"
    alt="T=1 R-block (acknowledgement) of the SE05x, 40 bits, most significant bit first. Host to chip: DAD
    (bits 39 to 36), SAD (bits 35 to 32), PCB (bits 31 to 24), LEN 0x00 (bits 23 to 16), CRC16 (bits 15
    to 0); Chip to host: DAD (bits 39 to 36), SAD (bits 35 to 32), PCB (bits 31 to 24), LEN 0x00 (bits
    23 to 16), CRC16 (bits 15 to 0). The PCB field of the Host to chip row: bit 7 1 (R-block), bit 6 0
    (R-block), bit 5 0 (reserved), bit 4 N(R), bit 3 0 (reserved), bit 2 0 (reserved), bit 1 error code,
    high, bit 0 error code, low.">
</picture>
<!-- /figure -->

Hardware description: [`docs/hardware.yml`](../hardware.yml)

Drawn from:

- [`docs/hardware.yml`](../hardware.yml)
- [`inc/se05x_ports.hpp`](../../inc/se05x_ports.hpp)

## SE05x

<!-- figure: chip-hero -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="chip-hero.dark.svg">
  <img src="chip-hero.svg"
    alt="Overview of the SE05x, a family of secure elements (SE050, SE051, SE052) that hold keys and
    credentials isolated from the host, sign, agree keys and attest with them inside the chip, and talk
    to the host over I2C with T=1 framing and an encrypted SCP03 channel. A MCU talks to it over I2C,
    T=1; it drives Sensor or actuator. Headline figures: EAL 6+ Common Criteria, hardware and OS (SE051
    2.2, p. 3; SE052 3.1, p. 3); 0x48 I2C target address, T=1 framing (SE052: Table 12, p. 18); 1.62 to
    3.6 V VIN and VCC, SE050 and SE051; 3 x 3 mm HX2QFN20, SE050 and SE051; 4 x 4 mm HVQFN20, SE052.">
</picture>
<!-- /figure -->

Hardware description: [`docs/hardware.yml`](../hardware.yml)

Drawn from:

- [`docs/hardware.yml`](../hardware.yml)
- [`inc/se05x_ports.hpp`](../../inc/se05x_ports.hpp)

## SE05x package, HX2QFN20

<!-- figure: chip-outline -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="chip-outline.dark.svg">
  <img src="chip-outline.svg"
    alt="Outline of the SE05x in HX2QFN20 drawn to scale from above: body 3.0 x 3.0 x 0.32 mm, pitch 0.4 mm,
    20 pins and an exposed pad.">
</picture>
<!-- /figure -->

Hardware description: [`docs/hardware.yml`](../hardware.yml)

Drawn from:

- [`docs/hardware.yml`](../hardware.yml)
- [`inc/se05x_ports.hpp`](../../inc/se05x_ports.hpp)

## SE05x pinout, HX2QFN20

<!-- figure: chip-pinout -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="chip-pinout.dark.svg">
  <img src="chip-pinout.svg"
    alt="Pinout of the SE05x in HX2QFN20, top view: 20 pins and an exposed pad, each with its name, its
    electrical type as a colour and the driver hook that uses it.">
</picture>
<!-- /figure -->

Hardware description: [`docs/hardware.yml`](../hardware.yml)

Drawn from:

- [`docs/hardware.yml`](../hardware.yml)
- [`inc/se05x_ports.hpp`](../../inc/se05x_ports.hpp)

## Wiring: Minimal application, no power cycle (SE050, SE051)

<!-- figure: chip-wiring-minimal -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="chip-wiring-minimal.dark.svg">
  <img src="chip-wiring-minimal.svg"
    alt="Wiring of the SE05x for the Minimal application, no power cycle (SE050, SE051): MCU I2C SDA to SDA
    (Write() / Read()); MCU I2C SCL to SCL (Write() / Read()). Supplies, grounds and the support parts
    are listed under the drawing.">
</picture>
<!-- /figure -->

Hardware description: [`docs/hardware.yml`](../hardware.yml)

Drawn from:

- [`docs/hardware.yml`](../hardware.yml)
- [`inc/se05x_ports.hpp`](../../inc/se05x_ports.hpp)

## Wiring: Recommended application (SE050, SE051)

<!-- figure: chip-wiring-typical -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="chip-wiring-typical.dark.svg">
  <img src="chip-wiring-typical.svg"
    alt="Wiring of the SE05x for the Recommended application (SE050, SE051): MCU I2C SDA to SDA (Write() /
    Read()); MCU I2C SCL to SCL (Write() / Read()); MCU GPIO to ENA (SetEnable() / PowerCycle()).
    Supplies, grounds and the support parts are listed under the drawing.">
</picture>
<!-- /figure -->

Hardware description: [`docs/hardware.yml`](../hardware.yml)

Drawn from:

- [`docs/hardware.yml`](../hardware.yml)
- [`inc/se05x_ports.hpp`](../../inc/se05x_ports.hpp)

## From a device key to a stored certificate

<!-- figure: csr-flow -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="csr-flow.dark.svg">
  <img src="csr-flow.svg"
    alt="The certificate flow: the chip generates the device key and signs the CSR body, the factory station
    has your CA issue the device and CA certificates, and the firmware writes both to the chip, which it
    reads back and verifies on every boot.">
</picture>
<!-- /figure -->

Hardware description: [`docs/model/csr-flow.seq.yml`](../model/csr-flow.seq.yml)

Drawn from:

- [`docs/model/csr-flow.seq.yml`](../model/csr-flow.seq.yml)

## The layers

<!-- figure: driver-layers -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="driver-layers.dark.svg">
  <img src="driver-layers.svg"
    alt="Layer diagram: your application calls the Device library, which has no platform code.">
</picture>
<!-- /figure -->

Figure module: [`docs/diagrams/figures/driver-layers.py`](../../docs/diagrams/figures/driver-layers.py)

Drawn from:

- `public calls` in [`inc/se05x_device.hpp`](../../inc/se05x_device.hpp)

## ECKey session: opening it

<!-- figure: eckey-session -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="eckey-session.dark.svg">
  <img src="eckey-session.svg"
    alt="Sequence diagram: attested read of the chip ECKA key, ephemeral key in the crypto port,
    ECKeySessionInternalAuthenticate, challenge and receipt, receipt check, session keys, wipe.">
</picture>
<!-- /figure -->

Figure module: [`docs/diagrams/figures/eckey-session.py`](../../docs/diagrams/figures/eckey-session.py)

Drawn from:

- [`inc/se05x_eckey.hpp`](../../inc/se05x_eckey.hpp)

## The first 15 minutes

<!-- figure: first-15-minutes -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="first-15-minutes.dark.svg">
  <img src="first-15-minutes.svg"
    alt="The first 15 minutes in four steps: run the host example in minutes 0 to 3, read what it did to
    minute 6, wire the chip to minute 11 and flash the ESP32 example to minute 15.">
</picture>
<!-- /figure -->

Hardware description: [`docs/model/first-15-minutes.graph.yml`](../model/first-15-minutes.graph.yml)

Drawn from:

- [`docs/model/first-15-minutes.graph.yml`](../model/first-15-minutes.graph.yml)

## I2C timing of the address byte

<!-- figure: i2c-timing -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="i2c-timing.dark.svg">
  <img src="i2c-timing.svg"
    alt="I2C timing of the SE05x: the start condition and the address 0x48 with the write bit, bit by bit,
    with the two data hold times the data sheet defines after a falling SCL edge, the edge times and the
    clock limits.">
</picture>
<!-- /figure -->

Hardware description: [`docs/model/i2c-timing.timing.yml`](../model/i2c-timing.timing.yml)

Drawn from:

- [`docs/model/i2c-timing.timing.yml`](../model/i2c-timing.timing.yml)

## Irreversible operations: plan, confirm, apply

<!-- figure: irreversible-flow -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="irreversible-flow.dark.svg">
  <img src="irreversible-flow.svg"
    alt="Four steps: build flag, Plan (no I/O), Confirmation from the operation's phrase, Apply; and the list
    of the operations that need them.">
</picture>
<!-- /figure -->

Figure module: [`docs/diagrams/figures/irreversible-flow.py`](../../docs/diagrams/figures/irreversible-flow.py)

Drawn from:

- `operation tags` in [`inc/se05x_confirm.hpp`](../../inc/se05x_confirm.hpp)

## What the chip does for your firmware

<!-- figure: jobs-map -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="jobs-map.dark.svg">
  <img src="jobs-map.svg"
    alt="Map of the jobs of the SE05x: your firmware talks to the chip over I2C with T=1 and SCP03, and the
    chip provides a root of trust, secret storage, certificates, TLS credentials, key agreement, secure
    sessions, attestation, counters and provisioning.">
</picture>
<!-- /figure -->

Hardware description: [`docs/model/jobs-map.graph.yml`](../model/jobs-map.graph.yml)

Drawn from:

- [`docs/model/jobs-map.graph.yml`](../model/jobs-map.graph.yml)

## Lifecycle settings and the roles that change them

<!-- figure: lifecycle -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="lifecycle.dark.svg">
  <img src="lifecycle.svg"
    alt="Central card: the chip in normal use. Around it: transport locked, platform SCP required, object
    creation restricted, applet features changed and factory reset, each reached by one command from one
    reserved role; irreversible ones in red.">
</picture>
<!-- /figure -->

Figure module: [`docs/diagrams/figures/lifecycle.py`](../../docs/diagrams/figures/lifecycle.py)

Drawn from:

- `AuthRole` in [`inc/se05x_lifecycle.hpp`](../../inc/se05x_lifecycle.hpp)
- `RequiredRole` in [`inc/se05x_lifecycle.hpp`](../../inc/se05x_lifecycle.hpp)

## Objects, policies and sessions

<!-- figure: object-policy -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="object-policy.dark.svg">
  <img src="object-policy.svg"
    alt="An authentication object opens a session; a policy of an object names that authentication object and
    the rules it allows; the chip checks the policy on every command.">
</picture>
<!-- /figure -->

Figure module: [`docs/diagrams/figures/object-policy.py`](../../docs/diagrams/figures/object-policy.py)

Drawn from:

- `ObjectClass, Origin, Lifetime` in [`inc/se05x_ids.hpp`](../../inc/se05x_ids.hpp)
- `Rule` in [`inc/se05x_policy_types.hpp`](../../inc/se05x_policy_types.hpp)

## Device certificates: provision once, verify at boot

<!-- figure: pki-provisioning -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="pki-provisioning.dark.svg">
  <img src="pki-provisioning.svg"
    alt="Factory row: generate the key in the chip, build and sign the CSR on the chip, the CA outside issues
    the certificate, store it and the trust anchor read-only. Boot row: read both back and verify the
    chain with the caller's time.">
</picture>
<!-- /figure -->

Figure module: [`docs/diagrams/figures/pki-provisioning.py`](../../docs/diagrams/figures/pki-provisioning.py)

Drawn from:

- [`inc/se05x_pki_csr.hpp`](../../inc/se05x_pki_csr.hpp)
- [`inc/se05x_pki_device.hpp`](../../inc/se05x_pki_device.hpp)
- [`inc/se05x_pki_verify.hpp`](../../inc/se05x_pki_verify.hpp)

## The factory provisioning flow

<!-- figure: provisioning-flow -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="provisioning-flow.dark.svg">
  <img src="provisioning-flow.svg"
    alt="Flow of factory provisioning: open with the product's platform keys, provision keys, record the
    identity, install certificates, create counters and store credentials, then either lock the device
    or ship it unlocked for development.">
</picture>
<!-- /figure -->

Hardware description: [`docs/model/provisioning-flow.graph.yml`](../model/provisioning-flow.graph.yml)

Drawn from:

- [`docs/model/provisioning-flow.graph.yml`](../model/provisioning-flow.graph.yml)

## The recovery ladder

<!-- figure: recovery-ladder -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="recovery-ladder.dark.svg">
  <img src="recovery-ladder.svg"
    alt="Six rungs from top to bottom: resend the block, resync, interface soft reset, reselect the applet,
    chip reset and power cycle, each with what it costs.">
</picture>
<!-- /figure -->

Figure module: [`docs/diagrams/figures/recovery-ladder.py`](../../docs/diagrams/figures/recovery-ladder.py)

Drawn from:

- `Rung` in [`inc/se05x_t1.hpp`](../../inc/se05x_t1.hpp)

## The anti-rollback boot check

<!-- figure: rollback-flow -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="rollback-flow.dark.svg">
  <img src="rollback-flow.svg"
    alt="Flow of the boot check: the image version is compared with the floor, an older image is refused, and
    a newer one runs the self test and then raises the floor in one command.">
</picture>
<!-- /figure -->

Hardware description: [`docs/model/rollback-flow.graph.yml`](../model/rollback-flow.graph.yml)

Drawn from:

- [`docs/model/rollback-flow.graph.yml`](../model/rollback-flow.graph.yml)

## Opening an SCP03 session

<!-- figure: scp03-open -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="scp03-open.dark.svg">
  <img src="scp03-open.svg"
    alt="Opening an SCP03 session: Device::Open sends a host challenge, derives the session keys from the
    card's reply, checks the card cryptogram and sends EXTERNAL AUTHENTICATE, after which every command
    and answer is protected.">
</picture>
<!-- /figure -->

Hardware description: [`docs/model/scp03-open.seq.yml`](../model/scp03-open.seq.yml)

Drawn from:

- [`docs/model/scp03-open.seq.yml`](../model/scp03-open.seq.yml)

## Platform SCP03: opening the channel

<!-- figure: scp03-session -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="scp03-session.dark.svg">
  <img src="scp03-session.svg"
    alt="Sequence diagram: INITIALIZE UPDATE, card cryptogram check in the crypto port, EXTERNAL
    AUTHENTICATE, then wrapped commands with MAC and encryption both ways.">
</picture>
<!-- /figure -->

Figure module: [`docs/diagrams/figures/scp03-session.py`](../../docs/diagrams/figures/scp03-session.py)

Drawn from:

- `SecurityLevel` in [`inc/se05x_scp03.hpp`](../../inc/se05x_scp03.hpp)

## SE052 package outline, HVQFN20

<!-- figure: se052-outline -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="se052-outline.dark.svg">
  <img src="se052-outline.svg"
    alt="Outline of the SE052 in HVQFN20 drawn to scale: a 4.0 x 4.0 mm body from above with five pin marks
    per side at a 0.5 mm pitch and pin 1 at the top left, and a side view 0.85 mm high.">
</picture>
<!-- /figure -->

Figure module: [`docs/diagrams/figures/se052-outline.py`](../../docs/diagrams/figures/se052-outline.py)

Drawn from:

- [`docs/diagrams/figures/_se052.py`](../../docs/diagrams/figures/_se052.py)

## SE052 pinout, HVQFN20

<!-- figure: se052-pinout -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="se052-pinout.dark.svg">
  <img src="se052-pinout.svg"
    alt="Pinout of the SE052 in HVQFN20, top view: 20 pins with their names, coloured by type; SDA on 11, SCL
    on 10, RST_N on 14, VIN on 12, VDD on 18, no ENA pin.">
</picture>
<!-- /figure -->

Figure module: [`docs/diagrams/figures/se052-pinout.py`](../../docs/diagrams/figures/se052-pinout.py)

Drawn from:

- [`docs/diagrams/figures/_se052.py`](../../docs/diagrams/figures/_se052.py)

## Wiring the SE052

<!-- figure: se052-wiring -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="se052-wiring.dark.svg">
  <img src="se052-wiring.svg"
    alt="Schematic in boxes: MCU I2C SDA and SCL with pull-ups to the 1.65 V to 3.6 V bus supply, VIN on that
    supply, VOUT to VDD, RST_N on a GPIO, optional 22 nF on VIN and VOUT.">
</picture>
<!-- /figure -->

Figure module: [`docs/diagrams/figures/se052-wiring.py`](../../docs/diagrams/figures/se052-wiring.py)

Drawn from:

- [`docs/diagrams/figures/_se052.py`](../../docs/diagrams/figures/_se052.py)

## Provision a signing key, then sign

<!-- figure: sign-call -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="sign-call.dark.svg">
  <img src="sign-call.svg"
    alt="Device identity: Provision creates a signing key pair inside the chip with no key bytes sent, and
    Sign sends a SHA-256 digest to the chip, which returns a DER signature checked by its response MAC.">
</picture>
<!-- /figure -->

Hardware description: [`docs/model/sign-call.seq.yml`](../model/sign-call.seq.yml)

Drawn from:

- [`docs/model/sign-call.seq.yml`](../model/sign-call.seq.yml)

## Store a secret, load it at every boot

<!-- figure: store-load-call -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="store-load-call.dark.svg">
  <img src="store-load-call.svg"
    alt="Secret storage: Store writes the secret to the chip once, encrypted and MACed, and every boot Load
    reads it back encrypted and returns it in a SecretBuffer that is wiped when it goes out of scope.">
</picture>
<!-- /figure -->

Hardware description: [`docs/model/store-load-call.seq.yml`](../model/store-load-call.seq.yml)

Drawn from:

- [`docs/model/store-load-call.seq.yml`](../model/store-load-call.seq.yml)

## One T=1 block on the bus

<!-- figure: t1-frame -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="t1-frame.dark.svg">
  <img src="t1-frame.svg"
    alt="Two rows of fields: the NXP flavour NAD, PCB, one-byte LEN, INF up to 254 bytes, CRC; the GP flavour
    NAD, PCB, two-byte LEN, INF up to 4089 bytes, CRC; and the three PCB forms.">
</picture>
<!-- /figure -->

Figure module: [`docs/diagrams/figures/t1-frame.py`](../../docs/diagrams/figures/t1-frame.py)

Drawn from:

- `kUm11225Frame, kGpFrame, kGpExampleCrc` in [`inc/se05x_wire.hpp`](../../inc/se05x_wire.hpp)

## One T=1 block each way on I2C

<!-- figure: t1-i2c-block -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="t1-i2c-block.dark.svg">
  <img src="t1-i2c-block.svg"
    alt="Two I2C transfers of the NXP T=1 flavour: the host writes a block with NAD, PCB, LEN, the
    information field and a two-byte CRC, and after polling reads the chip's block of the same form.">
</picture>
<!-- /figure -->

Hardware description: [`docs/model/t1-i2c-block.timing.yml`](../model/t1-i2c-block.timing.yml)

Drawn from:

- [`docs/model/t1-i2c-block.timing.yml`](../model/t1-i2c-block.timing.yml)

## The T=1 link: states and S-blocks

<!-- figure: t1-states -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="t1-states.dark.svg">
  <img src="t1-states.svg"
    alt="State diagram of t1::Link: Closed, Idle, InFlight, NeedsReselect and Dead, with the S-blocks handled
    while a command is in flight.">
</picture>
<!-- /figure -->

Figure module: [`docs/diagrams/figures/t1-states.py`](../../docs/diagrams/figures/t1-states.py)

Drawn from:

- `LinkState` in [`inc/se05x_t1.hpp`](../../inc/se05x_t1.hpp)
- `S-block codes` in [`inc/se05x_wire.hpp`](../../inc/se05x_wire.hpp)

## A TLS client signature

<!-- figure: tls-sign-call -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="tls-sign-call.dark.svg">
  <img src="tls-sign-call.svg"
    alt="Mutual TLS: when the server requests a certificate, the TLS stack sends the client certificate read
    from the chip, has the chip sign the handshake digest through TlsSign and sends the signature as
    CertificateVerify.">
</picture>
<!-- /figure -->

Hardware description: [`docs/model/tls-sign-call.seq.yml`](../model/tls-sign-call.seq.yml)

Drawn from:

- [`docs/model/tls-sign-call.seq.yml`](../model/tls-sign-call.seq.yml)

## Trust boundaries

<!-- figure: trust-boundaries -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="trust-boundaries.dark.svg">
  <img src="trust-boundaries.svg"
    alt="Zones: remote verifier, host MCU with the driver and crypto port, the I2C bus, and the chip with
    keys, policies, counters and RNG; arrows show attestations, signatures and wrapped APDUs crossing.">
</picture>
<!-- /figure -->

Figure module: [`docs/diagrams/figures/trust-boundaries.py`](../../docs/diagrams/figures/trust-boundaries.py)

Drawn from:

- [`inc/se05x_ports.hpp`](../../inc/se05x_ports.hpp)
- [`inc/se05x_secret.hpp`](../../inc/se05x_secret.hpp)

## Choosing a variant, an applet and an authentication

<!-- figure: variant-decision -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="variant-decision.dark.svg">
  <img src="variant-decision.svg"
    alt="Decision tree: FIPS 140-3 leads to SE052F, FIPS 140-2 to SE050F, NFC and Matter to SE051H, UWB to
    SE051W, field updates to SE051A or C, else SE050E, C, A, B or D by algorithms; then platform SCP03,
    ECKey or UserID sessions.">
</picture>
<!-- /figure -->

Figure module: [`docs/diagrams/figures/variant-decision.py`](../../docs/diagrams/figures/variant-decision.py)

Drawn from:

- [`inc/se05x_types.hpp`](../../inc/se05x_types.hpp)
- [`inc/se05x_caps.hpp`](../../inc/se05x_caps.hpp)
