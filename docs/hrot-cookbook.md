# HRoT cookbook

Recipes that combine the jobs of [Getting started by job](getting-started.md) into what a product needs from a
hardware root of trust. Each recipe lists the chip objects it uses, the order of the calls and the checks that make it
safe. They use the facade only, so every key gets the strict policy.

<!-- generated: datasheet-refs -->
??? abstract "Datasheet sections this page relies on"

    From NXP AN12543 Rev. 4.5:

    - Attestation: hash of the command, no freshness echo (applet 7.x): Attestation, p. 19

    All of them, with the driver API for each: [Datasheet map](datasheet.md).
<!-- /generated -->

Every recipe's code is compiled (`tests/docs/jobs.hpp`) and run against the chip model in the host tests. The
recipes assume the device is open with platform SCP03 (see
[Open a secure channel](getting-started.md#open-a-secure-channel)).

## :material-fingerprint: Device identity at the factory

1. `Identify()`: the 18-byte unique id, the family, the applet version and the OEF id. Record them.
2. `CheckPlan()` and `Provision<KeyUse::Sign>()` the device key in slot 0; `GetPublicKey()` reads the public half.
3. `Attest()` the key with the vendor attestation key: the record now proves the key was born in this chip.
4. Send the public key and the attestation to your certificate authority; store the certificate it returns with
   `StoreCertificate()`.

```cpp
--8<-- "tests/docs/jobs.hpp:identity"
```

Never generate the key on the host and import it: an external key shows `Origin::External` in every attestation for the
life of the chip. Building the CSR for step 4 is the optional [`se05x::pki` layer](pki.md).

## :material-cloud-lock-outline: TLS client key

A `TlsKey` signs the handshake digest with `TlsSign()`; your TLS stack calls it from its private-key callback. The
driver provides the signing call, not a TLS stack binding: wire this function into your stack's external-key hook.
The certificate comes from `LoadCertificate()`.

```cpp
--8<-- "tests/docs/jobs.hpp:tls"
```

For the host-side crypto of the driver itself (SCP03, the attestation check), the optional PSA crypto port in
[`examples/psa/`](../examples/psa/se05x_psa_crypto.hpp) replaces `ReferenceCrypto` with mbedTLS or any PSA Crypto
implementation; the ESP32 example uses it.

## :material-shield-check-outline: Anti-rollback floor for firmware

1. Create a counter per image type with `CreateCounter(slot, first_version)`.
2. At boot, after the image's signature checked out (`VerifySignature()` with the firmware root of
   [Key import](getting-started.md#import-a-key)), `CheckFloor(slot, image_version)`: `PolicyDenied` means the image
   is older than one that ran before; refuse it.
3. After the new image has booted and passed its self test, raise the floor with `RaiseCounterTo()` in one command.

```cpp
--8<-- "tests/docs/jobs.hpp:counters"
```

A counter only goes up, and its policy forbids delete, so a rollback cannot lower the floor even with full control
of the host: it can neither count down nor delete the counter and create it again lower. `CreateCounter()` sets the
start value in the same command that creates the counter, so a lost power cannot leave a floor of 0; when the slot
already holds a lower counter it is raised to the value asked. Authenticated answers (an R-MAC layer) keep a host on
the bus from forging the value it reads.

## :material-lock-check-outline: Sealed configuration

Store a configuration blob as `Protection::Secret`: every read, write and delete needs secure messaging, and the
facade sends it only over encrypted traffic (`Full`), so only a host that can open platform SCP03 (or a session)
reads it, and nothing on the bus does.

```cpp
--8<-- "tests/docs/jobs.hpp:storage"
```

To tie the read to a measured boot state as well, build the policy yourself with `RequirePcr()` and write it with
`Device::WriteBinary()`; the facade's policies have no PCR condition.

## :material-link-lock: Binding a host to the chip

Open an ECKey session with the host's key pair: the chip holds the host's public key as an authentication object,
so a chip moved to another board refuses that board. Verify the receipt (`Config::verify_eckey_receipt`, on by
default). The ECKey session is built only with `SE05X_ENABLE_ECKEY_SESSION=1`. See
[Secure channels](secure-channels.md).

## :material-dice-multiple-outline: Random numbers

`Random()` reads the chip's DRG.4 generator (seeded by a PTG.2 TRNG, SE050 data sheet section 3.1.1), up to 1024
bytes per call. Without secure messaging the bytes are not authenticated: a host on the bus could replace them.

```cpp
--8<-- "tests/docs/jobs.hpp:random"
```

## :material-speedometer-slow: Staying under the throughput limit

Status word 0x66A6 stops the chip until a reset: more than one million APDUs within 34 days on the SE052F (AN13904
p. 28), possibly on the SE051. A host that polls once per second sends about 2.9 million APDUs in 34 days. The facade
counts every APDU the device sends, across every `Open()` and recovery of the device object (the count saturates,
it never wraps), and refuses a call whose worst-case APDU count would pass the ceiling with `ThroughputLimited`
(layer `Hrot`, nothing sent, no reset). The count knows nothing of earlier boots of the host: persist it and give it
back at boot with `SetWindowCount()`. Calls made through `se05x::Device` directly are counted but not admitted.

Every facade call is admitted only when its worst case fits: the table below is `hrot::cost`, the number of APDUs a
call may send at most, whatever path it takes, as long as the chip answers it (the CTest `se05x_docs_costs` checks
that this table and the header agree, and edge tests check that no path passes its cost). One path goes past it: when
the chip answers SW 0x66A6 anyway (its own count differs from yours, for example after a lost window count), the device
resets the chip and selects the applet again, which sends up to four more APDUs (the select, the lifecycle read and,
with platform SCP03, the two handshake commands), and the call returns `ThroughputLimited` without sending anything
else (`Store` then leaves its unfinished object for `Erase` instead of deleting it). Those APDUs are counted in
`Used()`, so the count can end at most four past the ceiling; a test pins that bound.

| Constant | APDUs | Call |
| --- | --- | --- |
| `kIdentify` | 1 | `Identify` |
| `kProvision` | 2 | `Provision` |
| `kFind` | 3 | `Find` |
| `kGetPublicKey` | 1 | `GetPublicKey` |
| `kImportPublicKey` | 2 | `ImportPublicKey` |
| `kSign` | 1 | `Sign`, `TlsSign` |
| `kVerifySignature` | 1 | `VerifySignature` |
| `kAgree` | 1 | `Agree` |
| `kAttest` | 2 | `Attest` (1 once the unique id was read in this open) |
| `kStoreBase` | 3 | `Store`, `StoreCertificate`, plus one per 256 bytes of data |
| `kLoadBase` | 2 | `Load`, `LoadCertificate`, plus one per 256 bytes of the buffer, at most 2048 |
| `kErase` | 1 | `Erase`, `EraseCertificate` |
| `kCreateCounter` | 5 | `CreateCounter` (2 for a new counter) |
| `kCounterValue` | 1 | `CounterValue`, `CheckFloor` |
| `kCounterIncrement` | 2 | `CounterIncrement` |
| `kRaiseCounterTo` | 1 | `RaiseCounterTo` |
| `kRandomPer512` | 1 | `Random`, per 512 bytes |


```cpp
--8<-- "tests/docs/jobs.hpp:budget"
```

Cache what does not change (the identity, the public keys, the certificates) and never poll the chip for time or
randomness in a tight loop.
