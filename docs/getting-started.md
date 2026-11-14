# Getting started by job

One short path for each thing people use a secure element for. Each path names the calls, the chip objects and
policies they create, what can go wrong and where the chip documents it. Open the device first
([Quickstart](quickstart.md)); every path below starts from an open `se05x::Device` and, for the facade, an
`se05x::hrot::Device` bound to it.

<!-- generated: datasheet-refs -->
??? abstract "Datasheet sections this page relies on"

    - Reserved object identifiers: NXP AN12543 Rev. 4.5, Table 5, p. 10
    - Attestation: hash of the command, no freshness echo (applet 7.x): NXP AN12543 Rev. 4.5, Attestation, p. 19
    - Session policy and object policy headers: NXP AN12543 Rev. 4.5, Tables 62 and 63, p. 66
    - Session commands: CreateSession to ECKeySessionInternalAuthenticate: NXP AN12543 Rev. 4.5, Session management commands, p. 68
    - WriteECKey and key generation on the chip: NXP AN12543 Rev. 4.5, WriteECKey, p. 80
    - WriteSymmKey, RFC 3394 wrapped import: NXP AN12543 Rev. 4.5, WriteSymmKey, p. 83
    - WriteBinary, WriteUserID, WriteCounter: NXP AN12543 Rev. 4.5, WriteBinary, WriteUserID, WriteCounter, p. 84
    - ImportExternalObject: NXP AN12543 Rev. 4.5, ImportExternalObject, p. 88
    - ReadObject and the attested read: NXP AN12543 Rev. 4.5, ReadObject, p. 89
    - ECDSASign and ECDSAVerify: NXP AN12543 Rev. 4.5, ECDSASign, ECDSAVerify, p. 101
    - ECDHGenerateSharedSecret: NXP AN12543 Rev. 4.5, ECDHGenerateSharedSecret, p. 105
    - GetVersion, GetTimestamp, GetFreeMemory, GetRandom: NXP AN12543 Rev. 4.5, Generic management commands, p. 151
    - Edwards and Montgomery byte order on the wire: NXP AN12543 Rev. 4.5, Edwards and Montgomery byte order, p. 168
    - Pre-provisioned attestation keys: NXP AN12436 Rev. 2.4, Tables 8 and 9, p. 10
    - Attestation formats 1 and 2: NXP AN13030 Rev. 2.7, Attested read, p. 248
    - Timestamp layout: NXP AN13030 Rev. 2.7, GetTimestamp, p. 253

    All of them, with the driver API for each: [Datasheet map](datasheet.md).
<!-- /generated -->

Every snippet on this page is compiled for the board ports of the [Quickstart](quickstart.md)
(`tests/docs/jobs.hpp`) and run against the chip model in the host tests (`tests/test_docs_jobs.cpp`).

!!! note "Secure messaging first"
    Every facade key forbids use without secure messaging, and so do counters and secret data: over a bus that
    can be probed, an unauthenticated answer (a signature check, a counter value) could be forged, and a clear one
    read. Open the device with platform SCP03 (or an AESKey session) before these jobs. A call whose result you act
    on (keys, counters, verification) needs authenticated answers, an R-MAC layer (`CMacRMac` or `Full`); ECDH and
    `Protection::Secret` data need encryption both ways as well (`Full`). Otherwise the facade refuses with
    `PolicyDenied` (layer `Hrot`) and sends nothing. Identity, random numbers, public data and certificates work
    without it. For a root of trust set `ScpPolicy::Require`: `Auto` decides from an unauthenticated answer
    ([Security model](security-model.md)).

| Job | Facade call | Page section |
| --- | --- | --- |
| :material-key-plus: Provision a key | `hrot::Device::Provision<U>()` | [Provision](#provision-a-device-key) |
| :material-certificate-outline: Attest | `hrot::Device::Attest()` | [Attest](#attest-a-key-or-a-value) |
| :material-draw-pen: Sign and verify | `Sign()`, `VerifySignature()` | [Sign and verify](#sign-and-verify) |
| :material-handshake-outline: ECDH | `Agree()` | [ECDH](#agree-a-key-ecdh) |
| :material-key-arrow-right: Key import | `ImportPublicKey()`; `Device` with `WriteSymmKeyArgs` | [Key import](#import-a-key) |
| :material-lock-outline: Secure channel | `Device::SetPlatformKeys()`, `Begin*Session()` | [Secure channel](#open-a-secure-channel) |
| :material-safe-square-outline: Secure storage | `Store()`, `Load()` | [Secure storage](#store-data) |
| :material-file-certificate-outline: Certificates | `StoreCertificate()`, `LoadCertificate()` | [Certificates](#read-and-store-certificates) |
| :material-counter: Counters | `CheckFloor()`, `RaiseCounterTo()` | [Counters](#monotonic-counters) |
| :material-lock-alert-outline: Lifecycle and lock | `irreversible::Operations` | [Lifecycle](#lifecycle-and-lock) |

## Open a secure channel

| Channel | Call | When |
| --- | --- | --- |
| Platform SCP03 | `Device::SetPlatformKeys()`, then `Open()` with `Config::scp_policy` | The bus can be probed; mandatory on SE050F and when the chip requires it |
| AESKey session | `BeginAesKeySession()` | SCP03 at the applet, one AES authentication object |
| ECKey session | `BeginEcKeySession()` | Bind one host key pair to the chip |
| UserID session | `BeginUserIdSession()` | Application separation under a trusted host OS; no secure messaging |

Platform SCP03, with the keys as handles of your crypto port (never key bytes in the image, never a vendor default
key set in a product):

```cpp
--8<-- "tests/docs/jobs.hpp:open-secure"
```

An AESKey session over the default session:

```cpp
--8<-- "tests/docs/jobs.hpp:aeskey-session"
```

`EndSession()` closes it. A failed step wipes the session keys; a session that failed after CreateSession cannot be
closed, so the device selects the applet again (AN12543 3.6.5 p. 35). The ECKey session is off unless the build sets
`SE05X_ENABLE_ECKEY_SESSION=1`, and it needs the chip's ECKA key verified first (`Device::ReadEckaPublicKey`). A lost
frame or a failed check under a session leaves the device `NeedsReopen`: call `Device::Recover()`, then open the session
again. A UserID session alone is not secure messaging: the facade refuses key use over it. A facade policy names the
default session (authentication object 0) and, when the facade runs inside an AESKey or ECKey session, that session's
credential: id 0 does not cover other sessions (AN12543 3.7.1.2, p. 36), so an object made in one session is refused in
another ([Ambiguities](ambiguities.md), A20). Diagrams and details: [Secure channels](secure-channels.md).

## Provision a device key

`CheckPlan()` sends nothing and says whether each slot's policy builds for this chip. `Provision<U>(slot)`
generates a NIST P-256 key pair inside the chip (WriteECKey with no key bytes, AN12543 p. 80) under the strict
policy of its use: the use's rule, read of the public half, secure messaging; write, delete and regenerate
forbidden. A slot already in use gives `ObjectExists` and nothing is changed; `Find<U>(slot)` returns the key.

```cpp
--8<-- "tests/docs/jobs.hpp:provision"
```

!!! warning "A facade key is permanent"
    The strict policy forbids deleting the key, so the slot stays occupied for the life of the chip; only a factory
    reset ([Irreversible operations](irreversible.md), `DeleteAllObjects`) removes it. Plan the slots before you
    provision.

The key never leaves the chip. A `Key<U>` (`SignKey`, `AttestKey`, `AgreeKey`, `TlsKey`, `VerifyKey`) names the slot
only, only the facade makes a valid one, and each call takes only its own key type: `Sign()` with an `AgreeKey` does
not compile.

## Attest a key or a value

`Attest(key, slot)` returns `Verified<AttestedValue>` only when every check passed:

- a fresh 16-byte nonce from the host's crypto port for every request, never from the chip being attested (its
  answer could be replayed with an old attested answer);
- applet 3.x (format 1): the chip echoes the nonce and it must match;
- applet 7.x (format 2): the signature covers the hash of the command the chip received and the returned TLVs
  (AN12543 p. 19);
- a timestamp later than the last one accepted from this chip, across reopens (AN12543 3.9, p. 42), the signature
  with the attestation key you trust over the TLVs exactly as the chip returned them, and the 18-byte unique id
  equal to the one read in this open of the device (else `Counterfeit`).

```cpp
--8<-- "tests/docs/jobs.hpp:attest"
```

The trusted public key decides what the attestation proves. For the vendor key (`0xF0000012`, AN12436 p. 10) take it
from the vendor certificate after its chain was verified (the optional [`se05x::pki` layer](pki.md)); reading it from
the same chip proves nothing. A value that failed any check cannot become a `Verified<T>`: you get `AttestationInvalid`.
The facade returns up to 256 bytes of attested data.

## Sign and verify

`Sign(key, digest)` signs a SHA-256 digest you computed (ECDSA takes a digest, AN12543 p. 101) and returns the DER
signature. `VerifySignature()` fails closed: `Ok` only for a valid signature, `AttestationInvalid` for one that
does not verify, never a `true`/`false` to forget.

```cpp
--8<-- "tests/docs/jobs.hpp:sign"
```

## Agree a key (ECDH)

`Agree(key, peer, shared)` returns the 32-byte x coordinate of the shared point (ECDHGenerateSharedSecret, AN12543
p. 105) into a `SecretBuffer` that wipes itself. The secret crosses the bus encrypted only (`Full`). A chip
whose extended features forbid ECDH (`EXTCFG_CRYPTO_EC_FORBID_ECDH`) gives `Unsupported` before anything is sent.

```cpp
--8<-- "tests/docs/jobs.hpp:ecdh"
```

## Import a key

Generating keys inside the chip is the default. A trust anchor (a firmware-signing root, a server key) comes from
outside: `ImportPublicKey()` stores it in a key slot where it can verify and never be changed or deleted.

```cpp
--8<-- "tests/docs/jobs.hpp:import-anchor"
```

A symmetric key travels wrapped (RFC 3394) under a key-encryption key already in the chip, so the plain key never
exists on the host (WriteSymmKey, AN12543 p. 83). The facade has no symmetric keys; this is the device layer:

```cpp
--8<-- "tests/docs/jobs.hpp:import-wrapped"
```

A plain private key can be imported with `WriteEcKeyArgs` for provisioning only; it shows `Origin::External` in
every attestation. ImportExternalObject (AN12543 p. 88) is held: the vendor asks to be contacted before use.

## Store data

`Store(slot, data, protection)` creates a binary object of 1 to 2048 bytes (written 256 bytes per command);
`Protection::Secret` needs secure messaging for every read, write and delete (AN12543 p. 84), over encrypted traffic.
`Load()` reads the size from the chip, then the data. A slot in use gives `ObjectExists`: `Erase()` first. The
object is one byte longer than the data: `Store` writes a completion marker after the last chunk and `Load` refuses
an object without it (`FrameError`), so a store cut short by a power loss is never read back as a value; a store that
fails while powered deletes the object (A35), except after SW 0x66A6 (`ThroughputLimited`), when the chip refuses
work: then the object stays until `Erase()`.

```cpp
--8<-- "tests/docs/jobs.hpp:storage"
```

## Read and store certificates

A certificate slot holds the bytes as given: the facade parses nothing. The vendor provisions certificates of its own
keys (AN12436 Tables 8 and 9, p. 10). Anyone on the bus may read a certificate, and also replace it: its integrity is
its signature, so check it before you trust it. Building a CSR and parsing or verifying X.509 is the optional
[`se05x::pki` layer](pki.md).

```cpp
--8<-- "tests/docs/jobs.hpp:certificates"
```

## Monotonic counters

A counter slot holds a 4-byte counter that only goes up (WriteCounter, AN12543 p. 84), created with its start value
in one command. Its policy forbids delete, so a floor cannot be deleted and created again lower; only a factory reset
removes it. `CheckFloor(slot, version)` fails closed: `Ok` only when `version` is not below the counter,
`PolicyDenied` for an older one.
`RaiseCounterTo()` moves the floor in one command, never down; a loop of `CounterIncrement()` would spend the APDU
budget ([S-17](safety.md)). See the [HRoT cookbook](hrot-cookbook.md).

```cpp
--8<-- "tests/docs/jobs.hpp:counters"
```

## Lifecycle and lock

Locking the transport, requiring platform SCP03, restricting object creation, changing applet features and the
factory reset are lifecycle operations ([Lifecycle](lifecycle.md)). Those that cannot be undone exist only in a
build with `SE05X_ENABLE_IRREVERSIBLE=1` and go plan, confirm, apply ([Irreversible operations](irreversible.md)):

```cpp
--8<-- "tests/docs/lifecycle.hpp:lifecycle"
```

Read the current state at any time with ReadState.
