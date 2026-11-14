# Contract

What the SE05x driver promises, what it needs, and the rules a caller follows.

The driver inherits the [Kokeb Labs driver contract](https://github.com/kokeb-labs/.github/blob/main/standards/driver.md);
this page states only what is specific to it. A change to anything here is a breaking change, listed under
**Breaking** in the [changelog](changelog.md). The public headers in `inc/` are frozen: a change to a signature updates
the compile-only contract test (`tests/test_contract.cpp`) in the same change.

## Promises

- `Device::Open()` is the only way to start the driver. It waits for the chip, reads the ATR or CIP, resynchronises
  the T=1 link, selects the applet, reads the version and fills `Capabilities`. On any failure the device stays
  closed and the next call starts again from the beginning.
- Every call that touches the chip returns `Error::NotInitialized` before `Open()` succeeds. No call opens or
  resets the chip as a side effect.
- Every command is checked by the capability gate (generation, applet version, features, lock and platform SCP
  state), by the lifecycle role check, by the policy's applet generation and by the limits the codec cannot see
  (the 919-byte EdDSA input of a UserID session, the UserID credential rules) before any byte goes on the bus. A
  refusal is `Unsupported`, `WrongState`, `ConditionsNotSatisfied`, `PolicyInvalid` or `InvalidArgument` and costs
  no round trip.
- Once platform SCP03 is open, no applet command goes out in the clear until `Close()`; a lost platform channel
  leaves the device `NeedsReopen` until `Recover()` opens it again.
- SW 0x66A6 resets the chip once per call and never repeats the command (`ThroughputLimited`).
- Every port failure propagates; no getter returns a stale or zero value after a failed read. Every wait is bounded
  by `Config::timeouts`, `wtx_limit` and `frame_retries`.
- Secrets live in `Secret` and `KeyHandle` types, are wiped on destruction and are never logged.
- An irreversible operation is a distinct type behind a named `Confirmation`, and is compiled out unless the build
  sets `SE05X_ENABLE_IRREVERSIBLE` ([Safety rules](safety.md)).
- Every layer is built: the device (`Device<P>`), the facade (`hrot::Device<P>`) and the irreversible plans
  (`irreversible::Operations<P>`). No call returns `Error::NotImplemented` any more; the contract test pins every
  signature.

## Depends on

| Dependency | Version | Why |
| --- | --- | --- |
| A C++20 compiler | GCC 10, Clang 13 or later | Concepts constrain the ports |
| CMake | 3.16 or later | Generates `se05x_version.h` |
| Your ports | | A bus (I2C, 7-bit address 0x48, up to 400 kHz here), a clock; optionally reset, log and a hardware crypto port |

Nothing else: no RTOS, no SDK, no other repository of the org. The NXP Plug & Trust middleware is a test oracle in
the tools, never a dependency.

## Threading

The driver is not thread-safe and takes no lock. One command is in flight at a time (errata I2C.1): use each device
from one task, or guard every call with one mutex. Nothing may run in an ISR. Separate devices share no state.

## Errors

`se05x::Error` inside `se05x::Result<T>`. Values 0 to 9 are the shared base set; 16 and up are chip specific.

| `Error` | Value | Returned when |
| --- | --- | --- |
| `Ok` | 0 | The call succeeded |
| `NotInitialized` | 1 | `Open()` has not succeeded, or `Close()` ran since |
| `InvalidArgument` | 2 | An argument or `Config` field is out of range; nothing was sent |
| `Bus` | 3 | The I2C port failed |
| `Timeout` | 4 | A bounded wait ended |
| `DeviceIdMismatch` | 5 | The chip is not the expected family or applet |
| `Crc` | 6 | A T=1 frame failed its CRC16 and the retry budget is spent |
| `Busy` | 7 | A command is in flight |
| `DeviceFault` | 8 | The chip reported an internal error |
| `Unsupported` | 9 | The capability gate refuses the command |
| `BufferTooSmall` to `NotImplemented` | 16 to 38 | Transport, session, object, policy and attestation errors; `ToString` names each |
| `ThroughputLimited` | 39 | The chip answered SW 0x66A6: its APDU throughput limit |

`Result` carries `.error` and a `.detail` with the status word and the layer. The [API guide](api-guide.md) says
what to do about each.

## Memory

No heap, no exceptions, no RTTI, no `std::function`, no `std::string`, no `printf` and no static mutable state. All
buffers are fixed by `Config` limits and caller-supplied spans. A `Device` holds its command and response buffers
and four secure-messaging pipes (platform SCP03, AESKey, ECKey, UserID) as members: about 11 KiB, so place it in
static storage on a small target. The largest plain command is `kMaxPlainCommandApdu` (1033 bytes); the largest on
the wire, with an applet session inside platform SCP03, is `kMaxCommandApdu` (1108 bytes).

## Contract amendments of the device package

- `Device::SetPlatformKeys()` (the platform key handles for `Open()` and `Recover()`) and
  `Device::ReadEckaPublicKey()` (the attested ECKA key that `BeginEcKeySession()` requires).
- `Execute<C>()` does not compile for the commands the device runs itself (`detail::IsDeviceOwned`: the select, the
  session handshake steps, `TriggerSelfTest`).
- `AuthRole::Restrict` (RESERVED_ID_RESTRICT, `DisableObjCreation`).
- `TlsPrfArgs::role` (`TlsRole::Client` or `Server`, AN12543 4.17.3).
- `kMaxPlainCommandApdu`, `kSecureMessagingOverhead`, `kSessionFrameOverhead`; `kMaxCommandApdu` from 1024 to 1108.
- `ReferenceCrypto::kSlots` from 8 to 16 (two stacked secure-messaging layers hold eight keys).

## Contract amendments of the facade and the irreversible operations

- `hrot`: typed slots per kind (`Slot`, `DataSlot`, `CounterSlot`, `CertSlot`, each with `At<N>()` checked at
  compile time and `Make()` at run time; `MakeSlot()` kept); keys typed by use (`Key<U>`: `SignKey`, `AttestKey`,
  `AgreeKey`, `TlsKey`, `VerifyKey`) replace `KeyHandle`; `Provision<U>(slot)` and `Find<U>(slot)` (NIST P-256 only)
  replace `Provision(slot, use, curve)`; `GetPublicKey()` returns `EcPublicKey`; `Sign()` and `TlsSign()` return
  `Signature`; `VerifySignature()` fails closed (`Result<void>`) and replaces `Verify()`; `Agree()`,
  `ImportPublicKey()`, `TrustAttestationKey()`, `Attest(key, slot)` for every slot kind, `Store()`, `Load()`,
  `Erase()`, the certificate calls, `CreateCounter()`, `RaiseCounterTo()`, `SetWindowCount()`,
  `ApduBudget::Used()` and `Allows()`; `CheckPlan()` takes a span. `Wrap()` and `Unwrap()` are gone: the chip has no
  RFC 3394 wrap for the host, and a wrapped import is the device's `WriteSymmKey` with a key-encryption key.
  `CheckFloor(floor, version)` is `Ok` when the version is not below the counter.
- `irreversible`: every operation tag names its plan arguments (`Op::Args`, `NoArgs`, `ImmutableObjectArgs`,
  `FiniteAuthArgs`); `Plan<Op>::Arguments()`; `PlanCreateImmutableObject(id, policy, data)` and
  `PlanCreateFiniteAuthObject(id, policy, secret, max_attempts)` take what the creating command needs.
- `Device::ReadVerified()`: an attested read and its verification in one call (the facade's attestation and
  `ReadEckaPublicKey()` use it).

## Contract amendments of the PKI layer

- `Layer::Pki` (value 9) is appended to `Layer`: a refusal of the optional PKI layer (`se05x_pki.hpp`) carries it,
  with the precise `pki::Reason` in `Detail::step` (`pki::ReasonOf()`). Nothing else changes; the layer is opt-in and
  no other header includes it. It keeps no state between calls and allocates nothing: every buffer is the caller's
  ([Certificates (PKI)](pki.md)).

## Platform

Platform-free: the same code runs on any target with a C++20 compiler, including the host tests. The ESP-IDF ports
in [`examples/esp32`](examples.md) are an example, not part of the driver.

## Deviations from the standard

None.
