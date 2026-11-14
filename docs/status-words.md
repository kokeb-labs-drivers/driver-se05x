# Errors and status words

Every call returns `se05x::Result<T>`: an `Error`, and a `Detail` with the chip's raw status word (`sw`), the command,
the layer that failed, a layer step and, after a failed authentication, the attempts left. This page lists every
`Error`, what to do about it, and how the chip's status words map to it.

<!-- generated: datasheet-refs -->
??? abstract "Datasheet sections this page relies on"

    - APP.1 attestation over 1024 bytes, APP.2 CloseSession without a session: NXP SE050_Erratasheet Rev. 1.0, 3.5, 3.6, p. 9
    - NXP flavour S-blocks: NXP UM11225 Rev. 1.2, Table 9, p. 7
    - Status words and APDU encoding: NXP AN12543 Rev. 4.5, Table 21 and the APDU encoding rules, p. 49
    - APDU throughput limit on the SE052F: NXP AN13904 Rev. 1.0, APDU throughput limit, p. 28
    - APDU throughput limit, SW 0x66A6: NXP AN13030 Rev. 2.7, 2.12 and 10.16.6, p. 10

    All of them, with the driver API for each: [Datasheet map](datasheet.md).
<!-- /generated -->

## Errors

| `Error` | Value | Meaning | What to do |
| --- | --- | --- | --- |
| `Ok` | 0 | The call succeeded | |
| `NotInitialized` | 1 | `Open()` has not succeeded, or `Close()` ran | Call `Open()` |
| `InvalidArgument` | 2 | An argument or `Config` field is out of range; nothing was sent | Fix the argument; `Validate(config)` checks a `Config` |
| `Bus` | 3 | The I2C port failed (arbitration, framing) | Check wiring and pull-ups; the ladder has already retried |
| `Timeout` | 4 | A bounded wait ended (block waiting time, WTX budget, command timeout) | Raise the class timeout in `Config::timeouts` only if the command is slow by nature |
| `DeviceIdMismatch` | 5 | The chip is not an SE05x with the IoT applet | Check the part, the address and the flavour |
| `Crc` | 6 | A frame failed its CRC and the resend budget is spent | Signal integrity, bus speed, flavour |
| `Busy` | 7 | A command is in flight | One command at a time (errata I2C.1); serialise the callers |
| `DeviceFault` | 8 | The chip reported an internal error | Read `Detail::sw`; reset if it repeats |
| `Unsupported` | 9 | The capability gate refuses the command for this chip | Read the capabilities; choose another variant or call |
| `BufferTooSmall` | 16 | A caller buffer or a frame budget is too small | Give a larger span |
| `WrongState` | 17 | Locked applet, SCP required, no session, or the wrong object class | Open the session or channel the command needs |
| `Nack` | 18 | The chip did not acknowledge its address | Absent, still booting, or held in deep power-down |
| `BusStuck` | 19 | SCL or SDA held low | Power cycle: ENA (SE050, SE051) or the supply |
| `TransportDead` | 20 | The recovery ladder is spent | `Close()`, check the hardware, `Open()` |
| `FrameError` | 21 | A malformed T=1 block | Flavour mismatch is the usual cause |
| `Resynced` | 22 | The link recovered; the command was not repeated | Authenticate again, then repeat if it is safe to |
| `NeedsReselect` | 23 | The applet must be selected again | Call `Device::Recover()`; sessions are gone |
| `ObjectNotFound` | 24 | No object with that id | Provision it, or check the id |
| `ObjectExists` | 25 | An object with that id exists | Use `Find()` or another slot |
| `PolicyDenied` | 26 | The object's policy does not allow this. From the facade (layer `Hrot`): the answers are not authenticated (no R-MAC layer) for a key, counter or verification, or the traffic is not encrypted both ways for ECDH or secret data (nothing sent); or `CheckFloor` found a version below the floor. From the chip (0x6986): also an object made by the facade in another applet session (A20) | Open the session the policy names; for the facade, open platform SCP03 at `CMacRMac` or `Full` (`Full` for secrets), or an AESKey session |
| `PolicyInvalid` | 27 | A policy was refused, by the builder or the chip | Use rules valid for the class and generation |
| `AuthFailed` | 28 | Authentication failed; `attempts_left` when known | Check the credential; do not loop |
| `AuthLocked` | 29 | The credential is blocked, or the host-side attempt limit is reached | Stop; a blocked credential needs its owner |
| `ConditionsNotSatisfied` | 30 | SW 0x6985 with no better name in this context | Read `Detail`; often a missing precondition |
| `MemoryFull` | 31 | No room for the object | Delete objects; `FreeMemory()` reports what is left |
| `SecureChannelError` | 32 | A MAC, cryptogram, padding or counter check failed; the channel is closed | Re-open the channel; investigate if it repeats |
| `AttestationInvalid` | 33 | Freshness, timestamp or signature failed; from `hrot::Device::VerifySignature`, the signature does not verify | Treat the value as untrusted |
| `Counterfeit` | 34 | The unique id or certificate chain does not match | Treat the chip as untrusted |
| `IrreversibleNotConfirmed` | 35 | An irreversible operation without its plan or confirmation; also `Execute` of a `WriteUserId` or of a `WriteBinary` that creates an immutable file | See [Irreversible operations](irreversible.md) |
| `ChipSwUnknown` | 36 | A status word the driver has no mapping for | Read `Detail::sw` and report it |
| `CryptoFailure` | 37 | The crypto port failed or refused a key handle | Check your crypto port |
| `NotImplemented` | 38 | Not returned by any call of this version (kept for a later layer) | Report it: it is a bug |
| `ThroughputLimited` | 39 | SW 0x66A6: the chip refuses every command until it is reset; from the facade (layer `Hrot`): the call would pass the APDU budget, nothing was sent | Device: it reset the chip once and selected the applet again; re-authenticate and slow down. Facade: wait for the window to pass |

`ToString(Error)` gives each name. The values are a stable contract: 0 to 9 are the base set every driver shares.

## Layers

`Detail::layer` says which layer produced the error; `Detail::step` is that layer's own step number.

| `Layer` | Value | Produced by | `step` |
| --- | --- | --- | --- |
| `None` | 0 | Success | 0 |
| `Port` | 1 | A port hook (bus, clock, reset, crypto) | 0 |
| `T1` | 2 | The T=1 link | The frame or ladder step |
| `Apdu` | 3 | Encoding, TLV parsing, status-word mapping | 0 |
| `Scp03` | 4 | Platform SCP03 or an AESKey session | The handshake or unwrap step |
| `EcKey` | 5 | An ECKey session | The handshake step |
| `Gp` | 6 | The card manager | 0 |
| `Device` | 7 | The command layer (gate, roles, sessions, recovery) | The device step |
| `Hrot` | 8 | The facade | 1 refused before sending (closed, budget, no secure messaging); 2 an argument; 3 below the floor; 4 a signature that does not verify; 5 another chip's identity |
| `Pki` | 9 | The optional PKI layer ([PKI](pki.md)) | The `pki::Reason` (`pki::ReasonOf(detail)`) |

## Status words

The applet's generic status words are AN12543 Table 21 (p. 49); the document says its per-command lists are not
exhaustive. Rows marked "not in Table 21" come from other sources, named in the row. The same word
can mean different things by command, so `apdu::StatusToError(command, sw)` maps it in context.

| SW | The chip says | Usual `Error` |
| --- | --- | --- |
| `9000` | Success | `Ok` |
| `6700` | Wrong length | `InvalidArgument` |
| `6982` | Security status not satisfied | `PolicyDenied` |
| `6984` | Data invalid: policy set invalid for the object | `PolicyInvalid` |
| `6985` | Conditions of use not satisfied | `ConditionsNotSatisfied`, or by context `NeedsReselect`, `MemoryFull` (3.x), `PolicyInvalid` |
| `6986` | Command not allowed: access denied by the object policy | `PolicyDenied` |
| `6A80` | Wrong data (the text on p. 37 also uses it for an invalid policy) | `PolicyInvalid` on creation, else `InvalidArgument` |
| `6A82` | Not in Table 21; the driver's contract maps it as not found | `ObjectNotFound` |
| `6A84` | Not enough memory, transient or persistent | `MemoryFull` |
| `66A6` | APDU throughput limit reached (AN13904 p. 28) | `ThroughputLimited` |
| `6D00` | Not in Table 21; the vendor middleware reselects the applet on it (AN13030 p. 10) | `NeedsReselect` |

Contexts the driver knows:

- 0x6985 after CloseSession without a session leaves the applet unusable until it is selected again (errata APP.2,
  p. 9): the driver never sends that CloseSession and maps the word to `NeedsReselect`.
- 0x6985 on ExchangeSessionData means an invalid session policy; on VerifySessionUserID a wrong UserID
  (`AuthFailed`).
- Responses above 1024 bytes are refused on the SE050 (errata APP.1, p. 9); the driver checks the size first.
- AN12543 names both 6A80 (p. 37) and 6984 (Table 21) for an invalid policy; both map to `PolicyInvalid` on a
  create.

## T=1 control blocks

S-block requests and their responses (UM11225 Table 9, p. 7; GPC_SPE_172 Table 4-4, p. 34):

| Request | Response | NXP flavour | GP flavour |
| --- | --- | --- | --- |
| `C0` | `E0` | Resync | Resync |
| `C1` | `E1` | Information field size | Information field size |
| `C2` | `E2` | Abort | Abort |
| `C3` | `E3` | Waiting time extension | Waiting time extension |
| `C4` | `E4` | | CIP |
| `C5` | `E5` | End of APDU session (power saving) | |
| `C6` | `E6` | Chip reset | Release (power saving) |
| `C7` | `E7` | Get ATR | |
| `CF` | `EF` | Interface soft reset | Software reset |

The same code `C6` means a chip reset in one flavour and a release in the other: the link never sends it before the
flavour is known.
