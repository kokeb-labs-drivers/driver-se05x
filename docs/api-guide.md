# API guide

The driver's API by layer, with code that compiles: open, sessions, objects and policies, commands, the facade and
errors. The jobs of a root of trust, through the facade, are on [Getting started by job](getting-started.md) and in
the [HRoT cookbook](hrot-cookbook.md), each with compiled code.

<!-- generated: datasheet-refs -->
??? abstract "Datasheet sections this page relies on"

    From NXP AN13030 Rev. 2.7:

    - APDU throughput limit, SW 0x66A6: 2.12 and 10.16.6, p. 10

    All of them, with the driver API for each: [Datasheet map](datasheet.md).
<!-- /generated -->
## The shape of the API

| Group | Where | What it is |
| --- | --- | --- |
| Device | `se05x::Device<P>` | `Open`, `Close`, `Recover`, `PowerCycle`, `DeepPowerDown`, sessions, `Execute<Command>`, named wrappers |
| Irreversible | `se05x::irreversible::Operations<P>` | A `Plan` first, then `Apply` with a `Confirmation<Op>`; compiled out by default |
| HRoT facade | `se05x::hrot::Device<P>` | Slots, key handles, identity, attestation, `Verified<T>`, `ApduBudget` |
| Perso | `se05x::perso::Perso<P, T>` | Read-only PERSO applet access on SE051; writes behind tokens |
| Types | `se05x_types.hpp`, `se05x_caps.hpp` | `Config`, `Capabilities`, `AppletGeneration`, `Features` |
| Policies | `PolicyBuilder<G, C, P>` | Generation-typed policy bits (V3, V6, V7) checked against the object class |
| Attestation | `attest::Verifier<P, F>` | V1 freshness echo; V2 echoed command, SHA and TLVs, 12-byte timestamp |

## Open

The ports are the only platform code. A call returns `Result<T>`: check `.ok()` before using the value.

```cpp
--8<-- "tests/docs/quickstart.cpp:quickstart"
```

`Open()` does the boot wait, the ATR or CIP, the resynchronisation, the applet select and the version read.
`Probe()` on `perso::Perso` warns when the PERSO applet is still selectable.

## Commands

`Device::Execute<C>(args)` runs one command of the `Command` enum with its typed arguments and reply. A command that
is irreversible does not compile here: use `ExecuteIrreversible<C, Op>(args, Confirmation<Op>)` in a build with
`SE05X_ENABLE_IRREVERSIBLE`.

## Handle errors

| `Error` | What to do |
| --- | --- |
| `NotInitialized` | Call `Open()` |
| `Unsupported` | The chip lacks the command; check `GetCapabilities()` |
| `WrongState` | Open the session or authenticate first; see `Role()` |
| `Nack`, `Timeout`, `Crc` | The link retries; a persistent one climbs the recovery ladder |
| `Resynced`, `NeedsReselect` | Re-authenticate or select again, then repeat the command yourself |
| `BusStuck`, `TransportDead` | Call `PowerCycle()` when the reset port exists |
| `ThroughputLimited` | The chip limits APDUs (SW 0x66A6); wait, then the ladder ends in a chip reset ([S-17](safety.md)) |
| `PolicyDenied`, `AuthLocked` | The object policy or the attempt limit; no retry helps |
| `IrreversibleNotConfirmed` | An irreversible operation lacked its `Confirmation` |

`GetLastStatusWord()` and `GetLastDetail()` give the chip's status word and the layer that failed.

## Close

`Close()` ends the sessions and leaves the chip selectable; `DeepPowerDown()` puts it into its lowest-current state
when the core supply comes from VOUT.
