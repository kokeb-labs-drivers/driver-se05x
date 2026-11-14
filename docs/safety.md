# Safety rules

The chip holds keys that cannot be recovered and settings that cannot be undone. The driver is built so that none of
these steps is one call away.

## Irreversible operations (S-10)

The warnings, the flow and the full list: [Irreversible operations](irreversible.md). Threats and trust
boundaries: [Security model](security-model.md).

Every irreversible command is its own type behind a named confirmation. The whole set is compiled out unless the build
sets `SE05X_ENABLE_IRREVERSIBLE` (CMake option, Kconfig `SE05X_ENABLE_IRREVERSIBLE`; default off).

- `Device::Execute` refuses an irreversible command at compile time. `ExecuteIrreversible` needs a
  `Confirmation<Op>` whose operation matches the command.
- `irreversible::Operations` first returns a `Plan` (a dry run that lists what would change), then `Apply` takes the
  confirmation. There are 13 operations: 11 on `Operations` and two on `perso::Perso` (`WritePersoSetting`,
  `DeletePersoModule`). Seven of the 11 can be applied; `ReplacePlatformKeys`, `ChangeI2cAddress`,
  `ApplyAppletUpdate` and `ReplaceEcKeyCredential` are refused at the plan (`Unsupported`).
- `DeleteAll` needs the factory-reset role. `TriggerSelfTest` takes the non-irreversible `ResetExpected`
  acknowledgement, because the chip resets without a reply.
- PERSO writes change the I2C address or the interface flavour on the next reset. Deleting a PERSO module is
  permanent, and the `iot_base` module is never offered.

## Lifecycle checks

`RequiredRole(Command)` and `RoleOf(ObjectId)` state which authentication a command needs. The device checks the
role before it sends the APDU, so a refusal costs no chip round trip and no throughput budget.

## Rules

| Id | Rule |
| --- | --- |
| S-01 to S-08 | Secrets live in `Secret` and `KeyHandle` types, are wiped on destruction and never logged. Key material does not leave the crypto port. |
| S-09 | Attestation is checked against freshness. The nonce is new random bytes from the host's crypto port for every request, never from the chip being attested. V1: the random echoed back must equal the one sent. V2: the echoed command must equal the sent one byte for byte, then the signature over the SHA of the command and the TLVs exactly as the chip returned them is checked; the 12-byte timestamp (4 persistent plus 8 transient bytes) must be later than the last one accepted, across reopens of the device. A value that was not verified cannot be turned into a `Verified<T>`. |
| S-10 | Irreversible operations, as above. |
| S-11 to S-13 | Session and recovery: any recovery rung drops all session knowledge; a reset closes applet sessions; SCP03 counters never rewind. |
| S-14 | UserID sessions: no infinite attempt counters; a secret is never used over a UserID session; the attempt limit is stated in the type. The facade refuses a key, counter or verification call unless the answers are authenticated (an R-MAC layer), and an ECDH or secret-data call unless the traffic is also encrypted both ways (`PolicyDenied`, layer `Hrot`, nothing sent). Immutable files and UserID objects are created only through the irreversible operations (`IrreversibleNotConfirmed` otherwise). |
| S-15, S-16 | Host builds use `ReferenceCrypto` for tests only; it is labelled and must not hold real keys. A hardware crypto port replaces it on target. |
| S-17 | APDU budget. The chip limits throughput (status 66A6, about one million APDUs in a 34 day window). The facade counts every APDU the device sends, across reopens and recoveries, saturating (`ApduBudget`, with the persisted window count from `SetWindowCount()`) and admits a call only when its worst-case APDU count (`hrot::cost`) fits under the ceiling (`ThroughputLimited`, layer `Hrot`, nothing sent); counters move in one command (`RaiseCounterTo`) instead of a loop. A chip that answers 0x66A6 anyway makes the device climb the ladder to the chip reset rung; that recovery sends up to four APDUs beyond the admitted cost (the select, the lifecycle read and, with platform SCP03, the two handshake commands), counted in `Used()`, and the call sends nothing more (`Store` skips its clean-up delete), so one call ends at most four APDUs past the ceiling. |

## What must not run on the host

No real key is generated, imported or provisioned with the reference crypto. No irreversible build runs against a
real chip without a bench record. The test model replaces the chip on the host.
