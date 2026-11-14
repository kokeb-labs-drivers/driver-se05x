# Limitations

What the driver does not do, what it holds back, and what has not been checked. Each item says why.

<!-- generated: datasheet-refs -->
??? abstract "Datasheet sections this page relies on"

    From NXP AN12543 Rev. 4.5:

    - APDU buffer 270 bytes, internal buffer 1024 bytes: APDU buffer sizes, p. 3
    - ImportExternalObject: ImportExternalObject, p. 88
    - AEAD one-shot limit 888 bytes: AEADOneShot, p. 125

    All of them, with the driver API for each: [Datasheet map](datasheet.md).
<!-- /generated -->

## Not supported

| Item | Why |
| --- | --- |
| ISO 7816 and ISO 14443 interfaces | A host cannot reach them over I2C; they are chip-side interfaces |
| SE051P | It runs a customer applet and has no IoT applet |
| T4T applet (SE051H NFC file system) | A separate applet, not in AN12543 |
| SEMS Lite applet update agent | Its applet interface document is not published; the raw GlobalPlatform channel stays |
| SCP02, SCP11 | Not offered by the chip in the public documents |
| X.509 parsing in the facade | The facade stores and reads certificate bytes; DER, CSR and X.509 are the optional `se05x::pki` layer |
| Platform key replacement, I2C address change, applet update, ECKey credential replacement | The irreversible plans return `Unsupported` ([Irreversible operations](irreversible.md)) |
| The HRoT facade on applet 3.x (SE050 A to D, F) and 6.x (SE051 on early boards) | Every facade call returns `Unsupported` before anything is sent, after its argument checks (an invalid key, an off-curve point or an empty buffer is refused first with `InvalidArgument`); the device layer (`se05x::Device`) serves these chips |
| Reading with `Load` or `Attest` a data object that `Store` did not write | `Store` ends every object with a completion marker (0xA5). An object without it (written by `Device` or another tool) is `FrameError`; one that happens to end in 0xA5 reads back one byte short. Read such objects with `Device::ReadObject` |
| Facade curves other than NIST P-256 | The facade keys are P-256 (every variant has it, and the crypto port verifies it); other curves through `Device` |
| TPM 2.0 | A host-side software stack over the vendor middleware, not a chip command set |
| ImportExternalObject | The vendor asks to be contacted before use (AN12543 p. 88) |

## Held until confirmed

- The ECKey session key derivation is written from AN12543 but has no test vector: built behind a flag.
- The NXP-flavour CRC byte order is not in UM11225: both orders are tried in `Auto`.
- The length form of the TLVs in an attested answer is not fixed by the documents: the signature is checked over
  the bytes as returned (A21).
- Which NAD and MPOT unit a chip uses in the GP flavour, and whether `Auto` reaches every variant (A17, A32).
- Whether platform SCP03 in the default session satisfies a policy's REQUIRE_SM, and that facade objects made in
  one applet session are refused in another (A20).
- The SE050 boot time before the first frame is not in the documents: `Config::boot_wait_ms` (20 ms) then polling.
- The policy bit values of applet 6.x are not in any obtained document.
- Irreversible operations are compiled out by default.
- The length form an attestation hashes under secure messaging ([Ambiguities](ambiguities.md)).
- `DeleteAll` is sent with the `Lc 0x00` byte of AN12543 Table 339; the vendor middleware sends four bytes. Both
  should be accepted; a trace of a real chip decides it ([Ambiguities](ambiguities.md)).

## Limits of the chip the driver enforces

The applet's APDU buffer is 270 bytes and its internal buffer 1024 (AN12543 p. 3); an AEAD one-shot carries at most
888 bytes (p. 125); EdDSA sign and verify at most 940 bytes of input, 919 inside a UserID session (pp. 103-104);
an attested binary read at most 500 bytes per chunk; one applet session at a time through `Device` (the chip
allows two); the throughput limit of SW 0x66A6 ([Errors and status words](status-words.md)). `TLSPerformPRF` takes
the host's TLS role (`TlsPrfArgs::role`) to choose which random it passes (AN12543 4.17.3).

## Not verified

- **Nothing has run on hardware.** Every transport, timing and secure-channel behaviour is from the documents, the
  vendor middleware as a test oracle and an independent chip model. Bench steps are on every row of
  [Ambiguities](ambiguities.md).
- **No trace of a real chip** is in the test vectors yet.
- **The certification of the chip** (FIPS 140-2 on the SE050F, FIPS 140-3 on the SE052F) covers the chip, not this
  driver.

See also [Ambiguities](ambiguities.md) for every open question and its knob.
