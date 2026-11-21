# Ambiguities and knobs

Where the sources disagree or are missing, the driver does not guess silently. Each doubt below has a choice, a bench
step that settles it, and a knob where one exists (`Config` fields and build flags; "model" knobs belong to the test
chip model and only reproduce the case). The status column says whether the documents settle it (document and page
named), partly settle it, or leave it open.

| Id | Question | Status | Choice | Knob | Bench step (**not verified on hardware** until run) |
| --- | --- | --- | --- | --- | --- |
| A1 | SE051 applet version | settled: 6.0 on earlier boards, 7.2 since early 2022, 7.3 by update | capability by `GetVersion`, never by name | model profiles `se051_v6`, `se051_v7` | `Open()` an SE051 dev kit; compare `GetCapabilities().applet` with the label |
| A2 | SE052 package code SOT917-6 or -7 | open | both recorded in `hardware.yml`; the data sheet number is shown | none | read the package marking of an SE052 dev kit |
| A3 | OEF ids swapped between two tables of one note | open | trust the on-chip value | none | `Open()` each variant; record `Capabilities::oef_id` next to the part number |
| A4 | SE052F curve and RSA sets | open (config sheet not public) | capabilities from the applet configuration bits and a curve-list probe | model `profile` | `ReadEcCurveList` on an SE052F; record which curves answer |
| A5 | SE052 digests outside HMAC and PBKDF | open | digest commands gated on capability | model `profile` | `DigestOneShot` with each algorithm on an SE052F; record the status words |
| A6 | 7.x TLV numeric constants | partly settled | every codec checked byte for byte against the AN12543 and AN12413 APDU tables; 122 commands match the middleware (below); PAKE and T4T held | `held_commands` | trace one command of each group on a dev kit and compare with the codec |
| A7 | Changing the I2C address | partly settled (SE051 PERSO tag 0x800D) | read-only; the write sits behind the S-10 token on `perso::Perso` | none | read tag 0x800D on an SE051; do not write it on a shared board |
| A8 | Boot time before the first frame | partly: 5 ms NXP flavour, 25 ms GP, SE052 ATR WUT 5 ms; no SE050 value (UM11225 p. 19, GPC_SPE_172 p. 31) | `boot_wait_ms`, then poll the ATR with back-off | `Config` | power-cycle an SE050 and log the time from ENA high to the first ACKed read |
| A9 | Framing flavour per chip | both flavours settled (UM11225 pp. 5-19, GPC_SPE_172 pp. 21-39); the SE051 detects the flavour from the first frame (SE051 data sheet 4.1.2, p. 9); SE052F NXP by default (AN13904 p. 27); SE050 not stated | `Flavour::Auto`: the NXP form first for half of the budget, then GP; fix on the first valid frame (A17) | `Config`, model `gp_flavour` | `Open()` each variant with `Auto` and with each fixed flavour; record which open |
| A10 | CRC byte order on the wire | GP settled (MSB first, BDA4); NXP: the CRC is the one of ISO/IEC 7816-3 (UM11225 2.1, p. 5), the byte order is not printed | both orders tried in `Auto`; both in the model | model `crc_swapped` | log one NXP-flavour frame from a chip and check which byte of the CRC comes first |
| A11 | Command timeouts | partly: ATR gives BWT, MPOT, SEGT; ten retransmissions; WTX host timeout at least 4 s | class defaults; about 20 s is the quiet limit; a WTX extends any class to at least 4 s (A19) | `Config::timeouts`, `wtx_limit` | time `DeleteSecureObject` and a FIPS self-test window on an SE052F |
| A12 | DESFire availability | unchanged | capability bit | model `profile` | read the extended features of each variant |
| A13 | Does a reset close sessions | settled for the T=1 chip reset | every recovery rung drops all session knowledge | model | open an AESKey session, `Recover(ChipReset)`, send a wrapped command: the chip must refuse it |
| A14 | A second host-facing I2C address | open | not modelled | none | scan the bus of a dev kit for a second ACKing address |
| A15 | ECKey receipt on 7.x | settled: the receipt exists and the host checks it; the key derivation is printed in AN12543 pp. 22-23 and 72-73 | built from AN12543 behind a flag until a vector confirms it | model `receipt` | open an ECKey session on a 7.x dev kit with the flag on; the receipt check must pass |
| A16 | Throughput limit 66A6 | settled for the SE052F (AN13904 p. 28); possible on the SE051 (AN13030 p. 10) | status `ThroughputLimited`, chip-reset rung, APDU budget rule S-17 | model `throttle_enabled`, `throttle_after` | none needed on a shared kit (it costs a million APDUs); run once on a sacrificial SE052F |
| A17 | GP flavour NAD and Auto order | partly: GPC_SPE_172 4.2.1 (p. 33) only recommends NAD 0x21/0x12; the vendor middleware sends 0x5A and expects 0xA5 in its GP mode; the SE051 locks onto the protocol of the first frame (data sheet 4.1.2, p. 9) | GP accepts 0x12 or 0xA5 from the chip; `Auto` tries the NXP flavour first, so an SE051 is never locked into GP by the probe | `Config::flavour` | `Open()` an SE051 and an SE052 with `Gp` fixed; log the NAD of the first answer; then power-cycle and `Open()` with `Auto` |
| A18 | SE052 deep power-down by S-block | partly: tDPD 300 us before the next access (SE052 data sheet Table 15, p. 22); the 0xFF response code comes from the middleware only | after the S-block response nothing touches the bus for 300 us | none | send `DeepPowerDown()` to an SE052 and log the response PCB; wake it after 300 us and after 100 us |
| A19 | WTX on a short command class | settled: the host waits at least 4 s after a WTX (AN13904 8.3, p. 27); the SE052F sends WTX every second, also in its FIPS self-test | a WTX extends the command deadline itself to at least 4 s, whatever the class (`fast_ms` 2 s included) | `Config::wtx_limit` | `DeleteSecureObject` of a large object on an SE052F; it must succeed while WTX arrive |
| A20 | Authentication object 0 and other sessions | settled in the text: id 0 is the default session only, not inherited by authenticated sessions (AN12543 3.7.1.2, p. 36); whether platform SCP03 in the default session satisfies REQUIRE_SM is not stated (Table 63, p. 67) | facade policies name id 0 and, inside an AESKey or ECKey session, that session's credential; an object made in one session is refused in another (fails closed) | `PolicyBuilder::For()` for more sessions | provision a facade key under platform SCP03 and sign; then sign in an AESKey session: the first must pass, the second must be refused with 0x6986 |
| A21 | Length form of the attested TLVs | open: AN12543 4.1.3.2 (p. 49) allows any BER length form in an R-APDU; Tables 128, 131 and 313 do not fix one | the signature is checked over the TLV bytes exactly as returned; a verifier without them (format 2 vectors) rebuilds the `82 xx xx` form | model `attested_short_tlv` | one attested `ReadObject` on a dev kit: record the answer and check which length form the TLVs use |
| A22 | DeleteAll inside a session | settled: the reply is not wrapped (AN12543 4.20.5, p. 154); RESERVED_ID_FACTORY_RESET may be any authentication object type (3.2.4.1.1.5, p. 12) | a bare 9000 is success for a command that ends the session, in that session only; the session is then dropped | none | run `DeleteAll` in an AESKey factory-reset session on a sacrificial dev kit |
| A23 | Guard time between accesses | settled: SEGT (UM11225 Table 15, p. 20) and RWGT (GPC_SPE_172 3.2.7, p. 28) hold between any two accesses | the guard before every read and write, at least the default 10 us, except right after a NACKed drain probe (errata I2C.1: a wait there lets the next answer arrive before the write) | none | logic-analyser trace of one exchange: no two accesses closer than SEGT |
| A24 | ReadIDList MoreIndicator | open: the text of AN12543 p. 94 contradicts Table 56 (p. 63) | the table: 01 NO_MORE, 02 MORE | none | create more ids than one answer holds; read the list and check the indicator of the first answer |
| A25 | I2C controller command order | open: "only one READ at the end" (AN12543 p. 146) contradicts Figure 21 (p. 147), which reads several times | the strict reading: CONFIGURE first with a clock byte of 0x00 or 0x01, at most one READ, last | none | run Figure 21's sequence on a dev kit with an I2C target; if it passes, the rule can be relaxed |
| A26 | Le of a wrapped command | open: "Le must be smaller than 0x8000" (AN12543 4.1.2, p. 48); AN13904 Figure 8 (p. 16) shows a wrapped command with no Le | a wrapped command that carried Le goes out in the extended form with Le 00 00, as the vendor middleware frames it | none | send a wrapped `ReadObject` of 300 bytes under platform SCP03 and record the status word |
| A27 | Object ids 0x80000000 and up | partly: AN12543 3.2.4.1 (p. 10) reserves 0x7FFF0000 to 0x7FFFFFFF only; AN13904 Table 1 (p. 7) reserves 0x80000000 and up for NXP on the SE052F | `MakeUserObject()` refuses 0x7FFF0000-0x7FFFFFFF and 0xE0000000 and up on every part; AN13904 advises 0x00000000-0x7BFFFFFF | none | `MakeUserObject(0xE0000000)` on an SE052F dev kit is refused by the driver; `WriteBinary` to 0x80000000 there shows whether the chip reserves it (record the status word) |
| A28 | SCP03 counter for commands without data (errata JOS.2) | partly: the SE050 errata (3.13, p. 12) says the counter does not advance; the response ICV for such a command uses counter - 1 in the middleware only | `jos2_counter_rule` on by default for platform SCP03 on every variant | `ChannelParams::jos2_counter_rule` | under platform SCP03 at `Full`, send `GetVersion` (no data) then `ReadObject`: both R-MACs must verify |
| A29 | ECKey InternalAuthenticate form | open: AN13904 Figure 7 sends it without the TAG_1 wrapper and without Le; AN12543 Table 85 (pp. 72-73) wraps it | the AN13904 form, behind `SE05X_ENABLE_ECKEY_SESSION` | build flag | open an ECKey session on a 7.x dev kit with the flag on |
| A30 | Recovery order after retransmissions | settled by ISO/IEC 7816-3: RESYNC is allowed before the soft reset UM11225 2.4.1 (p. 11) names | the ladder sends RESYNC, then the soft reset, then selects the applet again, then the chip reset and the power cycle | none | break one frame on a dev kit (cut SDA for one byte); the log shows RESYNC answered |
| A31 | PAKE in FIPS 140-3 mode | open: AN12543 3.13.2 (pp. 45-47) says PAKE is allowed on p. 46 and not on p. 47 | PAKE stays held (A6) | `held_commands` | on an SE052F in FIPS mode, send one PAKE `CreateCryptoObject` with the command un-held in a lab build and record the status word |
| A32 | MPOT unit of the GP flavour | open: the SE052 data sheet (Table 12, p. 18) selects "GP 0.39 flavour", where MPOT is in ms; GPC_SPE_172 v1.0 (Table 4-9, p. 38) counts 100 us | MPOT read in v1.0 units, polling never faster than `Config::poll_interval_us` (1 ms or more) | `Config::poll_interval_us` | `Open()` an SE052 in GP; log the CIP MPOT byte and whether a poll 1 ms after a write is NACKed |
| A33 | Upper bound of BWT and of WTX waits | open: the documents give no maximum BWT and allow a WTX multiplier up to 255 (UM11225 Table 9, p. 8), so a wrong ATR or WTX could stretch a command to hours | an ATR or CIP BWT above 10 s is refused (`FrameError`); one WTX grants at most 30 s and the WTX of one command at most 180 s together, then the command ends with `Timeout` | `Config::wtx_limit` | log the BWT of each variant's ATR and the longest WTX run of a large `DeleteSecureObject` and of the SE052F self-test |
| A34 | Policy bytes read back by `ReadObjectAttributes` | open: AN12543 4.7.4 does not say the policy comes back byte for byte as written | `Find()` and `CreateCounter()` adopt an object only when its class and origin match, its policy equals byte for byte the one the facade builds, and `ReadType` says it is persistent; anything else is `PolicyDenied` (fails closed: a chip that reformats the policy would make adoption fail, never pass) | none | provision a facade key, then `ReadObjectAttributes` it on a dev kit and compare the policy with the one sent |
| A35 | A store cut short by a power loss | partly: AN12543 does not say whether one WriteBinary is atomic or what a new binary file holds before it is written | `Store` creates the object one byte longer than the data and writes a completion marker (0xA5) after every data chunk, by its own command; `Load` and `Attest` refuse an object without it. A new file that the chip does not zero-fill could hold 0xA5 there by chance (1 in 256). An object not written by `Store` is `FrameError`, or, if its last byte is 0xA5, reads back one byte short | none | cut the power during a 700-byte `Store` on a dev kit 20 times at random points; `Load` must return `FrameError` or the whole value every time |
| A36 | Attested read of an object above the 500-byte chunk limit | open: AN13030 (pp. 248-252) limits one attested binary read to 500 bytes, and does not say what the chip answers to a read without offset and length of a larger object | `Attest` reads the object whole into a 256-byte buffer (`kMaxAttestedBytes`); the model returns the whole value, which the host refuses as `BufferTooSmall`. A chip that answers an error status instead returns that status's error (a device error, not `BufferTooSmall`); either way no value is returned | model only (`kMaxBinary`) | `Store` 255, 300 and 600 bytes on a dev kit, `Attest` each, and record the error and the status word of each (`Device::GetLastStatusWord()`) |
| A37 | NAD of a block from the chip in the NXP flavour | settled: UM11225 Table 4 (p. 5) gives 0xA5 from the SE to the host; Figure 7 (p. 16) prints "NAD (0x5A)" in the SE-to-host frame, a copy of Figure 4 | the link expects 0xA5 from the chip (`kUm11225Frame`), as Table 4 says | none | log the NAD byte of the first reply of an SE050 in the NXP flavour |

## Corrections folded into the contract

- A quiet chip answers within about 20 s, and up to 40 WTX requests are answered at session open. The old reference of
  500 WTX is gone; `Config::wtx_limit` and `kSessionOpenWtxAllowance` carry the numbers.
- `GetFreeMemory` returns 4 bytes on the SE052F only and 2 bytes elsewhere, SE051 7.x included.
- SIGMA-I is not an SE05x feature. It is not in the command set.
- Ed25519 and Montgomery values on the wire are the byte reverse of RFC 8032 and RFC 7748 (AN12543 pp. 168-170; an
  earlier note said little endian, which AN12543 corrects). A Montgomery ECDH with an inline public key writes NVM on
  every call.
- On the SE050 and SE051, RST_N is the ISO 7816 reset and has no effect when only I2C is enabled (SE050 section 4.2,
  p. 9): there the reset port implements `Reset()` and `PowerCycle()` with ENA (VOUT wired to VCC) or a supply
  switch; the link only calls the port.

## Still open

UM11225 was obtained (addendum 3). Both T=1 flavours are specified except the CRC byte order of the NXP flavour:
the link accepts either order on the first valid frame and keeps it (A10). The code 0xC6 is a chip reset in the NXP
flavour and RELEASE in the GP one. The GP flavour is specified by GPC_SPE_172 v1.0, but the SE052 data sheet selects
a "GP 0.39" flavour, and the NAD and MPOT unit the chips use in it are open (A17, A32). The ECKey KDF is printed in
AN12543 pp. 22-23 and 72-73 but has no vector: it is built behind a feature flag. The order of the attestation
timestamp is settled (AN12543 3.9, p. 42: 4 persistent bytes, then 8 transient bytes, growing with every session
open); the driver accepts only a timestamp later than the last one it accepted. The 6.x policy bit values, the SE052
configuration sheet and the SOT917 code stay open. The SEMS Lite update agent is outside v1.

## Oracle vectors from the vendor middleware

`tests/vectors/nxp_oracle_vectors.hpp` holds vectors recorded by `tools/oracle/build_oracle.sh` against the pinned
middleware checkout `7102413e`, in a sandbox without network access (provenance and the BSD 3-Clause notice in `tests/vectors/THIRD_PARTY.md`).
It records 122 commands, 62 on applet 7.2 and 60 on applet 3.x. `tests/test_apdu_oracle_vectors.cpp` builds each
command with the same inputs and compares header and TLV body byte for byte; every remaining difference is listed
there with its class and evidence (middleware quirks such as TAG_11 version 0 and TAG_2 `FF`; policy-less creates,
which the library refuses, S-03; the `WriteUserID` instruction byte of the harness input; `DeleteAll`, below), and
removing any one of them makes the test fail. The `TLSPerformPRF` P2 is no longer a difference: `TlsPrfArgs::role`
gives the server role (AN12543 4.17.3), which the harness used. Framing is not compared: the middleware frames
short case 4 without Le and extended commands as `00 LcH LcL ... 00 00`. The structural check of
`tests/vectors/nxp_layouts.hpp` (read from the source text by `tools/oracle/extract_layouts.py`) remains. The
oracle covers 122 of the commands; the others rest on the APDU tables of AN12543 and AN12413 only. The ECKey key
derivation, receipt and first MAC chaining value still rest on the independent chip model only (A15): that session
stays behind its build flag.

## DeleteAll: Lc 0x00 or case 1

AN12543 Table 339 prints the `DeleteAll` command with `Lc 0x00`, so the codec sends `80 04 00 2A 00`; the middleware
sends case 1 (`80 04 00 2A`, four bytes). Read as ISO/IEC 7816-4 the trailing byte is an Le, which the chip ignores
for a command without a response, so both should be accepted. **Not verified on hardware**: a trace of `DeleteAll`
on a real chip (bench step: run it in a RESERVED_ID_FACTORY_RESET session on a dev kit and record the C-APDU and
the status word) decides it.

## Attested read under secure messaging

A format 2 attestation signs the hash of "the complete APDU except the Le bytes" (AN12543 3.2.7.2, p. 19). Inside
platform SCP03 or an AESKey session the applet sees the command after the secure channel unwrapped it, and the
documents do not say which length form it then hashes. The driver hashes the unwrapped command with the shortest Lc
form (one byte for up to 255 bytes, no Le), which is how the chip model rebuilds a command after unwrapping; outside
secure messaging it hashes the command exactly as sent (`Device::ReadVerified`, `detail::ShortestLcForm`). A wrong
choice fails closed: every attestation is refused with `AttestationInvalid`, nothing false is accepted. **Not
verified on hardware**: bench step: run `hrot::Device::Attest()` under platform SCP03 on a dev kit; if it fails while
the same read without secure messaging passes, the chip hashes the extended form.
