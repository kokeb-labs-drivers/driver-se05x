# Troubleshooting

Symptoms, causes and fixes, cheapest check first. The error names are on [Errors and status words](status-words.md).

<!-- generated: datasheet-refs -->
??? abstract "Datasheet sections this page relies on"

    - Start-up: the interface is chosen by the line levels at boot: NXP SE050-DATASHEET Rev. 3.8, 3.4 Startup behavior, p. 8
    - RST_N has no effect when only I2C is enabled: NXP SE050-DATASHEET Rev. 3.8, 4.2 ISO7816 and ISO14443 interface, p. 9
    - Wake-up from power-down may need a retransmission: NXP SE050-DATASHEET Rev. 3.8, Table 14 notes 4 and 5, p. 19
    - SE052 I2C parameters, flavour and address in the configuration: NXP SE052 Rev. 1.5, Table 12 I2C_SPI_PARAMS, I2C_SLAVE_ADDRESS, p. 18
    - Errata list and affected variants: NXP SE050_Erratasheet Rev. 1.0, Table of functional problems, p. 6
    - I2C.1 lock-up after a second command, I2C.2 no empty frame: NXP SE050_Erratasheet Rev. 1.0, 3.1, 3.2, p. 7
    - I2C.3 lines high around a soft reset, I2C.4 SCL before SDA: NXP SE050_Erratasheet Rev. 1.0, 3.3, 3.4, p. 8
    - APP.1 attestation over 1024 bytes, APP.2 CloseSession without a session: NXP SE050_Erratasheet Rev. 1.0, 3.5, 3.6, p. 9
    - JOS.1 wrong EC key length resets the chip, JOS.2 SCP03 counter: NXP SE050_Erratasheet Rev. 1.0, 3.12, 3.13, p. 11
    - Retransmissions, WTX and soft reset rules: NXP UM11225 Rev. 1.2, Error handling and retransmission, p. 11
    - GP flavour block, NAD 21/12, two-byte LEN, CRC example BDA4: GlobalPlatform GPC_SPE_172 v1.0, Table 4-1, p. 33
    - WTX host timeout at least 4 s; NXP mode is the default: NXP AN13904 Rev. 1.0, WTX and T=1 mode, p. 27
    - APDU throughput limit on the SE052F: NXP AN13904 Rev. 1.0, APDU throughput limit, p. 28
    - PERSO I2C_PARAMS bits and ATR/CIP interface bytes: NXP AN13015 Rev. 1.4, I2C_PARAMS, ATR and CIP bytes, p. 49
    - APDU throughput limit, SW 0x66A6: NXP AN13030 Rev. 2.7, 2.12 and 10.16.6, p. 10

    All of them, with the driver API for each: [Datasheet map](datasheet.md).
<!-- /generated -->

## Open returns Nack or Timeout

The chip is not answering.

1. Supply: VIN (and VCC) 1.62 V to 3.6 V on the SE050 and SE051; VIN 1.65 V to 3.6 V and VDD on the SE052.
2. ENA high on an SE050 or SE051: ENA low is deep power-down, and a chip in it NAKs.
3. Both lines high at power-up: the chip chooses I2C only when SDA and SCL are high at boot (SE050 section 3.4,
   p. 8). Pull-ups fitted, nothing else on the bus holding a line low.
4. Address 0x48, unless the chip was personalised otherwise (SE051 PERSO, see below).
5. A logic analyser should show the address byte acknowledged after the boot wait; if not, raise
   `Config::boot_wait_ms` (the SE050 boot time is not in the documents: ambiguity A8).

## Bus lock-up: BusStuck, SCL held low

**Cause.** Errata I2C.1: a second command was written before the first reply was read, and an SE050 with clock
stretching holds SCL low until it is power cycled; or errata I2C.2: an address-only write (a bus scan, a probe) and
the chip stretches after six more bytes (errata pp. 7-8). Other devices on the bus stop too.

**Fix.** Power cycle the chip: ENA low then high on the SE050 and SE051 with VOUT wired to VCC, or the supply. RST_N
does not help on an I2C-only SE050 or SE051. Then remove the cause:

- never let two tasks use one device without a lock (the driver returns `Busy`, but a second driver instance or a
  raw I2C access bypasses it);
- after a host reset, the chip may still hold an unread reply; the errata's workaround is a read before the first
  command, and `Open()` resynchronises the link before it sends one;
- remove every bus scan and `probe` call that touches 0x48.

Without a reset port the ladder cannot power cycle and ends in `TransportDead`; see the minimal circuit on
[SE050](se050.md#wiring).

## The chip resets itself about a second after a soft reset

Errata I2C.3: a line was low during an interface soft reset, so the chip could not detect its interface and reset
after about 1 s; several in a row lock it permanently until an applet select succeeds (errata p. 8). Keep both lines
high for at least 1 ms after the soft reset.

## Throughput limit: ThroughputLimited (SW 0x66A6)

The chip refuses every command until it is reset: more than one million APDUs within 34 days on the SE052F (AN13904
p. 28), possibly on the SE051. The device drops every session without sending anything, resets the chip once (the
chip-reset rung: the NXP S-block 0xC6, or the reset port in the GP flavour), selects the applet again, opens
platform SCP03 again when it was open, and the call returns `ThroughputLimited`; the command is not repeated.
Re-authenticate. If the chip still answers 0x66A6 to the select, the device stays `NeedsReopen` and does not reset
again.
Then find the loop: one APDU per second exceeds the limit in under two weeks. Cache what does not change, read
`hrot::Device::Budget()`, and never poll the chip for time or randomness ([HRoT cookbook](hrot-cookbook.md)).

## Flavour mismatch

**Symptom.** `Open()` returns `FrameError`, `Crc` or `DeviceIdMismatch`; a logic analyser shows the chip answering
with bytes that do not parse, or nothing after a PERSO write.

**Cause.** The host and the chip speak different T=1 flavours (NXP UM11225 and GlobalPlatform differ in NAD, LEN
width and control codes; [Transport](transport.md)). On the SE051 the flavour is a chip-side PERSO setting that takes
effect after the next reset (AN13015 p. 49); a mismatch leaves the chip silent to this host. On the SE052 the data
sheet's configuration names the GP flavour (p. 18) while AN13904 calls NXP mode the default.

**Fix.** Use `TransportFlavour::Auto` (the default), which tries both flavours and both CRC orders. If you fixed the
flavour in `Config`, set it to the one the chip uses. On an SE051 whose PERSO applet is still selectable, read
I2C_PARAMS with `perso::Perso`.

## No zero-length frames

A port that sends an empty write, or a test that probes the address, triggers errata I2C.2. The driver never passes
an empty span to `Write()`; check your port does not add one (some HALs probe before every transfer).

## Wake-up from power-down misses the first block

At 400 kHz or 1 MHz without clock stretching, the first block after power-down can arrive before the chip is awake;
the chip asks for it again with an R-block (SE050 Table 14 notes 4 and 5, p. 19). The link resends it; this is not an
error unless it repeats beyond `frame_retries`.

## DeviceIdMismatch

Something answers but is not an SE05x with the IoT applet: a wrong address, a flavour mismatch (above), or an SE051P
running a customer applet.

## A command returns Unsupported

The capability gate refuses it for this chip. Read the capabilities: the applet generation, the version and the
feature bits. Some commands exist only on 7.x; the SE052F in FIPS mode has no EdDSA, Montgomery curves, DES or PAKE.

## Resynced after a call

A recovery rung past a block resend ran: the command was not repeated and every session is gone. Open the session
again, then repeat the command if it is safe to.

## NotImplemented

No call of this version returns it; the value stays in the error model for a layer added later.
