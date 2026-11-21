# Porting

Run the driver on a new MCU by writing small port classes.

<!-- generated: datasheet-refs -->
??? abstract "Datasheet sections this page relies on"

    - RST_N has no effect when only I2C is enabled: NXP SE050-DATASHEET Rev. 3.8, 4.2 ISO7816 and ISO14443 interface, p. 9
    - ENA low time and glitches: NXP SE050-DATASHEET Rev. 3.8, Table 14 AC characteristics, p. 18
    - SE052 RST_N reset pulse width: NXP SE052 Rev. 1.5, Table 14 AC characteristics, p. 20
    - I2C.1 lock-up after a second command, I2C.2 no empty frame: NXP SE050_Erratasheet Rev. 1.0, 3.1, 3.2, p. 7
    - I2C.3 lines high around a soft reset, I2C.4 SCL before SDA: NXP SE050_Erratasheet Rev. 1.0, 3.3, 3.4, p. 8
    - One block per I2C write, no repeated start: NXP UM11225 Rev. 1.2, 3.1.1.1 SE I2C Receive State, Figure 4, p. 13
    - Polling with one-byte reads after MPOT: NXP UM11225 Rev. 1.2, 3.1.1.2 SE I2C Processing State, p. 14
    - Timeouts and waiting time extensions: NXP AN13030 Rev. 2.7, 2.10, p. 9

    All of them, with the driver API for each: [Datasheet map](datasheet.md).
<!-- /generated -->
The driver never calls your SDK. It calls hooks on classes you derive from the CRTP bases in
[`inc/se05x_ports.hpp`](../inc/se05x_ports.hpp); the `Ports<...>` bundle is constrained by concepts, so calls resolve
at compile time (no virtual functions, nothing to allocate) and a missing or misdeclared hook is a compile error.

## What you implement

| Port | Required | Hooks |
| --- | --- | --- |
| `BusInterface<D>` | yes | `bool EnsureInitialized()`, `BusStatus Write(addr7, ByteSpan)`, `BusRead Read(addr7, MutableByteSpan)` |
| `ClockInterface<D>` | yes | `uint64_t NowUs()`, `void DelayUs(uint32_t)` |
| `CryptoInterface<D>` | yes | key handles, AES, CMAC, P-256, hash, random; `ReferenceCrypto` is for tests and bring-up only. Its only verifier is P-256 (`EcdsaP256Verify`), which is all the driver and the facade need; a P-384 certificate chain needs a verifier of yours ([PKI](pki.md)) |
| `ResetInterface<D>` | no | `Reset()`, `PowerCycle()`, `SetEnable(bool)`; without it the power-cycle rung is gone. `Reset()` must really reset the chip: on the SE050 and SE051 the ENA power cycle (VOUT wired to VCC), because RST_N does nothing with I2C alone; on the SE052 RST_N, which has no ENA |
| `LogInterface<D>` | no | `Log(const LogRecord&)`; records never carry secrets |

The bus reads and writes are separate transactions (`kRepeatedStart` is false), at up to `kMaxClockHz`. A Nack means
the chip is not ready; the link polls.

```cpp
--8<-- "tests/docs/my_port.hpp:port"
```

## What the bus port must guarantee

- One block is one write: start, address, bytes, stop; never a repeated start (UM11225 p. 13).
- Never a zero-length write or an address-only probe on the chip's address (errata I2C.2, p. 7).
- A NAK of the address comes back as `Nack` (the chip is busy; the link polls after MPOT, UM11225 p. 14); a line held
  low comes back as `BusStuck`, a bounded wait as `Timeout`. Never block forever on clock stretching.
- SDA and SCL stay high while idle and around resets (errata I2C.3, p. 8); SCL changes before SDA with the data sheet
  margin (errata I2C.4, p. 8).
- One command in flight per device: the driver is not thread-safe (errata I2C.1).
- If your bus driver reports a NACK, a lost arbitration and a held line with one error code (ESP-IDF does), look at
  the lines after a failed transaction: SDA or SCL still low is `BusStuck` (the ESP-IDF example does this).

## What the clock port must guarantee

- `NowUs()` is monotonic and counts microseconds in 64 bits from boot, and never wraps in the life of the device.
  Every deadline in the link is an absolute 64-bit time compared with `NowUs()`; a clock that wraps would end or
  stretch a wait at the wrap. A 32-bit microsecond counter wraps every 71.6 minutes: widen it in the port (count the
  wraps) rather than pass it through.
- `DelayUs()` waits at least the time asked; the driver bounds every wait, so a longer delay only slows it down.

## The reset port

`PowerCycle()` is the last rung of the recovery ladder and the only cure for a bus held by errata I2C.1. On the SE050
and SE051 implement it with ENA: low for well above tENalt, which SE050 Table 14 (p. 18) gives as 2 us typical with no
minimum (the ESP-IDF example holds 10 us), then high, with VOUT wired to VCC so
the core really loses power. On the SE052 use a supply switch if the board has one, and `Reset()` with RST_N (at least
40 us low, SE052 Table 14, p. 20).

A step-by-step ESP-IDF port: [Porting to ESP-IDF](porting-esp-idf.md). An ESP-IDF set of ports is in [`examples/esp32/main/esp32_se05x_port.hpp`](../examples/esp32/main/esp32_se05x_port.hpp).
Hardware crypto: implement `CryptoInterface` over your engine so keys never leave it.
