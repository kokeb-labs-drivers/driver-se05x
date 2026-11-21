# Porting to ESP-IDF

The ESP-IDF ports in [`examples/esp32/main/esp32_se05x_port.hpp`](../examples/esp32/main/esp32_se05x_port.hpp) use the
`i2c_master` driver for the bus, `esp_timer` for the clock and a GPIO for the reset port. This page says what each
port must do for the SE05x and why. For another platform read [Porting](porting.md) first.

<!-- generated: datasheet-refs -->
??? abstract "Datasheet sections this page relies on"

    - I2C target address 0x48: NXP SE050-DATASHEET Rev. 3.8, 4.1 I2C interfaces, Figure 3, p. 8
    - I2C clock and clock stretching per variant: NXP SE050-DATASHEET Rev. 3.8, 4.1.1 Supported I2C frequencies, p. 9
    - I2C.1 lock-up after a second command, I2C.2 no empty frame: NXP SE050_Erratasheet Rev. 1.0, 3.1, 3.2, p. 7
    - I2C.3 lines high around a soft reset, I2C.4 SCL before SDA: NXP SE050_Erratasheet Rev. 1.0, 3.3, 3.4, p. 8
    - One block per I2C write, no repeated start: NXP UM11225 Rev. 1.2, 3.1.1.1 SE I2C Receive State, Figure 4, p. 13
    - Polling with one-byte reads after MPOT: NXP UM11225 Rev. 1.2, 3.1.1.2 SE I2C Processing State, p. 14
    - Development kit jumpers: ENA, reset, pull-ups: NXP AN13539 Rev. 1.2, Table 9 and the jumper tables, p. 15

    All of them, with the driver API for each: [Datasheet map](datasheet.md).
<!-- /generated -->

## Bus

| Setting | Value | Why |
| --- | --- | --- |
| Address | 7-bit `0x48` | SE050 section 4.1, p. 8 |
| Clock | 400 kHz | Holds for every configuration. Above 600 kHz the A to D and F configurations stretch the clock (section 4.1.1, p. 9) |
| Clock stretching | allowed, with a timeout | The chip may stretch; a stretch that never ends is errata I2C.1 and must come back as `BusStuck`, not hang |
| Pull-ups | external, on SDA and SCL | Do not rely on the MCU's internal pull-ups; the vendor kit fits 3.3 kΩ (AN13539 p. 15) |

Rules the bus port keeps:

- **One write per block.** `Write()` is one `i2c_master_transmit()`: start, address, bytes, stop. No
  `i2c_master_transmit_receive()`: the T=1 link never uses a repeated start (UM11225 p. 13).
- **Never empty.** No zero-length write and no `i2c_master_probe()` on the chip's address: an address-only frame can
  hold the bus (errata I2C.2, p. 7). The driver's `Write()` never passes an empty span.
- **Report a NAK as `Nack`.** While the chip works it NAKs its address; the link polls after MPOT (UM11225 p. 14).
  Map `ESP_ERR_TIMEOUT` to `Timeout` and a stuck line to `BusStuck`, so the ladder can act.
- **Keep the lines high.** After a soft reset both lines must be high for at least 1 ms (errata I2C.3, p. 8). Do not
  drive SDA or SCL low from software, and keep the bus free of other devices that hold it.
- **SCL before SDA.** The SE050 needs SCL to change before SDA with a margin (errata I2C.4, p. 8). Check that your
  controller's data hold time gives that margin; a bit-banged port must add a delay.

## Clock

`NowUs()` is `esp_timer_get_time()`, which is monotonic; `DelayUs()` may yield to other tasks. Waits are short
(MPOT is 1 ms), so a task delay with a 1 ms tick is enough.

## Reset port

| Chip | Pin | `SetEnable(false)` | `PowerCycle()` | `Reset()` |
| --- | --- | --- | --- | --- |
| SE050, SE051 | ENA, VOUT wired to VCC (`Esp32Se05xPins::enable`, GPIO11 by default) | ENA low: deep power-down | ENA low 10 us (tENalt is 2 us typical, no minimum printed), then high, then the boot wait | the ENA power cycle: RST_N has no effect with I2C alone |
| SE052 | RST_N (`Esp32Se05xPins::reset_n`; `enable` -1) | not available (no ENA) | supply switch, if the board has one (the example port returns false) | RST_N low at least 40 us |

Sources: SE050 sections 4.2 and 5.2 and Table 14 (pp. 9, 10, 18); SE052 Table 2 and Table 14 (pp. 4, 20). A board
without the reset port loses the power-cycle rung: a bus held by errata I2C.1 then stays held until the supply is
switched. On the vendor development kit ENA and the reset line reach the Arduino header through jumpers
(AN13539 p. 15).

## Crypto port

Bind the crypto port to mbedTLS or PSA on the target, never to the driver's `ReferenceCrypto` in a product: the
optional [`examples/psa/se05x_psa_crypto.hpp`](../examples/psa/se05x_psa_crypto.hpp) does it over PSA Crypto, which
the ESP-IDF mbedtls component provides (`se05x_hrot_example` uses it; add `mbedtls` to the component's `REQUIRES`).
Keep the platform SCP03 keys in NVS encryption or a key store and give the driver only `KeyRef` handles. Never
compile keys into the image.

## Concurrency

One command in flight: guard every call on one device with one mutex, or use it from one task. Two chips on two
buses are independent.

Bench status: **not verified on hardware**. The bench steps: an OM-SE050ARD on an ESP32 at 400 kHz, `Open()`,
`GetRandom()`, a forced I2C.1 lock-up (two writes without a read) recovered by the ENA power cycle.
