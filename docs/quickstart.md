# Quickstart

Run the driver on your PC first, with no hardware; then open the chip from your MCU: wire it, write two small ports,
call `Open()`.

<!-- generated: datasheet-refs -->
??? abstract "Datasheet sections this page relies on"

    From NXP SE050-DATASHEET Rev. 3.8:

    - I2C target address 0x48: 4.1 I2C interfaces, Figure 3, p. 8
    - Pin table of the HX2QFN20 package (SE050): Table 5 Pin description, p. 11

    All of them, with the driver API for each: [Datasheet map](datasheet.md).
<!-- /generated -->
## Try it on your PC

[`examples/host/`](../examples/host/README.md) runs the facade jobs against the simulated chip of the tests, then
shows what a bus with nothing on it gives. From the repository
root, with CMake and a C++20 compiler:

```bash
cmake -S examples/host -B build-example
cmake --build build-example
./build-example/se05x_host_example
```

```text
SE05X driver 0.1.0 on the host, simulated chip
Open with platform SCP03                     Ok
Identify                                     Ok
  applet 7.2.0, OEF id A921
Provision a signing key in slot 0            Ok
Provision slot 0 again                       ObjectExists
Attest the key (verified)                    Ok
Sign a digest                                Ok
Verify the signature on the chip             Ok
Seal a configuration                         Ok
Create the firmware floor at 3               Ok
Boot image version 4                         Ok
Boot image version 2 (a rollback)            PolicyDenied
APDUs sent: 23
Close                                        Ok
Open with nothing on the bus                 Nack
```

CI builds and runs this example on every pull request.

## 1. Wire it

| MCU | SE050, SE051 (HX2QFN20) | SE052 (HVQFN20) | Notes |
| --- | --- | --- | --- |
| I2C SDA | SDA, pin 9 | SDA, pin 11 | Pull-up to the bus supply; the vendor kit fits 3.3 kΩ |
| I2C SCL | SCL, pin 10 | SCL, pin 10 | Pull-up to the bus supply |
| GPIO | ENA, pin 11 | RST_N, pin 14 | The reset port's power cycle (ENA) or reset (RST_N) |
| 3.3 V | VIN, pin 12 | VIN, pin 12 | 1.62 V to 3.6 V (SE052: 1.65 V) |
| | VOUT to VCC (15 to 18) | VOUT to VDD (15 to 18) | Lets deep power-down switch the core off |
| | RST_N to VSS | | ISO 7816 reset; no effect with I2C alone |
| GND | VSS, pin 19 | VSS, pin 19 | |

Both I2C lines must be high when the chip powers up, or it does not choose I2C. Per-chip wiring:
[SE050](se050.md), [SE051](se051.md), [SE052](se052.md).

The chip answers at 7-bit address 0x48. [Hardware](hardware.md) has every pin.

## 2. Write the ports

```cpp
--8<-- "tests/docs/my_port.hpp:port"
```

## 3. Open the device

```cpp
--8<-- "tests/docs/quickstart.cpp:quickstart"
```

Next: [Porting](porting.md) for the full contract, [API guide](api-guide.md) for the layers.
