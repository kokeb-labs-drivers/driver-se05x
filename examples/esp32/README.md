# SE05x on ESP32

Two ESP-IDF applications for an SE050, SE051 or SE052 on an ESP32-C6 DevKitC-1: `se05x_basic_example` opens the chip
and logs what it is; `se05x_hrot_example` runs the root-of-trust facade (platform SCP03 with the PSA crypto port of
[`examples/psa/`](../psa/se05x_psa_crypto.hpp), the identity, the device key, a signature and the firmware floor).
Both are built with ESP-IDF v5.5 for esp32c6. **Not verified on hardware.**

## Wiring

| ESP32-C6 | SE05x | Notes |
| --- | --- | --- |
| GPIO6 | SDA | Pull-up to the supply; 4.7 kΩ |
| GPIO7 | SCL | Pull-up to the supply; 4.7 kΩ |
| GPIO11 | ENA (SE050, SE051) | The power-cycle and reset line, with VOUT wired to VCC |
| 3V3 | VIN | 1.62 V to 3.6 V; 100 nF to GND at the pin |
| GND | VSS, and RST_N on SE050 and SE051 | RST_N has no effect with I2C only (SE050 data sheet 4.2, p. 9) |

The chip answers at 7-bit address 0x48. On an SE052 there is no ENA: wire RST_N to a GPIO, set
`Esp32Se05xPins::reset_n` to it and `enable` to -1 (RST_N low for at least 40 us, SE052 data sheet Table 14,
p. 20).

## Platform SCP03 keys

`se05x_hrot_example` opens platform SCP03 when `LoadPlatformKeys()` gives it the keys. Fill that function from NVS
encryption or another key store; never compile key bytes into the image, and never ship a vendor default key set.
Without keys the example opens without secure messaging, and the facade refuses every key operation with
`PolicyDenied`, sending nothing.

## Build and flash

```bash
git submodule update --init scripts      # the ESP-IDF build scripts
. $IDF_PATH/export.sh                     # ESP-IDF v5.5
./scripts/build_app.sh list
./scripts/build_app.sh se05x_basic_example Debug
./scripts/flash_app.sh flash_monitor se05x_basic_example Debug
```

`idf.py menuconfig` shows "SE05X secure element" under Component config: the boot wait, the ATR poll budget, the
frame retries and the secure-messaging choice that `se05x::KconfigDefaults()` returns.

## Files

| File | What it is |
| --- | --- |
| [`main/se05x_basic_example.cpp`](main/se05x_basic_example.cpp) | Open, log, close |
| [`main/se05x_hrot_example.cpp`](main/se05x_hrot_example.cpp) | The facade jobs with the PSA crypto port |
| [`main/esp32_se05x_port.hpp`](main/esp32_se05x_port.hpp) | The ESP-IDF ports: bus, clock, reset |
| [`CMakeLists.txt`](CMakeLists.txt) | The ESP-IDF project; `EXTRA_COMPONENT_DIRS` points at the repository root, which is the component |
| [`app_config.yml`](app_config.yml) | The app matrix for the scripts, CI and the docs |
