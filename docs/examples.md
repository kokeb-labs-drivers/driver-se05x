# Examples

One folder per platform under `examples/`, each with its own ports, built by CI on every pull request. The driver
itself has no platform code; [Platforms](platforms.md) lists what exists.

## Host

[`examples/host/`](../examples/host/README.md) runs the root-of-trust jobs through the facade against the simulated
chip of the tests (`tests/model/`), then opens a bus with nothing on it. No hardware:

```bash
cmake -S examples/host -B build-example && cmake --build build-example && ./build-example/se05x_host_example
```

The host tests build it with warnings as errors and run it (CTest `se05x_host_example`).

## PSA crypto port

[`examples/psa/se05x_psa_crypto.hpp`](../examples/psa/se05x_psa_crypto.hpp) is an optional, header-only crypto port
over the PSA Crypto API (mbedTLS 3.x, the ESP-IDF mbedtls component): every key the driver hands over lives in PSA
as a volatile key, the driver holds handles only. It is the production replacement for `ReferenceCrypto` (S-15) and
the ESP32 facade example uses it. Nothing of mbedTLS is in this repository. With MbedTLS 3 installed, the host build
checks it against known answers and runs the whole stack with it (platform SCP03, an AESKey session, provision,
attest and sign against the chip model):

```bash
cmake -S . -B build -DSE05X_BUILD_TESTS=ON -DSE05X_BUILD_PSA_EXAMPLE=ON -DCMAKE_PREFIX_PATH=<mbedtls prefix>
cmake --build build --target se05x_psa_check && ctest --test-dir build -R se05x_psa_check
```

CI does not build it (no MbedTLS in the CI image); it was built and run on a workstation with MbedTLS 3.6.4.

## ESP32

An ESP-IDF application that opens the chip on an ESP32-C6 DevKitC-1; the wiring is in the
[example folder's README](../examples/esp32/README.md) and the ports in
[`esp32_se05x_port.hpp`](../examples/esp32/main/esp32_se05x_port.hpp). The project points
`EXTRA_COMPONENT_DIRS` at the repository root, which is the driver's ESP-IDF component.

### The apps
<!-- generated: examples -->
| App | What it shows | Source | CI |
| --- | --- | --- | --- |
| `se05x_basic_example` :material-star:{ title="featured" } | Open the SE05x from menuconfig values, log the result and close it | [`se05x_basic_example.cpp`](../examples/esp32/main/se05x_basic_example.cpp) | yes |
| `se05x_hrot_example` :material-star:{ title="featured" } | The root-of-trust facade: platform SCP03 with the PSA crypto port, identity, device key, sign, firmware floor | [`se05x_hrot_example.cpp`](../examples/esp32/main/se05x_hrot_example.cpp) | yes |

Build and flash one (from `examples/esp32`, ESP-IDF environment loaded):

```bash
./scripts/build_app.sh se05x_basic_example Release
./scripts/flash_app.sh flash_monitor se05x_basic_example Release
```

Source of this table: [`examples/esp32/app_config.yml`](../examples/esp32/app_config.yml).
<!-- /generated -->

### Set up once

```bash
git submodule update --init examples/esp32/scripts   # the ESP-IDF build scripts
cd examples/esp32
. $IDF_PATH/export.sh                                 # ESP-IDF v5.5
./scripts/build_app.sh list                           # every app and build type
```

The scripts read [`app_config.yml`](../examples/esp32/app_config.yml) (the same file this page's table comes
from) and build each app as its own firmware image.

### What to read in an example

| You want to | Read |
| --- | --- |
| See the open call and the error logged by name | `se05x_basic_example.cpp` |
| Run the facade jobs with platform SCP03 | `se05x_hrot_example.cpp` |
| Replace the reference crypto with PSA (mbedTLS) | [`examples/psa/se05x_psa_crypto.hpp`](../examples/psa/se05x_psa_crypto.hpp) |
| Write ESP-IDF ports | `esp32_se05x_port.hpp` |
| Use menuconfig values | `se05x_kconfig.hpp` and [`_config/Kconfig`](../_config/Kconfig) |
