# SE05x host example

The driver on your PC, with no hardware: [`main.cpp`](main.cpp) runs the root-of-trust jobs through the facade
against the simulated chip of the host tests ([`tests/model/`](../../tests/model/chip_bench.hpp): T=1, SCP03 and the
IoT applet written from the documents, with made-up keys), then opens a bus with nothing on it
([`tests/null_ports.hpp`](../../tests/null_ports.hpp)) and prints the error by name.

## Build and run

From the repository root, with CMake 3.16+ and a C++20 compiler:

```bash
cmake -S examples/host -B build-example
cmake --build build-example
./build-example/se05x_host_example
```

## Expected output

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

The exit code is 0 when every step gave the result its line expects. The host tests build this folder too and run
the example (CTest `se05x_host_example`).

## Files

| File | What it is |
| --- | --- |
| [`main.cpp`](main.cpp) | The example |
| [`CMakeLists.txt`](CMakeLists.txt) | A standalone project that links `se05x::se05x` |
