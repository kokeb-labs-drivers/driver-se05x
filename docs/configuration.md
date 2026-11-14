# Configuration

Every field of `se05x::Config`, how a configuration is checked, and the optional Kconfig layer.

<!-- generated: datasheet-refs -->
??? abstract "Datasheet sections this page relies on"

    From NXP AN13030 Rev. 2.7:

    - Timeouts and waiting time extensions: 2.10, p. 9

    All of them, with the driver API for each: [Datasheet map](datasheet.md).
<!-- /generated -->
## Fields

`Config{}` holds safe defaults, and `Validate()` rejects an out-of-range value before anything is sent.

| Field | Default | Meaning |
| --- | --- | --- |
| `i2c_address` | `kI2cAddress` (0x48) | 7-bit address |
| `boot_wait_ms` | 20 | Wait before the first frame (ambiguity A8); 0 is valid |
| `atr_poll_budget_ms` | 1000 | How long to poll for the ATR or CIP; must be above 0 |
| `frame_retries` | `kDefaultFrameRetries` (3) | T=1 retries per frame |
| `wtx_limit` | `kDefaultWtxLimit` (64) | Waiting time extensions per command; `kSessionOpenWtxAllowance` (40) applies at session open |
| `flavour` | `Auto` | T=1 framing flavour: the NXP form first, then GP (ambiguities A9, A17) |
| `timeouts` | class defaults | Per command class (ambiguity A11); a WTX extends any class to at least 4 s (A19) |
| `poll_interval_us` | 1000 | Polling period of a chip that NAKs until ready; 1 ms to 1 s |
| `scp_policy` | `Auto` | Platform SCP03: `Auto` opens it when the chip requires it, `Require` always, `Off` never. `Auto` decides from the chip's answer to ReadState, which is not authenticated, so a host on the bus can make it skip platform SCP03; the facade then refuses keys, counters and secrets (it fails closed). Set `Require` for a root of trust |
| `auth_attempt_limit` | 3 | Host-side authentication attempts per session (S-14) |
| `probe_capabilities` | `true` | Probe digest support and the curve list at `Open()` (A4, A5) |
| `verify_eckey_receipt` | `true` | Check the ECKey session receipt (A15); it cannot be turned off by a call |
| `allow_lab_override` | `false` | Lab only: let `TransmitRaw()` bypass the capability gate |
| `held_commands` | empty | Commands refused as `Unsupported` before sending (A6) |

The SCL clock is the bus port's, not a `Config` field: keep it at or below `kMaxClockHz` (a port can check its own
setting with `static_assert`, as the ESP-IDF example does).

## Kconfig

Under ESP-IDF, `idf.py menuconfig` has a "SE05X secure element" menu: `CONFIG_SE05X_BOOT_WAIT_MS`,
`ATR_POLL_BUDGET_MS`, `FRAME_RETRIES`, `SCP_REQUIRE` or `SCP_OFF`, `PROBE_DISABLE`, and
`SE05X_ENABLE_IRREVERSIBLE` (default off). `se05x::KconfigDefaults()` returns the result and equals `Config{}` when
nothing is changed. Outside ESP-IDF the CMake option `SE05X_ENABLE_IRREVERSIBLE` sets the same flag.

## Build flags

| Macro | Default | Effect | How to set it |
| --- | --- | --- | --- |
| `SE05X_ENABLE_IRREVERSIBLE` | 0 | Compiles the irreversible operations | CMake option of the same name, Kconfig under ESP-IDF, or `-DSE05X_ENABLE_IRREVERSIBLE=1` |
| `SE05X_ENABLE_ECKEY_SESSION` | 0 | Runs the ECKey session handshake (A15); without it `BeginEcKeySession()` returns `Unsupported` | a compile definition only: `target_compile_definitions(app PRIVATE SE05X_ENABLE_ECKEY_SESSION=1)` or `-DSE05X_ENABLE_ECKEY_SESSION=1` on every unit that includes the driver |
