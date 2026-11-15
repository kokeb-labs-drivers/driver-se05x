# AGENTS.md

driver-se05x: C++20 driver and hardware root-of-trust facade for the NXP EdgeLock SE050, SE051 and SE052 secure elements
over I2C (T=1, GlobalPlatform SCP03, IoT applet), with the transport, crypto and timing behind ports. It follows the
[Kokeb Labs engineering standard](https://github.com/kokeb-labs/.github/blob/main/standards/README.md) (agents:
`standards/agents.md`, drivers: `standards/driver.md`).

## Layout

- `inc/`, `src/`: the driver, header-only (each `src/*.ipp` is included by the header of the same name).
  `inc/se05x.hpp` is the umbrella header. By layer, bottom up:
  - Shared vocabulary: `se05x_types.hpp` (byte views, size limits, families, versions, `Config`),
    `se05x_status.hpp` (`Error`, `Detail`, `Result<T>`), `se05x_wire.hpp` (numbers read from the
    specifications), `se05x_detail.hpp` (compile-time helpers), `se05x_i2c_interface.hpp` (bus constants),
    `se05x_kconfig.hpp` (the only reader of Kconfig values).
  - Ports: `se05x_ports.hpp` (bus, clock, crypto with key handles, optional reset and log, and the `Ports<...>`
    set); `se05x_crypto.hpp` + `src/se05x_crypto*.ipp` (`ReferenceCrypto`, a crypto port for tests and
    bring-up); `se05x_secret.hpp` (`Zeroize`, `SecretBuffer`, constant-time compare, attempt limiter).
  - Transport: `se05x_t1_crc.hpp`, `se05x_atr.hpp`, `se05x_t1.hpp` + `src/se05x_t1.ipp` (`t1::Link`: both T=1
    flavours, bounded waits, the recovery ladder).
  - Secure channels: `se05x_scp03.hpp` + `.ipp` (platform SCP03, AESKey and UserID sessions),
    `se05x_eckey.hpp` + `.ipp` (ECKey session, behind `SE05X_ENABLE_ECKEY_SESSION`, default off).
  - APDU layer: `se05x_commands.hpp` (one `Command` per applet command), `se05x_device_types.hpp` (arguments
    and replies), `se05x_codec.hpp` (the `Codec<C>` interface), `se05x_apdu.hpp` (TLV, framing, status words),
    `se05x_apdu_consts.hpp`, `se05x_apdu_base.hpp`, `se05x_apdu_codec.hpp` and the four group headers
    `se05x_apdu_{identity,objects,crypto,misc}.hpp`.
  - Applet rules: `se05x_ids.hpp`, `se05x_policy_types.hpp`, `se05x_policy.hpp`, `se05x_objects.hpp`,
    `se05x_gate.hpp` (capability gate), `se05x_caps.hpp`, `se05x_lifecycle.hpp`, `se05x_attest.hpp` + `.ipp`.
  - Optional PKI layer (opt-in, not in the umbrella header): `se05x_pki.hpp` includes `se05x_pki_types.hpp`
    (reasons, key types, time, OIDs), `se05x_pki_der.hpp` (strict DER reader and writer), `se05x_pki_x509.hpp` +
    `src/se05x_pki_x509.ipp` (certificate parser), `se05x_pki_verify.hpp` (chain verification), `se05x_pki_csr.hpp`
    (PKCS#10 requests) and `se05x_pki_device.hpp` (chip signer, certificate storage).
  - Other applets: `se05x_gp.hpp` (card manager), `se05x_perso.hpp` (SE051 PERSO, read-only by default).
  - Command layer and facades: `se05x_device.hpp` + `src/se05x_device_*.ipp` (`Device<P>`),
    `se05x_hrot.hpp` (`hrot::Device<P>`, the root-of-trust facade), `se05x_confirm.hpp` and
    `se05x_irreversible.hpp` (`Operations<P>`, behind `SE05X_ENABLE_IRREVERSIBLE`, default off).
- `tests/`: host tests `tests/test_*.cpp` (one area each, at most about 55 cases per unit) over an independent
  chip model in `tests/model/` (`t1_target.hpp` the I2C/T=1 side, `scp_target.hpp` the card manager, SCP03 and
  sessions, `scp_crypto.hpp` the model's own crypto, `scp_loop.hpp` fault injection, `scp_script.hpp` scripted
  known answers); `tests/test_contract.cpp` pins the public surface and is built with the irreversible flag off
  and on; `tests/eckey_flag_on.cpp` builds as `se05x_eckey_on` with the ECKey flag on; `tests/null_ports.hpp`,
  `tests/vectors/`, `tests/fuzz/` (libFuzzer targets and corpora, replayed as CTests), `tests/compile_fail/`,
  `tests/docs/` (every code block on the site), `tests/install_consumer/`.
- `tools/`: `preflight.sh` (every local check), `misra_lint.py`, `check_standalone.py`, `mutants/mutants.py`
  (one-edit mutants that the tests must kill; full lists in `tools/mutants/*.txt`), `oracle/` (vector capture
  from the vendor middleware, run by the maintainer; see `docs/ambiguities.md`), `ci-container/`, `docs/`.
- `docs/`: the site pages (`docs/.nav.yml` orders them). `docs/datasheets.yml` records every document the driver
  follows (data sheets, the IoT applet APDU specification, the T=1 and SCP03 specifications; revision,
  SHA-256) and every topic it takes from them; `kokeb-docs gen` builds the README card, the Datasheet map
  (`docs/datasheet.md`) and each page's box from it (`tools/docs/generators/datasheet.py`). Pin data are in
  `docs/hardware.yml`; figures in `docs/diagrams/`.
- `examples/<platform>/`: the only platform code, one self-contained folder per platform with its own port.
  `examples/host/` (simulated chip, any PC) always exists and runs in the host tests.
  `examples/esp32/`: the ESP-IDF example; the root `CMakeLists.txt` is the ESP-IDF component (`ESP_PLATFORM`).
- `_config/`: all tool configuration (clang-format, clang-tidy, `Doxyfile`, `mkdocs.yml`, `Kconfig`, linters).
  Pass the path (`--style=file:_config/.clang-format`, `--config-file=_config/.clang-tidy`,
  `mkdocs build -f _config/mkdocs.yml`); never add copies or symlinks at the root.
- `cmake/se05x_build_settings.cmake`: the only place the version is set; `driver.yml` repeats name and version,
  and CI checks they agree.
- `.kokeb/handbook.yml`: the handbook release this repository follows, its kind and assurance level, and any
  waivers (rule, reason, approver, expiry). CI checks the handbook rules against it and reports each finding by
  rule ID (`KB-CPP-003`, ...); fix the code, or add a dated waiver only with the maintainer's approval.
- The root holds only what GitHub or a tool needs there and what a reader looks for first: `README.md`, `LICENSE`,
  `CHANGELOG.md`, `CMakeLists.txt`, `AGENTS.md`, `CLAUDE.md`, `.gitignore`, `.gitmodules`, `driver.yml`.

## Reading and citing the datasheet

- The documents in `docs/datasheets.yml` (data sheets, application notes, the T=1 and SCP03 specifications) are
  the only source of the driver's behaviour; the vendor middleware may be read for facts, never copied. The file
  names each exact document (vendor, number, revision, date, `url`, `pdf`, the `sha256` of the PDF) and lists
  every topic the driver takes from it: the document's section name, the printed page, the driver API that
  implements it and the docs pages that explain it. Link the PDF; keep the file itself out of the repository.
- Cite the section next to the code that depends on it (`// t_RST, section 8.2`), in the Doxygen comment of the
  API, and in the topic row, so code, docs and the Datasheet map agree. Run `kokeb-docs gen` after editing
  `docs/datasheets.yml`.
- Waits use the datasheet maximum, pulses its minimum; `Config{}` holds the reset values; `Validate()` the
  documented ranges.
- Behaviour learned on a bench is written as the driver's design, justified by the datasheet section that
  explains it. Where the datasheet is silent, write the design decision and its reasoning, and give the bench
  step that confirms it (**not verified on hardware** until someone runs it). The repository describes this
  chip only: no other boards, products, projects or drivers, and no dated history (`tools/check_standalone.py`
  checks this).

## Architecture and layer rules

Each layer talks only to the one below it: `Device<P>` sends commands through a `Codec<C>` and an
`ApduTransport` (a `t1::Link`, or a secure channel stacked on it); the link reaches the chip only through the
ports in `Ports<Bus, Clock, Crypto[, Reset][, Log]>`. `docs/architecture.md` draws the layers.

- A driver is MCU-agnostic and platform-free: no SDK, no RTOS, no lock, no heap, exceptions, RTTI, `std::function`,
  `std::string`, `printf` or static mutable state. It reaches the bus only through the port hooks.
- Everything is in `namespace se05x` (sub-namespaces `t1`, `scp03`, `eckey`, `session`, `gp`, `perso`,
  `attest`, `hrot`, `irreversible`, `apdu`, `codecs`, `gate`, `wire`, `refcrypto`, `pki`); internals in `detail`.
  The command layer is `se05x::Device<P>`, the facade `se05x::hrot::Device<P>`.
- Each port base declares no hook; the driver is constrained by the `BusPort`, `ClockPort`, `CryptoPort`,
  `ResetPort` and `LogPort` concepts, which check each hook's exact signature and `noexcept`. A member that needs
  an optional port is constrained on `Ports::kHasReset` or `kHasLog`, so it does not compile without it.
- Keys never leave the crypto port: the library holds `KeyRef` handles, wipes every secret it touched
  (`Zeroize`) and compares secrets in constant time (`ct::Equal`).
- Irreversible operations (lifecycle locks, `DeleteAll`, platform key replacement, ...) exist only with
  `SE05X_ENABLE_IRREVERSIBLE=1` and need a `Plan` and a typed `Confirmation`; nothing in the facade reaches them.
- Code follows the handbook's C++20 profile (KB-CPP20): ISO C++20 with no extensions, nothing from C++23, spans
  for buffers, masked shifts, `uint32_t` bit work, bounded loops, `[[nodiscard]]` error types.
- `Error` keeps the base set at values 0 to 9; chip-specific values start at 16 and each is returned somewhere.
- Every fallible call returns `Result<T>`; every port failure propagates. Constructors store the configuration
  with no I/O; `Open()` is the start-up call, and every I/O call fails with `NotInitialized` (or `WrongState`)
  before it has succeeded.
- A call sends only the traffic the specification needs; every wait is bounded by the configuration and every
  loop by a size limit in `se05x_types.hpp`.
- Public and protected methods PascalCase, private methods camelBack, members `snake_case_`, constants
  `kPascalCase`, units as suffixes. 100 columns (`_config/.clang-format`).
- Kconfig values are read only in `inc/se05x_kconfig.hpp`.

## Standards

- **Handbook rules** (`kokeb-labs/handbook`, rule IDs such as `KB-CPP-003`): CI checks them against
  `.kokeb/handbook.yml` and reports each finding by rule ID. Fix the code; a waiver (rule, reason, approver,
  expiry) needs the maintainer's approval.
- **C++20 profile** (KB-CPP20-001 to 058): the `cpp20-profile` skill lists which features to use, use with
  rules, or leave out, and runs the automated checks first.
- **MISRA C++:2023 matrix**: the CI job `MISRA` (`.github/workflows/ci-misra.yml`) analyses every translation
  unit; the `misra-review` skill reviews against the handbook's compliance matrix, lists the patterns the code
  follows (`default: break;` in every enumeration switch, `else` after `else if`, typed constant arguments with
  `static_cast<uint8_t>(0xFFU)`, ...) and cites guideline numbers only.
- **Hardware lessons** (reply validity, stuck and floating lines, resynchronisation, retries, ready waits, bus
  requirements, pin idle levels): the `hardware-lessons-review` skill checks each rule has a code path and a
  model test.

## Build, test and verify

```bash
cmake -S . -B build -DSE05X_BUILD_TESTS=ON
cmake --build build --parallel && ctest --test-dir build --output-on-failure
```

The tests build as ISO C++20 (`CMAKE_CXX_EXTENSIONS OFF`, `-pedantic-errors`) with `-fno-exceptions -fno-rtti
-Werror`, and the target `se05x_header_checks` compiles each public header alone. CI runs GCC and Clang; run
the compilers you have. The host example runs as the CTest `se05x_host_example`. ESP32 builds run in CI
(`esp32-examples-build-ci.yml`); the host build covers a change locally.

## Docs checks

```bash
python3 -m venv .venv && .venv/bin/pip install \
  "git+https://github.com/kokeb-labs/ci-tools@v1#subdirectory=packages/kokeb-mkdocs-theme"
.venv/bin/kokeb-docs figures && .venv/bin/kokeb-docs gen    # after changing headers or snippets
.venv/bin/kokeb-docs check && .venv/bin/mkdocs build -f _config/mkdocs.yml --strict -d /tmp/site
```

Code shown on the site lives in `tests/docs/` between `// --8<-- [start:x]` / `[end:x]` markers. Doxygen runs as
the CTest `se05x_doxygen` when `doxygen` is installed; every public symbol in `inc/` is documented.

The `verify` skill (`.claude/skills/verify/SKILL.md`) runs every check CI runs, in order: GCC and Clang host
tests, the strict-dialect header checks, the handbook source checks, `tools/check_standalone.py`, clang-format
20, clang-tidy 20, cppcheck, lizard, markdownlint and the docs build. `tools/preflight.sh` runs all of them in one
command; push only when it ends with `0 failure(s)`, and push the fixes together.

## Branches, commits and pull requests

- Branch from `main` as `feat/`, `fix/`, `docs/`, `ci/` or `chore/<topic>`; one logical change per branch.
- Commit with a sign-off (`git commit -s`) and an imperative subject.
- Open a pull request with the template filled in, including **Bench status**. When every check is green,
  including `CI gate / gate`, the change is merged with a squash merge; the PR title becomes the commit subject
  on `main`. `main` changes only through merged pull requests and keeps its history (no force-push).
- A red check is read before it is re-run. Re-run only an infrastructure failure (a failed install, upload or
  job set-up, a job that never got a runner, a full artifact quota, an API 502), at most twice; a re-run replays the
  `kokeb-labs/ci-tools` version the run started with, so a fix released since needs a new push. The `release`
  skill, section 5, has the list.

## Definition of done

A change is done when it is merged: one change; the standards followed or each deviation named; every check
passes locally (the `verify` skill); host tests for new behaviour including failure paths; docs, Doxygen and
`docs/datasheets.yml` updated with the datasheet sections; `CHANGELOG.md` under `## [Unreleased]`; CI green
including `CI gate / gate` (the handbook check, the Cortex-M build and the coverage, complexity and sanitizer
gates); anything hardware-dependent marked **not verified on hardware** with bench steps; squash-merged.

## Safety rules

- Every commit is signed off (DCO).
- No attribution lines in commits, pull requests or files: no `Co-Authored-By:` trailers, no "Generated with"
  footers, no tool banners.
- No secrets, credentials or vendor PDFs in the repository.
- No force-push to `main` and no history rewrites on it.
- Repository settings (rulesets, merge options, Pages) are the maintainers'; `docs/repo-setup.md` lists them.

## Skills

In `.claude/skills/`:

- `verify`: every check CI runs, before each push.
- `datasheet-conformance`: register maps, timing, reset values and errors from the datasheet, test first.
- `add-driver-feature`, `add-port`: a new driver capability; a new platform under `examples/`.
- `cpp20-profile`, `misra-review`, `hardware-lessons-review`: the reviews of the standards above.
- `release`, `bump-pin`: a version release; a submodule or workflow pin update.
- `new-driver-from-template`: turning a repository made from the template into a real driver.
- `first-push`: the gate before a new driver's first push: container rehearsal, independent review, evidence.

`.claude/agents/safety-reviewer.md` runs the review skills with `datasheet-conformance` and reports findings by
severity for the author to act on.
