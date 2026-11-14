# Testing and CI

How the driver is checked: host tests against an independent model of the chip, vectors from the specifications and
from the pinned NXP middleware (a test oracle, never a dependency), compile-fail tests, fuzzers, compiled
documentation, an install test, static analysis and measured quality gates, on every pull request.

## Host tests

The tests build the real driver with the firmware's flags, `-fno-exceptions -fno-rtti`, and warnings as errors, on GCC
and Clang.

```bash
cmake -S . -B build -DSE05X_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

| File | Covers |
| --- | --- |
| [`tests/test_contract.cpp`](../tests/test_contract.cpp) | The frozen contract: every header is included, every public type and constant is asserted; with the irreversible flag off and on |
| [`tests/test_errors.cpp`](../tests/test_errors.cpp) | The base `Error` values are 0 to 9; every chip-specific value has a name |
| [`tests/test_kconfig.cpp`](../tests/test_kconfig.cpp) | `KconfigDefaults()` with and without `CONFIG_` values |
| [`tests/test_version.cpp`](../tests/test_version.cpp) | The version getters follow the generated header |
| [`tests/compile_fail/`](../tests/compile_fail) | Code that must not compile, each for its `EXPECT:` diagnostic: a port that is not a port, an irreversible command through `Execute`, a wrong confirmation, a slot out of range |
| [`tests/fuzz/`](../tests/fuzz) | The ten fuzz targets; CTest replays their corpora |
| [`tests/docs/`](../tests/docs) | The snippets the pages show, compiled |
| [`tests/check_install.cmake`](../tests/check_install.cmake) | Installs into a scratch prefix and builds a consumer |

## The model stands alone

The chip model in [`tests/model/`](../tests/model/model_if.hpp) is written from the documents, not from the driver:
a chain `T1Target` -> `ScpTarget` -> `ChipModel` implements `ApduHandler`, with knobs for the open questions
(`crc_swapped`, `gp_flavour`, `throttle_enabled`, `throttle_after`). It includes no driver header other than the
frozen interface, so a wrong constant in the driver is caught by the model and the reverse. A behaviour found on
hardware becomes a fault in the model first, then a fix.

## Fuzz tests

Everything the driver reads comes from the chip over the bus. The fuzz targets corrupt what the chip sends and check
the promises after every
call: a failed call returns a defined `Error`, nothing is sent before `Open()`, a secret is never logged. Ten targets
run: `fuzz_apdu_response`, `fuzz_atr_cip`, `fuzz_contract_stub` (the shared byte parsers), `fuzz_device_sequence`,
`fuzz_hrot_sequence`, `fuzz_pki_der`, `fuzz_pki_x509`, `fuzz_policy_parse`, `fuzz_scp03_unwrap` and `fuzz_t1_frame`.
Each target also builds without libFuzzer as a replay and CTest runs its corpus.

## Mutation

`tools/mutants/mutants.py` applies one-edit mutants to a copy of `inc/`, `src/` and `tests/`, builds the host tests
with irreversible operations off and on, and runs them. Every mutant must be killed: by a failing test or a
`static_assert`. The unedited tree is built and run first; if it fails, the run stops, because a failing test would
otherwise count as a kill.

```bash
cmake -S . -B build -DSE05X_BUILD_TESTS=ON            # generates se05x_version.h
SE05X_GENERATED=build/se05x_generated tools/mutants/mutants.py --jobs 8
tools/mutants/mutants.py --list                        # the catalogue, active and pending
tools/mutants/mutants.py --selftest                    # every pattern of every catalogue is in its file
SE05X_GENERATED=build/se05x_generated tools/mutants/mutants.py --all   # the full lists of every area
```

The script holds a core set per area; the full lists are `tools/mutants/transport.txt`, `apdu.txt`, `channels.txt`,
`device.txt`, `hrot.txt` (the facade, the irreversible plans and the verified attested read) and `pki.txt` (the optional
PKI layer); `--catalogue FILE` runs one, `--all` every one. No entry is pending: every layer is built. Mutants build
with the library's bounds checks, so an out-of-range access traps, and a run that hangs past ten minutes counts as a
kill.

Policy:

- Every comparison, counter, constant and status-word mapping that guards a safety rule (S-01 to S-17) has a mutant:
  the CRC polynomial and order, N(S), the chaining bit, the WTX and retry caps, the single-flight and empty-write
  guards, the MAC, receipt, freshness and echoed-command compares, the SCP03 counter, the JOS.2 padding, the wipes,
  the timestamp order, the policy rules, the capability gate, the role check, the throughput rung and the budget, the
  confirmation compare and the plan check.
- A surviving mutant is a finding: it is closed by a test, never by deleting the mutant.
- An equivalent mutant (another guard covers the same case) is listed with its reason and not run.
- Mutants of a layer still being built are pending entries with their owner; the release gate (`--strict`) fails
  while any is left (none is left).
- The run is per file and part of the first-push evidence; it is not a CI job (it builds the tests once per mutant).

## MISRA C++:2023

The CI job `MISRA` analyses every translation unit against the handbook's compliance matrix at the `high` level;
`tools/misra_lint.py` checks the defect classes earlier scans found, in the preflight. A guideline the code cannot
follow gets a deviation record: the guideline number, the file and line, why, what makes it safe, the approver. The
records live in this section.

| Guideline | Where | Why | Mitigation | Approved |
| --- | --- | --- | --- | --- |
| none recorded | | | | |

## Quality gates

The `Host quality` job measures the library code, `inc/` and `src/` only (tests and examples are left out), and
fails when a value is over the limits of this repository's assurance level, `high` (set in
[`.kokeb/handbook.yml`](../.kokeb/handbook.yml), defined by the handbook's ADR-0020):

| Gate | Tool and how it is measured | Limit at `high` |
| --- | --- | --- |
| Complexity | lizard 1.24.1, modified cyclomatic complexity (`-m`: a `switch` counts once) per function | CCN at most 15 |
| Function length | lizard, lines of code per function | at most 60 |
| Parameters | lizard, per function | at most 6 |
| Line coverage | GCC 14 `--coverage -O0`, every CTest, gcovr 8.7 `--merge-lines` (a template's lines count once across its instances), `--exclude-unreachable-branches --exclude-throw-branches` | at least 85 % |
| Branch coverage | same run | at least 75 % |
| MC/DC | GCC `-fcondition-coverage`, same run | measured, not gated at `high` (100 % at `safety`) |
| Sanitizers | Clang, `-fsanitize=address,undefined -fno-sanitize-recover=all`, every CTest | no report |
| Fuzzing | libFuzzer with ASan and UBSan, 120 s per target | no broken promise |

The reports are in the run's `host-quality-reports` artifact and its step summary. To run the gates locally:

```bash
# Coverage (GCC 14 or later), then the complexity limits
cmake -S . -B build-cov -DCMAKE_CXX_COMPILER=g++-14 -DSE05X_BUILD_TESTS=ON \
  -DCMAKE_CXX_FLAGS="--coverage -O0 -fcondition-coverage"
cmake --build build-cov && ctest --test-dir build-cov
gcovr --root . --filter inc/ --filter src/ --merge-lines --exclude-unreachable-branches --txt build-cov
lizard -m -C 15 -L 60 -a 6 inc src

# Sanitizers (Clang)
cmake -S . -B build-san -DCMAKE_CXX_COMPILER=clang++ -DSE05X_BUILD_TESTS=ON \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-sanitize-recover=all -O1 -g"
cmake --build build-san && ctest --test-dir build-san --output-on-failure
```

The fuzz gate runs locally as shown in [Fuzz tests](#fuzz-tests).

clang-tidy 20 ([`_config/.clang-tidy`](../_config/.clang-tidy): bugprone, CERT, clang-analyzer,
cppcoreguidelines, modernize, performance, portability and readability, each disabled check with its reason) and
cppcheck (strict) run in the `C++ lint` and `Repository checks` jobs and fail on any finding.

The `MISRA` job ([`ci-misra.yml`](../.github/workflows/ci-misra.yml)) runs the shared `ru-misra` workflow of
ci-tools at level `high`: it traces a host build and the Cortex-M build (`se05x_optimised_build`) of every
translation unit, checks them against MISRA C++:2023 and the handbook's C++20 profile (the CodeQL coding-standards
and profile packs, plus the validated clang-tidy and cppcheck checks), and reports each finding against the
handbook's compliance matrix and deviation records. A finding is fixed in the code; a deliberate exception names
its deviation on the line before it (`// codeql::misra_deviation_next_line(MD-CPP-009)` above the `.ipp` include
of `inc/se05x.hpp`). Until the repository is public the job runs with `open_source_prerelease: true`, the
declaration that the code is released under the licence in `LICENSE` and is to be published.

### The MISRA scan, rehearsed locally

The scan runs only in CI, and a first push has paid for the same few findings again and again. `tools/misra_lint.py`
(standard-library Python, no build) catches those classes before the push; `tools/preflight.sh` runs it as the
`misra-lint` step, which cannot be skipped, and its `--selftest` as `misra-lint-selftest`. It reads the C++ files
(`*.hpp`, `*.cpp`, `*.ipp`) of `inc/`, `src/`, `tests/` and `examples/` and prints `file:line Rule N.N.N message`:

| Rule | Reported | Severity |
| --- | --- | --- |
| 9.4.1 | an `if ... else if` chain that does not end in a plain `else` (at the last `else if`) | error |
| 7.0.3 | arithmetic, comparison or conversion on a `char`: `c - '0'`, `c >= '0'`, `token[0] == '-'`, `static_cast<char>(byte)` | error |
| 0.1.2 | a call statement that drops the result of a function the tree declares with a class return type | error (scalar result: warning) |
| 13.3.3 | a function whose declaration and definition use different parameter names | error |
| KB-CPP-012 | an include in `inc/` or `src/` outside the driver's library subset | error |
| 8.0.1 | an operand of a logical and / or that is a comparison or bitwise expression and is not parenthesised | warning |

**Severity.** An error fails the preflight; a warning is printed and counted in the summary line
(`misra_lint: N file(s), E error(s), W warning(s)`) and does not. A finding is an error only when its rule is one the
CI scan blocks on and it is in `inc/` or `src/`; every finding in `tests/` or `examples/` is a warning, as are 8.0.1
everywhere and `--void-casts` (`(void)expr;`, which the scan accepts). `--strict` turns every warning into an error,
for a reviewer who wants the whole list. This split is derived from CI evidence, not from the rule text: the scan
reported 7.0.3, 9.4.1, 0.1.2 and 13.3.3 as `failure` and 8.0.1 as `warning`, only `failure` annotations fail the job,
all findings listed were in `inc/` and `src/`, and drivers whose CI is green still carry `else if` chains in `tests/`.
Revisit it if CodeQL is ever seen blocking on a finding in `tests/` or `examples/`, or on 8.0.1: move that rule or
folder into the error set (`TRACED` and the severities in `tools/misra_lint.py`).

The check is a token scan without types: it reports what it can decide and stays silent otherwise, so a clean run
does not replace the scan, but an error is an error. Fix the code: compare characters through a table or
`std::array<char, 1>` equality, convert a byte with `std::bit_cast<char>`, end the chain in `else`, give the
declaration and the definition the same parameter names, use the returned value or discard it with
`static_cast<void>`. A deliberate exception carries the deviation the scan reads
(`// codeql::misra_deviation_next_line(MD-CPP-...)` on the line before) or `// misra-lint: ignore 8.0.1` on the
line. `--strict-precedence` (`a < b + 1`) reports more 8.0.1.

The include subset is read from `handbook_check.py` of a ci-tools checkout (`CI_TOOLS_DIR`, default `../ci-tools`),
so the two never differ; without the checkout the built-in list of ADR-0017 applies. The preflight also runs that
`handbook_check.py` itself (the `handbook-check` step; skipped, with the reason named, only when the checkout or
PyYAML is missing), lints `tests/install_consumer/main.cpp` with clang-tidy like every other C++ file (it is built
by its own CMake project, so it is not in the host build's compilation database), and checks the first-push gitlink:
after `git add -A`, `examples/esp32/scripts` must be a gitlink (mode 160000).

## Documentation snippets

Every C++ block on this site is included from [`tests/docs/`](../tests/docs/my_port.hpp), which the host build
compiles (target `se05x_doc_snippets`) with the driver instantiated over the documented port. A change to
the API that breaks a page breaks the build first. The README's example is a generated copy of the same file;
`kokeb-docs check` fails when it drifts.

## CI workflows

Everything runs from [`ci.yml`](../.github/workflows/ci.yml), which calls one workflow file per check and ends in
the `CI gate` job, the single required check (`CI gate / gate`).

| Job | What it checks |
| --- | --- |
| Host tests | GCC, then Clang (one job), build and run every test above, then build and run `examples/host` on its own |
| Host quality | The gates above: complexity, coverage, sanitizers, fuzzing |
| Cross-compile | `arm-none-eabi-g++` for Cortex-M0+, M4F and M7F with the strict flags, warnings as errors (nothing linked) |
| C++ lint | clang-format and clang-tidy over the sources |
| MISRA | MISRA C++:2023 and the C++20 profile on traced host and Cortex-M builds, at level `high` (see [Quality gates](#quality-gates)) |
| Docs | Strict site build (`_config/mkdocs.yml`), figure and generated-region drift, Doxygen (`_config/Doxyfile`), offline link check, Lighthouse |
| Repository checks | One job: DCO on pull requests, the org standard, Markdown and YAML lint, the [Kokeb Labs handbook](https://github.com/kokeb-labs/handbook) rules for `.kokeb/handbook.yml` (by rule ID), template drift (warns only) and cppcheck over the driver sources; a second job runs the handbook's source checks (include guards, bus requirements, raw access) |
| CI gate | Passes only if every job above passed: the one required check |

The **ESP32 examples** job builds every app in `examples/esp32/app_config.yml`, for each listed ESP-IDF version and
build type, with the repository root as the driver's component, and lints the example sources. The gate needs it
too.

The workflows call the shared, versioned workflows of
[kokeb-labs/ci-tools](https://github.com/kokeb-labs/ci-tools) at `@v1`.

## On hardware

An MCU example ([Examples](examples.md)) is the bench test: it opens the chip and logs the result. Record the board,
the chip variant and the result in the pull request's bench-status section. No irreversible build runs against a real
chip without a bench record ([Safety rules](safety.md)).
