# Recurring defects

The defects that reached an independent reviewer or the first CI run of more than one driver, one entry per class.
Review skills cite these ids; the [mechanization policy](mechanization-policy.md) says where each class is caught and
when it moves up a level. Append new findings to the entry they belong to, or add an entry (see the policy).

Each entry gives the number of drivers in which the class was seen; the evidence itself is kept outside this
repository. Code examples are generic and minimal; none quotes a datasheet or a standard.

Detection levels: `lint` (a script in the preflight or the gate, no judgement), `test` (a model knob, a mutation, a
fuzz property or a compile-fail case that fails when the defect is present), `review` (a named reviewer asks one
question). Status: `enforced` is in the template now; `planned` is the target, tracked in the policy's backlog,
and until it lands the level below it (test, then review) is what protects the driver.

## Index

| Id | Class | Drivers | Detection now | Target |
| --- | --- | --- | --- | --- |
| RD-01 | Write after an unseen device reset | 4 | review | test |
| RD-02 | Decision from one unvalidated read | 5 | review | test |
| RD-03 | Stuck or floating line accepted as data | 3 | review | test |
| RD-04 | Invalid argument still sends something | 2 | test | test |
| RD-05 | Stop, switch-off or release refused | 4 | review | test |
| RD-06 | Transfer buffers on the stack | 4 | review | test |
| RD-07 | Chip model shares the driver's misreading | 2 | review | lint + review |
| RD-08 | False coverage matrix or fuzz claim | 3 | review | lint |
| RD-09 | Docs promise behaviour the code lacks | 6 | review | review (claims check) |
| RD-10 | Incomplete state-machine guard | 5 | review | test |
| RD-11 | Header outside the library subset | 2 | lint | lint |
| RD-12 | Rule 7.0.3 character arithmetic | 3 | CI | lint |
| RD-13 | Rule 8.0.1 missing parentheses | 2 | CI | lint |
| RD-14 | Rule 9.4.1 else-less chain | 3 | CI | lint |
| RD-15 | Rule 0.1.2 unused return value | 1 | CI | lint |
| RD-16 | Rule 13.3.3 parameter names differ | 1 | CI | lint |
| RD-17 | Rule 7.0.6 literal argument type | 4 | review | lint (partial) + review |
| RD-18 | Advisories 6.9.2, 15.1.4, 0.0.2 | 5 | CI | lint (known list) |
| RD-19 | Template drift | 3 | lint | lint |
| RD-20 | ESP-IDF REQUIRES incomplete | 1 | CI | lint |
| RD-21 | ESP32 example cannot start with its defaults | 3 | review | test |
| RD-22 | Compile-fail regex wording differs by compiler | 0 | review | lint |
| RD-23 | Tests are also scanned by MISRA | 2 | CI, review | lint |
| RD-24 | Missing gitlink for the scripts submodule | 2 | lint | lint |
| RD-25 | Guards no test kills (surviving mutants) | 6 | review | test |
| RD-26 | Fuzz target does not check the safety rules | 3 | review | test |
| RD-27 | Local tidy and format differ from CI | 4 | CI | lint |
| RD-28 | Datasheet misread in a decode, clear or timing | 6 | review | review |
| RD-29 | Hardware doc exceeds a datasheet limit | 3 | review | review |
| RD-30 | Out-of-bounds or UB before a guard | 3 | test | test |
| RD-31 | Clear-on-read flags lost by a diagnostic read | 2 | review | test |
| RD-32 | Docs style: line length, merged bullets, stale text | 3 | lint | lint |
| RD-33 | Another project's name or dated history | 1 | lint | lint |
| RD-34 | Unspecified evaluation order in a test check | 3 | lint | lint |

## Chip-protocol and safety classes

### RD-01 Write after an unseen device reset

Rule: every way the chip can reset itself is detected from evidence the chip leaves, and no cached value is written
over a chip that may have reset.

```cpp
// bad: the chip browned out; shadow_ holds the old setpoint, the chip is at its reset value
// bad: writes the whole shadow_ (the stale rest of it) over a chip that may have reset
Result<void> SetLimit(uint8_t v) { shadow_.limit = v; return WriteReg(kLimit, Pack(shadow_)); }
// good: check the evidence first, refuse until the application re-initialises
Result<void> SetLimit(uint8_t v) {
  if (auto r = ResetCheck(); !r) { return r; }        // status read, sentinel compare; pending until it passes
  return WriteReg(kLimit, Pack(WithLimit(shadow_, v)));
}
```

Hurts: stale state rewritten into a chip at reset values energises outputs or sets limits the application never
chose; the call returns Ok.
Seen in 4 drivers.
Detection: `test`: model knob "reset mid-session" (registers to reset values, reset flags set) plus a fuzz property
"no write after a reset is seen"; mutate the sentinel compare and the pending-check latch, each must fail a test.
`review`: hardware-lessons-review 12a. Question: "List every way this chip resets or reloads; for each, which bit or
sentinel shows it, which function reads it, and what does a setter do between the reset and that read?"

### RD-02 Decision from one unvalidated read

Rule: a read that decides a write, a state change or an identity is validated per the protocol (CRC, echo, length) and
a read-modify-write uses only a validated read; a single bad read never clears state or masks a lost write.

```cpp
// bad: one flipped read clears identity, the next switch-off returns NotInitialized and sends nothing
if (ReadReg(kId) != kExpectedId) { identified_ = false; }
// good: two agreeing reads before a state is dropped; switch-off ignores identified_
```

Hurts: a transient line error becomes "device reset" or "not initialised", a read-modify-write writes garbage bits
back, a resync hides a lost write so the chip runs at the wrong current.
Seen in 5 drivers.
Detection: `test`: model fault "one flipped reply at call k" swept over every call of every public function; the
expected result is the call's own error, no state loss, no unsafe write. `review`: hardware-lessons-review 1, 12.
Question: "Which reads in this driver decide something, and is there a mutant that removes each validation?"

### RD-03 Stuck or floating line accepted as data

Rule: a reply a dead, shorted or floating line can produce (all zeros, all ones, the command echoed, one word
repeated) is never a measurement or a ready status.

```cpp
// bad: an all-zero frame has a valid CRC for init 0x00, so 0 degC (or -200 degC after the offset) is returned
auto t = DecodeTemperature(words);
// good: reject by pattern before decoding, then plausibility-check the decoded value
if (IsStuck(words)) { return Error::NoDevice; }
```

Hurts: a wrong value is returned as data, which downstream control trusts.
Seen in 3 drivers.
Detection: `test`: one model fault per pattern (zeros, ones, echo, repeat) applied to every read function; a table
test lists each public read function and the fault, so a new read function without a row fails.
`review`: hardware-lessons-review 4. Question: "For each read path, which of the four patterns does the CRC pass,
and which line in the code refuses it?"

### RD-04 Invalid argument still sends something

Rule: a call that returns `InvalidArgument` (or any precondition error) sent nothing and changed nothing; validate
first, transfer second.

```cpp
// bad: reads the position first, then rejects the argument
auto pos = ReadPos(); if (steps > kMax) { return Error::InvalidArgument; }
// good
if (steps > kMax) { return Error::InvalidArgument; }
auto pos = ReadPos();
```

Hurts: a rejected call moves state or leaves the driver config invalid, and the next call sends from it.
Seen in 2 drivers.
Detection: `test`: the model counts frames; every `InvalidArgument` test asserts the count is unchanged, and the
fuzz target asserts it for every call that returned `InvalidArgument`. `review`: hardware-lessons-review 11.
Question: "For each early return of an argument error, what is the first line above it that touches the port?"

### RD-05 Stop, switch-off or release refused

Rule: a switch-off, a release to input and `Deinitialize()` are never refused for any uncertainty (reset report,
failed read, unknown mode, uninitialised after reset) and always send their writes, in the smallest atomic form.

```cpp
// bad
Result<void> Off() { if (!identified_) { return Error::NotInitialized; } return Write(kEnable, 0); }
// good: acts first, reports after
Result<void> Off() { auto r = Write(kEnable, 0); MarkUnverified(); return r; }
```

Hurts: the one command that makes the system safe is the one that fails when the system is most in doubt.
Seen in 4 drivers.
Detection: `test`: for every uncertainty flag the driver has, a test sets it through the model and asserts the
switch-off still writes (mutation: add the refusal back, the test fails). `review`: hardware-lessons-review 12c.
Question: "Name each flag that can make a call return early; show the test where it is set and Off still sends."

### RD-06 Transfer buffers on the stack

Rule: buffers handed to the bus are members of the driver object (memory a DMA engine reaches), never locals or
function-local statics.

```cpp
// bad
Result<void> Read(Reg r) { std::array<uint8_t, 4> tx{}; return port_.Transfer(tx.data(), rx, 4); }
// good
std::array<uint8_t, 4> tx_{};   // member
```

Hurts: DMA or TCM-stack ports fail on the first frame; the host build and a DMA-disabled example hide it.
Seen in 4 drivers.
Detection: `test`: the mock port records the address of every transmit and receive buffer and asserts it lies inside
`[&driver, &driver + sizeof(driver))`; compile it into the shared model. `review`: KB-HW-019.
Question: "In every function that calls the port, where does the memory of each buffer argument live?"

### RD-07 Chip model shares the driver's misreading

Rule: the model is written from the datasheet, including frame layout, not from the driver; golden frames are
transcribed from the datasheet's figures and checked by a test the driver's author did not derive from the code.

```cpp
// bad: driver and model both put the data in bytes 1..2 of the reply, the datasheet says bytes 0..1 of the data word
// good: test_model.cpp pins a golden frame copied from the datasheet figure; model includes no driver header
```

Hurts: green tests, wrong data on the wire; only hardware or an independent reader shows it.
Seen in 2 drivers.
Detection: `lint`: `tests/mock_*.hpp` includes no driver header (planned, preflight `model-standalone`); `review`:
datasheet-conformance, independence check. Question: "Take one golden frame from the datasheet figure; which test
fails if the driver and the model both decode it the other way?"

### RD-10 Incomplete state-machine guard

Rule: every command is checked against every state the chip or the driver can be in, including pending timers,
power gates, asleep and in-doubt; a start-up that leaves anything pending does not energise.

```cpp
// bad: waits only for velocity == 0, but the chip is still counting a stand-still delay and will drive back
while (Velocity() != 0) { }  Enable();
// good: also checks the pending-delay flag the datasheet names
while (Velocity() != 0 || DelayActive()) { }  Enable();
```

Hurts: outputs energise in a state the guard did not consider; the motion or power surprise is real.
Seen in 5 drivers.
Detection: `test`: a generated state x command table test (every public command in every modelled state, expected
result and frame count), and a mutant for each guard. `review`: hardware-lessons-review 11, 12.
Question: "Draw the states from the datasheet; for each command and state, where is the guard and which test
removes it?"

### RD-30 Out-of-bounds or UB before a guard

Rule: bounds, divisors and state are checked before they are used, on every path, including the framing layer.

Hurts: abort in hardened builds, UB elsewhere.
Seen in 3 drivers.
Detection: `test`: libFuzzer with ASan and UBSan in the gate (`enforced`); fuzz target feeds every public function.
`review`: question "which divisor, index or span length comes from a caller or the chip, and where is it checked?"

### RD-31 Clear-on-read flags lost by a diagnostic read

Rule: clear-on-read and write-1-to-clear flags collect in one driver-owned latch; a self-check or raw read never
discards them.

Seen in 2 drivers.
Detection: `test`: model with clear-on-read bits; test reads through every diagnostic path, then asserts the latch
still reports the fault. `review`: hardware-lessons-review 10, 12b.

## Datasheet and documentation classes

### RD-28 Datasheet misread in a decode, clear or timing

Rule: every field position, clear semantic, wait and gap cites its section and has a test that pins it independently.

Seen in 6 drivers.
Detection: `review` (datasheet-conformance): re-derive the five facts the change touches from the datasheet before
reading the code. Question: "For this register or frame, what do the datasheet's bits say, and does the code agree
before you look at the model?"

### RD-29 Hardware doc exceeds a datasheet limit

Rule: a reference circuit, wiring table or example never exceeds an absolute maximum or ties a pin the datasheet
forbids tying.

Seen in 3 drivers.
Detection: `review`: docs and diagram pass. Question: "For each net in the reference circuit, what is the highest
voltage the chip pin sees, and where does the datasheet allow it?"

### RD-09 Docs promise behaviour the code lacks

Rule: every behavioural claim in docs, Doxygen, the contract and the build report is checked against the code
line that implements it and the test that pins it.

```cpp
/// Enables the bridge again.            // doc
Result<void> ClearFaults();              // code returns Busy while the motor moves and stays disabled
```

Hurts: callers and later reviewers rely on the claim; a promised error never occurs, a promised recovery never runs.
Seen in 6 drivers.
Detection: `review` via the review-round claims-vs-code check: list every "always", "never", "returns", "enables" in
docs and the build report and cite the code line and test for each. Mechanical part (`lint`, planned): every `Error`
named in docs exists; every Doxygen `@return` lists the values the function can return.

### RD-08 False coverage matrix or fuzz claim

Rule: a matrix row, test id or knob named in docs exists in code, and a row's test asserts the row.

Seen in 3 drivers.
Detection: `lint` (planned `claims-symbols`): every backticked identifier in the datasheet coverage page,
the coverage matrix and `docs/ambiguities.md` resolves with grep in `inc/ src/ tests/`. `review`: row-level sample.

### RD-32 Docs style

Rule: Markdown lines are at most 120 characters, list items are separated, text changed by a fix is updated everywhere.

Seen in 3 drivers.
Detection: `lint` (`enforced`: markdownlint in the preflight; line length 120). Stale text after a change is RD-09.

### RD-33 Another project's name or dated history

Seen in more than one driver.

## Process and test-quality classes

### RD-25 Guards no test kills

Rule: every guard that protects a write, a state or a value has a test that fails when the guard is removed.

Seen in 6 drivers.
Detection: `test`: a mutation runner over the guard lines (one-edit mutants: negate, drop, swap constant), built by the
reviewer in each round; target: a template `tools/mutate.py` run by the gate with a survivor budget of zero on
guards. `review`: the review-round mutant check of fixes.

### RD-26 Fuzz target does not check the safety rules

Rule: the fuzz target asserts the invariants of the safety rules (no write after a reset is seen, no switch-on in
doubt, no frame after InvalidArgument), and a mutant of each invariant fails it.

Seen in 3 drivers.
Detection: `test`: mutate the invariant check in the harness; `review`: question "which safety rule does the fuzz
target assert, and what input would break each?"

### RD-34 Unspecified evaluation order in a test check

Rule: a call in a test or fuzz target takes, as separate arguments, no operation that changes state together with a
read of that state (`sent()`, `Transfers()`, `pending()`, a flag, a counter, a clock). The order of the arguments of a
call, of the operands of `+ - == <` and of the two sides of an assignment is unspecified; GCC on x86-64 evaluates
arguments right to left, Clang and GCC on aarch64 left to right. Braced-init lists, `&&`, `||`, `?:` and `,` are
sequenced. Two reads of the fuzzer's input (`in.Byte()`, `FuzzConfig(in)`) in one expression count as well: they
advance the input, so the same corpus file decodes into different calls per compiler.

```cpp
// bad: x86-64 GCC reads sent() before the call, so it is always 0 here
Check(d.Write(v), was_up, sent());
// good: the result first, then the read; or pass the probe and read it inside the helper, after the call
const auto r = d.Write(v);
Check(r, was_up, sent());
```

Hurts: the check passes, or aborts, on one CI runner only. A "nothing was sent" promise becomes vacuous, and a
positive promise (`sent >= 1`) aborts on a correct driver; neither shows on an Apple-silicon or aarch64 rehearsal.
Seen in more than one driver.
Detection: `lint` (`enforced`): `tools/eval_order_check.py`, the `eval-order` preflight step, scans `tests/` and
`examples/`. `test`: the fuzz replay with a one-edit mutant that must abort (`mutant_replay_*`, kept out of the
`fuzz_*` names so the libFuzzer job does not pick it up).

### RD-24 Missing gitlink for the scripts submodule

Seen in 2 drivers.
Detection: `lint` (`enforced`): the gate runs `git ls-files -s | grep ^160000` after setting the pinned commit.

### RD-19 Template drift

Seen in 3 drivers.

### RD-27 Local tidy and format differ from CI

Rule: the preflight runs clang-format 20 and clang-tidy over the same file list and compile database as CI, inside the
container.

Seen in 4 drivers.

## CI-only checks (MISRA scan, ESP-IDF, compile-fail)

### RD-11 Header outside the library subset

Rule: `#include <...>` in `inc/` and `src/` is only from the driver subset of the handbook (KB-CPP-012).

```cpp
#include <numeric>   // bad: not in the subset; std::accumulate -> write the OR out
#include <string_view>
```

Seen in more than one driver.

### RD-12 Rule 7.0.3 character arithmetic

Rule: no arithmetic or comparison on a `char` value, including `c - '0'` and `c == 'x'`.

```cpp
int d = c - '0';                 // bad
if (c == 'A') {}                 // bad
const int d = DigitValue(c);     // good: lookup in a constexpr digit array via std::find
```

Seen in 3 drivers.
Detection: `lint`: `misra_lint` rule 7.0.3 (planned): char literals in arithmetic or comparison in `inc src tests
examples`. Until then: grep `'.'` next to `-`, `+`, `==`, `!=`.

### RD-13 Rule 8.0.1 missing parentheses

Rule: a binary operand that is itself a binary expression of higher precedence is parenthesised, in `static_assert` too.

```cpp
static_assert(kA == 1 && kB < 2);           // bad
static_assert((kA == 1) && (kB < 2));       // good
```

Seen in 2 drivers.
Detection: `lint`: `misra_lint` rule 8.0.1 (planned): parenthesis-depth scan of `inc src tests`.

### RD-14 Rule 9.4.1 else-less chain

Rule: every `if ... else if` chain ends with `else`, with a comment when empty; in tests and models too.

Seen in 3 drivers.

### RD-15 Rule 0.1.2 unused return value

Seen in 1 driver.

### RD-16 Rule 13.3.3 parameter names differ

Seen in 1 driver.

### RD-17 Rule 7.0.6 literal argument type

Rule: a constant argument has its parameter's type (a `static_cast` of the constant; no literal operators), and no
mixed-width arithmetic on literals.

Seen in 4 drivers.
Detection: `lint` (partial, planned): literal passed to a `uint32_t` or `uint8_t` parameter of a known function;
`review`
for the rest (the CI scan is final). Question: "Which call passes a bare integer constant to a narrower parameter?"

### RD-18 Advisories 6.9.2, 15.1.4, 0.0.2

Rule: these three appear on every driver and need no re-report: 6.9.2 on the version getters (this driver has no
literal operators, whose `unsigned long long` parameter was the other 6.9.2 site), 15.1.4 on a constructor whose members
have default initialisers, 0.0.2 on a
condition a constant-hook port makes always the same.
Seen in the first CI run of 2 drivers and predicted for 3 more. 5 drivers.
Detection: `lint` (planned): the gate compares the CodeQL advisory list to this known list; anything else is new.
Reviewers do not report the known three; whether to record them as deviations is an owner decision.

### RD-20 ESP-IDF REQUIRES incomplete

Rule: every `#include` of an ESP-IDF header in `examples/esp32/main` has its component in `REQUIRES`.

Seen in 1 driver.

### RD-21 ESP32 example cannot start with its defaults

Rule: the example's default pins and `Config` start up; an optional hook returns `true` when the pin is absent.

Seen in 3 drivers.

### RD-22 Compile-fail regex wording differs by compiler

Rule: an `EXPECT:` is a concept or type name, or the `static_assert` text, never compiler wording.

Seen in more than one driver.

### RD-23 Tests are also scanned by MISRA

Rule: the MISRA job builds with tests on, so `tests/`, models, fuzz and consumers meet the same rules as `inc/`.

Seen in more than one driver.
