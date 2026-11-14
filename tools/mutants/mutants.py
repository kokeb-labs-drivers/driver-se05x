#!/usr/bin/env python3
"""One-edit mutants of the driver's guards: every active mutant must make the host tests fail.

  SE05X_GENERATED=<build dir>/se05x_generated tools/mutants/mutants.py [--jobs N] [--only ID] [--list] [--strict]
      [--catalogue FILE ... | --all]
  tools/mutants/mutants.py --selftest

SE05X_GENERATED names the directory with the generated se05x_version.h (the build tree's se05x_generated).

Each mutant is one textual edit (file, old text, new text, occurrence) applied to a copy of inc/, src/ and tests/ in a
scratch directory; the copy is compiled with the host test flags, twice (irreversible operations off and on), and run.
The unedited tree is built and run first; when it fails the run stops (exit 2), since a failing test would
count as a kill. A mutant is KILLED when a test fails or a static_assert fires; it SURVIVES when every test passes, which is a finding:
a guard that no test checks. An edit whose text is not in the file is BROKEN (the catalogue drifted from the code),
and an edit that does not compile for another reason is BROKEN too. The run exits 1 when a mutant survives or breaks.

The catalogue has two parts. ACTIVE mutants edit code that exists: a core set per area, kept here. The full lists of
each area are data files next to this script (transport.txt, apdu.txt, channels.txt; format in their header);
`--catalogue FILE` runs one of them instead of the core set, `--all` runs every one. PENDING entries are the must-kill list of the
design (section 10.6) for layers still being built: each names the package that owns the file and what the mutant must
remove. They are listed, not run; when the code lands its owner turns the entry into an active mutant with the exact
text. `--strict` (the release gate) fails while any pending entry is left. Equivalent mutants (an edit that cannot
change behaviour because another guard covers the same case) go in EQUIVALENT with the reason, and are not run.

Policy (docs/testing.md, "Mutation"): every comparison, counter, constant and status-word mapping that guards a
safety rule (S-01 to S-17) has a mutant; a survivor is fixed by a test, never by deleting the mutant.
"""
from __future__ import annotations

import concurrent.futures
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(__file__).resolve().parent.parent.parent
WIRE = 'inc/se05x_wire.hpp'
TYPES = 'inc/se05x_types.hpp'
CONFIRM = 'inc/se05x_confirm.hpp'
LIFECYCLE = 'inc/se05x_lifecycle.hpp'
HROT = 'inc/se05x_hrot.hpp'

T1 = 'src/se05x_t1.ipp'
CRC = 'inc/se05x_t1_crc.hpp'
APDU = 'inc/se05x_apdu.hpp'
ATTEST = 'src/se05x_attest.ipp'
SCP = 'src/se05x_scp03.ipp'
SECRET = 'inc/se05x_secret.hpp'
DEVICE = 'src/se05x_device_core.ipp'

# (id, file, old, new, occurrence of old, what the edit removes)
ACTIVE = [
    # Frozen constants.
    ('nad-nxp-out', WIRE, '.nad_host_to_se = 0x5AU', '.nad_host_to_se = 0x5BU', 1, 'NXP flavour NAD to the chip'),
    ('nad-gp-out', WIRE, '.nad_host_to_se = 0x21U', '.nad_host_to_se = 0x22U', 1, 'GP flavour NAD to the chip'),
    ('gp-crc-vector', WIRE, 'kGpExampleCrc = 0xBDA4U', 'kGpExampleCrc = 0xBDA5U', 1, 'the GP CRC example value'),
    ('chip-reset-code', WIRE, 'kUmChipReset = 0xC6U', 'kUmChipReset = 0xC7U', 1, 'the NXP chip-reset S-block code'),
    ('retry-cap', TYPES, 'kMaxFrameRetries = 10;', 'kMaxFrameRetries = 11;', 1, 'UM11225 ten retransmissions'),
    ('session-wtx', TYPES, 'kSessionOpenWtxAllowance = 40;', 'kSessionOpenWtxAllowance = 41;', 1,
     'the WTX allowance at session open'),
    ('budget-limit', TYPES, 'kThroughputLimitApdus = 1000000U;', 'kThroughputLimitApdus = 1000001U;', 1,
     'the APDU budget ceiling (S-17)'),
    ('attested-chunk', TYPES, 'kMaxAttestedBinaryRead = 500U;', 'kMaxAttestedBinaryRead = 501U;', 1,
     'the 500-byte attested read chunk'),
    ('poll-floor', TYPES, '(config.poll_interval_us >= 1000U)', '(config.poll_interval_us >= 999U)', 1,
     'Validate accepts a poll interval below MPOT'),
    ('apdu-payload', TYPES, 'kMaxApduPayload = 1024U;', 'kMaxApduPayload = 889U;', 1,
     'the payload limit is the 1024-byte internal buffer (AN12543 p. 3)'),
    ('eddsa-userid', WIRE, 'kEddsaInputMaxUserId = 919U;', 'kEddsaInputMaxUserId = 940U;', 1,
     'EdDSA input inside a UserID session is 919 bytes (AN12543 pp. 103-104)'),
    ('confirm-compare', CONFIRM, 'confirmed_(phrase == Op::kPhrase)', 'confirmed_(true)', 1,
     'any phrase confirms an irreversible operation (S-10)'),
    ('role-transport', LIFECYCLE, 'return AuthRole::Transport;', 'return AuthRole::None;', 1,
     'SetLockState needs no Transport session'),
    ('slot-bound', HROT, 'if (index >= kSlotCount) {', 'if (index > kSlotCount) {', 1, 'slot bound off by one'),
    ('budget-compare', HROT, '(cost <= (limit - used))', '(cost < (limit - used))', 1,
     'ApduBudget refuses a call that would pass the ceiling (S-17)'),
    ('plan-prepared', 'src/se05x_irreversible.ipp',
     'if (!plan.IsPrepared() || !confirmation.IsConfirmed() ||\n      (plan.owner_ != static_cast<const void*>(device_))) {',
     'if (!confirmation.IsConfirmed()) {', 1,
     'Apply refuses a plan that was not prepared for this device (S-10)'),
    # Transport (core of transport.txt).
    ('crc-init', CRC, 'kCrcInit = 0xFFFFU;', 'kCrcInit = 0x0000U;', 1, 'CRC-16/X-25 initial value 0xFFFF'),
    ('crc-poly', CRC, 'kCrcPolyReflected = 0x8408U;', 'kCrcPolyReflected = 0x1021U;', 1,
     'CRC-16/X-25 polynomial 0x8408'),
    ('crc-order', T1, '  if (crc_fixed_) {', '  if (false) {', 1, 'the CRC byte order fixed on the first valid frame'),
    ('ns-toggle', T1, '    ns_ = detail::Toggle(ns_);', '    ns_ = ns_;', 1, 'N(S) toggles after each I-block'),
    ('chain-bit', T1, '(more ? detail::kIMore : 0U)', '(more ? 0U : 0U)', 1, 'the M bit on every block but the last'),
    ('wtx-cap', T1, 'if (wtx_count_ > config_.wtx_limit) {', 'if (wtx_count_ > (config_.wtx_limit + 1U)) {', 1,
     'the WTX count is compared with wtx_limit'),
    ('wtx-floor', T1, '                        wire::kMinWtxHostTimeoutMs),', '                        0U),', 1,
     'the host waits at least 4 s after a WTX (AN13904 p. 27)'),
    ('retry-compare', T1, '    if (attempt == config_.frame_retries) {', '    if ((attempt + 1U) == config_.frame_retries) {',
     1, 'resends stop at frame_retries, not one early'),
    ('no-empty-write', T1, '  } else if (command.empty() || (command.size() > kMaxCommandApdu) ||',
     '  } else if ((command.size() > kMaxCommandApdu) ||', 1, 'an empty command is refused (errata I2C.2)'),
    ('single-flight', T1, '  } else if (state_ == LinkState::InFlight) {\n    early = Error::Busy;',
     '  } else if (false) {\n    early = Error::Busy;', 1, 'a second command while one is in flight is Busy (I2C.1)'),
    ('gp-chip-reset', T1, '(flavour_ == TransportFlavour::Gp) ? doPortReset(ResetKind::Reset) : doChipReset()',
     'doChipReset()', 1, 'the GP chip-reset rung uses the reset port, never 0xC6'),
    # APDU layer, policy, gate and attestation (core of apdu.txt).
    ('freshness', ATTEST, 'return ct::Equal(ByteSpan{in.answer.freshness}, ByteSpan{in.sent.nonce});', 'return true;', 1,
     'the format 1 freshness echo compare (S-09)'),
    ('echoed-command', ATTEST, '(in.answer.echoed_command.length == 0U) ||',
     '(in.answer.echoed_command.length != 0U) ||', 1, 'the format 2 echoed-command compare (S-09)'),
    ('timestamp-order', 'inc/se05x_attest.hpp', 'return now[i] > last[i];', 'return now[i] < last[i];', 1,
     'the timestamp is not older than the last one (S-09)'),
    ('policy-rule-class', 'inc/se05x_policy.hpp', 'rules |= v7 ? kV7Asymmetric : kV3Asymmetric;',
     'rules |= v7 ? kV7Symmetric : kV3Asymmetric;', 1, 'a rule invalid for the class is refused'),
    ('gate-version', 'inc/se05x_gate.hpp', 'return (generation == AppletGeneration::V6) ? kGenV6 : kGenV3;',
     'return (generation == AppletGeneration::V6) ? kGenV7 : kGenV3;', 1,
     'the capability gate compares the applet version'),
    ('sw-map', APDU, '{.sw = 0x66A6U, .error = Error::ThroughputLimited},',
     '{.sw = 0x66A7U, .error = Error::ThroughputLimited},', 1, 'StatusToError maps 0x66A6 to ThroughputLimited'),
    ('apdu-limit', APDU, '(body > kMaxApduPayload)', '(body > kMaxApduPayload + 1U)', 1,
     'a data field above the 1024-byte internal buffer is refused (AN12543 p. 3)'),
    ('aead-888', 'inc/se05x_apdu_crypto.hpp', '(apdu + up16(aad) + up16(data)) <= wire::kAeadOneShotMax',
     '(apdu + up16(aad) + up16(data)) < wire::kAeadOneShotMax', 1, 'the AEAD one-shot limit 888 (AN12543 p. 125)'),
    # Secure channels (core of channels.txt).
    ('ct-equal-length', SECRET, '  if (a.size() != b.size()) {', '  if (a.size() < b.size()) {', 1,
     'ct::Equal compares lengths first'),
    ('mac-compare', SCP, '  if (!ct::Equal(ByteSpan{mac.data(), kMacBytes}, ByteSpan{received})) {',
     '  if (ct::Equal(ByteSpan{}, ByteSpan{mac.data(), 1U})) {', 1, 'the R-MAC compare'),
    ('short-rmac', SCP, '  if (length < (2U + kMacBytes)) {', '  if (length < 2U) {', 1,
     'R-MAC is checked on short responses too'),
    ('scp-counter', 'inc/se05x_scp03.hpp', '  next = counter + 1U;', '  next = counter;', 1,
     'the encryption counter increments (S-16)'),
    ('jos2-counter', SCP, '(rule_ == CounterRule::EveryCommand) || last_had_data_, counter_);',
     '(rule_ == CounterRule::EveryCommand) || !last_had_data_, counter_);', 1,
     'platform SCP03 advances the counter only for commands with data (errata JOS.2)'),
    ('card-cryptogram', SCP, '  if (!ct::Equal(ByteSpan{expected}, ByteSpan{hs.card_cryptogram})) {',
     '  if (ct::Equal(ByteSpan{}, ByteSpan{expected})) {', 1, 'the card cryptogram is checked'),
    ('wipe-on-close', SCP, '        static_cast<void>(crypto_->ReleaseKey(key));', '        // released', 1,
     'session keys are released at close (S-01)'),
    # Device: the role check and the 0x66A6 rung (full list: device.txt).
    ('role-check', DEVICE, '  if ((needed != AuthRole::None) && (role_ != needed)) {', '  if (false) {', 1,
     'the device checks RequiredRole before sending'),
    ('throttle-rung', DEVICE, 'link_.Recover(t1::Rung::ChipReset)', 'link_.Recover(t1::Rung::Reselect)', 1,
     'ThroughputLimited climbs to the chip reset once, no loop'),
    ('release-wipes', 'src/se05x_crypto.ipp', '  slot->key.Wipe();\n', '\n', 1, 'ReleaseKey wipes the key bytes'),
    ('eckey-receipt', 'src/se05x_eckey.ipp', '    if (!ct::Equal(ByteSpan{expected}, ByteSpan{receipt})) {',
     '    if (ct::Equal(ByteSpan{}, ByteSpan{expected})) {', 1, 'the ECKey receipt compare'),
]

# The design's must-kill list for layers not built yet: (id, owner package, file, what the mutant removes).
PENDING: list = []

# Edits that cannot change behaviour because another guard covers the same case: id -> reason.
EQUIVALENT: dict[str, str] = {}

# The test build's library hardening, so an out-of-range access traps (a kill) instead of passing unseen.
FLAGS = ['-std=c++20', '-fno-exceptions', '-fno-rtti', '-w', '-O0', '-D_GLIBCXX_ASSERTIONS=1',
         '-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST']
SKIP_TESTS = ('test_kconfig.cpp', 'test_version.cpp')
TIMEOUT_S = 600  # a mutant that hangs the tests is killed: every wait of the library is bounded


def load_catalogue(path: Path) -> tuple[list, dict[str, str]]:
    """The mutants of a data file (format in its header), and its equivalent ones with their reasons."""
    items: list = []
    equivalent: dict[str, str] = {}
    cur = None
    for line in path.read_text().splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        if line[0] in '-+' and cur is not None and (len(line) == 1 or line[1] == ' '):
            cur[2 if line[0] == '-' else 3].append(line[2:])
        elif line.startswith('= ') and cur is not None:
            equivalent[cur[0]] = line[2:]
        else:
            mid, rel, what = (x.strip() for x in line.split('|', 2))
            cur = [mid, rel, [], [], what]
            items.append(cur)
    return [(m, rel, '\n'.join(o), '\n'.join(n), 1, w) for m, rel, o, n, w in items], equivalent


def apply_edit(text: str, old: str, new: str, nth: int) -> str | None:
    """`text` with the `nth` occurrence of `old` replaced, or None when there are fewer occurrences."""
    if text.count(old) < nth:
        return None
    parts = text.split(old)
    return old.join(parts[:nth]) + new + old.join(parts[nth:])


def run_one(item, work_root: str, cxx: str):
    mid, rel, old, new, nth, what = item
    work = Path(tempfile.mkdtemp(prefix='mut-' + mid + '-', dir=work_root))
    for d in ('inc', 'src', 'tests'):
        shutil.copytree(ROOT / d, work / d,
                        ignore=shutil.ignore_patterns('compile_fail', 'fuzz', 'install_consumer'))
    if rel is not None:
        path = work / rel
        edited = apply_edit(path.read_text(), old, new, nth)
        if edited is None:
            shutil.rmtree(work, ignore_errors=True)
            return mid, 'BROKEN', 'pattern not found: ' + old[:60]
        path.write_text(edited)
    tests = sorted(str(p) for p in (work / 'tests').glob('test_*.cpp') if p.name not in SKIP_TESTS)
    generated = os.environ.get('SE05X_GENERATED', str(ROOT / 'build' / 'se05x_generated'))
    verdict = ('SURVIVED', what)
    for irreversible in ('0', '1'):
        exe = work / f'tests_{irreversible}'
        build = subprocess.run([cxx, *FLAGS, f'-DSE05X_ENABLE_IRREVERSIBLE={irreversible}', '-I' + str(work / 'inc'),
                                '-I' + str(work / 'tests'), '-I' + generated, *tests, '-o', str(exe)],
                               capture_output=True, text=True)
        if build.returncode != 0:
            if 'static assert' in build.stderr or 'static_assert' in build.stderr:
                verdict = ('KILLED', 'a static_assert failed')
            else:
                lines = build.stderr.strip().splitlines() or ['?']
                verdict = ('BROKEN', 'build failed: ' + lines[-1][:80])
            break
        try:
            failed = subprocess.run([str(exe)], capture_output=True, text=True, timeout=TIMEOUT_S).returncode != 0
        except subprocess.TimeoutExpired:
            failed = True
        if failed:
            verdict = ('KILLED', 'a test failed')
            break
    shutil.rmtree(work, ignore_errors=True)
    return mid, verdict[0], verdict[1]


def catalogues() -> list[Path]:
    return sorted(HERE.glob('*.txt'))


def selftest() -> int:
    """The catalogues are well formed and every active pattern is in its file exactly as written."""
    bad = 0
    extra = [m for f in catalogues() for m in load_catalogue(f)[0]]
    ids = [m[0] for m in ACTIVE + extra] + [p[0] for p in PENDING]
    if len(ids) != len(set(ids)):
        print('duplicate mutant id')
        bad += 1
    for mid, rel, old, new, nth, _ in ACTIVE + extra:
        if old == new:
            print(f'{mid}: the edit changes nothing')
            bad += 1
        text = (ROOT / rel).read_text()
        if apply_edit(text, old, new, nth) is None:
            print(f'{mid}: {old!r} not in {rel} (occurrence {nth})')
            bad += 1
    for mid, owner, rel, _ in PENDING:
        if owner not in ('P1', 'P2', 'P3', 'P4', 'P5'):
            print(f'{mid}: unknown owner {owner}')
            bad += 1
        if not rel.startswith(('inc/', 'src/')):
            print(f'{mid}: {rel} is not library code')
            bad += 1
    print(f'selftest: {len(ACTIVE)} active, {len(extra)} in {len(catalogues())} catalogue(s), '
          f'{len(PENDING)} pending, {bad} problem(s)')
    return 1 if bad else 0


def main() -> int:
    args = sys.argv[1:]
    if '--selftest' in args:
        return selftest()
    if '--list' in args:
        for m in ACTIVE:
            print(f'active   {m[0]:20} {m[1]:28} {m[5]}')
        for p in PENDING:
            print(f'pending  {p[0]:20} {p[2]:28} {p[1]}: {p[3]}')
        return 0
    jobs = int(args[args.index('--jobs') + 1]) if '--jobs' in args else 4
    only = args[args.index('--only') + 1] if '--only' in args else None
    cxx = os.environ.get('CXX', 'c++')
    pool_items, equivalent = list(ACTIVE), dict(EQUIVALENT)
    files = catalogues() if '--all' in args else [Path(a) for i, a in enumerate(args) if args[i - 1] == '--catalogue']
    if files:
        pool_items = []
        for f in files:
            loaded, eq = load_catalogue(f)
            pool_items += loaded
            equivalent.update(eq)
    for mid, reason in equivalent.items():
        print(f'{mid:20} EQUIVALENT {reason}')
    items = [m for m in pool_items if only in (None, m[0]) and m[0] not in equivalent]
    with tempfile.TemporaryDirectory(prefix='se05x-mutants-') as work_root:
        # The unedited tree must build and pass, or a failing test would count as a kill.
        _, base, note = run_one(('baseline', None, '', '', 1, 'the unedited tree'), work_root, cxx)
        if base != 'SURVIVED':
            print(f'baseline {base}: {note}; fix the tests before reading any verdict')
            return 2
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
            results = list(pool.map(lambda m: run_one(m, work_root, cxx), items))
    bad = 0
    for mid, verdict, note in results:
        print(f'{mid:20} {verdict:9} {note}')
        bad += verdict != 'KILLED'
    print(f'{len(results)} mutants, {len(results) - bad} killed, {bad} not killed; '
          f'{len(equivalent)} equivalent not run; {len(PENDING)} pending')
    if '--strict' in args and PENDING:
        print('strict: pending mutants remain')
        return 1
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
