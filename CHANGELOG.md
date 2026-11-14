# Changelog

All notable changes to this repository are listed here. Versions follow [Semantic Versioning](https://semver.org/).
Entries under **Breaking** need source changes in code that used the affected API; any of them calls for a major
version bump (a minor bump before 1.0).

## [Unreleased]

### Added

- The public headers (types, error model, ports, T=1 link, APDU and TLV, SCP03, ECKey, GP,
  capability gate, objects and generation-typed policies, attestation, perso, 105 device commands, the HRoT facade,
  `wire` constants), stubs that return `NotImplemented`, the contract test, the model interface, the
  irreversible-operation gate (compiled out by default), the documentation skeleton and the hardware description of
  the SE050, SE051 and SE052.
- Documentation: getting started by job, the HRoT cookbook, the security model, the per-chip guides for the SE050,
  SE051 and SE052, choosing a variant, transport, secure channels, objects and policies, lifecycle and roles,
  irreversible operations, errors and status words, porting to ESP-IDF, limitations and a rewritten troubleshooting
  page; every chip fact cited to a document and page in `docs/datasheets.yml`.
- Figures: the T=1 block, link states and recovery ladder, the SCP03 and ECKey session sequences, the lifecycle, the
  object and policy model, the variant decision tree, the irreversible-operation flow, the trust boundaries, and the
  SE052 pinout and wiring; feature icons on the home page.
- `tools/mutants/mutants.py`: the mutation catalogue (active mutants of the frozen headers, the pending must-kill list
  of the layers being built) with a baseline check, and the mutation policy.
- Mutation catalogues per area (`tools/mutants/transport.txt`, `apdu.txt`, `channels.txt`, run with `--catalogue` or
  `--all`) and a core set of each in `mutants.py`; mutants run with the library's bounds checks and a timeout.
- `wire::kEddsaInputMax` (940) and `wire::kEddsaInputMaxUserId` (919), with `wire::EddsaInputMax()`; the CTest
  `se05x_eckey_on` (the ECKey session with its build flag on).
- `Device<P>`: `Open()` (card identification, select, extended features, probes, `ReadState`, capabilities,
  platform SCP03 by `Config::scp_policy`), `Close()`, `Recover()`, `PowerCycle()`, `DeepPowerDown()`, the UserID,
  AESKey and ECKey sessions (the ECKey one only after `ReadEckaPublicKey()` verified the chip's key by attestation),
  `Execute<C>()` for every reversible command through the gate, the role check, the policy generation check and the
  EdDSA and UserID limits, `ExecuteIrreversible<C, Op>()` with its typed state checks, the 0x66A6 reset ladder (one
  chip reset per call), raw lab access and the named wrappers; the transport stack runs an applet session inside
  platform SCP03 (`se05x_device_stage.hpp`) and never falls back to the plain link once platform SCP03 was open.
- `Device::SetPlatformKeys()`, `Device::ReadEckaPublicKey()`, `AuthRole::Restrict`, `TlsPrfArgs::role` (the TLS
  server role of `TLSPerformPRF`), `kMaxPlainCommandApdu`.
- The independent chip model `tests/model/chip_model.hpp` (profiles SE050, SE050E, SE051, SE052F) and the bench
  `tests/model/chip_bench.hpp`; device tests, the flag-on executable `se05x_device_irreversible_on`, the sequence
  fuzzer `fuzz_device_sequence` and the mutation catalogue `tools/mutants/device.txt`.

- The root-of-trust facade `hrot::Device<P>`: typed slots per kind, keys typed by use, `Provision<U>()`, `Find<U>()`,
  `GetPublicKey()`, `Sign()`, `TlsSign()`, `VerifySignature()` (fails closed), `Agree()`, `ImportPublicKey()`,
  `Attest()` returning `Verified<AttestedValue>`, stored data and certificates, monotonic counters with
  `CheckFloor()` and `RaiseCounterTo()`, `Random()`, the APDU budget (S-17) with `SetWindowCount()`; every key,
  counter and secret-data call needs secure messaging. Compile-fail tests for each foot-gun (wrong slot kind, wrong
  key use, a forged key or verified value, an out-of-range slot, a generated verification key, a confirmation of
  another operation).
- `irreversible::Operations<P>`: plans and `Apply()` for the persistent lock, the platform SCP03 requirement, the
  applet features, `DeleteAll`, the object-creation restriction, an immutable object and a finite authentication
  object; the four operations this version cannot do are refused at the plan.
- `Device::ReadVerified()`: an attested read verified in one call.
- Compiled job snippets for every path of the getting-started page and the cookbook (`tests/docs/jobs.hpp`,
  `lifecycle.hpp`), run against the chip model; the host example runs the facade jobs on the simulated chip; the
  ESP32 facade example; the optional PSA crypto port (`examples/psa/`); the mutation catalogue
  `tools/mutants/hrot.txt`; the facade sequence fuzzer `fuzz_hrot_sequence`.
- The optional PKI layer `se05x::pki` (`se05x_pki.hpp`, opt-in): a strict DER reader and a DER writer, PKCS#10
  requests signed by a chip key (`DeviceSigner`) or a crypto-port key (`PortSigner`) with subject and subjectAltName
  builders, a strict X.509 v3 parser, chain verification to caller-supplied trust anchors (ECDSA P-256 and P-384
  through a verifier port, caller-supplied time, path length), certificate and trust-anchor storage in read-only
  binary objects, the provisioning recipes, OpenSSL test vectors, the fuzz targets `fuzz_pki_der` and
  `fuzz_pki_x509`, the mutation catalogue `tools/mutants/pki.txt`, the page `docs/pki.md` and its figure.
- `Layer::Pki`: the layer of a PKI refusal, whose `Detail::step` is the `pki::Reason`.
- Safety behaviour of the first version: attested reads take a host nonce and accept only a later timestamp,
  across reopens; the facade's counters cannot be deleted and are created with their value; facade calls need
  authenticated answers (keys, counters, verification) or encryption both ways (ECDH, secret data); facade policies
  name the applet session they are made in; `Find()` and `CreateCounter()` adopt only a persistent object of the
  right class and origin with the facade's exact policy; ECDH peers and trust anchors must be points on P-256; immutable
  files and UserID objects only through the irreversible operations; the APDU count spans
  every open, counts every session handshake APDU and saturates; `Store()` writes a completion marker last and
  `Load()` and `Attest()` refuse an object without it; every facade call is admitted on its worst-case APDU count
  before the first APDU (`hrot::cost`, shown in the HRoT cookbook and checked by the CTest `se05x_docs_costs`); the
  facade runs on applet 7.x only and refuses 3.x and 6.x with `Unsupported` before sending.
- Transport behaviour: a WTX extends any command to at least 4 s, one WTX grants at most 30 s and the WTX of one
  command at most 180 s; a BWT above 10 s is refused; the guard time holds before every read and write; 300 us of
  quiet after an SE052 deep power-down by S-block; `Auto` tries the NXP flavour first, and the GP flavour accepts
  NAD 0xA5 from the chip.
- Documentation: ambiguities A1 to A36, each with a bench step; the datasheet map in `docs/datasheets.yml`; the
  hardware description in `docs/hardware.yml`.
- APDU budget after SW 0x66A6: the recovery (select, `ReadState`, the platform SCP03 handshake) may send up to four
  APDUs beyond a facade call's admitted cost, counted in `Used()`; `Store` sends no clean-up delete after
  `ThroughputLimited`. Claim C8, S-17 and the cost table say so, and a test pins the bound. Ambiguity A36 (attested
  read of an object above the 500-byte chunk limit), with a bench step.
- Facade refusals on older applets and short reads: the documents say applet 3.x and 6.x (every facade call
  returns `Unsupported` there after its argument checks; claim C13), with the model profile `se051_v6`, a test of
  every facade call on both generations and a test that the argument checks run first; `Attest` and `Load` are
  tested against a value cut short under a valid signature (model knob `read_truncate`), and the store-marker check
  directly, including a signed size above the 256-byte buffer.
