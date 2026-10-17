# Assurance case

[SECURITY](./SECURITY.md) states what a user can and cannot expect of
base58-bech32 in terms of security. This page argues why those
expectations hold: the threat model, the trust boundaries, how secure
design principles are applied, and how common implementation weaknesses
are countered. Each argument below names the file, the test or the
workflow that supports it; where SECURITY.md already states a fact, this
page points at it instead of repeating it.

## What is claimed

- **An encoding agrees with the specification that defines it.**
  Base58 and Base58Check against Bitcoin Core's vectors and the `base58`
  package's, whose round trips run over the Ripple alphabet too; bech32
  and bech32m against BIP173's and BIP350's; SS58 against Substrate's and
  polkadot-js'; and CashAddr against the specification's own.
  `tests/_data/README.md` says where each file came from, pins every
  vendored one to the upstream commit it was copied from, and says
  whether the two still match, which its *Re-checking a pin* procedure
  re-checks by hand. `.github/workflows/vendored-vectors.yml`
  runs weekly: it holds each vendored file to the `ours` or `blob`
  recorded there and `blob` to upstream's at the pinned commit, and
  reports a pin that is no longer upstream's tip.
- **Malformed input is refused the way the package says it is.** A
  public function handed an argument it cannot use raises
  `Base58Bech32TypeError` or `Base58Bech32ValueError`
  (`tests/input_validation_test.py`, `tests/integer_policy_test.py`,
  `tests/bool_parameter_test.py`, `tests/refusals_test.py`), and a decoder
  handed a hostile string raises one of the
  two and nothing else (`tests/fuzz_test.py`).
- **A published distribution is what this tree built.** SECURITY.md's
  *Supported versions* states how that is verified.

## Threat model

base58-bech32 is a library in its caller's process. It opens no
socket, runs no subprocess and writes no file, and the one file it reads
is its own installed metadata, for `__version__`.
`tests/imports_test.py` holds every module to the standard library, both
as imported and as written.

**What is defended.**

- A secret payload, such as the private key a WIF encodes, against
  recovery from what a refusal prints.
- The correctness of every answer: an encoded string, and the bytes,
  prefix, version or type a decoder returns.
- The caller's process, against a string built to make a decoder raise
  an exception this package does not document.

**The adversaries.**

- A party handing this package a string built to exploit a decoder, or
  to be accepted as another one.
- A party tampering with a distribution between this tree and the user.

**What is not defended**, each stated in SECURITY.md's *Limitations, not
vulnerabilities*:

- side channels: nothing here is constant-time
- memory disclosure: secret material in a Python object is not zeroized
- the checksums `b58decode_check` quotes when its `secret` is false
- the operating system and the interpreter

## Trust boundaries

**The caller and the public API.** Arguments cross from the caller into
base58-bech32 at every public function, and each is validated there.
CONTRIBUTING.md's *The public surface* states the rule and names the
tests that drive it.

**Strings from outside.** An address or a key is typed, scanned or
received from a peer, and every decoder that takes one -- those
`tests/fuzz_test.py` lists -- is driven by Hypothesis there and by
`fuzz/fuzz_codecs.py` under ClusterFuzzLite
(`.github/workflows/fuzz.yml`); `tests/fuzz_corpus_test.py` checks that
the harness calls each of them and that every seed of its corpus is
still read.

## Secure design principles

Saltzer and Schroeder's principles, over the layering `CLAUDE.md`'s
*Architecture* describes.

- **Economy of mechanism.** One module per format, over the coercions of
  `_utils` and the exceptions. `ss58` reuses `base58`'s private
  functions, and `cashaddr` reuses `bech32`'s alphabet and its private
  `_convertbits`, rather than each carrying its own copy.
- **Fail-safe defaults.** A decoder verifies the checksum on every call,
  with no switch to skip it, and every flag refuses a non-bool, `0`,
  `None` and `""` included (`tests/bool_parameter_test.py`).
- **Complete mediation.** Every public function validates its inputs;
  a private twin trusts its inputs because its callers checked them.
- **Open design.** The code, the vendored vectors and the fuzzing corpus
  are published, and SECURITY.md states what is not defended.
- **Least privilege.** The standard library alone, and within it no
  network, no subprocess, no file written.
- **Psychological acceptability.** A refusal is one of the package's two
  exception classes, each beside the built-in of its name, so a caller
  catching `ValueError` or `TypeError` catches it too.

## Common implementation weaknesses

Weaknesses from MITRE's CWE list that a package of this kind is exposed
to, and what counters each.

- **Improper input validation (CWE-20).** The trust boundaries above, and
  `tests/integer_policy_test.py`, which refuses a `bool` where an
  integer field -- a size, a 5-bit value, an SS58 prefix, a CashAddr
  type -- is expected.
- **Uncaught exceptions on hostile input (CWE-248, CWE-755).**
  `tests/fuzz_test.py`'s contract, driven by Hypothesis and by
  ClusterFuzzLite.
- **Uncontrolled resource consumption (CWE-400).** Base58 decoding is
  quadratic in the string's length, so `b58decode_check` refuses a string
  over `MAX_LENGTH` characters and `ss58_decode` one over the longest an
  SS58 address can be. Plain `b58decode` has no cap, as the `base58`
  package has none.
- **Exposure of sensitive information (CWE-209).** No decoder's refusal
  quotes the string it was handed, and the one refusal that quotes a
  hash of the payload, `b58decode_check`'s checksum mismatch, quotes
  nothing when its `secret` is true (`tests/refusals_test.py`).
  The rule is section 7's *A refusal carries no secret* in the
  [btclib-org standard](https://github.com/btclib-org/.github#a-refusal-carries-no-secret).
  Its helper, `assert_secret_free` in `tests/secret_free/__init__.py`, is
  called by each test of `tests/refusals_test.py` that feeds a secret, with
  the spellings its refusal could print. It reads each exception the
  refusal chains.
- **Type confusion (CWE-843).** mypy runs with `strict = true` over the
  package and the suite, as a hook of the lint gate.
- **Code that is wrong and still passes.** Line and branch coverage is
  held at 100% by `fail_under` in `pyproject.toml`, and mutation testing,
  profiled per codec under `.github/mutation/` and run by
  `.github/workflows/mutation.yml`, asks whether the suite notices a
  wrong line.
- **Supply chain.** SECURITY.md's *Supported versions* describes the
  attestations and the bill of materials. The runtime has no dependency;
  `uv.lock` pins the tools and the test oracles, and every third-party
  action is pinned to a commit sha.
