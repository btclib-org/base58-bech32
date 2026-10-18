# Vendored test vectors

This file is about `tests/_data/`: an entry pins where a file came from and
whether our copy still matches it, and a test module names its upstream
and points here for the revision. A citation that names the wrong
upstream is corrected in the module; this file is not where that
correction lives.

## Naming

A vendored file carries the name its upstream publishes it under, wherever
upstream publishes a file at all. A name of our own has no upstream name
to be compared against, so the citation in the module that loads it can
drift to a path upstream never had and nobody catches it -- the byte
comparison below is the only check the naming cannot fool.

The files that keep a name of their own are transcriptions: upstream
holds its vectors inside a test source or a specification, and there is
no upstream file of their shape whose name they could take.

## Reading an entry

Where an entry pins to a commit, it gives the upstream repository, the
path in it, and the commit. A `blob` line gives the git blob SHA-1 of
what that entry pins. An `ours` line gives the blob of the file kept here
where that is not the `blob`: a transcription. Each entry closes on a
verdict:

- **identical** -- our file and the upstream blob are the same bytes.
- **transcribed** -- the values of an upstream source written out as
  JSON; the entry says what was taken and what was left.

`pulled` is the date the file was taken. `behind` counts upstream
revisions of that path since the pin. It is a staleness figure, not a
defect: a vector file is a fixed set of cases and refreshing it is a
decision, not a chore.

A vector this package fails is vendored anyway and marked `xfail`, never
left out: an absent vector hides the defect it would have shown, and
`xfail_strict` turns the marker red the day the defect is fixed. A vector
this package refuses by design is vendored too, and its test asserts the
refusal.

## Re-checking a pin

The commit stands in a fence of its own, sitting inside the API path
rather than at the end of the command; the fence below reads it as
`${commit:?}`, the shell's must-be-set form, so a paste of that fence
alone fails naming the variable.

```shell
commit=<the pin the entry gives>
```

```shell
git hash-object tests/_data/base58_encode_decode.json
f=src/test/data/base58_encode_decode.json
gh api "repos/bitcoin/bitcoin/contents/$f?ref=${commit:?}" --jq .sha
```

The comparison is on git blob SHA-1, not sha256: it is what a tree entry
already carries, so nothing has to be downloaded, and `git hash-object`
reproduces it locally.

`.github/workflows/vendored-vectors.yml` runs weekly, for every entry
whose heading is one file's path and which carries a `blob` or an `ours`
line. It holds the file to `ours` (or `blob`), holds `blob` to upstream's
at `commit`, and fails, naming the file, on a mismatch: a file edited here
and a pin whose blob is not the one at its commit both fail. It also
reports an entry whose upstream moved past the pin. Add an `ours` line to
a new entry whose file is not upstream's bytes, and a `-text` line for the
file to `.gitattributes`.

## bitcoin/bitcoin

### `tests/_data/base58_encode_decode.json`

```text
repo    bitcoin/bitcoin
path    src/test/data/base58_encode_decode.json
commit  5dd3a0d8a899e4c7263d5b999135f4d7584e1244  2025-01-04
blob    7255fd45c8003ad99ee95c507d8c54f49b50e4c2
pulled  2026-10-17
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. Rows of `[hex, base58]`: Core's
`EncodeBase58`/`DecodeBase58`, the codec with no checksum on it, so what
reads them is `b58encode`/`b58decode` and not the checked pair -- one row
is 256 bytes, 348 base58 characters, which `b58decode_check` would refuse
on `MAX_LENGTH`. btclib carries the same file, at the same pin.

### `tests/_data/bech32_core_invalid_vectors.json`

```text
repo    bitcoin/bitcoin
path    src/test/bech32_tests.cpp
commit  7fcaccd9d0b7b9ec80b8224239aeb3c13b90593d  2026-08-28
blob    3b66606530942aa78c2c7211d10cba5356a0d9a6
ours    bd7ecc12e792e88109a065814c9e396d518483a6
pulled  2026-10-18
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**. The `CASES` and `ERRORS` of
`bech32_testvectors_invalid` and `bech32m_testvectors_invalid`, paired as
`[string, Core's error, where it locates it]`. A byte above 127 is written as
the code point of that value. Not taken: the valid vectors, which
`tests/bech32_test.py` carries from the specifications, and `LocateErrors`'s
positions, which this package does not compute.

Core refuses a string over its character limit and this package has no limit,
so its over-long vector with a valid checksum is read, and its test marks it
`xfail`.

## Other projects

### `tests/_data/base58_package_vectors.json`

```text
repo    keis/base58
path    test_base58.py
commit  04e0182bc83d1f6c2e4edc6be330f50492791ba8  2021-10-27
blob    d458c9a2333d98686c48620426e497e92b4a9b44
ours    622d0c7ea8986abfa4c977ec5b34e2581ad41fba
pulled  2026-10-17
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**. The known answers of the `base58` package's
tests, each under the name of the function it tests: the encodings and
decodings of "hello world", with leading zeros and empty, the checked
encoding and its corrupted twin, the integer of the whole alphabet, and
the backspace refused. Bytes are written as hex.

Not taken, being no fixed value: the round trips over every short string
and the random benchmarks, which `tests/base58_test.py` runs as its own
loop and hypothesis test. Not taken either, being what this package does
not do: `autofix`, and the Base45 alphabet, whose refusal
`tests/migration_test.py` measures.

### `tests/_data/fixtures.json`

```text
repo    bitcoinjs/bech32
path    src/test/fixtures.json
commit  8307501d91ac0cd7d93d55a0aefbe415148cdbbe  2021-02-15
blob    5925eb74db28404aceba011553f7035bf6b7e9fa
pulled  2026-10-18
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. Each invalid string and each invalid `prefix` with
`words` comes with the message bitcoinjs expects, and `fromWords` has its
padding refusals. `tests/refusals_test.py` asserts the refusal of each,
and that a valid string is refused under the other constant. The strings
over bitcoinjs's length limit are read by this package, which has none.

### `tests/_data/ss58_encode_vectors.json`

```text
repo    polkadot-js/common
path    packages/util-crypto/src/address/encode.spec.ts
commit  8d3cb0eb6b7f586514f42a1a529724bded866412  2026-03-12
blob    d7932317fc93a8be50000bad6b8e06d2dd9a4596
ours    7df2f15e562bac7bd7b4330906d8fbaa17f55e43
pulled  2026-10-17
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**. polkadot-js's encode vectors as
`[prefix, payload hex, address]`: Alice's ed25519 key under prefixes 42
and 255, Alice's sr25519 key re-encoded under 2 and 0, a 33-byte key, and
the table polkadot-js checks against Subkey, Substrate's command-line
tool. The 1-, 2-, 4- and 8-byte payloads are under `encode_short_payload`,
the 30-byte key under `encode_invalid_payload`, and the refused prefixes
under `encode_invalid_prefix`. A re-encoded address is given as the
payload it decodes to, `ALICE_PUBLIC_SR`, which `decode.spec.ts` asserts,
and the default prefix of `encodeAddress` as 42, which is `defaults.ts`'s.

The short payloads are account indices, which Substrate's `Ss58Codec`
does not decode and this package refuses: `tests/ss58_test.py` asserts
the refusal of each.

### `tests/_data/ss58_decode_vectors.json`

```text
repo    polkadot-js/common
path    packages/util-crypto/src/address/decode.spec.ts
commit  8d3cb0eb6b7f586514f42a1a529724bded866412  2026-03-12
blob    b2fce07a08022fb19a276114666f0c2d0c67b164
ours    a5c41b666aac87132c03fc043bf6ff905a5391df
pulled  2026-10-17
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**. polkadot-js's decode vectors as
`[address, payload hex]`, with the address its prefix-255 test compares
to, the council address's `modlpy/trsry` padded with zeros to 32 bytes,
and the strings it refuses: a wrong length, wrong checksums and an
"I". Not taken: the hex and byte inputs `decodeAddress` passes through,
which are no SS58.

### `tests/_data/cashaddr_vectors.json`

```text
repo    bitcoincashorg/bitcoincash.org
path    spec/cashaddr.md
commit  a86ce75cbdce8b14fa90b2315ebc7f0d78e6c9cb  2018-12-13
blob    c2c798b5bdefd68ba5aa6482440ddcda4531cc70
ours    e1a4b61a20b0a03079632e9583f73665bdf069fc
pulled  2026-10-17
behind  0 revisions; that commit is the tip of the path
```

Verdict: **transcribed**. The specification's tables, read off its
markdown by a script: the checksum vectors, the legacy translations and
the larger test vectors as `[size, type, address, hash hex]`, the hash
lowercased.

## Not vendored as files

- **Substrate's own addresses**, in `tests/ss58_test.py` beside the
  citation of `substrate/primitives/core/src/crypto.rs` and `ecdsa.rs` of
  paritytech/polkadot-sdk, at the commits it names: addresses with no
  payload upstream to transcribe, and a string refused.
- **The bech32 and bech32m strings** of BIP173 and BIP350's reference
  implementation, inline in `tests/bech32_test.py` as btclib carries
  them.
- **The Bitcoin wiki's WIF pair and Ripple's zero account**, inline in
  `tests/base58_test.py`.
- **The refusals of btcd and libbase58, and polkadot-js's `check.spec.ts`
  and `checksum.spec.ts`**, inline in `tests/refusals_test.py` beside the
  citation of each, being a handful of strings each. Read at btcd
  `c615bd70971ac4976de7e7d7f797a23fb0fe9998` (`address/base58/base58_test.go`
  and `address/bech32/bech32_test.go`), at libbase58
  `b1dd03fa8d1be4be076bb6152325c6b5cf64f678` (`tests/decode-*.sh`) and at
  polkadot-js/common `9281daa14c2c2a41708c3489de8770a064525577`, all read on
  2026-10-18. polkadot-js's prefix and ECDSA addresses of `decode.spec.ts` are
  in `ss58_decode_vectors.json` already.

## What is not pinned, and why

- **The suite asks upstream for nothing.** It hashes each pinned file
  offline, against the `ours` or `blob` its entry records, and that is a
  deliberate stopping point: a network call in the test suite would trade
  a documented drift for a flaky one. The weekly `vendored-vectors`
  workflow asks upstream instead: a byte mismatch fails the run, and a pin
  that moved opens an issue.

## Summary

No count here: the lists *are* the fact a number would summarize, and
the tree answers whenever the number is wanted:

```shell
git ls-files 'tests/_data/*' | grep -cv 'README.md'
```

- identical byte for byte: `base58_encode_decode.json` and `fixtures.json`.
- transcribed: `base58_package_vectors.json`, `ss58_encode_vectors.json`,
  `ss58_decode_vectors.json`, `cashaddr_vectors.json` and
  `bech32_core_invalid_vectors.json`.
