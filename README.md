# base58-bech32

Base58, Base58Check, bech32, bech32m, SS58 and CashAddr: the
binary-to-text codecs of cryptocurrency addresses and keys, in typed
Python, with nothing of any chain above them.

<!-- The badges are what the reader decides with, in three groups: what the
software is and whether it can be used, whether it works, and what the
OpenSSF makes of it.

Inside the second group the gates come first, in the order a commit meets
them, and the sentinels follow in the order section 10 of the organization
standard schedules them -- the badge order *is* the calendar order over
that subset, which is why the two move together or not at all. The day and
hour each sentinel owns live in that section and are not copied here: a
reader wanting the schedule reads it there, where it is still true.

One badge per line keeps a change to one line and every line inside MD013,
whose 80 columns bind only where a space follows them.

A badge that reports no state -- "we use ruff", "we use uv" -- reports a
choice instead, and those are in CONTRIBUTING.md, beside the prose that
says how the choice is enforced.
-->
[![PyPI version](https://img.shields.io/pypi/v/base58-bech32.svg?logo=pypi)](https://pypi.org/project/base58-bech32/)
[![GitHub release](https://img.shields.io/github/v/release/btclib-org/base58-bech32.svg)](https://github.com/btclib-org/base58-bech32/releases)
[![development status](https://img.shields.io/pypi/status/base58-bech32.svg)](https://pypi.org/project/base58-bech32/)
[![license](https://img.shields.io/github/license/btclib-org/base58-bech32.svg)](https://github.com/btclib-org/base58-bech32/blob/main/LICENSE)
[![downloads](https://static.pepy.tech/badge/base58-bech32)](https://pepy.tech/projects/base58-bech32)
[![supported Python versions](https://img.shields.io/pypi/pyversions/base58-bech32.svg?logo=python)](https://pypi.org/project/base58-bech32/)
[![implementation](https://img.shields.io/pypi/implementation/base58-bech32.svg)](https://pypi.org/project/base58-bech32/)
[![wheel](https://img.shields.io/pypi/wheel/base58-bech32.svg)](https://pypi.org/project/base58-bech32/)

[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/btclib-org/base58-bech32/main.svg)](https://results.pre-commit.ci/latest/github/btclib-org/base58-bech32/main)
[![lint workflow status](https://github.com/btclib-org/base58-bech32/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/btclib-org/base58-bech32/actions/workflows/lint.yml?query=branch%3Amain)
[![test workflow status](https://github.com/btclib-org/base58-bech32/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/btclib-org/base58-bech32/actions/workflows/test.yml?query=branch%3Amain)
[![docs workflow status](https://github.com/btclib-org/base58-bech32/actions/workflows/docs.yml/badge.svg?branch=main)](https://github.com/btclib-org/base58-bech32/actions/workflows/docs.yml?query=branch%3Amain)
[![documentation build](https://app.readthedocs.org/projects/base58-bech32/badge/?version=latest)](https://base58-bech32.readthedocs.io)
[![vendored-vectors workflow status](https://github.com/btclib-org/base58-bech32/actions/workflows/vendored-vectors.yml/badge.svg?branch=main)](https://github.com/btclib-org/base58-bech32/actions/workflows/vendored-vectors.yml?query=branch%3Amain)
[![mutation workflow status](https://github.com/btclib-org/base58-bech32/actions/workflows/mutation.yml/badge.svg?branch=main)](https://github.com/btclib-org/base58-bech32/actions/workflows/mutation.yml?query=branch%3Amain)
[![fuzz workflow status](https://github.com/btclib-org/base58-bech32/actions/workflows/fuzz.yml/badge.svg?branch=main)](https://github.com/btclib-org/base58-bech32/actions/workflows/fuzz.yml?query=branch%3Amain)
[![deps-latest workflow status](https://github.com/btclib-org/base58-bech32/actions/workflows/deps-latest.yml/badge.svg?branch=main)](https://github.com/btclib-org/base58-bech32/actions/workflows/deps-latest.yml?query=branch%3Amain)
[![pypi-install workflow status](https://github.com/btclib-org/base58-bech32/actions/workflows/pypi-install.yml/badge.svg?branch=main)](https://github.com/btclib-org/base58-bech32/actions/workflows/pypi-install.yml?query=branch%3Amain)
[![deps-oldest workflow status](https://github.com/btclib-org/base58-bech32/actions/workflows/deps-oldest.yml/badge.svg?branch=main)](https://github.com/btclib-org/base58-bech32/actions/workflows/deps-oldest.yml?query=branch%3Amain)
[![os-macos workflow status](https://github.com/btclib-org/base58-bech32/actions/workflows/os-macos.yml/badge.svg?branch=main)](https://github.com/btclib-org/base58-bech32/actions/workflows/os-macos.yml?query=branch%3Amain)
[![os-ubuntu workflow status](https://github.com/btclib-org/base58-bech32/actions/workflows/os-ubuntu.yml/badge.svg?branch=main)](https://github.com/btclib-org/base58-bech32/actions/workflows/os-ubuntu.yml?query=branch%3Amain)
[![os-windows workflow status](https://github.com/btclib-org/base58-bech32/actions/workflows/os-windows.yml/badge.svg?branch=main)](https://github.com/btclib-org/base58-bech32/actions/workflows/os-windows.yml?query=branch%3Amain)
[![links workflow status](https://github.com/btclib-org/base58-bech32/actions/workflows/links.yml/badge.svg?branch=main)](https://github.com/btclib-org/base58-bech32/actions/workflows/links.yml?query=branch%3Amain)
[![sdist-rebuild workflow status](https://github.com/btclib-org/base58-bech32/actions/workflows/sdist-rebuild.yml/badge.svg?branch=main)](https://github.com/btclib-org/base58-bech32/actions/workflows/sdist-rebuild.yml?query=branch%3Amain)
[![codeql workflow status](https://github.com/btclib-org/base58-bech32/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/btclib-org/base58-bech32/actions/workflows/codeql.yml?query=branch%3Amain)

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/btclib-org/base58-bech32/badge)](https://scorecard.dev/viewer/?uri=github.com/btclib-org/base58-bech32)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15632/badge)](https://www.bestpractices.dev/projects/15632)
[![OpenSSF Baseline](https://www.bestpractices.dev/projects/15632/baseline)](https://www.bestpractices.dev/projects/15632)

It is fully annotated and ships `py.typed`, and it imports nothing
but the standard library.

## What is here

- Base58, plain and checked: Bitcoin's alphabet, Ripple's, or any other
  58 distinct ascii bytes, and Base58Check's double SHA-256 checksum
  (`base58`)
- [bech32](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki)
  and [bech32m](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki),
  with no length limit, and `convertbits`, the regrouping of bytes into
  5-bit values and back (`bech32`)
- SS58, the address format of Polkadot and the Substrate chains, with
  both prefix forms (`ss58`)
- [CashAddr](https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md),
  the address format of Bitcoin Cash (`cashaddr`)

Every refusal is a `ValueError` or a `TypeError`, under one base,
`Base58Bech32Exception` (`exceptions`). No decoder's refusal quotes the
string it was handed: what reaches a decoder can be a private key.

What the bytes mean -- a witness program, a public key hash, a WIF -- is
not here: [btclib](https://github.com/btclib-org/btclib) is the library
above this one for bitcoin.
[The migration page](https://base58-bech32.readthedocs.io/en/latest/migration.html)
maps each function of the `base58` and `bech32` packages to its
equivalent here.

The suite answers to vectors their authors publish -- Bitcoin Core's,
the `base58` package's, Substrate's and the CashAddr specification's --
and [tests/_data/README.md](./tests/_data/README.md) pins each vendored
file to the upstream commit it was copied from.

## Installing

```shell
python -m pip install --upgrade base58-bech32
```

## An address of each format

```python
from base58_bech32 import base58, bech32, cashaddr, ss58

wif = base58.b58encode_check(bytes.fromhex("80" + "11" * 32 + "01"))
assert base58.b58decode_check(wif, out_size=34)[0] == 0x80

hrp, values = bech32.bech32_decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
program = bytes(bech32.convertbits(values[1:], 5, 8, False))
assert (hrp, values[0], program.hex()[:8]) == ("bc", 0, "751e76e8")

alice = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
prefix, account = ss58.ss58_decode(alice)
assert prefix == 42
polkadot = ss58.ss58_encode(0, account)
assert polkadot == b"15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5"

address = "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2"
assert cashaddr.cashaddr_decode(address)[:2] == ("bitcoincash", 0)
```

`tests/readme_test.py` runs every Python block of this file, so the
example above is the one the suite checks.

## Security

[SECURITY.md](./SECURITY.md) says how to report a vulnerability, which
versions are supported, and how a published file is traced back to the
run that built it.
[ASSURANCE_CASE.md](./ASSURANCE_CASE.md) argues why what it promises
holds: the threat model, the trust boundaries, and the weaknesses a
package of this kind is exposed to.

## Contributing

[CONTRIBUTING.md](./CONTRIBUTING.md) has the commands each CI job runs,
verbatim. `uv sync` creates the environment; uv is the only tool that has
to be installed. [REVIEWING.md](./REVIEWING.md) is what a pull request is
answered against.

How the organization decides, and who holds which role, is its
[GOVERNANCE.md](https://github.com/btclib-org/.github/blob/main/GOVERNANCE.md);
what it intends to do, and what it deliberately does not, is its
[ROADMAP.md](https://github.com/btclib-org/.github/blob/main/ROADMAP.md).

## Links

- Documentation: <https://base58-bech32.readthedocs.io/>
- Source: <https://github.com/btclib-org/base58-bech32>
- Releases: <https://github.com/btclib-org/base58-bech32/releases>
- [CHANGELOG.md](./CHANGELOG.md), and [RELEASE_NOTES.md](./RELEASE_NOTES.md)
  for what a release asks a user to act on

---

The btclib organization and its projects are actively supported by
[DGI](https://dgi.io) and [CheckSig](https://checksig.com).
