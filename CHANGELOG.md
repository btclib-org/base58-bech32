# Changelog

<!-- markdownlint-configure-file
  {
    // MD024/no-duplicate-heading - every release repeats the same few
    // headings, which is what keeps the page readable scrolling down it;
    // only a duplicate under the same release heading would be the
    // accident this rule looks for
    "MD024": { "siblings_only": true }
  }
-->

The release's own pull request writes its section here, from the squash
subjects since the previous tag; a pull request adds no entry
(`CONTRIBUTING.md`'s *Pull requests*, section 9 of [the organization
standard][std]). [RELEASE_NOTES.md](./RELEASE_NOTES.md) has the release
notes, which say what a user has to act on; this file is the record
behind them.

[std]: https://github.com/btclib-org/.github

## v2026.11.11

### A refusal describes an int by its sign and bit length

A name too long to quote, such as an HRP or a CashAddr prefix, is described
by its length (closes #118) (closes #119).

### The tests pass `b58decode_check`'s `out_size` in more types

An IntEnum, a float and a huge int are tested (closes #115).

### btclib-org/.github's reusable workflows are called at v2026.11.12

`reusable-claude-release.yml` is called by hand (issue
btclib-org/.github#2001).

### The README's status badges are a Status section at its end

The README links its own files absolutely, and the badge comment and
`scorecard.yml` cite the organization standard (issue btclib-org/.github#1856,
btclib-org/.github#1851).

### The tree takes btclib-org/.github's shared text and names its standard

`CONTRIBUTING.md`, `RELEASING.md`, `REVIEWING.md` and the shared configs
take it (#120) (#125) (issue btclib-org/.github#2088,
btclib-org/.github#2107, btclib-org/.github#2137, btclib-org/.github#2145).

### The bestpractices.dev answers are held in the tree, and corrected

`.bestpractices.json` holds them (issue btclib-org/.github#2153,
btclib-org/.github#2159).

### The tests take the shared `secret_free` helper from btclib-org/.github

(issue btclib-org/.github#1950).

### The actions, the dev tooling and the pre-commit hooks are updated

(#121) (#122) (#123).

## v2026.11.7

### `bech32_decode`'s docstring states the checksum's bounds per constant

The bounds hold for the constant passed as `m`; with `m=None` only the
single-change guarantee holds (closes #79).

### The tests cover the checksum's detection bounds and the length limit

Every detection-bound pattern is tested, and the fuzz tests draw the limit
around the string's length (closes #76) (closes #15).

### A release is verified by repository id, its signer named without a ref

`SECURITY.md`'s `gh attestation verify` takes `--owner btclib-org` and
compares the certificate's repository id, which a rename keeps (closes #57).

### btclib-org/.github's reusable workflows are called at a tagged commit

Every call names the commit of the tag v2026.11.5 (issue
btclib-org/.github#1870, btclib-org/.github#1988, btclib-org/.github#2005).

### The homepage is `https://btclib.org/base58-bech32/`

The documentation stays at `https://base58-bech32.readthedocs.io/`
(closes #83).

### `ARCHITECTURE.md` describes the package's layers

`tests/imports_test.py` checks each module's imports against them
(closes #62).

### The coverage floor measures `.github/scripts`

A run that leaves it unmeasured is refused (closes #91) (closes #95).

### Sourcery and CodeRabbit review pull requests; macOS runs on arm64 alone

`check-executables-have-shebangs` is on too (issue btclib-org/.github#1982,
btclib-org/.github#1998, btclib-org/.github#2005, btclib-org/btclib#2852).

### `CONTRIBUTING.md` and `REVIEWING.md` follow btclib-org/.github

(#84) (issue btclib-org/.github#1846, btclib-org/.github#1904,
btclib-org/.github#1919, btclib-org/.github#2004, btclib-org/.github#2022,
btclib-org/.github#2051, btclib-org/.github#2054).

### `RELEASING.md` is shared up to this tree's own section

It names the lint jobs a release run skips (issue btclib-org/.github#1855,
btclib-org/.github#1989).

### `check_vendored_vectors.py` names the functional-tests repository

Its docstring names it as it is now (closes #82) (closes #89).

### `scorecard.yml` drops its claim to be the one workflow without a dispatch

Its comment says why it takes no `workflow_dispatch` (closes #102).

### The tools move past their advisories

`uv.lock` takes setuptools and filelock past theirs, the publish action is
v1.14.3, and uv below 0.13.4 refuses to run here (issue
btclib-org/.github#1844, btclib-org/.github#1849).

### `dependabot.yml` names the `uv.lock` exception and `uv_build`'s ceiling

Its comment says what moves `uv.lock` (issue btclib-org/.github#1818,
btclib-org/.github#1848).

### The locked and pinned tools move

The dev-tooling group, `uv_build` with the check-sdist hook's ceiling, the
actions and the hook revisions (closes #54)
(#60, #67, #71, #72, #73, #77, #78, #92, #100, #101).

## v2026.10.23

### `bech32_decode` returns the constant that verified

It returns `(hrp, data, m)`, and with `m=None` accepts either constant; a
refusal under one constant says when the other verifies (closes #10)
(closes #11).

### `b58decode_check` refuses a mismatch without quoting a checksum

The message is "invalid checksum" and the `secret` parameter is removed
(closes #28).

### Length limits on bech32 and `b58decode`

`bech32_decode` and `bech32_encode` take `limit`, 1023 by default, and
`b58decode` takes `max_length` (closes #8) (closes #9).

### `bech32_encode_bytes` and `bech32_decode_bytes`

They encode and decode a payload of bytes without `convertbits`
(closes #19).

### `convertbits` refuses a width above 64

Either width, `from_bits` or `to_bits`, above 64 raises
`Base58Bech32ValueError` (closes #38).

### Alphabet validation shares the cache; decoding and checks are faster

Alphabet validation shares the tables' cache, short Base58 strings
decode digit by digit, and bech32 and CashAddr check in one pass
(closes #20) (closes #21) (closes #22) (closes #23) (closes #24) (closes #25).

### Checksums are compared with `hmac.compare_digest`

`b58decode_check` and `ss58_decode` do (closes #12).

### The docstrings and the migration page say what the decoders accept

Whitespace, a finite iterable and the QR form are documented (closes #16)
(closes #17) (closes #18), and `bytes_from_octets` says which whitespace
`bytes.fromhex` skips (#7).

### The tests cover the peers' refusals and folded characters

The peers' negative vectors, characters that fold onto ASCII and the QR
triple are asserted (closes #13) (closes #14) (closes #37) (issue #15).

### The shared `secret_free` helper checks grouped secrets

The refusal's text is searched for a secret printed in groups
(issue btclib-org/.github#1697).

### `REPOSITORY.md` records `main-self-merge` without its bypass

The maintainer removed it after the first release (closes #4).

### The locked and pinned tools move

`aiohttp`, `certifi`, `virtualenv` and GitPython in `uv.lock`, the hook
revisions and the dev-tooling group (closes #41) (#46, #47, #53,
issue btclib-org/.github#1824, issue btclib-org/.github#1835).

### `claude-review.yml` declines zizmor's dangerous-triggers

The ignore is on the `issue_comment` trigger, with its reason above it
(issue btclib-org/.github#1813).

### `AGENTS.md` replaces `CLAUDE.md`

`AGENTS.md` holds the guidance for any coding agent, `CLAUDE.md` is
removed and `CONTRIBUTING.md` gains the worktree steps; `test.yml` treats
`AGENTS.md` as prose (issue btclib-org/.github#1808).

## v2026.10.18

### The repository opens with btclib's codecs and new ones

Base58Check, bech32, bech32m and `convertbits`, taken from btclib, and new
plain Base58, SS58 and CashAddr codecs, with no runtime dependency (issue
btclib-org/btclib#2712).

### `REPOSITORY.md` records the settings read back after the first push

The branch protection, the rulesets and the signature setting are read
back, the Claude Code app is installed, and `main-self-merge` carries the
maintainer's bypass until the first release (issue btclib-org/btclib#2712).

### The pinned tool versions move

`astral-sh/setup-uv` 10.3.0 and ruff 0.17.0, and `uv_build` admitted up to
0.13, with `.clusterfuzzlite/requirements.txt` exported again (#1, #2).
