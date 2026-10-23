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
