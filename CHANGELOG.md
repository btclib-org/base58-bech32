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
