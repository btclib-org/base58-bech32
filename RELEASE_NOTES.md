# Release notes

Notable changes are documented here.
[CHANGELOG.md](./CHANGELOG.md) is the record behind them: this file says
what a user has to act on, that one says what changed.

Versions are *[calendar versions](https://calver.org/)*, `YYYY.M.D`: the
number says when a release was cut, and promises nothing about
compatibility, so a breaking change is announced in this file — read it
before upgrading, rather than a digit.

## v2026.10.18

The first release of `base58-bech32`: Base58, Base58Check, bech32, bech32m,
SS58 and CashAddr, on the standard library alone. There is no earlier
version of it to upgrade from.

Coming from the `base58` or the `bech32` package, it is not a drop-in: a
`str` to encode is read as hex, a string to decode is not stripped, and
every optional argument but `convertbits`'s `pad` is keyword-only.
[The migration page](https://base58-bech32.readthedocs.io/en/latest/migration.html)
gives each of their public names its equivalent here, or says there is
none.

The release attaches the wheel, `base58_bech32-2026.10.18-py3-none-any.whl`,
the sdist, `base58_bech32-2026.10.18.tar.gz`,
`base58_bech32-2026.10.18.cdx.json` and `v2026.10.18.intoto.jsonl`;
*Supported versions* in [SECURITY.md](./SECURITY.md) has the
`gh attestation verify` command.
