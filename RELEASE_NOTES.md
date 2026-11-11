# Release notes

Notable changes are documented here.
[CHANGELOG.md](./CHANGELOG.md) is the record behind them: this file says
what a user has to act on, that one says what changed.

Versions are *[calendar versions](https://calver.org/)*, `YYYY.M.D`: the
number says when a release was cut, and promises nothing about
compatibility, so a breaking change is announced in this file — read it
before upgrading, rather than a digit.

## v2026.11.11

A caller of `v2026.11.7` that matches the text of a refusal below breaks.
griffe and `api_gaps.py` find no break in the public API against it.

- A refusal describes the int it refuses by its sign and bit length,
  where it wrote the int out: `invalid limit: -1 < 0` reads
  `invalid limit: a negative int of 1 bits < 0`, and a 256-bit value
  refused by `convertbits` reads `invalid value: an int of 256 bits`. An
  expected size is written where it fits four bytes, as in
  `20 bytes instead of 21`, and described otherwise. Expected sizes read
  the same whatever iterable holds them: one stands alone, as `21` where
  a list read `[21]`, and several stand in parentheses, as `(21, 22)`
  where a list read `[21, 22]` and a generator `<generator object …>`. A
  refused HRP or CashAddr prefix of at most 16 characters is quoted, as
  `'A'` where it read `A`, and a longer one is given by its length, as
  `a str of length 17`.
- The release's certificate names the commit of btclib-org/.github's
  v2026.11.12, which `release.yml` now calls. The `gh attestation verify`
  command of *Supported versions* in [SECURITY.md](./SECURITY.md) names
  the signer without a ref and verifies this release unchanged.

## v2026.11.7

Nothing breaks a caller of `v2026.10.23`: griffe and `api_gaps.py` find no
break in the public API against it.

- A script that verifies the release's files with the command of
  `v2026.10.23`'s `SECURITY.md` refuses these: it names the signer
  `reusable-build.yml@refs/heads/main`, and this release's certificate
  names the commit of btclib-org/.github that `release.yml` calls. Name the
  signer without a ref, as *Supported versions* in
  [SECURITY.md](./SECURITY.md) does; that command also compares the
  repository by its id, which a rename keeps.
- `bech32_decode` with `m=None` keeps only the single-change guarantee of
  its checksum: three changed characters within 90, and two within 1023,
  can turn a bech32 string into a bech32m one, which then decodes with
  `BECH32_M_CONST` returned. A caller that knows its constant passes it, as
  its docstring says.

## v2026.10.23

These changes break a caller of `v2026.10.18`.

- `bech32_decode` returns `(hrp, data, m)`, where it returned `(hrp, data)`:
  a caller unpacking two values unpacks three. With `m=None` it accepts a
  checksum under either constant and `m` is the one that verified, so a
  caller reading a segwit address compares `m` with the witness version
  itself, as `bech32_decode`'s docstring says. With an explicit `m` that
  does not verify, where the other constant does, the refusal reads
  `invalid checksum: <NAME> verifies` instead of `invalid checksum`. A
  string with no data values decodes, where `m=None` raised "empty data in
  bech32 address".
- `b58decode_check` has no `secret` parameter, and a checksum mismatch is
  refused as `invalid checksum`, quoting neither checksum. A caller passing
  `secret` gets a `TypeError`, and one matching `invalid checksum: 0x...`
  matches `invalid checksum`.
- `bech32_decode` and `bech32_encode` refuse a string longer than 1023
  characters unless the caller passes another `limit`, or `limit=None`.
  A caller reading segwit addresses can pass `limit=90`, BIP173's limit.
- `convertbits` refuses a width above 64 with `Base58Bech32ValueError`,
  where v2026.10.18 converted it. Act on it if you pass one.

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
