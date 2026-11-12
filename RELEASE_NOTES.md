# Release notes

Notable changes are documented here.
[CHANGELOG.md](./CHANGELOG.md) is the record behind them: this file says
what a user has to act on, that one says what changed.

Versions are *[calendar versions](https://calver.org/)*, `YYYY.M.D`: the
number says when a release was cut, and promises nothing about
compatibility, so a breaking change is announced in this file — read it
before upgrading, rather than a digit.

## v2026.11.13

A caller of `v2026.11.12` that matches the text of the refusal changed
below, that passes a str, bytes, bytearray or list subclass whose own
methods it relies on, or that passes an object claiming a type it is not,
breaks. griffe and `api_gaps.py` find no break in the public API against
it.

- `cashaddr_decode` refuses a payload whose length is not the one its
  version byte gives with no size read from that byte:
  `invalid CashAddr hash size: 31 bytes instead of 64` reads
  `invalid CashAddr hash size: 31 bytes, not the version byte's`.
- A str, bytes or bytearray subclass is read by its base type's methods,
  so a method the subclass overrides, such as `encode`, `lower`,
  `__bytes__` or `__ne__`, does not decide what is encoded, decoded or
  compared. This holds for the string given to `b58decode`,
  `b58decode_check` and `ss58_decode`, `cashaddr_decode`'s and
  `cashaddr_encode`'s prefix, `bech32_encode`'s HRP, and octets given as
  a bytes or bytearray subclass. `cashaddr_decode` returns the prefix as
  a plain str.
- A Base58 alphabet given as a bytes subclass is copied to plain bytes
  before it is checked and cached, so it no longer decides the tables
  later calls read. `bech32_encode` copies a list subclass before it
  checks the items.
- A type test reads the object's own class, not its `__class__`: an
  object that claims a type it is not, such as `Mock(spec=bytes)`, is
  refused with a `Base58Bech32TypeError`, where `v2026.11.12` refused it
  with a built-in `TypeError` or a `Base58Bech32ValueError`, or took it
  as input: a true `pad`, or a `MagicMock(spec=bytes)` as empty bytes.

## v2026.11.12

A caller of `v2026.11.7` that matches the text of a refusal changed below
breaks. griffe and `api_gaps.py` find no break in the public API against it.

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
- `ss58_decode` refuses a prefix with no value read from the string, so a
  key pasted as an address has none of its bytes printed:
  `invalid SS58 prefix byte: 200` reads `invalid SS58 prefix byte`,
  `invalid SS58 prefix: 4 in the two-byte form` reads
  `invalid SS58 prefix: a one-byte prefix in the two-byte form`, and
  `reserved SS58 prefix: 46` reads `reserved SS58 prefix`.
- The bech32 and CashAddr decoders read the string they decode, given as a
  str subclass, as the plain str of its characters, so a method the
  subclass overrides, such as `lower`, does not decide what they read
  from it.
- The release's certificate names the commit of btclib-org/.github's
  v2026.11.12, which `release.yml` calls. The `gh attestation verify`
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
