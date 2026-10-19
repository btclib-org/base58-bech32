# Migrating from the `base58` and `bech32` packages

Each public name of the [`base58`](https://pypi.org/project/base58/)
2.1.1 and [`bech32`](https://pypi.org/project/bech32/) 1.2.0 packages,
and `base58`'s console script, with its equivalent here.
`tests/migration_test.py` runs both sides of each entry that has an
equivalent on the same inputs, and checks that the page names every
public name of the two packages.

Every refusal here is a `Base58Bech32ValueError` or a
`Base58Bech32TypeError`, subclasses of `ValueError` and `TypeError`.
Every optional argument here is keyword-only, `convertbits`'s `pad`
excepted.

## `base58`

Each name on the left is the `base58` package's, and the call after the
arrow is this package's.

- `BITCOIN_ALPHABET`, `alphabet` → `BITCOIN_ALPHABET`
- `RIPPLE_ALPHABET`, `XRP_ALPHABET` → `RIPPLE_ALPHABET`
- `b58encode(v, alphabet)` → `b58encode(v, alphabet=alphabet)`
- `b58decode(v, alphabet)` → `b58decode(v, alphabet=alphabet)`
- `b58encode_check(v, alphabet)` → `b58encode_check(v, alphabet=alphabet)`
- `b58decode_check(v, alphabet)` → `b58decode_check(v, alphabet=alphabet)`
- `b58decode_int(v, alphabet)` →
  `int.from_bytes(b58decode(v, alphabet=alphabet), "big")`
- `b58encode_int(i, default_one=False)` →
  `b58encode(i.to_bytes((i.bit_length() + 7) // 8, "big"))`
- `scrub_input(v)` → not needed: the decoders take a str or ascii bytes
  directly
- the `base58` console script → not here: there is no command line

Where the two differ:

- **A str to encode is hex here.** `b58encode("00ff")` encodes the bytes
  `00 ff`, where `base58` encodes the four ascii characters.
- **Nothing is stripped.** `base58`'s decoders drop trailing whitespace
  and refuse it elsewhere; here it is refused wherever it stands, unless
  the alphabet holds it. Both refuse NUL.
  `b58decode(v.rstrip())` reads what `base58` reads. Bitcoin Core's
  `DecodeBase58` differs too: the `b58decode` docstring says how.
- **The alphabet is 58 distinct ascii bytes.** `base58` takes any alphabet,
  Base45's included.
- **No `autofix`.** `base58`'s `autofix=True` reads "0" and "O" as "o",
  and "I" and "l" as "1", where the alphabet lacks them; here they are
  invalid characters.
- **`b58decode_check` is capped** at `MAX_LENGTH`, 112 characters, and
  takes `out_size`, the payload size required. `b58encode_check` takes
  `in_size`.
- **`b58encode_int(i)`** with its default `default_one=True` writes zero
  as the alphabet's first character, where the `b58encode` above writes
  nothing.

## `bech32`

Each name on the left is the `bech32` package's, and the call after the
arrow is this package's.

- `bech32_encode(hrp, data)` →
  `bech32_encode(hrp, data, m=BECH32_1_CONST).decode()`
- `bech32_decode(bech)` → `bech32_decode(bech, m=BECH32_1_CONST)[:2]`
- `convertbits(data, frombits, tobits, pad)` →
  `convertbits(data, frombits, tobits, pad)`
- `bech32_verify_checksum`, `bech32_create_checksum` → not published:
  `bech32_decode` verifies the checksum and `bech32_encode` appends it
- `bech32_polymod`, `bech32_hrp_expand`, `CHARSET` → not published
- `encode(hrp, witver, witprog)`, `decode(hrp, addr)` → not here: segwit
  addresses are bitcoin, and btclib's `b32`

Where the two differ:

- **This package raises where `bech32_decode` returns `(None, None)`**,
  and where `convertbits` returns `None`. The message says why.
- **`bech32_encode` answers ascii bytes**, as `base64` does, and refuses an
  HRP that is empty, out of BIP173's range or not lowercase, and a value
  that is not a 5-bit digit, which `bech32` writes or raises an
  `IndexError` for.
- **`data` is a list**, and `m` is `None` or one of the two constants;
  anything else is refused.
- **bech32m.** `m=BECH32_M_CONST` is BIP350's bech32m, which `bech32` 1.2.0
  does not have, and `bech32` always means `BECH32_1_CONST`. Without `m`,
  `bech32_encode` reads it off the first value, as a witness version, and
  `bech32_decode` accepts either constant.
- **`bech32_decode` returns `(hrp, data, m)`**, `m` being the constant the
  checksum verifies with.
- **No length limit.** BIP173 caps a string at 90 characters and its HRP
  at 83, and `bech32_decode` refuses an HRP over 83. Here neither is
  bounded, by decision: BOLT11's Lightning invoices are longer than 90.
