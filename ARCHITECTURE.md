# Architecture

The package is layered bottom-up. `exceptions` is the base: it imports
nothing, and `_utils`, `base58`, `bech32`, `ss58` and `cashaddr` raise its
errors. `_utils` holds the private argument checks and coercions, and
imports `exceptions` only.

`base58` and `bech32` are the two codecs. Each imports `_utils` and
`exceptions`, and neither imports the other. `ss58` builds on `base58`
and reuses its alphabet, encoder and decoder; `cashaddr` builds on `bech32` and
reuses its alphabet and bit regrouping. `ss58` and `cashaddr` do not
import each other, nor the codec they do not build on.

`__init__` imports no module of the package: it loads one when it is
first asked for.

`tests/imports_test.py` holds this rule. Its `_LAYERS` table is the
list of what each module may import, read against the import statements
of every file in `src/base58_bech32/`.
