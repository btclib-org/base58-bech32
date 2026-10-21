# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every decoder, on input nobody wrote down.

The rest of the suite is fixed vectors: exactly what conformance needs,
and blind to the malformed strings that never make it into a
specification's test section. This file is the converse. Apart from the
tests at its end, it does not assert that a decoder accepts the right things --
the vectors do that -- but that it *fails the way the package says it
fails*, whatever it is
handed: an IndexError off a short slice or a KeyError off an alphabet
lookup reaches a caller who catches `Base58Bech32ValueError` to reject
bad input and has no reason to expect anything else.

`fuzz/`'s atheris harness asks the same question of the same decoders
for an hour a week; this asks it on every run, for as long as hypothesis
spends on a test. Arbitrary text rarely carries a valid checksum, so the
strings below are also drawn from each format's own alphabet, and from
valid strings with one character changed, which is what reaches the
checksum and the length checks behind the alphabet lookup.

The first of the tests at its end draws its input the way Bitcoin Core's
`bech32_roundtrip` fuzz target does, in `src/test/fuzz/bech32.cpp`: an HRP
of the characters from 33 to 126 less the uppercase letters, and any bytes
regrouped from 8 bits to 5. Core stops at the 90 characters of BIP173's
limit; the sizes here are the rest of the file's, for the reason
`tests/refusals_test.py` gives.

The tests after that one draw a limit of one less than a valid string's
length, the length, or one more, and assert that the first is refused and
the other two accepted. `base_encode_decode.cpp` at bitcoin/bitcoin
4fe28722a5 draws `max_ret_len` from -1 to one past its input's length, and
asserts that a decode with a limit below the decoded length fails. What
corresponds is that a limit below the length refuses. What does not:
Core's `max_ret_len` bounds the decoded bytes, while `max_length` and
`limit` here bound the characters of the string; Core asserts no
acceptance; and a limit below zero is an invalid argument here, where
Core's -1 refuses every input but an empty or blank one.
`b58decode_check` and `ss58_decode` take no limit, only a fixed maximum
length, and are not drawn here.
"""

from __future__ import annotations

import contextlib
import string
from collections.abc import Callable
from functools import partial
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from base58_bech32 import base58, bech32, cashaddr, ss58
from base58_bech32.bech32 import BECH32_1_CONST, BECH32_M_CONST
from base58_bech32.exceptions import (
    Base58Bech32TypeError,
    Base58Bech32ValueError,
)

# what a decoder of this package is allowed to raise. Anything else
# leaves the contract src/base58_bech32/exceptions.py documents
CONTRACT = (Base58Bech32ValueError, Base58Bech32TypeError)

DECODERS: dict[str, Callable[[str | bytes], Any]] = {
    "base58.b58decode": base58.b58decode,
    "base58.b58decode_check": base58.b58decode_check,
    "bech32.bech32_decode": bech32.bech32_decode,
    "bech32.bech32_decode_bytes": partial(
        bech32.bech32_decode_bytes, m=bech32.BECH32_1_CONST
    ),
    "ss58.ss58_decode": ss58.ss58_decode,
    "cashaddr.cashaddr_decode": cashaddr.cashaddr_decode,
}

# every character any of the formats writes, and the separators
_ALPHABET = "".join(
    sorted(
        {
            *base58.BITCOIN_ALPHABET.decode(),
            *"qpzry9x8gf2tvdw0s3jn54khce6mua7l",
            ":",
            "1",
        }
    )
)

# valid strings of each format
_VALID = [
    "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
    "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
]


def _read(decoder: Callable[[str | bytes], Any], text: str | bytes) -> None:
    with contextlib.suppress(*CONTRACT):
        decoder(text)


@pytest.mark.parametrize("name", DECODERS)
@given(text=st.text(max_size=128))
def test_a_decoder_refuses_text_within_the_contract(name: str, text: str) -> None:
    """Arbitrary text is read, or refused as the package's own exception."""
    _read(DECODERS[name], text)


@pytest.mark.parametrize("name", DECODERS)
@given(data=st.binary(max_size=128))
def test_a_decoder_refuses_bytes_within_the_contract(name: str, data: bytes) -> None:
    """Arbitrary bytes, which need be no ascii, the same way."""
    _read(DECODERS[name], data)


@pytest.mark.parametrize("name", DECODERS)
@given(text=st.text(alphabet=_ALPHABET, max_size=128))
def test_a_decoder_refuses_the_alphabets_within_the_contract(
    name: str, text: str
) -> None:
    """Strings of the formats' own characters reach the checksum."""
    _read(DECODERS[name], text)


@pytest.mark.parametrize("name", DECODERS)
@given(
    valid=st.sampled_from(_VALID),
    position=st.integers(min_value=0),
    char=st.sampled_from(_ALPHABET),
)
def test_a_changed_character_is_refused_within_the_contract(
    name: str, valid: str, position: int, char: str
) -> None:
    """One character changed, inserted or removed in a valid string."""
    i = position % len(valid)
    for text in (
        valid[:i] + char + valid[i + 1 :],
        valid[:i] + char + valid[i:],
        valid[:i] + valid[i + 1 :],
    ):
        _read(DECODERS[name], text)


# the HRPs Core's fuzz target draws: [33, 126] less "A" to "Z", which a
# bech32 string writes lowercase
_HRP = st.text(
    alphabet=st.characters(
        min_codepoint=33, max_codepoint=126, exclude_characters=string.ascii_uppercase
    ),
    min_size=1,
    max_size=128,
)


@given(
    hrp=_HRP,
    data=st.binary(max_size=128),
    m=st.sampled_from([BECH32_1_CONST, BECH32_M_CONST]),
)
def test_any_bytes_regrouped_round_trip_under_both_constants(
    hrp: str, data: bytes, m: int
) -> None:
    """Encode, then decode, gives the HRP and the values back, in either case.

    The other constant is a different checksum, which is refused.
    """
    other = BECH32_M_CONST if m == BECH32_1_CONST else BECH32_1_CONST
    name = "BECH32_1_CONST" if m == BECH32_1_CONST else "BECH32_M_CONST"
    values = bech32.convertbits(data, 8, 5)
    text = bech32.bech32_encode(hrp, values, m=m)
    assert bech32.bech32_decode(text, m=m) == (hrp, values, m)
    assert bech32.bech32_decode(text.upper(), m=m) == (hrp, values, m)
    assert bytes(bech32.convertbits(values, 5, 8, False)) == data
    with pytest.raises(
        Base58Bech32ValueError, match=f"^invalid checksum: {name} verifies$"
    ):
        bech32.bech32_decode(text, m=other)


def _limit_message(text: bytes, limit: int) -> str:
    return f"^too many bech32 characters: {len(text)}, limit is {limit}$"


@given(
    hrp=_HRP,
    data=st.binary(max_size=128),
    m=st.sampled_from([BECH32_1_CONST, BECH32_M_CONST]),
    offset=st.integers(min_value=-1, max_value=1),
)
def test_bech32_decode_limit_is_exact_around_the_string_length(
    hrp: str, data: bytes, m: int, offset: int
) -> None:
    """A string is refused one character above the limit and read at it."""
    values = bech32.convertbits(data, 8, 5)
    text = bech32.bech32_encode(hrp, values, m=m, limit=None)
    limit = len(text) + offset
    if offset < 0:
        with pytest.raises(Base58Bech32ValueError, match=_limit_message(text, limit)):
            bech32.bech32_decode(text, m=m, limit=limit)
        with pytest.raises(Base58Bech32ValueError, match=_limit_message(text, limit)):
            bech32.bech32_decode_bytes(text, m=m, limit=limit)
    else:
        assert bech32.bech32_decode(text, m=m, limit=limit) == (hrp, values, m)
        assert bech32.bech32_decode_bytes(text, m=m, limit=limit) == (hrp, data)


@given(
    hrp=_HRP,
    data=st.binary(max_size=128),
    m=st.sampled_from([BECH32_1_CONST, BECH32_M_CONST]),
    offset=st.integers(min_value=-1, max_value=1),
)
def test_bech32_encode_limit_is_exact_around_the_string_length(
    hrp: str, data: bytes, m: int, offset: int
) -> None:
    """A string is refused one character above the limit and written at it."""
    values = bech32.convertbits(data, 8, 5)
    text = bech32.bech32_encode(hrp, values, m=m, limit=None)
    limit = len(text) + offset
    if offset < 0:
        with pytest.raises(Base58Bech32ValueError, match=_limit_message(text, limit)):
            bech32.bech32_encode(hrp, values, m=m, limit=limit)
        with pytest.raises(Base58Bech32ValueError, match=_limit_message(text, limit)):
            bech32.bech32_encode_bytes(hrp, data, m=m, limit=limit)
    else:
        assert bech32.bech32_encode(hrp, values, m=m, limit=limit) == text
        assert bech32.bech32_encode_bytes(hrp, data, m=m, limit=limit) == text


@given(
    data=st.binary(min_size=1, max_size=128),
    offset=st.integers(min_value=-1, max_value=1),
)
def test_b58decode_max_length_is_exact_around_the_string_length(
    data: bytes, offset: int
) -> None:
    """A string is refused one character above `max_length` and read at it.

    The string is never empty, so `max_length` is never below zero, which
    is an invalid argument rather than a refusal.
    """
    text = base58.b58encode(data)
    max_length = len(text) + offset
    if offset < 0:
        with pytest.raises(
            Base58Bech32ValueError,
            match=f"^too many base58 characters: {len(text)}, max is {max_length}$",
        ):
            base58.b58decode(text, max_length=max_length)
    else:
        assert base58.b58decode(text, max_length=max_length) == data
