# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every decoder, on input nobody wrote down.

The rest of the suite is fixed vectors: exactly what conformance needs,
and blind to the malformed strings that never make it into a
specification's test section. This file is the converse. It does not
assert that a decoder accepts the right things -- the vectors do that --
but that it *fails the way the package says it fails*, whatever it is
handed: an IndexError off a short slice or a KeyError off an alphabet
lookup reaches a caller who catches `Base58Bech32ValueError` to reject
bad input and has no reason to expect anything else.

`fuzz/`'s atheris harness asks the same question of the same decoders
for an hour a week; this asks it on every run, for as long as hypothesis
spends on a test. Arbitrary text rarely carries a valid checksum, so the
strings below are also drawn from each format's own alphabet, and from
valid strings with one character changed, which is what reaches the
checksum and the length checks behind the alphabet lookup.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from base58_bech32 import base58, bech32, cashaddr, ss58
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
