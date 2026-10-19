# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the one policy on integer fields: a bool is not a number.

One file rather than a case per module, because the decision is one and
`base58_bech32._utils.is_integer` states it. What makes it worth a
refusal is the json boundary: `true` decodes to `True`, and a schema
mistake would become a network prefix of one, an address type of one or
a 5-bit value of one instead of failing beside the input that caused it.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import IntEnum
from typing import Any

import pytest

from base58_bech32._utils import bytes_from_octets, is_integer
from base58_bech32.base58 import b58decode, b58decode_check, b58encode_check
from base58_bech32.bech32 import (
    BECH32_M_CONST,
    bech32_decode,
    bech32_encode,
    convertbits,
)
from base58_bech32.cashaddr import cashaddr_encode
from base58_bech32.exceptions import Base58Bech32TypeError
from base58_bech32.ss58 import ss58_encode

_ONE = b58encode_check(b"\x01")

# every field whose contract is an integer quantity, with the shortest
# call that reaches its validator
_CASES: list[tuple[str, Callable[[Any], object]]] = [
    ("octets size", lambda v: bytes_from_octets(b"\x01", v)),
    ("base58check payload size", lambda v: b58decode_check(_ONE, out_size=v)),
    ("base58 max_length", lambda v: b58decode("1", max_length=v)),
    ("bech32 5-bit value", lambda v: bech32_encode("a", [v])),
    ("bech32_encode m", lambda v: bech32_encode("a", [0], m=v)),
    ("bech32_decode m", lambda v: bech32_decode("a12uel5l", m=v)),
    ("bech32_encode limit", lambda v: bech32_encode("a", [0], limit=v)),
    ("bech32_decode limit", lambda v: bech32_decode("a12uel5l", limit=v)),
    ("convertbits value", lambda v: convertbits([v], 1, 8)),
    ("convertbits from_bits", lambda v: convertbits([1], v, 8)),
    ("convertbits to_bits", lambda v: convertbits([1], 8, v)),
    ("ss58 prefix", lambda v: ss58_encode(v, bytes(32))),
    ("cashaddr type", lambda v: cashaddr_encode("p", v, bytes(20))),
]

_IDS = [case[0] for case in _CASES]
_CALLS = [case[1] for case in _CASES]


@pytest.mark.parametrize("call", _CALLS, ids=_IDS)
@pytest.mark.parametrize("value", [True, False], ids=["true", "false"])
def test_a_bool_is_not_an_integer_field(
    call: Callable[[Any], object], *, value: bool
) -> None:
    """Every integer field refuses a boolean, and refuses it as a type.

    `isinstance(True, int)` is what would let each of these through as one
    or zero.
    """
    with pytest.raises(Base58Bech32TypeError):
        call(value)


def test_the_integers_a_bool_refusal_must_not_take_with_it() -> None:
    """The same calls with a number, which is what the refusal is around.

    A test that only checks refusals passes just as well when the field
    refuses everything.
    """
    assert bytes_from_octets(b"\x01", 1) == b"\x01"
    assert b58decode_check(_ONE, out_size=1) == b"\x01"
    assert b58decode("1", max_length=1) == b"\x00"
    assert bech32_encode("a", [1]) == bech32_encode("a", [1], m=BECH32_M_CONST)
    assert bech32_decode("a12uel5l", m=1) == ("a", [], 1)
    assert bech32_encode("a", [0], limit=9) == bech32_encode("a", [0])
    assert bech32_decode("a12uel5l", m=1, limit=8) == ("a", [], 1)
    assert convertbits([1], 1, 8) == [128]
    assert convertbits([1], 8, 1) == [0, 0, 0, 0, 0, 0, 0, 1]
    assert ss58_encode(1, bytes(32)) != ss58_encode(0, bytes(32))
    assert cashaddr_encode("p", 1, bytes(20)) != cashaddr_encode("p", 0, bytes(20))


def test_an_int_subclass_that_is_not_a_bool_is_still_an_integer() -> None:
    """`IntEnum` stays a number, which is why the predicate names bool.

    `type(value) is int` would refuse every `int` subclass, where the
    policy refuses one.
    """

    class Small(IntEnum):
        ONE = 1

    assert is_integer(Small.ONE)
    assert ss58_encode(Small.ONE, bytes(32)) == ss58_encode(1, bytes(32))

    assert is_integer(0)
    assert is_integer(-1)
    assert not is_integer(True)
    assert not is_integer(False)
    assert not is_integer(1.0)
    assert not is_integer("1")
