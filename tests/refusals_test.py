# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What a refusal of `base58_bech32` says, and what it does not.

A wrong type leaves as a `Base58Bech32TypeError` naming the parameter,
not as a builtin raised from underneath the package: these are the calls
`tests/input_validation_test.py`'s walk does not reach, each taking a
plain `str`, an `int` or a list. And no decoder's refusal quotes the
string it was handed, nor the payload a corrupted checksum carried:
what reaches a decoder can be a private key pasted in the wrong field,
and an exception message ends up in logs and crash reports.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any

import pytest

from base58_bech32.base58 import b58decode, b58decode_check, b58encode, b58encode_check
from base58_bech32.bech32 import (
    BECH32_1_CONST,
    BECH32_M_CONST,
    bech32_decode,
    bech32_encode,
    convertbits,
)
from base58_bech32.cashaddr import cashaddr_decode, cashaddr_encode
from base58_bech32.exceptions import Base58Bech32TypeError, Base58Bech32ValueError
from base58_bech32.ss58 import ss58_decode, ss58_encode
from tests.secret_free import assert_secret_free

# a fixed random 32-byte secret, the size of a private key
_SECRET = bytes.fromhex(
    "9b3c1e5f0a8d7246b1e0c39f5d84a27e6c0b19d3f4a85e72c61d09b8e3f4a751"
)

_WRONG_TYPES: list[tuple[str, Callable[[], Any], str]] = [
    (
        "bech32_encode(hrp=bytes)",
        lambda: bech32_encode(b"bc", [0]),  # type: ignore[arg-type]
        "invalid HRP type: bytes",
    ),
    (
        "bech32_encode(data=[float])",
        lambda: bech32_encode("bc", [1.0]),  # type: ignore[list-item]
        "invalid 5-bit value type: float",
    ),
    (
        "convertbits(data=None)",
        lambda: convertbits(None, 8, 5),  # type: ignore[arg-type]
        "invalid data type: NoneType",
    ),
    (
        "ss58_encode(prefix=str)",
        lambda: ss58_encode("42", _SECRET),  # type: ignore[arg-type]
        "invalid SS58 prefix type: str",
    ),
    (
        "ss58_encode(payload=int)",
        lambda: ss58_encode(42, 1),  # type: ignore[arg-type]
        "invalid octets type: int",
    ),
    (
        "cashaddr_encode(prefix=None)",
        lambda: cashaddr_encode(None, 0, bytes(20)),  # type: ignore[arg-type]
        "invalid CashAddr prefix type: NoneType",
    ),
    (
        "cashaddr_encode(kind=str)",
        lambda: cashaddr_encode("p", "0", bytes(20)),  # type: ignore[arg-type]
        "invalid CashAddr type type: str",
    ),
    (
        "cashaddr_decode(prefix=bytes)",
        lambda: cashaddr_decode("p:", prefix=b"p"),  # type: ignore[arg-type]
        "invalid CashAddr prefix type: bytes",
    ),
    (
        "b58encode(alphabet=str)",
        lambda: b58encode(b"", alphabet="1"),  # type: ignore[arg-type]
        "invalid alphabet type: str",
    ),
]


@pytest.mark.parametrize(
    "call, err_msg", [row[1:] for row in _WRONG_TYPES], ids=[r[0] for r in _WRONG_TYPES]
)
def test_a_wrong_type_is_the_packages_refusal(
    call: Callable[[], Any], err_msg: str
) -> None:
    """A `Base58Bech32TypeError` naming the parameter, and no builtin."""
    with pytest.raises(Base58Bech32TypeError, match=f"^{err_msg}$"):
        call()


def _corrupted(text: bytes) -> str:
    """Return the string with its last character changed to another one."""
    last = text[-1:]
    return (text[:-1] + (b"2" if last != b"2" else b"3")).decode("ascii")


def _ss58_of(data: bytes) -> bytes:
    checksum = hashlib.blake2b(b"SS58PRE" + data, digest_size=64).digest()[:2]
    return b58encode(data + checksum)


_DECODERS: list[tuple[str, Callable[[], Any]]] = [
    (
        "b58decode_check, secret",
        lambda: b58decode_check(_corrupted(b58encode_check(_SECRET)), secret=True),
    ),
    ("b58decode, invalid character", lambda: b58decode(b58encode(_SECRET) + b"0")),
    (
        "bech32_decode",
        lambda: bech32_decode(
            _corrupted(bech32_encode("a", convertbits(_SECRET, 8, 5)))
        ),
    ),
    (
        "bech32_decode, the other constant",
        lambda: bech32_decode(
            bech32_encode("a", convertbits(_SECRET, 8, 5), m=BECH32_M_CONST),
            m=BECH32_1_CONST,
        ),
    ),
    (
        "bech32_decode, mixed case",
        lambda: bech32_decode(
            bech32_encode("a", convertbits(_SECRET, 8, 5)).decode().capitalize()
        ),
    ),
    ("ss58_decode", lambda: ss58_decode(_corrupted(ss58_encode(42, _SECRET)))),
    (
        "ss58_decode, reserved",
        lambda: ss58_decode(_ss58_of(b"\x2e" + _SECRET)),
    ),
    (
        "cashaddr_decode",
        lambda: cashaddr_decode(_corrupted(cashaddr_encode("p", 0, _SECRET))),
    ),
    (
        "cashaddr_decode, prefix",
        lambda: cashaddr_decode(cashaddr_encode("p", 0, _SECRET), prefix="q"),
    ),
]


@pytest.mark.parametrize(
    "call", [row[1] for row in _DECODERS], ids=[r[0] for r in _DECODERS]
)
def test_a_decoders_refusal_quotes_nothing_of_its_input(
    call: Callable[[], Any],
) -> None:
    """Neither the encoded secret, in any spelling, nor the string itself."""
    with pytest.raises(Base58Bech32ValueError) as excinfo:
        call()
    assert_secret_free(excinfo.value, [_SECRET])
    # the string itself: the shortest decoded here is the Base58 of 32 bytes
    assert len(str(excinfo.value)) < 44


def test_a_checksum_is_quoted_unless_the_payload_is_secret() -> None:
    """The one refusal that quotes a hash of the payload, and its switch."""
    corrupted = _corrupted(b58encode_check(_SECRET))
    with pytest.raises(Base58Bech32ValueError, match="instead of 0x"):
        b58decode_check(corrupted)
    with pytest.raises(Base58Bech32ValueError, match="^invalid checksum$"):
        b58decode_check(corrupted, secret=True)
