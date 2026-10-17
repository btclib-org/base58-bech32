# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The coercions of `base58_bech32._utils`, against btclib's originals.

`_utils.py` copies `assert_type`, `bytes_from_octets`, `is_integer`,
`str_from_string`, `_message_text`, `Octets` and `String` from `btclib`
so that the package imports nothing of it, and a
copy can drift from its original with every other gate green. So each
input of one table is handed to both, and the two have to agree: the
same answer, or a refusal of the same built-in class and message, the
copy's being this package's own exception where the original's is
btclib's.

btclib is a test dependency and never a runtime one, which is what lets
it be the oracle here: tests/imports_test.py is what keeps it out of the
package.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, get_args

import pytest
from btclib import alias as btclib_alias
from btclib import utils as btclib_utils
from btclib.exceptions import BTClibException
from typing_extensions import override

from base58_bech32 import _utils
from base58_bech32.exceptions import Base58Bech32Exception

_OCTETS = [
    b"",
    b"\x00\xff",
    bytearray(b"\x01\x02"),
    memoryview(b"\x03\x04"),
    "",
    "00ff",
    " 00ff ",
    "0x00",
    "not hex",
    "abc",
    "\N{FULLWIDTH DIGIT ONE}0",
    memoryview(b"abcd")[::2],
    memoryview(b"abcd").cast("b"),
    None,
    1,
    1.5,
    [0, 1],
]

_VALUES: list[Any] = [0, 1, -1, True, False, 1.0, "1", None, b"1", 2**300]

# what `isinstance` takes as its second argument: one type, or a tuple
_EXPECTED: list[Any] = [str, bytes, int, (str, bytes), (int, float)]


class _Unwritable:
    """A value whose `str()` raises, which a refusal must not quote."""

    @override
    def __str__(self) -> str:
        """Refuse to be written."""
        raise RuntimeError


# the sizes `bytes_from_octets` checks two octets against
_SIZES: list[Any] = [2, 3, (1, 2), [3, 4], range(2, 4), True, 2.0, "2", None, (2.0,)]

_CASES: list[tuple[str, Callable[[Any], Any], Callable[[Any], Any], Any]] = [
    *(
        (
            "bytes_from_octets size",
            lambda v: _utils.bytes_from_octets(b"\x00\x01", v),
            lambda v: btclib_utils.bytes_from_octets(b"\x00\x01", v),
            v,
        )
        for v in _SIZES
    ),
    *(
        (
            "str_from_string",
            lambda v: _utils.str_from_string(v, "string"),
            lambda v: btclib_utils.str_from_string(v, "string"),
            v,
        )
        for v in [*_OCTETS, b"\xff", "\N{SNOWMAN}"]
    ),
    *(
        ("_message_text", _utils._message_text, btclib_utils._message_text, v)
        for v in [*_VALUES, 10**5000, -(10**5000), _Unwritable()]
    ),
    *(
        (
            "bytes_from_octets",
            _utils.bytes_from_octets,
            btclib_utils.bytes_from_octets,
            v,
        )
        for v in _OCTETS
    ),
    *(("is_integer", _utils.is_integer, btclib_utils.is_integer, v) for v in _VALUES),
    *(
        (
            "assert_type",
            lambda v, e=e: _utils.assert_type(v, e, "value"),
            lambda v, e=e: btclib_utils.assert_type(v, e, "value"),
            v,
        )
        for e in _EXPECTED
        for v in _VALUES
    ),
]


def _outcome(function: Callable[[Any], Any], value: Any) -> tuple[str, Any]:
    """Return what one call answered, or the built-in and message it raised.

    The class compared is the built-in beneath the package's own: the
    copy raises this package's exceptions and the original btclib's, and
    each is a `ValueError` or a `TypeError` beside its package's base.
    """
    try:
        return "answer", function(value)
    except (Base58Bech32Exception, BTClibException) as error:
        builtin = next(c for c in type(error).__mro__ if c in {ValueError, TypeError})
        return builtin.__name__, str(error)


@pytest.mark.parametrize(
    "copy, original, value",
    [
        pytest.param(*case[1:], id=f"{index}-{case[0]}")
        for index, case in enumerate(_CASES)
    ],
)
def test_the_copy_answers_as_the_original(
    copy: Callable[[Any], Any], original: Callable[[Any], Any], value: Any
) -> None:
    """One input, both functions, one outcome."""
    assert _outcome(copy, value) == _outcome(original, value)


def test_the_copy_raises_the_packages_own_exceptions() -> None:
    """The half the comparison above abstracts away, asserted by name."""
    with pytest.raises(Base58Bech32Exception):
        _utils.bytes_from_octets("not hex")
    with pytest.raises(Base58Bech32Exception):
        _utils.bytes_from_octets(1.5)  # type: ignore[arg-type]
    with pytest.raises(Base58Bech32Exception):
        _utils.assert_type(1, str, "value")


def test_the_aliases_are_the_same_unions() -> None:
    """Each alias names the same four types as btclib's."""
    assert set(get_args(_utils.Octets)) == set(get_args(btclib_alias.Octets))
    assert set(get_args(_utils.String)) == set(get_args(btclib_alias.String))


def test_the_table_reaches_every_outcome() -> None:
    """An answer, a value refusal and a type refusal, from each copy it asks.

    A table that only held valid inputs would agree on every row and
    say nothing about the refusals, which is where a copy drifts.
    """
    outcomes = {(name, _outcome(copy, value)[0]) for name, copy, _, value in _CASES}
    assert outcomes >= {
        ("bytes_from_octets", "answer"),
        ("bytes_from_octets", "ValueError"),
        ("bytes_from_octets", "TypeError"),
        ("bytes_from_octets size", "answer"),
        ("bytes_from_octets size", "ValueError"),
        ("bytes_from_octets size", "TypeError"),
        ("str_from_string", "answer"),
        ("str_from_string", "ValueError"),
        ("str_from_string", "TypeError"),
        ("_message_text", "answer"),
        ("is_integer", "answer"),
        ("assert_type", "answer"),
        ("assert_type", "TypeError"),
    }
