# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `base58_bech32.exceptions`, and for who catches what it raises.

The classes add nothing to their bases, so what is tested is the
hierarchy: one base to catch everything the package raises, and each
class a subclass of the built-in that names its kind of failure. The
second half is what a caller written against `except ValueError` relies
on, and the last test asks it of a refusal the package actually raises
rather than of the class alone.
"""

from __future__ import annotations

import pickle

import pytest

from base58_bech32 import exceptions
from base58_bech32.base58 import b58decode_check
from base58_bech32.bech32 import BECH32_1_CONST, bech32_decode, convertbits
from base58_bech32.exceptions import (
    Base58Bech32Exception,
    Base58Bech32TypeError,
    Base58Bech32ValueError,
)


def test_every_exception_of_the_module_is_one_base_to_catch() -> None:
    """`except Base58Bech32Exception` tells this package's failure apart.

    The classes are found rather than listed, so one added to the module
    is one this covers: a new exception that forgot the base would be a
    failure a caller catching it could not catch, and nothing else in the
    suite would say so.
    """
    classes = [
        getattr(exceptions, name)
        for name in exceptions.__all__
        if isinstance(getattr(exceptions, name), type)
    ]
    assert len(classes) == len(exceptions.__all__), "a non-class in __all__"
    uncatchable = [
        cls.__name__ for cls in classes if not issubclass(cls, Base58Bech32Exception)
    ]
    assert not uncatchable


@pytest.mark.parametrize(
    "cls, builtin",
    [(Base58Bech32ValueError, ValueError), (Base58Bech32TypeError, TypeError)],
    ids=["ValueError", "TypeError"],
)
def test_the_base_is_inherited_beside_the_builtin_not_instead_of_it(
    cls: type[Base58Bech32Exception], builtin: type[Exception]
) -> None:
    """The half that keeps every `except ValueError` already written working."""
    assert issubclass(cls, builtin)
    assert issubclass(cls, Base58Bech32Exception)


def test_the_base_carries_no_behaviour_of_its_own() -> None:
    """It adds a name to catch and nothing else, which is the whole design."""
    assert Base58Bech32Exception.__init__ is Exception.__init__
    assert Base58Bech32Exception.__str__ is Exception.__str__
    error = Base58Bech32ValueError("bad")
    assert str(error) == "bad"
    assert error.args == ("bad",)
    back = pickle.loads(pickle.dumps(error))  # noqa: S301 -- bytes this test wrote
    assert type(back) is Base58Bech32ValueError
    assert back.args == error.args


def test_the_exceptions_are_not_btclibs() -> None:
    """A caller catching btclib's classes does not catch these.

    Which is what the module docstring says, and the reason a caller
    moving from `btclib.base58` and `btclib.bech32`, which raise btclib's
    classes, to this package catches the built-in or this package's base
    rather than keeping btclib's name.
    btclib is a test dependency here, so asking it costs nothing the
    package pays for.
    """
    from btclib.exceptions import BTClibException  # noqa: PLC0415

    assert not issubclass(Base58Bech32Exception, BTClibException)


def test_a_refusal_raised_inside_the_package_is_a_value_error() -> None:
    """A real refusal, from deep in a decoder, caught by the built-in alone.

    A wrong checksum is refused inside the Base58Check and the bech32
    decoders; an `except ValueError` written by a caller who never heard
    of this package's classes catches both.
    """
    with pytest.raises(ValueError, match="invalid checksum") as base58_refusal:
        b58decode_check("3vQB7B6MrGQZaxCuFg4oH")
    assert isinstance(base58_refusal.value, Base58Bech32ValueError)

    with pytest.raises(ValueError, match="invalid checksum") as bech32_refusal:
        bech32_decode("a12uel5m", m=BECH32_1_CONST)
    assert isinstance(bech32_refusal.value, Base58Bech32ValueError)

    # and a wrong type is a TypeError the same way
    with pytest.raises(TypeError, match="invalid pad type: ") as refusal:
        convertbits([], 8, 5, None)  # type: ignore[arg-type]
    assert isinstance(refusal.value, Base58Bech32TypeError)
