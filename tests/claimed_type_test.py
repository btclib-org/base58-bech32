# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A value is tested by its own class, not by the class it claims.

`unittest.mock.Mock(spec=T)` sets its `__class__` to `T`, and
`isinstance` reads `__class__`, so a type test asking `isinstance` takes
the Mock for a `T`. `base58_bech32._utils._has_type` reads `type()`
instead, and no module of the package calls `isinstance`. Each case
below drives a public function with a Mock claiming the type its type
test expects, and the value is refused as the object it is.
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from importlib import import_module
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

import base58_bech32
from base58_bech32._utils import (
    assert_type,
    bytes_from_octets,
    is_integer,
    str_from_string,
)
from base58_bech32.base58 import (
    b58decode,
    b58decode_check,
    b58encode,
    b58encode_check,
)
from base58_bech32.bech32 import (
    bech32_decode,
    bech32_decode_bytes,
    bech32_encode,
    bech32_encode_bytes,
    convertbits,
)
from base58_bech32.cashaddr import cashaddr_decode, cashaddr_encode
from base58_bech32.exceptions import Base58Bech32TypeError
from base58_bech32.ss58 import ss58_decode, ss58_encode
from base58_bech32.strkey import strkey_decode, strkey_encode

from . import module_names

_ONE = b58encode_check(b"\x01")

# (module, call, the type the Mock claims): each a type test reached
# through a public function, and one `isinstance` would let through, as
# `test_isinstance_would_let_each_claim_through` shows
_REFUSED: tuple[tuple[str, Callable[[Any], object], type], ...] = (
    ("_utils", bytes_from_octets, str),
    ("_utils", bytes_from_octets, bytes),
    ("_utils", bytes_from_octets, bytearray),
    ("_utils", bytes_from_octets, memoryview),
    ("_utils", lambda v: bytes_from_octets(b"\x01", v), int),
    ("_utils", lambda v: str_from_string(v, "value"), str),
    ("_utils", lambda v: str_from_string(v, "value"), bytes),
    ("_utils", lambda v: assert_type(v, bytes, "value"), bytes),
    ("base58", b58encode, bytes),
    ("base58", lambda v: b58encode(b"\x01", alphabet=v), bytes),
    ("base58", lambda v: b58encode_check(b"\x01", in_size=v), int),
    ("base58", b58decode, str),
    ("base58", b58decode, bytes),
    ("base58", lambda v: b58decode("1", max_length=v), int),
    ("base58", b58decode_check, str),
    ("base58", lambda v: b58decode_check(_ONE, out_size=v), int),
    ("bech32", lambda v: bech32_encode(v, [0]), str),
    ("bech32", lambda v: bech32_encode("a", v), list),
    ("bech32", lambda v: bech32_encode("a", [v]), int),
    ("bech32", lambda v: bech32_encode("a", [0], m=v), int),
    ("bech32", lambda v: bech32_encode("a", [0], limit=v), int),
    ("bech32", bech32_decode, str),
    ("bech32", lambda v: bech32_decode("a12uel5l", m=v), int),
    ("bech32", lambda v: bech32_encode_bytes("a", v, m=1), bytes),
    ("bech32", lambda v: bech32_decode_bytes(v, m=1), str),
    ("bech32", lambda v: convertbits([v], 8, 5), int),
    ("bech32", lambda v: convertbits([1], v, 5), int),
    ("bech32", lambda v: convertbits([1], 8, 5, v), bool),
    ("cashaddr", lambda v: cashaddr_encode(v, 0, bytes(20)), str),
    ("cashaddr", lambda v: cashaddr_encode("p", v, bytes(20)), int),
    ("cashaddr", lambda v: cashaddr_encode("p", 0, v), bytes),
    ("cashaddr", cashaddr_decode, str),
    ("cashaddr", lambda v: cashaddr_decode("p:", prefix=v), str),
    ("ss58", lambda v: ss58_encode(v, bytes(32)), int),
    ("ss58", lambda v: ss58_encode(42, v), bytes),
    ("ss58", ss58_decode, str),
    ("strkey", lambda v: strkey_encode(v, b""), int),
    ("strkey", lambda v: strkey_encode(48, v), bytes),
    ("strkey", strkey_decode, str),
)


@pytest.mark.parametrize(
    "call, claimed",
    [case[1:] for case in _REFUSED],
    ids=[f"{i}-{case[0]}-{case[2].__name__}" for i, case in enumerate(_REFUSED)],
)
@pytest.mark.parametrize("mock", [Mock, MagicMock])
def test_a_value_that_claims_a_type_is_refused(
    call: Callable[[Any], object], claimed: type, mock: type[Mock]
) -> None:
    """The Mock is refused as the object it is, never read as `claimed`."""
    with pytest.raises(Base58Bech32TypeError):
        call(mock(spec=claimed))


# where the type test asks for an Iterable: a MagicMock is one by its own
# class, and only a Mock claims to be
_NOT_ITERABLE: tuple[tuple[str, Callable[[Any], object]], ...] = (
    ("_utils", lambda v: bytes_from_octets(b"\x01", v)),
    ("bech32", lambda v: convertbits(v, 8, 5)),
)


@pytest.mark.parametrize(
    "call", [case[1] for case in _NOT_ITERABLE], ids=[c[0] for c in _NOT_ITERABLE]
)
def test_a_value_that_claims_a_list_is_refused(call: Callable[[Any], object]) -> None:
    """A `Mock(spec=list)` has no `__iter__` of its own class."""
    with pytest.raises(Base58Bech32TypeError):
        call(Mock(spec=list))


def _isinstance(value: object, expected: Any) -> bool:
    """Test a type as `_has_type` would with `isinstance` back in it."""
    return isinstance(value, expected)


_CLAIMS = [
    *((case[1], mock, case[2]) for case in _REFUSED for mock in (Mock, MagicMock)),
    *((case[1], Mock, list) for case in _NOT_ITERABLE),
]


@pytest.mark.parametrize(
    "call, mock, claimed",
    _CLAIMS,
    ids=[f"{i}-{c[1].__name__}-{c[2].__name__}" for i, c in enumerate(_CLAIMS)],
)
def test_isinstance_would_let_each_claim_through(
    monkeypatch: pytest.MonkeyPatch,
    call: Callable[[Any], object],
    mock: type[Mock],
    claimed: type,
) -> None:
    """Each case above is one `isinstance` would not refuse as a type.

    So a case that `_has_type` and `isinstance` refuse alike, which tests
    nothing here, fails. Every module binding `_has_type` gets the
    `isinstance` version; the call then answers, or raises another error.
    """
    for name in module_names():
        module = import_module(name)
        if hasattr(module, "_has_type"):
            monkeypatch.setattr(module, "_has_type", _isinstance)
    outcome: object
    try:
        outcome = call(mock(spec=claimed))
    except Exception as e:  # noqa: BLE001
        outcome = e
    assert not isinstance(outcome, Base58Bech32TypeError)


@pytest.mark.parametrize("mock", [Mock, MagicMock])
def test_a_value_that_claims_an_int_is_answered_as_its_own(mock: type[Mock]) -> None:
    """What answers rather than refuses answers for the object it is."""
    assert not is_integer(mock(spec=int))


def test_a_magic_mock_is_read_as_the_iterable_it_is() -> None:
    """A MagicMock is an empty iterable by its own class."""
    assert convertbits(MagicMock(spec=list), 8, 5) == []


def _called_names(source: str) -> list[str]:
    """Return the name of every call of a bare name, at any depth."""
    return [
        node.func.id
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]


def _calls_by_module() -> dict[str, list[str]]:
    """Return the names each module of the installed package calls."""
    root = Path(base58_bech32.__path__[0])
    return {
        path.relative_to(root).with_suffix("").as_posix(): _called_names(
            path.read_text(encoding="utf-8")
        )
        for path in sorted(root.rglob("*.py"))
    }


def test_every_module_with_a_type_test_is_driven() -> None:
    """A module calling a type test of `_utils` has a case above."""
    tests = {"_has_type", "_int_from_integer", "assert_type", "is_integer"}
    testing = {name for name, calls in _calls_by_module().items() if tests & {*calls}}
    assert testing == {case[0] for case in (*_REFUSED, *_NOT_ITERABLE)}


def test_the_call_scan_finds_a_planted_isinstance() -> None:
    """The scan reaches a call inside a method, a nested and an async def."""
    source = (
        "class A:\n"
        "    def f(self, v):\n"
        "        def g():\n"
        "            return isinstance(v, int)\n"
        "        return g()\n"
        "async def h(v):\n"
        "    return isinstance(v, str)\n"
    )
    assert _called_names(source).count("isinstance") == 2


def test_the_package_tests_a_type_only_through_has_type() -> None:
    """No module calls `isinstance`, and `_utils` calls `_has_type`."""
    calls = _calls_by_module()
    assert "_has_type" in calls["_utils"]
    assert not [name for name, called in calls.items() if "isinstance" in called]
