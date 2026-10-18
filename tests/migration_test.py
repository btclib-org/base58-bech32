# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The entries of docs/source/migration.md, both sides run on the same inputs.

`base58` and `bech32` are test dependencies, the packages the page maps
from. Each test is an entry of the page, or a difference it states.
"""

from __future__ import annotations

from importlib import metadata
from pathlib import Path
from types import ModuleType

import base58 as base58_package
import bech32 as bech32_package
import pytest
from hypothesis import given
from hypothesis import strategies as st

from base58_bech32 import base58, bech32
from base58_bech32.exceptions import Base58Bech32TypeError, Base58Bech32ValueError

_PAGE = Path(__file__).parents[1] / "docs" / "source" / "migration.md"

ALPHABETS = st.sampled_from([base58.BITCOIN_ALPHABET, base58.RIPPLE_ALPHABET])
PAYLOAD = st.binary(max_size=60)


def test_the_alphabets() -> None:
    """The constants are the same bytes."""
    assert base58.BITCOIN_ALPHABET == base58_package.BITCOIN_ALPHABET
    assert base58_package.alphabet == base58.BITCOIN_ALPHABET
    assert base58.RIPPLE_ALPHABET == base58_package.RIPPLE_ALPHABET
    assert base58.RIPPLE_ALPHABET == base58_package.XRP_ALPHABET


@given(payload=PAYLOAD, alphabet=ALPHABETS)
def test_b58encode_and_b58decode(payload: bytes, alphabet: bytes) -> None:
    """Plain Base58, both ways."""
    encoded = base58.b58encode(payload, alphabet=alphabet)
    assert encoded == base58_package.b58encode(payload, alphabet=alphabet)
    assert base58.b58decode(encoded, alphabet=alphabet) == base58_package.b58decode(
        encoded, alphabet=alphabet
    )


@given(payload=PAYLOAD, alphabet=ALPHABETS)
def test_b58encode_check_and_b58decode_check(payload: bytes, alphabet: bytes) -> None:
    """Base58Check, both ways."""
    encoded = base58.b58encode_check(payload, alphabet=alphabet)
    assert encoded == base58_package.b58encode_check(payload, alphabet=alphabet)
    assert base58.b58decode_check(
        encoded, alphabet=alphabet
    ) == base58_package.b58decode_check(encoded, alphabet=alphabet)


@given(payload=PAYLOAD)
def test_b58decode_int(payload: bytes) -> None:
    """An integer is the bytes read big-endian, leading zero bytes and all."""
    encoded = base58.b58encode(payload)
    assert int.from_bytes(base58.b58decode(encoded), "big") == (
        base58_package.b58decode_int(encoded)
    )


@given(i=st.integers(min_value=0, max_value=2**400))
def test_b58encode_int(i: int) -> None:
    """`default_one=False` is the bytes of the integer, zero being none."""
    raw = i.to_bytes((i.bit_length() + 7) // 8, "big")
    assert base58.b58encode(raw) == base58_package.b58encode_int(i, default_one=False)


def test_the_base58_differences() -> None:
    """Each difference the page states, measured on both sides."""
    # a str to encode
    assert base58_package.b58encode("00ff") != base58.b58encode("00ff")
    assert base58.b58encode("00ff") == base58.b58encode(b"\x00\xff")
    # trailing whitespace
    assert base58_package.b58decode("StV1DL6CwTryKyV \n") == b"hello world"
    with pytest.raises(Base58Bech32ValueError, match="invalid characters"):
        base58.b58decode("StV1DL6CwTryKyV \n")
    # autofix
    assert base58_package.b58decode("StVlDL6CwTryKyV", autofix=True) == b"hello world"
    with pytest.raises(Base58Bech32ValueError, match="invalid characters"):
        base58.b58decode("StVlDL6CwTryKyV")
    # the cap
    long_payload = bytes(range(1, 100))
    encoded = base58_package.b58encode_check(long_payload)
    assert len(encoded) > base58.MAX_LENGTH
    assert base58_package.b58decode_check(encoded) == long_payload
    with pytest.raises(Base58Bech32ValueError, match="too many base58 characters"):
        base58.b58decode_check(encoded)
    # zero
    assert base58_package.b58encode_int(0) == b"1"
    assert base58.b58encode(b"") == b""
    # Base45's alphabet
    base45 = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
    assert base58_package.b58encode(b"\1", alphabet=base45) == b"1"
    with pytest.raises(Base58Bech32ValueError, match="invalid alphabet size"):
        base58.b58encode(b"\1", alphabet=base45)


HRP = st.text(alphabet="0123456789abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=10)
DATA = st.lists(st.integers(min_value=0, max_value=31), max_size=80)


@given(hrp=HRP, data=DATA)
def test_bech32_encode_and_bech32_decode(hrp: str, data: list[int]) -> None:
    """bech32, both ways."""
    encoded = bech32.bech32_encode(hrp, data, m=bech32.BECH32_1_CONST).decode()
    assert encoded == bech32_package.bech32_encode(hrp, data)
    assert bech32.bech32_decode(encoded, m=bech32.BECH32_1_CONST)[:2] == (
        bech32_package.bech32_decode(encoded)
    )


@given(
    data=st.lists(st.integers(min_value=0, max_value=31), max_size=60),
    widths=st.sampled_from([(8, 5), (5, 8), (5, 5), (8, 1), (1, 8)]),
    pad=st.booleans(),
)
def test_convertbits(data: list[int], widths: tuple[int, int], pad: bool) -> None:
    """The same list, or a refusal here where the package answers None."""
    from_bits, to_bits = widths
    expected = bech32_package.convertbits(data, from_bits, to_bits, pad)
    if expected is None:
        with pytest.raises(Base58Bech32ValueError):
            bech32.convertbits(data, from_bits, to_bits, pad)
    else:
        assert bech32.convertbits(data, from_bits, to_bits, pad) == expected


def test_the_bech32_differences() -> None:
    """Each difference the page states, measured on both sides."""
    corrupted = "a12uel5m"
    assert bech32_package.bech32_decode(corrupted) == (None, None)
    with pytest.raises(Base58Bech32ValueError, match="invalid checksum"):
        bech32.bech32_decode(corrupted, m=bech32.BECH32_1_CONST)

    assert bech32_package.convertbits([256], 8, 5) is None
    with pytest.raises(Base58Bech32ValueError, match="invalid value: 256"):
        bech32.convertbits([256], 8, 5)

    # what the package writes and this refuses
    for hrp, data in (("BC", [0, 1, 2]), ("", [0]), ("bc", [-1])):
        assert isinstance(bech32_package.bech32_encode(hrp, data), str)
        with pytest.raises(Base58Bech32ValueError):
            bech32.bech32_encode(hrp, data)
    with pytest.raises(IndexError):
        bech32_package.bech32_encode("bc", [32])
    with pytest.raises(Base58Bech32ValueError, match="invalid 5-bit value: 32"):
        bech32.bech32_encode("bc", [32])

    # bech32m, which the package refuses
    bech32m = "a1lqfn3a"
    assert bech32_package.bech32_decode(bech32m) == (None, None)
    assert bech32.bech32_decode(bech32m) == ("a", [], bech32.BECH32_M_CONST)

    # an HRP of 84 characters
    long_hrp = "a" * 84
    encoded = bech32.bech32_encode(long_hrp, [0], m=bech32.BECH32_1_CONST).decode()
    assert bech32_package.bech32_decode(encoded) == (None, None)
    assert bech32.bech32_decode(encoded, m=bech32.BECH32_1_CONST)[:2] == (long_hrp, [0])


def test_bech32_data_is_a_list_here() -> None:
    """`bech32` encodes a tuple; here it is refused, as is any other `m`."""
    assert bech32_package.bech32_encode("a", (0, 1)) == "a1qpamnt9j"
    assert bech32.bech32_encode("a", [0, 1]) == b"a1qpamnt9j"
    with pytest.raises(Base58Bech32TypeError):
        bech32.bech32_encode("a", (0, 1))  # type: ignore[arg-type]
    with pytest.raises(Base58Bech32ValueError):
        bech32.bech32_encode("a", [0, 1], m=5)


def test_scrub_input_is_not_needed() -> None:
    """The decoders take what `scrub_input` would have turned into bytes."""
    encoded = base58.b58encode(b"\0\1")
    as_str = encoded.decode("ascii")
    assert base58_package.scrub_input(as_str) == encoded
    assert base58.b58decode(as_str) == base58.b58decode(encoded) == b"\0\1"


def _own_names(module: ModuleType) -> set[str]:
    """Return a module's public names, less what it imports from elsewhere."""
    names = set()
    for name, value in vars(module).items():
        if name.startswith("_") or isinstance(value, ModuleType):
            continue
        # a constant is the module's own; a function or a typing alias
        # says where it was defined
        if (
            isinstance(value, (bytes, str))
            or getattr(value, "__module__", "").split(".")[0] == module.__name__
        ):
            names.add(name)
    return names


@pytest.mark.parametrize("module", [base58_package, bech32_package])
def test_the_page_names_every_public_name(module: ModuleType) -> None:
    """A name the package publishes and the page leaves out fails here."""
    page = _PAGE.read_text(encoding="utf-8")
    missing = sorted(n for n in _own_names(module) if f"`{n}" not in page)
    assert not missing, missing
    # the walk itself: an import is not a name of the package
    assert "sha256" not in _own_names(base58_package)
    assert "Union" not in _own_names(bech32_package)
    assert {"scrub_input", "alphabet"} <= _own_names(base58_package)


def test_the_page_names_the_console_scripts() -> None:
    """`base58` installs a console script, which the page says has no peer."""
    scripts = {
        package: [
            entry.name
            for entry in metadata.distribution(package).entry_points
            if entry.group == "console_scripts"
        ]
        for package in ("base58", "bech32")
    }
    assert scripts == {"base58": ["base58"], "bech32": []}
    assert "the `base58` console script" in _PAGE.read_text(encoding="utf-8")
