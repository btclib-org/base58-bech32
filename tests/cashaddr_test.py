# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `base58_bech32.cashaddr` module.

The vectors are the specification's, `spec/cashaddr.md`, transcribed into
tests/_data/cashaddr_vectors.json and pinned in tests/_data/README.md.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from base58_bech32.base58 import b58decode_check
from base58_bech32.cashaddr import (
    _HASH_SIZES,
    _decode,
    cashaddr_decode,
    cashaddr_encode,
)
from base58_bech32.exceptions import Base58Bech32TypeError, Base58Bech32ValueError
from tests import load, vector_id

VECTORS = load("_data", "cashaddr_vectors.json")


@pytest.mark.parametrize("address", VECTORS["checksum"])
def test_the_checksum_vectors(address: str) -> None:
    """The specification's checksum vectors, whose payloads are not addresses.

    Uppercase is the same string, and a changed character fails the
    checksum.
    """
    prefix = address.split(":", maxsplit=1)[0]
    assert _decode(address, None)[0] == prefix
    assert _decode(address.upper(), None)[0] == prefix
    last = address[-1]
    corrupted = address[:-1] + ("q" if last != "q" else "p")
    with pytest.raises(Base58Bech32ValueError, match="^invalid checksum$"):
        _decode(corrupted, None)


@pytest.mark.parametrize(
    "size, kind, address, digest",
    [
        pytest.param(*vector, id=vector_id(index, vector[0], vector[1], vector[2]))
        for index, vector in enumerate(VECTORS["larger"])
    ],
)
def test_the_larger_vectors(size: int, kind: int, address: str, digest: str) -> None:
    """Every hash size, the types 0, 1 and 15, and four prefixes, both ways."""
    prefix = address.split(":", maxsplit=1)[0]
    raw = bytes.fromhex(digest)
    assert len(raw) == size
    assert cashaddr_encode(prefix, kind, raw) == address.encode("ascii")
    assert cashaddr_decode(address) == (prefix, kind, raw)
    assert cashaddr_decode(address.upper()) == (prefix, kind, raw)
    # without its prefix, given as the one expected
    payload = address.split(":")[1]
    assert cashaddr_decode(payload, prefix=prefix) == (prefix, kind, raw)


@pytest.mark.parametrize("legacy, address", VECTORS["legacy"])
def test_the_legacy_translations(legacy: str, address: str) -> None:
    """The specification's legacy addresses, read with Base58Check.

    A version byte of 0 is P2KH, type 0, and one of 5 is P2SH, type 1.
    """
    payload = b58decode_check(legacy, out_size=21)
    kind = {0: 0, 5: 1}[payload[0]]
    assert cashaddr_encode("bitcoincash", kind, payload[1:]) == address.encode("ascii")
    assert cashaddr_decode(address, prefix="bitcoincash") == (
        "bitcoincash",
        kind,
        payload[1:],
    )


_ADDRESS = VECTORS["larger"][0][2]


@pytest.mark.parametrize(
    "address, err_msg",
    [
        (
            "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2 ",
            "invalid CashAddr character",
        ),
        ("bitcoin:cash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2", "more than one"),
        (":qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2", "empty CashAddr prefix"),
        (
            "bitcoin1:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
            "digit in CashAddr prefix",
        ),
        ("Bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2", "mixed case"),
        ("bitcoincash:qr6m7j9", "too short checksum"),
        ("bitcoincash:br6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2", "payload character"),
        ("bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg3", "invalid checksum"),
        (
            "bitcoincash:éqr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
            "CashAddr character",
        ),
    ],
)
def test_the_string_refusals(address: str, err_msg: str) -> None:
    """Each refusal of Bitcoin Cash Node's `cashaddr::Decode`."""
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        cashaddr_decode(address)


@pytest.mark.parametrize(
    "address, err_msg",
    [
        # the character check, then the separator count, then the case
        ("a:b:\u00e9", "invalid CashAddr character"),
        ("a:b:C", "more than one CashAddr separator"),
        ("a:b:c", "more than one CashAddr separator"),
        ("a:b c", "invalid CashAddr character"),
        ("a:b_c", "invalid CashAddr character"),
        ("A:b", "mixed case"),
        ("::", "more than one CashAddr separator"),
        (":", "empty CashAddr prefix"),
        ("", "no CashAddr prefix, and none given"),
        ("qqqq", "no CashAddr prefix, and none given"),
    ],
)
def test_the_split_refusals_and_their_order(address: str, err_msg: str) -> None:
    """The character check does not take a second ":" for a character."""
    with pytest.raises(Base58Bech32ValueError, match=f"^{err_msg}$"):
        cashaddr_decode(address)


def test_the_prefix_refusals() -> None:
    """A prefix missing from both, or different from the one expected."""
    payload = _ADDRESS.split(":")[1]
    with pytest.raises(Base58Bech32ValueError, match="no CashAddr prefix, and none"):
        cashaddr_decode(payload)
    with pytest.raises(Base58Bech32ValueError, match="not the one given"):
        cashaddr_decode(_ADDRESS, prefix="bchtest")
    # the checksum covers the prefix, so the wrong one fails it
    with pytest.raises(Base58Bech32ValueError, match="^invalid checksum$"):
        cashaddr_decode(payload, prefix="bchtest")
    with pytest.raises(Base58Bech32ValueError, match="invalid CashAddr prefix: "):
        cashaddr_decode(payload, prefix="BITCOINCASH")


def _string(prefix: str, values: list[int]) -> str:
    """Return a CashAddr string of any 5-bit values, correctly checksummed."""
    from base58_bech32.bech32 import _ALPHABET  # noqa: PLC0415
    from base58_bech32.cashaddr import _polymod, _prefix_expand  # noqa: PLC0415

    mod = _polymod(_prefix_expand(prefix) + values + [0] * 8)
    checksum = [(mod >> 5 * (7 - i)) & 31 for i in range(8)]
    return f"{prefix}:" + "".join(_ALPHABET[d] for d in values + checksum)


def test_the_payload_refusals() -> None:
    """Of `DecodeCashAddrContent`: correctly checksummed, and no address."""
    with pytest.raises(Base58Bech32ValueError, match="empty CashAddr payload"):
        cashaddr_decode(_string("p", []))
    # the reserved top bit of the version byte, over a 20-byte hash
    values = [16, 0, *[0] * 32]
    with pytest.raises(Base58Bech32ValueError, match="reserved bit set"):
        cashaddr_decode(_string("p", values))
    # a version byte saying 20 bytes, and 21 of them
    with pytest.raises(
        Base58Bech32ValueError, match="hash size: 21 bytes instead of 20"
    ):
        cashaddr_decode(_string("p", [0, 0, *[0] * 34]))
    with pytest.raises(Base58Bech32ValueError, match="non-zero padding"):
        cashaddr_decode(_string("p", [0, 0, *[0] * 31, 1]))


def test_the_encoder_refusals() -> None:
    """A prefix, a type and a hash the version byte cannot say."""
    digest = bytes(20)
    with pytest.raises(Base58Bech32ValueError, match="empty CashAddr prefix"):
        cashaddr_encode("", 0, digest)
    for prefix in ("BitcoinCash", "bch1", "bch test", "bché"):
        with pytest.raises(Base58Bech32ValueError, match="invalid CashAddr prefix: "):
            cashaddr_encode(prefix, 0, digest)
    with pytest.raises(Base58Bech32TypeError, match="invalid CashAddr prefix type"):
        cashaddr_encode(b"p", 0, digest)  # type: ignore[arg-type]
    for kind in (-1, 16):
        with pytest.raises(Base58Bech32ValueError, match="invalid CashAddr type: "):
            cashaddr_encode("p", kind, digest)
    for not_a_kind in (True, 0.0):
        with pytest.raises(Base58Bech32TypeError, match="invalid CashAddr type type"):
            cashaddr_encode("p", not_a_kind, digest)  # type: ignore[arg-type]
    with pytest.raises(Base58Bech32ValueError, match="invalid size: 21 bytes"):
        cashaddr_encode("p", 0, bytes(21))


def test_the_uppercase_form_for_qr_codes_is_read_back() -> None:
    """`cashaddr_decode` reads the `.upper()` of what `cashaddr_encode` made."""
    for prefix, kind, size in (("bitcoincash", 0, 20), ("bchtest", 1, 32)):
        digest = bytes(range(size))
        written = cashaddr_encode(prefix, kind, digest)
        assert written == written.lower()
        for upper in (written.upper(), written.upper().decode("ascii")):
            assert cashaddr_decode(upper) == (prefix, kind, digest)


@given(
    prefix=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=12),
    kind=st.integers(0, 15),
    size=st.sampled_from(_HASH_SIZES),
    data=st.data(),
)
def test_round_trip(prefix: str, kind: int, size: int, data: st.DataObject) -> None:
    """Every prefix, type and hash size comes back."""
    digest = data.draw(st.binary(min_size=size, max_size=size))
    address = cashaddr_encode(prefix, kind, digest)
    assert cashaddr_decode(address) == (prefix, kind, digest)
    assert cashaddr_decode(address.decode("ascii").upper()) == (prefix, kind, digest)
