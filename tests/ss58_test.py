# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `base58_bech32.ss58` module.

The vectors are Substrate's own addresses, inline below, and
polkadot-js', among them the ones it checks against Subkey, Substrate's
command-line tool.
tests/_data/README.md pins both.
"""

from __future__ import annotations

import hashlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from base58_bech32.base58 import b58decode, b58encode
from base58_bech32.exceptions import Base58Bech32TypeError, Base58Bech32ValueError
from base58_bech32.ss58 import ss58_decode, ss58_encode
from tests import load, vector_id

ENCODE = load("_data", "ss58_encode_vectors.json")
DECODE = load("_data", "ss58_decode_vectors.json")

# Substrate's own addresses, from `substrate/primitives/core/src/` of
# paritytech/polkadot-sdk: `DEV_ADDRESS` and the AccountId32 of
# `accountid_32_from_str_works` in crypto.rs, at 298bf2cb (2026-02-06),
# and the two ECDSA addresses of `ss58check_custom_format_works` in
# ecdsa.rs, at a2937bec (2026-09-01), each the tip of its path on
# 2026-10-17. Substrate's tests give no payload for them, so the prefix
# and the payload size are asserted, and the round trip
SUBSTRATE = [
    ("5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV", 42, 32),
    ("5G9VdMwXvzza9pS8qE8ZHJk3CheHW9uucBn9ngW4C1gmmzpv", 42, 32),
    ("4pbsSkWcBaYoFHrKJZp5fDVUKbqSYD9dhZZGvpp3vQ5ysVs5ybV", 200, 33),
    ("KWAfgC2aRG5UVD6CpbPQXCx4YZZUhvWqqAJE6qcYc9Rtr6g5C", 42, 33),
]


@pytest.mark.parametrize("address, prefix, size", SUBSTRATE)
def test_substrates_own_addresses(address: str, prefix: int, size: int) -> None:
    """Each decodes to the prefix Substrate's test names, and back."""
    decoded_prefix, payload = ss58_decode(address)
    assert decoded_prefix == prefix
    assert len(payload) == size
    assert ss58_encode(prefix, payload) == address.encode("ascii")


def test_substrates_invalid_account_id() -> None:
    """The string Substrate's `accountid_32_from_str_works` refuses."""
    with pytest.raises(Base58Bech32ValueError):
        ss58_decode("99G9VdMwXvzza9pS8qE8ZHJk3CheHW9uucBn9ngW4C1gmmzpv")


@pytest.mark.parametrize(
    "prefix, payload, address",
    [
        pytest.param(*vector, id=vector_id(index, vector[0], vector[2][:16]))
        for index, vector in enumerate(ENCODE["encode"])
    ],
)
def test_encode_vectors(prefix: int, payload: str, address: str) -> None:
    """polkadot-js's encode vectors, Subkey's among them, both directions."""
    assert ss58_encode(prefix, payload) == address.encode("ascii")
    assert ss58_decode(address) == (prefix, bytes.fromhex(payload))


@pytest.mark.parametrize(
    "address, payload",
    [
        pytest.param(*vector, id=vector_id(index, vector[0][:16]))
        for index, vector in enumerate(DECODE["decode"])
    ],
)
def test_decode_vectors(address: str, payload: str) -> None:
    """polkadot-js's decode vectors: the payload, and the address back."""
    prefix, decoded = ss58_decode(address)
    assert decoded == bytes.fromhex(payload)
    assert ss58_encode(prefix, decoded) == address.encode("ascii")


@pytest.mark.parametrize("prefix, payload, address", ENCODE["encode_short_payload"])
def test_an_account_index_is_not_encoded(
    prefix: int, payload: str, address: str
) -> None:
    """An account index is not encoded.

    polkadot-js encodes payloads of 1, 2, 4 or 8 bytes; Substrate and this
    do not.
    """
    with pytest.raises(Base58Bech32ValueError, match="invalid size: "):
        ss58_encode(prefix, payload)
    with pytest.raises(Base58Bech32ValueError, match="invalid SS58 address size: "):
        ss58_decode(address)


@pytest.mark.parametrize("address, payload", DECODE["decode_short_payload"])
def test_an_account_index_is_not_decoded(address: str, payload: str) -> None:
    """polkadot-js's short decode vectors, refused as a wrong length."""
    with pytest.raises(Base58Bech32ValueError, match="invalid SS58 address size: "):
        ss58_decode(address)


@pytest.mark.parametrize("prefix, payload", ENCODE["encode_invalid_payload"])
def test_a_wrong_payload_size_is_refused(prefix: int, payload: str) -> None:
    """polkadot-js's 30-byte key, refused by the encoder."""
    with pytest.raises(Base58Bech32ValueError, match="invalid size: 30 bytes"):
        ss58_encode(prefix, payload)


@pytest.mark.parametrize("prefix", ENCODE["encode_invalid_prefix"])
def test_a_prefix_out_of_range_or_reserved_is_refused(prefix: int) -> None:
    """polkadot-js's refused prefixes: -1, 16384 and the reserved 46 and 47."""
    with pytest.raises(Base58Bech32ValueError, match="SS58 prefix: "):
        ss58_encode(prefix, bytes(32))


@pytest.mark.parametrize("address", DECODE["decode_invalid_length"])
def test_decode_invalid_length(address: str) -> None:
    """polkadot-js's string of a wrong length."""
    with pytest.raises(Base58Bech32ValueError, match="invalid SS58 address size: "):
        ss58_decode(address)


@pytest.mark.parametrize("address", DECODE["decode_invalid_checksum"])
def test_decode_invalid_checksum(address: str) -> None:
    """polkadot-js's strings whose checksum does not match."""
    with pytest.raises(Base58Bech32ValueError, match="^invalid SS58 checksum$"):
        ss58_decode(address)


@pytest.mark.parametrize("address", DECODE["decode_invalid_base58"])
def test_decode_invalid_base58(address: str) -> None:
    """polkadot-js's string carrying an "I", which is no base58 character."""
    with pytest.raises(Base58Bech32ValueError, match="invalid characters"):
        ss58_decode(address)


def _address(data: bytes) -> bytes:
    """Return the Base58 of `data` and its SS58 checksum, whatever `data` is."""
    checksum = hashlib.blake2b(b"SS58PRE" + data, digest_size=64).digest()[:2]
    return b58encode(data + checksum)


def test_a_reserved_prefix_is_refused_by_the_decoder() -> None:
    """46 and 47, correctly checksummed, as Substrate's `FormatNotAllowed`."""
    for prefix in (46, 47):
        with pytest.raises(
            Base58Bech32ValueError, match=f"reserved SS58 prefix: {prefix}"
        ):
            ss58_decode(_address(bytes([prefix]) + bytes(32)))


def test_the_two_byte_form_of_a_one_byte_prefix_is_refused() -> None:
    """0x40 0x00 reads as prefix 0, which has its own one-byte form.

    Substrate decodes it, which gives the account a second address.
    """
    with pytest.raises(Base58Bech32ValueError, match="prefix: 0 in the two-byte form"):
        ss58_decode(_address(b"\x40\x00" + bytes(32)))
    assert ss58_decode(_address(b"\x00" + bytes(32))) == (0, bytes(32))


def test_a_prefix_byte_above_127_is_refused() -> None:
    """The top bit of the first byte is no prefix form."""
    with pytest.raises(Base58Bech32ValueError, match="invalid SS58 prefix byte: 128"):
        ss58_decode(_address(b"\x80\x00" + bytes(32)))


def test_too_short_and_too_long() -> None:
    """Under two bytes, and over the longest string, are refused first."""
    with pytest.raises(Base58Bech32ValueError, match="invalid SS58 address size: 1"):
        ss58_decode("2")
    with pytest.raises(Base58Bech32ValueError, match="length: 52 characters"):
        ss58_decode("2" * 52)
    # the longest form is 51 characters at most, and is decoded
    longest = ss58_encode(16383, b"\xff" * 33)
    assert len(longest) <= 51
    assert ss58_decode(longest) == (16383, b"\xff" * 33)


def test_the_prefix_is_an_integer() -> None:
    """A bool or a float is no prefix."""
    for prefix in (True, 42.0, "42"):
        with pytest.raises(Base58Bech32TypeError, match="invalid SS58 prefix type: "):
            ss58_encode(prefix, bytes(32))  # type: ignore[arg-type]


def test_the_prefix_forms() -> None:
    """63 is the last one-byte prefix, and 64 the first two-byte one."""
    assert len(b58decode(ss58_encode(63, bytes(32)))) == 1 + 32 + 2
    assert len(b58decode(ss58_encode(64, bytes(32)))) == 2 + 32 + 2


@given(
    prefix=st.integers(0, 16383).filter(lambda p: p not in {46, 47}),
    payload=st.one_of(
        st.binary(min_size=32, max_size=32), st.binary(min_size=33, max_size=33)
    ),
)
def test_round_trip(prefix: int, payload: bytes) -> None:
    """Every prefix and payload comes back, in a string of at most 51."""
    address = ss58_encode(prefix, payload)
    assert len(address) <= 51
    assert ss58_decode(address) == (prefix, payload)
    assert ss58_decode(address.decode("ascii")) == (prefix, payload)


# the addresses of polkadot-js's `checksum.spec.ts` with a two-byte prefix of
# 69 and of 252, whose payload is 32 bytes; its decode vectors have others
@pytest.mark.parametrize(
    "address, prefix",
    [
        ("cnVvyMzRdqjwejTFuByQQ4w2yu78V2hpFixjHQz5zr6NSYsxA", 69),
        ("xw8Ffc2SZtDqUJKd9Ky4vc7PRz2D2asuVkEEzf3WGAbw9cnfq", 252),
    ],
)
def test_polkadot_js_two_byte_prefixes_are_read(address: str, prefix: int) -> None:
    """The prefix, and the payload with which the address is written again."""
    decoded_prefix, payload = ss58_decode(address)
    assert decoded_prefix == prefix
    assert len(payload) == 32
    assert ss58_encode(prefix, payload) == address.encode("ascii")
