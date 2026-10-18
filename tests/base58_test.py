# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `base58_bech32.base58` module.

btclib's tests of its `base58` module, ported, with the vectors of
Bitcoin Core and of the `base58` package beside them, both pinned in
tests/_data/README.md.
"""

from __future__ import annotations

import array
import hmac
import itertools
from collections.abc import Callable

import pytest
from hypothesis import given
from hypothesis import strategies as st

from base58_bech32.base58 import (
    _PLAIN_MAX,
    BITCOIN_ALPHABET,
    MAX_LENGTH,
    RIPPLE_ALPHABET,
    _b58decode_to_int,
    _b58encode_from_int,
    _tables,
    b58decode,
    b58decode_check,
    b58encode,
    b58encode_check,
)
from base58_bech32.exceptions import Base58Bech32TypeError, Base58Bech32ValueError
from tests import load, vector_id

# Bitcoin Core's `src/test/data/base58_encode_decode.json`: [hex, base58]
# rows of Core's `EncodeBase58`/`DecodeBase58`, the codec with no checksum
CODEC_VECTORS = [
    pytest.param(hexed, encoded, id=vector_id(index, hexed[:16]))
    for index, (hexed, encoded) in enumerate(load("_data", "base58_encode_decode.json"))
]

# the `base58` package's own known answers, transcribed from its tests
PACKAGE = load("_data", "base58_package_vectors.json")

_DIGIT_OF, _CHAR_OF = _tables(BITCOIN_ALPHABET)


@pytest.mark.parametrize("hexed, encoded", CODEC_VECTORS)
def test_core_codec_vectors(hexed: str, encoded: str) -> None:
    """Both directions of Core's codec vectors, over plain Base58.

    One row is 256 bytes, 348 characters: `b58decode_check` would refuse
    it on `MAX_LENGTH`, the plain decoder being uncapped.
    """
    raw = bytes.fromhex(hexed)
    assert b58encode(raw) == encoded.encode("ascii")
    assert b58decode(encoded) == raw
    assert b58decode(encoded.encode("ascii")) == raw


@pytest.mark.parametrize("hexed, encoded", PACKAGE["b58encode"])
def test_the_base58_packages_encodings(hexed: str, encoded: str) -> None:
    """The `base58` package's `b58encode` known answers."""
    assert b58encode(bytes.fromhex(hexed)) == encoded.encode("ascii")


@pytest.mark.parametrize("encoded, hexed", PACKAGE["b58decode"])
def test_the_base58_packages_decodings(encoded: str, hexed: str) -> None:
    """The `base58` package's `b58decode` known answers, str and bytes."""
    assert b58decode(encoded) == bytes.fromhex(hexed)
    assert b58decode(encoded.encode("ascii")) == bytes.fromhex(hexed)


@pytest.mark.parametrize("hexed, encoded", PACKAGE["b58encode_check"])
def test_the_base58_packages_checked_vectors(hexed: str, encoded: str) -> None:
    """The `base58` package's Base58Check known answer, both directions."""
    assert b58encode_check(bytes.fromhex(hexed)) == encoded.encode("ascii")
    assert b58decode_check(encoded) == bytes.fromhex(hexed)


@pytest.mark.parametrize("encoded", PACKAGE["b58decode_check_invalid"])
def test_the_base58_packages_checksum_failure(encoded: str) -> None:
    """The `base58` package's corrupted string fails the checksum here too."""
    with pytest.raises(Base58Bech32ValueError, match="^invalid checksum: "):
        b58decode_check(encoded)


@pytest.mark.parametrize("encoded, hexed", PACKAGE["b58decode_int"])
def test_the_base58_packages_large_integer(encoded: str, hexed: str) -> None:
    """The `base58` package's integer, read as bytes: one leading zero byte.

    The alphabet in order, whose first character is the digit zero.
    """
    n = int(hexed, 16)
    assert _b58decode_to_int(encoded.encode("ascii"), _DIGIT_OF) == n
    assert _b58encode_from_int(n, _CHAR_OF) == encoded[1:].encode("ascii")
    assert b58decode(encoded) == b"\0" + n.to_bytes((n.bit_length() + 7) // 8, "big")


@pytest.mark.parametrize("encoded", PACKAGE["b58decode_invalid"])
def test_the_base58_packages_invalid_input(encoded: str) -> None:
    """A backspace is no base58 character."""
    with pytest.raises(Base58Bech32ValueError, match="invalid characters"):
        b58decode(encoded)


@pytest.mark.parametrize("alphabet", [BITCOIN_ALPHABET, RIPPLE_ALPHABET])
def test_round_trips_over_both_alphabets(alphabet: bytes) -> None:
    """The `base58` package's round trip: every short string of four bytes.

    Its third alphabet, Base45's, is no Base58 alphabet and is refused
    here.
    """
    possible_bytes = [b"\x00", b"\x01", b"\x10", b"\xff"]
    for length in range(5):
        for bytes_to_test in itertools.product(possible_bytes, repeat=length):
            raw = b"".join(bytes_to_test)
            assert (
                b58decode(b58encode(raw, alphabet=alphabet), alphabet=alphabet) == raw
            )
            checked = b58encode_check(raw, alphabet=alphabet)
            assert b58decode_check(checked, alphabet=alphabet) == raw


@pytest.mark.parametrize("alphabet", [BITCOIN_ALPHABET, RIPPLE_ALPHABET])
def test_simple_integers(alphabet: bytes) -> None:
    """Each character of an alphabet is the digit of its position."""
    digit_of, char_of = _tables(alphabet)
    for index, char in enumerate(alphabet):
        assert _b58decode_to_int(bytes([char]), digit_of) == index
        assert _b58encode_from_int(index, char_of) == bytes([char])


def test_the_ripple_alphabet() -> None:
    """Ripple's alphabet writes a zero byte as its own first character, "r".

    The account id of zeros is Ripple's well-known "black hole" address,
    rrrrrrrrrrrrrrrrrrrrrhoLvTp, the version byte 0 and twenty zero bytes.
    """
    assert b58encode(b"\0", alphabet=RIPPLE_ALPHABET) == b"r"
    black_hole = b"rrrrrrrrrrrrrrrrrrrrrhoLvTp"
    assert b58encode_check(bytes(21), alphabet=RIPPLE_ALPHABET) == black_hole
    assert b58decode_check(black_hole, alphabet=RIPPLE_ALPHABET) == bytes(21)
    # the same payload is another string in Bitcoin's alphabet
    assert b58encode_check(bytes(21)) != black_hole


@pytest.mark.parametrize(
    "alphabet, err_msg",
    [
        (BITCOIN_ALPHABET[:-1], "invalid alphabet size: 57 bytes instead of 58"),
        (BITCOIN_ALPHABET + b"0", "invalid alphabet size: 59 bytes instead of 58"),
        (BITCOIN_ALPHABET[:-1] + b"1", "invalid alphabet: repeated characters"),
        (BITCOIN_ALPHABET[:-1] + b"\xff", "invalid alphabet: non-ascii byte"),
        (b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:", "invalid alphabet size"),
    ],
)
def test_an_alphabet_is_58_distinct_bytes(alphabet: bytes, err_msg: str) -> None:
    """Every function refuses an alphabet not of 58 distinct ascii bytes."""
    calls: list[Callable[[], bytes]] = [
        lambda: b58encode(b"\1", alphabet=alphabet),
        lambda: b58decode("2", alphabet=alphabet),
        lambda: b58encode_check(b"\1", alphabet=alphabet),
        lambda: b58decode_check("2", alphabet=alphabet),
    ]
    for call in calls:
        with pytest.raises(Base58Bech32ValueError, match=err_msg):
            call()


def test_an_alphabet_is_bytes() -> None:
    """A str alphabet is refused as a type, not read as its characters."""
    with pytest.raises(Base58Bech32TypeError, match="invalid alphabet type: str"):
        b58encode(b"\1", alphabet=BITCOIN_ALPHABET.decode())  # type: ignore[arg-type]


def test_the_two_alphabets_are_one_set_in_two_orders() -> None:
    """Ripple's alphabet permutes Bitcoin's, so one string decodes two ways."""
    assert set(RIPPLE_ALPHABET) == set(BITCOIN_ALPHABET)
    assert b58decode("2") == b"\x01"
    assert b58decode("2", alphabet=RIPPLE_ALPHABET) == b"\x21"
    with pytest.raises(Base58Bech32ValueError, match="invalid characters"):
        b58decode("0", alphabet=RIPPLE_ALPHABET)


def test_empty() -> None:
    """Round-trip the empty payload, checksummed or not."""
    assert b58encode(b"") == b""
    assert b58decode(b"") == b""
    assert b58decode_check(b58encode_check(b""), out_size=0) == b""


def test_hello_world() -> None:
    """Check the 'hello world' known answer, in both directions."""
    assert b58encode(b"hello world") == b"StV1DL6CwTryKyV"
    assert b58decode(b"StV1DL6CwTryKyV") == b"hello world"
    assert b58decode_check(b58encode_check(b"hello world"), out_size=11) == (
        b"hello world"
    )


def test_leading_zeros() -> None:
    """Verify leading zero bytes become leading '1' characters, and back."""
    assert b58encode(b"\x00\x00hello world") == b"11StV1DL6CwTryKyV"
    assert b58decode(b"11StV1DL6CwTryKyV") == b"\x00\x00hello world"
    encoded = b58encode_check(b"\x00\x00hello world")
    assert b58decode_check(encoded, out_size=13) == b"\x00\x00hello world"


def test_a_hex_string_is_octets() -> None:
    """A str payload is hex, as `Octets` is everywhere in the package."""
    assert b58encode("68656c6c6f20776f726c64") == b"StV1DL6CwTryKyV"
    with pytest.raises(Base58Bech32ValueError, match="invalid hex string"):
        b58encode("hello world")


def test_exceptions() -> None:
    """Check the message of each way `b58decode_check` refuses an input."""
    encoded = b58encode_check(b"hello world")
    b58decode_check(encoded, out_size=11)

    wrong_length = len(encoded) - 1
    with pytest.raises(Base58Bech32ValueError, match="invalid decoded size: "):
        b58decode_check(encoded, out_size=wrong_length)

    # a requested size smaller than what decoded, not larger: `== out_size`
    # weakened to `>= out_size` refuses the size above and accepts this one
    with pytest.raises(Base58Bech32ValueError, match="invalid decoded size: "):
        b58decode_check(encoded, out_size=5)

    invalid_checksum = encoded[:-4] + b"1111"
    with pytest.raises(Base58Bech32ValueError, match="invalid checksum: "):
        b58decode_check(invalid_checksum, out_size=4)

    # the expected checksum is quoted unless the caller says its payload is
    # secret
    with pytest.raises(Base58Bech32ValueError, match="^invalid checksum$"):
        b58decode_check(invalid_checksum, out_size=4, secret=True)

    # a character outside ascii is an invalid base58 character like any
    # other, not a UnicodeEncodeError
    err_msg = "^non-ascii character in base58 string at position 1$"
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        b58decode_check("hèllo world")
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        b58decode("hèllo world")

    err_msg = "not enough bytes for checksum, invalid base58 decoded size: "
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        b58decode_check(b58encode(b"123"))


def test_a_size_is_an_integer() -> None:
    """`out_size` refuses a bool, which would accept a one-octet payload."""
    encoded = b58encode_check(b"\1")
    with pytest.raises(Base58Bech32TypeError, match="invalid output size type: bool"):
        b58decode_check(encoded, out_size=True)
    with pytest.raises(Base58Bech32ValueError, match="invalid size: 1 bytes"):
        b58encode_check(b"\1", in_size=2)
    assert b58encode_check(b"\1", in_size=(1, 2)) == encoded


def test_a_string_is_text_or_bytes() -> None:
    """What is neither is a type error, from either decoder."""
    for decode in (b58decode, b58decode_check):
        with pytest.raises(Base58Bech32TypeError, match="invalid base58 string type"):
            decode(58)  # type: ignore[arg-type]


def test_wif() -> None:
    """Reproduce the Bitcoin wiki's WIF vectors, compressed and not."""
    # https://en.bitcoin.it/wiki/Wallet_import_format
    prv = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D

    uncompressed_key = b"\x80" + prv.to_bytes(32, byteorder="big", signed=False)
    uncompressed_wif = b"5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
    assert b58encode_check(uncompressed_key) == uncompressed_wif
    assert b58decode_check(uncompressed_wif) == uncompressed_key

    compressed_key = uncompressed_key + b"\x01"
    compressed_wif = b"KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
    assert b58encode_check(compressed_key) == compressed_wif
    assert b58decode_check(compressed_wif) == compressed_key
    assert b58decode_check(compressed_wif.decode()) == compressed_key


def test_encode_octets_spellings() -> None:
    """The encoders take every `Octets` spelling, memoryview included."""
    payload = b"hello world"
    for spelling in (payload, bytearray(payload), memoryview(payload)):
        assert b58encode_check(spelling) == b"3vQB7B6MrGQZaxCuFg4oh"
        assert b58encode(spelling) == b"StV1DL6CwTryKyV"


def test_integers() -> None:
    """Verify the integer codec over each digit and the full alphabet."""
    digits = BITCOIN_ALPHABET
    for i in range(len(digits)):
        char = digits[i : i + 1]
        assert _b58decode_to_int(char, _DIGIT_OF) == i
        assert _b58encode_from_int(i, _CHAR_OF) == char
    number = (
        "0111d38e5fc9071ffcd20b4a763cc9ae4f252bb4e4"
        "8fd66a835e252ada93ff480d6dd43dc62a641155a5"
    )
    n = int(number, 16)
    assert _b58decode_to_int(digits, _DIGIT_OF) == n
    assert _b58encode_from_int(n, _CHAR_OF) == digits[1:]


def test_max_length() -> None:
    """Decoding is quadratic, so the checked decoder bounds its input first."""
    # a 78-byte BIP32 extended key: 112 characters, the cap itself
    longest = b58encode_check(b"\xff" * 78)
    assert len(longest) == MAX_LENGTH
    assert b58decode_check(longest, out_size=78) == b"\xff" * 78

    err_msg = f"too many base58 characters: {MAX_LENGTH + 1}, max is {MAX_LENGTH}"
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        b58decode_check(b"1" * (MAX_LENGTH + 1))
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        b58decode_check("1" * (MAX_LENGTH + 1))
    # the plain decoder is uncapped
    assert b58decode("1" * (MAX_LENGTH + 1)) == bytes(MAX_LENGTH + 1)


def test_decode_refuses_a_memoryview_of_the_wrong_shape() -> None:
    """A strided or wide-format memoryview is refused, not gathered silently."""
    strided = memoryview(b"1" * 40)[::2]
    wide = memoryview(array.array("I", [0x31313131] * 3))
    assert len(wide) == 3
    assert wide.nbytes == 12
    for decode in (b58decode, b58decode_check):
        with pytest.raises(Base58Bech32ValueError, match="non-contiguous"):
            decode(strided)
        with pytest.raises(Base58Bech32ValueError, match="memoryview format"):
            decode(wide)


@given(payload=st.binary(max_size=78))
def test_round_trip(payload: bytes) -> None:
    """Whatever goes in comes back, checksum and leading zeros included.

    78 bytes is the largest payload `MAX_LENGTH` leaves room for.
    """
    encoded = b58encode_check(payload)
    assert len(encoded) <= MAX_LENGTH
    assert b58decode_check(encoded) == payload
    assert b58decode_check(encoded, out_size=len(payload)) == payload
    assert b58decode_check(encoded.decode("ascii")) == payload
    assert b58decode(b58encode(payload)) == payload


def test_a_refused_alphabet_is_refused_whatever_was_cached() -> None:
    """A refused alphabet stays refused, and an accepted one accepted."""
    bad = BITCOIN_ALPHABET[:-1] + b"1"
    err_msg = "invalid alphabet: repeated characters"
    _tables.cache_clear()
    # a good alphabet cached, then a bad one
    assert b58encode(b"\1") == b"2"
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        b58encode(b"\1", alphabet=bad)
    # a bad one refused twice, then the good one again
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        b58decode("2", alphabet=bad)
    assert b58decode("2") == b"\1"
    # a bad alphabet refused first, then accepted when it is the good one
    _tables.cache_clear()
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        b58encode_check(b"\1", alphabet=bad)
    assert b58decode_check(b58encode_check(b"\1")) == b"\1"


def test_a_string_decodes_the_same_on_both_sides_of_the_plain_loop() -> None:
    """The loop that reads a digit at a time and the chunked one agree."""
    for length in (_PLAIN_MAX - 1, _PLAIN_MAX, _PLAIN_MAX + 1, 2 * _PLAIN_MAX + 3):
        s = (BITCOIN_ALPHABET[1:] * 3)[:length]
        expected = 0
        for char in s:
            expected = expected * 58 + BITCOIN_ALPHABET.index(char)
        assert _b58decode_to_int(s, _DIGIT_OF) == expected


def test_the_checksum_is_compared_in_constant_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`b58decode_check` compares checksums with `hmac.compare_digest`."""
    calls: list[tuple[bytes, bytes]] = []
    compare_digest = hmac.compare_digest

    def spy(a: bytes, b: bytes) -> bool:
        calls.append((a, b))
        return compare_digest(a, b)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    good = b58encode_check(b"\1" * 21)
    assert b58decode_check(good) == b"\1" * 21
    assert len(calls) == 1
    with pytest.raises(Base58Bech32ValueError, match="invalid checksum"):
        b58decode_check(good[:-1] + b"2")
    assert len(calls) == 2
