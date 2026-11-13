# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `base58_bech32.strkey` module.

The vectors are the *Tests* section of SEP-0023, Stellar's strkey
specification, transcribed into tests/_data/strkey_vectors.json and
pinned in tests/_data/README.md.

Some of its invalid cases decode: what makes them invalid is the size or
the layout of the payload their version byte names, which is above this
codec. `_key_type_refusal` models those rules of SEP-0023, and the tests
ask it to refuse each such case and to accept every valid one.
"""

from __future__ import annotations

import base64
import hmac

import pytest
from hypothesis import given
from hypothesis import strategies as st
from typing_extensions import override

from base58_bech32.exceptions import Base58Bech32TypeError, Base58Bech32ValueError
from base58_bech32.strkey import _checksum, strkey_decode, strkey_encode

from . import EncodesOther, load, vector_id

VECTORS = load("_data", "strkey_vectors.json")

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

# SEP-0023's key types whose payload has one size: the base value, which
# is the top five bits of the version byte, and that size
_SIZES = {6: 32, 12: 40, 18: 32, 19: 32, 23: 32, 2: 32, 11: 32, 1: 33, 22: 40}
_SIGNED_PAYLOAD = 15
_CLAIMABLE_BALANCE = 1
# what a signed payload starts with: an ed25519 key, then the length of
# the payload as four bytes
_SIGNER_SIZE = 32
_LENGTH_SIZE = 4


def _key_type_refusal(version: int, payload: bytes) -> str | None:
    """Return why SEP-0023 refuses a version byte and payload, if it does.

    The algorithm, in the low three bits, is zero, the only one SEP-0023
    defines. A signed payload is a key, the length, the payload and zero
    padding to a multiple of four bytes. A claimable balance starts with
    its type, of which SEP-0023 defines zero alone.
    """
    if version & 0b111:
        return "algorithm"
    kind = version >> 3
    if kind == _SIGNED_PAYLOAD:
        start = _SIGNER_SIZE + _LENGTH_SIZE
        size = int.from_bytes(payload[_SIGNER_SIZE:start], "big")
        if len(payload) != start + size + -size % 4:
            return "signed payload length"
        return None
    if len(payload) != _SIZES[kind]:
        return "size"
    if kind == _CLAIMABLE_BALANCE and payload[0]:
        return "claimable balance type"
    return None


@pytest.mark.parametrize(
    "strkey, version, payload",
    [
        pytest.param(*vector, id=vector_id(index, vector[0][:16]))
        for index, vector in enumerate(VECTORS["valid"])
    ],
)
def test_the_valid_cases(strkey: str, version: int, payload: str) -> None:
    """Each is its version byte and payload, which its key type accepts."""
    raw = bytes.fromhex(payload)
    assert strkey_decode(strkey) == (version, raw)
    assert strkey_decode(strkey.encode("ascii")) == (version, raw)
    assert strkey_encode(version, raw) == strkey.encode("ascii")
    assert strkey_encode(version, payload) == strkey.encode("ascii")
    assert _key_type_refusal(version, raw) is None


# the codec's answer to each invalid case, in the file's order: its
# refusal, or None where the case decodes and its key type refuses it.
# SEP-0023's reason for the "M47" string is its algorithm bits; its
# checksum is not that of its version byte, which the codec refuses first
_INVALID: list[str | None] = [
    None,
    "^invalid strkey: unused bits not zero$",
    "^invalid strkey length: 57 characters$",
    None,
    None,
    "^invalid strkey length: 70 characters$",
    None,
    "^invalid strkey checksum$",
    "^invalid strkey character$",
    "^invalid strkey checksum$",
    None,
    None,
    None,
    "^invalid strkey: unused bits not zero$",
    None,
    "^invalid strkey: unused bits not zero$",
    "^invalid strkey length: 70 characters$",
    None,
    None,
    "^invalid strkey checksum$",
]


@pytest.mark.parametrize(
    "strkey, refusal",
    [
        pytest.param(strkey, refusal, id=vector_id(index, reason))
        for index, ((strkey, reason), refusal) in enumerate(
            zip(VECTORS["invalid"], _INVALID, strict=True)
        )
    ],
)
def test_the_invalid_cases(strkey: str, refusal: str | None) -> None:
    """Each is refused by the codec, or decoded and refused by its key type."""
    if refusal is None:
        assert _key_type_refusal(*strkey_decode(strkey)) is not None
    else:
        with pytest.raises(Base58Bech32ValueError, match=refusal):
            strkey_decode(strkey)


@pytest.mark.parametrize("length", range(24))
def test_the_lengths(length: int) -> None:
    """A length congruent to 1, 3 or 6 mod 8 is refused; any other is bytes'.

    A run of "A" is zero bits, whose CRC16-XModem is zero, so where it
    holds three bytes or more it is a strkey of version byte zero.
    """
    text = "A" * length
    size = 5 * length // 8
    if length % 8 in {1, 3, 6}:
        err_msg = f"^invalid strkey length: {length} characters$"
        with pytest.raises(Base58Bech32ValueError, match=err_msg):
            strkey_decode(text)
    elif size < 3:
        err_msg = f"^invalid strkey size: {size} bytes$"
        with pytest.raises(Base58Bech32ValueError, match=err_msg):
            strkey_decode(text)
    else:
        assert strkey_decode(text) == (0, bytes(size - 3))
        assert strkey_encode(0, bytes(size - 3)) == text.encode("ascii")


@pytest.mark.parametrize("size, unused", [(0, 1), (1, 3), (3, 2), (4, 4)])
def test_an_unused_bit_set_is_refused(size: int, unused: int) -> None:
    """Each bit the last character holds of no byte, set alone.

    A payload of `size` bytes leaves `unused` bits in the last character,
    and one of 2 bytes leaves none.
    """
    strkey = strkey_encode(0, bytes(range(size))).decode("ascii")
    assert 5 * len(strkey) % 8 == unused
    last = ALPHABET.index(strkey[-1])
    for bit in range(unused):
        text = strkey[:-1] + ALPHABET[last | 1 << bit]
        with pytest.raises(
            Base58Bech32ValueError, match="^invalid strkey: unused bits not zero$"
        ):
            strkey_decode(text)


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(VECTORS["valid"][0][0].lower(), id="lowercase"),
        pytest.param(VECTORS["valid"][0][0] + "=", id="padding"),
        pytest.param(" " + VECTORS["valid"][0][0], id="space"),
        pytest.param(
            "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSG0", id="0"
        ),
        pytest.param("\N{KELVIN SIGN}" * 8, id="kelvin-sign"),
    ],
)
def test_a_character_outside_the_alphabet_is_refused(text: str) -> None:
    """Lowercase included: a lowercase strkey re-encodes to its uppercase."""
    with pytest.raises(Base58Bech32ValueError, match="^invalid strkey character$"):
        strkey_decode(text)


def test_a_non_ascii_byte_is_refused() -> None:
    """Bytes are read as ascii, as every decoder of the package reads them."""
    err_msg = "^non-ascii character in strkey at position 2$"
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        strkey_decode(b"GA\xc0AAAAA")


def test_a_str_subclass_is_read_as_its_characters() -> None:
    """Its own `encode` does not decide what the decoder reads."""
    strkey, version, payload = VECTORS["valid"][0]
    assert strkey_decode(EncodesOther(strkey)) == (version, bytes.fromhex(payload))


@pytest.mark.parametrize("version", [-1, 256])
def test_a_version_byte_out_of_range_is_refused(version: int) -> None:
    """A byte is from 0 to 255."""
    err_msg = "^invalid strkey version byte: .* not in 0..255$"
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        strkey_encode(version, b"")


class _InRange(int):
    """An int whose own comparisons say it is in any range.

    `0 <= value <= 255` calls these two: Python tries a subclass's
    reflected `__ge__` before int's `__le__`.
    """

    __slots__ = ()

    @override
    def __le__(self, other: object) -> bool:
        return True

    @override
    def __ge__(self, other: object) -> bool:
        return True


@pytest.mark.parametrize("version", [-1, 256])
def test_an_int_subclass_does_not_decide_the_range(version: int) -> None:
    """Its value is checked, whatever its own comparisons answer."""
    # what the comparisons answer, which would let the value through
    assert 0 <= _InRange(version) <= 0xFF
    err_msg = "^invalid strkey version byte: .* not in 0..255$"
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        strkey_encode(_InRange(version), b"")


def test_an_int_subclass_in_range_is_its_value() -> None:
    """The byte written is the int's value."""
    assert strkey_encode(_InRange(48), b"") == strkey_encode(48, b"")


def test_a_version_byte_is_an_integer() -> None:
    """Neither a str nor bytes of one byte."""
    with pytest.raises(
        Base58Bech32TypeError, match="^invalid strkey version byte type"
    ):
        strkey_encode(b"\x30", b"")  # type: ignore[arg-type]


def _crc16_xmodem(data: bytes) -> int:
    """Return the CRC16-XModem of `data`, a bit at a time.

    The polynomial 0x1021, from zero, most significant bit first and with
    no final xor.
    """
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = (crc << 1) ^ 0x1021 if crc & 0x8000 else crc << 1
            crc &= 0xFFFF
    return crc


def test_the_reference_crc_gives_the_xmodem_check_value() -> None:
    """The CRC of "123456789", which CRC catalogues give as its check."""
    assert _crc16_xmodem(b"123456789") == 0x31C3


@given(data=st.binary(max_size=128))
def test_the_checksum_is_the_crc16_xmodem_little_endian(data: bytes) -> None:
    """`binascii.crc_hqx` from zero, against the reference above."""
    assert _checksum(data) == _crc16_xmodem(data).to_bytes(2, "little")


@given(version=st.integers(0, 255), payload=st.binary(max_size=128))
def test_round_trip(version: int, payload: bytes) -> None:
    """Every version byte and payload comes back."""
    strkey = strkey_encode(version, payload)
    assert strkey_decode(strkey) == (version, payload)
    assert strkey_decode(strkey.decode("ascii")) == (version, payload)


def _round_trip_reference(text: str) -> tuple[int, bytes] | None:
    """Read a strkey as js-stellar-base's `decodeCheck` does, if it can.

    Decode leniently, refuse a string that does not re-encode to itself,
    and verify the checksum, with the reference CRC. SEP-0023 offers this
    round trip as the way to refuse what the codec refuses check by check.
    """
    try:
        data = base64.b32decode(text + "=" * (-len(text) % 8))
    except ValueError:
        return None
    if base64.b32encode(data).rstrip(b"=") != text.encode("ascii"):
        return None
    if len(data) < 3:
        return None
    body, checksum = data[:-2], data[-2:]
    if int.from_bytes(checksum, "little") != _crc16_xmodem(body):
        return None
    return body[0], body[1:]


_A_STRKEY = st.builds(strkey_encode, st.integers(0, 255), st.binary(max_size=64)).map(
    lambda strkey: strkey.decode("ascii")
)


@st.composite
def _strkey_changed(draw: st.DrawFn) -> str:
    """Draw a strkey with one character changed, inserted or removed."""
    strkey = draw(_A_STRKEY)
    i = draw(st.integers(0, len(strkey) - 1))
    char = draw(st.sampled_from(f"{ALPHABET}a=0"))
    changed = strkey[:i] + char + strkey[i + 1 :]
    inserted = strkey[:i] + char + strkey[i:]
    removed = strkey[:i] + strkey[i + 1 :]
    return draw(st.sampled_from([changed, inserted, removed]))


@given(
    text=st.one_of(
        st.text(alphabet=f"{ALPHABET}a=0", max_size=80),
        st.text(alphabet="A", max_size=80),
        _A_STRKEY,
        _strkey_changed(),
    )
)
def test_what_the_decoder_reads_is_what_re_encodes_to_itself(text: str) -> None:
    """The codec and the round trip read the same strings, as the same bytes."""
    try:
        decoded: tuple[int, bytes] | None = strkey_decode(text)
    except Base58Bech32ValueError:
        decoded = None
    assert decoded == _round_trip_reference(text)


def test_the_checksum_is_compared_with_compare_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`strkey_decode` compares checksums with `hmac.compare_digest`."""
    calls: list[tuple[bytes, bytes]] = []
    compare_digest = hmac.compare_digest

    def spy(a: bytes, b: bytes) -> bool:
        calls.append((a, b))
        return compare_digest(a, b)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    strkey = strkey_encode(0, bytes(32))
    assert strkey_decode(strkey) == (0, bytes(32))
    assert len(calls) == 1
    changed = strkey[:-1] + (b"B" if strkey[-1:] != b"B" else b"C")
    with pytest.raises(Base58Bech32ValueError, match="^invalid strkey checksum$"):
        strkey_decode(changed)
    assert len(calls) == 2
