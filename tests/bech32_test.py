# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

# Copyright (c) 2017 Pieter Wuille
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""Tests for the `base58_bech32.bech32` module.

btclib's tests of its `bech32` module and of `convertbits`, ported. The
string vectors are originally from
https://github.com/sipa/bech32/tree/master/ref/python, with the following
modifications:

- only the codec's: the segwit address vectors are btclib's
- checked for raised exceptions instead of assertIsNone
"""

import itertools
from enum import IntEnum

import pytest
from hypothesis import given
from hypothesis import strategies as st

from base58_bech32.bech32 import (
    _ALPHABET,
    _GENERATOR,
    _CHAR_OF,
    _DIGIT_OF,
    _NOT_A_DIGIT,
    _TAPS,
    BECH32_1_CONST,
    BECH32_M_CONST,
    _create_checksum,
    _hrp_in_range,
    bech32_decode,
    bech32_encode,
    convertbits,
)
from base58_bech32.exceptions import Base58Bech32TypeError, Base58Bech32ValueError


def test_the_tap_table_holds_the_taps_it_replaces() -> None:
    """Each entry is the XOR of the generator constants its bits select.

    What `_polymod` reads from `_TAPS` once per character, the reference
    computes with the five conditional XORs written out below. `chk >> 25`
    is five bits wide, so the 32 entries are the whole domain: this is
    exhaustive rather than a sample, which is what a table of constants no
    reader can check by eye asks for.
    """
    assert len(_TAPS) == 32
    for top in range(32):
        taps = 0
        for i in range(5):
            taps ^= _GENERATOR[i] if ((top >> i) & 1) else 0
        assert _TAPS[top] == taps


def test_bech32() -> None:
    """Test bech32 checksum."""
    valid_checksum = [
        "A12UEL5L",
        "a12uel5l",
        "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
        "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
        "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        "?1ezyfcl",
        # the next one would have been invalid with the 90 char limit
        "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
    ]

    for test in valid_checksum:
        decoded = bech32_decode(test, m=BECH32_1_CONST)
        assert decoded == bech32_decode(test.encode("ascii"), m=BECH32_1_CONST)
        assert bech32_encode(*decoded, m=BECH32_1_CONST).decode() == test.lower()
        pos = test.rfind("1")
        test = test[: pos + 1] + chr(ord(test[pos + 1]) ^ 1) + test[pos + 2 :]  # noqa: PLW2901
        with pytest.raises(Base58Bech32ValueError):  # assorted error messages
            bech32_decode(test, m=BECH32_1_CONST)

    # a byte outside ascii is not a str bech32_decode() ever receives from the
    # loop above, which only ever encodes an already-valid bech32 string:
    # nothing else exercises the UnicodeDecodeError catch this raises
    # instead of letting fly past a caller written to catch
    # Base58Bech32ValueError
    with pytest.raises(
        Base58Bech32ValueError, match="non-ascii character in bech32 string"
    ):
        bech32_decode(
            b"\xff1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j"
        )

    invalid_checksum = [
        # \x20 and \x7f are the boundary itself, one character below and
        # one above BIP173's HRP range [33-126]: `32 < ord(x) < 127`
        # weakened at either end to `<=` would accept them
        ["\x20" + " 1nwldj5", "HRP character out of range"],
        ["\x7f" + "1axkwrx", "HRP character out of range"],
        ["\x80" + "1eym55h", "HRP character out of range"],
        # mixed case where lowering it does not sort below the original:
        # `bech.lower() != bech` weakened to `< bech` is false here (the
        # raised "u" sorts above the "U" it replaces), and the `and`
        # after it only raises if the upper-casing check also does
        ["a12UEL5L", "mixed case"],
        ["pzry9x0s0muk", "no separator character"],
        ["1pzry9x0s0muk", "empty HRP"],
        ["x1b4n0q5v", "invalid data character"],
        ["li1dgmt3", "too short checksum"],
        # BIP173's "Invalid character in checksum" vector, which the
        # range check refuses before the alphabet lookup is reached
        ["de1lg7wt\xff", "data part character out of range"],
        # the lookup itself, with "b": in range and no bech32 digit
        ["de1lg7wtb", "invalid character in checksum"],
        # the same, at the far end of the checksum rather than the near
        # one: `bech[-6:]` weakened to `bech[-5:]` still catches the
        # vector above (its invalid byte is the very last character) and
        # misses this one, six characters from the end and not five
        ["de1bqpzry", "invalid character in checksum"],
        # checksum calculated with uppercase form of HRP
        ["A1G7SGD8", "invalid checksum"],
        ["10a06t8", "empty HRP"],
        ["1qzzfhee", "empty HRP"],
    ]

    # the whole message and nothing else: a refusal that quoted the
    # string it was given would repeat a key pasted where an address goes
    for addr, err_msg in invalid_checksum:
        with pytest.raises(Base58Bech32ValueError, match=f"^{err_msg}$"):
            bech32_decode(addr, m=BECH32_1_CONST)


def test_hrp_range_matches_bip173() -> None:
    """The HRP range is BIP173's [33-126], past letters, digits and "1".

    btclib-org/btclib#2287: a correctly checksummed string whose HRP sits
    outside a 48..122 window and inside BIP173's [33-126] is accepted. "!"
    (33) and "~" (126) are that range's own boundary; "/" (47) and "{"
    (123) are the narrower window's, ordinary interior characters.
    """
    for hrp in ("!", "~", "/", "{"):
        data = [0]
        checksum = _create_checksum(hrp, data, BECH32_1_CONST)
        s = f"{hrp}1" + "".join(_ALPHABET[d] for d in data + checksum)
        assert bech32_decode(s, m=BECH32_1_CONST) == (hrp, data)
        assert bech32_encode(hrp, data, m=BECH32_1_CONST) == s.encode("ascii")


def test_hrp_range_predicate_is_the_per_character_test() -> None:
    """The three C passes accept what `32 < ord(x) < 127` does, character
    by character, over every code point below U+3000, and a string only
    when each of its characters is accepted."""
    for code in range(0x3000):
        char = chr(code)
        assert _hrp_in_range(char) == (32 < code < 127), code
        assert _hrp_in_range("a" + char + "b") == (32 < code < 127), code
    assert _hrp_in_range("")


def test_the_translation_tables_are_the_alphabet() -> None:
    """`_DIGIT_OF` reads the alphabet and `_CHAR_OF` writes it back."""
    for digit, char in enumerate(_ALPHABET):
        assert _DIGIT_OF[ord(char)] == digit
        assert _CHAR_OF[digit] == ord(char)
    assert len(_DIGIT_OF) == len(_CHAR_OF) == 256
    assert {i for i, d in enumerate(_DIGIT_OF) if d != _NOT_A_DIGIT} == {
        ord(c) for c in _ALPHABET
    }


@pytest.mark.parametrize(
    "address, err_msg",
    [
        # "b", "i", "o" and "1" are no alphabet character
        ("a1qqqqqqb", "invalid character in checksum"),
        ("a1bqqqqqqqqqq", "invalid data character"),
        # the checksum is looked at before the data part
        ("a1bqqqqqqqqqb", "invalid character in checksum"),
        ("a1bqqqqqqqqqqq", "invalid data character"),
        # the first six characters of the data part are not the checksum
        ("a1qqbqqqqqqq", "invalid data character"),
        ("a1qqqqqqqqqqi", "invalid character in checksum"),
        # the range check comes before both
        ("a1b\x7fqqqqqq", "data part character out of range"),
    ],
)
def test_the_lookup_refusals_and_their_order(address: str, err_msg: str) -> None:
    """A checksum character is refused before a data character is."""
    with pytest.raises(Base58Bech32ValueError, match=f"^{err_msg}$"):
        bech32_decode(address, m=BECH32_1_CONST)


def test_a_value_that_is_a_subclass_of_int_is_accepted() -> None:
    """The fast path declines an `IntEnum`, and the loop accepts it."""

    class Digit(IntEnum):
        THREE = 3

    expected = bech32_encode("bc", [3, 3], m=BECH32_1_CONST)
    assert bech32_encode("bc", [Digit.THREE, 3], m=BECH32_1_CONST) == expected
    assert convertbits([Digit.THREE], 5, 5) == [3]


def test_the_first_offending_value_is_the_one_named() -> None:
    """Past the fast path, values are judged in order, as one at a time."""
    with pytest.raises(Base58Bech32ValueError, match="invalid 5-bit value: 40"):
        bech32_encode("bc", [1, 40, "x"], m=BECH32_1_CONST)  # type: ignore[list-item]
    with pytest.raises(Base58Bech32TypeError, match="invalid 5-bit value type: str"):
        bech32_encode("bc", [1, "x", 40], m=BECH32_1_CONST)  # type: ignore[list-item]
    with pytest.raises(Base58Bech32ValueError, match="invalid value: 32"):
        convertbits([1, 32, "x"], 5, 8)  # type: ignore[list-item]
    with pytest.raises(Base58Bech32TypeError, match="invalid value type: str"):
        convertbits([1, "x", 32], 5, 8)  # type: ignore[list-item]
    with pytest.raises(Base58Bech32ValueError, match="invalid value: -1"):
        convertbits([1, -1], 5, 8)
    # the bound is exclusive: 31 is five bits, 32 is not
    assert convertbits([31], 5, 8) == [248]


def test_encode_validates_hrp() -> None:
    """`encode` refuses an HRP `decode` would refuse, rather than writing it.

    btclib-org/btclib#2286: a mixed-case, empty, out-of-range or non-ascii
    HRP is refused before `str.encode("ascii")`, which would let a bare
    `UnicodeEncodeError` out for the non-ascii one.
    """
    with pytest.raises(Base58Bech32TypeError, match="invalid HRP type: int"):
        bech32_encode(123, [0])  # type: ignore[arg-type]

    with pytest.raises(Base58Bech32ValueError, match="empty HRP"):
        bech32_encode("", [0, 1, 2])

    with pytest.raises(Base58Bech32ValueError, match="HRP character out of range: *"):
        bech32_encode("b c", [0])

    # non-ascii: 'é' is above BIP173's range, so this never reaches
    # `str.encode("ascii")` at all
    with pytest.raises(Base58Bech32ValueError, match="HRP character out of range: *"):
        bech32_encode("bé", [0])

    # every data digit `_ALPHABET` can write is lowercase, so an
    # all-uppercase HRP paired with a data digit that is a letter -- as
    # here -- would write a string `decode` refuses as mixed case
    with pytest.raises(Base58Bech32ValueError, match="HRP is not lowercase: *"):
        bech32_encode("BC", [0, 1, 2])


def test_bech32_insertion_issue() -> None:
    """Test documented bech32 insertion issue.

    - https://github.com/sipa/bech32/issues/51
    - https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2019-November/017443.html
    - https://gist.github.com/sipa/a9845b37c1b298a7301c33a04090b2eb
    - https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2020-October/018236.html
    - https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2020-December/018292.html
    - https://gist.github.com/sipa/14c248c288c3880a3b191f978a34508e
    """
    strings = ("ii2134hk2xmat79tp", "eyg5bsz1l2mrq5ypl40hp")
    for string, i in itertools.product(strings, range(20)):
        bech32_decode(string[:-1] + i * "q" + string[-1:], m=BECH32_1_CONST)


def test_bech32m() -> None:
    """Reproduce the reference bech32m checksum vectors, valid and invalid."""
    valid_checksum = [
        "A1LQFN3A",
        "a1lqfn3a",
        "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
        "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
        "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
        "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
        "?1v759aa",
        # the next one would have been invalid with the 90 char limit
        "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
    ]
    for test in valid_checksum:
        decoded = bech32_decode(test, m=BECH32_M_CONST)
        assert decoded == bech32_decode(test.encode("ascii"), m=BECH32_M_CONST)
        assert bech32_encode(*decoded, m=BECH32_M_CONST).decode() == test.lower()
        pos = test.rfind("1")
        test = test[: pos + 1] + chr(ord(test[pos + 1]) ^ 1) + test[pos + 2 :]  # noqa: PLW2901
        with pytest.raises(Base58Bech32ValueError):
            bech32_decode(test, m=BECH32_M_CONST)

    invalid_checksum = [
        ["\x20" + "1xj0phk", "HRP character out of range"],
        ["\x7f" + "1g6xzxy", "HRP character out of range"],
        ["\x80" + "1vctc34", "HRP character out of range"],
        ["qyrz8wqd2c9m", "no separator character"],
        ["1qyrz8wqd2c9m", "empty HRP"],
        ["y1b0jsk6g", "invalid data character"],
        ["lt1igcx5c0", "invalid data character"],
        ["in1muywd", "too short checksum"],
        ["mm1crxm3i", "invalid character in checksum"],
        ["au1s5cgom", "invalid character in checksum"],
        ["M1VUXWEZ", "invalid checksum"],
        ["16plkw9", "empty HRP"],
        ["1p2gdwpf", "empty HRP"],
    ]

    for addr, err_msg in invalid_checksum:
        with pytest.raises(Base58Bech32ValueError, match=f"^{err_msg}$"):
            bech32_decode(addr, m=BECH32_M_CONST)


# lowercase only: encode writes the data part in lowercase, and a
# string mixing the two cases is rejected outright. "1" is left in on
# purpose -- it is the separator, and the hrp is delimited by the *last*
# one, which is the only thing that makes an hrp containing it work
HRP = st.text(alphabet="0123456789abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=10)
# non-empty: the constant to checksum with is chosen by the first value,
# which is the witness version when the payload is an address
DATA = st.lists(st.integers(min_value=0, max_value=31), min_size=1, max_size=80)


@given(hrp=HRP, data=DATA)
def test_round_trip(hrp: str, data: list[int]) -> None:
    """A bech32 string decodes to the hrp and data it was built from."""
    assert bech32_decode(bech32_encode(hrp, data)) == (hrp, data)


@given(hrp=HRP, data=DATA, position=st.integers(min_value=0), value=st.integers(0, 31))
def test_a_changed_character_fails_the_checksum(
    hrp: str, data: list[int], position: int, value: int
) -> None:
    """What the checksum is for, over the whole space rather than a vector."""
    encoded = bech32_encode(hrp, data).decode("ascii")
    # only the data part: changing the hrp is a different address, not a
    # corrupted one, and the separator would move
    body = encoded[len(hrp) + 1 :]
    i = position % len(body)
    mutated = body[:i] + _ALPHABET[value] + body[i + 1 :]
    if mutated == body:
        return
    with pytest.raises(Base58Bech32ValueError, match="^invalid checksum$"):
        bech32_decode(f"{hrp}1{mutated}")


def test_a_value_that_is_no_5_bit_digit_is_refused() -> None:
    """A negative digit would wrap around the alphabet into another string.

    `_ALPHABET[d]` is a plain string index, so Python reads -1 as the
    last character and -32 as the first: unchecked, the encoder would
    answer a correctly checksummed string spelling a payload nobody asked
    for. A digit above 31 would raise `IndexError`, and a float
    `TypeError`.
    """
    valid = [0, 1, 30, 31]
    assert bech32_decode(bech32_encode("bc", valid)) == ("bc", valid)

    for out_of_range in (-1, -32, 32, 2**32):
        with pytest.raises(Base58Bech32ValueError, match="invalid 5-bit value: "):
            bech32_encode("bc", [*valid, out_of_range])
    for not_a_digit in (1.0, "1", None, True):
        with pytest.raises(Base58Bech32TypeError, match="invalid 5-bit value type: "):
            bech32_encode("bc", [*valid, not_a_digit])  # type: ignore[list-item]

    # the boundaries themselves: `< 32` weakened to `<= 32`, or `0 <=`
    # to `-1 <=`, would accept a digit the alphabet has no character for
    assert bech32_encode("bc", [31]) != bech32_encode("bc", [0])


# a valid segwit address of BIP173's, in uppercase, and holding a "K":
# U+212A KELVIN SIGN, its own uppercase, lowers onto "k"
_UPPER = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"


def test_a_character_lowering_onto_the_alphabet_is_refused() -> None:
    """KELVIN SIGN would spell a second string for one decoded address.

    It passes a case check, being its own uppercase, and would then be
    looked up as the "k" that `str.lower` makes of it.
    """
    assert _UPPER.isascii()
    kelvin = _UPPER.replace("K", "\u212a")
    assert kelvin.lower() == _UPPER.lower()
    with pytest.raises(
        Base58Bech32ValueError, match="data part character out of range"
    ):
        bech32_decode(kelvin)
    assert bech32_decode(_UPPER) == bech32_decode(_UPPER.lower())


@pytest.mark.parametrize(
    "char",
    [
        "\u212a",  # KELVIN SIGN, lowers to "k"
        "\u0130",  # LATIN CAPITAL LETTER I WITH DOT ABOVE, lowers to two
        "\u017f",  # LATIN SMALL LETTER LONG S, uppercases to "S"
        "\u1e9e",  # LATIN CAPITAL LETTER SHARP S, casefolds to "ss"
        "\x7f",  # DEL, one above the range
        "\x80",  # one above ASCII
        " ",  # one below the range
        "\x00",
    ],
)
@pytest.mark.parametrize("address", [_UPPER, _UPPER.lower()])
@pytest.mark.parametrize("position", [3, -1])
def test_a_data_part_character_out_of_range_is_refused_first(
    char: str, address: str, position: int
) -> None:
    """Refused for its range, ahead of the case check and the lookup.

    Position 3 is the first data character and -1 the last checksum
    one. The case-mapping characters are the ones the case check or the
    lookup would otherwise diagnose, or, for KELVIN SIGN in the
    uppercase string, accept.
    """
    chars = list(address)
    chars[position] = char
    with pytest.raises(
        Base58Bech32ValueError, match="data part character out of range"
    ):
        bech32_decode("".join(chars))


@given(
    char=st.characters(exclude_characters=[chr(c) for c in range(33, 127)]),
    position=st.integers(min_value=0),
)
def test_no_character_outside_33_126_is_a_data_character(
    char: str, position: int
) -> None:
    """The range, over every code point rather than the named ones."""
    data_part = _UPPER[3:]
    i = position % len(data_part)
    mutated = data_part[:i] + char + data_part[i + 1 :]
    with pytest.raises(
        Base58Bech32ValueError, match="data part character out of range"
    ):
        bech32_decode(f"BC1{mutated}")


# `convertbits`, btclib's `b32.power_of_2_base_conversion`, whose tests
# btclib keeps in b32_test.py beside the segwit addresses


def test_a_value_wider_than_from_bits_is_refused() -> None:
    """A negative value, and one of more than `from_bits` bits.

    256, not only -1: a negative value's `>> from_bits` is always -1 in
    Python, truthy on its own, so `or` weakened to `and` still refuses
    -1; 256 needs the first half of the `or` false and the second true.
    """
    for value in (-1, 256):
        with pytest.raises(Base58Bech32ValueError, match="invalid value: "):
            convertbits([5, value], 8, 5)


@pytest.mark.parametrize(
    "from_bits, to_bits, err_msg",
    [
        (8, 0, "invalid to_bits: 0 < 1"),
        (8, -2, "invalid to_bits: -2 < 1"),
        (0, 5, "invalid from_bits: 0 < 1"),
        (-1, 5, "invalid from_bits: -1 < 1"),
    ],
)
def test_a_conversion_width_is_positive(
    from_bits: int, to_bits: int, err_msg: str
) -> None:
    """A width below 1 is refused before the conversion starts.

    A zero `to_bits` is the one of these that would otherwise never
    return, the regrouping loop subtracting nothing from its counter.
    """
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        convertbits([1], from_bits, to_bits)


def test_a_conversion_width_of_one_is_accepted() -> None:
    """A width of 1 is valid on either side, the refusal above stopping at 0."""
    assert convertbits([1], 8, 1) == [0, 0, 0, 0, 0, 0, 0, 1]
    assert convertbits([1], 1, 8) == [128]
    assert convertbits([1], 1, 1) == [1]


def test_a_conversion_takes_integers_only() -> None:
    """A width, a value, the data or `pad` of another type is a type error."""
    for width in (8.0, "8", None):
        with pytest.raises(Base58Bech32TypeError, match="invalid from_bits type: "):
            convertbits([1], width, 5)  # type: ignore[arg-type]
        with pytest.raises(Base58Bech32TypeError, match="invalid to_bits type: "):
            convertbits([1], 5, width)  # type: ignore[arg-type]
    for value in (1.0, "1", None):
        with pytest.raises(Base58Bech32TypeError, match="invalid value type: "):
            convertbits([value], 8, 5)  # type: ignore[list-item]
    with pytest.raises(Base58Bech32TypeError, match="invalid data type: NoneType"):
        convertbits(None, 8, 5)  # type: ignore[arg-type]
    with pytest.raises(Base58Bech32TypeError, match="invalid pad type: int"):
        convertbits([1], 8, 5, 0)  # type: ignore[arg-type]

    # any iterable of integers, a one-shot generator included: it is read
    # once, into the list the values are checked in
    assert convertbits((x for x in b"ab"), 8, 5) == [12, 5, 17, 0]


@pytest.mark.parametrize(
    "values, err_msg",
    [
        # 270 bits: 33 bytes and 6 bits of padding
        ([0] * 54, "zero padding of more than 4 bits in 5-to-8 conversion"),
        # 260 bits: 32 bytes and 4 bits of padding, the last one set
        ([0] * 51 + [1], "non-zero padding in 5-to-8 conversion"),
    ],
)
def test_the_padding_without_pad(values: list[int], err_msg: str) -> None:
    """Without `pad`, padding of 5 bits or more, or not zero, is refused."""
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        convertbits(values, 5, 8, False)


def test_the_witness_program_round_trip() -> None:
    """Bytes to 5-bit values and back, the conversion a segwit address makes."""
    program = bytes(range(32))
    values = convertbits(program, 8, 5)
    assert len(values) == 52
    assert bytes(convertbits(values, 5, 8, False)) == program


def test_without_m_the_first_value_is_needed() -> None:
    """`m` read off the first value refuses data that has none."""
    with pytest.raises(Base58Bech32ValueError, match="^empty data in bech32 address$"):
        bech32_encode("bc", [])
    with pytest.raises(Base58Bech32ValueError, match="^empty data in bech32 address$"):
        bech32_decode("a1lqfn3a")
    assert bech32_decode("a1lqfn3a", m=BECH32_M_CONST) == ("a", [])


def test_data_is_a_list() -> None:
    """Data that is not a list is refused.

    A tuple, bytes, an iterator, a str or None is refused as the package's
    own type error.
    """
    for not_a_list in ((0, 1), b"\x00\x01", iter([0, 1]), "01", None):
        with pytest.raises(Base58Bech32TypeError, match="^invalid 5-bit data type: "):
            bech32_encode("a", not_a_list)  # type: ignore[arg-type]


@pytest.mark.parametrize("m", [True, False, "x", 1.0, b"\x01"])
def test_m_is_an_integer(m: object) -> None:
    """A bool or any non-integer `m` is refused as a type, by both functions."""
    with pytest.raises(Base58Bech32TypeError, match="^invalid m type: "):
        bech32_encode("a", [0], m=m)  # type: ignore[arg-type]
    with pytest.raises(Base58Bech32TypeError, match="^invalid m type: "):
        bech32_decode("a12uel5l", m=m)  # type: ignore[arg-type]


@pytest.mark.parametrize("m", [0, 2, 5, BECH32_M_CONST + 1, -1])
def test_m_is_one_of_the_two_constants(m: int) -> None:
    """Any other integer would write a checksum no bech32 reader accepts."""
    err_msg = "neither BECH32_1_CONST nor BECH32_M_CONST$"
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        bech32_encode("a", [0], m=m)
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        bech32_decode("a12uel5l", m=m)


def test_both_constants_and_none_are_accepted() -> None:
    """The three values `m` takes."""
    for m in (BECH32_1_CONST, BECH32_M_CONST):
        assert bech32_decode(bech32_encode("a", [1], m=m), m=m) == ("a", [1])
    assert bech32_decode(bech32_encode("a", [1])) == ("a", [1])
