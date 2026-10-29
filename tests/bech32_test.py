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

import functools
import itertools
import operator
import random
from enum import IntEnum

import pytest
from hypothesis import given
from hypothesis import strategies as st

from base58_bech32.bech32 import (
    _ALPHABET,
    _CHAR_OF,
    _DIGIT_OF,
    _GENERATOR,
    _NOT_A_DIGIT,
    _TAPS,
    BECH32_1_CONST,
    BECH32_M_CONST,
    _create_checksum,
    _hrp_in_range,
    _polymod,
    bech32_decode,
    bech32_decode_bytes,
    bech32_encode,
    bech32_encode_bytes,
    convertbits,
)
from base58_bech32.exceptions import Base58Bech32TypeError, Base58Bech32ValueError
from tests import FOLDING


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
        hrp, data, m = bech32_decode(test, m=BECH32_1_CONST)
        assert m == BECH32_1_CONST
        assert (hrp, data, m) == bech32_decode(test.encode("ascii"), m=m)
        assert bech32_encode(hrp, data, m=m).decode() == test.lower()
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
        assert bech32_decode(s, m=BECH32_1_CONST) == (hrp, data, BECH32_1_CONST)
        assert bech32_encode(hrp, data, m=BECH32_1_CONST) == s.encode("ascii")


def test_hrp_range_predicate_is_the_per_character_test() -> None:
    """The three C passes are `32 < ord(x) < 127`, character by character.

    Held over every code point below U+3000, and a string is accepted
    only when each of its characters is.
    """
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
        hrp, data, m = bech32_decode(test, m=BECH32_M_CONST)
        assert m == BECH32_M_CONST
        assert (hrp, data, m) == bech32_decode(test.encode("ascii"), m=m)
        assert bech32_encode(hrp, data, m=m).decode() == test.lower()
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
    m = BECH32_1_CONST if data[0] == 0 else BECH32_M_CONST
    assert bech32_decode(bech32_encode(hrp, data)) == (hrp, data, m)


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
    """A digit outside 0..31 is refused, and so is a non-integer value."""
    valid = [0, 1, 30, 31]
    assert bech32_decode(bech32_encode("bc", valid))[:2] == ("bc", valid)

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
        *FOLDING,
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


@pytest.mark.parametrize("char", FOLDING)
@pytest.mark.parametrize("address", [_UPPER, _UPPER.lower()], ids=["upper", "lower"])
def test_a_character_folding_onto_ascii_is_refused_in_the_hrp(
    char: str, address: str
) -> None:
    """Each of `FOLDING`, in the HRP, under either `m`.

    The data and the checksum are
    `test_a_data_part_character_out_of_range_is_refused_first`'s. Whatever
    the string's case, the refusal is the package's and never an acceptance.
    """
    chars = list(address)
    chars[0] = char
    for m in (None, BECH32_1_CONST):
        with pytest.raises(
            Base58Bech32ValueError, match="^HRP character out of range$"
        ):
            bech32_decode("".join(chars), m=m)


@pytest.mark.parametrize("char", FOLDING)
@pytest.mark.parametrize("hrp", ["{}", "b{}", "{}c"])
def test_a_character_folding_onto_ascii_is_refused_in_the_encoders_hrp(
    char: str, hrp: str
) -> None:
    """`bech32_encode` refuses the HRP, as `bech32_decode` refuses its own."""
    with pytest.raises(Base58Bech32ValueError, match="^HRP character out of range"):
        bech32_encode(hrp.format(char), [0])


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
        (8, 65, "invalid to_bits: 65 > 64"),
        (65, 5, "invalid from_bits: 65 > 64"),
    ],
)
def test_a_conversion_width_is_in_range(
    from_bits: int, to_bits: int, err_msg: str
) -> None:
    """A width below 1 or above 64 is refused before the conversion starts.

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


def test_a_conversion_width_of_64_is_accepted() -> None:
    """A width of 64 is valid on either side, the refusal stopping at 65."""
    assert convertbits([1], 64, 64) == [1]
    assert convertbits([1], 5, 64) == [2**59]


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


@pytest.mark.parametrize("m", [None, BECH32_1_CONST, BECH32_M_CONST])
def test_the_uppercase_form_for_qr_codes_is_read_back(m: int | None) -> None:
    """`bech32_decode` reads the `.upper()` of what `bech32_encode` wrote.

    BIP173 says uppercase is the form for a QR code, and the encoder
    answers lowercase. The constant returned is `m`, and with `m` None the
    one the encoder read off the first value: bech32 for 0, else bech32m.
    """
    values = convertbits(bytes(range(20)), 8, 5)
    for hrp, data in (("bc", [0, *values]), ("lnbc", values), ("a~!", [1, *values])):
        written = bech32_encode(hrp, data, m=m)
        assert written == written.lower()
        expected = (
            m if m is not None else (BECH32_1_CONST if data[0] == 0 else BECH32_M_CONST)
        )
        for upper in (written.upper(), written.upper().decode("ascii")):
            assert bech32_decode(upper, m=m) == (hrp, data, expected)


def test_the_witness_program_round_trip() -> None:
    """Bytes to 5-bit values and back, the conversion a segwit address makes."""
    program = bytes(range(32))
    values = convertbits(program, 8, 5)
    assert len(values) == 52
    assert bytes(convertbits(values, 5, 8, False)) == program


def test_without_m_the_encoder_needs_the_first_value() -> None:
    """The encoder reads `m` off the first value; the decoder needs none."""
    with pytest.raises(Base58Bech32ValueError, match="^empty data in bech32 address$"):
        bech32_encode("bc", [])
    assert bech32_decode("a1lqfn3a") == ("a", [], BECH32_M_CONST)
    assert bech32_decode("a12uel5l") == ("a", [], BECH32_1_CONST)


# BIP350's invalid addresses: a version 1 program under the bech32
# constant, and a version 0 program under the bech32m one
_V1_BECH32 = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd"
_V0_BECH32M = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh"


def test_without_m_the_constant_that_verified_is_returned() -> None:
    """Either constant verifies, and the caller reads which one did."""
    hrp, data, m = bech32_decode(_V1_BECH32)
    assert (hrp, data[0], m) == ("bc", 1, BECH32_1_CONST)
    hrp, data, m = bech32_decode(_V0_BECH32M)
    assert (hrp, data[0], m) == ("bc", 0, BECH32_M_CONST)


def test_bip350s_rule_is_the_callers() -> None:
    """BIP350's rule, applied by a caller passing `m`.

    A string checksummed with the constant its witness version forbids is
    refused under the one it asks for. The refusal names the constant
    that verifies, and nothing else.
    """
    with pytest.raises(
        Base58Bech32ValueError, match="^invalid checksum: BECH32_1_CONST verifies$"
    ):
        bech32_decode(_V1_BECH32, m=BECH32_M_CONST)
    with pytest.raises(
        Base58Bech32ValueError, match="^invalid checksum: BECH32_M_CONST verifies$"
    ):
        bech32_decode(_V0_BECH32M, m=BECH32_1_CONST)


@pytest.mark.parametrize("m", [None, BECH32_1_CONST, BECH32_M_CONST])
def test_a_checksum_neither_constant_verifies(m: int | None) -> None:
    """A corrupted string is refused alike, whatever `m` asks for."""
    with pytest.raises(Base58Bech32ValueError, match="^invalid checksum$"):
        bech32_decode("a12uel5m", m=m)


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
        assert bech32_decode(bech32_encode("a", [1], m=m), m=m) == ("a", [1], m)
        assert bech32_decode(bech32_encode("a", [1], m=m)) == ("a", [1], m)
    assert bech32_decode(bech32_encode("a", [1])) == ("a", [1], BECH32_M_CONST)


# btcd's `TestCanDecodeUnlimitedBech32` (btcsuite/btcd,
# `address/bech32/bech32_test.go`): 91 characters, one over BIP173's 90
_BTCD_91 = (
    "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsqqqqqqqqqqqqqqqqqqq"
    "qqqqqqqqqqqqqqqqq5kx0yd"
)


def test_btcd_91_characters_and_the_bip173_limit() -> None:
    """Refused at BIP173's 90, decoded without a limit and by default."""
    assert len(_BTCD_91) == 91
    with pytest.raises(
        Base58Bech32ValueError, match="^too many bech32 characters: 91, limit is 90$"
    ):
        bech32_decode(_BTCD_91, limit=90)
    # btcd's expected values: one 16, the "s", among zeros
    expected = ("1", [0] * 46 + [16] + [0] * 36, BECH32_1_CONST)
    assert bech32_decode(_BTCD_91, limit=None) == expected
    assert bech32_decode(_BTCD_91) == expected


@pytest.mark.parametrize("length", [1023, 1024])
def test_the_default_limit_is_1023(length: int) -> None:
    """1023 characters are written and read, 1024 are not, either way."""
    data = [0] * (length - 8)  # "a", "1" and six checksum characters
    encoded = bech32_encode("a", data, limit=None)
    assert len(encoded) == length
    if length == 1023:
        assert bech32_encode("a", data) == encoded
        assert bech32_decode(encoded) == ("a", data, BECH32_1_CONST)
        return
    err_msg = "^too many bech32 characters: 1024, limit is 1023$"
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        bech32_encode("a", data)
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        bech32_decode(encoded)
    assert bech32_decode(encoded, limit=None) == ("a", data, BECH32_1_CONST)


def test_the_limit_comes_before_the_characters() -> None:
    """A string too long and out of the alphabet is refused for its length.

    Only a bytes argument's ascii decoding comes before the length: the
    HRP, the data characters and the checksum are checked after it.
    """
    with pytest.raises(Base58Bech32ValueError, match="^too many bech32 characters"):
        bech32_decode("a1" + "b" * 9, limit=10)
    with pytest.raises(Base58Bech32ValueError, match="^invalid character in checksum$"):
        bech32_decode("a1" + "b" * 9, limit=11)


@pytest.mark.parametrize("limit", [True, False, "90", 90.0])
def test_the_limit_is_an_integer(limit: object) -> None:
    """A limit of any other type is refused, a bool included."""
    with pytest.raises(Base58Bech32TypeError, match="^invalid limit type: "):
        bech32_encode("a", [0], limit=limit)  # type: ignore[arg-type]
    with pytest.raises(Base58Bech32TypeError, match="^invalid limit type: "):
        bech32_decode("a12uel5l", limit=limit)  # type: ignore[arg-type]


def test_a_negative_limit_is_refused() -> None:
    """No string is shorter than zero characters; zero refuses every one."""
    with pytest.raises(Base58Bech32ValueError, match="^invalid limit: -1 < 0$"):
        bech32_encode("a", [0], limit=-1)
    with pytest.raises(Base58Bech32ValueError, match="^invalid limit: -1 < 0$"):
        bech32_decode("a12uel5l", limit=-1)
    with pytest.raises(Base58Bech32ValueError, match="^too many bech32 characters"):
        bech32_decode("a12uel5l", limit=0)


@pytest.mark.parametrize("distance", [1022, 1023])
def test_past_1023_characters_two_errors_can_cancel(distance: int) -> None:
    """What the default limit keeps: two changes to the data part are detected.

    1023 is the code's length, so two characters that far apart, changed
    by the same XOR of their values, leave the checksum valid; one closer
    is refused.
    """
    data = [0] * 1030
    encoded = bech32_encode("a", data, m=BECH32_1_CONST, limit=None).decode("ascii")
    chars = list(encoded)
    for i in (3, 3 + distance):
        chars[i] = _ALPHABET[_ALPHABET.index(chars[i]) ^ 7]
    corrupted = "".join(chars)
    if distance == 1023:
        hrp, values, _ = bech32_decode(corrupted, m=BECH32_1_CONST, limit=None)
        assert (hrp, values) != ("a", data)
        return
    with pytest.raises(Base58Bech32ValueError, match="^invalid checksum$"):
        bech32_decode(corrupted, m=BECH32_1_CONST, limit=None)


def test_an_hrp_change_to_the_high_bits_can_cancel_within_the_limit() -> None:
    """The guarantee holds only for HRP changes to the low 5 bits.

    "!" for "a" changes the HRP character's high bits, a value checksummed
    before the separator; the checksum character 1022 places later, 1023
    checksummed values later, changed by the same XOR, cancels it in a
    string of 1023 characters, within the default limit.
    """
    encoded = list(bech32_encode("a", [0] * 1015, m=BECH32_1_CONST).decode("ascii"))
    assert len(encoded) == 1023
    xor = (ord("a") >> 5) ^ (ord("!") >> 5)
    encoded[0] = "!"
    encoded[1022] = _ALPHABET[_ALPHABET.index(encoded[1022]) ^ xor]
    corrupted = "".join(encoded)
    expected = ("!", [0] * 1015, BECH32_1_CONST)
    assert bech32_decode(corrupted, m=BECH32_1_CONST) == expected


# What `bech32_decode`'s docstring says the checksum detects, for every
# pattern of changes. A change to one value moves `_polymod`'s residue by
# an amount that depends on its position and its XOR only, never on the
# string, and the moves of several changes add by XOR: a pattern passes
# the checksum of the constant the string was written with exactly where
# its moves cancel. The residue is six elements of GF(32), whose modulus
# is x^5 + x^3 + 1 (`src/bech32.cpp` at bitcoin/bitcoin 363d9e9d38),
# packed five bits each
_GF32_MOD = 0b101001


def _gf32_mul(a: int, b: int) -> int:
    product = 0
    for i in range(5):
        if b >> i & 1:
            product ^= a << i
    for i in range(9, 4, -1):
        if product >> i & 1:
            product ^= _GF32_MOD << (i - 5)
    return product


_GF32_MUL = [[_gf32_mul(a, b) for b in range(32)] for a in range(32)]
_GF32_INV = [0] + [_GF32_MUL[a].index(1) for a in range(1, 32)]


def _scale(residue: int, k: int) -> int:
    """Multiply each of the residue's six elements by `k`."""
    row = _GF32_MUL[k]
    return sum(row[residue >> shift & 31] << shift for shift in range(0, 30, 5))


def _class(residue: int) -> int:
    """Scale the residue so that its top non-zero element is 1.

    Two residues have the same class exactly where one is a non-zero
    multiple of the other. Zero is its own class, `_GF32_INV[0]` being 0.
    """
    elements = (residue >> shift & 31 for shift in range(25, -1, -5))
    top = next((element for element in elements if element), 0)
    return _scale(residue, _GF32_INV[top])


@functools.cache
def _moves() -> list[list[int]]:
    """Tabulate the move of XOR by `d` of the value `t` before the last.

    Entry `[t][d]`, for `t` up to 1023, built from `_polymod` one bit of
    `d` at a time.
    """
    moves = []
    for t in range(1024):
        zero = _polymod([0] * (t + 1))
        bits = [_polymod([1 << b] + [0] * t) ^ zero for b in range(5)]
        moves.append(
            [
                functools.reduce(
                    operator.xor, (bits[b] for b in range(5) if d >> b & 1), 0
                )
                for d in range(32)
            ]
        )
    return moves


def test_the_moves_add_scale_and_repeat() -> None:
    """The premises of the two exhaustive tests below.

    `_TAPS` is linear, which is what makes the moves of several changes add
    by XOR. XOR by `d` moves the residue by `d` times what XOR by 1 does at
    the same place, so a pattern that cancels still cancels with every XOR
    scaled by one factor. The moves repeat every 1023 values, the code's
    length, so it still cancels shifted along the string.
    """
    assert all(
        _TAPS[a ^ b] == _TAPS[a] ^ _TAPS[b] for a in range(32) for b in range(32)
    )
    moves = _moves()
    for row in moves:
        assert row == [_scale(row[1], d) for d in range(32)]
    assert moves[1023] == moves[0]


def _four_changes_always_move(count: int) -> bool:
    """Whether no pattern of 1 to 4 changes in the last `count` values cancels.

    A pattern of up to four changes is two of at most two, which cancel
    only where their moves are equal. Each pattern of one or two changes is
    taken once, the XOR of its change nearest the end being 1: none may move
    by zero, and no two may move by multiples of one another, which is
    their classes being distinct.
    """
    moves = _moves()[:count]
    classes = [_class(row[1]) for row in moves]
    for first, second in itertools.combinations(moves, 2):
        classes.extend(_class(first[1] ^ move) for move in second[1:])
    return 0 not in classes and len(set(classes)) == len(classes)


def test_every_change_of_up_to_4_characters_within_90_is_detected() -> None:
    """BIP173's bound, for every pattern.

    The 89 characters besides the separator are the last 89 values the
    checksum reads, the low 5 bits of each HRP character included. With 90
    such characters four changes can cancel, which shows the check can fail.
    """
    assert _four_changes_always_move(89)
    assert not _four_changes_always_move(90)


def test_every_change_of_up_to_3_characters_within_1023_is_detected() -> None:
    """Bitcoin Core's bound, for every pattern.

    A pattern that cancels still cancels shifted until its change nearest
    the end is at the last value, and scaled until that change is XOR by
    1. Three changes cancel only where one moves the residue by a multiple
    of what the other two do. So it is enough that no pattern of XOR by 1
    at the last value and one more change within 1023 values moves the
    residue by zero, or by a multiple of what a single change does.
    """
    moves = _moves()
    singles = {_class(row[1]) for row in moves[:1023]}
    for row in moves[1:1023]:
        for move in row[1:]:
            pattern = _class(moves[0][1] ^ move)
            assert pattern != 0
            assert pattern not in singles


@pytest.mark.parametrize(
    "length, changes", [(90, 2), (90, 3), (90, 4), (1023, 2), (1023, 3)]
)
def test_a_sample_of_those_changes_fails_the_checksum(
    length: int, changes: int
) -> None:
    """The exhaustive tests above, through `bech32_decode`, on a seeded sample.

    `m` is given, the bounds holding for one constant at a time: a string
    the other constant verifies is refused too, and with `m` None it would
    be accepted.
    """
    data = [0] * (length - 8)  # "a", "1" and six checksum characters
    encoded = bech32_encode("a", data, m=BECH32_1_CONST).decode("ascii")
    rng = random.Random(f"{length}-{changes}")
    for _ in range(200):
        chars = list(encoded)
        for i in rng.sample(range(2, length), changes):
            chars[i] = _ALPHABET[_ALPHABET.index(chars[i]) ^ rng.randrange(1, 32)]
        with pytest.raises(Base58Bech32ValueError, match="^invalid checksum"):
            bech32_decode("".join(chars), m=BECH32_1_CONST)


# One change more than each bound, passing the checksum, on the strings the
# sample above changes. Bitcoin Core's own pair is proposed in
# bitcoin/bitcoin#36690
_ONE_CHANGE_MORE = [
    (90, {21: "z", 22: "m", 53: "m", 54: "0", 87: "w"}),
    (1023, {288: "a", 535: "h", 689: "f", 1022: "u"}),
]


@pytest.mark.parametrize("length, changes", _ONE_CHANGE_MORE)
def test_one_change_more_can_pass_the_checksum(
    length: int, changes: dict[int, str]
) -> None:
    """The bounds are tight: one change more than each can cancel."""
    data = [0] * (length - 8)
    chars = list(bech32_encode("a", data, m=BECH32_1_CONST).decode("ascii"))
    for i, char in changes.items():
        assert chars[i] != char
        chars[i] = char
    hrp, values, m = bech32_decode("".join(chars), m=BECH32_1_CONST, limit=length)
    assert (hrp, m) == ("a", BECH32_1_CONST)
    assert values != data


def test_with_m_none_one_change_never_passes_as_the_other_constant() -> None:
    """The single-change guarantee holds with `m` None, at every length.

    No change to one value moves the residue by the XOR of the two
    constants, and the moves repeat every 1023 values.
    """
    other = BECH32_1_CONST ^ BECH32_M_CONST
    assert all(row[d] != other for row in _moves()[:1023] for d in range(1, 32))


# ISS btclib-org/base58-bech32#79's string: the 90 characters
# `bech32_encode("a", [0] * 82, m=BECH32_1_CONST)` writes, three of them
# changed so that BECH32_M_CONST verifies
_OTHER_CONSTANT = (
    "a1qqqqqpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
    "3qqqqqqmqqqqqqq87k0gd"
)


# changes that make BECH32_M_CONST verify the strings the sample above
# changes: the issue's three within 90, and two within 1023
@pytest.mark.parametrize(
    "length, changes",
    [(90, {7: "p", 69: "3", 76: "m"}), (1023, {830: "n", 989: "n"})],
)
def test_with_m_none_a_few_changes_can_pass_as_the_other_constant(
    length: int, changes: dict[int, str]
) -> None:
    """With `m` None either constant verifies.

    Of `bech32_decode`'s bounds only the single-change guarantee then
    holds. `m` given refuses the string as the other constant's.
    """
    data = [0] * (length - 8)
    chars = list(bech32_encode("a", data, m=BECH32_1_CONST).decode("ascii"))
    for i, char in changes.items():
        assert chars[i] != char
        chars[i] = char
    corrupted = "".join(chars)
    if length == 90:
        assert corrupted == _OTHER_CONSTANT
    hrp, values, m = bech32_decode(corrupted, limit=length)
    assert (hrp, m) == ("a", BECH32_M_CONST)
    assert values != data
    err_msg = "^invalid checksum: BECH32_M_CONST verifies$"
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        bech32_decode(corrupted, m=BECH32_1_CONST, limit=length)


# NIP-19's examples (nostr-protocol/nips, 19.md): a public key and its npub
_NPUBS = [
    (
        "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
        "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6",
    ),
    (
        "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e",
        "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg",
    ),
]


@pytest.mark.parametrize("key, npub", _NPUBS)
def test_the_bytes_pair_on_nip19s_examples(key: str, npub: str) -> None:
    """A Nostr public key is a payload of bytes in a bech32 string."""
    assert bech32_encode_bytes("npub", key, m=BECH32_1_CONST) == npub.encode()
    assert bech32_decode_bytes(npub, m=BECH32_1_CONST) == ("npub", bytes.fromhex(key))


@given(
    hrp=HRP,
    payload=st.binary(max_size=80),
    m=st.sampled_from([BECH32_1_CONST, BECH32_M_CONST]),
)
def test_the_bytes_pair_is_the_5_bit_pair_and_convertbits(
    hrp: str, payload: bytes, m: int
) -> None:
    """The bytes round-trip, through the string the 5-bit pair writes."""
    encoded = bech32_encode_bytes(hrp, payload, m=m)
    assert encoded == bech32_encode(hrp, convertbits(payload, 8, 5), m=m)
    assert bech32_decode_bytes(encoded, m=m) == (hrp, payload)
    other = BECH32_M_CONST if m == BECH32_1_CONST else BECH32_1_CONST
    name = "BECH32_1_CONST" if m == BECH32_1_CONST else "BECH32_M_CONST"
    err_msg = f"^invalid checksum: {name} verifies$"
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        bech32_decode_bytes(encoded, m=other)


def test_bech32_encode_bytes_takes_octets() -> None:
    """A hex string, a bytearray or a memoryview, as `b58encode` takes."""
    expected = bech32_encode_bytes("a", b"\x00\xff", m=BECH32_1_CONST)
    for octets in ("00ff", bytearray(b"\x00\xff"), memoryview(b"\x00\xff")):
        assert bech32_encode_bytes("a", octets, m=BECH32_1_CONST) == expected
    with pytest.raises(Base58Bech32TypeError, match="^invalid octets type: list$"):
        bech32_encode_bytes("a", [0, 255], m=BECH32_1_CONST)  # type: ignore[arg-type]
    with pytest.raises(Base58Bech32ValueError, match="^invalid hex string: "):
        bech32_encode_bytes("a", "0", m=BECH32_1_CONST)
    with pytest.raises(Base58Bech32ValueError, match="^HRP is not lowercase: A$"):
        bech32_encode_bytes("A", b"", m=BECH32_1_CONST)


@pytest.mark.parametrize(
    "values, err_msg",
    [
        # 15 bits: a byte and 7 bits of padding
        ([0, 0, 0], "zero padding of more than 4 bits in 5-to-8 conversion"),
        # 10 bits: a byte and 2 bits of padding, the last one set
        ([0, 1], "non-zero padding in 5-to-8 conversion"),
    ],
)
def test_bech32_decode_bytes_refuses_the_padding_convertbits_refuses(
    values: list[int], err_msg: str
) -> None:
    """A string `bech32_decode` reads, and no payload of bytes encodes to."""
    encoded = bech32_encode("a", values, m=BECH32_1_CONST)
    assert bech32_decode(encoded, m=BECH32_1_CONST) == ("a", values, BECH32_1_CONST)
    with pytest.raises(Base58Bech32ValueError, match=f"^{err_msg}$"):
        bech32_decode_bytes(encoded, m=BECH32_1_CONST)


@pytest.mark.parametrize("m", [None, True, False, "x", 1.0, b"\x01"])
def test_the_bytes_pair_takes_an_integer_m(m: object) -> None:
    """None, a bool or any other non-integer `m` is refused as a type."""
    with pytest.raises(Base58Bech32TypeError, match="^invalid m type: "):
        bech32_encode_bytes("a", b"", m=m)  # type: ignore[arg-type]
    with pytest.raises(Base58Bech32TypeError, match="^invalid m type: "):
        bech32_decode_bytes("a12uel5l", m=m)  # type: ignore[arg-type]


@pytest.mark.parametrize("m", [0, 2, 5, BECH32_M_CONST + 1, -1])
def test_the_bytes_pair_takes_one_of_the_two_constants(m: int) -> None:
    """Any other integer is refused, as by the 5-bit pair."""
    err_msg = "neither BECH32_1_CONST nor BECH32_M_CONST$"
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        bech32_encode_bytes("a", b"", m=m)
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        bech32_decode_bytes("a12uel5l", m=m)


def test_the_bytes_pair_takes_the_limit_of_the_5_bit_pair() -> None:
    """A string over `limit` is refused, written or read; `None` caps none."""
    payload = bytes(range(100))
    encoded = bech32_encode_bytes("a", payload, m=BECH32_1_CONST)
    size = len(encoded)
    assert bech32_encode_bytes("a", payload, m=BECH32_1_CONST, limit=size) == encoded
    assert bech32_decode_bytes(encoded, m=BECH32_1_CONST, limit=size) == ("a", payload)
    err_msg = f"^too many bech32 characters: {size}, limit is {size - 1}$"
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        bech32_encode_bytes("a", payload, m=BECH32_1_CONST, limit=size - 1)
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        bech32_decode_bytes(encoded, m=BECH32_1_CONST, limit=size - 1)


def test_the_bytes_pair_caps_a_string_at_1023_characters_by_default() -> None:
    """The default is the 5-bit pair's, and `limit=None` lifts it."""
    payload = bytes(700)
    err_msg = "^too many bech32 characters: 1128, limit is 1023$"
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        bech32_encode_bytes("a", payload, m=BECH32_1_CONST)
    encoded = bech32_encode_bytes("a", payload, m=BECH32_1_CONST, limit=None)
    assert len(encoded) == 1128
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        bech32_decode_bytes(encoded, m=BECH32_1_CONST)
    assert bech32_decode_bytes(encoded, m=BECH32_1_CONST, limit=None) == ("a", payload)


def test_convertbits_excessive_width() -> None:
    """A width above 64 is refused with Base58Bech32ValueError."""
    with pytest.raises(Base58Bech32ValueError, match="invalid from_bits: .* > 64"):
        convertbits([0], 2**64, 5)

    with pytest.raises(Base58Bech32ValueError, match="invalid to_bits: .* > 64"):
        convertbits([0], 5, 2**64)

    with pytest.raises(Base58Bech32ValueError, match="invalid from_bits: .* > 64"):
        convertbits([], 2**64, 5)
