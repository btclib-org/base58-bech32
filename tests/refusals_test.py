# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What a refusal of `base58_bech32` says, and what it does not.

A wrong type leaves as a `Base58Bech32TypeError` naming the parameter,
not as a builtin raised from underneath the package: these are the calls
`tests/input_validation_test.py`'s walk does not reach, each taking a
plain `str`, an `int` or a list. And no decoder's refusal quotes the
string it was handed, nor the payload a corrupted checksum carried:
what reaches a decoder can be a private key pasted in the wrong field,
and an exception message ends up in logs and crash reports.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any

import pytest

from base58_bech32.base58 import b58decode, b58decode_check, b58encode, b58encode_check
from base58_bech32.bech32 import (
    BECH32_1_CONST,
    BECH32_M_CONST,
    bech32_decode,
    bech32_encode,
    convertbits,
)
from base58_bech32.cashaddr import cashaddr_decode, cashaddr_encode
from base58_bech32.exceptions import Base58Bech32TypeError, Base58Bech32ValueError
from base58_bech32.ss58 import ss58_decode, ss58_encode
from tests import load
from tests.secret_free import assert_secret_free

# a fixed random 32-byte secret, the size of a private key
_SECRET = bytes.fromhex(
    "9b3c1e5f0a8d7246b1e0c39f5d84a27e6c0b19d3f4a85e72c61d09b8e3f4a751"
)

_WRONG_TYPES: list[tuple[str, Callable[[], Any], str]] = [
    (
        "bech32_encode(hrp=bytes)",
        lambda: bech32_encode(b"bc", [0]),  # type: ignore[arg-type]
        "invalid HRP type: bytes",
    ),
    (
        "bech32_encode(data=[float])",
        lambda: bech32_encode("bc", [1.0]),  # type: ignore[list-item]
        "invalid 5-bit value type: float",
    ),
    (
        "convertbits(data=None)",
        lambda: convertbits(None, 8, 5),  # type: ignore[arg-type]
        "invalid data type: NoneType",
    ),
    (
        "ss58_encode(prefix=str)",
        lambda: ss58_encode("42", _SECRET),  # type: ignore[arg-type]
        "invalid SS58 prefix type: str",
    ),
    (
        "ss58_encode(payload=int)",
        lambda: ss58_encode(42, 1),  # type: ignore[arg-type]
        "invalid octets type: int",
    ),
    (
        "cashaddr_encode(prefix=None)",
        lambda: cashaddr_encode(None, 0, bytes(20)),  # type: ignore[arg-type]
        "invalid CashAddr prefix type: NoneType",
    ),
    (
        "cashaddr_encode(kind=str)",
        lambda: cashaddr_encode("p", "0", bytes(20)),  # type: ignore[arg-type]
        "invalid CashAddr type type: str",
    ),
    (
        "cashaddr_decode(prefix=bytes)",
        lambda: cashaddr_decode("p:", prefix=b"p"),  # type: ignore[arg-type]
        "invalid CashAddr prefix type: bytes",
    ),
    (
        "b58encode(alphabet=str)",
        lambda: b58encode(b"", alphabet="1"),  # type: ignore[arg-type]
        "invalid alphabet type: str",
    ),
]


@pytest.mark.parametrize(
    "call, err_msg", [row[1:] for row in _WRONG_TYPES], ids=[r[0] for r in _WRONG_TYPES]
)
def test_a_wrong_type_is_the_packages_refusal(
    call: Callable[[], Any], err_msg: str
) -> None:
    """A `Base58Bech32TypeError` naming the parameter, and no builtin."""
    with pytest.raises(Base58Bech32TypeError, match=f"^{err_msg}$"):
        call()


def _corrupted(text: bytes) -> str:
    """Return the string with its last character changed to another one."""
    last = text[-1:]
    return (text[:-1] + (b"2" if last != b"2" else b"3")).decode("ascii")


def _ss58_of(data: bytes) -> bytes:
    checksum = hashlib.blake2b(b"SS58PRE" + data, digest_size=64).digest()[:2]
    return b58encode(data + checksum)


_DECODERS: list[tuple[str, Callable[[], Any]]] = [
    ("b58decode_check", lambda: b58decode_check(_corrupted(b58encode_check(_SECRET)))),
    ("b58decode, invalid character", lambda: b58decode(b58encode(_SECRET) + b"0")),
    (
        "bech32_decode",
        lambda: bech32_decode(
            _corrupted(bech32_encode("a", convertbits(_SECRET, 8, 5)))
        ),
    ),
    (
        "bech32_decode, the other constant",
        lambda: bech32_decode(
            bech32_encode("a", convertbits(_SECRET, 8, 5), m=BECH32_M_CONST),
            m=BECH32_1_CONST,
        ),
    ),
    (
        "bech32_decode, mixed case",
        lambda: bech32_decode(
            bech32_encode("a", convertbits(_SECRET, 8, 5)).decode().capitalize()
        ),
    ),
    ("ss58_decode", lambda: ss58_decode(_corrupted(ss58_encode(42, _SECRET)))),
    (
        "ss58_decode, reserved",
        lambda: ss58_decode(_ss58_of(b"\x2e" + _SECRET)),
    ),
    (
        "cashaddr_decode",
        lambda: cashaddr_decode(_corrupted(cashaddr_encode("p", 0, _SECRET))),
    ),
    (
        "cashaddr_decode, prefix",
        lambda: cashaddr_decode(cashaddr_encode("p", 0, _SECRET), prefix="q"),
    ),
]


@pytest.mark.parametrize(
    "call", [row[1] for row in _DECODERS], ids=[r[0] for r in _DECODERS]
)
def test_a_decoders_refusal_quotes_nothing_of_its_input(
    call: Callable[[], Any],
) -> None:
    """Neither the encoded secret, in any spelling, nor the string itself."""
    with pytest.raises(Base58Bech32ValueError) as excinfo:
        call()
    assert_secret_free(excinfo.value, [_SECRET])
    # the string itself: the shortest decoded here is the Base58 of 32 bytes
    assert len(str(excinfo.value)) < 44


def test_a_mistyped_wif_quotes_neither_checksum() -> None:
    """Neither the expected checksum, a hash of the key, nor the written one."""
    payload = b"\x80" + _SECRET + b"\x01"
    mistyped = _corrupted(b58encode_check(payload))
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    written = b58decode(mistyped)[-4:]
    assert written != expected
    with pytest.raises(Base58Bech32ValueError, match="^invalid checksum$") as excinfo:
        b58decode_check(mistyped)
    assert_secret_free(excinfo.value, [payload, expected, written])


# What the peers refuse, and the refusal this package gives each string.
# The sources and their pins are in tests/_data/README.md. A string a peer
# refuses and this package reads is marked `xfail`, strictly, so that the
# day it is refused the marker turns red.
_NO_LIMIT = "bech32 has no length limit, by decision"


def _xfail(reason: str | None) -> list[Any]:
    """Return the marks of a vector this package reads and a peer refuses."""
    return [pytest.mark.xfail(strict=True, reason=reason)] if reason else []


# btcd's `invalidStringTests` in `address/base58/base58_test.go`. The first
# four are the characters the alphabet leaves out; "abcd\xd80" is the Go
# string with the byte 0xd8 in it, and the last has U+20BF, the bitcoin sign
_BTCD_BASE58_INVALID: list[str | bytes] = [
    "0",
    "O",
    "I",
    "l",
    "3mJr0",
    "O3yxU",
    "3sNI",
    "4kl8",
    "0OIl",
    "!@#$%^&*()-_=+~`",
    b"abcd\xd80",
    "abcd\N{BITCOIN SIGN}",
]


@pytest.mark.parametrize(
    "text",
    [pytest.param(text, id=str(i)) for i, text in enumerate(_BTCD_BASE58_INVALID)],
)
def test_btcds_invalid_base58_strings_are_refused(text: str | bytes) -> None:
    """Refused as an invalid character, or as a non-ascii one in a `str`."""
    non_ascii = isinstance(text, str) and not text.isascii()
    err_msg = "^non-ascii character in base58 string at position 4$"
    if not non_ascii:
        err_msg = "^Base58 string contains invalid characters$"
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        b58decode(text)
    if isinstance(text, str) and not non_ascii:
        with pytest.raises(Base58Bech32ValueError, match=err_msg):
            b58decode(text.encode("ascii"))


# libbase58's `tests/decode-highbit.sh` and `decode-highbit-prefix.sh`: the
# bytes 0x99, "2", "3" and "1", 0x99, "2", each with a byte above 127
@pytest.mark.parametrize("text", [b"\x9923", b"1\x992"])
def test_libbase58s_high_bit_strings_are_refused(text: bytes) -> None:
    """A byte with its high bit set is no Base58 character, anywhere."""
    err_msg = "^Base58 string contains invalid characters$"
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        b58decode(text)
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        b58decode_check(text)
    with pytest.raises(Base58Bech32ValueError, match="^non-ascii character"):
        b58decode(text.decode("latin-1"))


# libbase58's `tests/decode-b58c-fail.sh`, `decode-b58c-toolong.sh` and
# `decode-b58c-tooshort.sh`, each run as `base58 -d 25 -c`: an address whose
# checksum is wrong, the same with two more leading "1", and a string of
# 25 bytes whose checksum is wrong. The checksum is checked before the size
@pytest.mark.parametrize(
    "text",
    [
        "19DXstMaV43WpYg4ceREiiTv2UntmoiA9a",
        "1119DXstMaV43WpYg4ceREiiTv2UntmoiA9a",
        "111111111111111111114oLvT2",
    ],
)
def test_libbase58s_checked_decodes_are_refused(text: str) -> None:
    """Refused for the checksum, with and without the size libbase58 gets."""
    for out_size in (None, 25):
        with pytest.raises(Base58Bech32ValueError, match="^invalid checksum$"):
            b58decode_check(text, out_size=out_size)


# btcd's `TestMixedCaseEncode` in `address/bech32/bech32_test.go`: an HRP,
# the data as hex and the string btcd writes, which lowers the HRP. This
# package refuses an HRP that is not lowercase, by decision, and writes the
# same string for the lowercase one
_BTCD_MIXED_CASE = [
    ("A", "", "a12uel5l"),
    ("UPPERCASE", "787878", "uppercase10pu8sss7kmp"),
    (
        "AbCdEf",
        "00443214c74254b635cf84653a56d7c675be77df",
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    ),
    (
        "aBcDeF",
        "00443214c74254b635cf84653a56d7c675be77df",
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    ),
]


@pytest.mark.parametrize(
    "hrp, data, encoded", [pytest.param(*row, id=row[0]) for row in _BTCD_MIXED_CASE]
)
def test_btcds_mixed_case_hrps_are_refused_by_the_encoder(
    hrp: str, data: str, encoded: str
) -> None:
    """An HRP with an uppercase letter is refused, and not lowered."""
    values = convertbits(bytes.fromhex(data), 8, 5)
    with pytest.raises(Base58Bech32ValueError, match="^HRP is not lowercase: "):
        bech32_encode(hrp, values, m=BECH32_1_CONST)
    assert bech32_encode(hrp.lower(), values, m=BECH32_1_CONST) == encoded.encode()
    for text in (encoded, encoded.upper()):
        assert bech32_decode(text, m=BECH32_1_CONST) == (
            hrp.lower(),
            values,
            BECH32_1_CONST,
        )


# bitcoinjs/bech32's `src/test/fixtures.json`, whole
FIXTURES = load("_data", "fixtures.json")
_M = {"bech32": BECH32_1_CONST, "bech32m": BECH32_M_CONST}

# what this package says for what bitcoinjs/bech32 says, keyed by the start
# of its message. A string it refuses for its length is the exception: no
# message here is its own
_BITCOINJS_DECODE = [
    ("Mixed-case string", "^mixed case$"),
    ("Invalid prefix", "^HRP character out of range$"),
    ("Missing prefix", "^empty HRP$"),
    ("No separator character", "^no separator character$"),
    ("Data too short", "^too short checksum$"),
    ("Invalid checksum", "^invalid checksum$"),
    (
        "Unknown character",
        (
            "^(invalid data character|invalid character in checksum"
            "|data part character out of range)$"
        ),
    ),
]
_BITCOINJS_LENGTH = "Exceeds length limit"


def _bitcoinjs_decode_message(exception: str) -> str:
    """Return the message this package gives for a bitcoinjs `exception`."""
    for start, err_msg in _BITCOINJS_DECODE:
        if exception.startswith(start):
            return err_msg
    # "abc1rzg too short" and "16plkw9 too short", the second with no HRP
    assert exception.endswith("too short"), exception
    return "^(empty HRP|too short checksum)$"


def _bitcoinjs_decodes() -> list[Any]:
    """Return the strings bitcoinjs/bech32 refuses, as test parameters.

    The one string over its limit whose checksum holds is read here, and
    is marked. The other is refused for its checksum.
    """
    params = []
    for section, m in _M.items():
        for index, row in enumerate(FIXTURES[section]["invalid"]):
            if "string" in row:
                text = row["string"]
            elif "stringHex" in row:
                text = bytes.fromhex(row["stringHex"]).decode("latin-1")
            else:
                continue
            long = row["exception"] == _BITCOINJS_LENGTH
            reason = _NO_LIMIT if long and text.startswith("an84") else None
            err_msg = "^invalid checksum$" if long else None
            if not long:
                err_msg = _bitcoinjs_decode_message(row["exception"])
            params.append(
                pytest.param(
                    text, m, err_msg, id=f"{section}-{index}", marks=_xfail(reason)
                )
            )
    return params


@pytest.mark.parametrize("text, m, err_msg", _bitcoinjs_decodes())
def test_bitcoinjs_invalid_strings_are_refused(
    text: str, m: int, err_msg: str | None
) -> None:
    """Each string of the `invalid` lists, under the constant of its list."""
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        bech32_decode(text, m=m)


def _bitcoinjs_encodes() -> list[Any]:
    """Return the `prefix` and `words` bitcoinjs/bech32 refuses to encode.

    Those over its limit hold a word of 128, refused as it is, except the
    one that holds only the word 20, which this package writes.
    """
    params = []
    for section, m in _M.items():
        for index, row in enumerate(FIXTURES[section]["invalid"]):
            if "prefix" not in row:
                continue
            reason = _NO_LIMIT if set(row["words"]) == {20} else None
            err_msg = None
            if 128 in row["words"]:
                err_msg = "^invalid 5-bit value: 128$"
            elif reason is None:
                err_msg = "^HRP character out of range"
            params.append(
                pytest.param(
                    row["prefix"],
                    row["words"],
                    m,
                    err_msg,
                    id=f"{section}-{index}",
                    marks=_xfail(reason),
                )
            )
    return params


@pytest.mark.parametrize("hrp, words, m, err_msg", _bitcoinjs_encodes())
def test_bitcoinjs_invalid_encodes_are_refused(
    hrp: str, words: list[int], m: int, err_msg: str | None
) -> None:
    """Each `prefix` and `words` of the `invalid` lists."""
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        bech32_encode(hrp, words, m=m)


@pytest.mark.parametrize(
    "words, err_msg",
    [
        pytest.param(
            row["words"],
            "^zero padding of more than 4 bits in 5-to-8 conversion$"
            if row["exception"] == "Excess padding"
            else "^non-zero padding in 5-to-8 conversion$",
            id=row["exception"],
        )
        for row in FIXTURES["fromWords"]["invalid"]
    ],
)
def test_bitcoinjs_invalid_words_are_refused(words: list[int], err_msg: str) -> None:
    """The padding of the words, as `fromWords` reads it."""
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        convertbits(words, 5, 8, False)


@pytest.mark.parametrize(
    "section, row",
    [
        pytest.param(section, row, id=f"{section}-{i}")
        for section in _M
        for i, row in enumerate(FIXTURES[section]["valid"])
    ],
)
def test_bitcoinjs_valid_strings_are_refused_under_the_other_constant(
    section: str, row: dict[str, Any]
) -> None:
    """A valid string of one constant is refused under the other.

    Some carry a `limit` bitcoinjs is given, which this package has none of.
    """
    other = BECH32_M_CONST if section == "bech32" else BECH32_1_CONST
    name = "BECH32_1_CONST" if section == "bech32" else "BECH32_M_CONST"
    decoded = bech32_decode(row["string"], m=_M[section])
    assert decoded == (row["prefix"].lower(), row["words"], _M[section])
    assert bech32_decode(row["string"]) == decoded
    with pytest.raises(
        Base58Bech32ValueError, match=f"^invalid checksum: {name} verifies$"
    ):
        bech32_decode(row["string"], m=other)


# Bitcoin Core's `src/test/bech32_tests.cpp`, the `CASES` and `ERRORS` of
# `bech32_testvectors_invalid` and `bech32m_testvectors_invalid`, as
# `[string, Core's error, where it locates it]`
CORE = load("_data", "bech32_core_invalid_vectors.json")

# what this package says for what Core says. Core's "Invalid separator
# position" is an HRP of no length or fewer than six characters after the
# separator, which this package tells apart
_CORE_ERRORS = {
    "Invalid character or mixed case": (
        "^(HRP character out of range|data part character out of range|mixed case)$"
    ),
    "Missing separator": "^no separator character$",
    "Invalid separator position": "^(empty HRP|too short checksum)$",
    "Invalid Base 32 character": (
        "^(invalid data character|invalid character in checksum)$"
    ),
    "Invalid checksum": "^invalid checksum$",
    "Invalid Bech32 checksum": "^invalid checksum$",
    "Invalid Bech32m checksum": "^invalid checksum$",
    # Core's string of one hundred "q" has no separator, and is refused for
    # that here, the length limit being Core's
    "Bech32 string too long": "^no separator character$",
}


def _core() -> list[Any]:
    """Return Core's invalid strings, as test parameters.

    The long ones whose checksum holds are read here, and are marked.
    """
    return [
        pytest.param(
            text,
            m,
            error,
            _CORE_ERRORS[error],
            id=f"{section}-{index}",
            marks=_xfail(
                _NO_LIMIT if error == "Bech32 string too long" and "1" in text else None
            ),
        )
        for section, m in _M.items()
        for index, (text, error, _) in enumerate(CORE[section])
    ]


@pytest.mark.parametrize("text, m, error, err_msg", _core())
def test_cores_invalid_strings_are_refused(
    text: str, m: int, error: str, err_msg: str
) -> None:
    """Each string, with the message that answers Core's `error`."""
    with pytest.raises(Base58Bech32ValueError, match=err_msg):
        bech32_decode(text, m=m)


# polkadot-js's `checkAddress` tests in `check.spec.ts`: the address whose
# fifth character is an "I", which the Base58 alphabet does not have. The
# prefix 69 and 252 addresses of its `checksum.spec.ts` are valid, each
# with a two-byte prefix before a payload of 32 bytes
_POLKADOT_I = "5EnxIUmEbw8DkENKiYuZ1DwQuMoB2UWEQJZZXrTsxoz7SpgG"
_POLKADOT_TWO_BYTE_PREFIXES = [
    ("cnVvyMzRdqjwejTFuByQQ4w2yu78V2hpFixjHQz5zr6NSYsxA", 69),
    ("xw8Ffc2SZtDqUJKd9Ky4vc7PRz2D2asuVkEEzf3WGAbw9cnfq", 252),
]


def test_polkadot_js_invalid_character_is_refused() -> None:
    """An "I" in an address is refused as a Base58 character."""
    with pytest.raises(Base58Bech32ValueError, match="invalid characters"):
        ss58_decode(_POLKADOT_I)


@pytest.mark.parametrize("address, prefix", _POLKADOT_TWO_BYTE_PREFIXES)
def test_polkadot_js_two_byte_prefixes_are_read(address: str, prefix: int) -> None:
    """The prefix, and the payload with which the address is written again."""
    decoded_prefix, payload = ss58_decode(address)
    assert decoded_prefix == prefix
    assert len(payload) == 32
    assert ss58_encode(prefix, payload) == address.encode("ascii")
