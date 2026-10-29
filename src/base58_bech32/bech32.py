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
"""Bech32 and bech32m encoding and decoding, and the bit-group conversion.

A bech32 string is a human-readable part (HRP), the separator "1", and
5-bit values written with a 32-character alphabet, the last six of them a
checksum. BIP173 defines bech32 and BIP350 bech32m, which differ only in
the constant the checksum ends on: the `m` that `bech32_encode` and
`bech32_decode` take. Nothing here knows what the values mean: a segwit
address, a Lightning invoice and a Nostr key are all bech32. The
exception is `bech32_encode` without `m`, whose docstring says how.

- BIP173: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
- BIP350: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki

This implementation is originally from
https://github.com/sipa/bech32/tree/master/ref/python, by way of btclib,
with the following modifications:

* only the codec: the segwit address rules stay with the caller
* type annotated Python3
* raising exceptions instead of returning (None, None)
* the length limit is a keyword, `limit`, of the decoder and the
  encoder, whose default is not BIP173's 90; `bech32_decode` says why, and
  what the checksum guarantees at each length
* the checksum's inner loop is a 32-entry table of tap combinations
* detailed error messages
* an encoder that answers ascii bytes, as the standard library's `base64`
"""

from __future__ import annotations

from collections.abc import Iterable
from functools import reduce
from operator import xor

from base58_bech32._utils import (
    Octets,
    String,
    _message_text,
    assert_type,
    bytes_from_octets,
    is_integer,
    str_from_string,
)
from base58_bech32.exceptions import Base58Bech32TypeError, Base58Bech32ValueError

__all__ = [
    "BECH32_1_CONST",
    "BECH32_M_CONST",
    "bech32_decode",
    "bech32_decode_bytes",
    "bech32_encode",
    "bech32_encode_bytes",
    "convertbits",
]

_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
#: BIP173's bech32 constant, an `m` of `bech32_encode` and `bech32_decode`.
BECH32_1_CONST = 1
#: BIP350's bech32m constant, the other `m`.
BECH32_M_CONST = 0x2BC830A3

# BIP173's five generator constants, and the XOR of the ones each 5-bit
# selection picks. What a step of _polymod applies depends on nothing but
# the top five bits of chk, of which there are 32, so the table computed
# once here is the whole of the reference's inner loop
_GENERATOR = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
_TAPS = [
    reduce(xor, [g for i, g in enumerate(_GENERATOR) if top >> i & 1], 0)
    for top in range(32)
]

# the two translation tables of `bytes.translate`, built once. _DIGIT_OF
# maps an alphabet character to its digit and every other byte to
# _NOT_A_DIGIT, which is no digit and so doubles as the validity check;
# lowercase-only because `_decode` lowers the string before reaching it.
# _CHAR_OF is the inverse, defined on the digits 0..31 only
_NOT_A_DIGIT = 255
_DIGIT_OF = bytes(
    _ALPHABET.index(chr(b)) if chr(b) in _ALPHABET else _NOT_A_DIGIT for b in range(256)
)
_CHAR_OF = _ALPHABET.encode("ascii").ljust(256, b"\0")


def _hrp_in_range(text: str) -> bool:
    """Whether every character of `text` is in BIP173's HRP range [33-126].

    Printable ascii is [32-126], so the range is the printable ascii
    characters but the space: three passes in C instead of one Python
    test per character. `tests/bech32_test.py` holds it
    equal to `all(32 < ord(x) < 127 for x in text)` over every code point
    below U+3000.
    """
    return text.isascii() and text.isprintable() and " " not in text


def _polymod(values: Iterable[int]) -> int:
    """Return the bech32 checksum."""
    chk = 1
    for value in values:
        chk = (chk & 0x1FFFFFF) << 5 ^ value ^ _TAPS[chk >> 25]
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _create_checksum(hrp: str, data: list[int], m: int) -> list[int]:
    """Compute the checksum values given HRP and data."""
    values = _hrp_expand(hrp) + data
    polymod = _polymod([*values, 0, 0, 0, 0, 0, 0]) ^ m
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _assert_valid_m(m: int | None) -> None:
    """Refuse an `m` that is neither None nor one of the two constants.

    Any other integer would write, or verify, a checksum no bech32 reader
    accepts, and a bool is refused as for every integer field.
    """
    if m is None:
        return
    if not is_integer(m):
        raise Base58Bech32TypeError(f"invalid m type: {type(m).__name__}")
    if m not in (BECH32_1_CONST, BECH32_M_CONST):
        err_msg = f"invalid m: {_message_text(m)}, "
        err_msg += "neither BECH32_1_CONST nor BECH32_M_CONST"
        raise Base58Bech32ValueError(err_msg)


def _assert_valid_limit(limit: int | None) -> None:
    """Refuse a `limit` that is neither None nor a non-negative integer."""
    if limit is None:
        return
    if not is_integer(limit):
        raise Base58Bech32TypeError(f"invalid limit type: {type(limit).__name__}")
    if limit < 0:
        raise Base58Bech32ValueError(f"invalid limit: {_message_text(limit)} < 0")


def _assert_within_limit(length: int, limit: int | None) -> None:
    if limit is not None and length > limit:
        err_msg = f"too many bech32 characters: {length}, limit is {limit}"
        raise Base58Bech32ValueError(err_msg)


def _m_from_wit_ver(data: list[int]) -> int:
    if not data:
        raise Base58Bech32ValueError("empty data in bech32 address")
    wit_ver = data[0]
    return BECH32_1_CONST if wit_ver == 0 else BECH32_M_CONST


def _decode(bech: String, limit: int | None) -> tuple[str, list[int], list[int]]:
    """Determine a bech32 string HRP, data and checksum."""
    text = str_from_string(bech, "bech32 string")
    _assert_within_limit(len(text), limit)

    # no refusal quotes `text`: what reaches a decoder can be a private
    # key pasted in the wrong field, and an exception message is what
    # ends up in a log
    pos = text.rfind("1")  # find the separator between hrp and data
    if pos == -1:
        raise Base58Bech32ValueError("no separator character")
    if pos == 0:
        raise Base58Bech32ValueError("empty HRP")
    if pos + 7 > len(text):
        raise Base58Bech32ValueError("too short checksum")

    if not _hrp_in_range(text[:pos]):
        raise Base58Bech32ValueError("HRP character out of range")
    # the data part is held to the same range before anything lowers it:
    # str.lower maps U+212A KELVIN SIGN, its own uppercase, onto "k", so
    # an all-uppercase string carrying it would pass the case check and
    # decode as the string spelled with "K"
    if not _hrp_in_range(text[pos + 1 :]):
        raise Base58Bech32ValueError("data part character out of range")
    if text.lower() != text and text.upper() != text:
        raise Base58Bech32ValueError("mixed case")

    text = text.lower()
    hrp = text[:pos]

    # ascii by the range check above
    indices = text[pos + 1 :].encode("ascii").translate(_DIGIT_OF)
    if _NOT_A_DIGIT in indices[-6:]:
        raise Base58Bech32ValueError("invalid character in checksum")
    if _NOT_A_DIGIT in indices:
        raise Base58Bech32ValueError("invalid data character")

    return hrp, list(indices[:-6]), list(indices[-6:])


def bech32_decode(
    bech: String, *, m: int | None = None, limit: int | None = 1023
) -> tuple[str, list[int], int]:
    """Return (hrp, data, m) from a bech32 string, verifying its checksum.

    The `m` returned is the constant the checksum verifies with:
    `BECH32_1_CONST` for bech32, `BECH32_M_CONST` for bech32m. With `m`
    None either constant verifies; a constant passed as `m` must be the
    one that verifies; any other value is refused. A caller holding a
    segwit address checks the returned `m` against the witness version,
    as BIP350 says. The string is given as a str or as its ascii bytes,
    and the HRP comes back lowercase.

    A string longer than `limit` characters is refused before its HRP,
    its data characters and its checksum are checked; None refuses none.
    The default is not 90, BIP173's limit, because BOLT11's Lightning
    invoices are longer.

    The limit bounds what the checksum guarantees, for the constant passed
    as `m`, against errors that change only the low 5 bits of an HRP
    character, as BIP173 assumes:

    * within 89 characters besides the separator, any error affecting at
      most 4 characters is detected (BIP173), which `limit=90` keeps;
    * within 1023, the code's length, up to 3 errors are detected
      (Bitcoin Core's `src/bech32.cpp`), which the default keeps;
    * beyond 1023, one changed character is still detected, and up to 3
      within any 1023 consecutive characters, but two data characters
      1023 apart, changed by the same XOR of their values, leave the
      checksum valid.

    With `m` None, of these only the single-change guarantee holds: three
    changed characters within 90, and two within 1023, can turn a bech32
    string into a bech32m one, which decodes with `BECH32_M_CONST`
    returned. A caller that knows its constant passes it.

    Without BIP173's assumption the checksum runs over more values than
    the string has characters: each HRP character's high bits come first,
    as a value of their own. A change to those bits, such as a digit for a
    letter, can cancel a change 1023 checksummed values later, which is
    1023 minus the HRP's length characters later in the string, so two
    errors can pass within the default limit.
    """
    _assert_valid_m(m)
    _assert_valid_limit(limit)
    hrp, data, checksum = _decode(bech, limit)
    # the residue depends on the payload: a refusal names the constant it
    # matches and never prints it
    residue = _polymod(_hrp_expand(hrp) + data + checksum)
    if residue not in (BECH32_1_CONST, BECH32_M_CONST):
        raise Base58Bech32ValueError("invalid checksum")
    if m is not None and residue != m:
        name = "BECH32_1_CONST" if residue == BECH32_1_CONST else "BECH32_M_CONST"
        raise Base58Bech32ValueError(f"invalid checksum: {name} verifies")
    return hrp, data, residue


def bech32_encode(
    hrp: str, data: list[int], *, m: int | None = None, limit: int | None = 1023
) -> bytes:
    """Compute a bech32 string given HRP and 5-bit data values.

    `m` is `BECH32_1_CONST` or `BECH32_M_CONST`, any other value being
    refused; None reads it off the first value as a witness version, as
    BIP350 says, so a Lightning invoice or a Nostr key passes
    `m=BECH32_1_CONST`. `limit` is as `bech32_decode` takes it: a string
    longer than `limit` is refused rather than written. `data` is a list.
    The HRP is checked against the rule `bech32_decode` applies to it:
    non-empty, every character in BIP173's [33-126] range, and lowercase
    -- every data character is lowercase, so an uppercase HRP would write
    a string `bech32_decode` refuses as mixed case.

    Every value is one 5-bit digit, and each is checked rather than left
    to the translation table: a digit from 32 to 255 would write a NUL
    byte and say nothing, a bool would be written as its 0 or 1, and any
    other would leave as a built-in error rather than the package's.

    The string is lowercase. BIP173 says to use uppercase in a QR code,
    where it fits the smaller alphanumeric mode, and `bech32_decode` reads
    the `.upper()` of what this writes.
    """
    _assert_valid_m(m)
    _assert_valid_limit(limit)
    assert_type(data, list, "5-bit data")
    assert_type(hrp, str, "HRP")
    if not hrp:
        raise Base58Bech32ValueError("empty HRP")
    if not _hrp_in_range(hrp):
        raise Base58Bech32ValueError(f"HRP character out of range: {hrp}")
    if hrp != hrp.lower():
        raise Base58Bech32ValueError(f"HRP is not lowercase: {hrp}")

    # the fast path accepts an int of 0..31 and nothing else; any other
    # value, an IntEnum included, goes through the per-value loop, which
    # names the offender or accepts it
    if not all(type(d) is int and 0 <= d < 32 for d in data):
        for d in data:
            if not is_integer(d):
                raise Base58Bech32TypeError(
                    f"invalid 5-bit value type: {type(d).__name__}"
                )
            if not 0 <= d < 32:
                raise Base58Bech32ValueError(f"invalid 5-bit value: {_message_text(d)}")
    # the HRP, the separator, the data and the six checksum characters
    _assert_within_limit(len(hrp) + 1 + len(data) + 6, limit)
    m = _m_from_wit_ver(data) if m is None else m
    combined = data + _create_checksum(hrp, data, m)
    return f"{hrp}1".encode("ascii") + bytes(combined).translate(_CHAR_OF)


def convertbits(
    data: Iterable[int], from_bits: int, to_bits: int, pad: bool = True
) -> list[int]:
    """Convert a power-of-two digit sequence to another power-of-two base.

    The `convertbits` of BIP173's reference implementation: bytes to 5-bit
    values with `convertbits(data, 8, 5)`, and back with
    `convertbits(values, 5, 8, False)`. With `pad` the last group is
    padded with zero bits; without it, padding of `from_bits` bits or more,
    or padding that is not zero, is refused.

    `data` is any finite iterable of integers, such as a list, bytes or a
    generator, and is read to its end before the first value is checked:
    an unbounded iterator never returns.

    Both widths are integers from 1 to 64 and every value is an integer of
    at most `from_bits` bits, anything else being refused: a wider value
    would come out as the conversion of a different sequence, `[256]`
    from 8 to 5 bits as `[0]` does, and a zero `to_bits` would never
    leave the regrouping loop.
    """
    assert_type(pad, bool, "pad")
    for what, width in (("from_bits", from_bits), ("to_bits", to_bits)):
        if not is_integer(width):
            raise Base58Bech32TypeError(f"invalid {what} type: {type(width).__name__}")
        if width < 1:
            raise Base58Bech32ValueError(f"invalid {what}: {_message_text(width)} < 1")
        if width > 64:
            raise Base58Bech32ValueError(f"invalid {what}: {_message_text(width)} > 64")
    assert_type(data, Iterable, "data")

    values = list(data)
    # as in `bech32_encode`: the fast path takes an int of `from_bits`
    # bits, and the loop judges anything else
    top = 1 << from_bits
    if not all(type(value) is int and 0 <= value < top for value in values):
        for value in values:
            if not is_integer(value):
                raise Base58Bech32TypeError(
                    f"invalid value type: {type(value).__name__}"
                )
            if value < 0 or (value >> from_bits):
                raise Base58Bech32ValueError(f"invalid value: {_message_text(value)}")
    return _convertbits(values, from_bits, to_bits, pad)


def _convertbits(
    data: Iterable[int], from_bits: int, to_bits: int, pad: bool
) -> list[int]:
    # the validating wrapper's work, for a caller whose digits are
    # integers of `from_bits` bits by construction
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << to_bits) - 1
    max_acc = (1 << (from_bits + to_bits - 1)) - 1
    for value in data:
        acc = ((acc << from_bits) | value) & max_acc
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            ret.append((acc >> bits) & maxv)

    if pad:
        if bits:
            ret.append((acc << (to_bits - bits)) & maxv)
    elif bits >= from_bits:
        err_msg = f"zero padding of more than {from_bits - 1} bits"
        err_msg += f" in {from_bits}-to-{to_bits} conversion"
        raise Base58Bech32ValueError(err_msg)
    elif (acc << (to_bits - bits)) & maxv:
        err_msg = f"non-zero padding in {from_bits}-to-{to_bits} conversion"
        raise Base58Bech32ValueError(err_msg)

    return ret


def _assert_constant(m: int) -> None:
    """Refuse an `m` that is not one of the two constants, None included."""
    if not is_integer(m):
        raise Base58Bech32TypeError(f"invalid m type: {type(m).__name__}")
    _assert_valid_m(m)


def bech32_encode_bytes(
    hrp: str, payload: Octets, *, m: int, limit: int | None = 1023
) -> bytes:
    """Compute a bech32 string given HRP and a payload of bytes.

    The payload, a bytes-like object or a hex string, is regrouped into
    5-bit values, zero bits filling out the last one where needed, and
    written by `bech32_encode`, which checks the HRP. A Nostr key (NIP-19)
    is such a payload. A Lightning invoice is not: its 5-bit fields need
    not fill whole bytes, so it stays with `bech32_encode`.

    `m` is `BECH32_1_CONST` or `BECH32_M_CONST`, and None is refused: the
    first 5-bit value of a payload of bytes is no witness version to read
    it off. A segwit address is a witness version and a program, which
    this pair does not express: it is written with `bech32_encode` and
    `convertbits`. `limit` is as `bech32_decode` takes it.
    """
    _assert_constant(m)
    values = _convertbits(bytes_from_octets(payload), 8, 5, True)
    return bech32_encode(hrp, values, m=m, limit=limit)


def bech32_decode_bytes(
    bech: String, *, m: int, limit: int | None = 1023
) -> tuple[str, bytes]:
    """Return (hrp, payload) from a bech32 string, verifying its checksum.

    The inverse of `bech32_encode_bytes`, with the same `m` and `limit`.
    The string is read by `bech32_decode` and its 5-bit values are
    regrouped into bytes: padding of 5 bits or more, or padding that is
    not zero, is refused, as `convertbits(values, 5, 8, False)` refuses
    it.
    """
    _assert_constant(m)
    hrp, values, _ = bech32_decode(bech, m=m, limit=limit)
    return hrp, bytes(_convertbits(values, 5, 8, False))
