# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Base58 and Base58Check encoding and decoding.

Base58 writes bytes with 58 characters: Base64's alphabet less the
similar-looking 0 (zero), O (capital o), I (capital i) and l (lower case
L), and less "+" and "/", so that a double-click selects the whole
string. Each leading zero byte is written as one leading copy of the
alphabet's first character.

Base58Check is Base58 of the payload followed by a checksum, the first
four bytes of its double SHA-256; decoding verifies it.

Every function takes the alphabet as a keyword: Bitcoin's by default,
or Ripple's, or any other 58 distinct ascii bytes. The interface follows
the standard library's `base64`: an encoder takes bytes and answers
ascii bytes, a decoder takes ascii bytes or a str and answers bytes.

This implementation is originally from https://github.com/keis/base58,
by way of btclib, with the following modifications:

* type annotated Python3
* the checked decoder refuses a string longer than `MAX_LENGTH`
* an optional check on the decoded size
* translation tables and ten digits per big-integer step, where the
  original reads one character at a time
"""

from __future__ import annotations

import functools
import hashlib
from collections.abc import Iterable

from base58_bech32._utils import (
    Octets,
    String,
    _assert_byte_shaped,
    _message_text,
    assert_type,
    bytes_from_octets,
    is_integer,
)
from base58_bech32.exceptions import Base58Bech32TypeError, Base58Bech32ValueError

__all__ = [
    "BITCOIN_ALPHABET",
    "MAX_LENGTH",
    "RIPPLE_ALPHABET",
    "b58decode",
    "b58decode_check",
    "b58encode",
    "b58encode_check",
]

#: Bitcoin's alphabet, the default.
BITCOIN_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
#: Ripple's (XRP's) alphabet.
RIPPLE_ALPHABET = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

_BASE = 58

# how many digits are carried through the big-integer arithmetic at a
# time. 58**10 < 2**64, so a chunk's ten digits come out of an int the
# machine holds in a register, and the multiplication or division that
# costs O(size of the number) is paid once per ten digits instead of once
# per digit. Both loops stay quadratic in the length of the string -- the
# accumulator grows -- with a tenth of the coefficient
_CHUNK = 10
_CHUNK_BASE = _BASE**_CHUNK

#: The longest string `b58decode_check` decodes: a BIP32 extended key,
#: 78 bytes of payload and 4 of checksum, takes at most 112 characters.
#: Decoding is quadratic in the length, and the checksum that would refuse
#: a long string is verified only once the decoding has been paid for, so
#: the cap keeps that cost away from attacker-supplied text. The encoder is
#: uncapped: what it is handed is data the caller already holds.
MAX_LENGTH = 112


@functools.lru_cache(maxsize=8)
def _tables(alphabet: bytes) -> tuple[bytes, bytes]:
    """Return the digit-of and character-of translation tables of an alphabet.

    A whole string is translated in one C pass, where looking a character
    up in the alphabet is a scan of 58 bytes. `bytes.maketrans` leaves
    every byte it is not given alone, which is why a decoder asks first
    whether every character is in the alphabet.
    """
    digit_of = bytes.maketrans(alphabet, bytes(range(_BASE)))
    char_of = bytes.maketrans(bytes(range(_BASE)), alphabet)
    return digit_of, char_of


def _assert_valid_alphabet(alphabet: bytes) -> None:
    """Refuse what is not 58 distinct ascii bytes."""
    assert_type(alphabet, bytes, "alphabet")
    if len(alphabet) != _BASE:
        err_msg = f"invalid alphabet size: {len(alphabet)} bytes instead of {_BASE}"
        raise Base58Bech32ValueError(err_msg)
    if len(set(alphabet)) != _BASE:
        raise Base58Bech32ValueError("invalid alphabet: repeated characters")
    # the encoders answer ascii bytes, and a decoder reads ascii only
    if not alphabet.isascii():
        raise Base58Bech32ValueError("invalid alphabet: non-ascii byte")


def _b58encode_from_int(i: int, char_of: bytes) -> bytes:
    # least significant digit first into a bytearray, reversed once at the
    # end, and translated to characters in one pass
    digits = bytearray()
    while i >= _CHUNK_BASE:
        # ten digits of a number whose higher part is not zero yet, so all
        # ten are significant and the leading zeros among them are real
        i, chunk = divmod(i, _CHUNK_BASE)
        for _ in range(_CHUNK):
            chunk, digit = divmod(chunk, _BASE)
            digits.append(digit)
    while i or not digits:
        # the most significant digits, and `not digits` is zero itself:
        # written as one digit rather than as nothing
        i, digit = divmod(i, _BASE)
        digits.append(digit)
    digits.reverse()
    return bytes(digits).translate(char_of)


def _b58encode(v: bytes, alphabet: bytes) -> bytes:
    # leading zero bytes become leading first characters of the alphabet
    n_pad = len(v)
    v = v.lstrip(b"\0")
    vlen = len(v)
    n_pad -= vlen
    result = alphabet[:1] * n_pad

    if vlen:
        i = int.from_bytes(v, byteorder="big", signed=False)
        result += _b58encode_from_int(i, _tables(alphabet)[1])

    return result


def b58encode(v: Octets, *, alphabet: bytes = BITCOIN_ALPHABET) -> bytes:
    """Encode a bytes-like object, or a hex-string, using Base58.

    No checksum: `b58encode_check` is the checksummed form.
    """
    _assert_valid_alphabet(alphabet)
    return _b58encode(bytes_from_octets(v), alphabet)


def b58encode_check(
    v: Octets,
    *,
    in_size: int | Iterable[int] | None = None,
    alphabet: bytes = BITCOIN_ALPHABET,
) -> bytes:
    """Encode a bytes-like object, or a hex-string, using Base58Check.

    `in_size` is the payload size required, one size or any iterable of
    them. Uncapped: a payload of roughly 80 bytes or more encodes to a
    string longer than `MAX_LENGTH`, which `b58decode_check` then refuses.
    """
    _assert_valid_alphabet(alphabet)
    v = bytes_from_octets(v, in_size)
    checksum = hashlib.sha256(hashlib.sha256(v).digest()).digest()[:4]
    return _b58encode(v + checksum, alphabet)


def _b58decode_to_int(v: bytes, digit_of: bytes) -> int:
    digits = v.translate(digit_of)
    i = 0
    for start in range(0, len(digits), _CHUNK):
        chunk = digits[start : start + _CHUNK]
        value = 0
        for digit in chunk:
            value = value * _BASE + digit
        # one multiplication of the accumulator per ten digits, by the
        # power that matches the chunk actually read: the last one is
        # shorter unless the string divides by ten
        i = i * _BASE ** len(chunk) + value
    return i


def _b58decode(v: bytes, alphabet: bytes) -> bytes:
    # every alphabet byte deleted, so what is left is what is not one: the
    # question has to be asked before the translation, which leaves a byte
    # outside the alphabet as itself
    if v.translate(None, alphabet):
        raise Base58Bech32ValueError("Base58 string contains invalid characters")

    # leading first characters of the alphabet become leading zero bytes
    n_pad = len(v)
    v = v.lstrip(alphabet[:1])
    vlen = len(v)
    n_pad -= vlen
    result = b"\0" * n_pad

    if vlen:
        i = _b58decode_to_int(v, _tables(alphabet)[0])
        nbytes = (i.bit_length() + 7) // 8
        result += i.to_bytes(nbytes, byteorder="big", signed=False)

    return result


def _ascii_bytes(v: String) -> bytes:
    """Return the ascii octets of a base58 string, refusing what has none.

    A str is encoded, and a refusal names the position of a character
    outside ascii and never the character: the string can be a private
    key. A buffer is copied after `_assert_byte_shaped`, and anything
    else is a type error.
    """
    if isinstance(v, str):
        # do not trim spaces
        try:
            return v.encode("ascii")
        except UnicodeEncodeError as e:
            err_msg = f"non-ascii character in base58 string at position {e.start}"
        # raised outside the `except`: the Unicode error holds the whole
        # string, and must not be left as the new error's context
        raise Base58Bech32ValueError(err_msg)
    if not isinstance(v, (bytes, bytearray, memoryview)):
        err_msg = f"invalid base58 string type: {type(v).__name__}"  # type: ignore[unreachable]
        raise Base58Bech32TypeError(err_msg)
    # a strided memoryview or one whose format is not "B" is refused
    # before len() is read: for either, len() counts elements rather than
    # the octets bytes() would gather
    _assert_byte_shaped(v)
    return bytes(v)


def b58decode(v: String, *, alphabet: bytes = BITCOIN_ALPHABET) -> bytes:
    """Decode a Base58 string, given as ascii bytes or as a str.

    No checksum is verified and no length is capped: `b58decode_check`
    does both. Decoding is quadratic in the length of the string.
    """
    _assert_valid_alphabet(alphabet)
    return _b58decode(_ascii_bytes(v), alphabet)


def b58decode_check(
    v: String,
    *,
    out_size: int | None = None,
    alphabet: bytes = BITCOIN_ALPHABET,
    secret: bool = False,
) -> bytes:
    """Decode a Base58Check string, verifying its checksum.

    `out_size` is the payload size required. A checksum mismatch quotes
    both checksums, unless `secret` is true: the expected checksum is a
    hash of the payload, so a caller whose payload is a private key must
    not publish it.

    Capped at `MAX_LENGTH` characters, unlike `b58encode_check`: a string
    written from a payload of roughly 80 bytes or more is refused here.
    `secret` is a bool, anything else being refused: `0`, `None` and `""`
    would read as false and quote the checksums.
    """
    assert_type(secret, bool, "secret")
    _assert_valid_alphabet(alphabet)
    v = _ascii_bytes(v)

    if len(v) > MAX_LENGTH:
        err_msg = f"too many base58 characters: {len(v)}, max is {MAX_LENGTH}"
        raise Base58Bech32ValueError(err_msg)

    result = _b58decode(v, alphabet)
    if len(result) < 4:
        err_msg = "not enough bytes for checksum, "
        err_msg += f"invalid base58 decoded size: {len(result)}"
        raise Base58Bech32ValueError(err_msg)

    result, checksum = result[:-4], result[-4:]
    expected = hashlib.sha256(hashlib.sha256(result).digest()).digest()[:4]
    if checksum != expected:
        err_msg = "invalid checksum"
        if not secret:
            err_msg += f": 0x{checksum.hex()} instead of 0x{expected.hex()}"
        raise Base58Bech32ValueError(err_msg)

    # a bool would accept a one-octet payload and call it a checked size
    if out_size is not None and not is_integer(out_size):
        err_msg = f"invalid output size type: {type(out_size).__name__}"
        raise Base58Bech32TypeError(err_msg)

    if out_size is None or len(result) == out_size:
        return result

    err_msg = "valid checksum, invalid decoded size: "
    err_msg += f"{len(result)} bytes instead of {_message_text(out_size)}"
    raise Base58Bech32ValueError(err_msg)
