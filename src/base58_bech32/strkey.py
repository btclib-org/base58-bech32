# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Strkeys, the text form of Stellar's account ids, keys and addresses.

A strkey is the RFC 4648 base-32, without padding, of a version byte, a
payload and a checksum: the CRC16-XModem of the version byte and the
payload, stored little-endian.

SEP-0023 has a decoder refuse any string that does not re-encode to
itself. Such a string has a character outside the uppercase alphabet, a
length congruent to 1, 3 or 6 mod 8, or unused bits of its last
character that are not zero, and the decoder refuses each of the three.

What a version byte names is the caller's to know: the key type in its
top five bits, the algorithm in its low three, and the size and layout
of the payload each takes. So a strkey that SEP-0023 refuses for its
algorithm, or for its payload's size or layout, is read here, and
refusing it is the caller's.

The specification is SEP-0023, `ecosystem/sep-0023.md` of
https://github.com/stellar/stellar-protocol at commit
f2d364902615af726b3533021403c8b225aa6e5d, and the reference is the
`decodeCheck` and `encodeCheck` behind js-stellar-base's `StrKey`, in
`src/strkey.js` of https://github.com/stellar/js-stellar-base at commit
6ad55f781139898ade2bbb54987c268af0d6ecb6.
"""

from __future__ import annotations

import base64
import binascii
import hmac

from base58_bech32._utils import (
    Octets,
    String,
    _message_text,
    bytes_from_octets,
    is_integer,
    str_from_string,
)
from base58_bech32.exceptions import Base58Bech32TypeError, Base58Bech32ValueError

__all__ = [
    "strkey_decode",
    "strkey_encode",
]

_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
# the lengths mod 8 that no number of bytes encodes to: their last
# character would hold five or more bits of no byte
_INVALID_LENGTHS = (1, 3, 6)
_CHECKSUM_SIZE = 2


def _checksum(data: bytes) -> bytes:
    """Return the CRC16-XModem of `data`, little-endian.

    `crc_hqx` is the CRC with polynomial 0x1021, not reflected, and with
    no final xor; started from zero, it is XModem's.
    """
    return binascii.crc_hqx(data, 0).to_bytes(_CHECKSUM_SIZE, "little")


def strkey_encode(version: int, payload: Octets) -> bytes:
    """Return the strkey of a version byte and a payload, as ascii bytes.

    `version` is the byte, from 0 to 255, and `payload` the bytes after
    it, of any size.
    """
    if not is_integer(version):
        err_msg = f"invalid strkey version byte type: {type(version).__name__}"
        raise Base58Bech32TypeError(err_msg)
    # the plain int, so that no comparison of a subclass's own decides the
    # range check
    version = int.__index__(version)
    if not 0 <= version <= 0xFF:
        err_msg = f"invalid strkey version byte: {_message_text(version)} not in 0..255"
        raise Base58Bech32ValueError(err_msg)
    data = bytes([version]) + bytes_from_octets(payload)
    return base64.b32encode(data + _checksum(data)).rstrip(b"=")


def strkey_decode(strkey: String) -> tuple[int, bytes]:
    """Return the (version byte, payload) of a strkey, verifying its checksum.

    The strkey is given as a str or as its ascii bytes, in uppercase.
    """
    text = str_from_string(strkey, "strkey")
    if not text.isascii() or text.encode("ascii").translate(None, _ALPHABET):
        raise Base58Bech32ValueError("invalid strkey character")
    if len(text) % 8 in _INVALID_LENGTHS:
        raise Base58Bech32ValueError(f"invalid strkey length: {len(text)} characters")
    unused = 5 * len(text) % 8
    if unused and _ALPHABET.index(ord(text[-1])) & ((1 << unused) - 1):
        raise Base58Bech32ValueError("invalid strkey: unused bits not zero")
    data = base64.b32decode(text + "=" * (-len(text) % 8))
    if len(data) < 1 + _CHECKSUM_SIZE:
        raise Base58Bech32ValueError(f"invalid strkey size: {len(data)} bytes")
    body, checksum = data[:-_CHECKSUM_SIZE], data[-_CHECKSUM_SIZE:]
    if not hmac.compare_digest(checksum, _checksum(body)):
        raise Base58Bech32ValueError("invalid strkey checksum")
    return body[0], body[1:]
