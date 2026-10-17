# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""CashAddr encoding and decoding, the address format of Bitcoin Cash.

A CashAddr address is a prefix naming the network, the separator ":",
and 5-bit values written with bech32's alphabet: a version byte, a hash,
and a 40-bit checksum over the prefix and the rest. The version byte's
top bit is reserved and zero, the next four are the type of the address
and the low three the size of the hash, from 20 to 64 bytes. The prefix
may be left out of the string, the checksum still covering it, and the
decoder then has to be told which it is.

The specification is `spec/cashaddr.md` of
https://github.com/bitcoincashorg/bitcoincash.org, and the refusals are
those of Bitcoin Cash Node's `cashaddr::Decode` and
`DecodeCashAddrContent`. The type is the specification's four bits and
no more: 0 is P2KH and 1 P2SH, and what any other value means is the
caller's to know.
"""

from __future__ import annotations

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
from base58_bech32.bech32 import _ALPHABET, _INDEX_OF, _convertbits
from base58_bech32.exceptions import Base58Bech32TypeError, Base58Bech32ValueError

__all__ = [
    "cashaddr_decode",
    "cashaddr_encode",
]

# the hash size of each value of the version byte's size bits
_HASH_SIZES = (20, 24, 28, 32, 40, 48, 56, 64)
_CHECKSUM_SIZE = 8

# the specification's five generator constants, tabulated as bech32's are
_GENERATOR = (0x98F2BC8E61, 0x79B76D99E2, 0xF33E5FB3C4, 0xAE2EABE2A8, 0x1E4F43E470)
_TAPS = [
    reduce(xor, [g for i, g in enumerate(_GENERATOR) if top >> i & 1], 0)
    for top in range(32)
]


def _polymod(values: list[int]) -> int:
    """Return the CashAddr checksum: zero for a valid string."""
    c = 1
    for d in values:
        c = ((c & 0x07FFFFFFFF) << 5) ^ d ^ _TAPS[c >> 35]
    return c ^ 1


def _prefix_expand(prefix: str) -> list[int]:
    """Return the low five bits of each prefix character, then a zero."""
    return [ord(x) & 31 for x in prefix] + [0]


def _assert_valid_prefix(prefix: str) -> None:
    """Refuse a prefix that is not lowercase ascii letters."""
    assert_type(prefix, str, "CashAddr prefix")
    if not prefix:
        raise Base58Bech32ValueError("empty CashAddr prefix")
    if not (prefix.isascii() and prefix.isalpha() and prefix.islower()):
        raise Base58Bech32ValueError(f"invalid CashAddr prefix: {prefix}")


def cashaddr_encode(prefix: str, kind: int, digest: Octets) -> bytes:
    """Return the CashAddr address of a hash, as ascii bytes.

    `prefix` is the network's, lowercase letters such as "bitcoincash",
    and the address carries it. `kind` is the type, from 0 to 15, and
    `digest` the hash, of one of the sizes from 20 to 64 bytes the
    version byte can say.
    """
    _assert_valid_prefix(prefix)
    if not is_integer(kind):
        raise Base58Bech32TypeError(
            f"invalid CashAddr type type: {type(kind).__name__}"
        )
    if not 0 <= kind < 16:
        err_msg = f"invalid CashAddr type: {_message_text(kind)} not in 0..15"
        raise Base58Bech32ValueError(err_msg)
    digest = bytes_from_octets(digest, _HASH_SIZES)

    version = kind << 3 | _HASH_SIZES.index(len(digest))
    payload = _convertbits([version, *digest], 8, 5, True)
    mod = _polymod(_prefix_expand(prefix) + payload + [0] * _CHECKSUM_SIZE)
    checksum = [(mod >> 5 * (7 - i)) & 31 for i in range(_CHECKSUM_SIZE)]
    text = f"{prefix}:" + "".join(_ALPHABET[d] for d in payload + checksum)
    return text.encode("ascii")


def _split(text: str) -> tuple[str | None, str]:
    """Return the prefix the string carries, if any, and the payload part.

    Refused, as Bitcoin Cash Node refuses them: a character that is no
    ascii letter, digit or ":", a second ":", a ":" first, a digit before
    the ":", and upper and lower case mixed. No refusal quotes the string.
    """
    if not all(x.isascii() and (x.isalnum() or x == ":") for x in text):
        raise Base58Bech32ValueError("invalid CashAddr character")
    if text.count(":") > 1:
        raise Base58Bech32ValueError("more than one CashAddr separator")
    if text.lower() != text and text.upper() != text:
        raise Base58Bech32ValueError("mixed case")
    text = text.lower()
    if ":" not in text:
        return None, text
    prefix, payload = text.split(":")
    if not prefix:
        raise Base58Bech32ValueError("empty CashAddr prefix")
    if not prefix.isalpha():
        raise Base58Bech32ValueError("digit in CashAddr prefix")
    return prefix, payload


def _decode(address: String, prefix: str | None) -> tuple[str, list[int]]:
    """Verify an address's checksum, and return its prefix and 5-bit values."""
    if prefix is not None:
        _assert_valid_prefix(prefix)
    written, payload = _split(str_from_string(address, "CashAddr address"))
    if written is None:
        if prefix is None:
            raise Base58Bech32ValueError("no CashAddr prefix, and none given")
        written = prefix
    elif prefix is not None and written != prefix:
        raise Base58Bech32ValueError("CashAddr prefix is not the one given")

    if len(payload) < _CHECKSUM_SIZE:
        raise Base58Bech32ValueError("too short checksum")
    values = [_INDEX_OF.get(x, -1) for x in payload]
    if -1 in values:
        raise Base58Bech32ValueError("invalid CashAddr payload character")
    if _polymod(_prefix_expand(written) + values):
        raise Base58Bech32ValueError("invalid checksum")
    return written, values[:-_CHECKSUM_SIZE]


def cashaddr_decode(
    address: String, *, prefix: str | None = None
) -> tuple[str, int, bytes]:
    """Return the (prefix, type, hash) of a CashAddr address.

    The address is given as a str or as its ascii bytes, all lowercase or
    all uppercase. `prefix` is the network expected: an address carrying
    another is refused, and one carrying none is read as carrying it. An
    address carrying none, with no `prefix` given, is refused.
    """
    written, values = _decode(address, prefix)
    if not values:
        raise Base58Bech32ValueError("empty CashAddr payload")
    data = _convertbits(values, 5, 8, False)
    version = data[0]
    if version & 0x80:
        raise Base58Bech32ValueError("reserved bit set in CashAddr version byte")
    hash_size = _HASH_SIZES[version & 0x07]
    if len(data) != hash_size + 1:
        err_msg = f"invalid CashAddr hash size: {len(data) - 1} bytes "
        err_msg += f"instead of {hash_size}"
        raise Base58Bech32ValueError(err_msg)
    return written, version >> 3, bytes(data[1:])
