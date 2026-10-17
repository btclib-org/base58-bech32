# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""SS58 addresses, the format of Polkadot and of every Substrate chain.

An SS58 address is the Base58, over Bitcoin's alphabet, of a prefix, a
payload and a checksum. The prefix is a number from 0 to 16383 naming a
network: one byte below 64, two bytes from 64 up. The payload is a
32-byte account id, or the 33 bytes of a compressed ECDSA public key.
The checksum is the first two bytes of
`blake2b(b"SS58PRE" + prefix + payload, digest_size=64)`.

What is refused beyond what Substrate's `Ss58Codec` refuses: a prefix
above 16383, which Substrate masks into range when encoding; the reserved
prefixes 46 and 47 when encoding, which Substrate encodes and refuses
only when decoding; and a prefix below 64 written in the two-byte form,
which Substrate decodes and which would give one account a second
address. Like Substrate's, the decoder refuses 46 and 47. Both functions
refuse a payload other than 32 or 33 bytes, the sizes of Substrate's
account id and ECDSA public key. polkadot-js also encodes payloads of 1,
2, 4 or 8 bytes, account indices, with a one-byte checksum; they are
refused here.

`Ss58Codec` is in `substrate/primitives/core/src/crypto.rs` of
https://github.com/paritytech/polkadot-sdk, and polkadot-js' encoder in
`packages/util-crypto/src/address/encode.ts` of
https://github.com/polkadot-js/common, at commit
9281daa14c2c2a41708c3489de8770a064525577.
"""

from __future__ import annotations

import hashlib

from base58_bech32._utils import (
    Octets,
    String,
    _message_text,
    bytes_from_octets,
    is_integer,
)
from base58_bech32.base58 import BITCOIN_ALPHABET, _ascii_bytes, _b58decode, _b58encode
from base58_bech32.exceptions import Base58Bech32TypeError, Base58Bech32ValueError

__all__ = [
    "ss58_decode",
    "ss58_encode",
]

_CHECKSUM_PREFIX = b"SS58PRE"
_CHECKSUM_SIZE = 2
_PAYLOAD_SIZES = (32, 33)
_RESERVED = (46, 47)
_MAX_PREFIX = 16383
# the longest string a two-byte prefix, a 33-byte payload and the
# checksum can be written in: 37 bytes, at most 51 base58 characters.
# Refused before decoding, which is quadratic in the length
_MAX_LENGTH = 51


def _checksum(data: bytes) -> bytes:
    digest = hashlib.blake2b(_CHECKSUM_PREFIX + data, digest_size=64).digest()
    return digest[:_CHECKSUM_SIZE]


def _assert_valid_prefix(prefix: int) -> None:
    if not is_integer(prefix):
        err_msg = f"invalid SS58 prefix type: {type(prefix).__name__}"
        raise Base58Bech32TypeError(err_msg)
    if not 0 <= prefix <= _MAX_PREFIX:
        err_msg = (
            f"invalid SS58 prefix: {_message_text(prefix)} not in 0..{_MAX_PREFIX}"
        )
        raise Base58Bech32ValueError(err_msg)
    if prefix in _RESERVED:
        raise Base58Bech32ValueError(f"reserved SS58 prefix: {prefix}")


def _prefix_bytes(prefix: int) -> bytes:
    if prefix < 64:
        return bytes([prefix])
    # the six high bits of the low byte, flagged with 0b01, then the low
    # two bits of the low byte above the six bits of the high byte
    first = ((prefix & 0b0000_0000_1111_1100) >> 2) | 0b0100_0000
    second = (prefix >> 8) | ((prefix & 0b0000_0000_0000_0011) << 6)
    return bytes([first, second])


def ss58_encode(prefix: int, payload: Octets) -> bytes:
    """Return the SS58 address of a 32- or 33-byte payload on a network.

    `prefix` is the network's number, 42 for a generic Substrate chain and
    0 for Polkadot. The address comes back as ascii bytes.
    """
    _assert_valid_prefix(prefix)
    data = _prefix_bytes(prefix) + bytes_from_octets(payload, _PAYLOAD_SIZES)
    return _b58encode(data + _checksum(data), BITCOIN_ALPHABET)


def ss58_decode(address: String) -> tuple[int, bytes]:
    """Return the (prefix, payload) of an SS58 address, verifying its checksum.

    The address is given as a str or as its ascii bytes, and the payload
    comes back as 32 or 33 bytes.
    """
    v = _ascii_bytes(address)
    if len(v) > _MAX_LENGTH:
        err_msg = f"invalid SS58 address length: {len(v)} characters"
        raise Base58Bech32ValueError(err_msg)
    data = _b58decode(v, BITCOIN_ALPHABET)

    if len(data) < 2:
        raise Base58Bech32ValueError(f"invalid SS58 address size: {len(data)} bytes")
    if data[0] < 64:
        prefix_size, prefix = 1, data[0]
    elif data[0] < 128:
        prefix_size = 2
        low = ((data[0] << 2) | (data[1] >> 6)) & 0xFF
        prefix = low | ((data[1] & 0b0011_1111) << 8)
        if prefix < 64:
            err_msg = f"invalid SS58 prefix: {prefix} in the two-byte form"
            raise Base58Bech32ValueError(err_msg)
    else:
        raise Base58Bech32ValueError(f"invalid SS58 prefix byte: {data[0]}")

    payload_size = len(data) - prefix_size - _CHECKSUM_SIZE
    if payload_size not in _PAYLOAD_SIZES:
        raise Base58Bech32ValueError(f"invalid SS58 address size: {len(data)} bytes")
    if prefix in _RESERVED:
        raise Base58Bech32ValueError(f"reserved SS58 prefix: {prefix}")

    body, checksum = data[:-_CHECKSUM_SIZE], data[-_CHECKSUM_SIZE:]
    if checksum != _checksum(body):
        raise Base58Bech32ValueError("invalid SS58 checksum")
    return prefix, body[prefix_size:]
