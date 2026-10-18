# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing every decoder of the package.

An address or a key in text is what reaches a decoder from outside the
process: pasted, scanned from a QR code, read off a network. Each decoder
reads `data` twice, as the bytes it is and as UTF-8 text where it is
that, and a string that decodes is encoded again and has to give the
string back, lowercase where the format is case-insensitive.

A crash here on hostile input is a defect in the decoder, never in this
harness. `Base58Bech32Exception` is what each decoder answers malformed
input with, so that family is caught below as the expected outcome; any
other exception propagates to atheris as the finding it is.

The seed corpus is one string of each format.
"""

from __future__ import annotations

import contextlib
import sys

import atheris

from base58_bech32 import base58, bech32, cashaddr, ss58
from base58_bech32.exceptions import Base58Bech32Exception

# tests/fuzz_corpus_test.py reads this by ast.literal_eval, never by
# importing the module -- atheris below is CI-only and undeclared in
# pyproject.toml, so the test must not execute this file
ENTRY_POINTS = (
    "base58_bech32.base58:b58decode",
    "base58_bech32.base58:b58decode_check",
    "base58_bech32.bech32:bech32_decode",
    "base58_bech32.ss58:ss58_decode",
    "base58_bech32.cashaddr:cashaddr_decode",
)


def _round_trip(encoded: bytes, original: str | bytes) -> None:
    """Refuse an encoding that does not give back the string decoded."""
    if isinstance(original, str):
        original = original.encode("ascii")
    if encoded != original.lower() and encoded != original:
        msg = "a decoded string encodes to another string"
        raise AssertionError(msg)


def fuzz_target(data: bytes) -> None:
    """Read `data` with every decoder, as bytes and as text.

    `Base58Bech32Exception` is swallowed as each decoder's own refusal of
    malformed input; any other exception propagates, which is how atheris
    tells a defect in the decoder from the domain of input it already
    rejects.
    """
    inputs: list[str | bytes] = [data]
    with contextlib.suppress(UnicodeDecodeError):
        inputs.append(data.decode("utf-8"))
    for text in inputs:
        with contextlib.suppress(Base58Bech32Exception):
            _round_trip(base58.b58encode(base58.b58decode(text)), text)
        with contextlib.suppress(Base58Bech32Exception):
            _round_trip(base58.b58encode_check(base58.b58decode_check(text)), text)
        with contextlib.suppress(Base58Bech32Exception):
            hrp, values, m = bech32.bech32_decode(text)
            _round_trip(bech32.bech32_encode(hrp, values, m=m), text)
        with contextlib.suppress(Base58Bech32Exception):
            _round_trip(ss58.ss58_encode(*ss58.ss58_decode(text)), text)
        with contextlib.suppress(Base58Bech32Exception):
            _round_trip(cashaddr.cashaddr_encode(*cashaddr.cashaddr_decode(text)), text)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
