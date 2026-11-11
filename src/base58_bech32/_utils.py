# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The coercions every public function runs its inputs through.

Copies of `btclib.utils.assert_type`, `bytes_from_octets`, `is_integer`,
`str_from_string`, `_message_text`, `_message_field`, `_name_text`,
`_sizes_text`, `_int_description` and `_MAX_QUOTED_NAME_LENGTH`, and of
`btclib.alias.Octets` and `String`, raising this package's own
exceptions: importing them from `btclib` would make a package of codecs
depend on the whole of a bitcoin library.

A copy can drift from its original with every gate green, so
`tests/utils_test.py` runs both on one table of inputs and asks them for
the same answer, or for a refusal from the same built-in class.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from base58_bech32.exceptions import Base58Bech32TypeError, Base58Bech32ValueError

__all__ = [
    "Octets",
    "String",
    "assert_type",
    "bytes_from_octets",
    "is_integer",
    "str_from_string",
]

#: Bytes, or the hex-string that decodes to them, wherever raw bytes are
#: asked for.
Octets = bytes | str | bytearray | memoryview

#: Text, as a str or as its ascii bytes: what a decoder reads. The same
#: union as `Octets`, told apart at run time by the coercion each
#: parameter runs through.
String = bytes | str | bytearray | memoryview


def _assert_byte_shaped(octets: bytes | bytearray | memoryview) -> None:
    """Refuse a memoryview whose layout or format is not plain bytes.

    `bytes` and `bytearray` are always C-contiguous and always format
    "B" (unsigned bytes); a `memoryview` need not be either. A strided
    slice such as `mv[::2]` is not C-contiguous, and `bytes()` of one
    gathers its strides into a run that no buffer holds; a view cast to
    a signed "b", or over an array of a wider format such as "I", is
    contiguous and still counts elements where `bytes()` yields
    `itemsize` octets of each.
    """
    if not isinstance(octets, memoryview):
        return
    if not octets.c_contiguous:
        err_msg = "invalid octets: non-contiguous memoryview"
        raise Base58Bech32ValueError(err_msg)
    if octets.format != "B":
        err_msg = f"invalid octets: memoryview format {octets.format!r} instead of 'B'"
        raise Base58Bech32ValueError(err_msg)


def bytes_from_octets(
    octets: Octets, out_size: int | Iterable[int] | None = None
) -> bytes:
    """Return bytes from a hex-string, as `bytes.fromhex` reads it.

    `bytes.fromhex` skips ASCII whitespace (space, tab, newline, vertical
    tab, form feed, carriage return) anywhere but inside a byte.

    A `bytearray` or a `memoryview` is copied, which is what makes the
    `bytes` this promises true: handed back as it came, either is still
    the caller's own object.

    Optionally, it also ensures required output size: one size, or any
    iterable of them, and a bool is neither.
    """
    if isinstance(octets, str):  # hex string
        # the message is fromhex's own, which names a position and never
        # the string: an Octets parameter can be key material
        try:
            octets = bytes.fromhex(octets)
        except ValueError as e:
            raise Base58Bech32ValueError(f"invalid hex string: {e}") from e
    elif isinstance(octets, (bytes, bytearray, memoryview)):
        _assert_byte_shaped(octets)
        octets = bytes(octets)
    else:
        err_msg = f"invalid octets type: {type(octets).__name__}"  # type: ignore[unreachable]
        raise Base58Bech32TypeError(err_msg)

    if out_size is None:
        return octets

    if isinstance(out_size, int):
        sizes: tuple[int, ...] = (out_size,)
    elif isinstance(out_size, Iterable):
        sizes = tuple(out_size)
    else:
        err_msg = f"invalid output size type: {type(out_size).__name__}"  # type: ignore[unreachable]
        raise Base58Bech32TypeError(err_msg)

    for size in sizes:
        if not is_integer(size):
            err_msg = f"invalid output size type: {type(size).__name__}"
            raise Base58Bech32TypeError(err_msg)

    size = len(octets)
    if size in sizes:
        return octets

    err_msg = f"invalid size: {size} bytes instead of {_sizes_text(sizes)}"
    raise Base58Bech32ValueError(err_msg)


def _sizes_text(sizes: tuple[int, ...]) -> str:
    """Return the sizes octets were expected to have, for a refusal's message.

    A size is the library's constant or the caller's `out_size`, and no
    field of a format, so it is written in full only where it fits four
    bytes, through `_message_field`, and described otherwise. One size
    stands alone, any other count of them in parentheses.
    """
    text = ", ".join(_message_field(size, 32, "d") for size in sizes)
    return text if len(sizes) == 1 else f"({text})"


def str_from_string(s: String, what: str) -> str:
    """Return the text of a String, whether it came as text or as ascii bytes.

    A byte outside ascii is an invalid character like any other, and gets
    a refusal of this package's rather than a `UnicodeDecodeError`. `what`
    names the string in both messages. Nothing is stripped and nothing is
    lowered: which of those is right is the caller's to know.
    """
    if isinstance(s, str):
        return s

    if not isinstance(s, (bytes, bytearray, memoryview)):
        err_msg = f"invalid {what} type: {type(s).__name__}"  # type: ignore[unreachable]
        raise Base58Bech32TypeError(err_msg)

    _assert_byte_shaped(s)

    # raised outside the `except`: the Unicode error holds the whole
    # value, and must not be left as the new error's context
    try:
        return bytes(s).decode("ascii")
    except UnicodeDecodeError as e:
        position = e.start
    raise Base58Bech32ValueError(
        f"non-ascii character in {what} at position {position}"
    )


def _message_text(value: object) -> str:
    """Return the description of a value for a refusal's message, never raising.

    No value is written out: an argument in the wrong place may be a key,
    in an int, a str of its hex, a Decimal or a float of its digits, or
    its bytes. Section 7 of the organization's standard, *A refusal carries
    no secret*, lets a refusal print a value's type name and length, and
    not its digits or characters. `_message_field` is the exception, for
    a field the format defines.

    An int, a bool excepted, is described by its sign and bit length.
    Anything else, a bool included, is described by its type name, and
    by its length where `len()` gives one: "a str of length 64", "an
    object". The article is "an" before a name whose first letter, past
    any underscore, is a vowel.

    Neither reads the value's `str()`. That of an int past
    `sys.get_int_max_str_digits()` digits, or of what is written with
    one, a Fraction for one, raises ValueError, which would leave through
    the refusal the description is for, as that error rather than this
    library's.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        return _int_description(value)
    name = type(value).__name__
    article = "an" if name.lstrip("_")[:1].lower() in tuple("aeiou") else "a"
    description = f"{article} {name}"
    # every Exception and not only TypeError: a `__len__` of the caller's
    # own can raise anything, and no failure to describe a value may
    # replace the refusal the description is for
    try:
        return f"{description} of length {len(value)}"  # type: ignore[arg-type]
    except Exception:  # noqa: BLE001
        return description


#: The most characters of a refused name that a refusal quotes.
_MAX_QUOTED_NAME_LENGTH = 16


def _name_text(value: object) -> str:
    """Return a refused name for a refusal's message, never raising.

    A string refused where a name belongs, such as an HRP or a CashAddr
    prefix, is quoted where it has at most
    `_MAX_QUOTED_NAME_LENGTH` characters: section 7 of the organization's
    standard, *A refusal carries no secret*, lets a refusal quote it
    there, too short for a key. A longer one, and what is not a str, is
    described as `_message_text` describes it.
    """
    # str's own methods, for the reason _int_description gives
    if isinstance(value, str) and str.__len__(value) <= _MAX_QUOTED_NAME_LENGTH:
        return str.__repr__(value)
    return _message_text(value)


def _message_field(value: int, bits: int, spec: str) -> str:
    """Return a field's value for a refusal's message, never raising.

    Section 7 of the organization's standard lets a refusal print a field
    its format defines, of at most four bytes, where the value has the
    length the format gives it and is one of the values the format
    defines. A field every value of whose width is defined meets the
    second condition wherever it meets the first: an int from 0 to
    `2**bits - 1` is written with `format(value, spec)`, `"#x"` for hex.
    Any other value is `_message_text`'s to write, since one wider than
    its field may be a key passed in its place. A field whose width holds
    values the format does not define is no field for this function.
    """
    # int's own methods, for the reason _int_description gives
    if is_integer(value) and not int.__lt__(value, 0) and int.bit_length(value) <= bits:
        return int.__format__(value, spec)
    return _message_text(value)


def _int_description(value: int) -> str:
    """Return an int's sign and bit length, the text standing for its digits."""
    # int's own methods, not the value's: a subclass can override the
    # comparison and bit_length as it overrode __str__
    sign = "a negative" if int.__lt__(value, 0) else "an"
    return f"{sign} int of {int.bit_length(value)} bits"


def is_integer(value: Any) -> bool:
    """Return whether the value is an integer, a bool not being one.

    `isinstance(x, int)` is True for `True` and `False`, `bool` being a
    subclass of `int`, and `true` is what a json document decodes to
    `True`. `isinstance` and not `type(value) is int`, so an `IntEnum`
    stays an integer.
    """
    return isinstance(value, int) and not isinstance(value, bool)


def assert_type(value: Any, expected: Any, what: str) -> None:
    """Refuse a value of a type the signature does not declare.

    `expected` is what `isinstance` takes: one type, or a tuple of them.
    `value` is `Any` rather than the declared type, which is what makes
    the check reachable: mypy proves the argument cannot be wrong, and
    the caller who has not run mypy is who this is for.
    """
    if not isinstance(value, expected):
        err_msg = f"invalid {what} type: {type(value).__name__}"
        raise Base58Bech32TypeError(err_msg)
