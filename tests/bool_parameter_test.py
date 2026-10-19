# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every `bool` parameter of the package, held to refusing a non-bool.

A flag written down and read back -- json, a configuration file, a
coordinator's message -- arrives as whatever it was written as (issue
btclib-org/btclib#868). Most wrong values are true: `"no"`, a non-zero
number, an object. But `0`, `None` and `""` read as false, so a flag
read for its truth can be misread as on or as off. Every flag here
therefore refuses anything but a `bool` with a `Base58Bech32TypeError`.

`_bool_parameters` reads every public function of the package and every
`bool`-annotated parameter of one, so a flag added anywhere is in the
table here or the run is red.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from base58_bech32.bech32 import convertbits
from base58_bech32.exceptions import Base58Bech32TypeError

_LIBRARY = Path(__file__).parents[1] / "src" / "base58_bech32"

# a value of no bool type: a truthy string, the two integers `bool`
# inherits from, and the wrong values that read as false. Every one of
# them is a call mypy refuses
_WRONG_TYPES: tuple[Any, ...] = ("no", 0, 1, None, "", 1.0)


@dataclass(frozen=True)
class _Case:
    """One `bool` parameter, and a call of its function that works."""

    dotted: str
    flag: str
    function: Any
    # every argument but the flag, by keyword
    args: dict[str, Any] = field(default_factory=dict)


_FLAGS = (
    _Case(
        "base58_bech32.bech32.convertbits",
        "pad",
        convertbits,
        {"data": [0], "from_bits": 8, "to_bits": 5},
    ),
)

_IDS = tuple(f"{case.dotted}({case.flag})" for case in _FLAGS)


def _flags_of(function: ast.FunctionDef) -> set[str]:
    """Return the `bool`-annotated parameters of one public function."""
    if function.name.startswith("_") and not function.name.startswith("__"):
        return set()
    arguments = [
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ]
    return {
        argument.arg
        for argument in arguments
        if argument.annotation is not None
        and ast.unparse(argument.annotation) in {"bool", "bool | None"}
    }


def _bool_parameters() -> set[tuple[str, str]]:
    """Return every (function, `bool` parameter) pair of the public API.

    Keyed on the annotation, `bool` and `bool | None`: what a flag is
    called says nothing. A method counts and a private function does not,
    and a function nested in another is a closure rather than API.
    """
    found: set[tuple[str, str]] = set()

    def walk(node: ast.Module | ast.ClassDef, module: str, prefix: str) -> None:
        for child in node.body:
            if isinstance(child, ast.ClassDef):
                walk(child, module, f"{prefix}{child.name}.")
            elif isinstance(child, ast.FunctionDef):
                dotted = f"{module}.{prefix}{child.name}"
                found.update((dotted, flag) for flag in _flags_of(child))

    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        walk(ast.parse(path.read_text(encoding="utf-8")), module, "")
    return found


@pytest.mark.parametrize("case", _FLAGS, ids=_IDS)
def test_the_call_works(case: _Case) -> None:
    """True and False are accepted, which makes a refusal below a finding.

    Without this a case whose arguments had gone stale would pass every
    test in the file by refusing everything it is handed.
    """
    for value in (True, False):
        case.function(**case.args, **{case.flag: value})


@pytest.mark.parametrize("case", _FLAGS, ids=_IDS)
def test_a_flag_refuses_a_non_bool(case: _Case) -> None:
    """A flag is not read for its truth.

    `"no"` is true, so the flag would be on; `0`, `None` and `""` are
    false, so it would be off; `0` and `1` are the two `bool` inherits
    from, which is what makes `isinstance(value, int)` no check at all.
    """
    for value in _WRONG_TYPES:
        with pytest.raises(Base58Bech32TypeError, match=f"invalid {case.flag} type"):
            case.function(**case.args, **{case.flag: value})


def test_every_bool_parameter_is_in_the_table() -> None:
    """A parameter added anywhere under `src/base58_bech32/` fails here."""
    listed = {(case.dotted, case.flag) for case in _FLAGS}
    found = _bool_parameters()
    assert listed == found, (
        f"unlisted: {sorted(found - listed)};"
        f" gone from the tree: {sorted(listed - found)}"
    )


def test_the_walk_reaches_what_it_claims() -> None:
    """The shapes it must find, and the ones it must not.

    A walk that found nothing would pass the test above.
    """
    found = _bool_parameters()
    # a positional flag
    assert ("base58_bech32.bech32.convertbits", "pad") in found

    # a private function, and a parameter of another type
    assert ("base58_bech32.bech32._convertbits", "pad") not in found
    assert ("base58_bech32.base58.b58decode_check", "out_size") not in found

    # each kind of parameter, the tree's flags being of one kind:
    # positional-only, positional, keyword-only, and an optional flag
    source = "def f(a: bool, /, b: bool, *, c: bool, d: bool | None, e: int): ..."
    function = ast.parse(source).body[0]
    assert isinstance(function, ast.FunctionDef)
    assert _flags_of(function) == {"a", "b", "c", "d"}
