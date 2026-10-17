# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The gate for the two rules about a public function's inputs.

> Every public function guarantees the validation of all its inputs,
> directly or indirectly. A malformed argument leaves as
> `Base58Bech32TypeError` or `Base58Bech32ValueError`.

CONTRIBUTING.md's "Every public function validates its inputs" states it,
and which of the two classes comes out is not a coin toss -- it is the
distinction issue btclib-org/btclib#814 settled, so this file drives the
two separately:

- **a value of a type the signature does not declare** is the caller's
  own mistake, and leaves as a `Base58Bech32TypeError`.
- **a value of a declared type that no valid input carries** is a fact
  about the input, and leaves as a `Base58Bech32Exception`.

## How it calls what it calls

The input types are few and declared in this package: `Octets` and
`String` in `_utils.py`. `_WRONG_TYPE` and `_WRONG_VALUE` give each of
them values of the two kinds, and the walk finds every public
module-level function whose *required* parameters are all of those
types. Those it can call with no fixture and no knowledge of what the
function does.

Every argument is wrong at once, which is not weaker than one wrong
argument among valid ones: whichever the function refuses first, the rule
says how it must refuse it. And it needs no valid values, which is what
makes the walk automatic.

## What it does not reach

A **parameter with a default** is never driven: to reach it the arguments
before it would have to be valid, which is the table this design is built
to do without. `tests/bool_parameter_test.py` carries that table for the
`bool` ones.

A function taking a plain `str`, an `int` or a list of 5-bit values
needs a value the vocabulary does not build, and is driven by the tests
of its own module. `test_the_walk_reaches_what_it_claims` pins what the
walk does find, so a narrowing of it fails here rather than quietly
running over less.
"""

from __future__ import annotations

import ast
import importlib
from collections.abc import Callable, Iterator
from functools import partial
from pathlib import Path
from typing import Any

import pytest

from base58_bech32.exceptions import (
    Base58Bech32Exception,
    Base58Bech32TypeError,
)

_LIBRARY = Path(__file__).parents[1] / "src" / "base58_bech32"

# a value of no type the alias declares: the caller's own mistake, and a
# call mypy refuses. The tuples are read round-robin so that a function
# taking three parameters of one type is called with three different
# wrong values. Constants and not a strategy: what this gate reports has
# to be the same on two runs, the lists below being read as statements
# about the tree
_WRONG_TYPE: dict[str, tuple[Any, ...]] = {
    "Octets": (None, 1.5, tuple(range(4))),
    "String": (None, 1.5, tuple(range(4))),
}

# a value of a declared type that no valid input carries: a fact about
# the input. Every one of these type checks -- that is what puts it in
# this dict rather than in the one above -- so a `# type: ignore` is never
# needed to build the call, which is the same line drawn twice
_WRONG_VALUE: dict[str, tuple[Any, ...]] = {
    # a hex string that is not hex, and one of odd length
    "Octets": ("not hex at all", "9"),
    # a NUL, no character of any of the alphabets, and a byte outside ascii
    "String": ("\x00", b"\xff"),
}


def _alias_of(annotation: ast.expr) -> str | None:
    """Return the input type an annotation names, `X | None` included."""
    name = ast.unparse(annotation).replace(" | None", "").strip()
    return name if name in _WRONG_TYPE else None


def _drivable() -> dict[str, list[str]]:
    """Return every public function the vocabulary can call, by dotted name.

    Required parameters only: what carries a default is what a caller may
    leave out, so a function is driven on the arguments it insists on.
    All of them have to be in the vocabulary -- one `str` and the walk has
    nothing to pass.
    """
    found: dict[str, list[str]] = {}
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        for node in ast.parse(path.read_text(encoding="utf-8")).body:
            if not isinstance(node, ast.FunctionDef) or node.name.startswith("_"):
                continue
            positional = [*node.args.posonlyargs, *node.args.args]
            required = positional[: len(positional) - len(node.args.defaults)]
            # `is not None` narrows for mypy and never filters: mypy runs
            # strict over this package, so a parameter without an
            # annotation is a state the library does not reach
            annotations = [a.annotation for a in required if a.annotation is not None]
            aliases = [_alias_of(a) for a in annotations]
            if required and len(aliases) == len(required) and all(aliases):
                found[f"{module}.{node.name}"] = [a for a in aliases if a]
    return found


_DRIVABLE = _drivable()


def _calls(
    dotted: str, vocabulary: dict[str, tuple[Any, ...]]
) -> Iterator[Callable[[], Any]]:
    """Yield one prepared call per round, every argument wrong at once.

    The vocabulary is the parameter, and it is the whole of what tells the
    two rules apart: the same walk, the same function, two kinds of wrong
    value.
    """
    module_name, _, name = dotted.rpartition(".")
    function = getattr(importlib.import_module(module_name), name)
    aliases = _DRIVABLE[dotted]
    for round_ in range(max(len(vocabulary[a]) for a in aliases)):
        args = [vocabulary[a][round_ % len(vocabulary[a])] for a in aliases]
        # partial and not a lambda, which would close over the loop
        # variables and be read on a later round
        yield partial(function, *args)


_DRIVEN = sorted(_DRIVABLE)


@pytest.mark.parametrize("dotted", _DRIVEN)
def test_a_wrong_type_leaves_as_a_type_error_of_the_package(dotted: str) -> None:
    """The first rule, and it has no exceptions.

    `Base58Bech32TypeError` and not the base: this is where the class is
    the point. A bare `TypeError` fails here as a `Base58Bech32ValueError`
    does -- the first is a leak from underneath the package, the second
    is the package calling a caller's mistake a fact about the input.
    """
    for call in _calls(dotted, _WRONG_TYPE):
        with pytest.raises(Base58Bech32TypeError):
            call()


@pytest.mark.parametrize("dotted", _DRIVEN)
def test_a_wrong_value_leaves_as_an_exception_of_the_package(dotted: str) -> None:
    """The second rule, over what the walk drives.

    The base and not one of the two: which of them a malformed value
    deserves is the function's to decide, and the contract a caller is
    given is the base.
    """
    for call in _calls(dotted, _WRONG_VALUE):
        with pytest.raises(Base58Bech32Exception):
            call()


def test_the_vocabulary_is_the_packages_input_types() -> None:
    """A renamed type would narrow the walk without failing anything.

    Every name in the two vocabularies is declared at module level in
    this package, and every type the package declares and a public
    parameter is annotated with is in the vocabulary.
    """
    declared: set[str] = set()
    annotated: set[str] = set()
    for path in sorted(_LIBRARY.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        declared |= {
            node.targets[0].id
            for node in tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id[0].isupper()
        }
        annotated |= {
            ast.unparse(a.annotation).replace(" | None", "").strip()
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and not node.name.startswith("_")
            for a in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            if a.annotation is not None
        }

    assert set(_WRONG_TYPE) == set(_WRONG_VALUE)
    assert set(_WRONG_TYPE) <= declared
    assert declared & annotated <= set(_WRONG_TYPE)


def test_the_walk_reaches_what_it_claims() -> None:
    """The shapes the walk must find, and two it must not.

    A walk that found nothing would pass every test above. One function
    per shape it has to reach -- either type, and one behind a keyword it
    must ignore -- and the two kinds it must leave alone: a private name,
    and a function whose required parameters are not all in the
    vocabulary.
    """
    assert _DRIVABLE["base58_bech32.base58.b58encode"] == ["Octets"]
    assert _DRIVABLE["base58_bech32.cashaddr.cashaddr_decode"] == ["String"]
    # `out_size`, `alphabet` and `secret` are keywords and are not driven
    assert _DRIVABLE["base58_bech32.base58.b58decode_check"] == ["String"]

    # a private name, whatever its parameters
    assert "base58_bech32.base58._ascii_bytes" not in _DRIVABLE
    # a required parameter the vocabulary does not build: the prefix
    assert "base58_bech32.ss58.ss58_encode" not in _DRIVABLE
