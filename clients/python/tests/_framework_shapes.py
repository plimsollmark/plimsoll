"""Every member an adapter defines over a framework's own class, against that class at the
version the suite installs: what kind it is (a property, a method, a plain attribute),
whether it is a coroutine, and whether it takes every call the framework's member takes.

A framework calls an adapter's override the way its own member is declared, and a suite
that calls the override itself, the way the override is written, cannot see the two
differ. The same goes for a class the framework uses through a Protocol it does not
inherit (a duck-typed backend or executor): the protocol's members are compared the same
way, and one the class lacks is reported. Each framework suite runs :func:`problems` over
its adapter module (step T3 of the v0.28.0 plan, 2026-11-21: the public OpenAI Agents
adapter shipped unable to start an agent because a stand-in modeled a property as a method,
and every test passed).

Compatible is read as a caller would: the override takes every argument the framework's
member takes, by the same position or keyword (a ``*args`` or ``**kwargs`` of the override
takes what it can), and requires nothing the framework's member does not offer (a member of
``*args, **kwargs`` offers anything). An extra argument with a default is allowed.
"""

from __future__ import annotations

import inspect
from types import ModuleType
from typing import Any, Iterable, List, Optional, Sequence, Tuple

# Bases whose members are not a framework's: Python's, typing's and pydantic's model
# machinery, and plimsoll's own.
_NOT_FRAMEWORK = ("builtins", "typing", "abc", "plimsoll_client", "pydantic.main", "pydantic._internal", "collections.abc")

# Dunder members a framework calls by protocol; every other dunder is Python's business.
_CALLED_DUNDERS = ("__call__", "__aenter__", "__aexit__", "__enter__", "__exit__", "__aiter__", "__anext__", "__iter__", "__next__")


def _kind(raw: Any) -> str:
    if isinstance(raw, property):
        return "a property"
    if isinstance(raw, staticmethod):
        return "a staticmethod"
    if isinstance(raw, classmethod):
        return "a classmethod"
    if inspect.isfunction(raw):
        return "a method"
    return "an attribute"


def _function(raw: Any) -> Any:
    if isinstance(raw, property):
        return raw.fget
    if isinstance(raw, (staticmethod, classmethod)):
        return raw.__func__
    return raw


def _is_coroutine(fn: Any) -> bool:
    return inspect.iscoroutinefunction(fn) or inspect.isasyncgenfunction(fn)


def _signature(fn: Any) -> Optional[inspect.Signature]:
    try:
        return inspect.signature(fn)
    except (TypeError, ValueError):
        return None


def _call_problems(mine: inspect.Signature, theirs: inspect.Signature) -> List[str]:
    """Where a call the framework's member takes would fail on the override, or the
    override needs an argument no such call gives."""
    P = inspect.Parameter
    ours = list(mine.parameters.values())
    base = list(theirs.parameters.values())
    our_positional = [p.name for p in ours if p.kind in (P.POSITIONAL_ONLY, P.POSITIONAL_OR_KEYWORD)]
    our_keywords = {p.name for p in ours if p.kind in (P.POSITIONAL_OR_KEYWORD, P.KEYWORD_ONLY)}
    our_args = any(p.kind == P.VAR_POSITIONAL for p in ours)
    our_kwargs = any(p.kind == P.VAR_KEYWORD for p in ours)
    base_positional = [p for p in base if p.kind in (P.POSITIONAL_ONLY, P.POSITIONAL_OR_KEYWORD)]
    out: List[str] = []
    for i, p in enumerate(base_positional):
        if i < len(our_positional):
            if our_positional[i] != p.name and p.name in our_keywords:
                out.append(f"takes {our_positional[i]} at position {i + 1}, where the framework's member takes {p.name}")
        elif not our_args:
            out.append(f"cannot take {p.name} by position {i + 1}, as the framework's member can")
        if p.kind == P.POSITIONAL_OR_KEYWORD and p.name not in our_keywords and not our_kwargs:
            out.append(f"cannot take {p.name} by keyword, as the framework's member can")
    for p in base:
        if p.kind == P.KEYWORD_ONLY and p.name not in our_keywords and not our_kwargs:
            out.append(f"cannot take the keyword {p.name}, which the framework's member takes")
    base_names = {p.name for p in base if p.kind not in (P.VAR_POSITIONAL, P.VAR_KEYWORD)}
    base_open = any(p.kind in (P.VAR_POSITIONAL, P.VAR_KEYWORD) for p in base)
    for p in ours:
        if p.kind in (P.VAR_POSITIONAL, P.VAR_KEYWORD) or p.default is not P.empty or p.name in base_names or base_open:
            continue
        if p.kind != P.KEYWORD_ONLY and our_positional.index(p.name) < len(base_positional):
            continue  # filled by the framework's positional argument there
        out.append(f"requires {p.name}, which the framework's member never gives")
    return out


def compare(owner: str, name: str, mine: Any, theirs: Any, against: str) -> List[str]:
    """The ways ``mine`` (a raw class member) differs from ``theirs``, the framework's."""
    where = f"{owner}.{name} (against {against})"
    if _kind(mine) != _kind(theirs):
        return [f"{where} is {_kind(mine)}, the framework's is {_kind(theirs)}"]
    fm, ft = _function(mine), _function(theirs)
    if not (callable(fm) and callable(ft)):
        return []
    out: List[str] = []
    if _is_coroutine(fm) != _is_coroutine(ft):
        out.append(f"{where} is {'' if _is_coroutine(fm) else 'not '}a coroutine, the framework's is {'' if _is_coroutine(ft) else 'not '}one")
    if name == "__init__":
        return out
    sm, st = _signature(fm), _signature(ft)
    if sm is not None and st is not None:
        out += [f"{where} {p}" for p in _call_problems(sm, st)]
    return out


def _members(cls: type) -> Iterable[Tuple[str, Any]]:
    for name, raw in vars(cls).items():
        if name.startswith("__") and name not in _CALLED_DUNDERS:
            continue
        yield name, raw


def problems(module: ModuleType, protocols: Sequence[Tuple[type, type]] = ()) -> List[str]:
    """Every difference between a class of ``module`` and a framework class it inherits from,
    for each member both define; and, for each (class, protocol) pair, between the class and
    each member the protocol declares."""
    out: List[str] = []
    for cls in vars(module).values():
        if not inspect.isclass(cls) or cls.__module__ != module.__name__:
            continue
        for base in cls.__mro__[1:]:
            if base is object or base.__module__.startswith(_NOT_FRAMEWORK):
                continue
            against = f"{base.__module__}.{base.__qualname__}"
            for name, mine in _members(cls):
                if name in vars(base):
                    out += compare(cls.__name__, name, mine, vars(base)[name], against)
    for cls, protocol in protocols:
        against = f"{protocol.__module__}.{protocol.__qualname__}"
        declared = [n for n, _ in _members(protocol) if not n.startswith("_") or n in _CALLED_DUNDERS]
        for name in declared:
            mine = inspect.getattr_static(cls, name, None)
            if mine is None:
                out.append(f"{cls.__name__} has no {name}, which {against} declares")
                continue
            out += compare(cls.__name__, name, mine, inspect.getattr_static(protocol, name), against)
    return out


def _real_member(real: type, name: str) -> Any:
    raw = inspect.getattr_static(real, name, None)
    if raw is not None:
        return raw
    fields = getattr(real, "model_fields", None) or getattr(real, "__dataclass_fields__", None) or {}
    if name in fields or any(name in getattr(c, "__annotations__", {}) for c in real.__mro__):
        return _FIELD
    return None


#: A declared field (pydantic, a dataclass, an annotation): read as a plain attribute.
_FIELD = object()


def fake_problems(fake: type, real: type, test_only: Sequence[str] = ()) -> List[str]:
    """Every difference between a test's stand-in for a framework object and the real class:
    each public member the stand-in defines must be one the real class has, of the same kind,
    taking every call the real one takes. ``test_only`` names the stand-in's own helpers."""
    out: List[str] = []
    against = f"{real.__module__}.{real.__qualname__}"
    for name, mine in _members(fake):
        if name.startswith("_") and name not in _CALLED_DUNDERS:
            continue
        theirs = _real_member(real, name)
        if theirs is None:
            if name not in test_only:
                out.append(f"{fake.__name__}.{name}: {against} has no {name}")
            continue
        if theirs is _FIELD:
            if _kind(mine) not in ("an attribute", "a property"):
                out.append(f"{fake.__name__}.{name} (against {against}) is {_kind(mine)}, the framework's is a field")
            continue
        out += compare(fake.__name__, name, mine, theirs, against)
    return out
