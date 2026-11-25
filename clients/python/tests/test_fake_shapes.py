"""Every test fake of a Session, a Workspace or a checkpoint store against the real class: what kind each
member is (a value: an attribute or a property; or a method), and for a method whether it
is a coroutine and what it takes. A fake that models a property as a method passes its
suite and fails a real run: the released OpenAI Agents adapter could not start an agent
because its fake had ``Session.ended`` as a method (fixed in d4a8ad222, 2026-11-17; item 1
of the review of the unread half, 2026-11-18).

The fakes are parsed, never imported, so this runs with the core tests and no framework
installed. Members a fake keeps for its tests alone are listed in TEST_ONLY with why.
"""

from __future__ import annotations

import ast
import inspect
import os
import textwrap
import unittest
from typing import Dict, List, Optional, Tuple

from plimsoll_client.checkpoint import MemoryCheckpointStore
from plimsoll_client.client import Client, Session
from plimsoll_client.workspace import Workspace

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # clients/python

# (file under clients/python, class, the real class it stands in for)
FAKES: List[Tuple[str, str, type]] = [
    ("frameworks/adk/test_adk_environment.py", "FakeSession", Session),
    ("frameworks/agent_framework/test_agent_framework.py", "FakeSession", Session),
    ("frameworks/deepagents/test_deepagents.py", "FakeSession", Session),
    ("frameworks/deepagents/test_deepagents.py", "FakeWorkspace", Workspace),
    ("frameworks/deepagents/test_deepagents.py", "FakeAttachClient", Client),
    ("frameworks/openai_agents/_fake.py", "FakeSession", Session),
    ("frameworks/openai_agents/_fake.py", "FakeWorkspace", Workspace),
    ("frameworks/smolagents/test_smolagents.py", "FakeSession", Session),
    # PydanticAI's suite checks this fake itself, at run time, for the members the backend uses
    # (frameworks/pydantic_ai/_fake.py shape_differences); this check reads every public member, with no framework
    # installed.
    ("frameworks/pydantic_ai/_fake.py", "FakeSession", Session),
    ("frameworks/anthropic/test_anthropic_worker.py", "FakeWorkspace", Workspace),
    ("tests/test_workspace.py", "FakeSession", Session),
    ("tests/test_workspace.py", "ShellSession", Session),
    # The checkpoint store fakes of the reattach suite, against the store the client ships.
    ("tests/test_reattach.py", "FakeInterleavingStore", MemoryCheckpointStore),
    ("tests/test_reattach.py", "FakeFailingStore", MemoryCheckpointStore),
    ("tests/test_reattach.py", "FakeHoldingStore", MemoryCheckpointStore),
    ("tests/test_reattach.py", "FakeBeforeReadyStore", MemoryCheckpointStore),
    ("tests/docker_reattach_check.py", "FakeFileCheckpointStore", MemoryCheckpointStore),
    # The verifiers suite's session is named for the sandbox it stands in for, and the clients the suites open
    # their sessions from: a Client's members a fake defines (its own, or its overrides of a real Client's) take
    # what the real ones take (step T3 of the v0.28.0 plan, 2026-11-21: none was checked until then).
    ("frameworks/verifiers/test_verifiers_runtime.py", "FakeSandbox", Session),
    ("frameworks/verifiers/test_verifiers_runtime.py", "FakeClient", Client),
    ("frameworks/adk/test_adk_environment.py", "FakeClient", Client),
    ("frameworks/smolagents/test_smolagents.py", "FakeClient", Client),
    ("frameworks/pydantic_ai/_fake.py", "FakeClient", Client),
    ("frameworks/agent_framework/test_agent_framework.py", "FakeClient", Client),
]

# A fake's members with no counterpart in the real class, each with why it may have one:
# (file, class, member) -> reason.
TEST_ONLY: Dict[Tuple[str, str, str], str] = {
    ("frameworks/adk/test_adk_environment.py", "FakeSession", "runs"): "a test helper: the calls of one kind it was handed",
    ("frameworks/adk/test_adk_environment.py", "FakeSession", "commands"): "a test helper: the commands it was handed",
    ("tests/test_workspace.py", "FakeSession", "last"): "a test helper: the last call it was handed",
    # The PydanticAI suite's own list of these (test_pydantic_ai.py, ShapeTests.TEST_ONLY), which its check also
    # requires the real Session to lack.
    ("frameworks/pydantic_ai/_fake.py", "FakeSession", "answer"): "a test helper: answers one fixed step",
    ("frameworks/pydantic_ai/_fake.py", "FakeSession", "end"): "a test helper: ends the session as the daemon would",
    ("frameworks/pydantic_ai/_fake.py", "FakeSession", "result"): "a test helper: builds one project result",
    ("frameworks/pydantic_ai/_fake.py", "FakeSession", "script"): "a test helper: answers one of the backend's fixed scripts",
    ("frameworks/verifiers/test_verifiers_runtime.py", "FakeClient", "next"): "a test helper: the sandboxes the next opens answer",
    ("frameworks/verifiers/test_verifiers_runtime.py", "FakeClient", "opened"): "a test helper: each open's sandbox and options",
    ("frameworks/verifiers/test_verifiers_runtime.py", "FakeClient", "sessions"): "a test helper: whether describe() offers sessions",
    ("frameworks/adk/test_adk_environment.py", "FakeClient", "session"): "a test helper: the last session it opened",
    ("frameworks/smolagents/test_smolagents.py", "FakeClient", "session"): "a test helper: the last session it opened",
    ("frameworks/pydantic_ai/_fake.py", "FakeClient", "session"): "a test helper: the last session it opened",
    ("frameworks/agent_framework/test_agent_framework.py", "FakeClient", "session"): "a test helper: the last session it opened",
}

VALUE, METHOD = "a value (attribute or property)", "a method"


def _real_members(cls: type) -> Dict[str, Tuple[str, Optional[inspect.Signature], bool]]:
    """name -> (kind, signature of a method, coroutine): the class's public attributes,
    properties and methods, and the public attributes its __init__ sets."""
    out: Dict[str, Tuple[str, Optional[inspect.Signature], bool]] = {}
    for name in dir(cls):
        if name.startswith("_"):
            continue
        raw = inspect.getattr_static(cls, name)
        if isinstance(raw, property):
            out[name] = (VALUE, None, False)
        elif isinstance(raw, (staticmethod, classmethod)):
            fn = raw.__func__
            out[name] = (METHOD, inspect.signature(fn), inspect.iscoroutinefunction(fn))
        elif inspect.isfunction(raw):
            out[name] = (METHOD, inspect.signature(raw), inspect.iscoroutinefunction(raw))
        else:
            out[name] = (VALUE, None, False)
    init = ast.parse(textwrap.dedent(inspect.getsource(cls.__init__)))
    for node in ast.walk(init):
        for target in _targets(node):
            if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self" \
                    and not target.attr.startswith("_"):
                out.setdefault(target.attr, (VALUE, None, False))
    return out


def _targets(node: ast.AST) -> List[ast.expr]:
    if isinstance(node, ast.Assign):
        return list(node.targets)
    if isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        return [node.target]
    return []


class _FakeMember:
    def __init__(self, kind: str, fn: Optional[ast.AST] = None, alias: Optional[str] = None) -> None:
        self.kind, self.fn, self.alias = kind, fn, alias


def _fake_members(path: str, name: str, src: Optional[str] = None) -> Dict[str, _FakeMember]:
    if src is None:
        with open(os.path.join(HERE, path), encoding="utf-8") as f:
            src = f.read()
    tree = ast.parse(src, filename=path)
    cls = next((n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == name), None)
    if cls is None:
        raise AssertionError(f"{path} has no class {name}: update FAKES")
    out: Dict[str, _FakeMember] = {}
    for node in cls.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            decorators = {d.id for d in node.decorator_list if isinstance(d, ast.Name)} | \
                {d.attr for d in node.decorator_list if isinstance(d, ast.Attribute)}
            if "property" in decorators or "setter" in decorators:
                out.setdefault(node.name, _FakeMember(VALUE))
            else:
                out[node.name] = _FakeMember(METHOD, node)
            if node.name == "__init__":
                for sub in ast.walk(node):
                    for target in _targets(sub):
                        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
                            out.setdefault(target.attr, _FakeMember("instance"))
        for target in _targets(node):
            if isinstance(target, ast.Name):
                value = node.value if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
                # `read_whole = Workspace.read_whole`: the real member itself.
                if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name) and value.value.id in ("Workspace", "Session"):
                    out[target.id] = _FakeMember(METHOD, alias=value.attr)
                else:
                    out[target.id] = _FakeMember(VALUE)
    return out


def _params(fn: ast.AST) -> Tuple[List[str], List[str], bool, bool]:
    """(positional names after self, keyword-only names, *args, **kwargs) of a def."""
    a = fn.args  # type: ignore[attr-defined]
    positional = [p.arg for p in a.posonlyargs + a.args]
    if positional and positional[0] in ("self", "cls"):
        positional = positional[1:]
    return positional, [p.arg for p in a.kwonlyargs], a.vararg is not None, a.kwarg is not None


def _shape_problems(path: str, name: str, real: type, src: Optional[str] = None) -> List[str]:
    problems: List[str] = []
    real_members = _real_members(real)
    for member, fake in sorted(_fake_members(path, name, src).items()):
        if member.startswith("_"):
            continue
        where = f"{path} {name}.{member}"
        if member not in real_members:
            if fake.kind != "instance" and (path, name, member) not in TEST_ONLY:
                problems.append(f"{where}: {real.__name__} has no {member}; list it in TEST_ONLY with why, or remove it")
            continue
        kind, sig, coroutine = real_members[member]
        fake_kind = VALUE if fake.kind == "instance" else fake.kind
        if fake_kind != kind:
            problems.append(f"{where} is {fake_kind}, {real.__name__}.{member} is {kind}")
            continue
        if fake.alias is not None:
            if fake.alias != member:
                problems.append(f"{where} is {real.__name__}.{fake.alias}, another member")
            continue
        if kind != METHOD or fake.fn is None or sig is None:
            continue
        if isinstance(fake.fn, ast.AsyncFunctionDef) != coroutine:
            problems.append(f"{where}: {'a coroutine' if not coroutine else 'not a coroutine'} in the fake, "
                            f"{'one' if coroutine else 'not one'} in {real.__name__}")
        positional, keyword_only, varargs, varkw = _params(fake.fn)
        real_params = [p for p in sig.parameters.values() if p.name not in ("self", "cls")]
        real_positional = [p.name for p in real_params if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
        real_names = {p.name for p in real_params if p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)}
        real_varkw = any(p.kind == p.VAR_KEYWORD for p in real_params)
        for i, p in enumerate(positional):
            if i >= len(real_positional) or real_positional[i] != p:
                if p in real_names:
                    problems.append(f"{where}: takes {p} by position {i + 1}, {real.__name__}.{member} takes it by keyword only")
                elif not real_varkw:
                    problems.append(f"{where}: takes {p}, which {real.__name__}.{member} does not")
        for p in keyword_only:
            if p not in real_names and not real_varkw:
                problems.append(f"{where}: takes the keyword {p}, which {real.__name__}.{member} does not")
        # A required argument of the real method the fake cannot take: a call written for
        # the real one would fail on the fake, so a suite could not have exercised it.
        if not varkw:
            fake_names = set(positional) | set(keyword_only)
            for p in real_params:
                if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD) or p.default is not p.empty:
                    continue
                if p.name not in fake_names and not (varargs and p.kind != p.KEYWORD_ONLY):
                    problems.append(f"{where}: cannot take {p.name}, which {real.__name__}.{member} requires")
    return problems


class FakeShapeTests(unittest.TestCase):
    def test_every_fake_has_the_shape_of_the_class_it_stands_in_for(self) -> None:
        problems: List[str] = []
        for path, name, real in FAKES:
            problems += _shape_problems(path, name, real)
        self.assertEqual(problems, [], "\n" + "\n".join(problems))

    def test_every_fake_of_a_session_or_workspace_is_listed(self) -> None:
        # A new fake joins FAKES: any class named Fake...Session, Fake...Workspace,
        # Fake...Store (a checkpoint store), Fake...Sandbox or Fake...Client, or a session run on
        # a shell, in a suite.
        listed = {(p, n) for p, n, _ in FAKES}
        found = set()
        for root in ("frameworks", "tests"):
            for dirpath, _, files in os.walk(os.path.join(HERE, root)):
                for f in files:
                    if not f.endswith(".py"):
                        continue
                    rel = os.path.relpath(os.path.join(dirpath, f), HERE).replace(os.sep, "/")
                    with open(os.path.join(dirpath, f), encoding="utf-8") as fh:
                        tree = ast.parse(fh.read(), filename=rel)
                    for node in tree.body:
                        if isinstance(node, ast.ClassDef) and node.name.endswith(("Session", "Workspace", "Store", "Sandbox", "Client")) and \
                                (node.name.startswith("Fake") or node.name == "ShellSession"):
                            found.add((rel, node.name))
                        elif isinstance(node, ast.ClassDef) and (rel, node.name) in listed:
                            found.add((rel, node.name))  # a fake of another class, listed by hand (a Client's)
        self.assertEqual(sorted(found - listed), [], "fakes not in FAKES")
        self.assertEqual(sorted(listed - found), [], "FAKES entries with no such class")
        for key in TEST_ONLY:
            self.assertIn((key[0], key[1]), listed, f"TEST_ONLY names a fake not in FAKES: {key}")

    def test_the_check_finds_a_property_modeled_as_a_method(self) -> None:
        # The openai bug, put back on a copy of its fake: `ended` as a method.
        src = "class FakeSession:\n    def ended(self):\n        return None\n    def close(self):\n        pass\n"
        problems = _shape_problems("probe.py", "FakeSession", Session, src)
        self.assertTrue(any("ended is a method, Session.ended is a value" in p for p in problems), problems)
        # A keyword the real method does not take, and a coroutine where it is not one.
        src = "class FakeWorkspace:\n    async def read(self, path, *, max_bytes=1, offset=0, cancel=None, follow=False):\n        return b''\n"
        problems = _shape_problems("probe.py", "FakeWorkspace", Workspace, src)
        self.assertTrue(any("a coroutine in the fake" in p for p in problems), problems)
        self.assertTrue(any("takes the keyword follow" in p for p in problems), problems)


if __name__ == "__main__":
    unittest.main()
