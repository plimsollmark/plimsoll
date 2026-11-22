"""The framework shape check (tests/_framework_shapes.py) against classes made to differ, so
a clean answer from it in a framework suite means something: each way an override can
fail a framework's call is reported, and each way it may safely differ is not. No framework
is installed for these; the suites run the check over the real ones."""

from __future__ import annotations

import types
import unittest
from typing import Any, List, Protocol

from tests._framework_shapes import fake_problems, problems


class Framework:
    """A framework's own class, as an adapter subclasses one."""

    @property
    def ended(self) -> bool:
        return False

    async def run(self, command: str, *, timeout: float = 0.0) -> str:
        return command

    def read(self, path: str, offset: int = 0) -> bytes:
        return b""

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        return None

    async def _annotate(self, *, op: str, ok: Any = None, outputs: Any = None) -> Any:
        return None


class Executor(Protocol):
    async def start(self) -> None: ...

    async def run(self, command: str, *, timeout: float = 0.0) -> str: ...


def adapter(*classes: type) -> types.ModuleType:
    module = types.ModuleType("probe_adapter")
    for cls in classes:
        cls.__module__ = module.__name__
        setattr(module, cls.__name__, cls)
    return module


def found(*classes: type, protocols: Any = ()) -> List[str]:
    return problems(adapter(*classes), protocols)


class Reported(unittest.TestCase):
    def test_a_property_modeled_as_a_method(self) -> None:
        class Adapter(Framework):
            def ended(self) -> bool:  # type: ignore[override]
                return False

        self.assertEqual(found(Adapter), [f"Adapter.ended (against {__name__}.Framework) is a method, the framework's is a property"])

    def test_a_coroutine_where_the_framework_calls_a_function(self) -> None:
        class Adapter(Framework):
            async def read(self, path: str, offset: int = 0) -> bytes:  # type: ignore[override]
                return b""

        self.assertIn("is a coroutine, the framework's is not one", found(Adapter)[0])

    def test_a_function_where_the_framework_awaits(self) -> None:
        class Adapter(Framework):
            def run(self, command: str, *, timeout: float = 0.0) -> str:  # type: ignore[override]
                return command

        self.assertIn("is not a coroutine, the framework's is one", found(Adapter)[0])

    def test_a_keyword_the_framework_passes_is_not_taken(self) -> None:
        class Adapter(Framework):
            async def run(self, command: str) -> str:  # type: ignore[override]
                return command

        self.assertEqual(found(Adapter), [f"Adapter.run (against {__name__}.Framework) cannot take the keyword timeout, which the framework's member takes"])

    def test_an_argument_the_framework_never_gives_is_required(self) -> None:
        class Adapter(Framework):
            async def run(self, command: str, *, timeout: float = 0.0, ctx: Any) -> str:  # type: ignore[override]
                return command

        self.assertEqual(found(Adapter), [f"Adapter.run (against {__name__}.Framework) requires ctx, which the framework's member never gives"])

    def test_arguments_in_another_order(self) -> None:
        class Adapter(Framework):
            def read(self, offset: int = 0, path: str = "") -> bytes:  # type: ignore[override]
                return b""

        got = found(Adapter)
        self.assertIn("takes offset at position 2, where the framework's member takes path", got[0])

    def test_a_positional_argument_with_no_place(self) -> None:
        class Adapter(Framework):
            def read(self, path: str, *, offset: int = 0) -> bytes:  # type: ignore[override]
                return b""

        self.assertEqual(found(Adapter), [f"Adapter.read (against {__name__}.Framework) cannot take offset by position 3, as the framework's member can"])

    def test_a_protocol_member_missing_or_unlike(self) -> None:
        class Tool:
            def run(self, command: str, *, timeout: float = 0.0) -> str:
                return command

        got = found(Tool, protocols=[(Tool, Executor)])
        self.assertEqual(sorted(got), sorted([
            f"Tool has no start, which {__name__}.Executor declares",
            f"Tool.run (against {__name__}.Executor) is not a coroutine, the framework's is one",
        ]))


class Allowed(unittest.TestCase):
    def test_what_an_adapter_may_do(self) -> None:
        class Adapter(Framework):
            @property
            def ended(self) -> bool:
                return True

            # An extra keyword with a default (ADK's ctx).
            async def run(self, command: str, *, timeout: float = 0.0, ctx: Any = None) -> str:
                return command

            # Named parameters over the framework's *args, **kwargs (LangChain's and CrewAI's _run).
            def _run(self, code: str, language: str = "python") -> Any:
                return code

            # **kwargs taking keywords it does not name (the OpenAI Agents session's _annotate).
            async def _annotate(self, *, op: str, **kwargs: Any) -> Any:
                return None

        class Pass(Framework):
            # *args, **kwargs taking anything (smolagents' run).
            def read(self, *args: Any, **kwargs: Any) -> bytes:  # type: ignore[override]
                return b""

        class Tool:
            async def start(self) -> None:
                return None

            async def run(self, command: str, *, timeout: float = 0.0) -> str:
                return command

        self.assertEqual(found(Adapter, Pass, Tool, protocols=[(Tool, Executor)]), [])


class StandIns(unittest.TestCase):
    """fake_problems: a test's stand-in for a framework object against the real class."""

    def test_a_faithful_stand_in(self) -> None:
        class Stand:
            @property
            def ended(self) -> bool:
                return False

            async def run(self, command: str, *, timeout: float = 0.0) -> str:
                return command

            def recorded(self) -> List[str]:
                return []

        self.assertEqual(fake_problems(Stand, Framework, test_only=["recorded"]), [])

    def test_each_way_a_stand_in_differs(self) -> None:
        class Stand:
            def ended(self) -> bool:
                return False

            def run(self, command: str) -> str:
                return command

            def recorded(self) -> List[str]:
                return []

        got = fake_problems(Stand, Framework)
        where = f"(against {__name__}.Framework)"
        self.assertEqual(sorted(got), sorted([
            f"Stand.ended {where} is a method, the framework's is a property",
            f"Stand.run {where} is not a coroutine, the framework's is one",
            f"Stand.run {where} cannot take the keyword timeout, which the framework's member takes",
            f"Stand.recorded: {__name__}.Framework has no recorded",
        ]))

    def test_a_field_is_a_value(self) -> None:
        import dataclasses

        @dataclasses.dataclass
        class Record:
            id: str = ""

        class AsValue:
            id = "x"

        class AsMethod:
            def id(self) -> str:
                return "x"

        @dataclasses.dataclass
        class Required:
            id: str

        self.assertEqual(fake_problems(AsValue, Record), [])
        self.assertEqual(fake_problems(AsValue, Required), [])
        self.assertEqual(fake_problems(AsMethod, Required),
                         [f"AsMethod.id (against {__name__}.{Required.__qualname__}) is a method, the framework's is a field"])
        self.assertEqual(fake_problems(AsMethod, Record), [f"AsMethod.id (against {__name__}.{Record.__qualname__}) is a method, the framework's is an attribute"])


if __name__ == "__main__":
    unittest.main()
