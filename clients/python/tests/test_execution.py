"""Fresh execution helper checks through the real RPC handler."""

import unittest
from unittest.mock import patch

from plimsoll_client import Client
from plimsoll_client.errors import InsufficientIsolationError, InvalidRequestError, PlimsollError, TransportError, UnsupportedError
from plimsoll_client.execution import CodeExecutor
from ._env import setting


class ExecutionTests(unittest.TestCase):
    def test_dead_daemon_is_an_environment_refusal_before_run(self):
        client = Client("http://127.0.0.1:9")
        with self.assertRaises(TransportError) as original:
            client.describe()
        with patch.object(client, "run_project") as run:
            with self.assertRaises(TransportError) as caught:
                CodeExecutor(client).execute_code("print(42)")
        run.assert_not_called()
        self.assertEqual(caught.exception.not_dispatched, "environment")
        self.assertEqual(caught.exception.message, original.exception.message)
        self.assertEqual(caught.exception.code, original.exception.code)

    def test_describe_refusal_preserves_the_original_error(self):
        client = Client("http://127.0.0.1:9")
        cases = (("permission", "permission_denied", 403), ("capacity", "resource_exhausted", 429),
                 ("protocol", "unimplemented", 501), ("request", "invalid_argument", 400),
                 ("unsupported", "unimplemented", 501), ("isolation", "failed_precondition", 412),
                 ("environment", "failed_precondition", 412), ("unknown", "unknown", 500),
                 (None, "unavailable", 503))
        for reason, code, status in cases:
            with self.subTest(reason=reason):
                error = PlimsollError("Describe refused", code=code, http_status=status, not_dispatched=reason)
                with patch.object(client, "describe", side_effect=error), patch.object(client, "run_project") as run:
                    with self.assertRaises(PlimsollError) as caught:
                        CodeExecutor(client).execute_code("print(42)")
                run.assert_not_called()
                self.assertIs(caught.exception, error)
                self.assertEqual((error.message, error.code, error.http_status, error.not_dispatched),
                                 ("Describe refused", code, status, reason if reason is not None else "environment"))

    def test_real_describe_auth_refusal_keeps_the_daemon_reason(self):
        client = Client(setting("PLIMSOLL_AUTH_URL"))
        with patch.object(client, "run_project") as run:
            with self.assertRaises(PlimsollError) as caught:
                CodeExecutor(client).execute_code("print(42)")
        run.assert_not_called()
        self.assertEqual(caught.exception.code, "unauthenticated")
        self.assertEqual(caught.exception.not_dispatched, "permission")
        self.assertEqual(caught.exception.http_status, 401)

    def test_default_floor_refuses_the_scripted_container(self):
        with self.assertRaises(InsufficientIsolationError) as caught:
            CodeExecutor(Client(setting("PLIMSOLL_SCRIPTED_URL"))).execute_code("print(42)")
        self.assertEqual(caught.exception.not_dispatched, "isolation")

    def test_returns_checked_project_result_and_raw_artifact_bytes(self):
        result = CodeExecutor(Client(setting("PLIMSOLL_SCRIPTED_URL")), minimum_isolation="container").execute_code(
            "print(42)", files={"input.csv": "a,b\n1,2\n"}, artifacts=["input.csv"],
        )
        self.assertIsNotNone(result.record)
        self.assertEqual(result.outcome, "completed")
        self.assertEqual(result.steps[0].exit_code, 0)
        self.assertIsInstance(result.steps[0].stdout, bytes)
        self.assertEqual(result.artifacts[0].content, b"a,b\n1,2\n\x00\xff")

    def test_invalid_files_refused_before_even_describe(self):
        executor = CodeExecutor(Client("http://127.0.0.1:1"))
        for files in ({".plimsoll/code.py": "bad"}, {"../outside": "bad"}, [("x", "a"), ("x", "b")]):
            with self.subTest(files=files), self.assertRaises(InvalidRequestError) as caught:
                executor.execute_code("print(42)", files=files)
            self.assertEqual(caught.exception.not_dispatched, "request")

    def test_unknown_language_refused_before_describe(self):
        with self.assertRaises(UnsupportedError) as caught:
            CodeExecutor(Client("http://127.0.0.1:1")).execute_code("42", language="ruby")
        self.assertEqual(caught.exception.not_dispatched, "unsupported")

    def test_project_support_checked(self):
        with self.assertRaises(UnsupportedError) as caught:
            CodeExecutor(Client(setting("PLIMSOLL_WASM_URL")), minimum_isolation="process").execute_code("print(42)")
        self.assertEqual(caught.exception.not_dispatched, "unsupported")

    def test_invalid_budget_or_floor_is_an_explicit_refusal(self):
        for timeout in (0, -1, float("inf"), float("nan"), True, 301):
            with self.subTest(timeout=timeout), self.assertRaises(InvalidRequestError):
                CodeExecutor(Client("http://127.0.0.1:1"), timeout=timeout)
        with self.assertRaises(InvalidRequestError):
            CodeExecutor(Client("http://127.0.0.1:1"), minimum_isolation="")
