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

    def test_a_trace_id_reaches_the_run(self):
        client = Client(setting("PLIMSOLL_SCRIPTED_URL"))
        with patch.object(client, "run_project", wraps=client.run_project) as run:
            CodeExecutor(client, minimum_isolation="container").execute_code("print(42)", trace_id="019a-tool.call:1")
        self.assertEqual(run.call_args.kwargs["trace_id"], "019a-tool.call:1")

    def test_a_trace_id_outside_the_charset_is_refused_before_describe(self):
        executor = CodeExecutor(Client("http://127.0.0.1:1"))
        for tid in ("has space", "x" * 65, "a/b", chr(0xE9)):
            with self.subTest(tid=tid), self.assertRaises(InvalidRequestError) as caught:
                executor.execute_code("print(42)", trace_id=tid)
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


# An API description in plimsoll-specgen's shape, for the grant-echo daemons' one profile.
API = "Echo lights (v1).\n  host.getLight(id)  ->  GET /v1/lights/*\n"


def _grant_client(guard=False):
    if guard:
        return Client(setting("PLIMSOLL_GRANT_ECHO_GUARD_URL"), token=setting("PLIMSOLL_GRANT_ECHO_GUARD_TOKEN"))
    return Client(setting("PLIMSOLL_GRANT_ECHO_URL"), token=setting("PLIMSOLL_GRANT_ECHO_TOKEN"))


class GrantedExecutionTests(unittest.TestCase):
    """An executor built with a grant profile, against the grant-echo daemons (the
    tool-echo provider stating project grants, named docker or e2b, serving one profile,
    echo-api, whose routes a granted project's plan names)."""

    def test_every_run_carries_the_applications_profile(self):
        import json

        from plimsoll_client import _granted

        executor = CodeExecutor(_grant_client(), minimum_isolation="container", grant_profile="echo-api", api_description=API)
        self.assertEqual(executor.grant.languages, ("javascript", "python"))
        self.assertEqual((executor.grant.profile, executor.grant.description, executor.grant.provider), ("echo-api", API, "docker"))
        js = json.loads(executor.execute_code("console.log(1)", language="javascript").steps[0].stdout_text)
        self.assertEqual(js["grant"]["allow"], ["GET /v1/lights/*", "POST /v1/lights/*/on"])
        self.assertEqual(set(js["files"]), {".plimsoll/code.mjs"})
        py = json.loads(executor.execute_code("import plimsoll_host", language="python").steps[0].stdout_text)
        self.assertEqual(py["grant"]["allow"], js["grant"]["allow"])
        self.assertEqual(py["files"][_granted.HOST_MODULE_PATH], _granted.HOST_MODULE_SOURCE)
        self.assertIn(_granted.HOST_MODULE_DIR, py["steps"][0])
        # Without a grant, the same daemon is handed none.
        plain = json.loads(CodeExecutor(_grant_client(), minimum_isolation="container").execute_code("print(1)").steps[0].stdout_text)
        self.assertNotIn("grant", plain)
        self.assertEqual(set(plain["files"]), {".plimsoll/code.py"})

    def test_python_where_steps_cannot_reach_the_broker_is_refused_before_anything_is_sent(self):
        client = _grant_client(guard=True)
        executor = CodeExecutor(client, minimum_isolation="container", grant_profile="echo-api", api_description=API)
        self.assertEqual(executor.grant.languages, ("javascript",))
        with patch.object(client, "describe") as describe, patch.object(client, "run_project") as run:
            with self.assertRaises(UnsupportedError) as caught:
                executor.execute_code("print(1)", language="python")
        describe.assert_not_called()
        run.assert_not_called()
        self.assertEqual(caught.exception.not_dispatched, "unsupported")
        self.assertIn("provider (e2b) gives a Python step no way to reach plimsoll's broker", caught.exception.message)
        self.assertIn("Write the program in JavaScript", caught.exception.message)

    def test_an_unknown_profile_is_the_daemons_permission_refusal(self):
        executor = CodeExecutor(_grant_client(), minimum_isolation="container", grant_profile="no-such-api", api_description=API)
        with self.assertRaises(PlimsollError) as caught:
            executor.execute_code("console.log(1)", language="javascript")
        self.assertEqual(caught.exception.not_dispatched, "permission")

    def test_a_daemon_that_cannot_carry_a_grant_refuses_the_executor_when_it_is_built(self):
        for url, floor in (("PLIMSOLL_TOOL_ECHO_URL", "container"), ("PLIMSOLL_WASM_URL", "process")):
            with self.subTest(url=url), self.assertRaises(UnsupportedError) as caught:
                CodeExecutor(Client(setting(url)), minimum_isolation=floor, grant_profile="echo-api", api_description=API)
            self.assertEqual(caught.exception.not_dispatched, "unsupported")
        with self.assertRaises(TransportError) as dead:
            CodeExecutor(Client("http://127.0.0.1:9"), grant_profile="echo-api", api_description=API)
        self.assertEqual(dead.exception.not_dispatched, "environment")

    def test_a_daemon_that_changed_under_the_executor_is_refused_before_run(self):
        from dataclasses import replace

        client = _grant_client()
        executor = CodeExecutor(client, minimum_isolation="container", grant_profile="echo-api", api_description=API)
        info = client.describe()
        for changed, language in ((replace(info, supports_project_grants=False), "javascript"), (replace(info, provider="e2b"), "python")):
            with self.subTest(language=language), patch.object(client, "describe", return_value=changed), \
                    patch.object(client, "run_project") as run, self.assertRaises(UnsupportedError) as caught:
                executor.execute_code("1", language=language)
            run.assert_not_called()
            self.assertEqual(caught.exception.not_dispatched, "unsupported")

    def test_profile_and_description_go_together_and_are_checked_first(self):
        dead = Client("http://127.0.0.1:1")
        for kwargs in ({"grant_profile": "echo-api"}, {"api_description": API}, {"grant_profile": "", "api_description": API},
                       {"grant_profile": "echo-api", "api_description": " "},
                       {"grant_profile": "echo-api", "api_description": "x" * 32_001}):
            with self.subTest(kwargs=kwargs), self.assertRaises(InvalidRequestError) as caught:
                CodeExecutor(dead, **kwargs)
            self.assertEqual(caught.exception.not_dispatched, "request")
