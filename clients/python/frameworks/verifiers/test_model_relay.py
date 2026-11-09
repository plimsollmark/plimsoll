"""The relay that stands between verifiers and a real model API, and the driver's real-model
mode. Every upstream here is a local server on loopback and every key is a canary: nothing in
this file reaches a paid API. The driver tests swap verifiers' ``vf-eval`` for a small program
of the test's own, so they need no docker and show exactly what such a child was handed."""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
import http.client
import io
import json
import os
import secrets
import shutil
import socket
import stat
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple
from unittest import mock

from frameworks.verifiers.attempt import run_attempt
from frameworks.verifiers.attempt.model_relay import MAX_CALL_OUTPUT_TOKENS, ModelRelay, _RelayHTTPServer, parse_upstream, scan_tree
from frameworks.verifiers.scripted_model import ScriptedModel, assistant

MODEL = "vendor/test-model"
EXPECTED = "078fbbe4-adec-65a0-3629-496c56239d16"
SOURCE = "51fcd66f-cd2f-4790-b9b2-67682f8874ae"


class Upstream:
    """A local API whose every answer is the test's own function of (handler, body)."""

    def __init__(self, answer: Callable[[BaseHTTPRequestHandler, Dict[str, Any]], None]) -> None:
        outer = self
        self.requests: List[Tuple[str, Dict[str, str], Dict[str, Any]]] = []

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:
                pass

            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                outer.requests.append((self.path, dict(self.headers.items()), body))
                answer(self, body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, args=(0.02,), daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}/v1"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def reply(handler: BaseHTTPRequestHandler, status: int, body: Any, headers: Optional[Dict[str, str]] = None) -> None:
    data = json.dumps(body).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(data)))
    for name, value in (headers or {}).items():
        handler.send_header(name, value)
    handler.end_headers()
    handler.wfile.write(data)


def chat_ok(prompt: int = 10, completion: int = 5) -> Callable[[BaseHTTPRequestHandler, Dict[str, Any]], None]:
    def answer(handler: BaseHTTPRequestHandler, body: Dict[str, Any]) -> None:
        reply(handler, 200, {"id": "x", "choices": [], "usage": {"prompt_tokens": prompt, "completion_tokens": completion, "total_tokens": prompt + completion}})

    return answer


class Case(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="relay-test-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.key = "canary-" + secrets.token_hex(24)
        self.log = os.path.join(self.dir, "relay.jsonl")

    def upstream(self, answer: Callable[[BaseHTTPRequestHandler, Dict[str, Any]], None]) -> Upstream:
        u = Upstream(answer)
        self.addCleanup(u.close)
        return u

    def relay(self, upstream: str, budget: int = 1_000_000, **kw: Any) -> ModelRelay:
        r = ModelRelay(upstream_base=upstream, api_key=self.key, model=MODEL, token_budget=budget, log_path=self.log, **kw)
        r.__enter__()
        self.addCleanup(r.__exit__)
        return r

    def post(self, relay: ModelRelay, body: Optional[Dict[str, Any]] = None, *, token: Optional[str] = None, path: str = "/v1/chat/completions") -> Tuple[int, Dict[str, Any]]:
        status, raw = self.raw_post(relay, body, token=token, path=path)
        return status, json.loads(raw) if raw else {}

    def raw_post(self, relay: ModelRelay, body: Optional[Dict[str, Any]] = None, *, token: Optional[str] = None, path: str = "/v1/chat/completions") -> Tuple[int, bytes]:
        port = int(relay.base_url.rsplit(":", 1)[1].split("/")[0])
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        self.addCleanup(c.close)
        payload = json.dumps({"model": MODEL, "messages": [{"role": "user", "content": "hi"}]} if body is None else body)
        c.request("POST", path, body=payload, headers={"Authorization": f"Bearer {relay.local_token if token is None else token}", "Content-Type": "application/json"})
        r = c.getresponse()
        return r.status, r.read()

    def logged(self, at_least: int = 1) -> List[Dict[str, Any]]:
        # A call's line is written after its answer has gone back.
        for _ in range(500):
            with open(self.log, encoding="utf-8") as f:
                rows = [json.loads(line) for line in f]
            if len(rows) >= at_least:
                return rows
            time.sleep(0.01)
        return rows


class RelayForwarding(Case):
    def test_a_call_reaches_the_api_with_the_key_and_nothing_else_of_the_caller(self) -> None:
        up = self.upstream(chat_ok())
        relay = self.relay(up.base)
        status, _ = self.post(relay, {"model": MODEL, "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})
        self.assertEqual(status, 200)
        path, headers, body = up.requests[0]
        self.assertEqual(path, "/v1/chat/completions")
        self.assertEqual(headers["Authorization"], f"Bearer {self.key}")
        self.assertEqual({k.lower() for k in headers}, {"host", "accept-encoding", "content-length", "authorization", "content-type", "accept", "user-agent"})
        self.assertEqual(body["max_tokens"], 100)
        self.assertEqual(relay.totals()["total_tokens"], 15)
        row = self.logged()[0]
        self.assertEqual((row["status"], row["prompt_tokens"], row["completion_tokens"]), (200, 10, 5))

    def test_the_caller_s_headers_and_session_id_do_not_go_on(self) -> None:
        up = self.upstream(chat_ok())
        relay = self.relay(up.base)
        port = int(relay.base_url.rsplit(":", 1)[1].split("/")[0])
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        self.addCleanup(c.close)
        c.request("POST", "/v1/chat/completions", body=json.dumps({"model": MODEL, "messages": []}),
                  headers={"Authorization": f"Bearer {relay.local_token}", "X-Session-ID": "task-7", "X-Grader-Note": "secret", "OpenAI-Organization": "org"})
        self.assertEqual(c.getresponse().status, 200)
        names = {k.lower() for k in up.requests[0][1]}
        self.assertFalse(names & {"x-session-id", "x-grader-note", "openai-organization"})

    def test_max_tokens_is_capped_or_set(self) -> None:
        up = self.upstream(chat_ok())
        relay = self.relay(up.base)
        self.post(relay, {"model": MODEL, "messages": [], "max_tokens": 10_000_000})
        self.post(relay, {"model": MODEL, "messages": [], "max_completion_tokens": 10_000_000})
        self.post(relay, {"model": MODEL, "messages": []})
        for _, _, body in up.requests:
            self.assertEqual(body["max_tokens"], MAX_CALL_OUTPUT_TOKENS)
            self.assertNotIn("max_completion_tokens", body)

    def test_only_the_run_s_model_and_one_route_with_the_local_token(self) -> None:
        up = self.upstream(chat_ok())
        relay = self.relay(up.base)
        self.assertEqual(self.post(relay, {"model": "vendor/dearer", "messages": []})[0], 400)
        self.assertEqual(self.post(relay, path="/v1/embeddings")[0], 404)
        self.assertEqual(self.post(relay, path="/v1/chat/completions?x=1")[0], 404)
        self.assertEqual(self.post(relay, token="wrong")[0], 401)
        self.assertEqual(self.post(relay, token=self.key)[0], 401)  # the real key opens nothing here
        self.assertEqual(up.requests, [])
        self.assertEqual(relay.totals()["refused"], 5)

    def test_a_redirect_is_refused_and_the_key_stays_home(self) -> None:
        elsewhere = self.upstream(chat_ok())
        up = self.upstream(lambda h, b: reply(h, 307, {}, {"Location": elsewhere.base + "/chat/completions"}))
        relay = self.relay(up.base)
        self.assertEqual(self.post(relay)[0], 502)
        self.assertEqual(elsewhere.requests, [])

    def test_an_error_body_that_echoes_the_key_is_scrubbed(self) -> None:
        up = self.upstream(lambda h, b: reply(h, 401, {"error": {"message": f"bad key {self.key}"}}))
        relay = self.relay(up.base)
        status, raw = self.raw_post(relay)
        self.assertEqual(status, 401)
        self.assertNotIn(self.key.encode("utf-8"), raw)
        self.assertEqual(relay.totals()["total_tokens"], 0)  # a refused request made nothing

    def test_an_answer_with_no_usage_counts_as_its_whole_reservation(self) -> None:
        up = self.upstream(lambda h, b: reply(h, 200, {"id": "x", "choices": []}))
        relay = self.relay(up.base)
        self.post(relay, {"model": MODEL, "messages": [], "max_tokens": 1000})
        totals = relay.totals()
        self.assertGreaterEqual(totals["charged_without_usage"], 1000)
        self.assertEqual(totals["usage_missing"], 1)

    def test_a_server_error_counts_as_its_whole_reservation(self) -> None:
        up = self.upstream(lambda h, b: reply(h, 500, {"error": {"message": "boom"}}))
        relay = self.relay(up.base)
        self.assertEqual(self.post(relay, {"model": MODEL, "messages": [], "max_tokens": 1000})[0], 500)
        self.assertGreaterEqual(relay.totals()["charged_without_usage"], 1000)

    def test_an_unreachable_upstream_is_a_502_and_counts_as_its_whole_reservation(self) -> None:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        relay = self.relay(f"http://127.0.0.1:{port}/v1")
        self.assertEqual(self.post(relay, {"model": MODEL, "messages": [], "max_tokens": 1000})[0], 502)
        self.assertGreaterEqual(relay.totals()["charged_without_usage"], 1000)

    def test_a_key_that_would_end_up_in_a_traceback_is_refused_without_echoing_it(self) -> None:
        with self.assertRaises(ValueError) as caught:
            ModelRelay(upstream_base="https://api.example.com/v1", api_key="sk-secret\n", model=MODEL, token_budget=1, log_path=self.log)
        self.assertNotIn("sk-secret", str(caught.exception))

    def test_plain_http_is_for_this_machine_only(self) -> None:
        self.assertEqual(parse_upstream("https://api.example.com/v1/"), ("https", "api.example.com", 443, "/v1"))
        self.assertEqual(parse_upstream("http://127.0.0.1:8080/v1"), ("http", "127.0.0.1", 8080, "/v1"))
        for bad in ("http://api.example.com/v1", "ftp://x/v1", "https://user:pw@example.com/v1", "https://example.com/v1?k=v", "/v1"):
            with self.assertRaises(ValueError, msg=bad):
                parse_upstream(bad)


class RelayStreaming(Case):
    def stream(self, relay: ModelRelay) -> Tuple[List[bytes], List[float]]:
        port = int(relay.base_url.rsplit(":", 1)[1].split("/")[0])
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        self.addCleanup(c.close)
        c.request("POST", "/v1/chat/completions", body=json.dumps({"model": MODEL, "messages": [], "stream": True}),
                  headers={"Authorization": f"Bearer {relay.local_token}"})
        r = c.getresponse()
        self.assertEqual(r.status, 200)
        self.assertEqual(r.getheader("Content-Type"), "text/event-stream")
        pieces, times = [], []
        while True:
            chunk = r.read1(65536)
            if not chunk:
                return pieces, times
            pieces.append(chunk)
            times.append(time.monotonic())

    def test_pieces_pass_as_they_arrive_and_the_usage_chunk_is_counted(self) -> None:
        gate = threading.Event()

        def answer(handler: BaseHTTPRequestHandler, body: Dict[str, Any]) -> None:
            handler.send_response(200)
            handler.send_header("Content-Type", "text/event-stream")
            handler.send_header("Connection", "close")
            handler.end_headers()
            handler.close_connection = True
            for text in ("a", "b"):
                handler.wfile.write(b"data: " + json.dumps({"choices": [{"delta": {"content": text}}]}).encode() + b"\n\n")
                handler.wfile.flush()
                gate.wait(10)  # the test lets the next piece go only once it has read this one
            usage = {"choices": [], "usage": {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10}}
            handler.wfile.write(b"data: " + json.dumps(usage).encode() + b"\n\ndata: [DONE]\n\n")
            handler.wfile.flush()

        up = self.upstream(answer)
        relay = self.relay(up.base)
        port = int(relay.base_url.rsplit(":", 1)[1].split("/")[0])
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        self.addCleanup(c.close)
        c.request("POST", "/v1/chat/completions", body=json.dumps({"model": MODEL, "messages": [], "stream": True}),
                  headers={"Authorization": f"Bearer {relay.local_token}"})
        r = c.getresponse()
        self.assertIn(b'"a"', r.read1(65536))  # arrived while the upstream waits: not buffered
        gate.set()
        rest = b""
        while True:
            chunk = r.read1(65536)
            if not chunk:
                break
            rest += chunk
        self.assertIn(b"[DONE]", rest)
        for _ in range(100):
            if relay.totals()["total_tokens"]:
                break
            time.sleep(0.01)
        self.assertEqual(relay.totals()["total_tokens"], 10)
        self.assertEqual(up.requests[0][2]["stream_options"], {"include_usage": True})
        row = self.logged()[0]
        self.assertTrue(row["stream"] and row["finished"])

    def test_a_stream_cut_short_keeps_its_reservation(self) -> None:
        def answer(handler: BaseHTTPRequestHandler, body: Dict[str, Any]) -> None:
            handler.send_response(200)
            handler.send_header("Content-Type", "text/event-stream")
            handler.send_header("Connection", "close")
            handler.end_headers()
            handler.close_connection = True
            handler.wfile.write(b'data: {"choices": []}\n\n')

        up = self.upstream(answer)
        relay = self.relay(up.base)
        self.stream(relay)
        for _ in range(100):
            if relay.totals()["usage_missing"]:
                break
            time.sleep(0.01)
        self.assertGreaterEqual(relay.totals()["charged_without_usage"], MAX_CALL_OUTPUT_TOKENS)


class RelayBudget(Case):
    def test_a_call_past_the_budget_is_refused_and_never_reaches_the_api(self) -> None:
        up = self.upstream(chat_ok(prompt=900, completion=100))
        relay = self.relay(up.base, budget=1400)
        small = {"model": MODEL, "messages": [], "max_tokens": 10}
        self.assertEqual(self.post(relay, small)[0], 200)  # 1000 used
        self.assertEqual(self.post(relay, small)[0], 200)  # 1000 and a small reservation fit under 1400; now 2000
        status, body = self.post(relay, small)
        self.assertEqual((status, body["error"]["code"]), (403, "budget"))
        count = len(up.requests)
        status, _ = self.post(relay, small)
        self.assertEqual(status, 403)
        self.assertEqual(len(up.requests), count)
        totals = relay.totals()
        self.assertTrue(totals["budget_reached"])
        self.assertGreaterEqual(totals["refused"], 2)
        self.assertEqual([r.get("refused") for r in self.logged()][-1], "budget")

    def cached_ok(self, prompt: int, cached: int, completion: int) -> Callable[[BaseHTTPRequestHandler, Dict[str, Any]], None]:
        def answer(handler: BaseHTTPRequestHandler, body: Dict[str, Any]) -> None:
            reply(handler, 200, {"id": "x", "choices": [], "usage": {"prompt_tokens": prompt, "completion_tokens": completion, "total_tokens": prompt + completion,
                                                                      "prompt_tokens_details": {"cached_tokens": cached}}})

        return answer

    def test_cached_input_is_counted_at_its_cached_price(self) -> None:
        up = self.upstream(self.cached_ok(900, 600, 100))
        relay = self.relay(up.base, usd_budget=1.0, price_in=1.0, price_cached=0.1, price_out=2.0)
        self.assertEqual(self.post(relay, {"model": MODEL, "messages": [], "max_tokens": 10})[0], 200)
        totals = relay.totals()
        self.assertEqual((totals["prompt_tokens"], totals["cached_prompt_tokens"]), (900, 600))
        self.assertAlmostEqual(totals["usd_spent"], (300 * 1.0 + 600 * 0.1 + 100 * 2.0) / 1e6, places=9)
        self.assertEqual([r.get("cached_tokens") for r in self.logged()], [600])

    def test_the_dollar_budget_refuses_a_call_and_it_never_reaches_the_api(self) -> None:
        up = self.upstream(self.cached_ok(900, 600, 100))
        # Each call costs $0.00056; two fit under $0.0012 with room for a small reservation, a third does not.
        relay = self.relay(up.base, budget=10**9, usd_budget=0.0012, price_in=1.0, price_cached=0.1, price_out=2.0)
        small = {"model": MODEL, "messages": [], "max_tokens": 10}
        self.assertEqual(self.post(relay, small)[0], 200)
        self.assertEqual(self.post(relay, small)[0], 200)
        count = len(up.requests)
        status, body = self.post(relay, small)
        self.assertEqual((status, body["error"]["code"]), (403, "dollar_budget"))
        self.assertEqual(len(up.requests), count)
        self.assertTrue(relay.totals()["budget_reached"])
        self.assertLessEqual(relay.totals()["usd_spent"], 0.0012)

    def test_a_call_with_no_usage_is_charged_its_whole_reservation_in_dollars(self) -> None:
        up = self.upstream(lambda h, b: reply(h, 200, {"id": "x", "choices": []}))
        relay = self.relay(up.base, usd_budget=1.0, price_in=1.0, price_cached=0.1, price_out=2.0)
        self.assertEqual(self.post(relay, {"model": MODEL, "messages": [], "max_tokens": 1000})[0], 200)
        totals = relay.totals()
        self.assertAlmostEqual(totals["usd_spent"], totals["charged_without_usage"] * 2.0 / 1e6, places=9)

    def test_two_calls_in_flight_cannot_pass_the_budget_together(self) -> None:
        hold = threading.Event()

        def answer(handler: BaseHTTPRequestHandler, body: Dict[str, Any]) -> None:
            hold.wait(10)
            chat_ok(prompt=100, completion=100)(handler, body)

        up = self.upstream(answer)
        # One call reserves its bytes plus 16384; two would pass this budget.
        relay = self.relay(up.base, budget=MAX_CALL_OUTPUT_TOKENS + 500)
        results: List[int] = []
        first = threading.Thread(target=lambda: results.append(self.post(relay)[0]))
        first.start()
        for _ in range(500):
            if up.requests:
                break
            time.sleep(0.01)
        self.assertEqual(len(up.requests), 1)
        self.assertEqual(self.post(relay)[0], 403)  # the first has not answered, and is reserved
        hold.set()
        first.join(10)
        self.assertEqual(results, [200])
        self.assertEqual(len(up.requests), 1)

    def post_as(self, relay: ModelRelay, attempt: str, max_tokens: int = 10) -> int:
        port = int(relay.base_url.rsplit(":", 1)[1].split("/")[0])
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        self.addCleanup(c.close)
        c.request("POST", "/v1/chat/completions", body=json.dumps({"model": MODEL, "messages": [], "max_tokens": max_tokens}),
                  headers={"Authorization": f"Bearer {relay.local_token}", "X-Session-ID": attempt})
        r = c.getresponse()
        r.read()
        return r.status

    def test_a_runaway_attempt_stops_alone_and_the_others_go_on(self) -> None:
        up = self.upstream(chat_ok(prompt=900, completion=100))
        relay = self.relay(up.base, budget=1_000_000, attempt_budget=1100)
        self.assertEqual(self.post_as(relay, "stuck"), 200)  # 1000 used; the next reservation fits
        self.assertEqual(self.post_as(relay, "stuck"), 200)  # 2000 used
        self.assertEqual(self.post_as(relay, "stuck"), 403)
        self.assertEqual(self.post_as(relay, "healthy"), 200)
        self.assertEqual(relay.refused_attempts, {"stuck": "attempt_budget"})
        self.assertFalse(relay.totals()["budget_reached"])
        self.assertEqual([r.get("attempt") for r in self.logged(4) if r.get("status") == 200], ["stuck", "stuck", "healthy"])

    def test_the_session_id_never_reaches_the_api(self) -> None:
        up = self.upstream(chat_ok())
        relay = self.relay(up.base, attempt_budget=10_000)
        self.post_as(relay, "attempt-7")
        self.assertNotIn("x-session-id", {k.lower() for k in up.requests[0][1]})

    def test_a_burst_can_connect_before_the_accept_loop_runs(self) -> None:
        up = self.upstream(chat_ok())
        accepting = threading.Event()
        serve = _RelayHTTPServer.serve_forever

        def delayed(server: ThreadingHTTPServer, *args: Any) -> None:
            accepting.wait()
            serve(server, *args)

        # Hold accept deliberately, so this checks the listener's burst capacity
        # without depending on how quickly this machine schedules forty threads.
        with mock.patch.object(_RelayHTTPServer, "serve_forever", delayed):
            relay = self.relay(up.base)
            connections = []
            try:
                port = int(relay.base_url.rsplit(":", 1)[1].split("/")[0])
                for _ in range(40):
                    connections.append(socket.create_connection(("127.0.0.1", port), timeout=2))
            finally:
                for connection in connections:
                    connection.close()
                accepting.set()

    def test_the_budget_holds_under_many_concurrent_callers(self) -> None:
        up = self.upstream(chat_ok(prompt=100, completion=100))
        budget = 3 * (MAX_CALL_OUTPUT_TOKENS + 200)
        relay = self.relay(up.base, budget=budget)
        # Propagate worker exceptions to the test instead of losing a result in a
        # detached thread and reporting only a shorter results list.
        with ThreadPoolExecutor(max_workers=40) as pool:
            results = list(pool.map(lambda _: self.post(relay)[0], range(40)))
        totals = relay.totals()
        self.assertEqual(len(results), 40)
        self.assertLessEqual(totals["tokens_counted"], budget)
        self.assertEqual(totals["refused"] + totals["forwarded"], 40)


class RelayAnswerKey(Case):
    def relay_with_key(self, up: Upstream) -> ModelRelay:
        return self.relay(up.base, hidden=[EXPECTED, SOURCE], answers=[EXPECTED])

    def test_a_hidden_value_in_the_prompt_is_refused_and_marks_the_run(self) -> None:
        for planted in (EXPECTED, EXPECTED.upper(), EXPECTED.replace("-", ""), SOURCE):
            up = self.upstream(chat_ok())
            relay = self.relay_with_key(up)
            status, body = self.post(relay, {"model": MODEL, "messages": [{"role": "user", "content": f"the token is {planted}"}]})
            self.assertEqual((status, body["error"]["code"]), (403, "answer_key"), planted)
            self.assertEqual(up.requests, [])
            self.assertTrue(relay.totals()["answer_key_seen"])

    def test_a_hidden_value_in_a_system_message_or_a_tool_description_is_refused(self) -> None:
        up = self.upstream(chat_ok())
        relay = self.relay_with_key(up)
        late_system = [{"role": "user", "content": "go"}, {"role": "assistant", "content": "ok"}, {"role": "system", "content": EXPECTED}]
        self.assertEqual(self.post(relay, {"model": MODEL, "messages": late_system})[0], 403)
        tools = [{"type": "function", "function": {"name": "x", "description": f"the answer is {EXPECTED}"}}]
        self.assertEqual(self.post(relay, {"model": MODEL, "messages": [], "tools": tools})[0], 403)
        self.assertEqual(up.requests, [])

    def test_a_hidden_value_in_a_later_user_message_is_refused(self) -> None:
        up = self.upstream(chat_ok())
        relay = self.relay_with_key(up)
        later_user = [{"role": "user", "content": "go"}, {"role": "assistant", "content": "ok"}, {"role": "user", "content": f"the token is {EXPECTED}"}]
        status, body = self.post(relay, {"model": MODEL, "messages": later_user})
        self.assertEqual((status, body["error"]["code"]), (403, "answer_key"))
        self.assertEqual(up.requests, [])
        self.assertTrue(relay.totals()["answer_key_seen"])

    def test_what_the_model_found_or_worked_out_for_itself_goes_through(self) -> None:
        up = self.upstream(chat_ok())
        relay = self.relay_with_key(up)
        messages = [
            {"role": "user", "content": "recover the token"},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "1", "type": "function", "function": {"name": "bash", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": "1", "content": f"shard {SOURCE}"},
            {"role": "assistant", "content": f"I computed {EXPECTED}"},
        ]
        self.assertEqual(self.post(relay, {"model": MODEL, "messages": messages})[0], 200)
        self.assertEqual(self.logged()[0]["answer_first_role"], "assistant")
        self.assertFalse(relay.totals()["answer_key_seen"])

    def test_the_log_never_holds_a_prompt_or_a_hidden_value(self) -> None:
        up = self.upstream(chat_ok())
        relay = self.relay_with_key(up)
        self.post(relay, {"model": MODEL, "messages": [{"role": "user", "content": "a private prompt"}]})
        self.post(relay, {"model": MODEL, "messages": [{"role": "user", "content": EXPECTED}]})
        with open(self.log, encoding="utf-8") as f:
            log = f.read()
        self.assertNotIn("private prompt", log)
        self.assertNotIn(EXPECTED, log)


# verifiers' program, as far as the driver can tell: it reads the config the driver wrote, makes
# one chat call to the client it names, and leaves a trace. It also records the environment it
# was given, and if the key is in there it does what task code could do with it.
_SHIM = """#!{python}
import http.client, json, os, sys
out = os.getcwd()
config = open(os.path.join(out, "eval.toml"), encoding="utf-8").read()
base = [l for l in config.splitlines() if l.startswith("base_url")][0].split('"')[1]
port = int(base.split(":")[2].split("/")[0])
with open(os.path.join(out, "child-env.json"), "w", encoding="utf-8") as f:
    json.dump(dict(os.environ), f)
planted = os.environ.get("SHIM_LEAK_FROM")
if planted:
    open(os.path.join(out, "dumped-by-task-code.txt"), "w").write(open(planted).read())
c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
token = os.environ["PLIMSOLL_RELAY_KEY"]
c.request("POST", "/v1/chat/completions", body=json.dumps({{"model": sys.argv[sys.argv.index("-m") + 1], "messages": [{{"role": "user", "content": "go"}}]}}),
          headers={{"Authorization": "Bearer " + token, "X-Session-ID": "attempt-1"}})
r = c.getresponse()
usage = json.loads(r.read()).get("usage") or {{}}
# As verifiers saves a call's usage: prompt_tokens excludes what the API served from cache,
# which has its own field (verifiers/v1/types.py, Usage.from_openai).
cached = (usage.get("prompt_tokens_details") or {{}}).get("cached_tokens") or 0
usage = {{"prompt_tokens": usage.get("prompt_tokens", 0) - cached, "completion_tokens": usage.get("completion_tokens", 0), "cached_input_tokens": cached}}
run = os.path.join(out, "runs", "run")
os.makedirs(run, exist_ok=True)
trace = {{"id": "attempt-1", "task": {{"data": {{"idx": 0, "result_uuid": "{expected}"}}}}, "rewards": {{"solved": {{"score": 1.0, "weight": 1.0}}}},
         "num_total_tokens": 1, "nodes": [{{"message": {{"role": "user", "content": "go"}}}}], "calls": [{{"usage": usage}}], "timing": {{}}, "stop_condition": "agent_completed"}}
with open(os.path.join(run, "traces.jsonl"), "w", encoding="utf-8") as f:
    f.write(json.dumps({{"traces": [trace]}}) + "\\n")
sys.exit(int(os.environ.get("SHIM_EXIT", "0")))
"""


class DriverRealModel(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="real-model-test-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.out = os.path.join(self.dir, "out")
        self.shim = os.path.join(self.dir, "vf-eval-shim")
        with open(self.shim, "w", encoding="utf-8") as f:
            f.write(_SHIM.format(python=sys.executable, expected=EXPECTED))
        os.chmod(self.shim, os.stat(self.shim).st_mode | stat.S_IEXEC)
        self.canary = "canary-" + secrets.token_hex(24)
        self.up = ScriptedModel(lambda m: assistant("done"), model=MODEL, require_key=self.canary)
        self.up.__enter__()
        self.addCleanup(self.up.__exit__)
        for name, value in (("expected_values", lambda *a: {"answers": [EXPECTED], "sources": [SOURCE]}), ("check_task_files", lambda root: None)):
            patcher = mock.patch.object(run_attempt, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(os.environ.pop, "TEST_UPSTREAM_KEY", None)
        os.environ["TEST_UPSTREAM_KEY"] = self.canary

    def run_driver(self, *extra: str) -> int:
        argv = ["--task", "uuid-ctf", "--runtime", "plimsoll", "--url", "http://127.0.0.1:9", "--out", self.out, "--vf-eval", self.shim, "--taskset-path", self.dir,
                "--model", MODEL, "--upstream-base", self.up.base_url, "--upstream-key-var", "TEST_UPSTREAM_KEY", "--tasks", "1", *extra]
        with mock.patch("builtins.print"):
            return run_attempt.main(argv)

    def summary(self) -> Dict[str, Any]:
        with open(os.path.join(self.out, "summary.json"), encoding="utf-8") as f:
            return json.load(f)

    def child_env(self) -> Dict[str, str]:
        with open(os.path.join(self.out, "child-env.json"), encoding="utf-8") as f:
            return json.load(f)

    def test_the_key_reaches_the_api_and_no_file_and_no_child(self) -> None:
        self.assertEqual(self.run_driver(), 0)
        # It worked, so the key did reach the upstream: the scripted server refuses without it.
        self.assertEqual(self.up.request_headers[0]["Authorization"], f"Bearer {self.canary}")
        env = self.child_env()
        self.assertNotIn(self.canary, json.dumps(env))
        self.assertNotIn("TEST_UPSTREAM_KEY", env)
        self.assertEqual(scan_tree(self.out, self.canary), [])
        self.assertEqual(sorted(set(env) - {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "DOCKER_HOST", "LC_CTYPE", "PWD"}),
                         ["PLIMSOLL_RELAY_KEY", "PLIMSOLL_TOKEN", "PYTHONDONTWRITEBYTECODE", "PYTHONPATH", "PYTHONPYCACHEPREFIX", "PYTHONSAFEPATH"])
        self.assertNotIn("TEST_UPSTREAM_KEY", os.environ)
        s = self.summary()
        self.assertEqual(s["key_check"], {"files_with_the_key": [], "other_files_with_the_key": [], "other_files_checked": 0, "children_with_the_key": [], "children_checked": 1})
        self.assertEqual(s["key_source"], "env")
        self.assertIsNone(s["policy"])  # a real model followed no scripted policy
        self.assertNotIn("model_requests", s)  # there is no scripted model to count requests of

    def test_the_summary_prices_each_attempt_and_matches_the_relay(self) -> None:
        self.assertEqual(self.run_driver("--price-in", "1", "--price-out", "2", "--cost-cap-usd", "0.96"), 0)
        s = self.summary()
        row = s["rollouts"][0]
        real = s["real_model"]
        self.assertEqual(row["cost_usd"], round((row["input_tokens"] * 1 + row["output_tokens"] * 2) / 1e6, 6))
        self.assertEqual(real["cost_usd"], row["cost_usd"])
        self.assertTrue(real["traces_match_relay"])
        self.assertFalse(real["dry_run"])
        self.assertEqual(row["rewards"], {"solved": 1.0})  # from the trace's grader, never the model
        self.assertEqual(real["relay"]["forwarded"], 1)
        self.assertIsNone(row["relay_refused"])

    def test_cached_input_is_billed_input_and_the_costs_add_up(self) -> None:
        self.up.cached_share = 0.5
        self.assertEqual(self.run_driver("--price-in", "1", "--price-cached", "0.5", "--price-out", "2", "--cost-cap-usd", "0.96"), 0)
        s = self.summary()
        row, real = s["rollouts"][0], s["real_model"]
        self.assertGreater(row["cached_input_tokens"], 0)
        self.assertEqual(row["input_tokens"], real["relay"]["prompt_tokens"])  # every prompt token, cached or not
        self.assertEqual(row["cached_input_tokens"], real["relay"]["cached_prompt_tokens"])
        self.assertTrue(real["traces_match_relay"])
        want = ((row["input_tokens"] - row["cached_input_tokens"]) * 1 + row["cached_input_tokens"] * 0.5 + row["output_tokens"] * 2) / 1e6
        self.assertAlmostEqual(row["cost_usd"], want, places=6)
        self.assertAlmostEqual(sum(r["cost_usd"] for r in s["rollouts"]), real["cost_usd"], places=5)
        self.assertAlmostEqual(real["relay"]["usd_spent"], real["cost_usd"], places=5)
        self.assertTrue(real["costs_match_relay"])

    def test_a_cost_cap_over_the_approved_96_cents_never_starts(self) -> None:
        with self.assertRaises(SystemExit), mock.patch("sys.stderr"):
            self.run_driver("--cost-cap-usd", "0.97")
        self.assertEqual(self.up.requests, [])
        self.assertFalse(os.path.exists(self.out))

    def test_the_token_backstops_never_cut_an_attempt_before_the_dollar_cap_would(self) -> None:
        self.assertEqual(self.run_driver("--price-in", "0.06", "--price-cached", "0.03", "--price-out", "0.24"), 0)
        real = self.summary()["real_model"]
        # The cheapest token is a cached one: the whole cap spent on them is the most tokens
        # the dollar cap allows, and neither backstop is below it.
        most = real["cost_cap_usd"] / 0.03 * 1e6
        self.assertGreaterEqual(real["run_token_budget"], most)
        self.assertGreaterEqual(real["attempt_token_budget"], most)
        self.assertEqual(real["cost_cap_usd"], 0.96)

    def test_the_driver_s_own_log_is_scanned_for_the_key(self) -> None:
        log = os.path.join(self.dir, "driver.log")
        with open(log, "w", encoding="utf-8") as f:
            f.write("oops " + self.canary)
        self.assertEqual(self.run_driver("--scan-file", log), 1)
        self.assertEqual(self.summary()["key_check"]["other_files_with_the_key"], [log])

    def test_the_key_can_come_from_a_pipe_and_never_the_environment(self) -> None:
        del os.environ["TEST_UPSTREAM_KEY"]
        argv = ["--task", "uuid-ctf", "--runtime", "plimsoll", "--url", "http://127.0.0.1:9", "--out", self.out, "--vf-eval", self.shim, "--taskset-path", self.dir,
                "--model", MODEL, "--upstream-base", self.up.base_url, "--upstream-key-stdin", "--tasks", "1"]
        with mock.patch("builtins.print"), mock.patch("sys.stdin", io.StringIO(self.canary + "\n")):
            self.assertEqual(run_attempt.main(argv), 0)
        self.assertEqual(self.up.request_headers[0]["Authorization"], f"Bearer {self.canary}")
        self.assertEqual(self.summary()["key_check"]["files_with_the_key"], [])
        self.assertEqual(self.summary()["key_source"], "stdin")

    def test_the_child_environment_check_fails_when_the_leak_is_put_back(self) -> None:
        # Puts back the leak the mode exists to prevent: the key in vf-eval's environment.
        real_env = run_attempt.eval_environment
        with mock.patch.object(run_attempt, "eval_environment", lambda *a: {**real_env(*a), "LEAKED_KEY": self.canary}):
            self.assertEqual(self.run_driver(), 1)
        s = self.summary()
        self.assertEqual(len(s["key_check"]["children_with_the_key"]), 1)

    def test_the_file_check_fails_when_the_leak_is_put_back(self) -> None:
        # A child that wrote the key to a file, as task code could if it ever held it. It reads
        # the key from outside the run's directory, so only the file check can see this leak.
        source = os.path.join(self.dir, "key-outside-the-run")
        with open(source, "w", encoding="utf-8") as f:
            f.write(self.canary)
        real_env = run_attempt.eval_environment
        with mock.patch.object(run_attempt, "eval_environment", lambda *a: {**real_env(*a), "SHIM_LEAK_FROM": source}):
            self.assertEqual(self.run_driver(), 1)
        self.assertIn("dumped-by-task-code.txt", self.summary()["key_check"]["files_with_the_key"])

    def test_a_budget_over_the_cost_cap_never_starts(self) -> None:
        with self.assertRaises(SystemExit), mock.patch("sys.stderr"):
            self.run_driver("--cost-cap-usd", "0.961")
        self.assertEqual(self.up.requests, [])
        self.assertFalse(os.path.exists(self.out))

    def test_a_missing_key_never_starts(self) -> None:
        del os.environ["TEST_UPSTREAM_KEY"]
        with self.assertRaises(SystemExit), mock.patch("sys.stderr"):
            self.run_driver()
        self.assertFalse(os.path.exists(self.out))

    def test_a_failed_evaluation_fails_the_run(self) -> None:
        real_env = run_attempt.eval_environment
        with mock.patch.object(run_attempt, "eval_environment", lambda *a: {**real_env(*a), "SHIM_EXIT": "3"}):
            self.assertEqual(self.run_driver(), 1)
        self.assertEqual(self.summary()["vf_eval_exit"], 3)

    def test_an_answer_first_seen_in_a_user_message_fails_the_run(self) -> None:
        # The shim's trace holds the expected value in its user message: the trace's own check,
        # beside the relay's, on what verifiers says went to the model.
        with open(self.shim, encoding="utf-8") as f:
            source = f.read()
        with open(self.shim, "w", encoding="utf-8") as f:
            f.write(source.replace('"content": "go"}}]', f'"content": "{EXPECTED}"}}}}]'))
        self.assertEqual(self.run_driver(), 1)
        self.assertEqual(self.summary()["real_model"]["answer_key"]["first_role_system_or_user"], ["user"])

    def test_a_dry_run_says_so_and_needs_no_key(self) -> None:
        del os.environ["TEST_UPSTREAM_KEY"]
        argv = ["--task", "uuid-ctf", "--runtime", "plimsoll", "--url", "http://127.0.0.1:9", "--out", self.out, "--vf-eval", self.shim, "--taskset-path", self.dir,
                "--model", MODEL, "--fake-upstream", "gold", "--tasks", "1"]
        with mock.patch("builtins.print"):
            self.assertEqual(run_attempt.main(argv), 0)
        s = self.summary()
        self.assertTrue(s["real_model"]["dry_run"])
        self.assertEqual(s["real_model"]["upstream_host"], "loopback")
        self.assertEqual(s["model_requests"], 1)


class SummarizeTraces(unittest.TestCase):
    def test_a_call_cut_at_the_output_cap_is_named_by_its_finish_reason(self) -> None:
        run = tempfile.mkdtemp(prefix="traces-test-")
        self.addCleanup(shutil.rmtree, run, True)
        trace = {"id": "t", "calls": [{"finish_reason": "tool_calls", "usage": {"prompt_tokens": 5, "completion_tokens": 1, "cached_input_tokens": 10}},
                                      {"finish_reason": "length", "usage": {"prompt_tokens": 7, "completion_tokens": 9, "cached_input_tokens": 20}}]}
        with open(os.path.join(run, "traces.jsonl"), "w", encoding="utf-8") as f:
            f.write(json.dumps({"traces": [trace]}) + "\n")
        row = run_attempt.summarize_traces(run)[0]
        self.assertEqual(row["last_finish_reason"], "length")
        self.assertEqual((row["input_tokens"], row["cached_input_tokens"], row["output_tokens"]), (42, 30, 10))


class PinnedTask(unittest.TestCase):
    def package(self) -> str:
        # A package with the pinned names and this test's bytes, pinned for the test.
        root = tempfile.mkdtemp(prefix="pin-test-")
        self.addCleanup(shutil.rmtree, root, True)
        os.makedirs(os.path.join(root, "pkg"))
        with open(os.path.join(root, "pkg", "a.py"), "w", encoding="utf-8") as f:
            f.write("x = 1\n")
        return root

    def refused(self, root: str, why: str) -> None:
        pins = {"pkg/a.py": hashlib.sha256(b"x = 1\n").hexdigest()}
        with mock.patch.object(run_attempt, "PINNED_TASK_FILES", pins):
            run_attempt.check_task_files(self.package())
            with self.assertRaises((RuntimeError, OSError), msg=why):
                run_attempt.check_task_files(root)

    def test_a_linked_directory_is_refused(self) -> None:
        # A taskset/json -> elsewhere would be imported ahead of the standard library, and its
        # files were never hashed.
        root = self.package()
        outside = tempfile.mkdtemp(prefix="pin-outside-")
        self.addCleanup(shutil.rmtree, outside, True)
        with open(os.path.join(outside, "__init__.py"), "w", encoding="utf-8") as f:
            f.write("raise SystemExit('payload')\n")
        os.symlink(outside, os.path.join(root, "json"))
        self.refused(root, "directory symlink")

    def test_a_linked_file_is_refused(self) -> None:
        root = self.package()
        os.symlink(os.path.join(root, "pkg", "a.py"), os.path.join(root, "pkg", "b.py"))
        self.refused(root, "file symlink")

    def test_planted_bytecode_is_refused(self) -> None:
        # A hash-based .pyc runs in place of the unchanged source it names.
        root = self.package()
        os.makedirs(os.path.join(root, "pkg", "__pycache__"))
        with open(os.path.join(root, "pkg", "__pycache__", "x.pyc"), "wb") as f:
            f.write(b"payload")
        self.refused(root, "__pycache__/x.pyc")
        root = self.package()
        with open(os.path.join(root, "pkg", "a.pyc"), "wb") as f:
            f.write(b"payload")
        self.refused(root, "a stray .pyc")
        root = self.package()
        os.makedirs(os.path.join(root, "pkg", "__pycache__"))
        self.refused(root, "an empty __pycache__")

    def test_a_fifo_is_refused_without_hanging(self) -> None:
        root = self.package()
        os.mkfifo(os.path.join(root, "pkg", "pipe"))
        self.refused(root, "FIFO")

    def test_an_unreadable_directory_is_refused(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root reads every directory")
        root = self.package()
        locked = os.path.join(root, "pkg", "locked")
        os.makedirs(locked)
        os.chmod(locked, 0)
        self.addCleanup(os.chmod, locked, 0o755)
        self.refused(root, "unreadable directory")

    def test_children_never_read_the_tasksets_own_bytecode(self) -> None:
        env = run_attempt.eval_environment("", ["/somewhere"])
        prefix = env["PYTHONPYCACHEPREFIX"]
        self.assertTrue(os.path.isdir(prefix) and not os.listdir(prefix))
        self.assertNotEqual(prefix, run_attempt.eval_environment("", ["/somewhere"])["PYTHONPYCACHEPREFIX"])
        self.assertEqual(env["PYTHONSAFEPATH"], "1")

    def test_only_the_pinned_package_passes(self) -> None:
        root = self.package()
        pins = {"pkg/a.py": hashlib.sha256(b"x = 1\n").hexdigest()}
        with mock.patch.object(run_attempt, "PINNED_TASK_FILES", pins):
            run_attempt.check_task_files(root)
            with open(os.path.join(root, "pkg", "a.py"), "a", encoding="utf-8") as f:
                f.write("import os\n")
            with self.assertRaises(RuntimeError):
                run_attempt.check_task_files(root)
        root = self.package()
        with open(os.path.join(root, "extra.py"), "w", encoding="utf-8") as f:
            f.write("")
        with mock.patch.object(run_attempt, "PINNED_TASK_FILES", pins), self.assertRaises(RuntimeError):
            run_attempt.check_task_files(root)

    def test_a_task_that_is_not_the_pinned_one_never_starts(self) -> None:
        root = self.package()
        out = os.path.join(root, "out")
        os.environ["TEST_UPSTREAM_KEY"] = "canary"
        self.addCleanup(os.environ.pop, "TEST_UPSTREAM_KEY", None)
        argv = ["--task", "uuid-ctf", "--runtime", "plimsoll", "--url", "http://127.0.0.1:9", "--out", out, "--taskset-path", root,
                "--model", MODEL, "--upstream-base", "https://api.example.com/v1", "--upstream-key-var", "TEST_UPSTREAM_KEY"]
        with self.assertRaises(SystemExit), mock.patch("sys.stderr"):
            run_attempt.main(argv)
        self.assertFalse(os.path.exists(out))


class ScanTree(unittest.TestCase):
    def test_it_names_the_file_and_only_the_file(self) -> None:
        root = tempfile.mkdtemp(prefix="scan-test-")
        self.addCleanup(shutil.rmtree, root, True)
        os.makedirs(os.path.join(root, "a", "b"))
        for name, text in (("clean.txt", "nothing"), ("a/b/dirty.bin", "prefix-KEY-suffix")):
            with open(os.path.join(root, name), "w", encoding="utf-8") as f:
                f.write(text)
        self.assertEqual(scan_tree(root, "KEY"), ["a/b/dirty.bin"])
        self.assertEqual(scan_tree(root, "absent"), [])


if __name__ == "__main__":
    unittest.main()
