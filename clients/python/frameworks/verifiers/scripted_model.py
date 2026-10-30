"""A scripted stand-in for a model, so a verifiers rollout runs end to end without one.

An OpenAI-compatible chat completions server on loopback (standard library only) whose every
answer comes from a fixed *policy*: a function of the conversation so far that returns the
next assistant message, plain text or tool calls. It is not a model and decides nothing a
script does not say; it exists so verifiers' real interception server, a real harness and
a real runtime can be driven through a complete attempt at no cost. It answers both ways
verifiers asks: a streamed answer (server-sent events, with a usage chunk) and a plain one,
and lists its one model at ``/v1/models`` without a context window (so a harness that
discovers one compacts by its own default).

    with ScriptedModel(policy) as model:
        ...  # point the eval's client at model.base_url
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional

__all__ = ["ScriptedModel", "assistant", "tool_call", "last_tool_result"]

Policy = Callable[[List[Dict[str, Any]]], Dict[str, Any]]


def tool_call(name: str, **arguments: Any) -> Dict[str, Any]:
    """One tool call for :func:`assistant`."""
    return {"name": name, "arguments": arguments}


def assistant(content: Optional[str] = None, *calls: Dict[str, Any]) -> Dict[str, Any]:
    """A policy's answer: text, tool calls, or both."""
    return {"content": content, "tool_calls": list(calls)}


def last_tool_result(messages: List[Dict[str, Any]]) -> str:
    """The text of the newest tool result in the conversation ("" if none)."""
    for message in reversed(messages):
        if message.get("role") == "tool":
            content = message.get("content")
            if isinstance(content, list):
                return "".join(part.get("text", "") for part in content if isinstance(part, dict))
            return content or ""
    return ""


def _tokens(value: Any) -> int:
    # A rough count, four characters a token: the trace's usage fields want numbers.
    return max(1, len(json.dumps(value, default=str)) // 4)


class ScriptedModel:
    """The server; a context manager that starts it on 127.0.0.1 and stops it."""

    def __init__(self, policy: Policy, model: str = "scripted") -> None:
        self.policy = policy
        self.model = model
        self.requests: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._calls = 0
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def base_url(self) -> str:
        assert self._server is not None, "not started"
        return f"http://127.0.0.1:{self._server.server_address[1]}/v1"

    def __enter__(self) -> "ScriptedModel":
        scripted = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:
                pass

            def _json(self, status: int, body: Dict[str, Any]) -> None:
                data = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                if self.path.rstrip("/").endswith("/models"):
                    self._json(200, {"object": "list", "data": [{"id": scripted.model, "object": "model", "created": 0, "owned_by": "scripted"}]})
                else:
                    self._json(404, {"error": {"message": f"no route {self.path}"}})

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                if not self.path.rstrip("/").endswith("/chat/completions"):
                    self._json(404, {"error": {"message": f"no route {self.path}"}})
                    return
                try:
                    answer = scripted._answer(body)
                except Exception as e:  # a policy bug is a 500 the harness reports
                    self._json(500, {"error": {"message": f"scripted policy failed: {type(e).__name__}: {e}"}})
                    return
                if body.get("stream"):
                    self._stream(answer)
                else:
                    self._json(200, answer)

            def _stream(self, answer: Dict[str, Any]) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                choice = answer["choices"][0]
                message = choice["message"]
                base = {key: answer[key] for key in ("id", "created", "model")}
                base["object"] = "chat.completion.chunk"

                def event(delta: Dict[str, Any], finish: Optional[str] = None) -> None:
                    chunk = {**base, "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}
                    self.wfile.write(b"data: " + json.dumps(chunk).encode("utf-8") + b"\n\n")

                event({"role": "assistant", "content": ""})
                if message.get("content"):
                    event({"content": message["content"]})
                for i, call in enumerate(message.get("tool_calls") or []):
                    event({"tool_calls": [{"index": i, **call}]})
                event({}, choice["finish_reason"])
                usage = {**base, "choices": [], "usage": answer["usage"]}
                self.wfile.write(b"data: " + json.dumps(usage).encode("utf-8") + b"\n\n")
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()
                self.close_connection = True

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, name="scripted-model", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def _answer(self, body: Dict[str, Any]) -> Dict[str, Any]:
        messages = body.get("messages") or []
        with self._lock:
            self.requests.append(body)
            self._calls += 1
            n = self._calls
        reply = self.policy(messages)
        message: Dict[str, Any] = {"role": "assistant", "content": reply.get("content")}
        calls = [
            {"id": f"call_{n}_{i}", "type": "function", "function": {"name": c["name"], "arguments": json.dumps(c["arguments"])}}
            for i, c in enumerate(reply.get("tool_calls") or [])
        ]
        if calls:
            message["tool_calls"] = calls
        prompt, completion = _tokens(messages), _tokens(message)
        return {
            "id": f"chatcmpl-scripted-{n}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": body.get("model") or self.model,
            "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls" if calls else "stop"}],
            "usage": {"prompt_tokens": prompt, "completion_tokens": completion, "total_tokens": prompt + completion},
        }
