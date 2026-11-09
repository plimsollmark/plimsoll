"""A loopback relay between verifiers and a real model API, run inside the attempt driver.

``vf-eval`` imports an outside task's evaluator code into its own process, so it must never
hold an API key. It talks to this relay with a local token made for the run; the relay holds
the real key in memory, adds the ``Authorization`` header, and forwards one route to one
upstream. Standard library only, shaped like ``scripted_model.ScriptedModel``.

What the relay does on every call, and why:

- **Builds the upstream request from scratch.** No incoming header goes on, so nothing
  verifiers attaches reaches the API, and the path and host are fixed by the driver.
- **Names one model.** A request for any other model is refused, so a config slip or task
  code cannot reach a dearer model through the relay.
- **Caps the answer.** ``max_tokens`` is set to at most ``MAX_CALL_OUTPUT_TOKENS`` on every
  request: verifiers checks its per-attempt cap between turns, so one unbounded turn could
  run far past it.
- **Reserves before it spends.** The whole-run dollar budget (when one is set) and token
  budget are checked against what has been used plus an upper bound on every call in flight:
  the request's bytes (a token is at least about a byte) plus its ``max_tokens``, priced at
  the dearest of the three prices. Afterwards the reservation becomes the API's own ``usage``,
  with cached input at its cached price. A 2xx with no ``usage``, a stream cut short and a
  failed forward keep the whole reservation, so an unknown is counted as the most it could
  have been (at the output price).
- **Counts what the API bills, per attempt too.** An attempt's calls share verifiers' session
  id, so one attempt stuck in a loop can be stopped before it eats the others' share. This cap
  is needed because verifiers' own ``max_total_tokens`` counts each input token once, while an
  API bills the whole conversation again on every turn: 400,000 of verifiers' tokens can be
  many millions billed.
- **Refuses with a 403** once a budget is reached: the OpenAI library retries 429 and 5xx,
  and a refused call must not come back.
- **Looks for the answer key in what goes to the model.** ``hidden`` values (the task's
  expected answer and its source values) must not reach the model in a system message or
  before its first turn; such a request is refused and marks the run. Which role first
  carried an ``answers`` value is logged, without the value.
- **Logs tokens per call, never a prompt.** ``log_path`` gets one JSON line a call: counts,
  timings and the refusal, if any. Bodies stay out of it.

It uses ``http.client`` and not ``urllib``: ``urllib`` follows a redirect with the
``Authorization`` header still on it, which would hand the key to whatever host the answer
named. Here a 3xx is refused, and the key is scrubbed from any error body before it goes on.

    with ModelRelay(upstream_base=..., api_key=..., model=..., token_budget=..., log_path=...) as relay:
        ...  # point the eval's client at relay.base_url, with relay.local_token as its key
"""

from __future__ import annotations

import hmac
import http.client
import json
import os
import secrets
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

__all__ = ["MAX_CALL_OUTPUT_TOKENS", "ModelRelay", "SESSION_HEADER", "parse_upstream", "scan_files", "scan_tree"]

# The header verifiers' client names a rollout by; read here, never forwarded.
SESSION_HEADER = "X-Session-ID"

# One answer's token cap. A reasoning model spends part of it thinking before it writes; at
# 4096, Nemotron 3 Nano thought through the whole budget and answered nothing (measured
# 2026-10-27, examples/nemotron-agent/model.go), so the relay allows what that example does.
MAX_CALL_OUTPUT_TOKENS = 16384

# The largest request forwarded. A long attempt's context is well under this.
MAX_REQUEST_BYTES = 16 << 20

_UPSTREAM_TIMEOUT_S = 600.0
_CHUNK = 64 << 10
_LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def parse_upstream(base: str) -> Tuple[str, str, int, str]:
    """(scheme, host, port, path prefix) of an OpenAI-compatible base URL. Plain HTTP is
    refused except to this machine: a key must not cross a network in the clear."""
    parts = urlsplit(base)
    if parts.username or parts.password or parts.query or parts.fragment or not parts.hostname:
        raise ValueError("the upstream base must be a plain URL: scheme, host, optional port and path")
    if parts.scheme == "https":
        port = parts.port or 443
    elif parts.scheme == "http" and parts.hostname in _LOOPBACK:
        port = parts.port or 80
    else:
        raise ValueError(f"the upstream base must be https (plain http only to this machine), not {parts.scheme}://{parts.hostname}")
    return parts.scheme, parts.hostname, port, parts.path.rstrip("/")


def _forms(values: Iterable[str]) -> List[str]:
    out = set()
    for value in values:
        out.update((value, value.upper(), value.replace("-", ""), value.replace("-", "").upper()))
    return sorted(v for v in out if v)


def _usage_tokens(usage: Any) -> Optional[Tuple[int, int, int, int]]:
    """(prompt, completion, total, cached) from an OpenAI-shaped usage object, or None if it
    holds no numbers. A prompt-only count is not usage: the answer's tokens would go
    uncounted. ``prompt`` includes the cached tokens (OpenAI's meaning), which
    ``prompt_tokens_details.cached_tokens`` names; a missing or absurd cached count is 0."""
    if not isinstance(usage, dict):
        return None
    prompt, completion = usage.get("prompt_tokens"), usage.get("completion_tokens")
    if not isinstance(prompt, int) or not isinstance(completion, int) or prompt < 0 or completion < 0:
        return None
    total = usage.get("total_tokens")
    if not isinstance(total, int) or total < prompt + completion:
        total = prompt + completion
    details = usage.get("prompt_tokens_details")
    cached = details.get("cached_tokens") if isinstance(details, dict) else 0
    if not isinstance(cached, int) or isinstance(cached, bool) or cached < 0 or cached > prompt:
        cached = 0
    return prompt, completion, total, cached


class _RelayHTTPServer(ThreadingHTTPServer):
    # Admit a burst while the accept loop is scheduled out. The kernel caps this
    # backlog; the standard library's older default of five loses concurrent calls
    # before the relay can reserve or refuse their budgets.
    request_queue_size = socket.SOMAXCONN


class _SSEUsage:
    """Reads ``data:`` lines out of a stream's bytes as they pass, keeping the last usage."""

    def __init__(self) -> None:
        self._tail = b""
        self.usage: Optional[Tuple[int, int, int, int]] = None
        self.finished = False

    def feed(self, chunk: bytes) -> None:
        lines = (self._tail + chunk).split(b"\n")
        self._tail = lines.pop()
        for line in lines:
            self._line(line.rstrip(b"\r"))

    def _line(self, line: bytes) -> None:
        if not line.startswith(b"data:"):
            return
        data = line[5:].strip()
        if data == b"[DONE]":
            self.finished = True
            return
        if b'"usage"' not in data:
            return
        try:
            event = json.loads(data)
        except ValueError:
            return
        tokens = _usage_tokens(event.get("usage")) if isinstance(event, dict) else None
        if tokens is not None:
            self.usage = tokens


class ModelRelay:
    """The server; a context manager that starts it on 127.0.0.1 and stops it."""

    def __init__(
        self,
        *,
        upstream_base: str,
        api_key: str,
        model: str,
        token_budget: int,
        log_path: str,
        attempt_budget: Optional[int] = None,
        hidden: Iterable[str] = (),
        answers: Iterable[str] = (),
        max_call_output_tokens: int = MAX_CALL_OUTPUT_TOKENS,
        usd_budget: Optional[float] = None,
        price_in: float = 0.0,
        price_cached: float = 0.0,
        price_out: float = 0.0,
    ) -> None:
        # Checked here, without echoing the value: http.client quotes a bad header value in
        # its exception, which would put the key in a traceback.
        if not api_key or not all(33 <= ord(c) < 127 for c in api_key):
            raise ValueError("the API key is empty or holds a space, a control character or a non-ASCII character")
        if token_budget <= 0:
            raise ValueError("the token budget must be positive")
        if usd_budget is not None and (usd_budget <= 0 or min(price_in, price_cached) < 0 or price_out <= 0):
            raise ValueError("a dollar budget needs a positive budget and non-negative prices with a positive output price")
        self._scheme, self._host, self._port, self._prefix = parse_upstream(upstream_base)
        self._key = api_key
        self._key_bytes = api_key.encode("utf-8")
        self.model = model
        self.token_budget = token_budget
        self.attempt_budget = attempt_budget
        self.max_call_output_tokens = max_call_output_tokens
        self.usd_budget = usd_budget
        # USD per million tokens: list price for uncached input, the cached price for the
        # cached part, and the output price.
        self.prices = {"input": price_in, "cached_input": price_cached, "output": price_out}
        self.local_token = secrets.token_urlsafe(32)
        self._hidden = _forms(hidden)
        self._answers = _forms(answers)
        self._lock = threading.Lock()
        self._log = open(log_path, "a", encoding="utf-8")
        self._calls = 0
        self._reserved = 0
        self._usd_reserved = 0.0
        self._by_attempt: Dict[str, int] = {}  # tokens used and reserved, by session id
        self.refused_attempts: Dict[str, str] = {}  # session id -> the budget that stopped it
        self.used = {"prompt_tokens": 0, "cached_prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "charged_without_usage": 0}
        self.usd_spent = 0.0
        self.counts = {"forwarded": 0, "refused": 0, "upstream_errors": 0, "usage_missing": 0}
        self.budget_reached = False
        self.answer_key_seen = False
        self._server: Optional[ThreadingHTTPServer] = None

    @property
    def base_url(self) -> str:
        assert self._server is not None, "not started"
        return f"http://127.0.0.1:{self._server.server_address[1]}/v1"

    def totals(self) -> Dict[str, Any]:
        """What the run used, from the API's own usage fields."""
        with self._lock:
            return {
                **self.used,
                **self.counts,
                "tokens_counted": self.used["total_tokens"] + self.used["charged_without_usage"],
                "token_budget": self.token_budget,
                "usd_spent": round(self.usd_spent, 9),
                "usd_budget": self.usd_budget,
                "budget_reached": self.budget_reached,
                "answer_key_seen": self.answer_key_seen,
            }

    # --- the budget ------------------------------------------------------------------

    def _spent(self) -> int:
        return self.used["total_tokens"] + self.used["charged_without_usage"]

    def cost_usd(self, prompt: int, cached: int, completion: int, unknown: int = 0) -> float:
        """What tokens cost at the stated prices: cached input at its cached price, the rest
        of the input at the input price, and tokens of unknown kind at the output price, the
        dearer."""
        p = self.prices
        return ((prompt - cached) * p["input"] + cached * p["cached_input"] + (completion + unknown) * p["output"]) / 1e6

    def _reserve(self, tokens: int, attempt: str) -> Optional[str]:
        """Takes tokens (and dollars) from every budget, or names the one that refuses."""
        usd = tokens * max(self.prices.values()) / 1e6
        with self._lock:
            refused = None
            if self._spent() + self._reserved + tokens > self.token_budget:
                refused = "budget"
                self.budget_reached = True
            elif self.usd_budget is not None and self.usd_spent + self._usd_reserved + usd > self.usd_budget:
                refused = "dollar_budget"
                self.budget_reached = True
            elif self.attempt_budget is not None and self._by_attempt.get(attempt, 0) + tokens > self.attempt_budget:
                refused = "attempt_budget"
            if refused is not None:
                self.refused_attempts.setdefault(attempt, refused)
                return refused
            self._reserved += tokens
            self._usd_reserved += usd
            self._by_attempt[attempt] = self._by_attempt.get(attempt, 0) + tokens
            return None

    def _settle(self, reservation: int, attempt: str, tokens: Optional[Tuple[int, int, int, int]], *, charge_unknown: bool) -> None:
        with self._lock:
            self._reserved -= reservation
            self._usd_reserved -= reservation * max(self.prices.values()) / 1e6
            kept = 0
            if tokens is not None:
                prompt, completion, total, cached = tokens
                self.usd_spent += self.cost_usd(prompt, cached, completion)
                self.used["prompt_tokens"] += prompt
                self.used["cached_prompt_tokens"] += cached
                self.used["completion_tokens"] += completion
                self.used["total_tokens"] += total
                kept = total
            elif charge_unknown:
                self.used["charged_without_usage"] += reservation
                self.usd_spent += self.cost_usd(0, 0, 0, reservation)
                self.counts["usage_missing"] += 1
                kept = reservation
            self._by_attempt[attempt] += kept - reservation

    # --- the answer key ---------------------------------------------------------------

    def _check_hidden(self, body: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Whether a hidden value reached the model where only a leak could put it, and the
        role of the first message holding an expected answer. After the model's first turn
        a tool result can hold a source value it found, or an answer it worked out; in a
        system or user message, or before that turn, it can only have come from us."""
        leak, first_role, seen_assistant = False, None, False
        messages = body.get("messages")
        for message in messages if isinstance(messages, list) else []:
            if not isinstance(message, dict):
                continue
            role = message.get("role")
            text = json.dumps(message, ensure_ascii=False, default=str)
            if any(v in text for v in self._hidden) and (role in ("system", "user") or not seen_assistant):
                leak = True
            if first_role is None and any(v in text for v in self._answers):
                first_role = str(role)
            if role == "assistant":
                seen_assistant = True
        rest = json.dumps({k: v for k, v in body.items() if k != "messages"}, ensure_ascii=False, default=str)
        return leak or any(v in rest for v in self._hidden), first_role

    # --- the upstream ------------------------------------------------------------------

    def _connect(self) -> http.client.HTTPConnection:
        if self._scheme == "https":
            return http.client.HTTPSConnection(self._host, self._port, timeout=_UPSTREAM_TIMEOUT_S, context=ssl.create_default_context())
        return http.client.HTTPConnection(self._host, self._port, timeout=_UPSTREAM_TIMEOUT_S)

    def _scrub(self, data: bytes) -> bytes:
        return data.replace(self._key_bytes, b"[key removed by the relay]")

    def __enter__(self) -> "ModelRelay":
        relay = self

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

            def _refuse(self, status: int, reason: str, message: str) -> None:
                with relay._lock:
                    relay.counts["refused"] += 1
                relay._note({"status": status, "refused": reason, "attempt": self.headers.get(SESSION_HEADER) or ""})
                self._json(status, {"error": {"message": message, "type": "plimsoll_relay_refused", "code": reason}})

            def _authorized(self) -> bool:
                sent = self.headers.get("Authorization") or ""
                return hmac.compare_digest(sent.encode("utf-8"), f"Bearer {relay.local_token}".encode("utf-8"))

            def do_GET(self) -> None:
                if self.path.rstrip("/") == "/v1/models":
                    # Answered here, with no upstream call and no context window, as the
                    # scripted server answers, so the harness keeps its default compaction.
                    # It says only the run's model, so it takes no token.
                    self._json(200, {"object": "list", "data": [{"id": relay.model, "object": "model", "created": 0, "owned_by": "relay"}]})
                else:
                    self._refuse(404, "route", "this relay serves POST /v1/chat/completions and GET /v1/models")

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                if length > MAX_REQUEST_BYTES:
                    self.close_connection = True
                    self._refuse(413, "size", "the request is larger than the relay forwards")
                    return
                raw = self.rfile.read(length)
                if not self._authorized():
                    self._refuse(401, "auth", "this relay takes the run's local token")
                    return
                if self.path != "/v1/chat/completions":
                    self._refuse(404, "route", "this relay serves POST /v1/chat/completions and GET /v1/models")
                    return
                try:
                    body = json.loads(raw or b"{}")
                except ValueError:
                    body = None
                if not isinstance(body, dict):
                    self._refuse(400, "body", "the request is not a JSON object")
                    return
                if body.get("model") != relay.model:
                    self._refuse(400, "model", "this relay serves one model, the run's")
                    return
                leak, answer_role = relay._check_hidden(body)
                if leak:
                    with relay._lock:
                        relay.answer_key_seen = True
                    self._refuse(403, "answer_key", "a hidden value reached a request to the model")
                    return
                asked = body.get("max_tokens")
                cap = relay.max_call_output_tokens
                body["max_tokens"] = min(asked, cap) if isinstance(asked, int) and asked > 0 else cap
                body.pop("max_completion_tokens", None)
                if body.get("stream"):
                    # Without it a stream carries no usage, and the call would count as
                    # its whole reservation.
                    options = body.get("stream_options")
                    body["stream_options"] = {**(options if isinstance(options, dict) else {}), "include_usage": True}
                payload = json.dumps(body).encode("utf-8")
                reservation = len(payload) + body["max_tokens"]
                attempt = self.headers.get(SESSION_HEADER) or ""
                refused = relay._reserve(reservation, attempt)
                if refused is not None:
                    self._refuse(403, refused, {"attempt_budget": "this attempt's token budget is reached", "dollar_budget": "the run's dollar budget is reached"}.get(refused, "the run's token budget is reached"))
                    return
                self._forward(payload, bool(body.get("stream")), reservation, answer_role, attempt)

            def _forward(self, payload: bytes, stream: bool, reservation: int, answer_role: Optional[str], attempt: str) -> None:
                started = time.monotonic()
                note: Dict[str, Any] = {"stream": stream, "reserved": reservation, "answer_first_role": answer_role, "attempt": attempt}
                tokens: Optional[Tuple[int, int, int, int]] = None
                charge_unknown = True
                settled = False

                def settle() -> None:
                    # Before the answer goes back, so a caller that has its answer reads
                    # totals that include it; a stream settles when it ends.
                    nonlocal settled
                    if not settled:
                        settled = True
                        relay._settle(reservation, attempt, tokens, charge_unknown=charge_unknown)

                connection = relay._connect()
                try:
                    connection.request(
                        "POST",
                        f"{relay._prefix}/chat/completions",
                        body=payload,
                        headers={
                            "Authorization": f"Bearer {relay._key}",
                            "Content-Type": "application/json",
                            "Accept": "text/event-stream" if stream else "application/json",
                            "Accept-Encoding": "identity",
                            "User-Agent": "plimsoll-verifiers-relay",
                        },
                    )
                    answer = connection.getresponse()
                    note["status"] = answer.status
                    if answer.status >= 300:
                        # Nothing was generated for a refused request, so it costs nothing
                        # here; a redirect is never followed.
                        charge_unknown = answer.status >= 500
                        data = relay._scrub(answer.read(MAX_REQUEST_BYTES))
                        with relay._lock:
                            relay.counts["upstream_errors"] += 1
                        status = 502 if 300 <= answer.status < 400 else answer.status
                        settle()
                        self.send_response(status)
                        self.send_header("Content-Type", answer.getheader("Content-Type") or "application/json")
                        self.send_header("Content-Length", str(len(data)))
                        self.end_headers()
                        self.wfile.write(data)
                        return
                    with relay._lock:
                        relay.counts["forwarded"] += 1
                    if "text/event-stream" in (answer.getheader("Content-Type") or ""):
                        tokens = self._pass_stream(answer, note, started)
                    else:
                        data = answer.read()
                        try:
                            parsed = json.loads(data)
                        except ValueError:
                            parsed = None
                        tokens = _usage_tokens(parsed.get("usage")) if isinstance(parsed, dict) else None
                        settle()
                        self.send_response(200)
                        self.send_header("Content-Type", answer.getheader("Content-Type") or "application/json")
                        self.send_header("Content-Length", str(len(data)))
                        self.end_headers()
                        self.wfile.write(data)
                except (OSError, http.client.HTTPException) as e:
                    note["failed"] = type(e).__name__
                    self.close_connection = True
                    if "status" not in note:
                        note["status"] = 502
                        settle()
                        self._json_quietly(502, {"error": {"message": f"the relay could not reach the upstream: {type(e).__name__}", "type": "plimsoll_relay_upstream"}})
                finally:
                    connection.close()
                    if tokens is None and charge_unknown:
                        note["usage_missing"] = True
                    settle()
                    if tokens is not None:
                        note.update(prompt_tokens=tokens[0], completion_tokens=tokens[1], total_tokens=tokens[2], cached_tokens=tokens[3])
                    note["ms"] = round((time.monotonic() - started) * 1000)
                    relay._note(note)

            def _json_quietly(self, status: int, body: Dict[str, Any]) -> None:
                try:
                    self._json(status, body)
                except OSError:
                    pass

            def _pass_stream(self, answer: http.client.HTTPResponse, note: Dict[str, Any], started: float) -> Optional[Tuple[int, int, int, int]]:
                """Each piece goes on as it arrives; a reader that leaves ends the call, which
                keeps the reservation, since the API may bill what it generated."""
                self.send_response(200)
                self.send_header("Content-Type", answer.getheader("Content-Type") or "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                reader = _SSEUsage()
                pieces = 0
                while True:
                    chunk = answer.read1(_CHUNK)
                    if not chunk:
                        break
                    pieces += 1
                    if pieces == 1:
                        note["first_byte_ms"] = round((time.monotonic() - started) * 1000)
                    reader.feed(chunk)
                    self.wfile.write(chunk)
                    self.wfile.flush()
                note["pieces"] = pieces
                note["finished"] = reader.finished
                return reader.usage

        self._server = _RelayHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        threading.Thread(target=self._server.serve_forever, args=(0.05,), name="model-relay", daemon=True).start()
        return self

    def __exit__(self, *exc: Any) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        with self._lock:
            self._log.close()

    def _note(self, entry: Dict[str, Any]) -> None:
        with self._lock:
            self._calls += 1
            entry = {"n": self._calls, "at": round(time.time(), 3), **entry, "used_after": self._spent(), "budget": self.token_budget, "usd_after": round(self.usd_spent, 9)}
            if not self._log.closed:
                self._log.write(json.dumps(entry, sort_keys=True) + "\n")
                self._log.flush()


def scan_tree(root: str, secret: str) -> List[str]:
    """Every file under root holding secret's bytes, by relative path. The caller keeps the
    secret; only names come back, so a hit can be reported."""
    needle = secret.encode("utf-8")
    hits: List[str] = []
    for directory, _, names in os.walk(root):
        for name in names:
            path = os.path.join(directory, name)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            with open(path, "rb") as f:
                if needle in f.read():
                    hits.append(os.path.relpath(path, root))
    return sorted(hits)


def scan_files(paths: Iterable[str], secret: str) -> List[str]:
    """The given files (outside the run's directory, such as the driver's own log) holding
    secret's bytes, by the path as given. A file that does not exist holds nothing."""
    needle = secret.encode("utf-8")
    hits: List[str] = []
    for path in paths:
        try:
            with open(path, "rb") as f:
                if needle in f.read():
                    hits.append(path)
        except OSError:
            continue
    return hits
