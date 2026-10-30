# Agent-style code using the Anthropic Python library exactly as it ships. The library
# reads ANTHROPIC_BASE_URL and ANTHROPIC_API_KEY from the environment, which the grant
# profile's sdk_env set; with_raw_response and .response are the library's own accessors,
# used only to read back the headers it sent.
import anthropic

from report import headers, now_ms, report

client = anthropic.Anthropic()
calls = {}
messages = [{"role": "user", "content": "Say hello."}]

# 1. A messages call. The library sends anthropic-version itself, which the profile
# passes; the anthropic-beta header added here is one it does not.
raw = client.messages.with_raw_response.create(
    model="stub-model", max_tokens=64, messages=messages,
    extra_headers={"anthropic-beta": "plimsoll-example-not-passed"})
answer = raw.parse()
calls["messages"] = {"url": str(raw.http_request.url), "sent": headers(raw.http_request),
                     "status": raw.status_code, "answer": answer.content[0].text}

# 2. The same call streamed: each event's arrival time, as the library hands it over.
started = now_ms()
stream = client.messages.create(model="stub-model", max_tokens=64, messages=messages, stream=True)
pieces = []
for event in stream:
    delta = getattr(event, "delta", None)
    pieces.append({"at_ms": now_ms(), "type": event.type, "text": getattr(delta, "text", None)})
calls["stream"] = {"url": str(stream.response.request.url), "sent": headers(stream.response.request),
                   "status": stream.response.status_code, "content_type": stream.response.headers.get("content-type"),
                   "started_ms": started, "pieces": pieces}

report(calls, {"anthropic": anthropic.__version__})
