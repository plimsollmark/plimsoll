# The -live run: the Anthropic Python library, as it ships, against Anthropic's API. Nothing
# here names plimsoll: the library finds its base URL and a dummy key in the environment, set by
# the grant profile's sdk_env, and the broker outside the sandbox adds the real key as a bearer
# token. max_retries=0 keeps the run to exactly the calls below, and MAX_TOKENS bounds each
# answer: the program that starts this refuses to run if these calls at list price could pass
# its budget, and a test holds this file to the numbers it uses.
import anthropic

from live_scan import scan
from report import now_ms, report

MODEL = "claude-haiku-5-5"
MAX_TOKENS = 64
PROMPT = "Say hello in five words."

client = anthropic.Anthropic(max_retries=0, timeout=60)
calls = {}
messages = [{"role": "user", "content": PROMPT}]


def failed(e):
    return {"status": e.status_code, "error": type(e).__name__, "body": e.response.text[:400]}


# 1. A plain messages call.
try:
    raw = client.messages.with_raw_response.create(model=MODEL, max_tokens=MAX_TOKENS, messages=messages)
    answer = raw.parse()
    calls["plain"] = {"status": raw.status_code, "model": answer.model, "answer": "".join(b.text for b in answer.content if b.type == "text"),
                      "finish": answer.stop_reason, "input_tokens": answer.usage.input_tokens, "output_tokens": answer.usage.output_tokens}
except anthropic.APIStatusError as e:
    calls["plain"] = failed(e)

# 2. The same call streamed: when each event arrived, as the library hands it over.
try:
    started = now_ms()
    stream = client.messages.create(model=MODEL, max_tokens=MAX_TOKENS, messages=messages, stream=True)
    pieces, text, input_tokens, output_tokens = [], "", None, None
    for event in stream:
        pieces.append({"at_ms": now_ms()})
        if event.type == "message_start":
            input_tokens = event.message.usage.input_tokens
        elif event.type == "content_block_delta":
            text += getattr(event.delta, "text", "") or ""
        elif event.type == "message_delta":
            output_tokens = event.usage.output_tokens
    calls["stream"] = {"status": stream.response.status_code, "content_type": stream.response.headers.get("content-type"), "started_ms": started,
                       "pieces": pieces, "answer": text, "input_tokens": input_tokens, "output_tokens": output_tokens}
except anthropic.APIStatusError as e:
    calls["stream"] = failed(e)

# 3. A route the profile does not allow: the broker must refuse it, so it costs nothing.
try:
    client.messages.count_tokens(model=MODEL, messages=messages)
    calls["refused"] = {"error": None}
except anthropic.APIStatusError as e:
    calls["refused"] = {**failed(e), "x_should_retry": e.response.headers.get("x-should-retry")}

calls["key_scan"] = scan()
report(calls, {"anthropic": anthropic.__version__})
