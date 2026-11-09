# The -live run: the OpenAI Python library, as it ships, against a real OpenAI-compatible API.
# Nothing here names plimsoll or the provider's host: the library finds its base URL and a
# dummy key in the environment, set by the grant profile's sdk_env, and the broker outside the
# sandbox adds the real key. max_retries=0 keeps the run to exactly the calls below, and
# MAX_TOKENS bounds each answer: the program that starts this refuses to run if these calls at
# list price could pass its budget, and a test holds this file to the numbers it uses.
import openai
from openai import OpenAI

from live_scan import scan
from report import now_ms, report

MODEL = "nvidia/Nemotron-3_5-Lightning"
MAX_TOKENS = 64
PROMPT = "Say hello in five words."

client = OpenAI(max_retries=0, timeout=60)
calls = {}
messages = [{"role": "user", "content": PROMPT}]


def failed(e):
    return {"status": e.status_code, "error": type(e).__name__, "body": e.response.text[:400]}


# 1. A plain chat call.
try:
    raw = client.chat.completions.with_raw_response.create(model=MODEL, messages=messages, max_tokens=MAX_TOKENS)
    answer = raw.parse()
    choice = answer.choices[0]
    calls["plain"] = {"status": raw.status_code, "model": answer.model, "answer": choice.message.content or "", "finish": choice.finish_reason,
                      "input_tokens": answer.usage.prompt_tokens, "output_tokens": answer.usage.completion_tokens}
except openai.APIStatusError as e:
    calls["plain"] = failed(e)

# 2. The same call streamed: when each piece arrived, as the library hands it over. A reasoning
# model's pieces can all be its thinking, so a piece is counted whether or not it holds text.
try:
    started = now_ms()
    stream = client.chat.completions.create(model=MODEL, messages=messages, max_tokens=MAX_TOKENS, stream=True,
                                            stream_options={"include_usage": True})
    pieces, usage, text = [], None, ""
    for chunk in stream:
        if chunk.usage:
            usage = chunk.usage
        if chunk.choices:
            pieces.append({"at_ms": now_ms()})
            text += chunk.choices[0].delta.content or ""
    calls["stream"] = {"status": stream.response.status_code, "content_type": stream.response.headers.get("content-type"), "started_ms": started,
                       "pieces": pieces, "answer": text, "input_tokens": usage.prompt_tokens if usage else None,
                       "output_tokens": usage.completion_tokens if usage else None}
except openai.APIStatusError as e:
    calls["stream"] = failed(e)

# 3. A route the profile does not allow: the broker must refuse it, so it costs nothing.
try:
    client.embeddings.create(model=MODEL, input="hello")
    calls["refused"] = {"error": None}
except openai.APIStatusError as e:
    calls["refused"] = {**failed(e), "x_should_retry": e.response.headers.get("x-should-retry")}

calls["key_scan"] = scan()
report(calls, {"openai": openai.__version__})
