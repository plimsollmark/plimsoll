# Agent-style code using the OpenAI Python library exactly as it ships. Nothing here
# names plimsoll: the library finds its base URL and key in the environment
# (OPENAI_BASE_URL and OPENAI_API_KEY), which the grant profile's sdk_env set. The
# with_raw_response and .response accessors are the library's own, used only to read
# back the headers it sent.
import hashlib

import openai
from openai import OpenAI

from report import headers, now_ms, report

client = OpenAI()
calls = {}
messages = [{"role": "user", "content": "Say hello."}]

# 1. A chat call, with a header the profile does not pass: the guest would like to choose
# the organization its calls are billed to.
raw = client.chat.completions.with_raw_response.create(
    model="stub-model", messages=messages,
    extra_headers={"OpenAI-Organization": "org-chosen-by-the-guest"})
answer = raw.parse()
calls["chat"] = {"url": str(raw.http_request.url), "sent": headers(raw.http_request),
                 "status": raw.status_code, "answer": answer.choices[0].message.content}

# 2. The same call streamed: each piece's arrival time, as the library hands it over.
started = now_ms()
stream = client.chat.completions.create(model="stub-model", messages=messages, stream=True)
pieces = []
for chunk in stream:
    pieces.append({"at_ms": now_ms(), "text": chunk.choices[0].delta.content if chunk.choices else None})
calls["stream"] = {"url": str(stream.response.request.url), "sent": headers(stream.response.request),
                   "status": stream.response.status_code, "content_type": stream.response.headers.get("content-type"),
                   "started_ms": started, "pieces": pieces}

# 3. An 8 MiB file upload through the Files API, as multipart. The bytes are the same on
# every run (SHAKE-256 of a fixed phrase), so their digest is too.
data = hashlib.shake_256(b"plimsoll sdk-grants example upload").digest(8 << 20)
raw = client.files.with_raw_response.create(file=("sample.bin", data, "application/octet-stream"), purpose="user_data")
uploaded = raw.parse()
calls["upload"] = {"url": str(raw.http_request.url), "sent": headers(raw.http_request), "status": raw.status_code,
                   "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                   "file_id": uploaded.id, "api_bytes": uploaded.bytes}

# 4. A route the profile does not allow. The stub serves it; the broker must not let
# the call reach it.
try:
    client.embeddings.create(model="stub-embedding", input="hello")
    calls["refused"] = {"error": None}
except openai.APIStatusError as e:
    calls["refused"] = {"url": str(e.request.url), "sent": headers(e.request), "error": type(e).__name__,
                        "status": e.status_code, "x_should_retry": e.response.headers.get("x-should-retry"),
                        "body": e.response.text[:400]}

report(calls, {"openai": openai.__version__})
