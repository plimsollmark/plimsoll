"""Checks made before anything is sent, ported from the Go package ``sandbox``
(ValidateRequest, ValidateProjectRequest, ValidateModuleRequest,
SoftwareRule.Validate, MergeSoftwareRules) and from ``client.New``'s base URL check.

A failure is InvalidRequestError marked not dispatched with reason ``request``:
the request never left the process.
"""

from __future__ import annotations

import ipaddress
import math
import re
from typing import Any, Iterable, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import urlsplit, urlunsplit

from .errors import InsecureHTTPError, InvalidBaseURLError, InvalidRequestError
from .types import SoftwareRule

MAX_CODE_BYTES = 256 << 10
MAX_PROJECT_BYTES = 4 << 20
MAX_PROJECT_FILES = 200
MAX_PROJECT_STEPS = 20
MAX_PROJECT_ARTIFACTS = 100
MAX_PROJECT_PATH_BYTES = 1024
MAX_PROJECT_STEP_BYTES = 16 << 10

MAX_MODULE_ROWS = 100_000
MAX_MODULE_ROW_WIDTH = 64
MAX_MODULE_STEPS = 1_000_000
MAX_MODULE_RESULT_BYTES = 8 << 20
_MODULE_RESULT_HEADER = 20

_MODULE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_TRACE_ID = re.compile(r"[A-Za-z0-9._:-]{1,64}")
_IDENTITY_CHARS = re.compile(r"[A-Za-z0-9._:/@+-]+")
FLOORS = ("process", "container", "kernel", "vm")

INT32_MAX = (1 << 31) - 1
UINT32_MAX = (1 << 32) - 1

FilesArg = Union[Mapping[str, str], Iterable[Tuple[str, str]], None]


def invalid(message: str) -> InvalidRequestError:
    return InvalidRequestError(f"plimsoll: invalid request: {message}", not_dispatched="request")


# --- base URL ----------------------------------------------------------------


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_base_url(raw: Any, insecure_http: bool) -> str:
    """client.New's check: an absolute http or https URL with a host, no
    userinfo, query or fragment, and cleartext only to loopback unless the caller
    opted in. Returns the URL with a lowercase scheme and no trailing slash."""
    if not isinstance(raw, str) or raw == "" or raw != raw.strip():
        raise InvalidBaseURLError("plimsoll: base URL must be non-empty and contain no surrounding whitespace")
    try:
        u = urlsplit(raw)
        hostname = u.hostname
        u.port  # raises ValueError on a malformed port
    except ValueError:
        raise InvalidBaseURLError("plimsoll: base URL must be an absolute HTTP or HTTPS URL") from None
    scheme = u.scheme.lower()
    if not u.scheme or not u.netloc or not hostname:
        raise InvalidBaseURLError("plimsoll: base URL must be an absolute HTTP or HTTPS URL")
    if scheme not in ("http", "https"):
        raise InvalidBaseURLError("plimsoll: base URL scheme must be http or https")
    if "@" in u.netloc or u.query or "?" in raw or "#" in raw:
        raise InvalidBaseURLError("plimsoll: userinfo, query, and fragment are not permitted in the base URL")
    if any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in raw):
        raise InvalidBaseURLError("plimsoll: base URL must not contain whitespace or control characters")
    if scheme == "http" and not _is_loopback(hostname) and not insecure_http:
        raise InsecureHTTPError("plimsoll: cleartext HTTP to a non-loopback plimsoll requires insecure_http=True")
    return urlunsplit((scheme, u.netloc, u.path.rstrip("/"), "", ""))


# --- request pieces ------------------------------------------------------------


def _utf8(s: Any, what: str) -> bytes:
    if not isinstance(s, str):
        raise invalid(f"{what} must be a str")
    try:
        return s.encode("utf-8")
    except UnicodeEncodeError:
        raise invalid(f"{what} must be valid UTF-8") from None


def floor(minimum: Optional[str]) -> str:
    """The wire form of a floor: "" for none, else one of process, container,
    kernel, vm."""
    if minimum is None or minimum == "":
        return ""
    if minimum not in FLOORS:
        raise invalid("minimum isolation must be process, container, kernel, or vm")
    return minimum


def trace_id(tid: Optional[str]) -> str:
    """The daemon drops a trace ID outside [A-Za-z0-9._:-]{1,64} silently, which
    would leave a caller believing its logs correlate; refuse it here instead."""
    if tid is None or tid == "":
        return ""
    if not isinstance(tid, str) or not _TRACE_ID.fullmatch(tid):
        raise invalid("trace ID must be 1 to 64 characters of [A-Za-z0-9._:-]")
    return tid


def grant_profile(p: Optional[str]) -> str:
    if p is None:
        return ""
    _utf8(p, "grant profile")
    return p


def timeout_ms(seconds: Optional[float]) -> int:
    """A run's budget in whole milliseconds for the int32 wire field; 0 asks for
    the daemon's default. Clamped, never wrapped (client.timeoutMs)."""
    if seconds is None:
        return 0
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or math.isnan(seconds):
        raise invalid("timeout must be a number of seconds")
    if seconds <= 0:
        return 0
    if seconds * 1000 >= INT32_MAX:
        return INT32_MAX
    ms = round(seconds * 1_000_000) // 1000
    return ms if ms > 0 else 1


def duration_ms(seconds: Optional[float], what: str) -> int:
    """A session lifetime or idle timeout for the uint32 wire field; 0 takes the
    daemon's."""
    if seconds is None:
        return 0
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or math.isnan(seconds):
        raise invalid(f"{what} must be a number of seconds")
    if seconds <= 0:
        return 0
    if seconds * 1000 >= UINT32_MAX:
        return UINT32_MAX
    ms = round(seconds * 1_000_000) // 1000
    return ms if ms > 0 else 1


def software_rule(rule: Optional[SoftwareRule]) -> Optional[SoftwareRule]:
    """SoftwareRule.Validate: exact with one identity, or approved with 1 to 32,
    each 1 to 256 bytes of [A-Za-z0-9._:/@+-], no duplicates."""
    if rule is None:
        return None
    if not isinstance(rule, SoftwareRule):
        raise invalid("software rule must be a SoftwareRule")
    ids = rule.identities
    if (
        rule.mode not in ("exact", "approved")
        or not isinstance(ids, tuple)
        or len(ids) == 0
        or len(ids) > 32
        or (rule.mode == "exact" and len(ids) != 1)
    ):
        raise invalid("software rule needs exact with one identity or approved with 1 to 32 identities")
    seen = set()
    for i in ids:
        if not isinstance(i, str) or len(i) == 0 or len(i.encode("utf-8", "surrogatepass")) > 256 or i in seen:
            raise invalid("software identity is empty, too long or duplicated")
        if not _IDENTITY_CHARS.fullmatch(i):
            raise invalid("software identity contains an invalid character")
        seen.add(i)
    return rule


def merge_rules(a: Optional[SoftwareRule], b: Optional[SoftwareRule]) -> Optional[SoftwareRule]:
    """MergeSoftwareRules: a session's rule and a call's both apply, so the call
    runs under their intersection; neither can be weakened."""
    software_rule(a)
    software_rule(b)
    if a is None:
        return b
    if b is None:
        return a
    ids = tuple(i for i in a.identities if i in b.identities)
    if not ids:
        raise invalid("the call's software rule shares no identity with the session's")
    return SoftwareRule("exact" if len(ids) == 1 else "approved", ids)


def rule_wire(rule: Optional[SoftwareRule]) -> Optional[dict]:
    if rule is None:
        return None
    return {"mode": rule.mode, "identities": list(rule.identities)}


def code(c: Any) -> str:
    b = _utf8(c, "code")
    if c == "":
        raise invalid("code is required")
    if "\x00" in c:
        raise invalid("code must be valid UTF-8 without NUL bytes")
    if len(b) > MAX_CODE_BYTES:
        raise invalid(f"code exceeds {MAX_CODE_BYTES} bytes")
    return c


def _project_path(kind: str, name: Any) -> str:
    b = _utf8(name, f"{kind} path")
    if len(b) > MAX_PROJECT_PATH_BYTES:
        raise invalid(f"{kind} path exceeds {MAX_PROJECT_PATH_BYTES} bytes")
    # Go requires path.Clean(name) == name, not "." or "..", not absolute, not
    # escaping, with no control character or backslash. Clean leaves a name alone
    # exactly when no segment is empty, "." or "..", which is the check below.
    unsafe = (
        name == ""
        or any(seg in ("", ".", "..") for seg in name.split("/"))
        or "\\" in name
        or any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in name)
    )
    if unsafe:
        raise invalid(f"unsafe {kind} path {name!r}")
    return name


def _strings(v: Any, what: str) -> List[str]:
    if isinstance(v, (str, bytes)):
        raise invalid(f"{what} must be a list of strings, not a single string")
    try:
        out = list(v)
    except TypeError:
        raise invalid(f"{what} must be a list of strings") from None
    return out


def _files(files: FilesArg) -> List[Tuple[str, str]]:
    if files is None:
        return []
    if isinstance(files, Mapping):
        pairs = list(files.items())
    else:
        if isinstance(files, (str, bytes)):
            raise invalid("files must be a mapping of path to content or a list of (path, content) pairs")
        pairs = []
        for item in files:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                raise invalid("files must be a mapping of path to content or a list of (path, content) pairs")
            pairs.append((item[0], item[1]))
    return pairs


LANGUAGES = ("javascript", "python")


def _file_list(files: FilesArg) -> List[dict]:
    """The rule for files written into the work directory, a project's or a cell's."""
    pairs = _files(files)
    if len(pairs) > MAX_PROJECT_FILES:
        raise invalid(f"too many files (max {MAX_PROJECT_FILES})")
    total = 0
    seen = set()
    for path, content in pairs:
        _project_path("file", path)
        if isinstance(content, (bytes, bytearray)):
            raise invalid(f"file {path!r} content must be str: the protocol carries text files only")
        size = len(_utf8(content, f"file {path!r} content"))
        if path in seen:
            raise invalid(f"duplicate file path {path!r}")
        seen.add(path)
        if size > MAX_PROJECT_BYTES - total:
            raise invalid(f"files exceed {MAX_PROJECT_BYTES} bytes")
        total += size
    return [{"path": p, "content": c} for p, c in pairs]


def cell(language: Any, c: Any, files: FilesArg) -> dict:
    """ValidateCellRequest, returning the payload's wire form."""
    if language not in LANGUAGES:
        raise invalid(f"unknown cell language {language!r} (want javascript or python)")
    out: dict = {"language": language, "code": code(c)}
    file_list = _file_list(files)
    if file_list:
        out["files"] = file_list
    return out


def project(files: FilesArg, steps: Sequence[str], artifacts: Sequence[str]) -> dict:
    """ValidateProjectRequest, returning the payload's wire form."""
    step_list = _strings(steps, "steps")
    if len(step_list) == 0:
        raise invalid("at least one step is required")
    if len(step_list) > MAX_PROJECT_STEPS:
        raise invalid(f"too many steps (max {MAX_PROJECT_STEPS})")
    for i, s in enumerate(step_list):
        b = _utf8(s, f"step {i}")
        if "\x00" in s:
            raise invalid(f"step {i} must be valid UTF-8 without NUL bytes")
        if len(b) > MAX_PROJECT_STEP_BYTES:
            raise invalid(f"step {i} exceeds {MAX_PROJECT_STEP_BYTES} bytes")
    file_list = _file_list(files)
    artifact_list = _strings(artifacts, "artifacts")
    if len(artifact_list) > MAX_PROJECT_ARTIFACTS:
        raise invalid(f"too many artifacts (max {MAX_PROJECT_ARTIFACTS})")
    seen_artifacts = set()
    for a in artifact_list:
        _project_path("artifact", a)
        if a in seen_artifacts:
            raise invalid(f"duplicate artifact path {a!r}")
        seen_artifacts.add(a)
    out: dict = {"steps": step_list}
    if file_list:
        out["files"] = file_list
    if artifact_list:
        out["artifacts"] = artifact_list
    return out


def _number(v: Any, what: str) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise invalid(f"{what} must be numbers")
    try:
        return float(v)
    except OverflowError:
        raise invalid(f"{what} must be finite") from None


def module(model: Any, rows: Any, end_time: Any, step: Any) -> dict:
    """ValidateModuleRequest, returning the payload's wire form."""
    if not isinstance(model, str) or not _MODULE_ID.fullmatch(model):
        raise invalid("model must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    if isinstance(rows, (str, bytes)):
        raise invalid("rows must be a list of lists of numbers")
    table: List[List[float]] = []
    try:
        for row in rows:
            if isinstance(row, (str, bytes)):
                raise invalid("rows must be a list of lists of numbers")
            table.append([_number(x, "row values") for x in row])
    except TypeError:
        raise invalid("rows must be a list of lists of numbers") from None
    if len(table) == 0:
        raise invalid("at least one row is required")
    if len(table) > MAX_MODULE_ROWS:
        raise invalid(f"too many rows (max {MAX_MODULE_ROWS})")
    width = len(table[0])
    if width == 0 or width > MAX_MODULE_ROW_WIDTH:
        raise invalid(f"rows must carry 1 to {MAX_MODULE_ROW_WIDTH} values")
    for i, row in enumerate(table):
        if len(row) != width:
            raise invalid(f"row {i} has {len(row)} values, row 0 has {width}")
        for j, v in enumerate(row):
            if not math.isfinite(v):
                raise invalid(f"row {i} value {j} is not finite")
    end_time, step = _number(end_time, "end_time"), _number(step, "step")
    for name, v in (("end_time", end_time), ("step", step)):
        if not (v > 0) or math.isinf(v):
            raise invalid(f"{name} must be positive and finite")
    if end_time / step > MAX_MODULE_STEPS:
        raise invalid(f"end_time/step exceeds {MAX_MODULE_STEPS} steps")
    max_steps = int(end_time / step) + 2
    worst = _MODULE_RESULT_HEADER + len(table) * (4 + 8 * max_steps)
    if worst > MAX_MODULE_RESULT_BYTES:
        raise invalid(
            f"results could reach at least {worst} bytes for {len(table)} rows of up to {max_steps} steps, "
            f"over the {MAX_MODULE_RESULT_BYTES} byte budget; send fewer rows or a shorter horizon"
        )
    return {"model": model, "rows": [{"values": r} for r in table], "endTime": end_time, "step": step}
