"""The answer-key tripwire: find sealed values in what a model under test was sent.

A harness (the program that runs an evaluation) records every request it sends to the model
under test, and lists in a *sealed-values file* what must never be in one: truth labels,
hidden fields, the reference's numbers, the names of planted test files. :func:`scan` walks
every string, object key and number of every recorded request, and the name of every file
and directory recorded, and reports each sealed value it finds by file, place in the request
and the value's id. A report never repeats a sealed value, a name that holds one included,
so it can be published beside the evidence. :func:`find_sealed` checks one request object
before it is sent.

The canary run (:func:`make_canary`, :func:`check_canary`) tests the harness instead of one
run's data: the harness plants generated marker values in every hidden place for one run,
and the check fails when a marker reaches a request, or when a place's marker is in none of
the hidden files (a canary that was never planted proves nothing).

``python -m plimsoll_client.tripwire`` runs both from the command line (:func:`main`): exit 0
when nothing is found, 1 on a finding (a sealed value in a request, an unplanted canary place),
2 on a usage error or an input that does not load.

Standard library only, no plimsoll server. ``docs/answer-key-tripwire.md`` in the plimsoll
repository describes the file formats, the matching rules and what the tripwire cannot find.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import bisect
import hashlib
import json
import os
import re
import secrets
import string
import sys
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, TextIO, Tuple
from urllib.parse import unquote

SEALED_VERSION = 1

# A file larger than this is checked by its digest only: recorded uploads (a video, an image)
# sit beside recorded requests, and reading them as text finds nothing a digest would not.
MAX_TEXT_BYTES = 64 << 20
# A run of base64 characters this long is a payload, not prose: it is decoded and checked by
# digest, and its characters are searched as text only for text values of MIN_PAYLOAD_TEXT
# characters or more, since a shorter one turns up in base64 by chance. 256 characters hold
# 192 bytes; a SHA-256 in hex (64) or base64 (44) stays text.
MIN_BASE64_RUN = 256
# The shortest whole string that is decoded as base64 when no payload was found in it: an API
# that takes a file as a bare base64 field (a short text document, a label file) sends it so,
# with no data: prefix. The string is still searched as written too, so this only adds checks;
# decoded bytes are searched only when they are text, which random letters and digits seldom
# decode to.
MIN_WHOLE_BASE64 = 8
# The shortest text value a payload's characters are searched for as written. A run that
# looks like base64 can be a long path of letters, digits and slashes holding a planted name,
# and a value of 8 characters turns up in random base64 at a given place about once in 32^8
# (10^12, a letter matching in either case), so about once in 16,000 values over the largest
# file read as text.
MIN_PAYLOAD_TEXT = 8

_HEX64 = re.compile(r"\A[0-9a-fA-F]{64}\Z")
_WORD_CHAR = re.compile(r"[^\W_]")  # a letter or digit, in any script
_NUMBER = re.compile(r"(?<![^\W_])(?<![.])([0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][-+]?[0-9]+)?(?![0-9])(?!\.[0-9])")
# Digits grouped in threes by commas or underscores (4,127.46 as Python's f"{x:,}" writes it, 4_127.46 as a Python
# literal), read once more without the separators: _NUMBER alone reads 4,127.46 as 4 and 127.46.
# A match starts only at a run's first group: no start after a comma, and none after a digit and an underscore.
# Without (?<![0-9]_), every group of "123_" * k + "1" was a start that read the rest of the run and gave it back, so
# 80,000 characters took 9 s and a megabyte of model output would take about half an hour.
_GROUPED = re.compile(r"(?<![^\W_])(?<![.,])(?<![0-9]_)[0-9]{1,3}([,_])[0-9]{3}(?:\1[0-9]{3})*(?:\.[0-9]+)?(?![0-9])(?!\.[0-9])(?![,_][0-9])")
_TIMECODE = re.compile(r"(?<![0-9:.])(?:([0-9]{1,3}):)?([0-9]{1,2}):([0-9]{2})(\.[0-9]+)?(?![0-9:])")
_DATA_URL = re.compile(r"data:([A-Za-z0-9!#$&^_.+-]*/[A-Za-z0-9!#$&^_.+-]*)?((?:;[^;,\s]*)*?);base64,([A-Za-z0-9+/_-]+=*)", re.I)
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/_-]{%d,}=*" % MIN_BASE64_RUN)
_BASE64_LINE = re.compile(r"\A[A-Za-z0-9+/_-]+=*\Z")
_PERCENT = re.compile(r"%[0-9A-Fa-f]{2}")
_TEXT_MIME = re.compile(r"\A(text/.*|application/(json|xml|x-ndjson|.*\+json|.*\+xml|javascript|x-yaml|yaml))\Z", re.I)
_PLACE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")

_TEXT_OPTIONS = {"case_sensitive", "whole_word"}
_NUMBER_OPTIONS = {"tolerance", "timecode"}
_COMMON = {"id", "place"}
_KINDS = ("text", "number", "sha256")


class SealedFileError(ValueError):
    """A sealed-values file that does not load. It is refused whole: a file that loads with a
    typo checks for less than its author believes."""


@dataclass(frozen=True)
class SealedValue:
    """One value that must not reach the model under test. Exactly one of ``text``,
    ``number`` and ``sha256`` is set."""

    id: str
    place: str = ""
    text: Optional[str] = None
    case_sensitive: bool = False
    whole_word: bool = True
    number: Optional[Decimal] = None
    tolerance: Decimal = Decimal(0)
    timecode: bool = False
    sha256: Optional[str] = None

    @property
    def kind(self) -> str:
        return "text" if self.text is not None else "number" if self.number is not None else "sha256"

    @property
    def weak(self) -> bool:
        """Short enough to turn up in unrelated text: a hit on it needs a look before it is
        called a leak. A canary run has no weak values."""
        if self.text is not None:
            return len(self.text.strip()) < 4
        if self.number is not None:
            digits = format(abs(self.number).normalize(), "f").replace(".", "").lstrip("0")
            return len(digits) < 3 and self.tolerance == 0
        return False


@dataclass(frozen=True)
class Sealed:
    """A loaded sealed-values file. ``sha256`` is the digest of the file as read, so a report
    can name exactly which set it checked for without repeating it."""

    values: Tuple[SealedValue, ...]
    sha256: str = ""
    path: str = ""
    _patterns: Dict[str, "re.Pattern[str]"] = field(default_factory=dict, repr=False, compare=False)

    def first_word(self, v: SealedValue) -> Optional[str]:
        """The value's first word as a substring test (lowercased unless case matters), or
        None when the value is not ASCII."""
        assert v.text is not None
        if not v.text.isascii():
            return None
        w = v.text.split()[0]
        return w if v.case_sensitive else w.lower()

    def pattern(self, v: SealedValue) -> "re.Pattern[str]":
        p = self._patterns.get(v.id)
        if p is None:
            p = _text_pattern(v)
            self._patterns[v.id] = p
        return p


@dataclass(frozen=True)
class Hit:
    """One sealed value found. ``location`` is a JSON path (``$.messages[1].content``),
    prefixed with ``line N`` in a JSON Lines file, or ``line N, column C`` in plain text;
    ``how`` says what matched: ``text``, ``number``, ``timecode``, ``key`` (an object key, named
    in the path by its position, ``<key 2>``, so the path does not repeat the value),
    ``digest`` (a string, payload or file whose SHA-256 is sealed), with ``, base64`` or
    ``, percent-decoded`` when it was found only after decoding. ``count`` is how many times
    it was found there. ``pointer`` is ``location`` with every object key named by its
    position (``$.<key 0>[1].<key 2>``), for a report that must carry no text the recorded
    requests hold (one uploaded to another service); a location outside a JSON document is
    its own pointer."""

    file: str
    location: str
    sealed_id: str
    how: str
    count: int = 1
    pointer: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"file": self.file, "location": self.location, "sealed_id": self.sealed_id,
                "how": self.how, "count": self.count}


@dataclass
class Report:
    """What :func:`scan` found. ``notes`` say what was read only in part (a binary or very
    large file checked by digest alone, a ``.json`` file that did not parse). ``partial``
    names, for a report that states it apart from the notes' text, each file read only in
    part and why: ``(shown name, "not_utf8" | "too_large" | "symlink")``. ``digests`` is
    each file's SHA-256 by its shown name: the bytes that were searched, for a record that
    must name exactly what a scan saw."""

    sealed: Sealed
    hits: List[Hit] = field(default_factory=list)
    files: int = 0
    notes: List[str] = field(default_factory=list)
    partial: List[Tuple[str, str]] = field(default_factory=list)
    digests: Dict[str, str] = field(default_factory=dict)

    @property
    def weak(self) -> List[str]:
        return [v.id for v in self.sealed.values if v.weak]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check": "answer-key tripwire",
            "sealed_file": self.sealed.path,
            "sealed_sha256": self.sealed.sha256,
            "sealed_values": len(self.sealed.values),
            "weak_values": self.weak,
            "files": self.files,
            "hits": [h.to_dict() for h in self.hits],
            "notes": list(self.notes),
        }


# --- the sealed-values file ---------------------------------------------------------------


def load_sealed(path: str) -> Sealed:
    """Reads and checks a sealed-values file (:data:`SEALED_VERSION`); raises
    :class:`SealedFileError` on anything malformed."""
    with open(path, "rb") as f:
        raw = f.read()
    try:
        doc = json.loads(raw.decode("utf-8"), parse_float=Decimal)
    except (UnicodeDecodeError, ValueError) as e:
        raise SealedFileError(f"{path}: not a JSON document: {e}") from None
    s = parse_sealed(doc, where=path)
    return Sealed(values=s.values, sha256=hashlib.sha256(raw).hexdigest(), path=path)


def parse_sealed(doc: Any, where: str = "sealed values") -> Sealed:
    """Checks a sealed-values document already parsed from JSON (numbers may be ``Decimal``,
    ``int`` or ``float``; a ``float`` is read through its shortest decimal form)."""
    if not isinstance(doc, Mapping):
        raise SealedFileError(f"{where}: the document must be a JSON object")
    extra = set(doc) - {"version", "values"}
    if extra:
        raise SealedFileError(f"{where}: unknown field(s) {sorted(extra)}")
    if doc.get("version") != SEALED_VERSION or isinstance(doc.get("version"), bool):
        raise SealedFileError(f"{where}: version must be {SEALED_VERSION}")
    entries = doc.get("values")
    if not isinstance(entries, list) or not entries:
        raise SealedFileError(f"{where}: values must be a non-empty list")
    out: List[SealedValue] = []
    seen = set()
    for i, e in enumerate(entries):
        at = f"{where}: values[{i}]"
        if not isinstance(e, Mapping):
            raise SealedFileError(f"{at}: must be an object")
        vid = e.get("id")
        if not isinstance(vid, str) or not vid.strip() or vid != vid.strip():
            raise SealedFileError(f"{at}: id must be a non-empty string without surrounding spaces")
        if vid in seen:
            raise SealedFileError(f"{at}: id {vid!r} is used twice")
        seen.add(vid)
        at = f"{where}: value {vid!r}"
        kinds = [k for k in _KINDS if k in e]
        if len(kinds) != 1:
            raise SealedFileError(f"{at}: must hold exactly one of text, number or sha256")
        kind = kinds[0]
        allowed = _COMMON | {kind} | (_TEXT_OPTIONS if kind == "text" else _NUMBER_OPTIONS if kind == "number" else set())
        extra = set(e) - allowed
        if extra:
            raise SealedFileError(f"{at}: field(s) {sorted(extra)} do not apply to a {kind} value")
        place = e.get("place", "")
        if not isinstance(place, str) or (place and not _PLACE.match(place)):
            raise SealedFileError(f"{at}: place must be letters, digits and . _ : / - (at most 128)")
        if kind == "text":
            text = e["text"]
            if not isinstance(text, str) or not text.strip():
                raise SealedFileError(f"{at}: text must be a non-empty string")
            out.append(SealedValue(id=vid, place=place, text=text,
                                   case_sensitive=_bool(e, "case_sensitive", False, at),
                                   whole_word=_bool(e, "whole_word", True, at)))
        elif kind == "number":
            num = _decimal(e["number"], f"{at}: number")
            tol = _decimal(e.get("tolerance", 0), f"{at}: tolerance")
            if tol < 0:
                raise SealedFileError(f"{at}: tolerance must not be negative")
            out.append(SealedValue(id=vid, place=place, number=num, tolerance=tol,
                                   timecode=_bool(e, "timecode", False, at)))
        else:
            digest = e["sha256"]
            if not isinstance(digest, str) or not _HEX64.match(digest):
                raise SealedFileError(f"{at}: sha256 must be 64 hex characters")
            out.append(SealedValue(id=vid, place=place, sha256=digest.lower()))
    return Sealed(values=tuple(out))


def _bool(e: Mapping[str, Any], key: str, default: bool, at: str) -> bool:
    v = e.get(key, default)
    if not isinstance(v, bool):
        raise SealedFileError(f"{at}: {key} must be true or false")
    return v


def _decimal(v: Any, at: str) -> Decimal:
    if isinstance(v, bool):
        raise SealedFileError(f"{at} must be a number, not true or false")
    try:
        if isinstance(v, float):
            d = Decimal(repr(v))
        elif isinstance(v, (int, Decimal)):
            d = Decimal(v)
        elif isinstance(v, str) and v.strip() == v and v:
            d = Decimal(v)
        else:
            raise InvalidOperation
    except (InvalidOperation, ValueError):
        raise SealedFileError(f"{at} must be a number or a decimal string") from None
    if not d.is_finite():
        raise SealedFileError(f"{at} must be finite")
    return d


def _text_pattern(v: SealedValue) -> "re.Pattern[str]":
    assert v.text is not None
    words = v.text.split()
    body = r"\s+".join(re.escape(w) for w in words)
    if v.whole_word:
        if _WORD_CHAR.match(words[0][0]):
            body = r"(?<![^\W_])" + body
        if _WORD_CHAR.match(words[-1][-1]):
            body += r"(?![^\W_])"
    return re.compile(body, 0 if v.case_sensitive else re.IGNORECASE)


# --- matching --------------------------------------------------------------------------------


class _Collector:
    def __init__(self, file: str) -> None:
        self.file = file
        self.found: Dict[Tuple[str, str, str], int] = {}
        # A JSON location's pointer (Hit.pointer), registered by _walk. Locations are unique
        # within a file: an object's keys are, and a masked key's <key N> is written apart.
        self.pointers: Dict[str, str] = {}

    def add(self, location: str, vid: str, how: str) -> None:
        key = (location, vid, how)
        self.found[key] = self.found.get(key, 0) + 1

    def hits(self) -> List[Hit]:
        return [Hit(self.file, loc, vid, how, n, self.pointers.get(loc, loc)) for (loc, vid, how), n in self.found.items()]


def _number_matches(v: SealedValue, x: Decimal) -> bool:
    assert v.number is not None
    try:
        return abs(abs(x) - abs(v.number)) <= v.tolerance
    except ArithmeticError:
        # A token like 1e999999 in a recorded request is past Decimal's range. It is not a
        # sealed value, and one such token must not end the scan of everything after it.
        return False


def _digests(raw: bytes) -> Iterator[str]:
    yield hashlib.sha256(raw).hexdigest()
    stripped = raw.rstrip(b"\r\n")
    if stripped != raw:
        yield hashlib.sha256(stripped).hexdigest()
    yield hashlib.sha256(stripped + b"\n").hexdigest()


def _check_digest(raw: bytes, sealed: Sealed, out: _Collector, location: str, how: str) -> None:
    digests = set(_digests(raw))
    for v in sealed.values:
        if v.sha256 is not None and v.sha256 in digests:
            out.add(location, v.id, how)


def _b64decode(run: str) -> Optional[bytes]:
    compact = re.sub(r"\s+", "", run)
    alt = b"-_" if ("-" in compact or "_" in compact) else None
    padded = compact.rstrip("=")
    padded += "=" * (-len(padded) % 4)
    try:
        return base64.b64decode(padded, altchars=alt, validate=True)
    except (binascii.Error, ValueError):
        return None


def _texty(raw: bytes) -> Optional[str]:
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not s:
        return None
    printable = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return s if printable >= 0.9 * len(s) else None


def _mixed(run: str) -> bool:
    # Base64 of anything but a few repeated bytes holds capitals, small letters and digits; a
    # long identifier or path segment of one case does not, and stays text.
    return bool(re.search(r"[A-Z]", run) and re.search(r"[a-z]", run) and re.search(r"[0-9]", run))


def _wrapped_base64(s: str) -> bool:
    """A whole string that is base64 wrapped over lines (the ``base64`` command's 76 columns,
    PEM's 64): every line but the last the same length, a multiple of 4, at least 40."""
    lines = s.strip().splitlines()
    if len(lines) < 2 or not all(_BASE64_LINE.match(ln.strip()) for ln in lines):
        return False
    width = len(lines[0].strip())
    return (width >= 40 and width % 4 == 0 and all(len(ln.strip()) == width for ln in lines[:-1])
            and len(lines[-1].strip()) <= width and _mixed(s))


_DATA_START = re.compile(r"data:", re.I)
_PARAMS_END = re.compile(r"[,\s]")
_BASE64_TAIL = re.compile(r";base64", re.I)  # as _DATA_URL reads it, case folding included (";baſe64" is one)
# _DATA_URL's media type and its first payload character, compiled with re.I as it is, so the same characters match
# (under re.I, [A-Za-z] also matches the long s and the Kelvin sign).
_DATA_MIME = re.compile(r"[A-Za-z0-9!#$&^_.+-]*/[A-Za-z0-9!#$&^_.+-]*", re.I)
_PAYLOAD_START = re.compile(r"[A-Za-z0-9+/_-]", re.I)


def _data_head_ok(s: str, a: int, b: int) -> bool:
    """Whether s[a:b], the text between a "data:" and its ";base64", is what _DATA_URL accepts there: an optional
    media type, then ;-parameters. The parameters can hold anything but ";", "," and white space, and the comma that
    closes the span is the first one, so only the media type, up to the first ";", can fail. The media type's
    characters exclude ":", so the match stops by the next "data:" at the latest."""
    if a == b or s[a] == ";":
        return True
    m = _DATA_MIME.match(s, a, b)
    return m is not None and (m.end() == b or s[m.end()] == ";")


def _data_urls(s: str) -> Iterator["re.Match[str]"]:
    """_DATA_URL.finditer(s), the same matches, in one pass over s.

    A data URL's media type and parameters hold no comma and no white space, so its ";base64," is the first comma
    after its "data:". Every "data:" before that comma shares it, so the comma, the ";base64" before it and the
    payload character after it are read once for all of them; each start then needs only its media type checked
    (_data_head_ok), and the first that passes is the match finditer finds. Before, each start read its parameters to
    that comma again: "data:;" * k cost k * k / 2 (120,000 characters took 20 s), and so did "data:;" * k + "base64,"
    and "data:" * k + ";base64," (300,000 characters took 133 s; security scan of 2026-11-25, F3)."""
    pos = 0
    while True:
        start = _DATA_START.search(s, pos)
        if start is None:
            return
        end = _PARAMS_END.search(s, start.end())
        if end is None:
            return  # no comma after it, so no data URL
        comma = end.start()
        if (s[comma] != "," or comma < 7 or not _BASE64_TAIL.fullmatch(s, comma - 7, comma)
                or not _PAYLOAD_START.match(s, comma + 1)):
            pos = comma
            continue
        m = None
        st: Optional["re.Match[str]"] = start
        while st is not None and st.end() <= comma - 7:
            if _data_head_ok(s, st.end(), comma - 7):
                m = _DATA_URL.match(s, st.start())
                break
            st = _DATA_START.search(s, st.start() + 1, comma)
        if m is None:
            pos = comma
            continue
        yield m
        pos = m.end()


def _payloads(s: str) -> Iterator[Tuple[int, int, str, str]]:
    """Base64 payloads inside a string: (start, end, the base64 text, the declared MIME type
    or ''). A data URL's payload, a long run of base64 characters, or a whole string that is
    base64 wrapped over lines."""
    taken: List[Tuple[int, int]] = []
    for m in _data_urls(s):
        taken.append((m.start(), m.end()))
        yield m.start(), m.end(), m.group(3), (m.group(1) or "")
    for m in _BASE64_RUN.finditer(s):
        if any(a <= m.start() < b for a, b in taken):
            continue
        run = m.group(0)
        if _mixed(run):
            taken.append((m.start(), m.end()))
            yield m.start(), m.end(), run, ""
    if not taken and len(s) >= MIN_BASE64_RUN and _wrapped_base64(s):
        yield 0, len(s), s, ""


def _scan_string(s: str, sealed: Sealed, out: _Collector, location: str, *, key: bool = False,
                 decoded: bool = False, position: Optional[Any] = None) -> None:
    """Every check on one string. ``position`` maps an offset to a location (plain text files)."""
    suffix = ", base64" if decoded else ""
    if position is None:  # a whole file's digest is checked by _scan_file
        _check_digest(s.encode("utf-8"), sealed, out, location, "digest" + suffix)
    text = s
    if not decoded:
        cut: List[Tuple[int, int]] = []
        for start, end, payload, mime in _payloads(s):
            raw = _b64decode(payload)
            if raw is None:
                continue
            cut.append((start, end))
            where = position(start) if position else location
            _check_digest(raw, sealed, out, where, "digest, base64")
            inner = _texty(raw) if (not mime or _TEXT_MIME.match(mime)) else None
            if inner is not None:
                _scan_string(inner, sealed, out, where, decoded=True)
            # Its characters as written, for values long enough that chance does not find them.
            at = (lambda offset, a=start: position(a + offset)) if position else None
            _scan_text(s[start:end], sealed, out, location, "key" if key else None, "", at,
                       numbers=False, min_text=MIN_PAYLOAD_TEXT)
        if not cut:
            whole = s.strip()
            if len(whole) >= MIN_WHOLE_BASE64 and _BASE64_LINE.match(whole):
                raw = _b64decode(whole)
                inner = _texty(raw) if raw is not None else None
                if inner is not None:
                    where = position(0) if position else location
                    _check_digest(raw, sealed, out, where, "digest, base64")
                    _scan_string(inner, sealed, out, where, decoded=True)
        if cut:
            # Each payload becomes one space (a payload holds no line break, so line numbers
            # hold), and offsets in what is left map back to the string's.
            pieces: List[str] = []
            starts: List[Tuple[int, int]] = []  # (offset in text, offset in s)
            at, new = 0, 0
            for a, b in sorted(cut):
                starts.append((new, at))
                pieces.append(s[at:a] + " ")
                new += a - at + 1
                at = b
            starts.append((new, at))
            pieces.append(s[at:])
            text = "".join(pieces)
            if position is not None:
                outer, keys = position, [n for n, _ in starts]

                def position(offset: int) -> str:
                    i = bisect.bisect_right(keys, offset) - 1
                    return outer(starts[i][1] + offset - starts[i][0])
    how = "key" if key else None
    _scan_text(text, sealed, out, location, how, suffix, position)
    if not _PERCENT.search(text):
        return
    # Percent escapes decoded once: a value with a space or a slash in a URL. In a plain text
    # file each line is decoded on its own, so a hit keeps its line number.
    decoded_suffix = suffix + ", percent-decoded"
    if position is None:
        _scan_text(unquote(text), sealed, out, location, how, decoded_suffix, None)
        return
    for n, line in enumerate(text.split("\n"), 1):
        if _PERCENT.search(line):
            _scan_text(unquote(line), sealed, out, f"line {n}", how, decoded_suffix, None)


def _scan_text(text: str, sealed: Sealed, out: _Collector, location: str, how: Optional[str],
               suffix: str, position: Optional[Any], numbers: bool = True, min_text: int = 0) -> None:
    def where(offset: int) -> str:
        return position(offset) if position else location

    folded = text.lower() if text.isascii() else None
    for v in sealed.values:
        if v.text is None or len(v.text) < min_text:
            continue
        # A cheap test first: in ASCII text, a value whose first word is ASCII matches only
        # where that word occurs (lowercased, unless case matters). Other text gets the
        # pattern alone, since its case folding is not str.lower's.
        needle = sealed.first_word(v)
        if folded is not None and needle is not None and needle not in (text if v.case_sensitive else folded):
            continue
        for m in sealed.pattern(v).finditer(text):
            out.add(where(m.start()), v.id, (how or "text") + suffix)
    if not numbers:
        return
    numbers_sealed = [v for v in sealed.values if v.number is not None]
    if not numbers_sealed:
        return
    for m in _NUMBER.finditer(text):
        try:
            x = Decimal(m.group(0))
        except InvalidOperation:
            continue
        for v in numbers_sealed:
            if _number_matches(v, x):
                out.add(where(m.start()), v.id, (how or "number") + suffix)
    for m in _GROUPED.finditer(text):
        x = Decimal(m.group(0).replace(m.group(1), ""))
        for v in numbers_sealed:
            if _number_matches(v, x):
                out.add(where(m.start()), v.id, (how or "number") + suffix)
    timed = [v for v in numbers_sealed if v.timecode]
    for m in _TIMECODE.finditer(text) if timed else ():
        h, mnt, sec, frac = m.groups()
        if not int(h or 0) and not int(mnt):
            continue  # 0:31.5 is 31.5, which the number rule has already read
        x = Decimal(int(h or 0) * 3600 + int(mnt) * 60 + int(sec)) + (Decimal(frac) if frac else 0)
        for v in timed:
            if _number_matches(v, x):
                out.add(where(m.start()), v.id, (how or "timecode") + suffix)


def _key_path(path: str, key: str) -> str:
    if re.match(r"\A[A-Za-z_][A-Za-z0-9_]*\Z", key):
        return f"{path}.{key}"
    return f"{path}[{json.dumps(key, ensure_ascii=False)}]"


def _walk(obj: Any, sealed: Sealed, out: _Collector, path: str, pos: Optional[str] = None) -> None:
    # pos is path with every key named by its position: the hit's pointer.
    pos = path if pos is None else pos
    out.pointers.setdefault(path, pos)
    if isinstance(obj, Mapping):
        for i, (k, v) in enumerate(obj.items()):
            # A key holding a sealed value is named by its position, never its text, so the
            # report does not repeat the value in this path or in any path below it.
            before = len(out.found), sum(out.found.values())
            masked, kpos = f"{path}.<key {i}>", f"{pos}.<key {i}>"
            out.pointers.setdefault(masked, kpos)
            _scan_string(str(k), sealed, out, masked, key=True)
            kp = masked if (len(out.found), sum(out.found.values())) != before else _key_path(path, str(k))
            _walk(v, sealed, out, kp, kpos)
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _walk(v, sealed, out, f"{path}[{i}]", f"{pos}[{i}]")
    elif isinstance(obj, str):
        _scan_string(obj, sealed, out, path)
    elif isinstance(obj, bool) or obj is None:
        return
    elif isinstance(obj, (int, float, Decimal)):
        x = Decimal(repr(obj)) if isinstance(obj, float) else Decimal(obj)
        if not x.is_finite():
            return
        for v in sealed.values:
            if v.number is not None and _number_matches(v, x):
                out.add(path, v.id, "number")
        # A number is also text: a sealed seed listed as text is found in {"seed": 731904}.
        _scan_text(str(obj), sealed, out, path, None, "", None, numbers=False)


def find_sealed(request: Any, sealed: Sealed, source: str = "request") -> List[Hit]:
    """Checks one request object (as it is about to be sent: dicts, lists, strings, numbers)
    and returns every hit, with ``source`` as the hits' file name. A harness calls it before
    each send and refuses to send on any hit."""
    out = _Collector(source)
    _walk(request, sealed, out, "$")
    return out.hits()


def _line_col(text: str) -> Any:
    starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def position(offset: int) -> str:
        line = bisect.bisect_right(starts, offset)
        return f"line {line}, column {offset - starts[line - 1] + 1}"

    return position


def _scan_file(path: str, shown: str, sealed: Sealed, report: Report) -> None:
    out = _Collector(shown)
    # One read: the digest is of the bytes searched, so whatever is bound to it later names
    # exactly the bytes this scan saw, never bytes it did not.
    h = hashlib.sha256()
    with open(path, "rb") as f:
        raw = f.read(MAX_TEXT_BYTES + 1)
        h.update(raw)
        size = len(raw)
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
    whole = h.hexdigest()
    report.digests[shown] = whole
    for v in sealed.values:
        if v.sha256 == whole:
            out.add("(whole file)", v.id, "digest")
    if size > MAX_TEXT_BYTES:
        report.notes.append(f"{shown}: {size} bytes, over {MAX_TEXT_BYTES}; checked by its digest only")
        report.partial.append((shown, "too_large"))
        report.hits.extend(out.hits())
        return
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        report.notes.append(f"{shown}: not UTF-8 text; checked by its digest only")
        report.partial.append((shown, "not_utf8"))
        report.hits.extend(out.hits())
        return
    lower = path.lower()
    if lower.endswith((".jsonl", ".ndjson")):
        for n, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line, parse_float=Decimal)
            except ValueError:
                _scan_string(line, sealed, out, f"line {n}")
                continue
            _walk(obj, sealed, out, f"line {n} $")
    else:
        obj: Any = None
        parsed = False
        if lower.endswith(".json") or text.lstrip()[:1] in ("{", "["):
            try:
                obj = json.loads(text, parse_float=Decimal)
                parsed = True
            except ValueError:
                if lower.endswith(".json"):
                    report.notes.append(f"{shown}: not valid JSON; searched as plain text")
        if parsed:
            _walk(obj, sealed, out, "$")
        else:
            _scan_string(text, sealed, out, "(text)", position=_line_col(text))
    report.hits.extend(out.hits())


def _files(paths: Iterable[str], sealed: Sealed, report: Report) -> Iterator[Tuple[str, str]]:
    """Every file under ``paths``, with the name the report shows it by. A recorded file's
    name is part of what was sent (an upload goes up under it), so every file's name, and
    every directory's below a directory given, is searched as text too: a name holding a
    sealed value is a hit at ``(file name)`` or ``(directory name)``, and is shown as
    ``<name N>`` from then on, so no line of the report repeats it. The names given on the
    command line, a directory's own or a file's directories, are the caller's and are not
    searched."""
    aliases = 0

    def name(n: str, parent: str, kind: str) -> str:
        nonlocal aliases
        out = _Collector("")
        _scan_string(n, sealed, out, f"({kind} name)")
        if not out.found:
            return n
        aliases += 1
        alias = f"<name {aliases}>"
        shown = os.path.join(parent, alias) if parent else alias
        report.hits.extend(Hit(shown, loc, vid, how, c, loc) for (loc, vid, how), c in out.found.items())
        return alias

    for p in paths:
        if os.path.isdir(p):
            top = os.path.abspath(p)
            shown_as = {top: os.path.basename(top)}
            for root, dirs, names in os.walk(p):
                dirs.sort()
                here = shown_as[os.path.abspath(root)]
                for d in dirs:
                    full = os.path.join(root, d)
                    shown_as[os.path.abspath(full)] = os.path.join(here, name(d, here, "directory"))
                    if os.path.islink(full):  # os.walk does not enter it; say so, as for a linked file
                        report.notes.append(f"{shown_as[os.path.abspath(full)]}: a symbolic link to a directory; skipped")
                        report.partial.append((shown_as[os.path.abspath(full)], "symlink"))
                for n in sorted(names):
                    full = os.path.join(root, n)
                    shown = os.path.join(here, name(n, here, "file"))
                    if os.path.islink(full):
                        report.notes.append(f"{shown}: a symbolic link; skipped")
                        report.partial.append((shown, "symlink"))
                    elif os.path.isfile(full):
                        yield full, shown
        elif os.path.isfile(p):
            parent, n = os.path.split(p)
            yield p, os.path.join(parent, name(n, parent, "file"))
        else:
            raise FileNotFoundError(p)


def scan(paths: Iterable[str], sealed: Sealed) -> Report:
    """Walks every file under ``paths`` (files or directories, recursively; symbolic links
    inside a directory, to files or to directories, are skipped and noted) and returns every sealed value found, in the files and
    in their names (:func:`_files`).

    A ``.json`` file is one JSON document, a ``.jsonl`` or ``.ndjson`` file one per line,
    any other UTF-8 file a JSON document when it parses as one and plain text otherwise; a
    file that is not UTF-8, or is over :data:`MAX_TEXT_BYTES`, is checked by its SHA-256
    alone. Inside each string: base64 payloads (data URLs and long base64 runs) are decoded
    and checked by digest, searched as text when they decode to text, and searched as
    written for text values of :data:`MIN_PAYLOAD_TEXT` characters or more; the rest is
    searched as written and, when it holds percent escapes, decoded once. A string with no
    payload that is base64 as a whole (:data:`MIN_WHOLE_BASE64` characters or more) is also
    decoded and searched when it decodes to text. Numbers are read as written and, where
    their digits are grouped in threes by commas or underscores, without the separators."""
    report = Report(sealed=sealed)
    for full, shown in _files(paths, sealed, report):
        report.files += 1
        _scan_file(full, shown, sealed, report)
    report.hits.sort(key=lambda h: (h.file, h.location, h.sealed_id, h.how))
    return report


# --- the canary run ----------------------------------------------------------------------------


def make_canary(places: Sequence[str], *, rand: Optional[Any] = None) -> Dict[str, Any]:
    """A sealed-values document of fresh marker values, two for each hidden place: a text
    marker (letters and digits, safe in a file name, a label or a JSON field) with id
    ``<place>/text``, and a number marker with id ``<place>/number``.

    Text markers are found anywhere (``whole_word`` false), so a copy run into a longer name
    (``clip`` + marker + ``.mp4``) still counts: 12 random letters and digits do not turn up
    by chance, so they need no word boundary to tell them from other text. Number markers lie between 1000 and 10000, never within 0.3 of a whole number, and are
    found within 0.25 (and as a time code), so a copy rounded to one decimal still counts
    while no whole number (a token limit, an image size, a year) can match one. ``rand`` is a
    ``random.Random`` for reproducible markers in tests; by default they come from
    :mod:`secrets`."""
    if not places:
        raise ValueError("make_canary needs at least one place")
    if len(set(places)) != len(places):
        raise ValueError("make_canary: a place is listed twice")
    alphabet = string.ascii_lowercase + string.digits
    choice = rand.choice if rand is not None else secrets.choice
    randbelow = (lambda n: rand.randrange(n)) if rand is not None else secrets.randbelow
    values: List[Dict[str, Any]] = []
    used: List[Decimal] = []
    for place in places:
        if not _PLACE.match(place):
            raise ValueError(f"make_canary: place {place!r} must be letters, digits and . _ : / - (at most 128)")
        marker = "cnry" + "".join(choice(alphabet) for _ in range(12))
        while True:
            n = Decimal(1000 + randbelow(9000)) + Decimal(30 + randbelow(40)) / 100
            if all(abs(n - u) > 1 for u in used):
                break
        used.append(n)
        values.append({"id": f"{place}/text", "place": place, "text": marker, "whole_word": False})
        values.append({"id": f"{place}/number", "place": place, "number": str(n),
                       "tolerance": "0.25", "timecode": True})
    return {"version": SEALED_VERSION, "values": values}


@dataclass
class CanaryReport:
    """What :func:`check_canary` found. ``ok`` is true only when every place's marker was
    planted and none reached a request."""

    planted: Report
    requests: Report
    places: List[str]
    unplanted: List[str]

    @property
    def ok(self) -> bool:
        return not self.unplanted and not self.requests.hits

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check": "canary run",
            "ok": self.ok,
            "places": self.places,
            "unplanted_places": self.unplanted,
            "leaks": [h.to_dict() for h in self.requests.hits],
            "request_files": self.requests.files,
            "planted_files": self.planted.files,
            "notes": self.planted.notes + self.requests.notes,
        }


def check_canary(sealed: Sealed, planted: Iterable[str], requests: Iterable[str]) -> CanaryReport:
    """Checks one canary run: each place's marker must be in at least one of the hidden files
    ``planted`` (else that place was never tested), and no marker may be in ``requests``."""
    places: List[str] = []
    for v in sealed.values:
        p = v.place or v.id
        if p not in places:
            places.append(p)
    planted_report = scan(planted, sealed)
    place_of = {v.id: v.place or v.id for v in sealed.values}
    found = {place_of[h.sealed_id] for h in planted_report.hits}
    unplanted = [p for p in places if p not in found]
    return CanaryReport(planted=planted_report, requests=scan(requests, sealed), places=places, unplanted=unplanted)


# --- the command line ----------------------------------------------------------------------------


def _print_json(obj: object, out: TextIO) -> None:
    json.dump(obj, out, indent=2, default=str)
    out.write("\n")


def report_lines(report: Report) -> List[str]:
    """A report as the command prints it: a line a hit (the file, the place, the sealed id, how it matched and, past
    one, how many times), a warning naming the weak values, then each note. No line holds a sealed value."""
    lines = [f"{h.file}: {h.location}: sealed value {h.sealed_id} ({h.how}"
             + (f", {h.count} times" if h.count > 1 else "") + ")" for h in report.hits]
    if report.weak:
        lines.append("warning: short values that can turn up by chance; look at each hit on them: "
                     + ", ".join(report.weak))
    lines += [f"note: {n}" for n in report.notes]
    return lines


def _cmd_tripwire(a: argparse.Namespace, out: TextIO) -> int:
    sealed = load_sealed(a.sealed)
    report = scan(a.paths, sealed)
    if a.json:
        _print_json(report.to_dict(), out)
    else:
        for line in report_lines(report):
            print(line, file=out)
        if report.hits:
            files = len({h.file for h in report.hits})
            print(f"tripwire: {len(report.hits)} hit{'s' if len(report.hits) != 1 else ''} in {files} of "
                  f"{report.files} files", file=out)
        else:
            print(f"tripwire: no sealed value found in {report.files} files", file=out)
    return 1 if report.hits else 0


def _cmd_canary_make(a: argparse.Namespace, out: TextIO) -> int:
    doc = make_canary(a.places)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            _print_json(doc, f)
    else:
        _print_json(doc, out)
    return 0


def _cmd_canary_check(a: argparse.Namespace, out: TextIO) -> int:
    sealed = load_sealed(a.sealed)
    report = check_canary(sealed, a.planted, a.requests)
    if a.json:
        _print_json(report.to_dict(), out)
    else:
        for p in report.unplanted:
            print(f"not planted: no marker of place {p} is in any hidden file, so that place was not tested", file=out)
        for line in report_lines(report.requests):
            print(line, file=out)
        print("canary: OK, every place planted and no marker reached a request" if report.ok else "canary: FAILED", file=out)
    return 0 if report.ok else 1


def add_tripwire_command(sub: Any) -> Tuple[argparse.ArgumentParser, Any]:
    """Adds the ``tripwire`` command to a command line's subcommands (``sub``, from ``add_subparsers``). Returns its
    parser and its group of output formats, so a command line that offers another report format adds it there."""
    t = sub.add_parser("tripwire", help="find sealed values in recorded model requests")
    t.add_argument("--sealed", required=True, help="the sealed-values file")
    formats = t.add_mutually_exclusive_group()
    formats.add_argument("--json", action="store_true", help="print the report as JSON")
    t.add_argument("paths", nargs="+", help="recorded requests: files or directories")
    t.set_defaults(run=_cmd_tripwire)
    return t, formats


def add_canary_command(sub: Any) -> argparse.ArgumentParser:
    """Adds the ``canary`` command (``canary make``, ``canary check``) to a command line's subcommands."""
    c = sub.add_parser("canary", help="plant marker values for one run, then check none reached a request")
    csub = c.add_subparsers(dest="canary_command", required=True)
    cm = csub.add_parser("make", help="write a sealed-values file of fresh markers, two per hidden place")
    cm.add_argument("places", nargs="+", help="names of the hidden places (truth, reference-times, plan-names, ...)")
    cm.add_argument("-o", "--output", help="write here instead of stdout")
    cm.set_defaults(run=_cmd_canary_make)
    cc = csub.add_parser("check", help="every place planted, no marker in any request")
    cc.add_argument("--sealed", required=True, help="the file canary make wrote")
    cc.add_argument("--planted", action="append", required=True, help="a hidden file or directory the markers were planted in")
    cc.add_argument("--requests", action="append", required=True, help="the run's recorded requests: a file or directory")
    cc.add_argument("--json", action="store_true")
    cc.set_defaults(run=_cmd_canary_check)
    return c


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m plimsoll_client.tripwire",
        description="The answer-key tripwire: find sealed values (what the model under test must never be sent) in the "
                    "requests a harness recorded; and the canary run, which tests the harness itself for that leak.")
    sub = p.add_subparsers(dest="command", required=True)
    add_tripwire_command(sub)
    add_canary_command(sub)
    return p


def main(argv: Optional[Sequence[str]] = None, out: Optional[TextIO] = None) -> int:
    """The command line: exit 0 when nothing is found, 1 on a finding, 2 on a usage error or an input that does not
    load (a sealed-values file is refused whole, since one that loads with a typo checks for less than its author
    believes)."""
    out = out or sys.stdout
    p = parser()
    args = p.parse_args(argv)
    try:
        return int(args.run(args, out))
    except (ValueError, FileNotFoundError, IsADirectoryError, PermissionError) as e:  # SealedFileError is a ValueError
        print(f"{p.prog}: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
