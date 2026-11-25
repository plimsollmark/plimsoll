"""The answer-key tripwire and the canary run (plimsoll_client.tripwire): offline."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import random
import re
import tempfile
import time
import unittest
from decimal import Decimal

from plimsoll_client import tripwire as t
from plimsoll_client import tripwire as cli  # its command line is the module's main()


def sealed(*values):
    return t.parse_sealed({"version": 1, "values": list(values)})


def found(request, s):
    return sorted((h.location, h.sealed_id, h.how) for h in t.find_sealed(request, s))


def ids(request, s):
    return sorted({h.sealed_id for h in t.find_sealed(request, s)})


class SealedFile(unittest.TestCase):
    def test_refuses_what_would_check_for_less(self) -> None:
        good = {"id": "a", "text": "omit3"}
        for doc in (
            [],
            {"values": [good]},
            {"version": 2, "values": [good]},
            {"version": 1, "values": []},
            {"version": 1, "values": [good], "extra": 1},
            {"version": 1, "values": [{"text": "x"}]},
            {"version": 1, "values": [{"id": " a", "text": "x"}]},
            {"version": 1, "values": [good, {"id": "a", "text": "y"}]},
            {"version": 1, "values": [{"id": "a"}]},
            {"version": 1, "values": [{"id": "a", "text": "x", "number": 1}]},
            {"version": 1, "values": [{"id": "a", "text": "  "}]},
            {"version": 1, "values": [{"id": "a", "text": "x", "tolerance": 1}]},
            {"version": 1, "values": [{"id": "a", "number": 1, "whole_word": False}]},
            {"version": 1, "values": [{"id": "a", "number": True}]},
            {"version": 1, "values": [{"id": "a", "number": "NaN"}]},
            {"version": 1, "values": [{"id": "a", "number": "12 "}]},
            {"version": 1, "values": [{"id": "a", "number": 1, "tolerance": -1}]},
            {"version": 1, "values": [{"id": "a", "sha256": "ab"}]},
            {"version": 1, "values": [{"id": "a", "text": "x", "case_sensitive": "yes"}]},
            {"version": 1, "values": [{"id": "a", "text": "x", "place": "has space"}]},
            {"version": 1, "values": [{"id": "a", "text": "x", "typo_option": True}]},
        ):
            with self.subTest(doc=doc), self.assertRaises(t.SealedFileError):
                t.parse_sealed(doc)

    def test_load_keeps_numbers_exact_and_states_the_file_digest(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "sealed.json")
            raw = b'{"version": 1, "values": [{"id": "t", "number": 31.50}, {"id": "u", "text": "omit3"}]}'
            with open(p, "wb") as f:
                f.write(raw)
            s = t.load_sealed(p)
        self.assertEqual(s.sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(s.values[0].number, Decimal("31.50"))
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.json")
            with open(p, "w") as f:
                f.write("{not json")
            with self.assertRaises(t.SealedFileError):
                t.load_sealed(p)

    def test_weak_values_are_named(self) -> None:
        s = sealed({"id": "short", "text": "ab"}, {"id": "five", "number": 5}, {"id": "half", "number": 0.5},
                   {"id": "ok-text", "text": "omit3"}, {"id": "ok-number", "number": 31.5},
                   {"id": "ok-big", "number": 1200}, {"id": "ok-tol", "number": 5, "tolerance": 0.25})
        self.assertEqual(t.Report(sealed=s).weak, ["short", "five", "half"])


class HugeNumbers(unittest.TestCase):
    """Found on a real run's requests, 2026-10-31: a model's code held a number past Decimal's
    range, and the scan crashed with decimal.Overflow, so everything after it went unread."""

    def test_a_number_past_range_does_not_end_the_scan(self) -> None:
        s = sealed({"id": "gain", "number": 505.7})
        for huge in ("1e999999", "9e9999999", "-1e999999"):
            with self.subTest(huge=huge):
                request = {"messages": [{"content": f"{huge} then later 505.7"}]}
                self.assertEqual(ids(request, s), ["gain"])


class TextValues(unittest.TestCase):
    s = sealed({"id": "plan", "text": "omit3"}, {"id": "phrase", "text": "tighten the bolt"})

    def test_whole_word_any_case(self) -> None:
        for text in ("omit3", "OMIT3.mp4", "clip_omit3.mp4", "runs/omit3/x", "[omit3]", "file 'Omit3'"):
            with self.subTest(text=text):
                self.assertEqual(ids({"x": text}, self.s), ["plan"])
        for text in ("omit30", "xomit3", "omit3x", "om it3", "émit3omit3"):
            with self.subTest(text=text):
                self.assertEqual(ids({"x": text}, self.s), [])

    def test_text_that_is_not_ascii(self) -> None:
        s = sealed({"id": "plan", "text": "omit3"}, {"id": "accent", "text": "café-42"})
        self.assertEqual(ids({"x": "naïve OMIT3"}, s), ["plan"])
        self.assertEqual(ids({"x": "CAFÉ-42 ok"}, s), ["accent"])
        self.assertEqual(ids({"x": "CAFE-42"}, s), [])

    def test_words_match_across_any_whitespace(self) -> None:
        self.assertEqual(ids({"x": "now TIGHTEN\n the\tbolt."}, self.s), ["phrase"])
        self.assertEqual(ids({"x": "tighten the bolts"}, self.s), [])

    def test_options(self) -> None:
        s = sealed({"id": "cs", "text": "Kestrel", "case_sensitive": True},
                   {"id": "sub", "text": "ret42", "whole_word": False})
        self.assertEqual(ids({"x": "kestrel"}, s), [])
        self.assertEqual(ids({"x": "Kestrel"}, s), ["cs"])
        self.assertEqual(ids({"x": "secret42x"}, s), ["sub"])

    def test_keys_are_checked_and_never_named_in_the_path(self) -> None:
        hits = t.find_sealed({"files": {"a.mp4": 1, "omit3.mp4": {"size": 9}}}, self.s)
        self.assertEqual([(h.location, h.how) for h in hits], [("$.files.<key 1>", "key")])
        report = json.dumps([h.to_dict() for h in hits])
        self.assertNotIn("omit3", report)

    def test_a_number_is_also_text(self) -> None:
        s = sealed({"id": "seed", "text": "731904"})
        self.assertEqual(found({"seed": 731904}, s), [("$.seed", "seed", "text")])

    def test_percent_escapes_are_decoded_once(self) -> None:
        self.assertEqual(found({"u": "https://x/?q=tighten%20the%20bolt"}, self.s),
                         [("$.u", "phrase", "text, percent-decoded")])

    def test_paths(self) -> None:
        req = {"messages": [{"role": "user", "content": [{"type": "text", "text": "a"},
                                                         {"type": "text", "text": "see omit3"}]}],
               "odd key": "omit3"}
        self.assertEqual(found(req, self.s), [("$.messages[0].content[1].text", "plan", "text"),
                                              ('$["odd key"]', "plan", "text")])


class NumberValues(unittest.TestCase):
    s = sealed({"id": "t3", "number": 31.5})

    def test_formatting_variants(self) -> None:
        for v in ("31.5", "31.50", "t=31.5s", "31.5 sec", "at 0:31.5", "31.5000", "-31.5", "(31.5)", "3.15e1"):
            with self.subTest(v=v):
                self.assertEqual(ids({"x": v}, self.s), ["t3"])
        for v in (31.5, Decimal("31.50"), -31.5):
            with self.subTest(v=v):
                self.assertEqual(found({"x": v}, self.s), [("$.x", "t3", "number")])

    def test_other_numbers_are_not_it(self) -> None:
        for v in ("131.5", "31.55", "31.5.2", "v31.5", "315", "31", 31, 32.0, True):
            with self.subTest(v=v):
                self.assertEqual(ids({"x": v}, self.s), [])

    def test_tolerance(self) -> None:
        s = sealed({"id": "near", "number": 31.47, "tolerance": 0.05})
        self.assertEqual(ids({"x": "31.5"}, s), ["near"])
        self.assertEqual(ids({"x": "31.6"}, s), [])

    def test_timecodes(self) -> None:
        s = sealed({"id": "tc", "number": "91.5", "timecode": True}, {"id": "plain", "number": "91.5"})
        for v in ("1:31.5", "00:01:31.500", "at 1:31.50 the"):
            with self.subTest(v=v):
                self.assertEqual(ids({"x": v}, s), ["tc"])
        self.assertEqual(ids({"x": "12:31:30"}, s), [])
        # A time code's seconds are read as a number too: 1:31.5 is a hit for 31.5.
        self.assertEqual(ids({"x": "1:31.5"}, self.s), ["t3"])


class Payloads(unittest.TestCase):
    def test_a_data_url_is_hashed_not_read(self) -> None:
        # The payload's base64 text holds "+omit3+", a whole word as written: it must not be
        # read as text (a chance hit), while the decoded bytes are checked by digest.
        b64 = "QUFB" * 80 + "+omit3+A" + "QUFB" * 4
        raw = base64.b64decode(b64)
        s = sealed({"id": "plan", "text": "omit3"}, {"id": "clip", "sha256": hashlib.sha256(raw).hexdigest()})
        self.assertEqual(found({"url": "data:image/png;base64," + b64}, s),
                         [("$.url", "clip", "digest, base64")])
        self.assertEqual(found({"md": "look: ![x](data:image/png;base64," + b64 + ") and omit3"}, s),
                         [("$.md", "clip", "digest, base64"), ("$.md", "plan", "text")])

    def test_a_text_payload_is_read_after_decoding(self) -> None:
        s = sealed({"id": "plan", "text": "omit3"})
        payload = base64.b64encode(b"the clips: omit3.mp4, omit5.mp4").decode()
        self.assertEqual(found({"u": "data:text/plain;base64," + payload}, s), [("$.u", "plan", "text, base64")])

    def test_a_long_base64_run_is_a_payload_and_short_text_is_text(self) -> None:
        s = sealed({"id": "plan", "text": "omit3"})
        run = "QUFB" * 80 + "+omit3+A" + "QUFB" * 4
        self.assertEqual(found({"data": run}, s), [])
        self.assertEqual(found({"data": "+omit3+A"}, s), [("$.data", "plan", "text")])
        # A long identifier of one case is not base64 and stays text.
        ident = "_".join(["segment"] * 40) + "_omit3"
        self.assertEqual(found({"data": ident}, s), [("$.data", "plan", "text")])

    def test_wrapped_base64_and_plain_lines(self) -> None:
        s = sealed({"id": "plan", "text": "omit3"})
        wrapped = base64.encodebytes(("plan omit3 removes step three. " * 12).encode()).decode()
        self.assertEqual(found({"pem": wrapped}, s), [("$.pem", "plan", "text, base64")])
        words = "\n".join(["Word"] * 60 + ["omit3"] + ["Word2"] * 10)
        self.assertEqual(found({"lines": words}, s), [("$.lines", "plan", "text")])

    def test_columns_in_a_text_file_count_the_payload(self) -> None:
        s = sealed({"id": "plan", "text": "omit3"})
        b64 = base64.b64encode(os.urandom(300)).decode()
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "log.txt")
            with open(p, "w") as f:
                f.write("first\nimg data:image/png;base64," + b64 + " then omit3\n")
            hits = t.scan([p], s).hits
        self.assertEqual([h.location for h in hits], [f"line 2, column {len('img data:image/png;base64,' + b64 + ' then ') + 1}"])

    def test_a_string_whose_digest_is_sealed(self) -> None:
        s = sealed({"id": "truth-file", "sha256": hashlib.sha256(b'{"a": 1}\n').hexdigest()})
        self.assertEqual(found({"attached": '{"a": 1}'}, s), [("$.attached", "truth-file", "digest")])


class Files(unittest.TestCase):
    def test_every_kind_of_file(self) -> None:
        s = sealed({"id": "plan", "text": "omit3"}, {"id": "blob", "sha256": hashlib.sha256(b"\xff\xfe\x00video").hexdigest()})
        with tempfile.TemporaryDirectory() as d:
            req = os.path.join(d, "requests")
            os.makedirs(os.path.join(req, "sub"))
            with open(os.path.join(req, "a.jsonl"), "w") as f:
                f.write('{"x": "fine"}\n\n{"y": ["fine", "omit3"]}\nnot json omit3\n')
            with open(os.path.join(req, "b.txt"), "w") as f:
                f.write("one\ntwo\nfour omit3\n")
            with open(os.path.join(req, "sub", "c.bin"), "wb") as f:
                f.write(b"\xff\xfe\x00video")
            with open(os.path.join(req, "d.json"), "w") as f:
                f.write('{"x": "omit3", ')
            with open(os.path.join(req, "e.log"), "w") as f:
                f.write('{"m": "omit3"}')
            os.symlink(os.path.join(req, "b.txt"), os.path.join(req, "link.txt"))
            report = t.scan([req], s)
        self.assertEqual(report.files, 5)
        self.assertEqual([(h.file, h.location, h.sealed_id) for h in report.hits], [
            ("requests/a.jsonl", "line 3 $.y[1]", "plan"),
            ("requests/a.jsonl", "line 4", "plan"),
            ("requests/b.txt", "line 3, column 6", "plan"),
            ("requests/d.json", "line 1, column 8", "plan"),
            ("requests/e.log", "$.m", "plan"),
            ("requests/sub/c.bin", "(whole file)", "blob"),
        ])
        notes = "\n".join(report.notes)
        self.assertIn("requests/sub/c.bin: not UTF-8", notes)
        self.assertIn("requests/d.json: not valid JSON", notes)
        self.assertIn("requests/link.txt: a symbolic link", notes)
        self.assertNotIn("omit3", json.dumps(report.to_dict()))

    def test_names_are_searched_and_never_shown(self) -> None:
        # An upload recorded under the name it went up with, a directory a harness named
        # after a plan, and a file given on its own: each name is searched, a hit is placed at
        # the name, and the report shows <name N> in its place, never the value.
        s = sealed({"id": "plan", "text": "omit3"}, {"id": "step", "number": "31.5"})
        with tempfile.TemporaryDirectory() as d:
            req = os.path.join(d, "requests")
            os.makedirs(os.path.join(req, "runs-omit3"))
            with open(os.path.join(req, "upload-omit3.mp4"), "wb") as f:
                f.write(b"\x00\xffvideo")
            with open(os.path.join(req, "runs-omit3", "call.json"), "w") as f:
                f.write('{"say": "omit3"}')
            with open(os.path.join(req, "clip-31.5s.txt"), "w") as f:
                f.write("fine\n")
            alone = os.path.join(d, "omit3.json")
            with open(alone, "w") as f:
                f.write("{}")
            report = t.scan([req, alone], s)
        self.assertEqual([(h.file, h.location, h.sealed_id, h.how) for h in report.hits], [
            (os.path.join(d, "<name 4>"), "(file name)", "plan", "text"),
            ("requests/<name 1>", "(directory name)", "plan", "text"),
            ("requests/<name 1>/call.json", "$.say", "plan", "text"),
            ("requests/<name 2>", "(file name)", "step", "number"),
            ("requests/<name 3>", "(file name)", "plan", "text"),
        ])
        self.assertIn("requests/<name 3>: not UTF-8", "\n".join(report.notes))
        dumped = json.dumps(report.to_dict())
        self.assertNotIn("omit3", dumped)
        self.assertNotIn("31.5", dumped)

    def test_a_long_path_that_looks_like_base64_is_searched_for_long_values(self) -> None:
        # A path of letters, digits and slashes, no dot, long enough to be taken for a base64
        # payload: a 16-character marker in it is found as written; a 5-character value is
        # not, since one that short turns up in base64 by chance.
        marker = "cnry7q2x9v4k1m8p"
        path = "/".join(["Data2026RunsBatchA"] * 14) + "/" + marker + "/omit3/Frames"
        self.assertGreaterEqual(len(path), t.MIN_BASE64_RUN)
        s = sealed({"id": "plan/text", "text": marker}, {"id": "short", "text": "omit3"})
        self.assertEqual(found({"path": path}, s), [("$.path", "plan/text", "text")])
        self.assertEqual(found({"path": path.replace("Data2026RunsBatchA", "data-runs")}, s),
                         [("$.path", "plan/text", "text"), ("$.path", "short", "text")])

    def test_a_missing_path_is_an_error(self) -> None:
        with self.assertRaises(FileNotFoundError):
            t.scan(["/nonexistent/requests"], sealed({"id": "a", "text": "abcd"}))


class Canary(unittest.TestCase):
    places = ["truth", "reference-times", "plan-names"]

    def test_markers(self) -> None:
        doc = t.make_canary(self.places, rand=random.Random(7))
        s = t.parse_sealed(doc)
        self.assertEqual([v.id for v in s.values], [f"{p}/{k}" for p in self.places for k in ("text", "number")])
        self.assertEqual(t.Report(sealed=s).weak, [])
        texts = [v.text for v in s.values if v.text]
        self.assertEqual(len(set(texts)), 3)
        for v in s.values:
            if v.number is not None:
                frac = v.number % 1
                self.assertTrue(Decimal("0.3") <= frac < Decimal("0.7"), v.number)
                self.assertTrue(1000 <= v.number < 10000)
                self.assertEqual((v.tolerance, v.timecode), (Decimal("0.25"), True))
        # No whole number can match a number marker, and a copy rounded to one decimal does.
        for v in s.values:
            if v.number is not None:
                self.assertEqual(ids({"x": int(v.number)}, s), [])
                self.assertEqual(ids({"x": f"{v.number:.1f}"}, s), [v.id])
        with self.assertRaises(ValueError):
            t.make_canary(["a", "a"])
        with self.assertRaises(ValueError):
            t.make_canary([])

    def _harness(self, d: str, s: t.Sealed, leak: str = "") -> None:
        """A small harness: hidden files hold the answer key; the request is built from an
        allow-list of fields; ``leak`` re-adds one of the mistakes the check exists for."""
        marker = {v.id: v for v in s.values}
        hidden = os.path.join(d, "hidden")
        os.makedirs(hidden, exist_ok=True)
        truth = {"steps": ["pick up", marker["truth/text"].text]}
        times = {"step_seconds": [12.25, float(marker["reference-times/number"].number)]}
        plans = {"clip": marker["plan-names/text"].text + ".mp4", "removed_step": 3}
        for name, obj in (("truth.json", truth), ("times.json", times), ("plans.json", plans)):
            with open(os.path.join(hidden, name), "w") as f:
                json.dump(obj, f)
        request = {"model": "m", "messages": [{"role": "user", "content": "Check the clip against the procedure."}],
                   "upload": {"filename": "sha256-" + hashlib.sha256(b"clip").hexdigest()[:16] + ".mp4"}}
        if leak == "times":
            request["messages"][0]["content"] += f" The expert's step 2 took {times['step_seconds'][1]:.1f} s."
        if leak == "name":
            request["upload"]["filename"] = plans["clip"]
        req_dir = os.path.join(d, "requests")
        os.makedirs(req_dir, exist_ok=True)
        with open(os.path.join(req_dir, "call-1.json"), "w") as f:
            json.dump(request, f)

    def test_a_clean_harness_passes_and_each_leak_fails(self) -> None:
        s = t.parse_sealed(t.make_canary(self.places))
        for leak, place in (("", None), ("times", "reference-times/number"), ("name", "plan-names/text")):
            with self.subTest(leak=leak), tempfile.TemporaryDirectory() as d:
                self._harness(d, s, leak)
                r = t.check_canary(s, [os.path.join(d, "hidden")], [os.path.join(d, "requests")])
                self.assertEqual(r.unplanted, [])
                self.assertEqual(r.ok, not leak)
                self.assertEqual(sorted({h.sealed_id for h in r.requests.hits}), [place] if place else [])

    def test_a_marker_planted_as_a_clip_name(self) -> None:
        # The docs' procedure: the text marker planted as the planted clips' names, nowhere
        # else. The place counts as planted, and an upload recorded under that name is a leak.
        s = t.parse_sealed(t.make_canary(["plan-names"]))
        marker = s.values[0].text
        for leak in (False, True):
            with self.subTest(leak=leak), tempfile.TemporaryDirectory() as d:
                hidden, req = os.path.join(d, "hidden"), os.path.join(d, "requests")
                os.makedirs(hidden)
                os.makedirs(req)
                with open(os.path.join(hidden, f"clip-{marker}.mp4"), "wb") as f:
                    f.write(b"\x00\xffframes")
                upload = f"upload-{marker}.mp4" if leak else "upload-3f2a91c0.mp4"
                with open(os.path.join(req, upload), "wb") as f:
                    f.write(b"\x00\xffframes")
                r = t.check_canary(s, [hidden], [req])
                self.assertEqual(r.unplanted, [])
                self.assertEqual(r.ok, not leak)
                self.assertEqual([(h.file, h.location) for h in r.requests.hits], [("requests/<name 1>", "(file name)")] if leak else [])
                self.assertNotIn(marker, json.dumps(r.to_dict()))

    def test_a_place_never_planted_fails(self) -> None:
        s = t.parse_sealed(t.make_canary(self.places + ["self-check-marks"]))
        with tempfile.TemporaryDirectory() as d:
            self._harness(d, s)
            r = t.check_canary(s, [os.path.join(d, "hidden")], [os.path.join(d, "requests")])
        self.assertEqual(r.unplanted, ["self-check-marks"])
        self.assertFalse(r.ok)


class WaysAroundIt(unittest.TestCase):
    """Ways a harness can send a value that the tripwire missed, or skipped without a word, until an attack on it
    (2026-11-18) found them. The ways it still misses are listed in docs/answer-key-tripwire.md, "What the tripwire
    cannot catch"."""

    def test_a_canary_text_marker_run_into_a_longer_name(self) -> None:
        # A harness that names a clip "clip" + marker + ".mp4", with no separator, made a copy no whole-word rule sees.
        s = t.parse_sealed(t.make_canary(["plan-names"], rand=random.Random(5)))
        marker = s.values[0].text
        self.assertFalse(s.values[0].whole_word)
        for text in ("clip" + marker + ".mp4", marker + "clip", "x" + marker.upper() + "9"):
            with self.subTest(text=text):
                self.assertEqual(ids({"upload": text}, s), ["plan-names/text"])
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "clip" + marker + ".mp4"), "wb") as f:
                f.write(b"\x00\xff")
            self.assertEqual([(h.location, h.sealed_id) for h in t.scan([d], s).hits], [("(file name)", "plan-names/text")])

    def test_digits_grouped_by_commas_or_underscores(self) -> None:
        # Python's f"{x:,}" writes 3075.38 as 3,075.38, which the plain number rule reads as 3 and 75.38.
        s = sealed({"id": "t", "number": "3075.38"}, {"id": "big", "number": "12345678.5"})
        for v, want in (("3,075.38", "t"), ("3_075.38", "t"), ("at 3,075.38 s", "t"), ("12,345,678.5", "big"),
                        ("12_345_678.5", "big")):
            with self.subTest(v=v):
                self.assertEqual(ids({"x": v}, s), [want])
        for v in ("3 075.38", "3075,38", "3,07538", "3,075,38", "13,075.38", "3,075.381", "3,075_380"):
            with self.subTest(v=v):
                self.assertEqual(ids({"x": v}, s), [])
        # A canary's number markers lie where such grouping starts, between 1000 and 10000.
        c = t.parse_sealed(t.make_canary(["reference-times"], rand=random.Random(5)))
        n = [v for v in c.values if v.number is not None][0]
        self.assertEqual(ids({"x": f"{n.number:,}"}, c), [n.id])

    def test_a_whole_string_of_short_base64(self) -> None:
        # An API that takes a file as a bare base64 field ({"type": "base64", "media_type": "text/plain", "data": ...})
        # sends it with no data: prefix, and a short document's base64 is under the 256 characters a run needs.
        s = sealed({"id": "plan", "text": "omit3"})
        raw = b"labels: omit3"
        data = base64.b64encode(raw).decode()
        self.assertLess(len(data), t.MIN_BASE64_RUN)
        self.assertEqual(found({"source": {"type": "base64", "media_type": "text/plain", "data": data}}, s),
                         [("$.source.data", "plan", "text, base64")])
        self.assertEqual(found({"data": data}, sealed({"id": "file", "sha256": hashlib.sha256(raw).hexdigest()})),
                         [("$.data", "file", "digest, base64")])
        # Inside a sentence it is not decoded, as the page says; a string that only looks like base64 is still text.
        self.assertEqual(found({"x": "see " + data + " here"}, s), [])
        self.assertEqual(found({"x": "omit3/Data2026xy"}, s), [("$.x", "plan", "text")])

    def test_a_linked_directory_is_named_as_skipped(self) -> None:
        # os.walk does not enter a symbolic link to a directory; a recording kept behind one was skipped with no note,
        # and the report read "no sealed value found in 0 files".
        s = sealed({"id": "plan", "text": "omit3"})
        with tempfile.TemporaryDirectory() as d:
            real, req = os.path.join(d, "elsewhere"), os.path.join(d, "requests")
            os.makedirs(real)
            os.makedirs(req)
            with open(os.path.join(real, "call.json"), "w") as f:
                json.dump({"x": "omit3"}, f)
            os.symlink(real, os.path.join(req, "linked"))
            report = t.scan([req], s)
        self.assertEqual((report.files, report.hits), (0, []))
        self.assertEqual(report.partial, [("requests/linked", "symlink")])
        self.assertIn("requests/linked: a symbolic link to a directory; skipped", report.notes)


class HostileText(unittest.TestCase):
    """Text a model wrote is the tripwire's normal input. Two patterns once cost time growing with the square of the
    text's length on one shape of text; each test gives that shape, at a size where the old pattern took about a
    minute or more, a bound of 2 s, which a pass over the text meets with room on a loaded machine (each measured at a
    few milliseconds to a few tens of milliseconds, 2026-11-20). Each fix is also held to the old pattern's answers on
    many small random texts, where the old pattern is quick."""

    BOUND_S = 2.0
    # The grouped-number pattern as it was, for the comparison.
    OLD_GROUPED = re.compile(r"(?<![^\W_])(?<![.,])[0-9]{1,3}([,_])[0-9]{3}(?:\1[0-9]{3})*(?:\.[0-9]+)?(?![0-9])"
                             r"(?!\.[0-9])(?![,_][0-9])")

    def timed(self, what: str, f) -> None:
        t0 = time.perf_counter()
        f()
        took = time.perf_counter() - t0
        self.assertLess(took, self.BOUND_S, f"{what} took {took:.2f} s")

    @staticmethod
    def texts(tokens, n=3000, seed=36):
        rand = random.Random(seed)
        for _ in range(n):
            yield "".join(rand.choice(tokens) for _ in range(rand.randrange(1, 24)))

    def test_a_long_run_of_underscored_groups(self) -> None:
        # 80,000 characters of this took 9.1 s before; 200,004 would take about a minute.
        s = t.parse_sealed({"version": 1, "values": [{"id": "n", "number": "4127.46"}]})
        text = "123_" * 50_000 + "1"
        self.timed("the grouped-number rule", lambda: self.assertEqual(t.find_sealed({"x": text}, s), []))
        self.timed("the grouped-number rule, with commas",
                   lambda: self.assertEqual(t.find_sealed({"x": text.replace("_", ",")}, s), []))

    def test_a_long_chain_of_data_prefixes(self) -> None:
        # 120,000 characters of this took 20 s before; 300,000 would take about two minutes.
        s = t.parse_sealed({"version": 1, "values": [{"id": "p", "text": "omit3"}]})
        self.timed("the data URL rule", lambda: self.assertEqual(t.find_sealed({"x": "data:;" * 50_000}, s), []))
        self.timed("the data URL rule, closed by a comma",
                   lambda: self.assertEqual(t.find_sealed({"x": "data:;" * 50_000 + ",x"}, s), []))
        # The two shapes the security scan of 2026-11-25 named (F3): every "data:" before a ";base64," that
        # no payload follows, and a run of "data:" with one ";base64," at its end. Each start read the parameters
        # to the same comma again.
        self.timed("the data URL rule, a ;base64 with no payload",
                   lambda: self.assertEqual(t.find_sealed({"x": "data:;" * 50_000 + "base64,"}, s), []))
        self.timed("the data URL rule, a ;base64 with no payload, then a space",
                   lambda: self.assertEqual(t.find_sealed({"x": "data:;" * 50_000 + "base64, x"}, s), []))
        self.timed("the data URL rule, one ;base64 after a run of starts",
                   lambda: self.assertEqual(t.find_sealed({"x": "data:" * 50_000 + ";base64,"}, s), []))

    def test_grouped_numbers_read_as_before(self) -> None:
        # A match now starts only at a run's first group. The one difference: a group after a digit and an
        # underscore is no start, so 1_2_345 is not read as 2,345 (Python reads that literal as 12345).
        seen = 0
        for text in self.texts(["1", "23", "123", "_", ",", ".", "4567", "a", " "]):
            new = {(m.start(), m.group(0)) for m in t._GROUPED.finditer(text)}
            old = {(m.start(), m.group(0)) for m in self.OLD_GROUPED.finditer(text)}
            seen += bool(new)
            self.assertLessEqual(new, old, text)
            for at, _ in old - new:
                self.assertRegex(text[:at], r"[0-9]_\Z", text)
        self.assertGreater(seen, 20)
        self.assertEqual([m.group(0) for m in self.OLD_GROUPED.finditer("1_2_345")], ["2_345"])
        self.assertEqual([m.group(0) for m in t._GROUPED.finditer("1_2_345")], [])

    def test_data_urls_read_as_before(self) -> None:
        tokens = ["data:", "DATA:", ";", ";base64", ";baſe64", ",", " ", "text/plain", "a", "/", "QUJD", "=", "\n", ":"]
        seen = 0
        for text in self.texts(tokens):
            want = [(m.span(), m.groups()) for m in t._DATA_URL.finditer(text)]
            seen += bool(want)
            self.assertEqual([(m.span(), m.groups()) for m in t._data_urls(text)], want, text)
        self.assertGreater(seen, 20)


class CommandLine(unittest.TestCase):
    def run_cli(self, *argv: str) -> "tuple[int, str]":
        out = io.StringIO()
        err = io.StringIO()
        import contextlib

        with contextlib.redirect_stderr(err):
            code = cli.main(list(argv), out=out)
        return code, out.getvalue() + err.getvalue()

    def test_tripwire_and_canary(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            sp = os.path.join(d, "sealed.json")
            with open(sp, "w") as f:
                json.dump({"version": 1, "values": [{"id": "plan/3", "text": "omit3"}, {"id": "t", "number": 31.5}]}, f)
            req = os.path.join(d, "req.json")
            with open(req, "w") as f:
                json.dump({"messages": [{"content": "clip omit3.mp4 at 31.50"}]}, f)
            clean = os.path.join(d, "clean.json")
            with open(clean, "w") as f:
                json.dump({"messages": [{"content": "clip 9f2c.mp4"}]}, f)
            code, text = self.run_cli("tripwire", "--sealed", sp, req)
            self.assertEqual(code, 1)
            self.assertIn("req.json: $.messages[0].content: sealed value plan/3 (text)", text)
            self.assertNotIn("omit3", text)
            code, text = self.run_cli("tripwire", "--sealed", sp, "--json", clean)
            self.assertEqual((code, json.loads(text)["hits"]), (0, []))
            with open(sp, "w") as f:
                f.write('{"version": 1, "values": [{"id": "x", "txt": "typo"}]}')
            code, text = self.run_cli("tripwire", "--sealed", sp, req)
            self.assertEqual(code, 2)
            self.assertIn("exactly one of text, number or sha256", text)

            self.assertEqual(self.run_cli("canary", "make", "truth", "truth")[0], 2)
            cp = os.path.join(d, "canary.json")
            self.assertEqual(self.run_cli("canary", "make", "truth", "-o", cp)[0], 0)
            marker = t.load_sealed(cp).values[0].text
            hidden = os.path.join(d, "truth.json")
            with open(hidden, "w") as f:
                json.dump({"label": marker}, f)
            code, text = self.run_cli("canary", "check", "--sealed", cp, "--planted", hidden, "--requests", clean)
            self.assertEqual(code, 0, text)
            code, text = self.run_cli("canary", "check", "--sealed", cp, "--planted", clean, "--requests", clean)
            self.assertEqual(code, 1)
            self.assertIn("not planted: no marker of place truth", text)


if __name__ == "__main__":
    unittest.main()
