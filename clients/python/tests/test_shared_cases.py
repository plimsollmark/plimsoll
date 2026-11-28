"""The record cases of internal/clientcases/testdata/records.json, which the Go and
TypeScript clients run too, on the paths this client has for them: the record an
unanswered session call's error carries (check_unanswered, which the session calls), the
lost call's record an attach answer returns (_lost_record, which the attach calls,
refusing every problem it states as a broken chain), an answered call's response against
the request sent (check) and the answer an attach returns for a lost call against that
call's record (check_lost_answer). The file-call cases of files-calls.json run through
``Session.run_files`` against the files daemon, each case a session of its own. Each
verdict is asserted here and written down for the judge of the shared cases
(tests/_cases.py)."""

from __future__ import annotations

import json
import unittest
from typing import Any, Dict, List, Optional

from plimsoll_client import ChainError, Client, MalformedResponseError, PlimsollError, SessionCheckpoint
from plimsoll_client import files as fs
from plimsoll_client._record import check, check_lost_answer, check_unanswered, files_op, record_from_wire, request_digest
from plimsoll_client._wire import Msg
from plimsoll_client.client import _files_result, _lost_record

from ._cases import ROOT, says_of, verdict
from ._env import setting

CASES = json.loads((ROOT / "internal" / "clientcases" / "testdata" / "records.json").read_text())["cases"]
FILES_CASES = json.loads((ROOT / "internal" / "clientcases" / "testdata" / "files-calls.json").read_text())["cases"]


def _operation(c: Dict[str, Any]) -> fs.FilesOperation:
    """A case's call (bytes in hex) as this client's operation."""
    x = bytes.fromhex
    op = c["op"]
    if op == "stat":
        return fs.FilesStat(x(c["path"]))
    if op == "read":
        return fs.FilesRead(x(c["path"]), offset=c["offset"], max_bytes=c["max_bytes"])
    if op == "write":
        return fs.FilesWrite(x(c["path"]), x(c["content"]), mode=c["mode"], make_parents=c["make_parents"])
    if op == "list":
        return fs.FilesList(x(c["path"]), recursive=c["recursive"], match=x(c["match"]), after=x(c["after"]), budget_bytes=c["budget_bytes"])
    if op == "read_many":
        return fs.FilesReadMany([x(p) for p in c["paths"]], max_bytes_each=c["max_bytes_each"], budget_bytes=c["budget_bytes"])
    if op == "make_dir":
        return fs.FilesMakeDir(x(c["path"]), parents=c["parents"])
    if op == "remove":
        return fs.FilesRemove(x(c["path"]), dir=c["dir"])
    if op == "rename":
        return fs.FilesRename(x(c["from"]), x(c["to"]), replace=c["replace"])
    raise AssertionError(f"a case names the operation {op!r}")


def _answer_says(r: fs.FilesResult) -> Dict[str, Any]:
    """A file call's result as the shared cases state it: words, and bytes in hex."""
    a: Dict[str, Any] = {"outcome": r.outcome, "error": r.error, "errno": r.errno, "op": r.op}
    ans = r.answer
    if isinstance(ans, fs.FilesStatAnswer):
        a.update(type=ans.type, size=ans.size, mode=ans.mode)
    elif isinstance(ans, fs.FilesReadAnswer):
        a.update(content=ans.content.hex(), size_at_open=ans.size_at_open)
    elif isinstance(ans, fs.FilesWriteAnswer):
        a.update(written=ans.written)
    elif isinstance(ans, fs.FilesListAnswer):
        a.update(entries=[{"path": e.path.hex(), "type": e.type, "size": e.size} for e in ans.entries], more=ans.more)
    elif isinstance(ans, fs.FilesReadManyAnswer):
        a.update(items=[{"error": i.error, "errno": i.errno, "content": i.content.hex(), "size_at_open": i.size_at_open} for i in ans.items], more=ans.more)
    return {"answer": a}


class SharedRecordCases(unittest.TestCase):
    def test_every_record_case_on_every_path(self) -> None:
        self.assertTrue(CASES, "no record cases")
        for c in CASES:
            inp = c["input"]
            for path in c["paths"]:
                err: Optional[PlimsollError] = None
                if path == "session-unanswered":
                    try:
                        check_unanswered(inp["requestSha256"], inp["floor"], None, Msg(inp["record"], "unanswered"))
                    except PlimsollError as e:
                        err = e
                elif path == "answer":
                    # The answered call's response against the request sent, as the
                    # session's call checks it (check, with the request's operation).
                    req = inp["request"]
                    try:
                        check(request_digest(req), "files", None, Msg(inp["response"], "run"), files_op(Msg(req["files"], "files")))
                    except PlimsollError as e:
                        err = e
                elif path == "lost-answer":
                    # The same response as an attach's lost answer, against its own record.
                    try:
                        resp = Msg(inp["response"], "lostAnswer")
                        rec = resp.get_msg("record")
                        assert rec is not None
                        check_lost_answer(resp, record_from_wire(rec))
                    except PlimsollError as e:
                        err = e
                elif path == "attach-lost":
                    cp = SessionCheckpoint.from_json(inp["checkpoint"])
                    _, problem = _lost_record(cp, inp["lost"], Msg(inp["record"], "lostRecord"))
                    if problem:
                        err = ChainError(f"plimsoll: the daemon's answer to the attach {problem}")
                else:
                    continue  # a path this client does not have (stored is Go's)
                with self.subTest(c["id"], path=path):
                    got = says_of(err)
                    verdict(c["id"], path, got)
                    self.assertEqual(got, c["expect"][path], err)


class FilesAnswerValues(unittest.TestCase):
    """session-files-20: what this client returns of a file call's answer is what its record's
    digest covered: both read the answer through the same typed reads (Msg), so an integer in
    the other form proto3 JSON allows (mode "420", a size as a JSON number) reaches the caller as
    the integer, and an answer whose flag is not a boolean or whose number is not an integer is
    refused before any value of it reaches a caller."""

    def _result(self, case_id: str) -> fs.FilesResult:
        c = next(c for c in CASES if c["id"] == case_id)
        resp = Msg(c["input"]["response"], "response")
        return _files_result(resp, resp.get_msg("files"))

    def test_the_values_returned_are_the_values_hashed(self) -> None:
        for case_id in ("files-answer/accepted", "files-answer/accepted-integers-as-strings"):
            a = self._result(case_id).answer
            self.assertEqual((a.type, a.size, a.mode), ("file", 1234, 420), case_id)
            self.assertIs(type(a.mode), int, case_id)
        for case_id in ("files-answer/list-more-a-string", "files-answer/read-many-more-a-number", "files-answer/mode-a-fraction", "files-answer/size-a-boolean"):
            with self.assertRaises(MalformedResponseError, msg=case_id):
                self._result(case_id)


class SharedFileCallCases(unittest.TestCase):
    def test_every_file_call_case(self) -> None:
        self.assertTrue(FILES_CASES, "no file-call cases")
        url = setting("PLIMSOLL_FILES_URL")
        for c in FILES_CASES:
            s = Client(url).open_session()
            self.assertEqual(s.file_scopes, ("work",))
            self.assertEqual(s.work_dir, "/work")
            calls: List[Any] = []
            for call in c["input"]["calls"]:
                tid = f"forge-files-{call['forge']}" if call.get("forge") else None
                try:
                    r = s.run_files(_operation(call["call"]), trace_id=tid)
                except PlimsollError as e:
                    outcome, _, check = says_of(e).partition("/")
                    v: Dict[str, Any] = {"refused": outcome}
                    if call.get("rule"):
                        v["check"] = check
                    calls.append(v)
                    continue
                self.assertIsNotNone(r.record)
                calls.append(_answer_says(r))
            got = {"calls": calls}
            with self.subTest(c["id"]):
                verdict(c["id"], "files-call", got)
                self.assertEqual(got, c["expect"]["files-call"])
            try:
                s.close()
            except PlimsollError:
                pass

    def test_paths_as_text_and_the_async_session(self) -> None:
        """A str path is encoded as os.fsencode encodes it, so a name os.fsdecode made from
        bytes that are not UTF-8 names the same file; text in another normal form is
        another name; the display form is beside the bytes. A malformed operation is
        refused before anything is sent. The async session's run_files is the same call."""
        import asyncio
        import os

        from plimsoll_client import AsyncSession, InvalidRequestError

        s = Client(setting("PLIMSOLL_FILES_URL")).open_session()
        raw = b"caf\xc3\xa9-\xff\n"  # "café" in NFC, a byte that is not UTF-8, a newline
        self.assertEqual(s.run_files(fs.FilesWrite(raw, b"1")).error, "none")
        listed = s.run_files(fs.FilesList())
        assert isinstance(listed.answer, fs.FilesListAnswer)
        self.assertEqual([(e.path, e.path_text) for e in listed.answer.entries], [(raw, "caf\u00e9-\\xff\n")])
        self.assertEqual(s.run_files(fs.FilesStat(os.fsdecode(raw))).error, "none")
        nfd = "cafe\u0301-" + os.fsdecode(b"\xff\n")  # the same text in NFD: another name
        self.assertEqual(s.run_files(fs.FilesStat(nfd)).error, "not_found")
        for bad in (fs.FilesRead(raw, max_bytes=-1), fs.FilesWrite(raw, "text"), fs.FilesStat(raw, scope="disk"), fs.FilesReadMany(raw), "stat"):
            with self.subTest(bad=bad), self.assertRaises(InvalidRequestError) as cm:
                s.run_files(bad)  # type: ignore[arg-type]
            self.assertEqual(cm.exception.not_dispatched, "request")
        r = asyncio.run(AsyncSession(s).run_files(fs.FilesRead(raw)))
        assert isinstance(r.answer, fs.FilesReadAnswer)
        self.assertEqual((r.answer.content, r.record.sequence if r.record else 0), (b"1", 5))
        s.close()


if __name__ == "__main__":
    unittest.main()
