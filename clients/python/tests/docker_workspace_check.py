"""The agent workspace on a real docker session: its file calls through plimsoll's own
helper in the sandbox (docs/session-files.md), and what the command scripts do there. Not a test_*.py, so `unittest discover` does not pick it up: the daemon-backed
suites must never skip, and this one needs docker. client_test.go's
TestPythonWorkspaceDocker serves a docker daemon with sessions on, sets
PLIMSOLL_DOCKER_SESSIONS_URL and runs this module by name; `make docker-suite` runs that
test. Without the setting every case skips, unless PLIMSOLL_DOCKER_REQUIRED=1."""

from __future__ import annotations

import errno
import io
import os
import tarfile
import unittest
from typing import Optional

from plimsoll_client import CancelHandle, Client, Workspace, WorkspacePathError, WorkspaceTooLargeError
from plimsoll_client.errors import RequestCanceledError
from plimsoll_client import files as fs
from plimsoll_client import workspace as ws


def _url() -> str:
    url = os.environ.get("PLIMSOLL_DOCKER_SESSIONS_URL", "")
    if not url:
        if os.environ.get("PLIMSOLL_DOCKER_REQUIRED") == "1":
            raise RuntimeError("PLIMSOLL_DOCKER_SESSIONS_URL is not set, and PLIMSOLL_DOCKER_REQUIRED=1")
        raise unittest.SkipTest("PLIMSOLL_DOCKER_SESSIONS_URL is not set; run through go test ./clients/python -run TestPythonWorkspaceDocker")
    return url


class _CancelAfter:
    """A session that cancels ``handle`` once a file call of kind ``after`` is answered, so
    the operation's next call is refused before it is sent; everything else is the session's."""

    def __init__(self, inner) -> None:
        self.inner = inner
        self.handle: Optional[CancelHandle] = None
        self.after: Optional[type] = None

    def run_files(self, op, **kw):
        out = self.inner.run_files(op, **kw)
        if self.after is not None and self.handle is not None and isinstance(op, self.after):
            self.handle.cancel()
        return out

    def __getattr__(self, name: str):
        return getattr(self.inner, name)


class WorkspaceOnDocker(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = Client(_url())

    def workspace(self) -> Workspace:
        return Workspace(self.client.open_session(minimum_isolation="container"), timeout=60)

    def test_cwd_and_exports_persist_across_commands(self) -> None:
        with self.workspace() as w:
            root = w.root
            self.assertTrue(root.startswith("/"), root)
            out = w.exec("mkdir -p a/b && cd a/b && export GREETING=hello && echo $PWD")
            self.assertEqual(out.exit_code, 0, out.stderr_text)
            self.assertEqual(out.stdout_text.strip(), root + "/a/b")
            self.assertEqual(out.cwd, root + "/a/b")
            out = w.exec("pwd; echo $GREETING")
            self.assertEqual(out.stdout_text.split("\n")[:2], [root + "/a/b", "hello"])
            # A command's own exports cannot move the state directory of a later step.
            w.exec("export __plimsoll_s=/tmp/elsewhere; export PWD=/tmp")
            out = w.exec("echo $GREETING; pwd")
            self.assertEqual(out.stdout_text.split("\n")[:2], ["hello", root + "/a/b"])
            self.assertEqual(out.exit_code, 0)
            out = w.exec("exit 7")
            self.assertEqual(out.exit_code, 7)
            out = w.exec("false")
            self.assertEqual(out.exit_code, 1)

    def test_files_search_and_edit(self) -> None:
        with self.workspace() as w:
            w.write("src/app.py", "import os\nprint('one')\n")
            w.write("src/lib/util.py", "import sys\n")
            w.write("data.bin", bytes(range(256)) * 3)
            self.assertEqual(w.read("src/app.py"), b"import os\nprint('one')\n")
            self.assertEqual(w.read("data.bin"), bytes(range(256)) * 3)
            self.assertEqual(w.read("data.bin", max_bytes=4), bytes(range(4)))
            self.assertEqual(w.read(w.root + "/src/app.py"), b"import os\nprint('one')\n")
            with self.assertRaises(FileNotFoundError):
                w.read("missing.txt")
            with self.assertRaises(IsADirectoryError):
                w.read("src")
            with self.assertRaises(WorkspacePathError):
                w.read("/etc/passwd")
            self.assertEqual(w.glob("*.py", "src"), ["app.py"])
            self.assertEqual(w.glob("src/**/*.py"), ["src/app.py", "src/lib/util.py"])
            self.assertEqual(w.glob("**/util.py"), ["src/lib/util.py"])
            self.assertEqual(w.glob("*.nothing"), [])
            # A pattern with a space is one pattern on BusyBox sh too (finding release-41).
            w.write("my", "m")
            w.write("my file1.txt", "f")
            self.assertEqual(w.glob("my file*.txt"), ["my file1.txt"])
            # A dash-led name past one piece is just a name (finding release-42).
            dashed = bytes(range(256)) * ((ws.MAX_READ_BYTES + 3000) // 256)
            w.write("-big", dashed)
            self.assertEqual(w.read_whole("-big"), dashed)
            self.assertEqual(w.grep("^import", "src"), "src/app.py:1:import os\nsrc/lib/util.py:1:import sys")
            self.assertEqual(w.grep("print", "src/app.py"), "src/app.py:2:print('one')")
            self.assertEqual(w.grep("absent"), "")
            with self.assertRaises(ValueError):
                w.grep("(")
            self.assertEqual(w.edit("src/app.py", "'one'", "'two'"), 1)
            self.assertEqual(w.read("src/app.py"), b"import os\nprint('two')\n")
            out = w.exec("cat src/app.py | wc -l")
            self.assertEqual(out.stdout_text.strip(), "2")

    def test_persist_then_hydrate_into_another_session(self) -> None:
        big = os.urandom(9 << 20)  # past 8 MiB: the archive is read and written in pieces
        with self.workspace() as a:
            a.write("keep/me.txt", "kept\n")
            a.write("blob", b"\x00\x01\x02")
            a.write("big.bin", big)
            a.exec("export X=1")
            tar = a.persist()
            self.assertGreater(len(tar), 9 << 20)
            # The archive is gone from the sandbox once read, and no file method sees the state.
            out = a.exec("ls -a .plimsoll-shell")
            self.assertNotIn("persist-", out.stdout_text)
        names = {m.name.lstrip("./") for m in tarfile.open(fileobj=io.BytesIO(tar)).getmembers()}
        self.assertIn("keep/me.txt", names)
        self.assertIn("blob", names)
        self.assertFalse(any(n.startswith(".plimsoll-shell") for n in names), names)
        with self.workspace() as b:
            b.hydrate(tar)
            self.assertEqual(b.read("keep/me.txt"), b"kept\n")
            self.assertEqual(b.read("blob"), b"\x00\x01\x02")
            self.assertEqual(b.read_whole("big.bin"), big)
            self.assertNotIn("hydrate-", b.exec("ls -a .plimsoll-shell").stdout_text)
        with self.workspace() as c:
            c.write("small", "x")
            with self.assertRaises(WorkspaceTooLargeError):
                c.persist(limit=100)

    def test_a_persist_or_hydrate_cut_by_its_cancel_handle_leaves_no_archive(self) -> None:
        # release-128: the handle is cancelled once the first piece is answered, so the next
        # call is refused before it is sent and the session goes on; the archive must go.
        s = _CancelAfter(self.client.open_session(minimum_isolation="container"))
        with Workspace(s, timeout=60) as w:
            w.write("big.bin", os.urandom(9 << 20))  # past 8 MiB: the archive is read in two pieces
            for method, args, after in (
                (w.persist, (), fs.FilesRead),
                (w.hydrate, (b"x" * ((4 << 20) + 1),), fs.FilesWrite),  # two writes
            ):
                s.handle, s.after = CancelHandle(), after
                with self.assertRaises(RequestCanceledError):
                    method(*args, cancel=s.handle)
                s.after = None
                out = w.exec("ls -a .plimsoll-shell")
                self.assertEqual(out.exit_code, 0, out.stderr_text)
                self.assertNotIn("persist-", out.stdout_text)
                self.assertNotIn("hydrate-", out.stdout_text)

    def test_a_persist_past_half_the_work_folder_is_a_size_error(self) -> None:
        # release-129, and the outside fact py-tar-no-space-words: tar in the image prints the
        # C library's "No space left on device" when /work (a 128 MiB tmpfs) cannot hold the
        # archive beside the tree.
        with self.workspace() as w:
            w.write("big.bin", os.urandom(77 << 20))  # 60 percent of /work
            with self.assertRaises(WorkspaceTooLargeError) as e:
                w.persist(limit=None)
            self.assertIn("work folder", str(e.exception))
            self.assertNotIn("persist-", w.exec("ls -a .plimsoll-shell").stdout_text)

    def test_links_folders_pipes_and_odd_names_through_the_helper(self) -> None:
        with self.workspace() as w:
            w.write("a.txt", "A")
            out = w.exec("mkdir -p d && ln -s a.txt inside && ln -s ../a.txt d/up && ln -s /etc out && mkfifo pipe "
                         "&& printf x > \"$(printf 'caf\\351')\" && printf h > .env")
            self.assertEqual(out.exit_code, 0, out.stderr_text)
            # A link that stays inside the work directory is followed; one that leaves is refused.
            self.assertEqual(w.read("inside"), b"A")
            self.assertEqual(w.read("d/up"), b"A")
            with self.assertRaises(WorkspacePathError):
                w.read("out/passwd")
            self.assertEqual(w.stat("inside").type, "link")
            kinds = {e.path: e.type for e in w.list()}
            self.assertEqual((kinds[b"inside"], kinds[b"out"], kinds[b"d"], kinds[b"a.txt"]), ("link", "link", "dir", "file"))
            self.assertEqual(kinds[b"pipe"], "other")
            self.assertNotIn(ws.STATE_DIR.encode(), kinds)
            # A FIFO is never opened: an answered error at once, not a hang until the deadline.
            with self.assertRaises(OSError) as caught:
                w.read("pipe")
            self.assertEqual(caught.exception.errno, errno.ENXIO)
            with self.assertRaises(IsADirectoryError):
                w.read_whole("d")
            # A name that is not UTF-8 is listed by its bytes and read back by them.
            self.assertIn(b"caf\xe9", kinds)
            self.assertEqual(w.read(b"caf\xe9"), b"x")
            # `*` matches dot files now (the helper's glob).
            self.assertIn(".env", w.glob("*"))
            self.assertIn("inside", w.glob("*"))
            # stat, rename, make_dir, remove.
            w.make_dir("n/m", parents=True)
            w.rename("a.txt", "n/m/a.txt")
            self.assertEqual(w.read("n/m/a.txt"), b"A")
            with self.assertRaises(FileNotFoundError):
                w.read("inside")  # a dangling link now
            w.remove("inside")
            with self.assertRaises(OSError) as caught:
                w.remove("n", dir=True)
            self.assertEqual(caught.exception.errno, errno.ENOTEMPTY)
            items = w.read_many(["n/m/a.txt", "nope", "d"])
            self.assertEqual([(i.error, i.content) for i in items], [("none", b"A"), ("not_found", b""), ("is_dir", b"")])

    def test_a_recursive_listing_names_a_folder_it_cannot_enter_and_goes_on(self) -> None:
        # As Workspace.list's docstring states (the pre-scan clients review, finding release-131):
        # an entry of type unreadable, no error; only the folder listed itself is PermissionError.
        with self.workspace() as w:
            out = w.exec("mkdir -p a/locked/deep b && touch a/locked/deep/x b/y && chmod 000 a/locked")
            self.assertEqual(out.exit_code, 0, out.stderr_text)
            got = [(e.path, e.type) for e in w.list(recursive=True)]
            self.assertEqual(got, [(b"a", "dir"), (b"a/locked", "unreadable"), (b"b", "dir"), (b"b/y", "file")])
            with self.assertRaises(PermissionError):
                list(w.list("a/locked"))

    def test_a_page_ended_by_its_budget_a_listing_past_its_bounds_and_a_call_past_its_deadline(self) -> None:
        with self.workspace() as w:
            s = w.session
            out = w.exec("mkdir many && cd many && i=0; while [ $i -lt 600 ]; do : > \"a-name-of-forty-bytes-or-thereabouts-$i\"; i=$((i+1)); done")
            self.assertEqual(out.exit_code, 0, out.stderr_text)
            # Paged by hand at the least budget: every page holds an entry and ends with more,
            # and the cursor picks up after the last entry, nothing missed or repeated.
            pages, paths, after = 0, [], b""
            while True:
                r = s.run_files(fs.FilesList(b"many", after=after, budget_bytes=8192))
                self.assertEqual((r.outcome, r.error, r.op), ("completed", "none", "list"))
                self.assertTrue(r.answer.entries)
                pages += 1
                paths += [e.path for e in r.answer.entries]
                if not r.answer.more:
                    break
                after = r.answer.entries[-1].path
            self.assertGreater(pages, 2)
            self.assertEqual(len(paths), 600)
            self.assertEqual(paths, sorted(set(paths)))
            self.assertEqual([e.path for e in w.list("many")], paths)
            # A tree deeper than a listing walks in one call: scan_limit, never a cut answer.
            w.run(["mkdir", "-p", "/".join(["deep"] + ["a"] * 520)])
            r = s.run_files(fs.FilesList(b"deep", recursive=True))
            self.assertEqual((r.outcome, r.error, r.answer), ("completed", "scan_limit", None))
            with self.assertRaises(WorkspaceTooLargeError):
                list(w.list("deep", recursive=True))
            # A call past its deadline is timed_out (an answer, in the chain); the session goes on.
            r = s.run_files(fs.FilesStat(b"."), timeout=0.001)
            self.assertEqual(r.outcome, "timed_out")
            self.assertIsNotNone(r.record)
            with self.assertRaises(TimeoutError):
                Workspace(s, timeout=0.001).stat(".")
            self.assertEqual(w.stat("many").type, "dir")

    def test_an_unconfined_workspace_names_paths_in_the_sandbox(self) -> None:
        session = self.client.open_session(minimum_isolation="container")
        with Workspace(session, timeout=60, confined=False) as w:
            w.write("/tmp/staged/x.txt", "outside")
            self.assertEqual(w.read("/tmp/staged/x.txt"), b"outside")
            w.write("inside.txt", "in")
            self.assertEqual(w.read(w.root + "/inside.txt"), b"in")
            self.assertEqual(w.exec("cat /tmp/staged/x.txt inside.txt").stdout_text, "outsidein")
            # A kernel file whose open states size 0 is read whole all the same: the helper's
            # own /proc/self/status, the guest's uid in it.
            status = w.read_whole("/proc/self/status")
            self.assertTrue(status.startswith(b"Name:\t"), status[:80])
            self.assertIn(b"\nUid:\t", status)

    def test_a_background_process_does_not_survive_the_call(self) -> None:
        with self.workspace() as w:
            out = w.exec("(sleep 2; echo late > marker.txt) >/dev/null 2>&1 & echo started")
            self.assertEqual(out.stdout_text.strip(), "started")
            out = w.exec("sleep 3; ls marker.txt 2>&1 || echo absent")
            self.assertEqual(out.stdout_text.strip().split("\n")[-1], "absent")


if __name__ == "__main__":
    unittest.main()
