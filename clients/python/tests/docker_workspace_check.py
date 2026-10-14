"""The agent workspace on a real docker session: what the fixed scripts do in the
sandbox. Not a test_*.py, so `unittest discover` does not pick it up: the daemon-backed
suites must never skip, and this one needs docker. client_test.go's
TestPythonWorkspaceDocker serves a docker daemon with sessions on, sets
PLIMSOLL_DOCKER_SESSIONS_URL and runs this module by name; `make docker-suite` runs that
test. Without the setting every case skips, unless PLIMSOLL_DOCKER_REQUIRED=1."""

from __future__ import annotations

import io
import os
import tarfile
import unittest

from plimsoll_client import Client, Workspace, WorkspacePathError


def _url() -> str:
    url = os.environ.get("PLIMSOLL_DOCKER_SESSIONS_URL", "")
    if not url:
        if os.environ.get("PLIMSOLL_DOCKER_REQUIRED") == "1":
            raise RuntimeError("PLIMSOLL_DOCKER_SESSIONS_URL is not set, and PLIMSOLL_DOCKER_REQUIRED=1")
        raise unittest.SkipTest("PLIMSOLL_DOCKER_SESSIONS_URL is not set; run through go test ./clients/python -run TestPythonWorkspaceDocker")
    return url


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
            with self.assertRaises(FileNotFoundError):
                w.read("src")
            with self.assertRaises(WorkspacePathError):
                w.read("/etc/passwd")
            self.assertEqual(w.glob("*.py", "src"), ["app.py"])
            self.assertEqual(w.glob("src/**/*.py"), ["src/app.py", "src/lib/util.py"])
            self.assertEqual(w.glob("**/util.py"), ["src/lib/util.py"])
            self.assertEqual(w.glob("*.nothing"), [])
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
        with self.workspace() as a:
            a.write("keep/me.txt", "kept\n")
            a.write("blob", b"\x00\x01\x02")
            a.exec("export X=1")
            tar = a.persist()
        names = {m.name.lstrip("./") for m in tarfile.open(fileobj=io.BytesIO(tar)).getmembers()}
        self.assertIn("keep/me.txt", names)
        self.assertIn("blob", names)
        self.assertFalse(any(n.startswith(".plimsoll-shell") for n in names), names)
        with self.workspace() as b:
            b.hydrate(tar)
            self.assertEqual(b.read("keep/me.txt"), b"kept\n")
            self.assertEqual(b.read("blob"), b"\x00\x01\x02")

    def test_a_background_process_does_not_survive_the_call(self) -> None:
        with self.workspace() as w:
            out = w.exec("(sleep 2; echo late > marker.txt) >/dev/null 2>&1 & echo started")
            self.assertEqual(out.stdout_text.strip(), "started")
            out = w.exec("sleep 3; ls marker.txt 2>&1 || echo absent")
            self.assertEqual(out.stdout_text.strip().split("\n")[-1], "absent")


if __name__ == "__main__":
    unittest.main()
