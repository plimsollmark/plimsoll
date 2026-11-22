"""Mutation check for what the Agent Framework adapter hands the application: each mutation
breaks one behavior in a scratch copy of plimsoll-client's source (under tmp/), and the Agent
Framework suite (frameworks/agent_framework) must fail on it. The unmutated suite must pass
first. Needs the Agent Framework environment (make py-frameworks PY_FRAMEWORKS=agent_framework);
from the repository root:

    python3 clients/python/frameworks/agent_framework/mutate_agent_framework.py
"""

import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), *[os.pardir] * 4))  # the repository
PY = os.path.join(ROOT, "tmp", "py-frameworks", "agent_framework", "bin", "python")
CLIENTS = os.path.join(ROOT, "clients", "python")

AF = "plimsoll_client/agent_framework.py"
WS = "plimsoll_client/workspace.py"

MUTATIONS = [
    ("run drops the tier", AF, "            isolation=r.isolation,\n", ""),
    ("run drops the record digest", AF, '            record_sha256=r.record.sha256 if r.record is not None else "",\n', ""),
    ("run drops the checked result", AF, "            result=r,\n        )", "        )"),
    ("parser drops the labels", AF, "{**fields, **call_labels(result)}", "fields"),
    ("parser drops Microsoft's fields", AF, "{**fields, **call_labels(result)}", "call_labels(result)"),
    ("no span label on a result", AF, "            _label_span(name, call_labels(result))\n            return result", "            return result"),
    ("no span label on a refusal", AF, "                _label_span(name, call_labels(e))\n                if may_have_run(e):", "                if may_have_run(e):"),
    ("span guard removed", AF, "        if attributes is None or (", "        if False and ("),
    ("a span that hides its attributes is labeled (release-32)", AF, "        if attributes is None or (", "        if attributes is not None and ("),
    ("instrumentation switch ignored", AF, "        if not OBSERVABILITY_SETTINGS.ENABLED:\n            return\n", ""),
    ("labels skip the closed-set check", AF, "def call_labels(value: Any) -> Dict[str, str]:", "def call_labels(value: Any) -> Dict[str, str]:\n    if isinstance(value, PlimsollShellResult):\n        return {'plimsoll_dispatched': 'yes', 'plimsoll_outcome': value.outcome, 'plimsoll_isolation': value.isolation, 'plimsoll_record_sha256': value.record_sha256}"),
    ("refusal reason dropped", AF, '        return _closed_set_labels({"refused": value.not_dispatched})', "        return _closed_set_labels({})"),
    ("unanswered record ignored", AF, "    record = value.record if isinstance(value, PlimsollError) else None", "    record = None"),
    ("code tool parser drops labels", AF, "call_labels(answer) if isinstance(answer, Mapping) else {}", "{}"),
    ("code tool span not labeled", AF, "        _label_span(name, call_labels(answer))\n        return answer", "        return answer"),
    ("workspace drops the result again", WS, 'raise WorkspaceCallError(f"plimsoll: the call did not run: {result.outcome}: {result.detail}", result)',
     'raise RuntimeError(f"plimsoll: the call did not run: {result.outcome}: {result.detail}")'),
    ("refusals raised as the kit's ShellExecutionError", AF, "        out = workspace.exec(command, timeout=budget, cancel=cancel)\n",
     "        try:\n            out = workspace.exec(command, timeout=budget, cancel=cancel)\n        except PlimsollError as e:\n            from agent_framework_tools.shell import ShellExecutionError\n            raise ShellExecutionError(str(e)) from e\n"),
    ("a command that may have run does not stop the run", AF, "                if may_have_run(e):\n", "                if False:\n"),
    ("setup_failed counted as may have run", AF, 'isinstance(e, WorkspaceCallError) and e.result.outcome == "setup_failed":', "False:"),
    ("labels do not read through the stop", AF, "        value = value.__cause__\n", "        pass\n"),
    ("an exception that is not plimsoll's counts as nothing ran (release-28)", AF,
     "    return True\n\n\ndef _check_command", "    return isinstance(e, (PlimsollError, WorkspaceCallError))\n\n\ndef _check_command"),
    ("the command check is not made before the call (release-28)", AF, "        _check_command(command)\n", ""),
    ("the description says BusyBox sh on every provider (release-29)", AF,
     "The shell is the sandbox image's sh (BusyBox sh on plimsoll's docker images).", "The shell is BusyBox sh."),
    ("a retry of a failed command", AF, "                result = await self.run(command)\n            except Exception as e:",
     "                try:\n                    result = await self.run(command)\n                except PlimsollError:\n                    result = await self.run(command)\n            except Exception as e:"),
]


def suite(src: str) -> bool:
    """Whether the Agent Framework suite passes against the source tree src."""
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([src, os.path.join(CLIENTS, "agent-framework-plimsoll", "src")]),
               PYTHONDONTWRITEBYTECODE="1")
    p = subprocess.run([PY, "-B", "-m", "unittest", "discover", "-s", "frameworks/agent_framework", "-t", "."], cwd=CLIENTS,
                       env=env, capture_output=True, text=True)
    return p.returncode == 0


def main() -> int:
    if not suite(os.path.join(CLIENTS, "src")):
        print("the unmutated suite fails: fix that first")
        return 1
    survived = 0
    for label, rel, old, new in MUTATIONS:
        os.makedirs(os.path.join(ROOT, "tmp"), exist_ok=True)
        scratch = tempfile.mkdtemp(dir=os.path.join(ROOT, "tmp"), prefix="mut-af-")
        try:
            src = os.path.join(scratch, "src")
            shutil.copytree(os.path.join(CLIENTS, "src"), src)
            path = os.path.join(src, rel)
            text = open(path).read()
            if text.count(old) != 1:
                print(f"BAD MUTATION ({text.count(old)} matches): {label}")
                survived += 1
                continue
            open(path, "w").write(text.replace(old, new))
            killed = not suite(src)
            survived += not killed
            print(("killed  " if killed else "SURVIVED") + "  " + label)
        finally:
            shutil.rmtree(scratch)
    print(f"{len(MUTATIONS) - survived} of {len(MUTATIONS)} killed")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
