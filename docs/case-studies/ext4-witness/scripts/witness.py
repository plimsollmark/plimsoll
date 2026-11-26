#!/usr/bin/env python3
"""witness.py: undo kernel fixes one at a time and see which ext4 KUnit tests notice. Standard library only.

This is the program behind the ext4 case-study page
(https://plimsollmark.github.io/plimsoll/case-studies/ext4-witness/index.html), as it stood for the last run there
(the kernel configuration check). Earlier runs that day used earlier versions of it: the 48-fix run predates the
stopped-part-way outcome (it labeled its one crash "cannot-run"), and kconfig_add came with the configuration check.
The copy published here differs from the one that ran last in three ways only, none of which changes a result: the
Linux checkout and the build directories can be moved with WITNESS_REPO and WITNESS_WORK (the defaults are the paths
the runs used), ccache is used only when it is installed, and the comments were rewritten for outside readers.

It reads a queue of jobs (queues.py writes them) and runs each against a Linux checkout that already holds the
commits the jobs name (setup.sh fetches them).

Forms:
  revert  at the tip, the fix's changes outside fs/ext4/*-test.c reversed (git diff FIX^ FIX, applied with
          git apply -R --3way), against the tip itself: "the code without the fix, the tests as they are".
          The test files are kept on purpose: a whole-commit revert would also delete a test that came in the
          same commit as its fix.
  pair    the fix's parent with the named test files as at the test's commit laid over it, against the fix with the
          same files laid over it: "the literal before and after".
  plain   one commit, no change: the whole suite as it is there. With kconfig_add (a list of "CONFIG_X=y" strings)
          those options go to kunit.py's --kconfig_add on top of fs/ext4/.kunitconfig, in a build directory of their
          own; report_config names further options whose .config values are recorded.

Per KUnit test case, the outcome is one of:
  witness        fails before (without the fix), passes after (with it)
  passes-both    passes before and after: it does not tell the fix apart
  not-reached    the unfixed tree's run stopped part way (a test or suite reported ERROR, the crash kunit.py
                 records) before it reached this test
  cannot-run     the unfixed tree has no such test, or could not be made or built
  fails-after    the test does not pass on the fixed tree itself
A job whose fixed tree does not build, or whose run writes no results, is build-or-infra; a job with no witness whose
unfixed tree stopped part way is stopped-part-way (the code without the fix crashed the suite, which is not the same
as a reversal that does not apply). A job's verdict is "witnessed" when at least one test is a witness, otherwise
"not-witnessed".

Two optional job fields, used by the masking check:
  revert   (revert form) the commits whose non-test changes are reversed at the tip, in this order; default [fix].
           A later fix whose diff touches an earlier one's lines is listed first.
  watch    "FILE:LINE" locations of KUnit expectations. kunit.py prints each failed one as
           "# TEST: EXPECTATION FAILED at FILE:LINE"; each run's failed locations are recorded (failed_at), and each
           watched location gets an outcome as a test does (witness: fails before, not after). With watch, the job's
           verdict is "witnessed" when every watched location is a witness; the test-level verdict is kept as
           test_verdict.

usage: witness.py QUEUE.json OUTDIR      (QUEUE: {"tip": SHA, "jobs": [job, ...]})
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time

WORK = os.environ.get("WITNESS_WORK", "/root")
REPO = os.environ.get("WITNESS_REPO", os.path.join(WORK, "linux"))
JOBS = str(os.cpu_count() or 8)
KUNIT_TIMEOUT = 2400
UML_TMP = os.path.join(WORK, "umltmp")
CC = "CC=ccache gcc" if shutil.which("ccache") else "CC=gcc"
FAILED_AT = re.compile(r"# (\S+): (?:EXPECTATION|ASSERTION) FAILED at (\S+:\d+)")


def git(*a, check=True, inp=None):
    r = subprocess.run(["git", "-C", REPO, *a], input=inp, capture_output=True)
    if check and r.returncode != 0:
        raise RuntimeError("git %s: %s" % (" ".join(a), r.stderr.decode("utf-8", "replace")[-800:]))
    return r


def reset(commit):
    git("reset", "-q", "--hard")
    git("clean", "-fdq")
    git("checkout", "-q", "--detach", commit)
    git("reset", "-q", "--hard")


def flatten(node, prefix, out):
    name = node.get("name") or ""
    here = prefix + "." + name if prefix and name else (name or prefix)
    for tc in node.get("test_cases") or []:
        out[here + "." + tc["name"] if here else tc["name"]] = tc.get("status", "?")
    for sg in node.get("sub_groups") or []:
        flatten(sg, here, out)


def failed_at(log):
    """The expectations kunit.py's output reports failed: sorted "FILE:LINE" strings, each once."""
    return sorted({m.group(2) for m in FAILED_AT.finditer(log)})


def kunit(tag, build_dir, outdir, suite, kconfig_add=()):
    """One kunit.py run of the tree as checked out, with any --kconfig_add options on top of fs/ext4/.kunitconfig.
    Returns (tests or None, seconds, exit code, log tail, failed expectations). The kernel's own output
    (BUILD_DIR/test.log) and the generated .config are kept beside the log as TAG.kernel.log and TAG.config."""
    js = os.path.join(outdir, tag + ".kunit.json")
    if os.path.exists(js):
        os.remove(js)
    argv = ["python3", "tools/testing/kunit/kunit.py", "run", "--arch=um", "--kunitconfig=fs/ext4",
            "--build_dir=" + build_dir, "--jobs=" + JOBS, "--json=" + js, "--make_options", CC]
    for opt in kconfig_add:
        argv.append("--kconfig_add=" + opt)
    if suite:
        argv.append(suite)
    t0 = time.time()
    try:
        # UML maps its memory from a file in TMPDIR with PROT_EXEC; where /dev/shm is mounted noexec (it was in the
        # cloud sandbox) the kernel refuses to start there ("/dev/shm must be not mounted noexec").
        os.makedirs(UML_TMP, exist_ok=True)
        env = dict(os.environ, TMPDIR=UML_TMP)
        r = subprocess.run(argv, cwd=REPO, capture_output=True, timeout=KUNIT_TIMEOUT, env=env)
        log = (r.stdout + r.stderr).decode("utf-8", "replace")
        code = r.returncode
    except subprocess.TimeoutExpired as e:
        log = ((e.stdout or b"") + (e.stderr or b"")).decode("utf-8", "replace") + "\n[timeout]"
        code = -1
    secs = round(time.time() - t0, 1)
    with open(os.path.join(outdir, tag + ".log"), "w") as f:
        f.write(log)
    for name, dest in ((".config", tag + ".config"), ("test.log", tag + ".kernel.log")):
        src = os.path.join(build_dir, name)
        if os.path.exists(src):
            shutil.copyfile(src, os.path.join(outdir, dest))
    tests = None
    if os.path.exists(js):
        try:
            doc = json.load(open(js))
            tests = {}
            flatten(doc, "", tests)
            # The top group is the run itself (its name the kernel's), not a suite.
            top = doc.get("name") or ""
            tests = {k[len(top) + 1:] if top and k.startswith(top + ".") else k: v for k, v in tests.items()}
        except Exception as e:  # unreadable results are no results
            log += "\n[json unreadable: %s]" % e
            tests = None
    return tests, secs, code, log[-1500:], failed_at(log)


def build_dir_for(kconfig_add):
    """The tip's build directory for the suite's own config; one of its own for each set of added options, so a
    config change never reuses another config's objects."""
    if not kconfig_add:
        return os.path.join(WORK, "b-tip")
    return os.path.join(WORK, "b-") + "-".join(re.sub(r"[^A-Za-z0-9]+", "_", o).strip("_").lower() for o in kconfig_add)


def read(path):
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return None


PANIC = re.compile(r"^.*(?:Kernel panic|Segfault with|Kernel mode fault|Oops|BUG:|general protection).*$", re.M)


def config_values(config_text, names):
    """Each named option's line in a .config: 'y', 'm', a value, or 'not set' (absent or '# ... is not set')."""
    out = {}
    for n in names:
        m = re.search(r"^%s=(.*)$" % re.escape(n), config_text or "", re.M)
        out[n] = m.group(1) if m else ("not set" if config_text is not None else None)
    return out


def plain_summary(tests, code, kernel_log, config_text, names):
    """What a plain run of the whole suite says: counts by status, whether every reported test passed, whether the
    kernel stopped part way (a test or suite ERROR, or a panic line in the kernel's own output), the panic lines, and
    the named options' values in the generated .config. outcome: all-pass, fails, crashed or build-or-infra."""
    counts = {}
    for st in (tests or {}).values():
        counts[st] = counts.get(st, 0) + 1
    panics = PANIC.findall(kernel_log or "")[:20]
    # The panic lines are reported as found; only a kunit.py ERROR or the kernel's own "Kernel panic" decides
    # crashed, so a test that prints a matching word on purpose cannot make a run read as a crash.
    crashed = bool(counts.get("ERROR")) or "Kernel panic" in (kernel_log or "")
    if not tests:
        outcome = "build-or-infra"
    elif crashed:
        outcome = "crashed"
    elif code == 0 and set(counts) == {"PASS"}:
        outcome = "all-pass"
    else:
        outcome = "fails"
    return {"status_counts": counts, "ran": sum(counts.values()), "outcome": outcome,
            "not_passed": sorted(k for k, v in (tests or {}).items() if v != "PASS"),
            "panic_lines": panics, "config": config_values(config_text, names)}


def stopped_part_way(before, after):
    """The unfixed tree's run stopped part way: it reported an ERROR (kunit.py's mark for a crashed test or suite,
    given to a placeholder case when the suite dies) and reached fewer of the fixed tree's tests."""
    if not before or not after:
        return False
    return any(st == "ERROR" for st in before.values()) and any(n not in before for n in after)


def compare(before, after):
    per = {}
    if after is None:
        return per
    stopped = stopped_part_way(before, after)
    for name, st in sorted(after.items()):
        if st != "PASS":
            per[name] = "fails-after"
        elif stopped and name not in before:
            per[name] = "not-reached"
        elif before is None or name not in before or before[name] == "SKIP":
            per[name] = "cannot-run"
        elif before[name] == "PASS":
            per[name] = "passes-both"
        else:
            per[name] = "witness"
    return per


def watched(job, before_failed, after_failed, before):
    """Each watched expectation's outcome: witness, passes-both, fails-after or cannot-run."""
    out = {}
    for loc in job.get("watch") or []:
        if after_failed is None:
            out[loc] = "cannot-run"
        elif loc in after_failed:
            out[loc] = "fails-after"
        elif before is None or before_failed is None:
            out[loc] = "cannot-run"
        elif loc in before_failed:
            out[loc] = "witness"
        else:
            out[loc] = "passes-both"
    return out


def summarize(job, before, after, before_note, before_failed=None, after_failed=None):
    per = compare(before, after)
    counts = {}
    for v in per.values():
        counts[v] = counts.get(v, 0) + 1
    if job["form"] == "pair" and after is not None and not after:
        # The named test is not in the fix's own tree: nothing to lay the parent against.
        category = "cannot-run"
    elif after is None or not after:
        category = "build-or-infra"
    elif counts.get("witness"):
        category = "witnessed"
    elif counts.get("not-reached"):
        category = "stopped-part-way"
    elif before is None or counts.get("cannot-run"):
        category = "cannot-run"
    elif counts.get("fails-after"):
        category = "build-or-infra"
    else:
        category = "passes-both"
    verdict = "witnessed" if counts.get("witness") else "not-witnessed"
    rec = {"id": job["id"], "form": job["form"], "verdict": verdict,
           "category": category, "counts": counts, "before_note": before_note,
           "witnesses": sorted(k for k, v in per.items() if v == "witness"), "per_test": per}
    if job.get("watch"):
        w = watched(job, before_failed, after_failed, before)
        rec.update(test_verdict=verdict, watched=w,
                   verdict="witnessed" if w and all(v == "witness" for v in w.values()) else "not-witnessed")
    return rec


def overlay(commit, paths):
    for p in paths:
        blob = git("show", "%s:%s" % (commit, p), check=False)
        if blob.returncode == 0:
            full = os.path.join(REPO, p)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as f:
                f.write(blob.stdout)


def run_job(job, tip, outdir, cache):
    jid = job["id"] + "." + job["form"]
    rec = {"job": job, "started": time.strftime("%FT%TZ", time.gmtime())}
    if job["form"] == "plain":
        reset(job["commit"])
        add = list(job.get("kconfig_add") or [])
        tests, secs, code, tail, fails = kunit(jid, build_dir_for(add), outdir, None, add)
        rec.update(tests=tests, seconds=secs, exit=code, tail=tail if tests is None else "", failed_at=fails)
        rec.update(plain_summary(tests, code, read(os.path.join(outdir, jid + ".kernel.log")),
                                 read(os.path.join(outdir, jid + ".config")),
                                 [o.split("=", 1)[0] for o in add] + list(job.get("report_config") or [])))
        return rec
    suite = job.get("suite")
    if job["form"] == "revert":
        key = "tip:" + (suite or "*")
        if key not in cache:
            reset(tip)
            cache[key] = kunit(jid + ".after", os.path.join(WORK, "b-tip"), outdir, suite)
        after, a_secs, a_code, a_tail, a_fail = cache[key]
        reset(tip)
        refused = None
        for c in job.get("revert") or [job["fix"]]:
            diff = git("diff", "--binary", c + "^", c, "--", ".", ":(exclude)fs/ext4/*-test.c").stdout
            ap = git("apply", "-R", "--3way", "--whitespace=nowarn", check=False, inp=diff)
            if ap.returncode != 0:
                refused = "the reverse of %s does not apply at the tip: %s" % (
                    c[:12], ap.stderr.decode("utf-8", "replace")[-400:])
                break
        if refused is None and git("diff", "--quiet", "--cached", check=False).returncode == 0 and \
                git("diff", "--quiet", check=False).returncode == 0:
            refused = "the reverse of the fix does not apply at the tip: it changes nothing"
        if refused:
            note = refused
            before, b_secs, b_code, b_tail, b_fail = None, 0, None, "", None
        else:
            note = ""
            before, b_secs, b_code, b_tail, b_fail = kunit(jid + ".before", os.path.join(WORK, "b-tip"), outdir, suite)
            if before is None:
                note = "the tree without the fix did not build or run"
        reset(tip)
    elif job["form"] == "pair":
        paths = job.get("test_paths") or []
        reset(job["fix"])
        overlay(job["test_commit"], paths)
        after, a_secs, a_code, a_tail, a_fail = kunit(jid + ".after", os.path.join(WORK, "b-pair"), outdir, suite)
        reset(job["fix"] + "^")
        overlay(job["test_commit"], paths)
        before, b_secs, b_code, b_tail, b_fail = kunit(jid + ".before", os.path.join(WORK, "b-pair"), outdir, suite)
        note = "" if before is not None else "the parent with the test files laid over it did not build or run"
        reset(tip)
    else:
        raise ValueError("unknown form " + job["form"])
    rec.update(summarize(job, before, after, note, b_fail, a_fail))
    rec.update(before_tests=before, after_tests=after, before_failed_at=b_fail, after_failed_at=a_fail,
               before_seconds=b_secs, after_seconds=a_secs,
               before_exit=b_code, after_exit=a_code,
               before_tail=b_tail if before is None else "", after_tail=a_tail if after is None else "")
    return rec


def main(queue_path, outdir):
    q = json.load(open(queue_path))
    os.makedirs(outdir, exist_ok=True)
    cache = {}
    prog = os.path.join(outdir, "progress.txt")
    for job in q["jobs"]:
        jid = job["id"] + "." + job["form"]
        dest = os.path.join(outdir, jid + ".result.json")
        if os.path.exists(dest):
            continue
        with open(prog, "a") as f:
            f.write("start %s %s\n" % (jid, time.strftime("%FT%TZ", time.gmtime())))
        try:
            rec = run_job(job, q["tip"], outdir, cache)
        except Exception as e:
            rec = {"job": job, "id": job["id"], "form": job["form"], "verdict": "not-witnessed",
                   "category": "build-or-infra", "error": repr(e)[-1500:]}
            try:
                reset(q["tip"])
            except Exception:
                pass
        with open(dest + ".tmp", "w") as f:
            json.dump(rec, f, indent=1, sort_keys=True)
        os.replace(dest + ".tmp", dest)
        with open(prog, "a") as f:
            f.write("done %s %s %s\n" % (jid, rec.get("category", "-"), time.strftime("%FT%TZ", time.gmtime())))
    with open(os.path.join(outdir, "ALLDONE"), "w") as f:
        f.write("ok\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
