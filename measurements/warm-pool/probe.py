"""Measures a pool of never-used locked-down containers against a cold docker run.

For each runtime (runc, runsc): N cold runs of a snippet; N pre-started pool members,
each claimed once by a docker exec of the same snippet (alone, and after a docker
inspect read-back as sessions do), then removed; the idle memory of a pool member;
and how long starting and removing one takes (off the request path in a pool)."""

import json, statistics, subprocess, sys, time, uuid

IMAGE = "node:22-alpine"
SNIPPET = ["node", "-e", "console.log(1)"]
N = int(sys.argv[1]) if len(sys.argv) > 1 else 20


def flags(runtime):
    f = ["--log-driver", "none"]
    if runtime:
        f += ["--runtime", runtime]
    f += ["--memory", "256m", "--memory-swap", "256m", "--pids-limit", "128", "--cpus", "1", "--read-only",
          "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--tmpfs", "/dev/shm:rw,noexec,nosuid,size=16m",
          "--user", "1000:1000", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
          "--ulimit", "core=0", "--ulimit", "nofile=4096:4096", "--ipc", "private", "--network", "none"]
    return f


def timed(argv, **kw):
    t = time.perf_counter()
    out = subprocess.run(argv, capture_output=True, text=True, **kw)
    ms = (time.perf_counter() - t) * 1000
    if out.returncode != 0:
        raise SystemExit(f"{' '.join(argv[:4])}...: {out.stderr.strip()}")
    return ms, out.stdout


def summary(xs):
    xs = sorted(xs)
    return {"median": statistics.median(xs), "p90": xs[int(0.9 * (len(xs) - 1))], "min": xs[0], "max": xs[-1], "samples": xs}


def mem_mib(name):
    _, out = timed(["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", name])
    used = out.split("/")[0].strip()
    num = float("".join(c for c in used if c.isdigit() or c == "."))
    return num / 1024 if used.endswith("KiB") else num * 1024 if used.endswith("GiB") else num


results = {"image": IMAGE, "n": N, "runtimes": {}}
for runtime in ("runc", "runsc"):
    r = {}
    # Cold: what a run costs today, container create and start included.
    cold = []
    for _ in range(N):
        ms, out = timed(["docker", "run", "--rm", "-i"] + flags(runtime) + [IMAGE] + SNIPPET)
        assert out.strip() == "1"
        cold.append(ms)
    r["cold_run"] = summary(cold)
    # Pool: start N members, never touched by any code, then claim each once.
    names, starts = [], []
    for _ in range(N):
        name = "plsm-pool-" + uuid.uuid4().hex[:12]
        ms, _ = timed(["docker", "run", "-d", "--init", "--name", name] + flags(runtime) + [IMAGE, "sleep", "3600"])
        names.append(name)
        starts.append(ms)
    r["pool_member_start"] = summary(starts)
    time.sleep(2)
    r["idle_member_mib"] = summary([mem_mib(n) for n in names[:5]])
    claim, claim_inspect, removes = [], [], []
    for i, name in enumerate(names):
        if i % 2 == 0:
            ms, out = timed(["docker", "exec", "-i", "--user", "1000:1000", name] + SNIPPET)
            claim.append(ms)
        else:
            t = time.perf_counter()
            timed(["docker", "inspect", "--format", "{{json .HostConfig}}", name])
            _, out = timed(["docker", "exec", "-i", "--user", "1000:1000", name] + SNIPPET)
            claim_inspect.append((time.perf_counter() - t) * 1000)
        assert out.strip() == "1"
        ms, _ = timed(["docker", "rm", "-f", name])
        removes.append(ms)
    r["claim_exec"] = summary(claim)
    r["claim_inspect_exec"] = summary(claim_inspect)
    r["member_remove"] = summary(removes)
    results["runtimes"][runtime] = r
    print(runtime, {k: round(v["median"], 1) for k, v in r.items()}, flush=True)

results["docker_version"] = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"], capture_output=True, text=True).stdout.strip()
results["measured"] = time.strftime("%Y-%m-%d %H:%M %Z")
json.dump(results, open(sys.argv[2] if len(sys.argv) > 2 else "tmp/warm-pool/results.json", "w"), indent=1)
