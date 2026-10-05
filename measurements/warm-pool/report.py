"""Renders docs/measurements/warm-pool/index.html from the data beside it: pass-2.json (the probe's second full pass), pass-3.json,
exec-split.json, pooled-runc.json and pooled-runsc.json (pooled/main.go, the pool as
built), and hints-runc.json (hints/main.go, the language hints) when it exists. Light
theme, inline SVG, no dependencies.

    python3 measurements/warm-pool/report.py
    python3 measurements/warm-pool/report.py --check
"""

import argparse
import html
import json
import os
import sys

HERE = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "docs", "measurements", "warm-pool"))
p2 = json.load(open(os.path.join(HERE, "pass-2.json")))
p3 = json.load(open(os.path.join(HERE, "pass-3.json")))
split = json.load(open(os.path.join(HERE, "exec-split.json")))
pooled = {rt: json.load(open(os.path.join(HERE, f"pooled-{rt}.json"))) for rt in ("runc", "runsc")}
hints_path = os.path.join(HERE, "hints-runc.json")
hints = json.load(open(hints_path)) if os.path.exists(hints_path) else None

RUNTIMES = [("runc", "runc (container)"), ("runsc", "gVisor (kernel tier)")]
BARS = [
    ("cold_run", "Cold run today", "var(--s1)"),
    ("claim_exec", "Pool claim", "var(--s2)"),
    ("claim_inspect_exec", "Pool claim + read-back", "var(--s3)"),
]


def med(d, rt, k):
    return d["runtimes"][rt][k]["median"]


def bars_svg(rt, label):
    w, row, top, left = 520, 34, 30, 170
    scale = (w - left - 70) / 300.0  # 300 ms spans the plot
    h = top + row * len(BARS) + 30
    out = [f'<svg viewBox="0 0 {w} {h}" role="img" aria-label="{html.escape(label)}: median time to first output">']
    out.append(f'<text x="0" y="16" class="ttl">{html.escape(label)}</text>')
    for ms in (0, 100, 200, 300):
        x = left + ms * scale
        out.append(f'<line x1="{x:.1f}" y1="{top - 6}" x2="{x:.1f}" y2="{h - 22}" class="grid"/>')
        out.append(f'<text x="{x:.1f}" y="{h - 6}" class="tick" text-anchor="middle">{ms} ms</text>')
    for i, (key, name, color) in enumerate(BARS):
        v = med(p2, rt, key)
        y = top + i * row
        bw = max(v * scale, 2)
        samples = p2["runtimes"][rt][key]
        tip = f"{name}, {label}: median {v:.0f} ms, p90 {samples['p90']:.0f} ms, range {samples['min']:.0f} to {samples['max']:.0f} ms (n={len(samples['samples'])})"
        out.append(f'<text x="{left - 10}" y="{y + 15}" class="lab" text-anchor="end">{html.escape(name)}</text>')
        out.append(f'<g class="mark"><title>{html.escape(tip)}</title>'
                   f'<rect x="{left}" y="{y}" width="{bw:.1f}" height="20" rx="4" fill="{color}"/>'
                   f'<rect x="{left}" y="{y - 6}" width="{w - left:.1f}" height="32" fill="transparent"/></g>')
        out.append(f'<text x="{left + bw + 6:.1f}" y="{y + 15}" class="val">{v:.0f} ms</text>')
    out.append("</svg>")
    return "".join(out)


def pmed(rt, name):
    for smp in pooled[rt]["samples"]:
        if smp["name"] == name:
            xs = sorted(smp["ms"])
            return xs[len(xs) // 2], xs
    raise KeyError(name)


POOL_BARS = [
    ("no pool: open + first javascript cell", "No pool, JavaScript", "var(--s1)"),
    ("pool: claim + first javascript cell", "Pool, JavaScript", "var(--s2)"),
    ("no pool: open + first python cell", "No pool, Python", "var(--s1)"),
    ("pool: claim + first python cell", "Pool, Python", "var(--s2)"),
]


def pooled_svg(rt, label):
    w, row, top, left = 520, 34, 30, 150
    scale = (w - left - 70) / 1000.0  # 1000 ms spans the plot
    h = top + row * len(POOL_BARS) + 30
    out = [f'<svg viewBox="0 0 {w} {h}" role="img" aria-label="{html.escape(label)}: open a session and run its first cell, median">']
    out.append(f'<text x="0" y="16" class="ttl">{html.escape(label)}: open + first cell</text>')
    for ms in (0, 250, 500, 750, 1000):
        x = left + ms * scale
        out.append(f'<line x1="{x:.1f}" y1="{top - 6}" x2="{x:.1f}" y2="{h - 22}" class="grid"/>')
        out.append(f'<text x="{x:.1f}" y="{h - 6}" class="tick" text-anchor="middle">{ms} ms</text>')
    for i, (key, name, color) in enumerate(POOL_BARS):
        v, xs = pmed(rt, key)
        y = top + i * row
        bw = max(v * scale, 2)
        tip = f"{name}, {label}: median {v:.0f} ms, range {xs[0]:.0f} to {xs[-1]:.0f} ms (n={len(xs)})"
        out.append(f'<text x="{left - 10}" y="{y + 15}" class="lab" text-anchor="end">{html.escape(name)}</text>')
        out.append(f'<g class="mark"><title>{html.escape(tip)}</title>'
                   f'<rect x="{left}" y="{y}" width="{bw:.1f}" height="20" rx="4" fill="{color}"/>'
                   f'<rect x="{left}" y="{y - 6}" width="{w - left:.1f}" height="32" fill="transparent"/></g>')
        out.append(f'<text x="{left + bw + 6:.1f}" y="{y + 15}" class="val">{v:.0f} ms</text>')
    out.append("</svg>")
    return "".join(out)


def mib(rt, k):
    xs = pooled[rt][k]
    return sum(xs) / len(xs)


pool_tiles = "".join(
    f'<div class="tile"><div class="sub">{html.escape(label)}, JavaScript</div><div class="big">{pmed(rt, POOL_BARS[1][0])[0]:.0f} ms</div>'
    f'<div class="sub">claim + first cell, against {pmed(rt, POOL_BARS[0][0])[0]:.0f} ms without a pool</div></div>'
    for rt, label in RUNTIMES)
pool_tiles += "".join(
    f'<div class="tile"><div class="sub">{html.escape(label)}, a waiting member</div><div class="big">{mib(rt, "memberMiB"):.0f} MiB</div>'
    f'<div class="sub">both interpreters running, against {mib(rt, "bareMiB"):.1f} MiB for a bare session container</div></div>'
    for rt, label in RUNTIMES)


SET_COLORS = {"javascript,python": "var(--s3)", "python": "var(--s1)", "javascript": "var(--s2)"}
SET_NAMES = {"javascript,python": "both languages", "python": "Python only", "javascript": "JavaScript only"}


def hints_svg():
    """One bar per phase: the pool's waiting members by the languages they warm."""
    phases = hints["phases"]
    w, row, top, left = 560, 34, 30, 230
    unit = (w - left - 20) / hints["size"]
    h = top + row * len(phases) + 10
    out = [f'<svg viewBox="0 0 {w} {h}" role="img" aria-label="The pool split by language after each phase of hinted opens">']
    out.append('<text x="0" y="16" class="ttl">Waiting members by the languages they warm</text>')
    for i, ph in enumerate(phases):
        y = top + i * row
        lab = "start, no hints yet" if not ph["hint"] else f'after {ph["opens"]} {ph["hint"].capitalize() if ph["hint"] != "javascript" else "JavaScript"}-hinted opens'
        out.append(f'<text x="{left - 10}" y="{y + 15}" class="lab" text-anchor="end">{html.escape(lab)}</text>')
        x0 = left
        for key in ("javascript,python", "python", "javascript"):
            n = ph["split"].get(key, 0)
            if not n:
                continue
            bw = n * unit
            out.append(f'<g class="mark"><title>{html.escape(f"{lab}: {n} warming {SET_NAMES[key]}")}</title>'
                       f'<rect x="{x0:.1f}" y="{y}" width="{bw - 2:.1f}" height="20" rx="4" fill="{SET_COLORS[key]}"/></g>'
                       f'<text x="{x0 + 6:.1f}" y="{y + 15}" class="inbar">{n}</text>')
            x0 += bw
    out.append("</svg>")
    return "".join(out)


def hints_section():
    if not hints:
        return ""
    med = lambda xs: sorted(xs)[len(xs) // 2]
    tiles = "".join(
        f'<div class="tile"><div class="sub">A waiting member warming {html.escape(SET_NAMES[k])}</div><div class="big">{v:.0f} MiB</div>'
        f'<div class="sub">runc, docker stats</div></div>' for k, v in sorted(hints["mib"].items()))
    tiles += "".join(
        f'<div class="tile"><div class="sub">{html.escape(ph["hint"].capitalize() if ph["hint"] != "javascript" else "JavaScript")}-hinted open + first cell</div>'
        f'<div class="big">{med(ph["firstCellMs"]):.0f} ms</div><div class="sub">median of {len(ph["firstCellMs"])}, while the split moved</div></div>'
        for ph in hints["phases"] if ph["hint"])
    legend = "".join(f'<span><i style="background:{SET_COLORS[k]}"></i>{html.escape(SET_NAMES[k])}</span>' for k in SET_COLORS)
    return f"""
<h2>Language hints (2026-10-02)</h2>
<p>A session may name the languages its cells
will use. It is handed the waiting member warming the most of them, and the pool divides its size across language sets
by a weight that follows roughly the last 16 to 32 opens. Measured {html.escape(hints['when'][:10])} with
<code>hints/main.go</code> against the provider directly, a pool of {hints['size']}, 3 s between opens.</p>
<div class="tiles">{tiles}</div>
<div class="legend">{legend}</div>
<div class="charts">{hints_svg()}</div>
<p>Every hinted open got a warm member (a cold open is about 740 ms). Its first cell answered in
{min(min(ph["firstCellMs"]) for ph in hints["phases"] if ph["hint"]):.0f} to {max(max(ph["firstCellMs"]) for ph in hints["phases"] if ph["hint"]):.0f} ms,
above the 18 to 22 ms of the pooled run above; that gap was not investigated. A hint changes latency, never behavior: a cell in a language the member did not warm still runs, starting its
interpreter on first use, and a session without a hint counts as wanting every language. Hints move members between
sets and never add any, so <code>SANDBOX_SESSION_POOL</code> still bounds the memory.</p>
"""


def split_svg():
    w, row, top, left = 520, 34, 30, 170
    scale = (w - left - 70) / 100.0
    h = top + row * 2 + 30
    out = [f'<svg viewBox="0 0 {w} {h}" role="img" aria-label="Where a pool claim spends its time">']
    out.append('<text x="0" y="16" class="ttl">Where a claim spends its time (median, ms)</text>')
    for ms in (0, 25, 50, 75, 100):
        x = left + ms * scale
        out.append(f'<line x1="{x:.1f}" y1="{top - 6}" x2="{x:.1f}" y2="{h - 22}" class="grid"/>')
        out.append(f'<text x="{x:.1f}" y="{h - 6}" class="tick" text-anchor="middle">{ms}</text>')
    for i, (rt, label) in enumerate(RUNTIMES):
        y = top + i * row
        ex = split[rt]["exec_true"]
        node = max(split[rt]["exec_node"] - ex, 0)
        out.append(f'<text x="{left - 10}" y="{y + 15}" class="lab" text-anchor="end">{html.escape(label)}</text>')
        x0 = left
        for part, v, color in (("docker exec", ex, "var(--s1)"), ("Node starting", node, "var(--s2)")):
            bw = v * scale
            out.append(f'<g class="mark"><title>{html.escape(f"{label}: {part} {v:.0f} ms")}</title>'
                       f'<rect x="{x0:.1f}" y="{y}" width="{max(bw - 2, 1):.1f}" height="20" rx="4" fill="{color}"/></g>')
            if bw > 30:
                out.append(f'<text x="{x0 + 6:.1f}" y="{y + 15}" class="inbar">{v:.0f}</text>')
            x0 += bw
    out.append("</svg>")
    return "".join(out)


def row(rt, label, key, unit="ms"):
    a, b = med(p2, rt, key), med(p3, rt, key)
    fmt = (lambda v: f"{v:.1f}") if unit == "MiB" else (lambda v: f"{v:.0f}")
    return f"<tr><td>{label}</td><td>{key}</td><td>{fmt(a)} {unit}</td><td>{fmt(b)} {unit}</td><td>{fmt(p2['runtimes'][rt][key]['p90'])} {unit}</td></tr>"


saved = {rt: med(p2, rt, "cold_run") - med(p2, rt, "claim_inspect_exec") for rt, _ in RUNTIMES}
tiles = "".join([
    f'<div class="tile"><div class="big">{saved["runc"]:.0f} ms</div><div class="sub">saved per call under runc ({med(p2, "runc", "cold_run"):.0f} to {med(p2, "runc", "claim_inspect_exec"):.0f} ms, read-back included)</div></div>',
    f'<div class="tile"><div class="big">{saved["runsc"]:.0f} ms</div><div class="sub">saved per call under gVisor ({med(p2, "runsc", "cold_run"):.0f} to {med(p2, "runsc", "claim_inspect_exec"):.0f} ms)</div></div>',
    f'<div class="tile"><div class="big">{med(p2, "runsc", "idle_member_mib"):.0f} MiB</div><div class="sub">held by each idle pool member under gVisor; {med(p2, "runc", "idle_member_mib"):.1f} MiB under runc</div></div>',
    f'<div class="tile"><div class="big">~15 ms</div><div class="sub">what a claim could reach with a relay and interpreter already attached, as a warm session cell does (inferred, not measured here)</div></div>',
])

table = "".join(row(rt, label, k, "MiB" if k == "idle_member_mib" else "ms")
                for rt, label in RUNTIMES
                for k in ("cold_run", "claim_exec", "claim_inspect_exec", "pool_member_start", "member_remove", "idle_member_mib"))

page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Warm pool: never-used containers against a cold start</title>
<style>
:root {{ color-scheme: light; --bg: #fcfcfb; --ink: #0b0b0b; --ink2: #52514e; --grid: #e4e3df;
  --s1: #2a78d6; --s2: #eb6834; --s3: #1baf7a; }}
body {{ margin: 0; background: var(--bg); color: var(--ink); font: 15px/1.5 system-ui, sans-serif; }}
main {{ max-width: 1100px; margin: 0 auto; padding: 28px 20px 60px; }}
h1 {{ font-size: 24px; margin: 0 0 6px; }} h2 {{ font-size: 18px; margin: 32px 0 8px; }}
p, li {{ color: var(--ink2); max-width: 75ch; }}
.tiles {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(min(220px, 100%), 1fr)); gap: 12px; margin: 18px 0; }}
.tile {{ border: 1px solid var(--grid); border-radius: 8px; padding: 14px; background: #fff; }}
.big {{ font-size: 28px; font-weight: 650; }} .sub {{ color: var(--ink2); font-size: 13px; }}
.charts {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(min(420px, 100%), 1fr)); gap: 18px; }}
.charts > svg {{ max-width: 560px; }}
table {{ display: block; overflow-x: auto; }}
svg {{ width: 100%; height: auto; background: #fff; border: 1px solid var(--grid); border-radius: 8px; padding: 10px; box-sizing: border-box; }}
.ttl {{ font-weight: 600; font-size: 14px; fill: var(--ink); }} .lab {{ font-size: 13px; fill: var(--ink); }}
.val {{ font-size: 13px; fill: var(--ink); font-weight: 600; }} .tick {{ font-size: 11px; fill: var(--ink2); }}
.inbar {{ font-size: 12px; fill: #fff; font-weight: 600; }} .grid {{ stroke: var(--grid); stroke-width: 1; }}
.mark:hover rect:first-of-type {{ opacity: .8; }}
.legend {{ display: flex; gap: 18px; font-size: 13px; color: var(--ink2); margin: 8px 0; flex-wrap: wrap; }}
.legend i {{ display: inline-block; width: 12px; height: 12px; border-radius: 3px; margin-right: 6px; vertical-align: -1px; }}
table {{ border-collapse: collapse; width: 100%; font-size: 13px; background: #fff; }}
th, td {{ border-bottom: 1px solid var(--grid); padding: 6px 8px; text-align: left; }} th {{ color: var(--ink2); font-weight: 600; }}
code {{ font-size: 13px; }} pre {{ overflow-x: auto; background: #f4f6f9; padding: 10px 12px; border-radius: 6px; }}
</style></head><body><main>
<nav style="display:flex;flex-wrap:wrap;gap:6px 20px;align-items:baseline;padding:0 0 12px;margin:0 0 20px;border-bottom:1px solid #d1d9e0;font-size:15px"><a href="https://plimsollmark.github.io/plimsoll/" style="font-weight:700;color:#0f4a85;text-decoration:none">plimsoll home</a><a href="https://plimsollmark.github.io/plimsoll/measurements/session-latency/index.html">Session latency</a><a href="https://plimsollmark.github.io/plimsoll/trainers/">Lessons</a><a href="https://github.com/plimsollmark/plimsoll">Source on GitHub ↗</a></nav>
<h1>Warm pool: never-used containers against a cold start</h1>
<p>Whether a pool of locked-down containers that no code has touched, each claimed once and removed after, takes the
container start off the path of a session's first call (<code>SANDBOX_SESSION_POOL</code>; the terms session, cell
and relay are defined in <a href="https://github.com/plimsollmark/plimsoll/blob/main/docs/sessions.md">the sessions
guide (EXTERNAL · source repo ↗)</a>). The page has three parts: the pool as built, the language hints that steer it,
and the probe that came first. The probe was measured {html.escape(p2['measured'])} on a laptop, docker {html.escape(p2['docker_version'])},
image <code>{html.escape(p2['image'])}</code>, the docker provider's lockdown flags, {p2['n']} samples per bar, a
<code>node -e</code> snippet as the call. A laptop number, not a product number: what carries over is the ratio and the
breakdown, not the milliseconds.</p>
<h2>Built: the pool with interpreters attached (2026-10-02)</h2>
<p>Each never-used member gets an interpreter started and its relay attached
for every language the image runs, and <code>OpenSession</code> hands one over. Measured
{html.escape(pooled['runc']['when'][:10])} with <code>pooled/main.go</code> against the provider directly (not through
plimsolld), image <code>{html.escape(pooled['runc']['image'])}</code>, {pooled['runc']['reps']} samples per bar, 3 s
between samples so the pool refills, a cell of <code>6 * 7</code>. Without a pool the time is a container start, the
read-back and process list, then the first cell starting the interpreter and its relay.</p>
<div class="tiles">{pool_tiles}</div>
<div class="legend"><span><i style="background:var(--s1)"></i>No pool (open creates the container)</span><span><i style="background:var(--s2)"></i>Pool (open claims a waiting member)</span></div>
<div class="charts">{pooled_svg('runc', 'runc (container)')}{pooled_svg('runsc', 'gVisor (kernel tier)')}</div>
<p>What made the first measurement slow: <code>OpenSession</code> re-ran the docker Preflight, which re-runs once its
result is 5 seconds old, before claiming. A claim now skips it: the member was verified when it was made and is read
back before every call, and it must match the execution state the last Preflight verified. With that, claiming takes
under a millisecond and the time is the first cell's. The cost is memory: the interpreters a waiting member holds count
inside its session's memory limit, including the language a session never uses.</p>
{hints_section()}
<h2>The probe before the build: a plain pool</h2>
<div class="tiles">{tiles}</div>
<h2>Time to first output</h2>
<div class="legend">{''.join(f'<span><i style="background:{c}"></i>{html.escape(n)}</span>' for _, n, c in BARS)}</div>
<div class="charts">{bars_svg('runc', 'runc (container)')}{bars_svg('runsc', 'gVisor (kernel tier)')}</div>
<p>"Cold run" is today's path: <code>docker run --rm</code> of the snippet. "Pool claim" is <code>docker exec</code> of
the same snippet into a pre-started, never-used member. "Read-back" adds the <code>docker inspect</code> a session
already makes before every call; a pool would make it at claim.</p>
<h2>Where a claim's time goes</h2>
<div class="legend"><span><i style="background:var(--s1)"></i>docker exec of <code>true</code></span><span><i style="background:var(--s2)"></i>Node starting and printing</span></div>
<div class="charts">{split_svg()}</div>
<p>Most of what remains is the <code>docker exec</code> round trip and Node starting. A warm session cell takes 14 to 15
ms on this laptop because its relay is already attached and its interpreter already running (measured 2026-10-01);
a pool member could be prepared the same way, which is what the pool as built (above) does.</p>
<h2>What it costs</h2>
<ul>
<li>Memory held while idle: about {med(p2, 'runsc', 'idle_member_mib'):.0f} MiB per member under gVisor (its Sentry), under
1 MiB under runc. A pool of 8 under gVisor holds about {8 * med(p2, 'runsc', 'idle_member_mib'):.0f} MiB, which
<code>SANDBOX_TOTAL_MEMORY_MB</code> would have to count.</li>
<li>Restocking, off the call's path: starting a member takes {med(p2, 'runc', 'pool_member_start'):.0f} ms (runc) and
{med(p2, 'runsc', 'pool_member_start'):.0f} ms (gVisor); removing one {med(p2, 'runc', 'member_remove'):.0f} and
{med(p2, 'runsc', 'member_remove'):.0f} ms.</li>
<li>No clone caveats: every member boots on its own, and none is ever handed to a second call.</li>
</ul>
<h2>All numbers</h2>
<div style="overflow-x:auto"><table><thead><tr><th>Runtime</th><th>Measure</th><th>Median, pass 2</th><th>Median, pass 3</th><th>p90, pass 2</th></tr></thead>
<tbody>{table}</tbody></table></div>
<p>Pass 1 agreed with these to within 10 ms.</p>
<h2>The data and how to rerun it</h2>
<p>Raw samples beside this page: <a href="pass-2.json">pass-2.json</a> and <a href="pass-3.json">pass-3.json</a> (the
probe), <a href="pooled-runc.json">pooled-runc.json</a> and <a href="pooled-runsc.json">pooled-runsc.json</a> (the pool
as built), <a href="hints-runc.json">hints-runc.json</a> (language hints). <a href="exec-split.json">exec-split.json</a>
holds two medians per runtime timed by hand (<code>docker exec</code> of <code>true</code>, and of the snippet); no
program reproduces it. The programs are in
<a href="https://github.com/plimsollmark/plimsoll/tree/main/measurements/warm-pool">measurements/warm-pool
(EXTERNAL · source repo ↗)</a>. From a checkout, with the images <code>make docker-images</code> builds (and
gVisor installed for the runsc runs):</p>
<pre><code>python3 measurements/warm-pool/probe.py 20 docs/measurements/warm-pool/pass-2.json
go run ./measurements/warm-pool/pooled                  # runc
go run ./measurements/warm-pool/pooled -runtime runsc   # gVisor
go run ./measurements/warm-pool/hints
python3 measurements/warm-pool/report.py</code></pre>
<p>Your numbers will differ from these: they are one laptop's. What should carry over is the ratio between a pool and
a cold start, and where the time goes.</p>
</main></body></html>
"""
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--check", action="store_true", help="check the committed page without writing it")
args = parser.parse_args()
output = os.path.join(HERE, "index.html")
rendered = page.encode("utf-8")
if args.check:
    try:
        with open(output, "rb") as file:
            committed = file.read()
    except FileNotFoundError:
        committed = None
    if rendered != committed:
        print(f"{output} differs from the rendered measurement data", file=sys.stderr)
        sys.exit(1)
else:
    with open(output, "wb") as file:
        file.write(rendered)
    print("wrote", output)
