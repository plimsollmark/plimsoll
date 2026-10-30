"""Renders docs/measurements/warm-pool/index.html from the data beside it: pass-2.json (the probe's second full pass), pass-3.json,
exec-split.json, pooled-runc.json and pooled-runsc.json (pooled/main.go, the pool as
built), hints-runc.json (hints/main.go, the language hints), openshell.json
(openshell/main.go, the pool on the openshell provider) and onecall-<runtime>.json
(onecall/main.go, a Run of one cell through plimsolld with and without prefer_warm)
when they exist. Light theme, inline SVG, no dependencies.

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
openshell_path = os.path.join(HERE, "openshell.json")
openshell = json.load(open(openshell_path)) if os.path.exists(openshell_path) else None
# onecall/main.go: a Run of one cell through plimsolld, by runtime; a "-repeat" file is the
# same runtime measured again.
ONECALL_RUNTIMES = [("runc", "runc (container)"), ("runsc", "gVisor (kernel tier)"), ("openshell", "OpenShell (container)")]
onecall = {}
for _rt, _ in ONECALL_RUNTIMES + [("runc-repeat", "")]:
    _p = os.path.join(HERE, f"onecall-{_rt}.json")
    if os.path.exists(_p):
        onecall[_rt] = json.load(open(_p))

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


def smed(data, name):
    for smp in data["samples"]:
        if smp["name"] == name:
            xs = sorted(smp["ms"])
            return xs[len(xs) // 2], xs
    raise KeyError(name)


def pmed(rt, name):
    return smed(pooled[rt], name)


POOL_BARS = [
    ("no pool: open + first javascript cell", "No pool, JavaScript", "var(--s1)"),
    ("pool: claim + first javascript cell", "Pool, JavaScript", "var(--s2)"),
    ("no pool: open + first python cell", "No pool, Python", "var(--s1)"),
    ("pool: claim + first python cell", "Pool, Python", "var(--s2)"),
]


def pooled_svg(rt, label):
    return pool_svg(pooled[rt], label)


def pool_svg(data, label):
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
        v, xs = smed(data, key)
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


def openshell_section():
    if not openshell:
        return ""
    d = openshell
    v = lambda name: smed(d, name)[0]
    avg = lambda xs: sum(xs) / len(xs)
    tiles = "".join(
        f'<div class="tile"><div class="sub">OpenShell, {lang}</div><div class="big">{v(f"pool: claim + first {key} cell"):.0f} ms</div>'
        f'<div class="sub">claim + first cell, against {v(f"no pool: open + first {key} cell"):.0f} ms without a pool</div></div>'
        for key, lang in (("javascript", "JavaScript"), ("python", "Python")))
    tiles += (f'<div class="tile"><div class="sub">OpenShell, a waiting sandbox</div><div class="big">{avg(d["warmMiB"]):.0f} MiB</div>'
              f'<div class="sub">both interpreters running, against {avg(d["bareMiB"]):.0f} MiB bare: the sandbox\'s container and the '
              f'gateway\'s supervisor container beside it</div></div>')
    return f"""
<h2>OpenShell (2026-10-28)</h2>
<p>The same pool on the <code>openshell</code> provider, which runs each sandbox through an OpenShell gateway: one
mechanism, with OpenShell's own way of making, checking and deleting a member. Measured {html.escape(d['when'][:10])}
with <code>openshell/main.go</code> against a local gateway (OpenShell v0.1.2, its docker driver, runc), image
<code>{html.escape(d['image'])}</code>, {d['reps']} samples per bar, {d['pauseMs'] / 1000:.0f} s between samples.
Before the pool was built, the same program timed the first call in a session opened ahead of time, as a waiting
member would be: {v("opened ahead: first javascript cell, interpreter not started"):.0f} ms for a JavaScript cell with its
interpreter not yet started and {v("opened ahead: first javascript cell, interpreter started"):.0f} ms with it running,
against {v("no pool: open + first javascript cell"):.0f} ms to open a session and run that cell. That was the reason to
build it.</p>
<div class="tiles">{tiles}</div>
<div class="legend"><span><i style="background:var(--s1)"></i>No pool (open creates the sandbox)</span><span><i style="background:var(--s2)"></i>Pool (open claims a waiting sandbox)</span></div>
<div class="charts">{pool_svg(d, 'openshell (container)')}</div>
<p>Without a pool, the open alone takes {v("no pool: open + first javascript cell (open)"):.0f} ms: the gateway creates the
sandbox and its supervisor and reports it ready, and plimsoll reads it back and records its processes. A snippet in a
claimed sandbox took {v("pool: claim + first snippet"):.0f} ms against {v("no pool: open + first snippet"):.0f} ms, most
of it the read-back and the sweep every session call makes here.</p>
"""


def quant(xs, q):
    """The nearest-rank q-quantile, as onecall/main.go prints it."""
    s = sorted(xs)
    return s[max(0, min(len(s) - 1, -(-int(len(s) * q * 1000000) // 1000000) - 1))]


def ocs(data, name):
    """One call's samples in a onecall run: (median, p10, p90, sorted samples)."""
    for smp in data["samples"]:
        if smp["name"] == name:
            xs = sorted(smp["ms"])
            return quant(xs, 0.5), quant(xs, 0.1), quant(xs, 0.9), xs
    raise KeyError(name)


LANGS = [("python", "Python"), ("javascript", "JavaScript")]
# (sample name, label, color, opacity): Preflight cached is the same call's color, lighter.
ONECALL_BARS = [
    ("warm", "One call, warm", "var(--s2)", 1),
    ("session", "Session: open + cell", "var(--s3)", 1),
    ("fresh, Preflight cached", "Fresh, Preflight cached", "var(--s1)", 0.5),
    ("fresh", "Fresh, Preflight due", "var(--s1)", 1),
    ("miss, Preflight cached", "Miss, Preflight cached", "var(--s4)", 0.5),
    ("miss", "Miss, Preflight due", "var(--s4)", 1),
]


def nice_max(v):
    for step in (100, 250, 500, 1000):
        if v <= step * 6:
            return step, step * (int(v // step) + 1)
    return 2000, 2000 * (int(v // 2000) + 1)


def onecall_svg(rt, label):
    """One bar per call and language: the median, with a line from the 10th to the 90th percentile."""
    d = onecall[rt]
    w, row, head, top, left = 560, 24, 22, 30, 170
    # One scale for every runtime, so the charts side by side compare by length.
    step, top_ms = nice_max(max(ocs(onecall[r], f"{k} {lang}")[2] for r, _ in ONECALL_RUNTIMES if r in onecall
                                for k, *_ in ONECALL_BARS for lang, _ in LANGS))
    scale = (w - left - 64) / top_ms
    h = top + len(LANGS) * (head + row * len(ONECALL_BARS)) + 24
    out = [f'<svg viewBox="0 0 {w} {h}" role="img" aria-label="{html.escape(label)}: one Run of a cell through plimsolld, median and 10th to 90th percentile">']
    out.append(f'<text x="0" y="16" class="ttl">{html.escape(label)}: one cell, end to end</text>')
    y = top
    for ms in range(0, top_ms + 1, step):
        x = left + ms * scale
        out.append(f'<line x1="{x:.1f}" y1="{top - 4}" x2="{x:.1f}" y2="{h - 22}" class="grid"/>')
        out.append(f'<text x="{x:.1f}" y="{h - 6}" class="tick" text-anchor="middle">{ms} ms</text>')
    for lang, lname in LANGS:
        out.append(f'<text x="4" y="{y + 15}" class="grp">{lname}</text>')
        y += head
        for key, name, color, alpha in ONECALL_BARS:
            v, p10, p90, xs = ocs(d, f"{key} {lang}")
            bw = max(v * scale, 2)
            tip = (f"{name}, {lname}, {label}: median {v:.0f} ms, 10th to 90th percentile {p10:.0f} to {p90:.0f} ms, "
                   f"range {xs[0]:.0f} to {xs[-1]:.0f} ms (n={len(xs)})")
            out.append(f'<text x="{left - 10}" y="{y + 12}" class="lab" text-anchor="end">{html.escape(name)}</text>')
            out.append(f'<g class="mark"><title>{html.escape(tip)}</title>'
                       f'<rect x="{left}" y="{y}" width="{bw:.1f}" height="16" rx="4" fill="{color}" fill-opacity="{alpha}"/>'
                       f'<line x1="{left + p10 * scale:.1f}" y1="{y + 8}" x2="{left + p90 * scale:.1f}" y2="{y + 8}" class="whisk"/>'
                       f'<line x1="{left + p10 * scale:.1f}" y1="{y + 4}" x2="{left + p10 * scale:.1f}" y2="{y + 12}" class="whisk"/>'
                       f'<line x1="{left + p90 * scale:.1f}" y1="{y + 4}" x2="{left + p90 * scale:.1f}" y2="{y + 12}" class="whisk"/>'
                       f'<rect x="{left}" y="{y - 4}" width="{w - left:.1f}" height="{row}" fill="transparent"/></g>')
            out.append(f'<text x="{left + max(bw, p90 * scale) + 6:.1f}" y="{y + 12}" class="val">{v:.0f} ms</text>')
            y += row
    out.append("</svg>")
    return "".join(out)


HEAVY_LOAD = 4  # on this 24-CPU laptop, a 1-minute load above this means other work was competing


def load_text(d):
    peak = max(d["repLoad1"])
    heavy = sum(1 for x in d["repLoad1"] if x > HEAVY_LOAD)
    text = (f'1-minute load average {d["loadStart"][0]:.1f} at the start and {d["loadEnd"][0]:.1f} at the end, at most '
            f'{peak:.1f} as a repetition began')
    if heavy:
        text += (f'; <b>{heavy} of its {len(d["repLoad1"])} repetitions began under heavy load</b>, above {HEAVY_LOAD}, '
                 f'from other programs on the machine')
    return text


def pct(x):
    return "0%" if round(x) == 0 else f"{x:+.0f}%"


def onecall_reading(present, pf):
    """What the bars say, each number read from the data."""
    m = lambda rt, name: ocs(onecall[rt], name)[0]
    pair = lambda rt, key: f'{m(rt, f"{key} python"):.0f} ms (Python) and {m(rt, f"{key} javascript"):.0f} ms (JavaScript)'

    def span(rt, a, b):
        ds = [m(rt, f"{a} {lang}") - m(rt, f"{b} {lang}") for lang, _ in LANGS]
        sg = lambda x: "0" if round(x) == 0 else f"{x:+.0f}"
        return f"{sg(min(ds))} to {sg(max(ds))} ms" if round(min(ds)) != round(max(ds)) else f"{sg(ds[0])} ms"
    out = []
    for rt, label in present:
        out.append(
            f'<li><b>{html.escape(label)}.</b> A warm call answered in {pair(rt, "warm")}; a fresh one took '
            f'{pair(rt, "fresh")} with Preflight due and {pair(rt, "fresh, Preflight cached")} with it cached. '
            + (f'Most of that difference is Preflight itself: <code>GET /readyz</code> took {pf[rt]:.0f} ms (median) when it '
               f'ran it. ' if pf[rt] > 50 else
               f'This provider\'s Preflight costs nothing a caller would notice (<code>GET /readyz</code> took {pf[rt]:.0f} ms), '
               f'so the due and cached bars are the same call measured twice. ')
            + f'A session claimed from the pool reached its answer in {pair(rt, "session")}, its warm-only open about '
            f'{m(rt, "session python (open)"):.0f} ms of it, but its close took a further '
            f'{m(rt, "session python (close)"):.0f} ms (Python) and {m(rt, "session javascript (close)"):.0f} ms (JavaScript, '
            f'anywhere from {ocs(onecall[rt], "session javascript (close)")[3][0]:.0f} to '
            f'{ocs(onecall[rt], "session javascript (close)")[3][-1]:.0f} ms) before the caller was done; the one call deletes '
            f'its member after answering, off the caller\'s path. '
            f'A miss runs fresh: it took {pair(rt, "miss")} with Preflight due and {pair(rt, "miss, Preflight cached")} '
            f'with it cached, {span(rt, "miss", "fresh")} and {span(rt, "miss, Preflight cached", "fresh, Preflight cached")} '
            f'against the fresh call in the same Preflight state, while the pool was making its next member beside it.</li>')
    pooled_warm = f'{pmed("runc", POOL_BARS[3][0])[0]:.0f} and {pmed("runc", POOL_BARS[1][0])[0]:.0f} ms'
    return f"""<p>What the bars say, median for median:</p>
<ul>{''.join(out)}</ul>
<p>A warm call here takes longer than a claimed session's first cell in the pool section below ({pooled_warm} under
runc for Python and JavaScript, measured 2026-10-02 against the provider directly, with older code). The extra time is
somewhere in the request through the daemon, its checks, the run record each side computes and the code changed since;
this page does not break it down.</p>"""


def onecall_section():
    if "runc" not in onecall:
        return ""
    present = [(rt, label) for rt, label in ONECALL_RUNTIMES if rt in onecall]
    base = onecall["runc"]
    m = lambda rt, name: ocs(onecall[rt], name)[0]
    tiles = ""
    for rt, label in present:
        for lang, lname in LANGS:
            tiles += (f'<div class="tile"><div class="sub">{html.escape(label)}, {lname}</div>'
                      f'<div class="big">{m(rt, f"warm {lang}"):.0f} ms</div>'
                      f'<div class="sub">one call from a waiting member, against {m(rt, f"fresh {lang}"):.0f} ms fresh '
                      f'({m(rt, f"fresh, Preflight cached {lang}"):.0f} ms with Preflight cached)</div></div>')
    legend = "".join(
        f'<span><i style="background:{c};opacity:{a}"></i>{html.escape(n)}</span>' for _, n, c, a in ONECALL_BARS)
    legend += '<span><i class="whisk-key"></i>10th to 90th percentile</span>'
    charts = "".join(onecall_svg(rt, label) for rt, label in present)

    rows = ""
    for rt, label in present:
        d = onecall[rt]
        for lang, lname in LANGS:
            for key, name, *_ in ONECALL_BARS + [("readyz before fresh, Preflight cached", "GET /readyz with Preflight due", "", 1),
                                                 ("session", "", "", 1)]:
                if key == "session" and name == "":
                    for part in ("open", "cell", "close"):
                        v, p10, p90, xs = ocs(d, f"session {lang} ({part})")
                        rows += (f"<tr><td>{html.escape(label)}</td><td>{lname}</td><td>Session: the {part}</td><td>{v:.0f}</td>"
                                 f"<td>{p10:.0f} to {p90:.0f}</td><td>{xs[0]:.0f} to {xs[-1]:.0f}</td><td>{len(xs)}</td></tr>")
                    continue
                v, p10, p90, xs = ocs(d, f"{key} {lang}")
                rows += (f"<tr><td>{html.escape(label)}</td><td>{lname}</td><td>{html.escape(name)}</td><td>{v:.0f}</td>"
                         f"<td>{p10:.0f} to {p90:.0f}</td><td>{xs[0]:.0f} to {xs[-1]:.0f}</td><td>{len(xs)}</td></tr>")
    loads = "".join(
        f'<li>{html.escape(label)}: measured {html.escape(onecall[rt]["when"][:16].replace("T", " "))} UTC; {load_text(onecall[rt])}.</li>'
        for rt, label in present)

    repeat = ""
    if "runc-repeat" in onecall:
        r = onecall["runc-repeat"]
        reprows, changes = "", []
        for lang, lname in LANGS:
            for key, name, *_ in ONECALL_BARS:
                a, b = m("runc", f"{key} {lang}"), ocs(r, f"{key} {lang}")[0]
                changes.append((b - a) / a * 100)
                reprows += f"<tr><td>{lname}</td><td>{html.escape(name)}</td><td>{a:.0f}</td><td>{b:.0f}</td><td>{pct((b - a) / a * 100)}</td></tr>"
        big = max(changes, key=abs)
        repeat = f"""
<p>The runc set measured a second time, {html.escape(r['when'][:16].replace('T', ' '))} UTC, with a daemon of its own and the
same settings; {load_text(r)}. Every median landed within {abs(big):.0f}% of the first set's, medians in ms:</p>
<div style="overflow-x:auto"><table><thead><tr><th>Language</th><th>Call</th><th>First set</th><th>Second set</th><th>Change</th></tr></thead>
<tbody>{reprows}</tbody></table></div>"""

    checks = []
    for rt, label in present + ([("runc-repeat", "runc, second set")] if "runc-repeat" in onecall else []):
        d = onecall[rt]
        timed = [s for s in d["samples"] if s["warm"] and "(" not in s["name"]]
        member = [w for s in timed if s["name"].split(" ")[0] in ("warm", "session") for w in s["warm"]]
        made = [w for s in timed if s["name"].split(" ")[0] in ("fresh,", "fresh", "miss,", "miss") for w in s["warm"]]
        aw = d["auditWarm"]
        line = (f'{html.escape(label)}: {sum(member)} of {len(member)} warm and session samples answered by a waiting member, '
                f'{len(made) - sum(made)} of {len(made)} fresh and miss samples by a sandbox made for it; the daemon\'s audit '
                f'log recorded {aw.get("true", 0)} cell Runs warm and {aw.get("false", 0)} fresh, the warm-up and the untimed '
                f'calls that took the member included')
        if d["provider"] == "docker":
            counted = sum(len(x["freshCreates"]) for x in timed)
            jumps = {j.split(":")[0] for j in d["clockJumps"]}
            off = [u.split(":")[0] for u in d["unexpected"]]
            line += (f'; docker\'s event log showed the run containers each call should make (one for a fresh or miss call, '
                     f'none for a warm call or a session) in {counted - len(off)} of {counted} samples')
            stepped = [u for u in off if u in jumps]
            other = [u for u in off if u not in jumps]
            if stepped:
                line += (f' (not in {html.escape("; ".join(stepped))}, which ran while the machine\'s clock stepped back '
                         f'about a second: that moves the time stamps docker\'s events are found by, and the answer and the '
                         f'audit line say where {"it" if len(stepped) == 1 else "each"} ran)')
            if other:
                line += f' (not explained: {html.escape("; ".join(other))})'
            line += (f'; {"no" if not d["leftover"] else len(d["leftover"])} plimsoll container'
                     f'{"s" if len(d["leftover"]) != 1 else ""} remained after the daemon stopped')
        checks.append(f"<li>{line}.</li>")

    pf = {rt: ocs(onecall[rt], "readyz before fresh, Preflight cached python")[0] for rt, _ in present}
    return f"""
<h2>The one-call path through the daemon (2026-10-29)</h2>
<p>A <code>Run</code>, the daemon's call that runs code once in a sandbox of its own, may now carry a
<a href="https://plimsollmark.github.io/plimsoll/trainers/glossary.html#cell">cell (INTERNAL · glossary →)</a>, code for
a Python or JavaScript interpreter whose final value is printed, and ask for
<code>prefer_warm</code>: the daemon then runs it in a pool member that is already waiting, a sandbox no code has
touched with both interpreters running, and deletes the member after the one call. With no member free it runs the
cell in a sandbox made for it, as it does without the flag (a <dfn>miss</dfn>: the call still runs, only slower).
The answer's <code>warm</code> says which path ran. This section times that call end to end, as a caller sees it:
<code>onecall/main.go</code> builds plimsolld from the checkout, starts it with the docker provider{
' (or, for the OpenShell set, the openshell provider and a local OpenShell gateway, v0.1.2, with its docker driver)' if 'openshell' in onecall else ''}, image
<code>{html.escape(base['image'])}</code> and a pool of {base['pool']} (<code>SANDBOX_SESSION_POOL</code>), and calls it
over loopback (the machine's own network interface) with the Go client, which checks every answer's
<a href="https://plimsollmark.github.io/plimsoll/trainers/glossary.html#run-record">run record (INTERNAL · glossary →)</a>.
The cell is <code>{html.escape(base['code'])}</code>; {base['reps']} samples per bar, each call preceded by an untimed
{base['pauseMs'] / 1000:.1f} s pause so the pool has made its next member; the calls of a repetition run in the same
order, so a change in the machine's load reaches every bar alike.</p>
<p>Six calls per language. <b>One call, warm</b>: a Run with <code>prefer_warm</code>, served by the waiting member.
<b>Session: open + cell</b>: the same work as three calls, what the clients did before the daemon took the path over: a
session opened warm-only (it is handed the waiting member or refused), one cell, then the close, which is not in the bar
(the table has it). <b>Fresh</b>: the Run without <code>prefer_warm</code>, in a sandbox made for it. <b>Miss</b>: a Run
with <code>prefer_warm</code> sent as soon as another such Run has taken the only member, while the pool is still making
the next one, so it runs fresh. Fresh and miss are each measured twice, because a fresh run on docker first re-runs the
provider's <a href="https://plimsollmark.github.io/plimsoll/trainers/glossary.html#preflight">Preflight (INTERNAL ·
glossary →)</a>, its checks of the docker daemon, the runtime and the images, whenever the last one is 5 s old or more,
and a warm call never does: <b>Preflight due</b> is the call as it comes after the pause, <b>Preflight cached</b> the
same call sent right after a <code>GET /readyz</code> (untimed), which re-runs it. A caller whose calls are seconds apart
on a quiet daemon sees the first; a busy daemon, where some fresh run or readiness check ran in the last 5 s, the
second.</p>
<div class="tiles">{tiles}</div>
<div class="legend">{legend}</div>
<div class="charts">{charts}</div>
{onecall_reading(present, pf)}
<h3>All one-call numbers (ms)</h3>
<div style="overflow-x:auto"><table><thead><tr><th>Runtime</th><th>Language</th><th>Call</th><th>Median</th><th>10th to 90th percentile</th><th>Min to max</th><th>n</th></tr></thead>
<tbody>{rows}</tbody></table></div>
<p>The machine while each set ran. The load average is the number of processes running or waiting for a CPU, averaged
over the last minute; this laptop has {html.escape(base['machine'].split(', ')[1])}, and other programs ran beside these
sets.</p>
<ul>{loads}</ul>
{repeat}
<p>Checked on every sample, not assumed:</p>
<ul>{''.join(checks)}</ul>
<p>What these numbers do not show:</p>
<ul>
<li>Another machine or a network. One laptop ({html.escape(base['machine'])}), docker {html.escape(base.get('docker', ''))}
on the same machine as the daemon and the client, so no network lies between them.</li>
<li>A workload. The cell does almost nothing, so the bars are the path's own cost, not a program's run time.</li>
<li>Bursts. The pool held {base['pool']} member{'s' if base['pool'] != 1 else ''} and the calls came {base['pauseMs'] / 1000:.1f} s apart; more calls at
once than the pool holds, or calls faster than it refills, turn warm calls into misses. The miss was measured only as
the second of two calls in a row.</li>
<li>The machine's work. A warm call still costs a sandbox's start and removal; the pool makes them off the caller's
path. What a waiting member holds in memory is measured in the sections below, not here.</li>
<li>The wall clock. This laptop's clock stepped back about a second several times during the sets; the samples are
timed on the monotonic clock, which such a step does not move.</li>
</ul>
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

onecall_links = ""
if onecall:
    files = [f'<a href="onecall-{rt}.json">onecall-{rt}.json</a>' for rt in [r for r, _ in ONECALL_RUNTIMES] + ["runc-repeat"] if rt in onecall]
    onecall_links = ", " + ", ".join(files) + " (one call through the daemon)"

page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Warm pool: never-used containers against a cold start</title>
<style>
:root {{ color-scheme: light; --bg: #fcfcfb; --ink: #0b0b0b; --ink2: #52514e; --grid: #e4e3df;
  --s1: #2a78d6; --s2: #eb6834; --s3: #1baf7a; --s4: #eda100; }}
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
.grp {{ font-size: 13px; font-weight: 600; fill: var(--ink2); }} .whisk {{ stroke: var(--ink); stroke-width: 1.5; }}
.legend i.whisk-key {{ width: 16px; height: 0; border-radius: 0; border-top: 1.5px solid var(--ink); vertical-align: 3px; }}
h3 {{ font-size: 15px; margin: 22px 0 6px; }}
.legend {{ display: flex; gap: 18px; font-size: 13px; color: var(--ink2); margin: 8px 0; flex-wrap: wrap; }}
.legend i {{ display: inline-block; width: 12px; height: 12px; border-radius: 3px; margin-right: 6px; vertical-align: -1px; }}
table {{ border-collapse: collapse; width: 100%; font-size: 13px; background: #fff; }}
th, td {{ border-bottom: 1px solid var(--grid); padding: 6px 8px; text-align: left; }} th {{ color: var(--ink2); font-weight: 600; }}
code {{ font-size: 13px; }} pre {{ overflow-x: auto; background: #f4f6f9; padding: 10px 12px; border-radius: 6px; }}
</style></head><body><main>
<nav style="display:flex;flex-wrap:wrap;gap:6px 20px;align-items:baseline;padding:0 0 12px;margin:0 0 20px;border-bottom:1px solid #d1d9e0;font-size:15px"><a href="https://plimsollmark.github.io/plimsoll/" style="font-weight:700;color:#0f4a85;text-decoration:none">plimsoll home</a><a href="https://plimsollmark.github.io/plimsoll/measurements/session-latency/index.html">Session latency</a><a href="https://plimsollmark.github.io/plimsoll/trainers/">Lessons</a><a href="https://github.com/plimsollmark/plimsoll">Source on GitHub ↗</a></nav>
<h1>Warm pool: never-used containers against a cold start</h1>
<p>Whether a pool of locked-down containers that no code has touched, each claimed once and removed after, takes the
container start off the path of a session's first call, and of a single call that asks for one
(<code>SANDBOX_SESSION_POOL</code>; the terms session, cell and relay are defined in
<a href="https://github.com/plimsollmark/plimsoll/blob/main/docs/sessions.md">the sessions guide (EXTERNAL · source
repo ↗)</a>). The page has {"five" if onecall else "four"} parts: {"one call through the daemon (<code>prefer_warm</code>), the newest; " if onecall else ""}the pool as built, the language hints that steer it,
the same pool on OpenShell, and the probe that came first. The probe was measured {html.escape(p2['measured'])} on a laptop, docker {html.escape(p2['docker_version'])},
image <code>{html.escape(p2['image'])}</code>, the docker provider's lockdown flags, {p2['n']} samples per bar, a
<code>node -e</code> snippet as the call. A laptop number, not a product number: what carries over is the ratio and the
breakdown, not the milliseconds.</p>
{onecall_section()}
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
{openshell_section()}
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
as built), <a href="hints-runc.json">hints-runc.json</a> (language hints), <a href="openshell.json">openshell.json</a> (the pool
on OpenShell){onecall_links}. <a href="exec-split.json">exec-split.json</a>
holds two medians per runtime timed by hand (<code>docker exec</code> of <code>true</code>, and of the snippet); no
program reproduces it. The programs are in
<a href="https://github.com/plimsollmark/plimsoll/tree/main/measurements/warm-pool">measurements/warm-pool
(EXTERNAL · source repo ↗)</a>. From a checkout, with the images <code>make docker-images</code> builds (and
gVisor installed for the runsc runs):</p>
<pre><code>python3 measurements/warm-pool/probe.py 20 docs/measurements/warm-pool/pass-2.json
go run ./measurements/warm-pool/pooled                  # runc
go run ./measurements/warm-pool/pooled -runtime runsc   # gVisor
go run ./measurements/warm-pool/hints
go run ./measurements/warm-pool/openshell                # SANDBOX_OPENSHELL_* naming a gateway
go run ./measurements/warm-pool/onecall                  # runc, through plimsolld
go run ./measurements/warm-pool/onecall -runtime runsc   # gVisor
go run ./measurements/warm-pool/onecall -tag repeat      # runc again, a second file
go run ./measurements/warm-pool/onecall -provider openshell  # SANDBOX_OPENSHELL_* naming a gateway
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
