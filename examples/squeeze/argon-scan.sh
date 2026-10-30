#!/usr/bin/env bash
# The leaked practice seed of the did-it-learn entry (the Gemini 4 Argon hackathon,
# 2026-10-25), looked for with plimsoll-withheld, offline.
#
# Until 12:55 that day an example URL in the entry's replay viewer, tasks/drone/view.mjs,
# named one of the easy course's 16 practice seeds, and the viewer was one of the files the
# harness put into every rebuild's sandbox. This rebuilds those files from the public
# repository at two commits, the last one before the fix (12:44) and the fix (12:55), the way
# the entry's own loop/kit.py built them (its DRONE_FILES list, with task.mjs's practice-seed
# block cut out by kit.py's own regular expression), and scans both against a withheld set of
# the 16 seeds. Run it from the root of a plimsoll checkout:
#
#   git clone https://github.com/carrollco/did-it-learn ../did-it-learn
#   examples/squeeze/argon-scan.sh ../did-it-learn
#
# It writes only under tmp/argon-scan/ and prints the transcript that
# examples/squeeze/argon-scan.txt holds and the page quotes. It starts no sandbox, calls no
# model and needs no network once the clone is made.
set -euo pipefail

repo="${1:?usage: examples/squeeze/argon-scan.sh DID_IT_LEARN_CHECKOUT}"
before=6887745aaaf49d18492f38aa7000aa4a83d4f932
after=b49116e19281648cf1aac82db70b00508506f59c
work=tmp/argon-scan
[ -f go.mod ] && [ -d cmd/plimsoll-withheld ] || { echo "run this from the root of a plimsoll checkout" >&2; exit 2; }
rm -rf "$work"
mkdir -p "$work"

# The files one rebuild's sandbox got at COMMIT, written under OUT/workspace.
ship() {
  python3 -I - "$repo" "$1" "$2" <<'SHIP'
import pathlib, re, subprocess, sys
repo, commit, out = sys.argv[1], sys.argv[2], pathlib.Path(sys.argv[3]) / "workspace"
def show(path):
    return subprocess.run(["git", "-C", repo, "show", f"{commit}:{path}"], check=True, capture_output=True).stdout.decode()
names = re.findall(r'"([^"]+)"', re.search(r"DRONE_FILES = \[(.*?)\]", show("loop/kit.py"), re.S).group(1))
files = {"harness/package.json": show("harness/package.json")}
for name in names:
    text = show(f"tasks/drone/{name}")
    if name == "task.mjs":  # kit.py's sources(task, variant) for every variant but the explorer
        text = re.sub(r"\s*// VALIDATION_SEEDS_START.*?// VALIDATION_SEEDS_END", "", text, flags=re.S)
    files[f"tasks/drone/{name}"] = text
for rel, text in files.items():
    (out / rel).parent.mkdir(parents=True, exist_ok=True)
    (out / rel).write_text(text)
print(f"#   {len(files)} files: {', '.join(sorted(files))}")
SHIP
}

echo "# did-it-learn $before (12:44, the last commit before the fix), as loop/kit.py shipped it into a rebuild's sandbox:"
ship "$before" "$work/before"
echo "# did-it-learn $after (12:55, the fix), the same way:"
ship "$after" "$work/after"
echo "# The check the entry made before shipping, in loop/kit.py at $before:"
git -C "$repo" show "$before:loop/kit.py" | grep -n 'assert "VALIDATION_SEEDS"' | sed 's/^/#   /'

echo "# The withheld values: the easy course's 16 practice seeds, from examples/squeeze/jobs/hackathon-regrade.json, one per line."
python3 -I -c 'import json, sys; print("\n".join(str(s) for s in json.load(open(sys.argv[1]))["courses"][0]["practice"]))' \
  examples/squeeze/jobs/hackathon-regrade.json > "$work/seeds.txt"
echo "\$ wc -l < $work/seeds.txt"
wc -l < "$work/seeds.txt"

run() {
  echo "\$ go run $*"
  local code=0
  go run "$@" 2>/dev/null || code=$?
  echo "(exit $code)"
}
echo "\$ go run ./cmd/plimsoll-withheld build -mode refuse -values $work/seeds.txt > $work/withheld.json"
go run ./cmd/plimsoll-withheld build -mode refuse -values "$work/seeds.txt" > "$work/withheld.json"
echo "(exit 0; the set file's SHA-256: $(sha256sum "$work/withheld.json" | cut -d' ' -f1))"
run ./cmd/plimsoll-withheld scan -set "$work/withheld.json" "$work/before/workspace"
run ./cmd/plimsoll-withheld scan -set "$work/withheld.json" "$work/after/workspace"

echo "# What the find points at:"
echo "\$ sed -n 2p $work/seeds.txt"
sed -n 2p "$work/seeds.txt"
echo "\$ grep -n -o 'track=[^&]*' $work/before/workspace/tasks/drone/view.mjs $work/after/workspace/tasks/drone/view.mjs"
grep -n -o 'track=[^&]*' "$work/before/workspace/tasks/drone/view.mjs" "$work/after/workspace/tasks/drone/view.mjs"
