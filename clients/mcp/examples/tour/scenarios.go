package main

// The code and data the scripted calls send. Each is what a model would write for the
// question its scenario poses; the data files are made up for the examples.

// primeCode answers "is 2**61 - 1 prime?" by running a deterministic Miller-Rabin
// test, with a number one digit away that is not, so the answer is not a lucky guess.
const primeCode = `def is_prime(n):
    if n < 2:
        return False
    bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in bases:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    # Miller-Rabin with these twelve bases is exact for every n below 3.3 * 10**24.
    for a in bases:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

for label, n in [("2**61 - 1", 2**61 - 1), ("2**61 + 1", 2**61 + 1)]:
    if is_prime(n):
        print(f"{n} = {label}: prime")
    else:
        factor = next(p for p in range(2, 1000) if n % p == 0)
        print(f"{n} = {label}: not prime, divisible by {factor}")
`

// ridesCSV is made-up data: daily bike rentals at three stations over four days.
const ridesCSV = `date,station,rides,avg_minutes
2026-06-01,Harbor,182,14.2
2026-06-01,Market,240,11.8
2026-06-01,Hillside,95,19.5
2026-06-02,Harbor,201,13.9
2026-06-02,Market,262,12.1
2026-06-02,Hillside,88,20.3
2026-06-03,Harbor,176,14.8
2026-06-03,Market,231,11.5
2026-06-03,Hillside,102,18.7
2026-06-04,Harbor,224,13.1
2026-06-04,Market,288,12.4
2026-06-04,Hillside,97,19.9
`

const ridesCode = `import csv
import statistics

with open("data/rides.csv", newline="") as f:
    rows = list(csv.DictReader(f))

rides = [int(r["rides"]) for r in rows]
print("rows:", len(rows))
print("total rides:", sum(rides))
print("mean per station per day:", round(statistics.mean(rides), 1))
print("median:", statistics.median(rides))
print("standard deviation:", round(statistics.stdev(rides), 1))

by_station = {}
for r in rows:
    by_station.setdefault(r["station"], []).append(r)
for station, rs in sorted(by_station.items()):
    total = sum(int(r["rides"]) for r in rs)
    minutes = statistics.mean(float(r["avg_minutes"]) for r in rs)
    print(f"{station}: {total} rides over {len(rs)} days, mean trip {minutes:.1f} min")

busiest = max(rows, key=lambda r: int(r["rides"]))
print("busiest:", busiest["station"], "on", busiest["date"], "with", busiest["rides"], "rides")
`

// readingsCSV is made-up data: a fortnight of daily highs.
const readingsCSV = `day,celsius
2026-06-01,21.4
2026-06-02,22.9
2026-06-03,24.1
2026-06-04,25.6
2026-06-05,23.8
2026-06-06,22.2
2026-06-07,24.9
2026-06-08,26.3
2026-06-09,27.4
2026-06-10,26.8
2026-06-11,24.4
2026-06-12,23.1
2026-06-13,25.2
2026-06-14,26.0
`

const loadReadings = `import csv

with open("readings.csv", newline="") as f:
    readings = {row["day"]: float(row["celsius"]) for row in csv.DictReader(f)}
len(readings)
`

const warmestDay = `warmest = max(readings, key=readings.get)
warmest, readings[warmest]
`

const daysAbove25 = `sum(1 for c in readings.values() if c > 25)
`

// medianBuggy returns the upper middle value for an even count, which its own check catches.
const medianBuggy = `def median(xs):
    xs = sorted(xs)
    return xs[len(xs) // 2]

assert median([3, 1, 2]) == 2
assert median([4, 1, 3, 2]) == 2.5, f"median([4, 1, 3, 2]) gave {median([4, 1, 3, 2])}"
print("all checks pass")
`

const medianFixed = `def median(xs):
    xs = sorted(xs)
    mid = len(xs) // 2
    return xs[mid] if len(xs) % 2 else (xs[mid - 1] + xs[mid]) / 2

assert median([3, 1, 2]) == 2
assert median([4, 1, 3, 2]) == 2.5, f"median([4, 1, 3, 2]) gave {median([4, 1, 3, 2])}"
print("all checks pass")
`

// networkCode names the server by address, so no name lookup is involved: what fails is
// the sandbox's network itself, at once, well inside the run's time budget.
const networkCode = `import socket
import urllib.request

print("network interfaces:", [name for _, name in socket.if_nameindex()])

try:
    with urllib.request.urlopen("https://1.1.1.1/", timeout=2) as response:
        print("reached the internet: HTTP", response.status)
except Exception as error:
    print("no network:", type(error).__name__, error)
`

const writeJSON = `import json

trip = {"city": "Lisbon", "highs_c": [21, 23, 22, 25, 24], "note": "made-up example data"}
with open("trip.json", "w") as f:
    json.dump(trip, f)
print("wrote trip.json with", len(trip["highs_c"]), "daily highs")
`

const readJSON = `const fs = require("node:fs");
const trip = JSON.parse(fs.readFileSync("trip.json", "utf8"));
const mean = trip.highs_c.reduce((a, b) => a + b, 0) / trip.highs_c.length;
console.log(` + "`${trip.city}: mean daily high ${mean.toFixed(1)} C, read by Node ${process.version}`" + `);
`

const setAnswer = `answer = 42
print("answer is", answer)
`

const runaway = `while True:
    pass
`

const stillThere = `print("still answering")
try:
    print("answer is still", answer)
except NameError:
    print("answer is gone: this interpreter is not the one that defined it")
`
