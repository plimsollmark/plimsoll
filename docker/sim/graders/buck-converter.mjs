// The buck-converter grader. Reads a trajectory the judge wrote (per tick: v, i,
// u as little-endian float64) and prints one JSON line with the score in [0, 1]
// and the named failure, deterministically. It ships in the simulation image as
// /oracle/graders/buck-converter.mjs and runs in a project run of its own, after the
// run that made the trajectory, so that run's record binds its score to the
// trajectory it read (review D9, 2026-10-23).
//
//   node /oracle/graders/buck-converter.mjs trajectory.bin [h]
//
// Target 5 V. Score is the fraction of ticks from 2 ms onward with the output
// within 0.1 V of it. Hard failures: output above 6 V at any tick (overvoltage,
// the load is damaged) or inductor current beyond 10 A (overcurrent, the
// inductor saturates); either scores 0, and a value that is not a number counts as
// beyond its limit.
// Trivial policies: duty 0 never charges (never_regulated, 0); duty 1 from a cold
// start drives the inductor past 10 A within 100 us (overcurrent, 0).
import { readFileSync } from 'node:fs';
const [path, hArg = '0.00001'] = process.argv.slice(2);
if (!path) { console.error('usage: node buck-converter.mjs trajectory.bin [h]'); process.exit(2); }
const h = Number(hArg), width = 2, stride = width + 1;
const buf = readFileSync(path);
const rec = new Float64Array(buf.buffer, buf.byteOffset, buf.byteLength / 8);
const ticks = Math.floor(rec.length / stride);
const ref = 5, band = 0.1, from = Math.round(0.002 / h);
let overV = null, overI = null, maxV = -Infinity, maxI = 0, inBand = 0, counted = 0;
for (let k = 0; k < ticks; k++) {
  const v = rec[k * stride], i = rec[k * stride + 1];
  if (v > maxV) maxV = v;
  if (Math.abs(i) > maxI) maxI = Math.abs(i);
  // Each limit is phrased so a value that is not a number fails it: NaN compares
  // false, so "v > 6" would let a NaN voltage pass (review, 2026-10-24).
  if (overV === null && !(v <= 6)) overV = k * h;
  if (overI === null && !(Math.abs(i) <= 10)) overI = k * h;
  if (k >= from) { counted++; if (Math.abs(v - ref) <= band) inBand++; }
}
const frac = counted ? inBand / counted : 0;
const failure = overI !== null && (overV === null || overI <= overV) ? 'overcurrent' : (overV !== null ? 'overvoltage' : (frac === 0 ? 'never_regulated' : null));
console.log(JSON.stringify({ score: failure ? 0 : frac, failure, ticks, max_v: maxV, max_abs_i: maxI, overvoltage_at: overV, overcurrent_at: overI, band_fraction: frac }));
