// The cart-pole swing-up grader. Reads a trajectory the judge wrote (per tick:
// x, v, theta, omega, F as little-endian float64; theta is the angle from upright,
// unwrapped, so an upright pole may read 0 or any multiple of 2 pi) and prints one
// JSON line with the score in [0, 1] and the named failure, deterministically. It
// ships in the simulation image as /oracle/graders/cartpole-swingup.mjs and runs in a
// project run of its own, after the run that made the trajectory, so that run's record
// binds its score to the trajectory it read (review D9, 2026-10-23).
//
//   node /oracle/graders/cartpole-swingup.mjs trajectory.bin [h]
//
// Upright means cos(theta) > 0.98 (within about 0.2 rad). The run succeeds if the
// pole is upright at every tick from some time t_up to the end; the score is
// 1 - t_up / t_end, so a faster swing-up scores higher. Hard failure: the cart
// leaves the track (|x| > 2.4 m at any tick, or x not a number) and the run scores 0. A run that never
// holds upright scores 0 with failure never_upright.
// Trivial policies: F = 0 leaves the pole hanging (never_upright, 0); F = +20
// forever drives the cart off the track (off_track, 0).
import { readFileSync } from 'node:fs';

const [path, hArg = '0.01'] = process.argv.slice(2);
if (!path) { console.error('usage: node cartpole-swingup.mjs trajectory.bin [h]'); process.exit(2); }
const h = Number(hArg);
const width = 4, stride = width + 1;
const buf = readFileSync(path);
const rec = new Float64Array(buf.buffer, buf.byteOffset, buf.byteLength / 8);
const ticks = Math.floor(rec.length / stride);
const tEnd = ticks * h;

let offTrackAt = null, maxAbsX = 0;
let upFrom = null; // start tick of the current upright stretch
for (let k = 0; k < ticks; k++) {
  const x = rec[k * stride], theta = rec[k * stride + 2];
  const ax = Math.abs(x);
  if (ax > maxAbsX) maxAbsX = ax;
  // Phrased so a position that is not a number leaves the track: NaN compares false
  // (review, 2026-10-24).
  if (offTrackAt === null && !(ax <= 2.4)) offTrackAt = k * h;
  if (Math.cos(theta) > 0.98) { if (upFrom === null) upFrom = k; } else upFrom = null;
}
const tUp = upFrom === null ? null : upFrom * h;
const failure = offTrackAt !== null ? 'off_track' : (tUp === null ? 'never_upright' : null);
const score = failure ? 0 : 1 - tUp / tEnd;
console.log(JSON.stringify({ score, failure, ticks, t_up: tUp, off_track_at: offTrackAt, max_abs_x: maxAbsX }));
