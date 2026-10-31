// The double pendulum's flip map: 320 by 320 pendulums, each released at rest from a pair of
// angles measured from straight down. A pixel's number is the step at which either arm first
// goes over the top, 0 if it never does. Equal masses and arms, g/l = 1, fourth-order
// Runge-Kutta, 10,000 steps of 0.02. Writes 320 x 320 little-endian uint16 to the file named.
import { writeFileSync } from 'node:fs';

const N = 320, STEPS = 10000, dt = 0.02, PI = Math.PI;

function acc(t1, t2, w1, w2, out) {
  const d = t1 - t2, sd = Math.sin(d), cd = Math.cos(d);
  const den = 3 - Math.cos(2 * d);
  out[0] = (-3 * Math.sin(t1) - Math.sin(t1 - 2 * t2) - 2 * sd * (w2 * w2 + w1 * w1 * cd)) / den;
  out[1] = (2 * sd * (2 * w1 * w1 + 2 * Math.cos(t1) + w2 * w2 * cd)) / den;
}

const a = [0, 0], b = [0, 0], c = [0, 0], e = [0, 0];

function flipStep(th1, th2) {
  // At rest, energy decides: a start above this line cannot reach the top, so it is not simulated.
  if (2 * Math.cos(th1) + Math.cos(th2) > 1) return 0;
  let t1 = th1, t2 = th2, w1 = 0, w2 = 0;
  for (let k = 1; k <= STEPS; k++) {
    acc(t1, t2, w1, w2, a);
    acc(t1 + dt / 2 * w1, t2 + dt / 2 * w2, w1 + dt / 2 * a[0], w2 + dt / 2 * a[1], b);
    acc(t1 + dt / 2 * (w1 + dt / 2 * a[0]), t2 + dt / 2 * (w2 + dt / 2 * a[1]), w1 + dt / 2 * b[0], w2 + dt / 2 * b[1], c);
    acc(t1 + dt * (w1 + dt / 2 * b[0]), t2 + dt * (w2 + dt / 2 * b[1]), w1 + dt * c[0], w2 + dt * c[1], e);
    const nt1 = t1 + dt / 6 * (w1 + 2 * (w1 + dt / 2 * a[0]) + 2 * (w1 + dt / 2 * b[0]) + (w1 + dt * c[0]));
    const nt2 = t2 + dt / 6 * (w2 + 2 * (w2 + dt / 2 * a[1]) + 2 * (w2 + dt / 2 * b[1]) + (w2 + dt * c[1]));
    w1 += dt / 6 * (a[0] + 2 * b[0] + 2 * c[0] + e[0]);
    w2 += dt / 6 * (a[1] + 2 * b[1] + 2 * c[1] + e[1]);
    t1 = nt1; t2 = nt2;
    if (t1 > PI || t1 < -PI || t2 > PI || t2 < -PI) return k;
  }
  return 0;
}

const out = new Uint16Array(N * N);
for (let j = 0; j < N; j++) {
  const th2 = PI - (j + 0.5) * (2 * PI / N);
  for (let i = 0; i < N; i++) out[j * N + i] = flipStep(-PI + (i + 0.5) * (2 * PI / N), th2);
}
writeFileSync(process.argv[2], Buffer.from(out.buffer));
