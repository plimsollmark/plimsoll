// The accepted controller: average current-mode control. An inner loop makes the
// inductor current follow a reference (fast: the inductor answers the duty in
// tens of microseconds), and an outer proportional-integral voltage loop sets
// that reference, clamped so the inductor can never be asked for more than 6 A.
// The reference voltage ramps from 0 to 5 V over the first 3 ms so a cold start
// is a controlled charge, not an inrush. Both loops have anti-windup. Current
// feedback is what damps the LC resonance that a voltage-only loop rings on.
import { createInterface } from 'node:readline';
const ref = 5, h = 1e-5, ramp = 0.003, iMax = 6;
const kpv = 1.0, kiv = 5000, kci = 0.2, kii = 2000;
let t = 0, vInt = 0, dInt = 0;
const rl = createInterface({ input: process.stdin });
rl.on('line', (line) => {
  const [v, i] = line.split('|')[0].trim().split(' ').map(Number);
  const target = t < ramp ? ref * (t / ramp) : ref;
  const e = target - v;
  let iRef = kpv * e + kiv * vInt;
  if (iRef > -2 && iRef < iMax) vInt += e * h;
  if (iRef > iMax) iRef = iMax;
  if (iRef < -2) iRef = -2;
  const ei = iRef - i;
  let u = kci * ei + dInt;
  if (u >= 0 && u <= 1) dInt += kii * ei * h;
  if (u < 0) u = 0;
  if (u > 1) u = 1;
  t += h;
  process.stdout.write(u + '\n');
});
