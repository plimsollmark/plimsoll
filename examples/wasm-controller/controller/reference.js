// The JavaScript controller that controller.c is a line-for-line port of: the same
// swing-up law, run by the judge as a Node process. While the pole is down it drives
// the cart so the pole's mechanical energy climbs toward its upright value (push in
// the direction that adds energy, with a small centring term so the cart stays on
// the track); once the pole is near upright and slow it hands over to a linear
// balancing law with the angle wrapped into [-pi, pi]. Pole mass 0.1 kg and
// half-length 0.5 m are the plant's defaults.
//
// The example judges this file beside the C build so the page can compare their
// fingerprints from one run. Every expression has the operand order of its C twin,
// so the only arithmetic that differs between the two is cos: V8's Math.cos here,
// the cos compiled into controller.wasm there.
import { createInterface } from 'node:readline';
const m = 0.1, g = 9.81, l = 0.5;
const eUp = m * g * l;
const kE = 60, kx = 2.0, kv = 3.0;
const kp = 40, kd = 5, kxb = 1, kvb = 1;
let catching = false;
const wrap = (a) => { let w = (a + Math.PI) % (2 * Math.PI); if (w < 0) w += 2 * Math.PI; return w - Math.PI; };
const rl = createInterface({ input: process.stdin });
rl.on('line', (line) => {
  const [x, v, theta, omega] = line.split('|')[0].trim().split(' ').map(Number);
  const tw = wrap(theta);
  const c = Math.cos(theta);
  if (!catching && c > 0.9 && Math.abs(omega) < 3.5) catching = true;
  if (catching && c < 0.3) catching = false;
  let u;
  if (catching) {
    u = kp * tw + kd * omega + kxb * x + kvb * v;
  } else {
    const E = (2 / 3) * m * l * l * omega * omega + m * g * l * c;
    const dir = omega * c >= 0 ? 1 : -1;
    u = kE * (E - eUp) * dir - kx * x - kv * v;
  }
  if (u > 20) u = 20;
  if (u < -20) u = -20;
  process.stdout.write(u + '\n');
});
