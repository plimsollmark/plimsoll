// The agent's first draft: the same structure with the position and velocity
// terms of the wrong sign, a classic mistake (the cart must move under the pole,
// not away from where it stands). It balances the pole for a moment and then
// runs off the rail. The judge records exactly where.
import { createInterface } from 'node:readline';
const kp = 40, kd = 5, kx = -1, kv = -1;
const rl = createInterface({ input: process.stdin });
rl.on('line', (line) => {
  const [x, v, theta, omega] = line.split(' ').map(Number);
  const u = kp * theta + kd * omega + kx * x + kv * v;
  process.stdout.write(u + '\n');
});
