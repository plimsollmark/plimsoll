// The accepted controller: linear state feedback. Each line on stdin is the plant
// state "x v theta omega"; the answer is one number, the force on the cart. Only
// + and * so the arithmetic is plain IEEE doubles with no engine-specific libm.
import { createInterface } from 'node:readline';
const kp = 40, kd = 5, kx = 1, kv = 1;
const rl = createInterface({ input: process.stdin });
rl.on('line', (line) => {
  const [x, v, theta, omega] = line.split(' ').map(Number);
  const u = kp * theta + kd * omega + kx * x + kv * v;
  process.stdout.write(u + '\n');
});
