// One trial of one cart-pole controller: a linear state-feedback law (force on the cart from
// the pole's angle and spin and the cart's place and speed) on the textbook cart-pole, 500
// steps of 10 ms. Only +, -, *, / and comparisons on doubles, whose rounding IEEE 754
// specifies, and sine and cosine as fixed polynomials, so conforming engines should print the
// same bytes.
const C = __C__, S = __S__, KP = __KP__, KD = __KD__, KX = __KX__, KV = __KV__, THETA0 = __THETA0__;
const g = 9.81, M = 1.0, m = 0.1, l = 0.5, FMAX = 20, DT = 0.01, STEPS = 500;
const sin = (a) => { const q = a * a; return a * (1 - q / 6 * (1 - q / 20 * (1 - q / 42 * (1 - q / 72 * (1 - q / 110))))); };
const cos = (a) => { const q = a * a; return 1 - q / 2 * (1 - q / 12 * (1 - q / 30 * (1 - q / 56 * (1 - q / 90)))); };
// The trajectory's fingerprint: 32-bit FNV-1a over every state's eight bytes, every step.
const view = new DataView(new ArrayBuffer(8));
let h = 0x811c9dc5;
const mix = (d) => { view.setFloat64(0, d); for (let i = 0; i < 8; i++) h = Math.imul(h ^ view.getUint8(i), 0x01000193) >>> 0; };
let x = 0, v = 0, th = THETA0, w = 0, t = 0;
while (t < STEPS) {
  let F = KP * th + KD * w + KX * x + KV * v;
  if (F > FMAX) F = FMAX;
  if (F < -FMAX) F = -FMAX;
  const s = sin(th), c = cos(th), total = M + m;
  const temp = (F + m * l * w * w * s) / total;
  const aw = (g * s - c * temp) / (l * (4 / 3 - m * c * c / total));
  const av = temp - m * l * aw * c / total;
  x += DT * v; v += DT * av; th += DT * w; w += DT * aw;
  mix(x); mix(v); mix(th); mix(w);
  t++;
  if (th > 0.8 || th < -0.8 || x > 2.4 || x < -2.4) break;
}
const upright = t === STEPS && th < 0.05 && th > -0.05 && x < 0.5 && x > -0.5;
console.log(JSON.stringify({ trial: [C, S], steps: t, upright, hash: h.toString(16) }));
