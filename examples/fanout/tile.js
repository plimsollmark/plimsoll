// One tile of the Mandelbrot set: the iteration count of each pixel, as hex.
// Only floating-point operations whose rounding the JavaScript standard specifies,
// so every conforming engine should print the same bytes.
const T = __GRID__, S = __SIZE__, N = T * S, MAX = 255, tx = __TX__, ty = __TY__;
const step = 3 / N, x0 = -2.25, y0 = -1.5;
let out = '';
for (let j = 0; j < S; j++) {
  const ci = y0 + (ty * S + j + 0.5) * step;
  for (let i = 0; i < S; i++) {
    const cr = x0 + (tx * S + i + 0.5) * step;
    let zr = 0, zi = 0, n = 0;
    while (n < MAX) {
      const zr2 = zr * zr, zi2 = zi * zi;
      if (zr2 + zi2 > 4) break;
      zi = 2 * zr * zi + ci;
      zr = zr2 - zi2 + cr;
      n++;
    }
    out += (n < 16 ? '0' : '') + n.toString(16);
  }
}
console.log(JSON.stringify({ tile: [tx, ty], counts: out }));
