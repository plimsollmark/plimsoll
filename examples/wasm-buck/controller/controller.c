// A buck converter controller in C, compiled to WebAssembly inside the sandbox and
// judged against the plant /models/buck.wasm: an averaged synchronous buck
// converter (100 uH, 100 uF) that must hold 5 V from an input of 10 to 16 V while
// the load halves partway through the run.
//
// The law is average current-mode control, the usual structure of converter
// firmware. An inner loop makes the inductor current follow a reference (fast: the
// inductor answers the duty cycle in tens of microseconds), and an outer
// proportional-integral voltage loop sets that reference, clamped so the inductor
// is never asked for more than 6 A. The voltage target ramps from 0 to 5 V over the
// first 3 ms, so a cold start is a controlled charge, not an inrush. Both loops
// have anti-windup: an integrator stops accumulating while its output is clamped.
// Current feedback is what damps the LC resonance a voltage-only loop rings on.
//
// The contract with controller.js, the Node shim the judge runs: the module exports
// one function, control, called once per 10 us tick with the output voltage, the
// inductor current and the tick index, returning the duty cycle in [0, 1]. State
// between ticks lives in globals, because a module instance lives for the whole
// run. The module imports nothing.
//
// This is a line-for-line port of reference.js, the same law in JavaScript. Every
// expression keeps the JavaScript operand order and the build passes
// -ffp-contract=off, so no multiply and add are fused; the law calls no library
// function at all. Each operation is therefore the same IEEE 754 double operation
// in both languages, and the two trajectories are identical to the bit.

static const double ref = 5, h = 1e-5, ramp = 0.003, iMax = 6;
static const double kpv = 1.0, kiv = 5000, kci = 0.2, kii = 2000;
static double t = 0, vInt = 0, dInt = 0;

__attribute__((export_name("control")))
double control(double v, double i, int k) {
  (void)k; // the law keeps its own clock, t, as reference.js does
  const double target = t < ramp ? ref * (t / ramp) : ref;
  const double e = target - v;
  double iRef = kpv * e + kiv * vInt;
  if (iRef > -2 && iRef < iMax) vInt += e * h;
  if (iRef > iMax) iRef = iMax;
  if (iRef < -2) iRef = -2;
  const double ei = iRef - i;
  double u = kci * ei + dInt;
  if (u >= 0 && u <= 1) dInt += kii * ei * h;
  if (u < 0) u = 0;
  if (u > 1) u = 1;
  t += h;
  return u;
}
