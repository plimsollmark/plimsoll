// A cart-pole swing-up controller in C, compiled to WebAssembly inside the sandbox
// and judged against the plant /models/cartpole.wasm.
//
// The law: while the pole is down, drive the cart so the pole's mechanical energy
// climbs toward its upright value (push in the direction that adds energy, with a
// small centring term so the cart stays on the track). Once the pole is near
// upright and slow, hand over to a linear balancing law with the angle wrapped
// into [-pi, pi]. Pole mass 0.1 kg and half-length 0.5 m are the plant's defaults;
// the cart mass is not known and the law does not need it.
//
// The contract with controller.js, the Node shim the judge runs: the module exports
// one function, control, called once per tick with the state and the tick index,
// returning the force in newtons. State between ticks lives in globals, because a
// module instance lives for the whole episode. The module must import nothing: the
// shim instantiates it with an empty import object.
//
// Every expression keeps the operand order of the JavaScript law it was ported
// from, and the build compiles with -ffp-contract=off, so the only arithmetic that
// can differ from a JavaScript run of the same law is cos itself: wasi-libc's cos
// here, V8's Math.cos there.
#include <math.h>

#define M 0.1
#define G 9.81
#define L 0.5
#define KE 60.0
#define KX 2.0
#define KV 3.0
#define KP 40.0
#define KD 5.0
#define KXB 1.0
#define KVB 1.0

static int catching = 0;

// wrap maps an angle into [-pi, pi). fmod is exact, like JavaScript's %.
static double wrap(double a) {
  double w = fmod(a + M_PI, 2 * M_PI);
  if (w < 0) w += 2 * M_PI;
  return w - M_PI;
}

__attribute__((export_name("control")))
double control(double x, double v, double theta, double omega, int k) {
  (void)k; // this law does not need the tick index; a scheduled one would
  const double eUp = M * G * L;
  double tw = wrap(theta);
  double c = cos(theta);
  if (!catching && c > 0.9 && fabs(omega) < 3.5) catching = 1;
  if (catching && c < 0.3) catching = 0;
  double u;
  if (catching) {
    u = KP * tw + KD * omega + KXB * x + KVB * v;
  } else {
    double E = (2.0 / 3.0) * M * L * L * omega * omega + M * G * L * c;
    double dir = omega * c >= 0 ? 1 : -1;
    u = KE * (E - eUp) * dir - KX * x - KV * v;
  }
  if (u > 20) u = 20;
  if (u < -20) u = -20;
  return u;
}
