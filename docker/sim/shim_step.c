// Vendored from the plimsoll-sim repository at commit d3f9b28 (2026-09-18),
// unchanged below this header. The stepping shim around models/CartPole: a host
// drives one communication step at a time and sets the force before each, which
// is what lets a controller outside the module (the caller's process) be judged
// against the plant. Compiled to /models/cartpole.wasm, loaded by /oracle/run.mjs.
// Stepping shim around a Reference-style FMU with an input (FMI 3.0
// co-simulation): the host drives one communication step at a time and sets the
// input before each, so a controller outside the module can close the loop.
// Which model, which three parameters, which input and which outputs come from
// macros; the default is CartPole (models/CartPole).
//
//   sim_init(p0, p1, p2, h, t_end) -> 0, or a negative code
//   sim_width()                    -> outputs per state read
//   sim_get(out)                   -> the current state into out[0..width)
//   sim_step(u, out)               -> set the input to u, advance one step of h,
//                                     write the new state; 1, 0 at termination,
//                                     negative on error
//   sim_free()
//
// One instance per module instance: a host that wants N plants instantiates the
// module N times, which is how every host in this repository already works.
#include <stdlib.h>
#include <stdint.h>
#include "fmi3Functions.h"
#define TOKEN "{BFE341C2-CAE8-4202-9242-30BE8F255E82}"   /* CartPole */
#define VR_P0 5   /* theta, the initial lean */
#define VR_P1 10  /* l, pole half-length */
#define VR_P2 11  /* M, cart mass */
#define VR_IN 9   /* F, the force the controller applies */
#define NOUT 4
#define VR_O {1, 3, 5, 7}  /* x, v, theta, omega */

static fmi3Instance inst;
static double t, step_h;
static const fmi3ValueReference outvr[NOUT] = VR_O;

__attribute__((export_name("alloc")))
void *shim_alloc(size_t bytes) { return malloc(bytes); }

__attribute__((export_name("sim_width")))
int32_t sim_width(void) { return NOUT; }

__attribute__((export_name("sim_init")))
int32_t sim_init(double p0, double p1, double p2, double h, double t_end) {
    if (inst) { fmi3FreeInstance(inst); inst = NULL; }
    inst = fmi3InstantiateCoSimulation("m", TOKEN, "", fmi3False, fmi3False, fmi3False, fmi3False,
                                       NULL, 0, NULL, NULL, NULL);
    if (!inst) return -1;
    const fmi3ValueReference vrs[3] = {VR_P0, VR_P1, VR_P2};
    const fmi3Float64 vals[3] = {p0, p1, p2};
    if (fmi3SetFloat64(inst, vrs, 3, vals, 3) != fmi3OK) return -2;
    if (fmi3EnterInitializationMode(inst, fmi3False, 0, 0, fmi3True, t_end) != fmi3OK) return -3;
    if (fmi3ExitInitializationMode(inst) != fmi3OK) return -4;
    t = 0;
    step_h = h;
    return 0;
}

__attribute__((export_name("sim_get")))
int32_t sim_get(double *out) {
    if (!inst) return -1;
    return fmi3GetFloat64(inst, outvr, NOUT, out, NOUT) == fmi3OK ? 0 : -6;
}

__attribute__((export_name("sim_step")))
int32_t sim_step(double u, double *out) {
    if (!inst) return -1;
    const fmi3ValueReference invr = VR_IN;
    if (fmi3SetFloat64(inst, &invr, 1, &u, 1) != fmi3OK) return -7;
    fmi3Boolean ev, term, early;
    fmi3Float64 last;
    if (fmi3DoStep(inst, t, step_h, fmi3True, &ev, &term, &early, &last) != fmi3OK) return -5;
    t += step_h;
    if (fmi3GetFloat64(inst, outvr, NOUT, out, NOUT) != fmi3OK) return -6;
    return term ? 0 : 1;
}

__attribute__((export_name("sim_free")))
void sim_free(void) {
    if (inst) { fmi3FreeInstance(inst); inst = NULL; }
}
