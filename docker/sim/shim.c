// Vendored from the plimsoll-sim repository at commit 0be8574 (2026-09-18),
// unchanged below this header. Compiled with the Reference FMUs sources (Modelica
// Association, BSD-2, fetched at a pinned tag by docker/sim.Dockerfile) and with
// models/Lorenz into the wasm32-wasi reactor modules that /models/*.so are
// AOT-compiled from.
// Host-facing shim around a Reference FMU (FMI 3.0 co-simulation). Which model,
// which three parameters are set and which outputs are recorded come from
// macros, so the same shim serves VanDerPol (default), BouncingBall (-DBB) and
// the Lorenz model of our own (-DLORENZ, models/Lorenz).
// sim_run() instantiates, sets p0..p2, steps the FMU with communication step h to
// t_end, writes the NOUT outputs after every step, frees the instance.
#include <stdlib.h>
#include <stdint.h>
#include "fmi3Functions.h"
#if defined(BB)
#define TOKEN "{1AE5E10D-9521-4DE3-80B9-D0EAAA7D5AF1}"   /* BouncingBall */
#define VR_P0 6  /* e, coefficient of restitution */
#define VR_P1 1  /* h */
#define VR_P2 3  /* v */
#define NOUT 2
#define VR_O {1, 3}  /* h, v */
#elif defined(LORENZ)
#define TOKEN "{04D78D0D-C43D-4398-9272-AC49A652338F}"   /* Lorenz, models/Lorenz */
#define VR_P0 8  /* rho, the swept parameter */
#define VR_P1 7  /* sigma */
#define VR_P2 9  /* beta */
#define NOUT 3
#define VR_O {1, 3, 5}  /* x, y, z */
#else
#define TOKEN "{BD403596-3166-4232-ABC2-132BDF73E644}"   /* VanDerPol */
#define VR_P0 5  /* mu */
#define VR_P1 1  /* x0 */
#define VR_P2 3  /* x1 */
#define NOUT 2
#define VR_O {1, 3}  /* x0, x1 */
#endif

__attribute__((export_name("alloc")))
void *shim_alloc(size_t bytes) { return malloc(bytes); }

/* Outputs recorded per step: sim_run writes NOUT values after every step. A host
   reads this instead of assuming the layout, so a model with a different output
   set changes one macro here and nothing in the worker. */
__attribute__((export_name("sim_width")))
int32_t sim_width(void) { return NOUT; }

__attribute__((export_name("sim_run")))
int32_t sim_run(double p0, double p1, double p2, double t_end, double h, double *out, int32_t max_steps) {
    fmi3Instance inst = fmi3InstantiateCoSimulation("m", TOKEN, "", fmi3False, fmi3False, fmi3False, fmi3False,
                                                     NULL, 0, NULL, NULL, NULL);
    if (!inst) return -1;
    const fmi3ValueReference vrs[3] = {VR_P0, VR_P1, VR_P2};
    const fmi3Float64 vals[3] = {p0, p1, p2};
    if (fmi3SetFloat64(inst, vrs, 3, vals, 3) != fmi3OK) return -2;
    if (fmi3EnterInitializationMode(inst, fmi3False, 0, 0, fmi3True, t_end) != fmi3OK) return -3;
    if (fmi3ExitInitializationMode(inst) != fmi3OK) return -4;
    const fmi3ValueReference outvr[NOUT] = VR_O;
    double t = 0;
    int32_t n = 0;
    /* Guard on the step count, not the accumulated t: 6,000 additions of 0.01
       land 3.4e-12 short of 60, and a guard on t then asks for a step past the
       stop time, which the FMU refuses. t itself stays accumulated, because the
       FMU accumulates its next communication point the same way. */
    while (n < max_steps && (n + 1) * h <= t_end + 1e-9) {
        fmi3Boolean ev, term, early;
        fmi3Float64 last;
        if (fmi3DoStep(inst, t, h, fmi3True, &ev, &term, &early, &last) != fmi3OK) return -5;
        t += h;
        if (fmi3GetFloat64(inst, outvr, NOUT, &out[NOUT * n], NOUT) != fmi3OK) return -6;
        n++;
        if (term) break;
    }
    fmi3FreeInstance(inst);
    return n;
}
