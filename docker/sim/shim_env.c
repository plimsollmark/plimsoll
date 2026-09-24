// The generic stepping shim of the control-design environments. Which model,
// which three parameters, which input, which outputs and which states come from a
// plant.h in the model's directory (put it on the include path); the shim itself
// is the same for every plant. It subsumes the vendored shim_step.c: the same
// stepping arithmetic, proven by the cart-pole fingerprints staying unchanged.
//
//   sim_init(p0, p1, p2, h, t_end) -> 0, or a negative code
//   sim_width()                    -> outputs per state read
//   sim_get(out)                   -> the current state into out[0..width)
//   sim_step(u, out)               -> set the input to u, advance one step of h,
//                                     write the new state; 1, 0 at termination,
//                                     negative on error
//   sim_free()
//
// Differentiable access, the same for every plant:
//
//   sim_nx()                       -> number of continuous states n
//   sim_solver_step()              -> the fixed Euler substep inside one step of h
//   sim_nin()                      -> inputs per tick (1 unless plant.h says more)
//   sim_step_n(u, out)             -> the same as sim_step with nin inputs
//   sim_jac(A, B)                  -> the plant's linearization at the current
//                                     state and inputs: A is n x n row-major
//                                     d(dx_i/dt)/dx_j, B is n x nin d(dx_i/dt)/du_k, by
//                                     central differences on the model's own
//                                     derivative outputs; 0, or a negative code
//
// sim_jac perturbs each state through its value reference, reads the derivatives,
// and restores the exact original doubles, so a step after it is byte-identical
// to a step without it. One step of h is m = h / sim_solver_step() forward Euler
// substeps, so the discrete step map is the product of (I + h_s A) evaluated
// along the substeps; a caller that wants the exact discrete Jacobian steps at
// h = sim_solver_step() and multiplies. A caller that accepts first order uses
// I + h A and h B at the tick.
//
// One instance per module instance: a host that wants N plants instantiates the
// module N times.
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include "fmi3Functions.h"
#include "config.h"
#include "plant.h"

// Inputs per tick. A plant.h that names one input (VR_IN) gets NIN 1; a plant
// with several names them all in VR_INS with NIN, and the judge sends that many
// numbers per line (sim_step_n). sim_step keeps the one-number entry.
#ifndef NIN
#define NIN 1
#define VR_INS {VR_IN}
#endif

static fmi3Instance inst;
static double t, step_h, last_u[NIN];
static const fmi3ValueReference outvr[NOUT] = VR_O;
static const fmi3ValueReference invr[NIN] = VR_INS;
static const fmi3ValueReference xvr[NX] = VR_X;
static const fmi3ValueReference dxvr[NX] = VR_DX;

__attribute__((export_name("alloc")))
void *shim_alloc(size_t bytes) { return malloc(bytes); }

__attribute__((export_name("sim_width")))
int32_t sim_width(void) { return NOUT; }

__attribute__((export_name("sim_nx")))
int32_t sim_nx(void) { return NX; }

__attribute__((export_name("sim_nin")))
int32_t sim_nin(void) { return NIN; }

__attribute__((export_name("sim_solver_step")))
double sim_solver_step(void) { return FIXED_SOLVER_STEP; }

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
    for (int32_t k = 0; k < NIN; k++) last_u[k] = 0;
    return 0;
}

__attribute__((export_name("sim_get")))
int32_t sim_get(double *out) {
    if (!inst) return -1;
    return fmi3GetFloat64(inst, outvr, NOUT, out, NOUT) == fmi3OK ? 0 : -6;
}

__attribute__((export_name("sim_step_n")))
int32_t sim_step_n(const double *u, double *out) {
    if (!inst) return -1;
    if (fmi3SetFloat64(inst, invr, NIN, u, NIN) != fmi3OK) return -7;
    for (int32_t k = 0; k < NIN; k++) last_u[k] = u[k];
    fmi3Boolean ev, term, early;
    fmi3Float64 last;
    if (fmi3DoStep(inst, t, step_h, fmi3True, &ev, &term, &early, &last) != fmi3OK) return -5;
    t += step_h;
    if (fmi3GetFloat64(inst, outvr, NOUT, out, NOUT) != fmi3OK) return -6;
    return term ? 0 : 1;
}

// The one-number entry: sets the first input, leaves the others as they were.
__attribute__((export_name("sim_step")))
int32_t sim_step(double u, double *out) {
    double all[NIN];
    for (int32_t k = 0; k < NIN; k++) all[k] = last_u[k];
    all[0] = u;
    return sim_step_n(all, out);
}

// Central differences on the model's derivative outputs. The perturbation is
// 1e-6 scaled by the state's magnitude, the classic choice for second-order
// differences in double precision; every perturbed value is restored to the
// exact original double.
__attribute__((export_name("sim_jac")))
int32_t sim_jac(double *A, double *B) {
    if (!inst) return -1;
    double x0[NX], dxp[NX], dxm[NX];
    if (fmi3GetFloat64(inst, xvr, NX, x0, NX) != fmi3OK) return -6;
    for (int32_t j = 0; j < NX; j++) {
        const double scale = fabs(x0[j]) > 1 ? fabs(x0[j]) : 1;
        const double eps = 1e-6 * scale;
        double v = x0[j] + eps;
        if (fmi3SetFloat64(inst, &xvr[j], 1, &v, 1) != fmi3OK) return -8;
        if (fmi3GetFloat64(inst, dxvr, NX, dxp, NX) != fmi3OK) return -6;
        v = x0[j] - eps;
        if (fmi3SetFloat64(inst, &xvr[j], 1, &v, 1) != fmi3OK) return -8;
        if (fmi3GetFloat64(inst, dxvr, NX, dxm, NX) != fmi3OK) return -6;
        if (fmi3SetFloat64(inst, &xvr[j], 1, &x0[j], 1) != fmi3OK) return -8;
        for (int32_t i = 0; i < NX; i++) A[i * NX + j] = (dxp[i] - dxm[i]) / (2 * eps);
    }
    for (int32_t k = 0; k < NIN; k++) {
        const double scale = fabs(last_u[k]) > 1 ? fabs(last_u[k]) : 1;
        const double eps = 1e-6 * scale;
        double v = last_u[k] + eps;
        if (fmi3SetFloat64(inst, &invr[k], 1, &v, 1) != fmi3OK) return -8;
        if (fmi3GetFloat64(inst, dxvr, NX, dxp, NX) != fmi3OK) return -6;
        v = last_u[k] - eps;
        if (fmi3SetFloat64(inst, &invr[k], 1, &v, 1) != fmi3OK) return -8;
        if (fmi3GetFloat64(inst, dxvr, NX, dxm, NX) != fmi3OK) return -6;
        if (fmi3SetFloat64(inst, &invr[k], 1, &last_u[k], 1) != fmi3OK) return -8;
        for (int32_t i = 0; i < NX; i++) B[i * NIN + k] = (dxp[i] - dxm[i]) / (2 * eps);
    }
    return 0;
}

__attribute__((export_name("sim_free")))
void sim_free(void) {
    if (inst) { fmi3FreeInstance(inst); inst = NULL; }
}
