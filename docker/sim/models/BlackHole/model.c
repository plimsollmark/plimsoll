// The black-hole station-keeping plant (see config.h for the equations and the
// units). The controller is NOT in this model: the two thrust components are FMI
// inputs a host sets before every communication step. sqrt and fabs come from
// the libm the model is compiled with; in the WebAssembly build that is wasi-libc
// inside the module.
#include <math.h>
#include "config.h"
#include "model.h"

static double clampAbs(double v, double lim) {
    if (v > lim) return lim;
    if (v < -lim) return -lim;
    return v;
}

Status setStartValues(ModelInstance *comp) {
    ASSERT_NOT_NULL2(comp);

    M(r_target) = 5;
    M(v0) = 0;
    M(a_max) = 0.02;
    M(r) = 5;
    M(v) = 0;
    M(phi) = 0;
    M(L) = 5 / sqrt(2.0);   // circular orbit at r = 5: L^2 = r^2 / (r - 3)
    M(t) = 0;
    M(fuel) = 0;
    M(a_r) = 0;
    M(a_phi) = 0;
    M(omega) = M(L) / 25;

    comp->isDirtyValues = true;

    return OK;
}

// The parameters fix the initial state: the probe starts on the circular orbit
// of the target radius with the radial kick v0. Applied when the parameters are
// set (before initialisation), so a scenario is three numbers.
static void applyScenario(ModelInstance *comp) {
    const double r0 = M(r_target) > 3.05 ? M(r_target) : 3.05;
    M(r) = r0;
    M(v) = M(v0);
    M(phi) = 0;
    M(L) = r0 / sqrt(r0 - 3);
    M(t) = 0;
    M(fuel) = 0;
}

Status calculateValues(ModelInstance *comp) {
    ASSERT_NOT_NULL2(comp);

    const double r = M(r);
    const double ar = clampAbs(M(a_r), M(a_max));
    const double aphi = clampAbs(M(a_phi), M(a_max));
    if (r <= 2.05) {
        // Captured: nothing below here is a control problem. Freeze.
        M(der_r) = 0; M(der_v) = 0; M(der_phi) = 0; M(der_L) = 0; M(der_t) = 0; M(der_fuel) = 0;
        M(omega) = 0;
        comp->isDirtyValues = false;
        return OK;
    }
    const double L = M(L), r2 = r * r, r3 = r2 * r, r4 = r3 * r;
    const double f = 1 - 2 / r;
    M(der_r) = M(v);
    M(der_v) = -1 / r2 + L * L / r3 - 3 * L * L / r4 + ar;
    M(der_phi) = L / r2;
    M(der_L) = r * aphi;
    const double E2 = M(v) * M(v) + f * (1 + L * L / r2);
    M(der_t) = sqrt(E2 > 0 ? E2 : 0) / f;
    M(der_fuel) = fabs(ar) + fabs(aphi);
    M(omega) = L / r2;

    comp->isDirtyValues = false;

    return OK;
}

Status getFloat64(ModelInstance* comp, ValueReference vr, double values[], size_t nValues, size_t* index) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(values);
    ASSERT_NOT_NULL2(index);

    calculateValues(comp);

    switch (vr) {
        case vr_time:     ASSERT_NVALUES(1); values[(*index)++] = comp->time;  return OK;
        case vr_r:        ASSERT_NVALUES(1); values[(*index)++] = M(r);        return OK;
        case vr_der_r:    ASSERT_NVALUES(1); values[(*index)++] = M(der_r);    return OK;
        case vr_v:        ASSERT_NVALUES(1); values[(*index)++] = M(v);        return OK;
        case vr_der_v:    ASSERT_NVALUES(1); values[(*index)++] = M(der_v);    return OK;
        case vr_phi:      ASSERT_NVALUES(1); values[(*index)++] = M(phi);      return OK;
        case vr_der_phi:  ASSERT_NVALUES(1); values[(*index)++] = M(der_phi);  return OK;
        case vr_L:        ASSERT_NVALUES(1); values[(*index)++] = M(L);        return OK;
        case vr_der_L:    ASSERT_NVALUES(1); values[(*index)++] = M(der_L);    return OK;
        case vr_t:        ASSERT_NVALUES(1); values[(*index)++] = M(t);        return OK;
        case vr_der_t:    ASSERT_NVALUES(1); values[(*index)++] = M(der_t);    return OK;
        case vr_fuel:     ASSERT_NVALUES(1); values[(*index)++] = M(fuel);     return OK;
        case vr_der_fuel: ASSERT_NVALUES(1); values[(*index)++] = M(der_fuel); return OK;
        case vr_a_r:      ASSERT_NVALUES(1); values[(*index)++] = M(a_r);      return OK;
        case vr_a_phi:    ASSERT_NVALUES(1); values[(*index)++] = M(a_phi);    return OK;
        case vr_r_target: ASSERT_NVALUES(1); values[(*index)++] = M(r_target); return OK;
        case vr_v0:       ASSERT_NVALUES(1); values[(*index)++] = M(v0);       return OK;
        case vr_a_max:    ASSERT_NVALUES(1); values[(*index)++] = M(a_max);    return OK;
        case vr_omega:    ASSERT_NVALUES(1); values[(*index)++] = M(omega);    return OK;
        default:
            logError(comp, "Get Float64 is not allowed for value reference %u.", vr);
            return Error;
    }
}

Status setFloat64(ModelInstance* comp, ValueReference vr, const double values[], size_t nValues, size_t* index) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(values);
    ASSERT_NOT_NULL2(index);

    switch (vr) {
        case vr_r:     ASSERT_NVALUES(1); M(r) = values[(*index)++];     break;
        case vr_v:     ASSERT_NVALUES(1); M(v) = values[(*index)++];     break;
        case vr_phi:   ASSERT_NVALUES(1); M(phi) = values[(*index)++];   break;
        case vr_L:     ASSERT_NVALUES(1); M(L) = values[(*index)++];     break;
        case vr_t:     ASSERT_NVALUES(1); M(t) = values[(*index)++];     break;
        case vr_fuel:  ASSERT_NVALUES(1); M(fuel) = values[(*index)++];  break;
        case vr_a_r:   ASSERT_NVALUES(1); M(a_r) = values[(*index)++];   break;
        case vr_a_phi: ASSERT_NVALUES(1); M(a_phi) = values[(*index)++]; break;
        case vr_r_target:
        case vr_v0:
        case vr_a_max:
            if (comp->type == ModelExchange &&
                comp->state != Instantiated &&
                comp->state != InitializationMode &&
                comp->state != EventMode) {
                logError(comp, "Variable %u can only be set after instantiation, in initialization mode or event mode.", vr);
                return Error;
            }
            ASSERT_NVALUES(1);
            if (vr == vr_r_target) M(r_target) = values[(*index)++];
            else if (vr == vr_v0) M(v0) = values[(*index)++];
            else M(a_max) = values[(*index)++];
            applyScenario(comp);
            break;
        default:
            logError(comp, "Set Float64 is not allowed for value reference %u.", vr);
            return Error;
    }

    comp->isDirtyValues = true;

    return OK;
}

size_t getNumberOfContinuousStates(ModelInstance* comp) {
    UNUSED(comp);
    return MAX_CONTINUOUS_STATES;
}

Status getContinuousStates(ModelInstance *comp, double x[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(x);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    calculateValues(comp);

    x[0] = M(r); x[1] = M(v); x[2] = M(phi); x[3] = M(L); x[4] = M(t); x[5] = M(fuel);

    return OK;
}

Status getNominalsOfContinuousStates(ModelInstance* comp, double nominals[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(nominals);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    calculateValues(comp);

    nominals[0] = 5; nominals[1] = 0.1; nominals[2] = 1; nominals[3] = 4; nominals[4] = 100; nominals[5] = 1;

    return OK;
}

Status setContinuousStates(ModelInstance *comp, const double x[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(x);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    M(r) = x[0]; M(v) = x[1]; M(phi) = x[2]; M(L) = x[3]; M(t) = x[4]; M(fuel) = x[5];

    comp->isDirtyValues = true;

    return OK;
}

Status getDerivatives(ModelInstance *comp, double dx[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(dx);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    calculateValues(comp);

    dx[0] = M(der_r); dx[1] = M(der_v); dx[2] = M(der_phi); dx[3] = M(der_L); dx[4] = M(der_t); dx[5] = M(der_fuel);

    return OK;
}

Status eventUpdate(ModelInstance *comp) {
    ASSERT_NOT_NULL2(comp);

    comp->valuesOfContinuousStatesChanged   = false;
    comp->nominalsOfContinuousStatesChanged = false;
    comp->terminateSimulation               = false;
    comp->nextEventTimeDefined              = false;

    return OK;
}
