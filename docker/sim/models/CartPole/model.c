// Vendored from the plimsoll-sim repository at commit d3f9b28 (2026-09-18),
// unchanged below this header. The cart-pole plant of the physics oracle, in the
// Reference FMU style (models/CartPole there).
#include <math.h>
#include "config.h"
#include "model.h"

// Cart-pole without friction, the form used throughout the reinforcement-learning
// literature (a cart on a rail, a pole hinged on it, one force on the cart). The
// controller is NOT in this model: the force is an FMI input a host sets before
// every communication step. sin and cos come from the libm this model is
// compiled with; in the WebAssembly build that is wasi-libc inside the module, so
// the trajectory does not depend on the host machine.

Status setStartValues(ModelInstance *comp) {
    ASSERT_NOT_NULL2(comp);

    M(x) = 0;
    M(v) = 0;
    M(theta) = 0.2;
    M(omega) = 0;
    M(F) = 0;
    M(l) = 0.5;
    M(M) = 1.0;
    M(m) = 0.1;
    M(g) = 9.81;
    M(Fmax) = 20;

    comp->isDirtyValues = true;

    return OK;
}

Status calculateValues(ModelInstance *comp) {
    ASSERT_NOT_NULL2(comp);

    double F = M(F);
    if (F > M(Fmax)) F = M(Fmax);
    if (F < -M(Fmax)) F = -M(Fmax);
    const double s = sin(M(theta));
    const double c = cos(M(theta));
    const double total = M(M) + M(m);
    const double temp = (F + M(m) * M(l) * M(omega) * M(omega) * s) / total;

    M(der_x) = M(v);
    M(der_theta) = M(omega);
    M(der_omega) = (M(g) * s - c * temp) / (M(l) * (4.0 / 3.0 - M(m) * c * c / total));
    M(der_v) = temp - M(m) * M(l) * M(der_omega) * c / total;

    comp->isDirtyValues = false;

    return OK;
}

Status getFloat64(ModelInstance* comp, ValueReference vr, double values[], size_t nValues, size_t* index) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(values);
    ASSERT_NOT_NULL2(index);

    calculateValues(comp);

    switch (vr) {
        case vr_time:      ASSERT_NVALUES(1); values[(*index)++] = comp->time;   return OK;
        case vr_x:         ASSERT_NVALUES(1); values[(*index)++] = M(x);         return OK;
        case vr_der_x:     ASSERT_NVALUES(1); values[(*index)++] = M(der_x);     return OK;
        case vr_v:         ASSERT_NVALUES(1); values[(*index)++] = M(v);         return OK;
        case vr_der_v:     ASSERT_NVALUES(1); values[(*index)++] = M(der_v);     return OK;
        case vr_theta:     ASSERT_NVALUES(1); values[(*index)++] = M(theta);     return OK;
        case vr_der_theta: ASSERT_NVALUES(1); values[(*index)++] = M(der_theta); return OK;
        case vr_omega:     ASSERT_NVALUES(1); values[(*index)++] = M(omega);     return OK;
        case vr_der_omega: ASSERT_NVALUES(1); values[(*index)++] = M(der_omega); return OK;
        case vr_F:         ASSERT_NVALUES(1); values[(*index)++] = M(F);         return OK;
        case vr_l:         ASSERT_NVALUES(1); values[(*index)++] = M(l);         return OK;
        case vr_M:         ASSERT_NVALUES(1); values[(*index)++] = M(M);         return OK;
        case vr_m:         ASSERT_NVALUES(1); values[(*index)++] = M(m);         return OK;
        case vr_g:         ASSERT_NVALUES(1); values[(*index)++] = M(g);         return OK;
        case vr_Fmax:      ASSERT_NVALUES(1); values[(*index)++] = M(Fmax);      return OK;
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
        case vr_x:     ASSERT_NVALUES(1); M(x) = values[(*index)++];     break;
        case vr_v:     ASSERT_NVALUES(1); M(v) = values[(*index)++];     break;
        case vr_theta: ASSERT_NVALUES(1); M(theta) = values[(*index)++]; break;
        case vr_omega: ASSERT_NVALUES(1); M(omega) = values[(*index)++]; break;
        case vr_F:     ASSERT_NVALUES(1); M(F) = values[(*index)++];     break;
        case vr_l:
        case vr_M:
        case vr_m:
        case vr_g:
        case vr_Fmax:
            if (comp->type == ModelExchange &&
                comp->state != Instantiated &&
                comp->state != InitializationMode &&
                comp->state != EventMode) {
                logError(comp, "Variable %u can only be set after instantiation, in initialization mode or event mode.", vr);
                return Error;
            }
            ASSERT_NVALUES(1);
            if (vr == vr_l) M(l) = values[(*index)++];
            else if (vr == vr_M) M(M) = values[(*index)++];
            else if (vr == vr_m) M(m) = values[(*index)++];
            else if (vr == vr_g) M(g) = values[(*index)++];
            else M(Fmax) = values[(*index)++];
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

    x[0] = M(x);
    x[1] = M(v);
    x[2] = M(theta);
    x[3] = M(omega);

    return OK;
}

Status getNominalsOfContinuousStates(ModelInstance* comp, double nominals[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(nominals);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    calculateValues(comp);

    nominals[0] = 1.0;
    nominals[1] = 1.0;
    nominals[2] = 1.0;
    nominals[3] = 1.0;

    return OK;
}

Status setContinuousStates(ModelInstance *comp, const double x[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(x);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    M(x) = x[0];
    M(v) = x[1];
    M(theta) = x[2];
    M(omega) = x[3];

    comp->isDirtyValues = true;

    return OK;
}

Status getDerivatives(ModelInstance *comp, double dx[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(dx);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    calculateValues(comp);

    dx[0] = M(der_x);
    dx[1] = M(der_v);
    dx[2] = M(der_theta);
    dx[3] = M(der_omega);

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
