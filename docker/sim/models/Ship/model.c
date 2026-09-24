// The ship-heading plant (see config.h). The controller is NOT in this model: the
// commanded rudder angle is an FMI input a host sets before every communication
// step. sin comes from the libm this model is compiled with; in the WebAssembly
// build that is wasi-libc inside the module, so the trajectory does not depend
// on the host machine.
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

    M(psi) = 0;
    M(r) = 0;
    M(delta) = 0;
    M(u) = 0;
    M(K) = 0.2;
    M(T) = 20;
    M(wave) = 0.002;
    M(wave_omega) = 0.5;
    M(delta_max) = 0.6109;   // 35 degrees
    M(delta_rate) = 0.0524;  // 3 degrees per second
    M(tau_r) = 2.0;

    comp->isDirtyValues = true;

    return OK;
}

Status calculateValues(ModelInstance *comp) {
    ASSERT_NOT_NULL2(comp);

    const double cmd = clampAbs(M(u), M(delta_max));
    M(der_psi) = M(r);
    M(der_r) = (M(K) * M(delta) - M(r)) / M(T) + M(wave) * sin(M(wave_omega) * comp->time);
    M(der_delta) = clampAbs((cmd - M(delta)) / M(tau_r), M(delta_rate));

    comp->isDirtyValues = false;

    return OK;
}

Status getFloat64(ModelInstance* comp, ValueReference vr, double values[], size_t nValues, size_t* index) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(values);
    ASSERT_NOT_NULL2(index);

    calculateValues(comp);

    switch (vr) {
        case vr_time:       ASSERT_NVALUES(1); values[(*index)++] = comp->time;    return OK;
        case vr_psi:        ASSERT_NVALUES(1); values[(*index)++] = M(psi);        return OK;
        case vr_der_psi:    ASSERT_NVALUES(1); values[(*index)++] = M(der_psi);    return OK;
        case vr_r:          ASSERT_NVALUES(1); values[(*index)++] = M(r);          return OK;
        case vr_der_r:      ASSERT_NVALUES(1); values[(*index)++] = M(der_r);      return OK;
        case vr_delta:      ASSERT_NVALUES(1); values[(*index)++] = M(delta);      return OK;
        case vr_der_delta:  ASSERT_NVALUES(1); values[(*index)++] = M(der_delta);  return OK;
        case vr_u:          ASSERT_NVALUES(1); values[(*index)++] = M(u);          return OK;
        case vr_K:          ASSERT_NVALUES(1); values[(*index)++] = M(K);          return OK;
        case vr_T:          ASSERT_NVALUES(1); values[(*index)++] = M(T);          return OK;
        case vr_wave:       ASSERT_NVALUES(1); values[(*index)++] = M(wave);       return OK;
        case vr_wave_omega: ASSERT_NVALUES(1); values[(*index)++] = M(wave_omega); return OK;
        case vr_delta_max:  ASSERT_NVALUES(1); values[(*index)++] = M(delta_max);  return OK;
        case vr_delta_rate: ASSERT_NVALUES(1); values[(*index)++] = M(delta_rate); return OK;
        case vr_tau_r:      ASSERT_NVALUES(1); values[(*index)++] = M(tau_r);      return OK;
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
        case vr_psi:   ASSERT_NVALUES(1); M(psi) = values[(*index)++];   break;
        case vr_r:     ASSERT_NVALUES(1); M(r) = values[(*index)++];     break;
        case vr_delta: ASSERT_NVALUES(1); M(delta) = values[(*index)++]; break;
        case vr_u:     ASSERT_NVALUES(1); M(u) = values[(*index)++];     break;
        case vr_K:
        case vr_T:
        case vr_wave:
        case vr_wave_omega:
        case vr_delta_max:
        case vr_delta_rate:
        case vr_tau_r:
            if (comp->type == ModelExchange &&
                comp->state != Instantiated &&
                comp->state != InitializationMode &&
                comp->state != EventMode) {
                logError(comp, "Variable %u can only be set after instantiation, in initialization mode or event mode.", vr);
                return Error;
            }
            ASSERT_NVALUES(1);
            if (vr == vr_K) M(K) = values[(*index)++];
            else if (vr == vr_T) M(T) = values[(*index)++];
            else if (vr == vr_wave) M(wave) = values[(*index)++];
            else if (vr == vr_wave_omega) M(wave_omega) = values[(*index)++];
            else if (vr == vr_delta_max) M(delta_max) = values[(*index)++];
            else if (vr == vr_delta_rate) M(delta_rate) = values[(*index)++];
            else M(tau_r) = values[(*index)++];
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

    x[0] = M(psi);
    x[1] = M(r);
    x[2] = M(delta);

    return OK;
}

Status getNominalsOfContinuousStates(ModelInstance* comp, double nominals[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(nominals);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    calculateValues(comp);

    nominals[0] = 1.0;
    nominals[1] = 0.1;
    nominals[2] = 0.5;

    return OK;
}

Status setContinuousStates(ModelInstance *comp, const double x[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(x);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    M(psi) = x[0];
    M(r) = x[1];
    M(delta) = x[2];

    comp->isDirtyValues = true;

    return OK;
}

Status getDerivatives(ModelInstance *comp, double dx[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(dx);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    calculateValues(comp);

    dx[0] = M(der_psi);
    dx[1] = M(der_r);
    dx[2] = M(der_delta);

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
