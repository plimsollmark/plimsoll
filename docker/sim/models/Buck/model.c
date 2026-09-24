// The buck-converter plant (see config.h). The controller is NOT in this model:
// the duty cycle is an FMI input a host sets before every communication step.
// No libm calls, so the trajectory is plain IEEE arithmetic.
#include "config.h"
#include "model.h"

static double clamp01(double v) {
    if (v < 0) return 0;
    if (v > 1) return 1;
    return v;
}

Status setStartValues(ModelInstance *comp) {
    ASSERT_NOT_NULL2(comp);

    M(v) = 0;
    M(i) = 0;
    M(u) = 0;
    M(Vin) = 12;
    M(R0) = 4;
    M(t_step) = 0.01;
    M(L) = 100e-6;
    M(C) = 100e-6;
    M(R) = 4;

    comp->isDirtyValues = true;

    return OK;
}

Status calculateValues(ModelInstance *comp) {
    ASSERT_NOT_NULL2(comp);

    const double d = clamp01(M(u));
    M(R) = comp->time >= M(t_step) ? M(R0) * 0.5 : M(R0);
    M(der_i) = (d * M(Vin) - M(v)) / M(L);
    M(der_v) = (M(i) - M(v) / M(R)) / M(C);

    comp->isDirtyValues = false;

    return OK;
}

Status getFloat64(ModelInstance* comp, ValueReference vr, double values[], size_t nValues, size_t* index) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(values);
    ASSERT_NOT_NULL2(index);

    calculateValues(comp);

    switch (vr) {
        case vr_time:   ASSERT_NVALUES(1); values[(*index)++] = comp->time; return OK;
        case vr_v:      ASSERT_NVALUES(1); values[(*index)++] = M(v);       return OK;
        case vr_der_v:  ASSERT_NVALUES(1); values[(*index)++] = M(der_v);   return OK;
        case vr_i:      ASSERT_NVALUES(1); values[(*index)++] = M(i);       return OK;
        case vr_der_i:  ASSERT_NVALUES(1); values[(*index)++] = M(der_i);   return OK;
        case vr_u:      ASSERT_NVALUES(1); values[(*index)++] = M(u);       return OK;
        case vr_Vin:    ASSERT_NVALUES(1); values[(*index)++] = M(Vin);     return OK;
        case vr_R0:     ASSERT_NVALUES(1); values[(*index)++] = M(R0);      return OK;
        case vr_t_step: ASSERT_NVALUES(1); values[(*index)++] = M(t_step);  return OK;
        case vr_L:      ASSERT_NVALUES(1); values[(*index)++] = M(L);       return OK;
        case vr_C:      ASSERT_NVALUES(1); values[(*index)++] = M(C);       return OK;
        case vr_R:      ASSERT_NVALUES(1); values[(*index)++] = M(R);       return OK;
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
        case vr_v: ASSERT_NVALUES(1); M(v) = values[(*index)++]; break;
        case vr_i: ASSERT_NVALUES(1); M(i) = values[(*index)++]; break;
        case vr_u: ASSERT_NVALUES(1); M(u) = values[(*index)++]; break;
        case vr_Vin:
        case vr_R0:
        case vr_t_step:
        case vr_L:
        case vr_C:
            if (comp->type == ModelExchange &&
                comp->state != Instantiated &&
                comp->state != InitializationMode &&
                comp->state != EventMode) {
                logError(comp, "Variable %u can only be set after instantiation, in initialization mode or event mode.", vr);
                return Error;
            }
            ASSERT_NVALUES(1);
            if (vr == vr_Vin) M(Vin) = values[(*index)++];
            else if (vr == vr_R0) M(R0) = values[(*index)++];
            else if (vr == vr_t_step) M(t_step) = values[(*index)++];
            else if (vr == vr_L) M(L) = values[(*index)++];
            else M(C) = values[(*index)++];
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

    x[0] = M(v);
    x[1] = M(i);

    return OK;
}

Status getNominalsOfContinuousStates(ModelInstance* comp, double nominals[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(nominals);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    calculateValues(comp);

    nominals[0] = 5.0;
    nominals[1] = 1.0;

    return OK;
}

Status setContinuousStates(ModelInstance *comp, const double x[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(x);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    M(v) = x[0];
    M(i) = x[1];

    comp->isDirtyValues = true;

    return OK;
}

Status getDerivatives(ModelInstance *comp, double dx[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(dx);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    calculateValues(comp);

    dx[0] = M(der_v);
    dx[1] = M(der_i);

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
