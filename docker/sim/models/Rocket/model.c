// The twin-paradox rocket (see config.h). The controller is NOT in this model:
// the proper acceleration is an FMI input a host sets before every communication
// step. sinh, cosh, tanh and fabs come from wasi-libc inside the module.
#include <math.h>
#include "config.h"
#include "model.h"

Status setStartValues(ModelInstance *comp) {
    ASSERT_NOT_NULL2(comp);

    M(eta) = 0;
    M(x) = 0;
    M(t) = 0;
    M(fuel) = 0;
    M(a) = 0;
    M(T_target) = 40;
    M(fuel_budget) = 14;
    M(a_max) = 1;
    M(beta) = 0;

    comp->isDirtyValues = true;

    return OK;
}

Status calculateValues(ModelInstance *comp) {
    ASSERT_NOT_NULL2(comp);

    double a = M(a);
    if (a > M(a_max)) a = M(a_max);
    if (a < -M(a_max)) a = -M(a_max);
    if (M(fuel) >= M(fuel_budget)) a = 0;   // tanks empty: the engine is silent
    M(der_eta) = a;
    M(der_x) = sinh(M(eta));
    M(der_t) = cosh(M(eta));
    M(der_fuel) = fabs(a);
    M(beta) = tanh(M(eta));

    comp->isDirtyValues = false;

    return OK;
}

Status getFloat64(ModelInstance* comp, ValueReference vr, double values[], size_t nValues, size_t* index) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(values);
    ASSERT_NOT_NULL2(index);

    calculateValues(comp);

    switch (vr) {
        case vr_time:        ASSERT_NVALUES(1); values[(*index)++] = comp->time;     return OK;
        case vr_eta:         ASSERT_NVALUES(1); values[(*index)++] = M(eta);         return OK;
        case vr_der_eta:     ASSERT_NVALUES(1); values[(*index)++] = M(der_eta);     return OK;
        case vr_x:           ASSERT_NVALUES(1); values[(*index)++] = M(x);           return OK;
        case vr_der_x:       ASSERT_NVALUES(1); values[(*index)++] = M(der_x);       return OK;
        case vr_t:           ASSERT_NVALUES(1); values[(*index)++] = M(t);           return OK;
        case vr_der_t:       ASSERT_NVALUES(1); values[(*index)++] = M(der_t);       return OK;
        case vr_fuel:        ASSERT_NVALUES(1); values[(*index)++] = M(fuel);        return OK;
        case vr_der_fuel:    ASSERT_NVALUES(1); values[(*index)++] = M(der_fuel);    return OK;
        case vr_a:           ASSERT_NVALUES(1); values[(*index)++] = M(a);           return OK;
        case vr_T_target:    ASSERT_NVALUES(1); values[(*index)++] = M(T_target);    return OK;
        case vr_fuel_budget: ASSERT_NVALUES(1); values[(*index)++] = M(fuel_budget); return OK;
        case vr_a_max:       ASSERT_NVALUES(1); values[(*index)++] = M(a_max);       return OK;
        case vr_beta:        ASSERT_NVALUES(1); values[(*index)++] = M(beta);        return OK;
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
        case vr_eta:  ASSERT_NVALUES(1); M(eta) = values[(*index)++];  break;
        case vr_x:    ASSERT_NVALUES(1); M(x) = values[(*index)++];    break;
        case vr_t:    ASSERT_NVALUES(1); M(t) = values[(*index)++];    break;
        case vr_fuel: ASSERT_NVALUES(1); M(fuel) = values[(*index)++]; break;
        case vr_a:    ASSERT_NVALUES(1); M(a) = values[(*index)++];    break;
        case vr_T_target:
        case vr_fuel_budget:
        case vr_a_max:
            if (comp->type == ModelExchange &&
                comp->state != Instantiated &&
                comp->state != InitializationMode &&
                comp->state != EventMode) {
                logError(comp, "Variable %u can only be set after instantiation, in initialization mode or event mode.", vr);
                return Error;
            }
            ASSERT_NVALUES(1);
            if (vr == vr_T_target) M(T_target) = values[(*index)++];
            else if (vr == vr_fuel_budget) M(fuel_budget) = values[(*index)++];
            else M(a_max) = values[(*index)++];
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

    x[0] = M(eta); x[1] = M(x); x[2] = M(t); x[3] = M(fuel);

    return OK;
}

Status getNominalsOfContinuousStates(ModelInstance* comp, double nominals[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(nominals);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    calculateValues(comp);

    nominals[0] = 1; nominals[1] = 10; nominals[2] = 10; nominals[3] = 10;

    return OK;
}

Status setContinuousStates(ModelInstance *comp, const double x[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(x);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    M(eta) = x[0]; M(x) = x[1]; M(t) = x[2]; M(fuel) = x[3];

    comp->isDirtyValues = true;

    return OK;
}

Status getDerivatives(ModelInstance *comp, double dx[], size_t nx) {
    ASSERT_NOT_NULL2(comp);
    ASSERT_NOT_NULL2(dx);
    ASSERT_SIZE_T(nx, MAX_CONTINUOUS_STATES);

    calculateValues(comp);

    dx[0] = M(der_eta); dx[1] = M(der_x); dx[2] = M(der_t); dx[3] = M(der_fuel);

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
